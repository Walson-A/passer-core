//! passer-core for apps.
//!
//! One object, [`PasserDevice`], is the whole surface an app needs: create or join a
//! group, start the device, declare what it can do, invite, call other devices. UniFFI
//! generates Swift (iOS, macOS) and Kotlin (Android) bindings from these definitions; the
//! desktop app (Tauri) uses the same object from Rust directly.
//!
//! The app supplies three things through callback interfaces, implemented natively:
//!
//! - [`KeyVault`]: where the device key lives (Keychain `ThisDeviceOnly` on iOS, Android
//!   Keystore-wrapped storage). The secret is generated in Rust and handed over once.
//! - [`ApprovalPrompter`]: how to ask the user to approve a sensitive action (a sheet, a
//!   notification).
//! - [`CapabilityHandler`]: what the device actually does (read the clipboard, receive a
//!   file...), for the [`CapabilitySpec`]s it declares. The bus checks permissions, asks for
//!   approval, enforces sessions and journals *before* the handler is called.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use passer_bus::{
    Bus, Capability, Ctx, Effect, IndicatorRequirement, Journal, Manifest, Module, ModuleError,
    Policy, Request, Response,
};
use passer_identity::{DeviceId, Identity, IdentityError, KeyStore};
use passer_membership::DeviceLog;
use passer_membership::pairing::Invitation;
use passer_node::approval::{ApprovalModule, ApprovalPrompt, Prompter, RemoteApprover};
use passer_node::{Group, Network, Node, NodeOptions, now_secs};
use serde_json::Value;

uniffi::setup_scaffolding!();

/// Everything that can go wrong, in terms an app can show or act on.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PasserError {
    #[error("storage error: {message}")]
    Storage { message: String },
    #[error("this device does not belong to a group yet")]
    NoGroup,
    #[error("this device already belongs to a group")]
    AlreadyInGroup,
    #[error("the device is not started")]
    NotStarted,
    #[error("invalid: {message}")]
    Invalid { message: String },
    #[error("network error: {message}")]
    Network { message: String },
    /// The other device answered, and said no (or failed). `code` is stable, e.g.
    /// `denied`, `not_member`, `approval_timeout`, `invalid_input`.
    #[error("{code}: {message}")]
    Refused { code: String, message: String },
}

impl PasserError {
    fn storage(e: impl std::fmt::Display) -> Self {
        Self::Storage {
            message: e.to_string(),
        }
    }
    fn invalid(e: impl std::fmt::Display) -> Self {
        Self::Invalid {
            message: e.to_string(),
        }
    }
    fn network(e: impl std::fmt::Display) -> Self {
        Self::Network {
            message: format!("{e:#}"),
        }
    }
}

/// How far the device reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NetworkKind {
    /// Direct addresses only (same network, or addresses from a coordination server).
    LocalOnly,
    /// n0's public relays and lookup. Development only.
    N0Dev,
}

impl From<NetworkKind> for Network {
    fn from(n: NetworkKind) -> Self {
        match n {
            NetworkKind::LocalOnly => Network::LocalOnly,
            NetworkKind::N0Dev => Network::N0Dev,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EffectKind {
    Read,
    Write,
    Sensitive,
}

impl From<EffectKind> for Effect {
    fn from(e: EffectKind) -> Self {
        match e {
            EffectKind::Read => Effect::Read,
            EffectKind::Write => Effect::Write,
            EffectKind::Sensitive => Effect::Sensitive,
        }
    }
}

/// A capability the app implements, declared before [`PasserDevice::start`].
#[derive(Clone, Debug, uniffi::Record)]
pub struct CapabilitySpec {
    /// Dotted lowercase name, e.g. `clipboard.read`.
    pub name: String,
    pub title: String,
    pub description: String,
    /// JSON Schema of the input, as a JSON string.
    pub input_schema_json: String,
    pub effect: EffectKind,
    /// Kind of target the capability acts on, if any (e.g. `app`, `folder`).
    pub target_kind: Option<String>,
    /// The device must show a visible indicator while it runs.
    pub indicator_required: bool,
}

/// A member of the group.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MemberInfo {
    pub id: String,
    pub name: String,
    pub approver: bool,
    pub this_device: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct InviteInfo {
    /// Show as a QR code. Contains a one-time secret: never share or screenshot it.
    pub link: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct JoinResult {
    pub group_name: String,
    /// Six digits the inviting device also shows. If they differ, cancel.
    pub sas: String,
}

/// Who is calling a capability on this device.
#[derive(Clone, Debug, uniffi::Record)]
pub struct CallerInfo {
    pub device_id: String,
    pub device_name: String,
    /// Set when an AI agent asks through that device.
    pub agent: Option<String>,
}

/// What the user is asked to approve.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ApprovalInfo {
    /// Show a short form of the ids too: names are unique in a group, ids cannot be faked.
    pub requester_id: String,
    pub requester_name: String,
    pub agent: Option<String>,
    pub target_device_id: String,
    /// The device that would act.
    pub target_device_name: String,
    pub capability: String,
    pub title: String,
    pub target: Option<String>,
    pub duration_minutes: u64,
}

/// Where the device key is kept. Implemented natively (Keychain, Keystore).
#[uniffi::export(with_foreign)]
pub trait KeyVault: Send + Sync {
    /// The stored 32-byte secret, if any.
    fn load(&self) -> Option<Vec<u8>>;
    /// Stores a freshly generated secret. Called once, on first use.
    fn store(&self, secret: Vec<u8>) -> Result<(), PasserError>;
}

/// Asks the person using this device. Implemented natively (sheet, notification).
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait ApprovalPrompter: Send + Sync {
    async fn ask(&self, request: ApprovalInfo) -> bool;
}

/// Runs the app's capabilities. Called only after the bus allowed the call.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait CapabilityHandler: Send + Sync {
    /// Returns the output as a JSON string.
    async fn invoke(
        &self,
        capability: String,
        target: Option<String>,
        input_json: String,
        caller: CallerInfo,
    ) -> Result<String, PasserError>;
}

// ---------------------------------------------------------------------------------------
// Adapters from the app's callbacks to the core's traits
// ---------------------------------------------------------------------------------------

struct VaultStore(Arc<dyn KeyVault>);

impl KeyStore for VaultStore {
    fn load_or_create(&self) -> Result<Identity, IdentityError> {
        if let Some(bytes) = self.0.load() {
            let secret: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::Malformed)?;
            return Ok(Identity::from_secret_bytes(&secret));
        }
        let identity = Identity::generate();
        let secret = identity.secret_key().to_bytes().to_vec();
        self.0
            .store(secret)
            .map_err(|e| IdentityError::Io(std::io::Error::other(e.to_string())))?;
        Ok(identity)
    }
}

struct ForeignModule {
    specs: Vec<CapabilitySpec>,
    handler: Arc<dyn CapabilityHandler>,
    group: Arc<Group>,
}

#[async_trait]
impl Module for ForeignModule {
    fn manifest(&self) -> Manifest {
        let capabilities = self
            .specs
            .iter()
            .map(|s| {
                let mut cap = Capability::call(
                    &s.name,
                    &s.title,
                    &s.description,
                    s.effect.into(),
                    serde_json::from_str(&s.input_schema_json).unwrap_or(Value::Null),
                );
                cap.target_kind = s.target_kind.clone();
                if s.indicator_required {
                    cap.indicator = IndicatorRequirement::Required;
                }
                cap
            })
            .collect();
        Manifest {
            module: "app".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            capabilities,
        }
    }

    async fn invoke(&self, ctx: Ctx, capability: &str, input: Value) -> Result<Value, ModuleError> {
        let caller = CallerInfo {
            device_id: ctx.subject.device.to_string(),
            device_name: name_of(&self.group, &ctx.subject.device),
            agent: ctx.subject.agent.clone(),
        };
        let out = self
            .handler
            .invoke(
                capability.to_owned(),
                ctx.target.clone(),
                input.to_string(),
                caller,
            )
            .await
            .map_err(|e| ModuleError::Failed(e.to_string()))?;
        serde_json::from_str(&out)
            .map_err(|e| ModuleError::Failed(format!("the handler returned invalid JSON: {e}")))
    }
}

struct ForeignPrompter(Arc<dyn ApprovalPrompter>);

#[async_trait]
impl Prompter for ForeignPrompter {
    async fn ask(&self, p: &ApprovalPrompt) -> bool {
        self.0
            .ask(ApprovalInfo {
                requester_id: p.requester.to_string(),
                target_device_id: p.target_device.to_string(),
                requester_name: p.requester_name.clone(),
                agent: p.agent.clone(),
                target_device_name: p.target_device_name.clone(),
                capability: p.capability.clone(),
                title: p.title.clone(),
                target: p.target.clone(),
                duration_minutes: p.lease_secs.div_ceil(60),
            })
            .await
    }
}

fn name_of(group: &Group, device: &DeviceId) -> String {
    group
        .membership()
        .members
        .get(device)
        .map(|m| m.name.clone())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------
// The device
// ---------------------------------------------------------------------------------------

struct Running {
    node: Arc<Node>,
    sync_loop: Option<tokio::task::JoinHandle<()>>,
    coord: Option<iroh::EndpointAddr>,
}

/// Capabilities declared by the app, and the handler that runs them.
type AppModule = (Vec<CapabilitySpec>, Arc<dyn CapabilityHandler>);

/// This device, as an app sees it.
#[derive(uniffi::Object)]
pub struct PasserDevice {
    home: PathBuf,
    identity: Arc<Identity>,
    modules: Mutex<Vec<AppModule>>,
    prompter: Mutex<Option<Arc<dyn ApprovalPrompter>>>,
    running: tokio::sync::Mutex<Option<Running>>,
}

impl PasserDevice {
    fn group_path(&self) -> PathBuf {
        self.home.join("group.json")
    }

    fn load_group(&self) -> Result<Group, PasserError> {
        if !self.group_path().exists() {
            return Err(PasserError::NoGroup);
        }
        Group::load(self.group_path()).map_err(PasserError::storage)
    }

    fn load_policy(&self) -> Result<Policy, PasserError> {
        match std::fs::read_to_string(self.home.join("policy.json")) {
            Ok(text) => serde_json::from_str(&text).map_err(PasserError::storage),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Policy::default()),
            Err(e) => Err(PasserError::storage(e)),
        }
    }

    async fn node(&self) -> Result<Arc<Node>, PasserError> {
        self.running
            .lock()
            .await
            .as_ref()
            .map(|r| r.node.clone())
            .ok_or(PasserError::NotStarted)
    }

    fn resolve(&self, group: &Group, query: &str) -> Result<DeviceId, PasserError> {
        let m = group.membership();
        let hits: Vec<DeviceId> = m
            .members
            .iter()
            .filter(|(id, member)| {
                member.name.eq_ignore_ascii_case(query) || id.to_string() == query
            })
            .map(|(id, _)| *id)
            .collect();
        match hits.as_slice() {
            [one] => Ok(*one),
            [] => Err(PasserError::invalid(format!("no member named \"{query}\""))),
            _ => Err(PasserError::invalid(format!(
                "several members are named \"{query}\"; use the id"
            ))),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl PasserDevice {
    /// Opens this device's storage in `home` (a private app directory) and loads its key
    /// from `vault`, creating it on first launch.
    #[uniffi::constructor]
    pub fn new(home: String, vault: Arc<dyn KeyVault>) -> Result<Arc<Self>, PasserError> {
        let home = PathBuf::from(home);
        std::fs::create_dir_all(&home).map_err(PasserError::storage)?;
        let identity = VaultStore(vault)
            .load_or_create()
            .map_err(PasserError::storage)?;
        Ok(Arc::new(Self {
            home,
            identity: Arc::new(identity),
            modules: Mutex::default(),
            prompter: Mutex::default(),
            running: tokio::sync::Mutex::default(),
        }))
    }

    /// This device's public id (hex).
    pub fn device_id(&self) -> String {
        self.identity.id().to_string()
    }

    pub fn has_group(&self) -> bool {
        self.group_path().exists()
    }

    /// Creates a new group with this device as its first approver.
    pub fn create_group(&self, group_name: String, device_name: String) -> Result<(), PasserError> {
        if self.has_group() {
            return Err(PasserError::AlreadyInGroup);
        }
        let log = DeviceLog::create(&self.identity, &group_name, &device_name, now_secs())
            .map_err(PasserError::invalid)?;
        Group::new(log, Some(self.group_path())).map_err(PasserError::storage)?;
        Ok(())
    }

    /// Joins a group with a link scanned from an approver's QR code.
    pub async fn join(
        &self,
        link: String,
        device_name: String,
        network: NetworkKind,
    ) -> Result<JoinResult, PasserError> {
        if self.has_group() {
            return Err(PasserError::AlreadyInGroup);
        }
        let invitation = Invitation::parse_link(&link).map_err(PasserError::invalid)?;
        let (log, sas) =
            passer_node::join(&self.identity, &invitation, &device_name, network.into())
                .await
                .map_err(PasserError::network)?;
        let group = Group::new(log, Some(self.group_path())).map_err(PasserError::storage)?;
        Ok(JoinResult {
            group_name: group.membership().name,
            sas,
        })
    }

    /// The group's members, as this device's verified log says.
    pub fn members(&self) -> Result<Vec<MemberInfo>, PasserError> {
        let me = self.identity.id();
        Ok(self
            .load_group()?
            .membership()
            .members
            .into_iter()
            .map(|(id, m)| MemberInfo {
                id: id.to_string(),
                name: m.name,
                approver: m.approver,
                this_device: id == me,
            })
            .collect())
    }

    /// Declares capabilities this app implements. Call before `start`.
    pub fn add_capabilities(
        &self,
        specs: Vec<CapabilitySpec>,
        handler: Arc<dyn CapabilityHandler>,
    ) {
        self.modules
            .lock()
            .expect("modules lock")
            .push((specs, handler));
    }

    /// How to ask this device's user for approvals. Call before `start`.
    pub fn set_approval_prompter(&self, prompter: Arc<dyn ApprovalPrompter>) {
        *self.prompter.lock().expect("prompter lock") = Some(prompter);
    }

    /// Starts serving: other members can reach this device. `coord` is a coordination
    /// server written `<id>@<ip:port>`.
    pub async fn start(
        &self,
        network: NetworkKind,
        coord: Option<String>,
    ) -> Result<(), PasserError> {
        let mut running = self.running.lock().await;
        if running.is_some() {
            return Ok(());
        }
        let group = Arc::new(self.load_group()?);
        let coord = coord
            .as_deref()
            .map(passer_coord::parse_server)
            .transpose()
            .map_err(PasserError::invalid)?;
        let prompter: Option<Arc<dyn Prompter>> = self
            .prompter
            .lock()
            .expect("prompter lock")
            .clone()
            .map(|p| Arc::new(ForeignPrompter(p)) as Arc<dyn Prompter>);
        let approver = RemoteApprover::new(group.clone(), prompter.clone());
        let me = name_of(&group, &self.identity.id());
        let mut builder = Bus::builder(group.clone())
            .module(Arc::new(passer_device_info::DeviceInfo::new(me)))
            .approver(approver.clone())
            .policy(self.load_policy()?)
            .journal(Arc::new(
                Journal::open(self.home.join("journal.jsonl")).map_err(PasserError::storage)?,
            ));
        if let Some(p) = prompter {
            builder = builder.module(Arc::new(ApprovalModule::new(group.clone(), p)));
        }
        for (specs, handler) in self.modules.lock().expect("modules lock").iter() {
            builder = builder.module(Arc::new(ForeignModule {
                specs: specs.clone(),
                handler: handler.clone(),
                group: group.clone(),
            }));
        }
        let bus = Arc::new(builder.build().map_err(PasserError::invalid)?);
        let options = NodeOptions {
            network: network.into(),
            on_admitted: None,
            approver: Some(approver),
        };
        let node = Arc::new(
            Node::spawn(self.identity.clone(), group, bus, options)
                .await
                .map_err(PasserError::network)?,
        );
        let sync_loop = coord.clone().map(|server| {
            passer_coord::spawn_sync_loop(node.clone(), server, Duration::from_secs(30))
        });
        *running = Some(Running {
            node,
            sync_loop,
            coord,
        });
        Ok(())
    }

    /// Stops serving. Running sessions are revoked.
    pub async fn stop(&self) {
        if let Some(r) = self.running.lock().await.take() {
            r.node.bus().leases().revoke_all("device stopped");
            if let Some(task) = r.sync_loop {
                task.abort();
                let _ = task.await;
            }
            if let Ok(node) = Arc::try_unwrap(r.node) {
                let _ = node.shutdown().await;
            }
        }
    }

    /// Direct addresses of this device (`ip:port`), once started.
    pub async fn addresses(&self) -> Result<Vec<String>, PasserError> {
        Ok(self
            .node()
            .await?
            .addr()
            .ip_addrs()
            .map(ToString::to_string)
            .collect())
    }

    /// Tells this device where another member can be reached directly (`ip:port`).
    pub async fn add_peer_address(
        &self,
        device: String,
        address: String,
    ) -> Result<(), PasserError> {
        let node = self.node().await?;
        let id = self.resolve(node.group(), &device)?;
        let sock = address.parse().map_err(PasserError::invalid)?;
        node.peers()
            .remember(iroh::EndpointAddr::new(id).with_ip_addr(sock));
        Ok(())
    }

    /// A one-time invitation for a new device. Only an approver can invite.
    pub async fn invite(&self, minutes: u32, as_approver: bool) -> Result<InviteInfo, PasserError> {
        let node = self.node().await?;
        let ttl = u64::from(minutes) * 60;
        let inv = if as_approver {
            node.invite_approver(ttl)
        } else {
            node.invite(ttl)
        }
        .map_err(PasserError::invalid)?;
        Ok(InviteInfo {
            link: inv.to_link(),
            expires_at: inv.expires_at,
        })
    }

    /// Calls a capability on another member (by name or id). Input and output are JSON.
    pub async fn call(
        &self,
        device: String,
        capability: String,
        input_json: String,
    ) -> Result<String, PasserError> {
        let node = self.node().await?;
        let id = self.resolve(node.group(), &device)?;
        let input: Value = if input_json.trim().is_empty() {
            Value::Object(Default::default())
        } else {
            serde_json::from_str(&input_json).map_err(PasserError::invalid)?
        };
        let addr = node.peers().addr_of(&id);
        match node
            .call(addr, Request::new(&capability, input))
            .await
            .map_err(PasserError::network)?
        {
            Response::Ok { output } => Ok(output.to_string()),
            Response::Error { code, message } => Err(PasserError::Refused {
                code: code.as_str().into(),
                message,
            }),
        }
    }

    /// Exchanges logs and addresses with the coordination server now.
    pub async fn sync(&self) -> Result<(), PasserError> {
        let running = self.running.lock().await;
        let r = running.as_ref().ok_or(PasserError::NotStarted)?;
        let server = r
            .coord
            .clone()
            .ok_or_else(|| PasserError::invalid("no coordination server configured"))?;
        passer_coord::sync(&r.node, server)
            .await
            .map_err(PasserError::network)?;
        Ok(())
    }

    /// Removes a device from the group (approvers; or this device leaving).
    pub async fn remove_device(&self, device: String) -> Result<(), PasserError> {
        let node = self.node().await?;
        let id = self.resolve(node.group(), &device)?;
        node.remove(id).map_err(PasserError::invalid)
    }

    /// The stop button: ends every session running on this device.
    pub async fn stop_all_sessions(&self) -> Result<(), PasserError> {
        self.node()
            .await?
            .bus()
            .leases()
            .revoke_all("stopped by the user");
        Ok(())
    }
}
