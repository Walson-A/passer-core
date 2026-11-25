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

#![warn(missing_docs)]

mod files;
mod members;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
pub use files::StreamKind;
use members::MemberCache;
/// The bus types a Rust host needs for `add_module`, `set_indicator` and `open_stream`.
pub use passer_bus;
use passer_bus::{
    Bus, Capability, Ctx, Effect, Event, IndicatorRequirement, Journal, Manifest, Mode, Module,
    ModuleError, Policy, Request, Response, StreamIo,
};
use passer_identity::{DeviceId, Identity, IdentityError, KeyStore};
use passer_membership::DeviceLog;
use passer_membership::pairing::Invitation;
pub use passer_node::OpenStream;
use passer_node::approval::{ApprovalModule, ApprovalPrompt, Prompter, RemoteApprover};
use passer_node::{Group, Network, Node, NodeOptions, now_secs};
use serde_json::Value;

uniffi::setup_scaffolding!();

/// Everything that can go wrong, in terms an app can show or act on.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PasserError {
    /// This device's files (key, group, journal) could not be read or written.
    #[error("storage error: {message}")]
    Storage {
        /// What went wrong, for logs.
        message: String,
    },
    /// The call needs a group: create or join one first.
    #[error("this device does not belong to a group yet")]
    NoGroup,
    /// `create_group` or `join` on a device that already has a group.
    #[error("this device already belongs to a group")]
    AlreadyInGroup,
    /// The call needs a running device: call `start` first.
    #[error("the device is not started")]
    NotStarted,
    /// A bad argument: an unknown or ambiguous member, malformed JSON, a bad link or URL.
    #[error("invalid: {message}")]
    Invalid {
        /// What was wrong, for logs or display.
        message: String,
    },
    /// The other device or the server could not be reached, or the connection broke.
    #[error("network error: {message}")]
    Network {
        /// What went wrong, for logs.
        message: String,
    },
    /// The other device answered, and said no (or failed). `code` is stable, e.g.
    /// `denied`, `not_member`, `approval_timeout`, `invalid_input`.
    #[error("{code}: {message}")]
    Refused {
        /// Stable error code, to act on.
        code: String,
        /// Explanation from the other device. Untrusted text: display it, never act on it.
        message: String,
    },
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
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NetworkKind {
    /// Direct addresses only (same network, or addresses from a coordination server).
    LocalOnly,
    /// Your own relay (`https://...`), for devices on different networks. Pair it with a
    /// coordination server so devices find each other. See docs/self-hosting.md.
    Relay {
        /// The relay's URL, e.g. `https://relay.example.com`.
        url: String,
    },
    /// n0's public relays and lookup. Development only.
    N0Dev,
}

impl TryFrom<NetworkKind> for Network {
    type Error = PasserError;

    fn try_from(n: NetworkKind) -> Result<Self, PasserError> {
        Ok(match n {
            NetworkKind::LocalOnly => Network::LocalOnly,
            NetworkKind::N0Dev => Network::N0Dev,
            NetworkKind::Relay { url } => Network::Relay(
                url.parse()
                    .map_err(|e| PasserError::invalid(format!("relay URL: {e}")))?,
            ),
        })
    }
}

/// What a capability does to the device, which sets its default permission: members may
/// call `Read` and `Write`; `Sensitive` asks a human first. Agents get nothing unless
/// granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EffectKind {
    /// Only reads, changes nothing (e.g. device info, list files).
    Read,
    /// Changes something on the device (e.g. receive a file).
    Write,
    /// Touches private data or acts for the user (e.g. read the clipboard): asks first.
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
    /// Short human name, shown in approvals and device screens.
    pub title: String,
    /// What it does, in a sentence. Agents read it too.
    pub description: String,
    /// JSON Schema of the input, as a JSON string.
    pub input_schema_json: String,
    /// What it does to the device, which sets who may call it by default.
    pub effect: EffectKind,
    /// Kind of target the capability acts on, if any (e.g. `app`, `folder`).
    pub target_kind: Option<String>,
    /// The device must show a visible indicator while it runs.
    pub indicator_required: bool,
    /// Set for a capability that moves a file: the caller sends one (`Upload`, see
    /// [`CapabilityHandler::receive_file`]) or gets one (`Download`, see
    /// [`CapabilityHandler::provide_file`]). `None`: a call with a JSON answer.
    pub stream: Option<StreamKind>,
    /// Largest upload accepted, in bytes (default 4 GiB).
    pub max_bytes: Option<u64>,
}

/// What sort of device a member is. The app tells the core for its own device
/// ([`PasserDevice::set_device_details`]); other members say it themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceKind {
    /// A phone.
    Phone,
    /// A tablet.
    Tablet,
    /// A laptop.
    Laptop,
    /// A desktop computer.
    Desktop,
    /// Not said yet, or a kind this version does not know.
    Unknown,
}

impl From<DeviceKind> for passer_device_info::DeviceKind {
    fn from(k: DeviceKind) -> Self {
        match k {
            DeviceKind::Phone => Self::Phone,
            DeviceKind::Tablet => Self::Tablet,
            DeviceKind::Laptop => Self::Laptop,
            DeviceKind::Desktop => Self::Desktop,
            DeviceKind::Unknown => Self::Unknown,
        }
    }
}

impl From<passer_device_info::DeviceKind> for DeviceKind {
    fn from(k: passer_device_info::DeviceKind) -> Self {
        use passer_device_info::DeviceKind as K;
        match k {
            K::Phone => Self::Phone,
            K::Tablet => Self::Tablet,
            K::Laptop => Self::Laptop,
            K::Desktop => Self::Desktop,
            K::Unknown => Self::Unknown,
        }
    }
}

/// A member of the group: who it is (from the verified device log), and what it last
/// said about itself (from the member cache, refreshed by
/// [`PasserDevice::refresh_members`]). The descriptive fields come from that device and
/// are only for display.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MemberInfo {
    /// The device's public id (hex). Cannot be faked: show a short form next to the name.
    pub id: String,
    /// Its name in the group, unique in the group.
    pub name: String,
    /// It can invite devices, remove them, and approve sensitive requests.
    pub approver: bool,
    /// This is the device the app runs on.
    pub this_device: bool,
    /// What sort of device it says it is.
    pub kind: DeviceKind,
    /// `windows`, `macos`, `ios`, `android`, `linux`...
    pub os: Option<String>,
    /// Its OS version, as its app reported it.
    pub os_version: Option<String>,
    /// Its app's version, as its app reported it.
    pub app_version: Option<String>,
    /// The passer-core version it runs.
    pub core_version: Option<String>,
    /// When it last answered this device (Unix seconds). `None`: never, or this device.
    pub answered_at: Option<u64>,
}

/// A capability another member lets this device call, as it last said.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OfferedCapability {
    /// Dotted name to pass to [`PasserDevice::call`], e.g. `clipboard.read`.
    pub name: String,
    /// Short human name, for a button.
    pub title: String,
    /// What it does, in a sentence.
    pub description: String,
    /// What it does to that device.
    pub effect: EffectKind,
    /// Kind of target it acts on, if any (e.g. `app`, `folder`).
    pub target_kind: Option<String>,
    /// A human on an approver device approves each session first.
    pub needs_approval: bool,
}

/// One line of this device's journal. Never holds what was sent or received.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct JournalEntry {
    /// Position in this device's journal, increasing.
    pub seq: u64,
    /// Unix seconds.
    pub at: u64,
    /// `true`: this device called `peer_id`. `false`: `peer_id` called this device.
    pub outgoing: bool,
    /// The other device's id (hex).
    pub peer_id: String,
    /// The peer's current name in the group, empty if it has left.
    pub peer_name: String,
    /// The AI agent that made the call through the peer, if any.
    pub agent: Option<String>,
    /// The capability called, e.g. `file.drop`.
    pub capability: String,
    /// The target it acted on, if any.
    pub target: Option<String>,
    /// On received calls: `allow`, `ask` or `deny` before any approval (`none` when the
    /// call was refused before the policy, e.g. an unknown capability, and on calls this
    /// device made).
    pub decision: String,
    /// Set when a human was asked.
    pub approved: Option<bool>,
    /// `ok`, or an error code such as `denied`, `approval_timeout` or `unreachable`.
    pub outcome: String,
}

/// A one-time invitation, from [`PasserDevice::invite`].
#[derive(Clone, Debug, uniffi::Record)]
pub struct InviteInfo {
    /// Show as a QR code. Contains a one-time secret: never share or screenshot it.
    pub link: String,
    /// When the link stops working (Unix seconds).
    pub expires_at: u64,
}

/// The outcome of [`PasserDevice::join`].
#[derive(Clone, Debug, uniffi::Record)]
pub struct JoinResult {
    /// The name of the group joined.
    pub group_name: String,
    /// Six digits the inviting device also shows. If they differ, cancel.
    pub sas: String,
}

/// Who is calling a capability on this device.
#[derive(Clone, Debug, uniffi::Record)]
pub struct CallerInfo {
    /// The calling device's id (hex), authenticated by the connection.
    pub device_id: String,
    /// Its name in this device's copy of the group.
    pub device_name: String,
    /// Set when an AI agent asks through that device.
    pub agent: Option<String>,
}

/// What the user is asked to approve.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ApprovalInfo {
    /// Show a short form of the ids too: names are unique in a group, ids cannot be faked.
    pub requester_id: String,
    /// The requesting device's name in this device's copy of the group.
    pub requester_name: String,
    /// The AI agent asking through the requesting device, if any.
    pub agent: Option<String>,
    /// The id (hex) of the device that would act.
    pub target_device_id: String,
    /// The device that would act.
    pub target_device_name: String,
    /// The capability asked for, e.g. `clipboard.read`.
    pub capability: String,
    /// Its human title.
    pub title: String,
    /// The target it would act on, if any.
    pub target: Option<String>,
    /// How long the approval lasts, in minutes (rounded up).
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

/// Told when a new device has joined through one of this device's invitations.
#[uniffi::export(with_foreign)]
pub trait AdmissionListener: Send + Sync {
    /// `sas` is the 6-digit code the new device also shows: ask the user to compare.
    fn admitted(&self, device_id: String, device_name: String, sas: String);
}

/// Asks the person using this device. Implemented natively (sheet, notification).
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait ApprovalPrompter: Send + Sync {
    /// Shows `request` and returns `true` if the user approves. Unanswered after 60 s
    /// counts as no.
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

    /// An `Upload` capability received a whole file, at `path` in this device's private
    /// folder. Move or copy it where it belongs before returning: whatever is left at
    /// `path` is deleted. Returns the output as a JSON string. Incomplete files never
    /// reach this method.
    async fn receive_file(
        &self,
        capability: String,
        target: Option<String>,
        input_json: String,
        caller: CallerInfo,
        path: String,
    ) -> Result<String, PasserError>;

    /// A `Download` capability: returns the path of the file to send.
    async fn provide_file(
        &self,
        capability: String,
        target: Option<String>,
        input_json: String,
        caller: CallerInfo,
    ) -> Result<String, PasserError>;
}

/// Told how far a file transfer has gone: `done` bytes so far, out of `total` when
/// known (uploads). Called at most once per MiB, and once at the end.
#[uniffi::export(with_foreign)]
pub trait TransferProgress: Send + Sync {
    /// `done` bytes transferred so far, out of `total` bytes when known.
    fn progress(&self, done: u64, total: Option<u64>);
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
    /// Where uploads land before the handler takes them.
    incoming: PathBuf,
}

impl ForeignModule {
    fn caller(&self, ctx: &Ctx) -> CallerInfo {
        CallerInfo {
            device_id: ctx.subject.device.to_string(),
            device_name: name_of(&self.group, &ctx.subject.device),
            agent: ctx.subject.agent.clone(),
        }
    }
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
                if s.stream.is_some() {
                    cap.mode = Mode::Stream;
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

    async fn invoke_stream(
        &self,
        ctx: Ctx,
        capability: &str,
        input: Value,
        io: StreamIo,
    ) -> Result<Value, ModuleError> {
        let spec = self
            .specs
            .iter()
            .find(|s| s.name == capability)
            .ok_or_else(|| ModuleError::Unsupported(capability.to_owned()))?;
        let call = (
            capability.to_owned(),
            ctx.target.clone(),
            input.to_string(),
            self.caller(&ctx),
        );
        match spec.stream {
            Some(StreamKind::Upload) => {
                let max = spec.max_bytes.unwrap_or(files::DEFAULT_MAX_BYTES);
                let out = files::receive(io, &self.incoming, max, &self.handler, call)
                    .await
                    .map_err(ModuleError::Failed)?;
                serde_json::from_str(&out).map_err(|e| {
                    ModuleError::Failed(format!("the handler returned invalid JSON: {e}"))
                })
            }
            Some(StreamKind::Download) => {
                let bytes = files::provide(io, &self.handler, call)
                    .await
                    .map_err(ModuleError::Failed)?;
                Ok(serde_json::json!({ "bytes": bytes }))
            }
            None => Err(ModuleError::Unsupported(capability.to_owned())),
        }
    }

    async fn invoke(&self, ctx: Ctx, capability: &str, input: Value) -> Result<Value, ModuleError> {
        let caller = self.caller(&ctx);
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

fn parse_input(input_json: &str) -> Result<Value, PasserError> {
    if input_json.trim().is_empty() {
        Ok(Value::Object(Default::default()))
    } else {
        serde_json::from_str(input_json).map_err(PasserError::invalid)
    }
}

/// The target's answer, as the app sees it.
fn answer(response: Response) -> Result<String, PasserError> {
    match response {
        Response::Ok { output } => Ok(output.to_string()),
        Response::Error { code, message } => Err(PasserError::Refused {
            code: code.as_str().into(),
            message,
        }),
    }
}

// ---------------------------------------------------------------------------------------
// The device
// ---------------------------------------------------------------------------------------

struct Running {
    node: Arc<Node>,
    sync_loop: Option<tokio::task::JoinHandle<()>>,
    refresh: tokio::task::JoinHandle<()>,
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
    admissions: Mutex<Option<Arc<dyn AdmissionListener>>>,
    details: Mutex<passer_device_info::Details>,
    cache: Arc<MemberCache>,
    /// The push token to publish at the next sync (`Some("")` removes it).
    push: Arc<Mutex<Option<String>>>,
    running: tokio::sync::Mutex<Option<Running>>,
    /// Modules a Rust host adds directly (see [`PasserDevice::add_module`]).
    rust_modules: Mutex<Vec<Arc<dyn Module>>>,
    /// The host's visible sign that a capability is running (see `set_indicator`).
    indicator: Mutex<Option<Arc<dyn passer_bus::Indicator>>>,
}

/// For Rust hosts (desktop apps): what UniFFI cannot carry, such as raw byte streams.
/// Swift and Kotlin apps use the exported API instead.
impl PasserDevice {
    /// Adds a module written in Rust (any [`passer_bus::Module`], e.g. `passer_exec::Exec`
    /// or `passer_files::Files`). Call before `start`.
    pub fn add_module(&self, module: Arc<dyn Module>) {
        self.rust_modules.lock().expect("modules lock").push(module);
    }

    /// The device's indicator: shown while a capability that requires one runs (a screen
    /// being viewed, say), hidden when its session ends. Without one, such capabilities
    /// refuse to run. Call before `start`.
    pub fn set_indicator(&self, indicator: Arc<dyn passer_bus::Indicator>) {
        *self.indicator.lock().expect("indicator lock") = Some(indicator);
    }

    /// Opens a stream capability on another member (by name or id): send with
    /// `io.outgoing`, receive with `io.incoming`, then await `done` for the target's
    /// result. A refusal (not allowed, approval denied...) is `PasserError::Refused`.
    pub async fn open_stream(
        &self,
        device: String,
        capability: String,
        input_json: String,
    ) -> Result<passer_node::OpenStream, PasserError> {
        let node = self.node().await?;
        let id = self.resolve(node.group(), &device)?;
        let input = parse_input(&input_json)?;
        let opened = self
            .reaching(&node, id, || {
                let (node, input) = (node.clone(), input.clone());
                let capability = capability.clone();
                async move {
                    node.open_stream(
                        node.peers().addr_of(&id),
                        Request::stream(&capability, input),
                    )
                    .await
                    .map_err(PasserError::network)
                }
            })
            .await;
        let journaled = match &opened {
            Ok(Ok(_)) => Ok(Response::stream_open()),
            Ok(Err(refusal)) => Ok(refusal.clone()),
            Err(e) => Err(PasserError::Network {
                message: e.to_string(),
            }),
        };
        self.journal_outgoing(&node, &id, &capability, &journaled);
        match opened? {
            Ok(open) => Ok(open),
            Err(refusal) => answer(refusal).map(|_| unreachable!("a refusal is an error")),
        }
    }

    /// The name of a member, by its id (hex), from this device's verified log.
    pub fn member_name(&self, id: &str) -> Option<String> {
        let group = self.load_group().ok()?;
        let id: DeviceId = id.parse().ok()?;
        group.membership().members.get(&id).map(|m| m.name.clone())
    }
}

impl PasserDevice {
    fn with_identity(home: PathBuf, identity: Identity) -> Arc<Self> {
        Arc::new(Self {
            cache: MemberCache::open(home.join("members.json")),
            home,
            identity: Arc::new(identity),
            modules: Mutex::default(),
            prompter: Mutex::default(),
            admissions: Mutex::default(),
            details: Mutex::default(),
            push: Arc::default(),
            running: tokio::sync::Mutex::default(),
            rust_modules: Mutex::default(),
            indicator: Mutex::default(),
        })
    }

    /// Runs `attempt`; if the device cannot be reached and a coordination server is
    /// configured, asks the server to wake it (a push to the phone) and tries again for a
    /// few seconds. Only connecting is retried, never a transfer under way.
    async fn reaching<T, F, Fut>(
        &self,
        node: &Arc<Node>,
        device: DeviceId,
        attempt: F,
    ) -> Result<T, PasserError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, PasserError>>,
    {
        let first = attempt().await;
        if !matches!(first, Err(PasserError::Network { .. })) {
            return first;
        }
        let server = self
            .running
            .lock()
            .await
            .as_ref()
            .and_then(|r| r.coord.clone());
        let Some(server) = server else {
            return first;
        };
        if !passer_coord::wake(node, server, device)
            .await
            .unwrap_or(false)
        {
            return first;
        }
        let mut last = first;
        for secs in [2, 3, 4, 5, 6] {
            tokio::time::sleep(Duration::from_secs(secs)).await;
            last = attempt().await;
            if !matches!(last, Err(PasserError::Network { .. })) {
                return last;
            }
        }
        last
    }

    fn journal_path(&self) -> PathBuf {
        self.home.join("journal.jsonl")
    }

    /// One line for each call or transfer this device makes, like the ones it receives.
    fn journal_outgoing(
        &self,
        node: &Node,
        to: &DeviceId,
        capability: &str,
        result: &Result<Response, PasserError>,
    ) {
        let outcome = match result {
            Ok(Response::Ok { .. }) => "ok".to_owned(),
            Ok(Response::Error { code, .. }) => code.as_str().to_owned(),
            Err(PasserError::Network { .. }) => "unreachable".to_owned(),
            Err(_) => "failed".to_owned(),
        };
        if let Err(e) = node.bus().journal().append(Event {
            device: self.identity.id().to_string(),
            to: Some(to.to_string()),
            capability: passer_bus::printable(capability, 96),
            decision: "none".into(),
            outcome,
            ..Default::default()
        }) {
            tracing::error!("journal write failed: {e}");
        }
    }

    /// For desktop apps written in Rust: the key is kept by the platform's store
    /// (DPAPI on Windows; a file elsewhere until Keychain and Secret Service land), in
    /// `home/device.key`.
    pub fn open_on_desktop(home: impl Into<PathBuf>) -> Result<Arc<Self>, PasserError> {
        let home = home.into();
        std::fs::create_dir_all(&home).map_err(PasserError::storage)?;
        let identity = passer_identity::platform_store(home.join("device.key"))
            .load_or_create()
            .map_err(PasserError::storage)?;
        Ok(Self::with_identity(home, identity))
    }

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
        Ok(Self::with_identity(home, identity))
    }

    /// This device's public id (hex).
    pub fn device_id(&self) -> String {
        self.identity.id().to_string()
    }

    /// Whether this device belongs to a group (created or joined).
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
        let (log, sas) = passer_node::join(
            &self.identity,
            &invitation,
            &device_name,
            Network::try_from(network)?,
        )
        .await
        .map_err(PasserError::network)?;
        let group = Group::new(log, Some(self.group_path())).map_err(PasserError::storage)?;
        Ok(JoinResult {
            group_name: group.membership().name,
            sas,
        })
    }

    /// The group's members, as this device's verified log says, with what each last said
    /// about itself.
    pub fn members(&self) -> Result<Vec<MemberInfo>, PasserError> {
        let me = self.identity.id();
        let mine = self.details.lock().expect("details lock").clone();
        Ok(self
            .load_group()?
            .membership()
            .members
            .into_iter()
            .map(|(id, m)| {
                let mut info = MemberInfo {
                    id: id.to_string(),
                    name: m.name,
                    approver: m.approver,
                    this_device: id == me,
                    kind: DeviceKind::Unknown,
                    os: None,
                    os_version: None,
                    app_version: None,
                    core_version: None,
                    answered_at: None,
                };
                if id == me {
                    info.kind = mine.kind.into();
                    info.os = Some(std::env::consts::OS.into());
                    info.os_version = mine.os_version.clone();
                    info.app_version = mine.app_version.clone();
                    info.core_version = Some(env!("CARGO_PKG_VERSION").into());
                } else if let Some(entry) = self.cache.get(&id) {
                    info.answered_at = Some(entry.answered_at);
                    if let Some(d) = entry.described {
                        info.kind = passer_device_info::DeviceKind::parse(&d.kind).into();
                        info.os = d.os;
                        info.os_version = d.os_version;
                        info.app_version = d.app_version;
                        info.core_version = d.core_version;
                    }
                }
                info
            })
            .collect())
    }

    /// Describes this device to the others: its kind, OS version and app version. Call
    /// before `start`.
    pub fn set_device_details(
        &self,
        kind: DeviceKind,
        os_version: Option<String>,
        app_version: Option<String>,
    ) {
        *self.details.lock().expect("details lock") = passer_device_info::Details {
            kind: kind.into(),
            os_version: os_version.map(|v| passer_bus::printable(&v, 64)),
            app_version: app_version.map(|v| passer_bus::printable(&v, 64)),
        };
    }

    /// Asks every other member, now, what it is and what it offers this device. Returns
    /// how many answered. `start` runs one in the background; call it again after a
    /// device joins, or when the app comes back to the foreground.
    pub async fn refresh_members(&self) -> Result<u32, PasserError> {
        let node = self.node().await?;
        Ok(self.cache.refresh(&node).await)
    }

    /// What another member (by name or id) lets this device call, as it last said.
    /// Empty until it has answered a refresh.
    pub fn member_capabilities(
        &self,
        device: String,
    ) -> Result<Vec<OfferedCapability>, PasserError> {
        let group = self.load_group()?;
        let id = self.resolve(&group, &device)?;
        Ok(self
            .cache
            .get(&id)
            .map(|e| e.offered)
            .unwrap_or_default()
            .into_iter()
            .map(|o| OfferedCapability {
                effect: match o.effect.as_str() {
                    "read" => EffectKind::Read,
                    "write" => EffectKind::Write,
                    _ => EffectKind::Sensitive,
                },
                name: o.name,
                title: o.title,
                description: o.description,
                target_kind: o.target_kind,
                needs_approval: o.needs_approval,
            })
            .collect())
    }

    /// The most recent lines of this device's journal (at most 200 are kept for display),
    /// newest first, optionally only those with one member (by name or id).
    pub async fn journal_recent(
        &self,
        limit: u32,
        device: Option<String>,
    ) -> Result<Vec<JournalEntry>, PasserError> {
        let group = self.load_group()?;
        let only = device
            .map(|d| self.resolve(&group, &d).map(|id| id.to_string()))
            .transpose()?;
        let lines = match self.running.lock().await.as_ref() {
            Some(r) => r.node.bus().journal().recent(),
            None if self.journal_path().exists() => Journal::open(self.journal_path())
                .map_err(PasserError::storage)?
                .recent(),
            None => Vec::new(),
        };
        let members = group.membership().members;
        Ok(lines
            .into_iter()
            .rev()
            .map(|l| l.record)
            .map(|r| {
                let outgoing = r.to.is_some();
                let peer_id = r.to.clone().unwrap_or_else(|| r.device.clone());
                let peer_name = peer_id
                    .parse::<DeviceId>()
                    .ok()
                    .and_then(|id| members.get(&id))
                    .map(|m| m.name.clone())
                    .unwrap_or_default();
                JournalEntry {
                    seq: r.seq,
                    at: r.at,
                    outgoing,
                    peer_id,
                    peer_name,
                    agent: r.agent,
                    capability: r.capability,
                    target: r.target,
                    decision: r.decision,
                    approved: r.approved,
                    outcome: r.outcome,
                }
            })
            .filter(|e| only.as_ref().is_none_or(|id| *id == e.peer_id))
            .take(limit as usize)
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

    /// Who to tell when a device joins through this device's invitations. Call before
    /// `start`.
    pub fn set_admission_listener(&self, listener: Arc<dyn AdmissionListener>) {
        *self.admissions.lock().expect("admissions lock") = Some(listener);
    }

    /// The group's name, if this device belongs to one.
    pub fn group_name(&self) -> Option<String> {
        self.load_group().ok().map(|g| g.membership().name)
    }

    /// Whether the device is started.
    pub async fn is_running(&self) -> bool {
        self.running.lock().await.is_some()
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
        let details = self.details.lock().expect("details lock").clone();
        let mut builder = Bus::builder(group.clone())
            .module(Arc::new(
                passer_device_info::DeviceInfo::new(me).with_details(details),
            ))
            .approver(approver.clone())
            .policy(self.load_policy()?)
            .journal(Arc::new(
                Journal::open(self.journal_path()).map_err(PasserError::storage)?,
            ));
        if let Some(p) = prompter {
            builder = builder.module(Arc::new(ApprovalModule::new(group.clone(), p)));
        }
        for (specs, handler) in self.modules.lock().expect("modules lock").iter() {
            builder = builder.module(Arc::new(ForeignModule {
                specs: specs.clone(),
                handler: handler.clone(),
                group: group.clone(),
                incoming: self.home.join("incoming"),
            }));
        }
        for module in self.rust_modules.lock().expect("modules lock").iter() {
            builder = builder.module(module.clone());
        }
        if let Some(indicator) = self.indicator.lock().expect("indicator lock").clone() {
            builder = builder.indicator(indicator);
        }
        let bus = Arc::new(builder.build().map_err(PasserError::invalid)?);
        let options = NodeOptions {
            network: Network::try_from(network)?,
            on_admitted: self
                .admissions
                .lock()
                .expect("admissions lock")
                .clone()
                .map(|l| {
                    Arc::new(move |id: DeviceId, name: &str, sas: &str| {
                        l.admitted(id.to_string(), name.to_owned(), sas.to_owned())
                    }) as passer_node::AdmissionHook
                }),
            approver: Some(approver),
        };
        let node = Arc::new(
            Node::spawn(self.identity.clone(), group, bus, options)
                .await
                .map_err(PasserError::network)?,
        );
        let sync_loop = coord.clone().map(|server| {
            passer_coord::spawn_sync_loop_with(
                node.clone(),
                server,
                Duration::from_secs(30),
                self.push.clone(),
            )
        });
        // What the other members are and offer, for the UI: in the background, so that
        // `start` does not wait for devices that are asleep.
        let refresh = {
            let (cache, node) = (self.cache.clone(), node.clone());
            tokio::spawn(async move {
                cache.refresh(&node).await;
            })
        };
        *running = Some(Running {
            node,
            sync_loop,
            refresh,
            coord,
        });
        Ok(())
    }

    /// Stops serving. Running sessions are revoked.
    pub async fn stop(&self) {
        if let Some(r) = self.running.lock().await.take() {
            r.node.bus().leases().revoke_all("device stopped");
            r.refresh.abort();
            let _ = r.refresh.await;
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
        let input = parse_input(&input_json)?;
        let result = self
            .reaching(&node, id, || {
                let (node, input) = (node.clone(), input.clone());
                let capability = capability.clone();
                async move {
                    node.call(node.peers().addr_of(&id), Request::new(&capability, input))
                        .await
                        .map_err(PasserError::network)
                }
            })
            .await;
        self.journal_outgoing(&node, &id, &capability, &result);
        answer(result?)
    }

    /// Sends the file at `path` to an `Upload` capability of another member (by name or
    /// id). Returns the target's output as JSON. The target only hands the file to its
    /// app once all of it arrived.
    pub async fn send_file(
        &self,
        device: String,
        capability: String,
        input_json: String,
        path: String,
        progress: Option<Arc<dyn TransferProgress>>,
    ) -> Result<String, PasserError> {
        let node = self.node().await?;
        let id = self.resolve(node.group(), &device)?;
        let input = parse_input(&input_json)?;
        let opened = self
            .reaching(&node, id, || {
                let (node, input) = (node.clone(), input.clone());
                let capability = capability.clone();
                async move {
                    node.open_stream(
                        node.peers().addr_of(&id),
                        Request::stream(&capability, input),
                    )
                    .await
                    .map_err(PasserError::network)
                }
            })
            .await;
        let result = match opened {
            Err(e) => Err(e),
            Ok(Err(refusal)) => Ok(refusal),
            Ok(Ok(open)) => {
                let passer_node::OpenStream { io, done } = open;
                let StreamIo { incoming, outgoing } = io;
                let sent = files::send(outgoing, std::path::Path::new(&path), progress).await;
                drop(incoming);
                match sent {
                    Err(e) => {
                        done.abort();
                        Err(e)
                    }
                    Ok(_) => match done.await {
                        Ok(Ok(response)) => Ok(response),
                        Ok(Err(e)) => Err(PasserError::network(e)),
                        Err(e) => Err(PasserError::network(e)),
                    },
                }
            }
        };
        self.journal_outgoing(&node, &id, &capability, &result);
        answer(result?)
    }

    /// Gets a file from a `Download` capability of another member (by name or id) into
    /// `destination`, which appears only once the whole file arrived. Returns the
    /// target's output as JSON (`{"bytes": n}`).
    pub async fn fetch_file(
        &self,
        device: String,
        capability: String,
        input_json: String,
        destination: String,
        progress: Option<Arc<dyn TransferProgress>>,
    ) -> Result<String, PasserError> {
        let node = self.node().await?;
        let id = self.resolve(node.group(), &device)?;
        let input = parse_input(&input_json)?;
        let destination = PathBuf::from(destination);
        let mut part = destination.clone().into_os_string();
        part.push(".part");
        let part = PathBuf::from(part);
        let opened = self
            .reaching(&node, id, || {
                let (node, input) = (node.clone(), input.clone());
                let capability = capability.clone();
                async move {
                    node.open_stream(
                        node.peers().addr_of(&id),
                        Request::stream(&capability, input),
                    )
                    .await
                    .map_err(PasserError::network)
                }
            })
            .await;
        let result = match opened {
            Err(e) => Err(e),
            Ok(Err(refusal)) => Ok(refusal),
            Ok(Ok(open)) => {
                let passer_node::OpenStream { io, done } = open;
                let StreamIo { incoming, outgoing } = io;
                drop(outgoing);
                let complete = files::fetch(incoming, &part, progress).await;
                let response = done.await;
                match (complete, response) {
                    (Ok(true), Ok(Ok(response @ Response::Ok { .. }))) => {
                        std::fs::rename(&part, &destination).map_err(PasserError::storage)?;
                        Ok(response)
                    }
                    (Err(e), _) => Err(e),
                    (_, Ok(Ok(response @ Response::Error { .. }))) => Ok(response),
                    (_, Ok(Err(e))) => Err(PasserError::network(e)),
                    (_, Err(e)) => Err(PasserError::network(e)),
                    (Ok(_), Ok(Ok(_))) => Err(PasserError::Network {
                        message: "the stream broke before the file was complete".into(),
                    }),
                }
            }
        };
        if !matches!(result, Ok(Response::Ok { .. })) {
            let _ = std::fs::remove_file(&part);
        }
        self.journal_outgoing(&node, &id, &capability, &result);
        answer(result?)
    }

    /// The push token the system gave this app (APNs, FCM), so that other members can
    /// wake this device through the coordination server when it sleeps; `None` stops
    /// that. Published at the next sync (`sync` publishes it now). When woken, start the
    /// device for a moment so it can answer.
    pub fn set_push_token(&self, token: Option<String>) {
        *self.push.lock().expect("push lock") = Some(token.unwrap_or_default());
    }

    /// Exchanges logs and addresses with the coordination server now.
    pub async fn sync(&self) -> Result<(), PasserError> {
        let running = self.running.lock().await;
        let r = running.as_ref().ok_or(PasserError::NotStarted)?;
        let server = r
            .coord
            .clone()
            .ok_or_else(|| PasserError::invalid("no coordination server configured"))?;
        let token = self.push.lock().expect("push lock").clone();
        passer_coord::sync_with(&r.node, server, token)
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

    /// Applies `policy.json` again, after the app changed it: new requests follow the new
    /// rules at once, and sessions already running are left as they are (stop them with
    /// `stop_all_sessions` if a rule now forbids them). Does nothing before `start`, which
    /// reads the file anyway.
    pub async fn reload_policy(&self) -> Result<(), PasserError> {
        let policy = self.load_policy()?;
        if let Some(r) = self.running.lock().await.as_ref() {
            r.node.bus().set_policy(policy);
        }
        Ok(())
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
