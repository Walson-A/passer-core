//! The capability bus: the single point every invocation goes through on the target
//! device.
//!
//! A module declares [`Capability`]s and implements [`Module::invoke`]. It never checks
//! permissions itself: the [`Bus`] does, in this order, before calling it:
//!
//! 1. the requester is a member of the group (authenticated by the transport);
//! 2. the capability exists, the target is consistent, the input matches its schema;
//! 3. the [`Policy`] decides allow / ask / deny; `ask` goes to an [`Approver`] (a human,
//!    on an approver device);
//! 4. a capability that requires an indicator runs only if an [`Indicator`] is installed,
//!    and the indicator is shown for as long as the lease lives;
//! 5. the invocation runs inside a [`LeaseHandle`], which the device can suspend or revoke;
//! 6. one line goes to the [`Journal`], without any content.
//!
//! A `call` capability answers once ([`Bus::handle`]). A `stream` capability goes through
//! the same checks ([`Bus::open`]), then exchanges bytes both ways for as long as its
//! lease lives ([`Session::run_stream`], [`stream`]).

#![warn(missing_docs)]

pub mod capability;
pub mod journal;
pub mod lease;
pub mod policy;
pub mod stream;
pub mod wire;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use passer_identity::DeviceId;
use serde_json::{Value, json};

pub use capability::{Capability, Effect, IndicatorRequirement, Manifest, Mode};
pub use journal::{Event, Journal};
pub use lease::{EndReason, LeaseHandle, LeaseInfo, LeaseState, Leases};
pub use policy::{Decision, Policy, Rule, Subject, Verdict, Who};
pub use stream::{StreamBroken, StreamClosed, StreamIo};
pub use wire::{ErrorCode, Request, Response};

/// Name of the built-in capability that lists what the requester may call.
pub const LIST_CAPABILITY: &str = "bus.capabilities";
/// How long a human has to answer an approval request.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest accepted target string.
pub const MAX_TARGET_LEN: usize = 256;

/// One entry of `bus.capabilities`: the capability, and the decision the policy gives
/// the requester when no target is involved. Readers that only know [`Capability`] ignore
/// `decision`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Listed {
    /// The capability as its module declares it.
    #[serde(flatten)]
    pub capability: Capability,
    /// `allow` or `ask` for this requester. Denied capabilities are not listed.
    pub decision: Decision,
}

/// Read access to the group's membership, provided by whoever owns the device log.
pub trait MembershipView: Send + Sync {
    /// Whether `device` is a member of the group right now.
    fn is_member(&self, device: &DeviceId) -> bool;
}

/// What an approver device is asked.
#[derive(Clone, Debug)]
pub struct ApprovalRequest {
    /// Who asks.
    pub subject: Subject,
    /// What they want to invoke.
    pub capability: Capability,
    /// The target, if the capability takes one.
    pub target: Option<String>,
    /// How long the session lasts if approved, in seconds.
    pub lease_secs: u64,
}

/// A human's answer to an [`ApprovalRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// The human said yes.
    Approved,
    /// The human said no, or nobody could be asked.
    Denied,
}

/// Asks a human. Implementations route the request to approver devices (a notification
/// on the phone, a dialog on the PC) and return the first answer.
#[async_trait]
pub trait Approver: Send + Sync {
    /// Asks a human about `request`. The bus gives up after [`APPROVAL_TIMEOUT`].
    async fn approve(&self, request: &ApprovalRequest) -> ApprovalOutcome;
}

/// The default approver: nobody is there to say yes.
pub struct NoApprover;

#[async_trait]
impl Approver for NoApprover {
    async fn approve(&self, _: &ApprovalRequest) -> ApprovalOutcome {
        ApprovalOutcome::Denied
    }
}

/// A visible sign on the target device that a capability is running (a HUD, a frame
/// around the screen), with a way to stop it.
pub trait Indicator: Send + Sync {
    /// Shows the indicator when the session of `lease` starts.
    fn show(&self, lease: &LeaseInfo);
    /// Hides the indicator of lease `lease_id` when its session ends.
    fn hide(&self, lease_id: u64);
}

/// What a module receives with each invocation.
pub struct Ctx {
    /// Who invoked the capability.
    pub subject: Subject,
    /// The target, present exactly when the capability declares a `target_kind`.
    pub target: Option<String>,
    /// Stop acting when this lease is no longer active.
    pub lease: LeaseHandle,
}

/// Why a module could not serve an invocation. Each variant maps to an [`ErrorCode`].
#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    /// The input matches the schema but makes no sense (`invalid_input`).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Not possible on this device or platform (`unsupported`).
    #[error("not supported here: {0}")]
    Unsupported(String),
    /// Anything else that went wrong (`module_error`). The message is sent to the caller.
    #[error("{0}")]
    Failed(String),
}

/// A set of capabilities served by one piece of code.
#[async_trait]
pub trait Module: Send + Sync {
    /// The capabilities this module serves. Read once, when the bus is built.
    fn manifest(&self) -> Manifest;
    /// Runs a `call` capability. The bus has already checked `input` against the schema
    /// and the policy; stop when `ctx.lease` ends.
    async fn invoke(&self, ctx: Ctx, capability: &str, input: Value) -> Result<Value, ModuleError>;

    /// Runs a `stream` capability: read what the caller sends from `io.incoming`, send
    /// back through `io.outgoing`, and return a small JSON result once done. Stop when
    /// `ctx.lease` ends; the bus also cuts the stream then.
    async fn invoke_stream(
        &self,
        _ctx: Ctx,
        capability: &str,
        _input: Value,
        _io: StreamIo,
    ) -> Result<Value, ModuleError> {
        Err(ModuleError::Unsupported(format!(
            "`{capability}` is not a stream here"
        )))
    }
}

/// Why [`BusBuilder::build`] refused the modules' manifests.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Two capabilities have the same name.
    #[error("capability `{0}` is declared twice")]
    Duplicate(String),
    /// The name is not lowercase dotted segments (letters, digits, `_`, `-`), at most 96 bytes.
    #[error("capability name `{0}` is invalid")]
    BadName(String),
    /// The input schema is not a valid JSON Schema.
    #[error("capability `{0}` has an invalid input schema: {1}")]
    BadSchema(String, String),
    /// Names starting with `bus.` belong to the bus itself.
    #[error("`{0}` is reserved for the bus")]
    Reserved(String),
}

struct Registered {
    module: Arc<dyn Module>,
    capability: Capability,
    validator: jsonschema::Validator,
}

/// Builds a [`Bus`].
pub struct BusBuilder {
    modules: Vec<Arc<dyn Module>>,
    policy: Policy,
    approver: Arc<dyn Approver>,
    indicator: Option<Arc<dyn Indicator>>,
    journal: Arc<Journal>,
    members: Arc<dyn MembershipView>,
}

impl BusBuilder {
    /// A builder with no module, the default [`Policy`], no approver (every `ask` is
    /// denied), no indicator and an in-memory journal. `members` decides who may call at all.
    pub fn new(members: Arc<dyn MembershipView>) -> Self {
        Self {
            modules: Vec::new(),
            policy: Policy::default(),
            approver: Arc::new(NoApprover),
            indicator: None,
            journal: Arc::new(Journal::in_memory()),
            members,
        }
    }

    /// Adds a module.
    pub fn module(mut self, module: Arc<dyn Module>) -> Self {
        self.modules.push(module);
        self
    }

    /// Sets the starting policy (the default policy otherwise).
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Sets who answers `ask` decisions ([`NoApprover`] otherwise).
    pub fn approver(mut self, approver: Arc<dyn Approver>) -> Self {
        self.approver = approver;
        self
    }

    /// Installs the indicator. Without one, capabilities that require it are refused.
    pub fn indicator(mut self, indicator: Arc<dyn Indicator>) -> Self {
        self.indicator = Some(indicator);
        self
    }

    /// Sets the journal (an in-memory one otherwise).
    pub fn journal(mut self, journal: Arc<Journal>) -> Self {
        self.journal = journal;
        self
    }

    /// Checks every manifest (reserved names, names, schemas, duplicates) and builds the bus.
    pub fn build(self) -> Result<Bus, BuildError> {
        let mut caps = HashMap::new();
        for module in self.modules {
            for capability in module.manifest().capabilities {
                let name = capability.name.clone();
                if name == LIST_CAPABILITY || name.starts_with("bus.") {
                    return Err(BuildError::Reserved(name));
                }
                if !capability::valid_name(&name) {
                    return Err(BuildError::BadName(name));
                }
                let validator = jsonschema::validator_for(&capability.input_schema)
                    .map_err(|e| BuildError::BadSchema(name.clone(), e.to_string()))?;
                if caps.contains_key(&name) {
                    return Err(BuildError::Duplicate(name));
                }
                caps.insert(
                    name,
                    Registered {
                        module: module.clone(),
                        capability,
                        validator,
                    },
                );
            }
        }
        Ok(Bus {
            caps,
            policy: RwLock::new(self.policy),
            approver: self.approver,
            indicator: self.indicator,
            leases: Leases::default(),
            journal: self.journal,
            members: self.members,
        })
    }
}

/// The capability bus of one device.
pub struct Bus {
    caps: HashMap<String, Registered>,
    policy: RwLock<Policy>,
    approver: Arc<dyn Approver>,
    indicator: Option<Arc<dyn Indicator>>,
    leases: Leases,
    journal: Arc<Journal>,
    members: Arc<dyn MembershipView>,
}

impl Bus {
    /// Starts a [`BusBuilder`]. `members` decides who may call at all.
    pub fn builder(members: Arc<dyn MembershipView>) -> BusBuilder {
        BusBuilder::new(members)
    }

    /// The live sessions, to list or stop them.
    pub fn leases(&self) -> &Leases {
        &self.leases
    }

    /// The journal every invocation is written to.
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Replaces the policy. Applies to new requests; running sessions keep their lease.
    pub fn set_policy(&self, policy: Policy) {
        *self.policy.write().expect("policy lock") = policy;
    }

    /// The capabilities `subject` could invoke (everything not denied outright).
    pub fn capabilities_for(&self, subject: &Subject) -> Vec<Capability> {
        self.listing_for(subject)
            .into_iter()
            .map(|l| l.capability)
            .collect()
    }

    /// The capabilities `subject` could invoke, each with what would happen: run at once
    /// (`allow`) or after a human approves (`ask`). This is what `bus.capabilities`
    /// answers.
    pub fn listing_for(&self, subject: &Subject) -> Vec<Listed> {
        let policy = self.policy.read().expect("policy lock");
        let mut v: Vec<_> = self
            .caps
            .values()
            .filter_map(|r| {
                // Without a target we cannot know a per-target rule; show the capability
                // unless it is denied for every target.
                let decision = policy
                    .evaluate(subject, &r.capability.name, None, r.capability.effect)
                    .decision;
                (decision != Decision::Deny).then(|| Listed {
                    capability: r.capability.clone(),
                    decision,
                })
            })
            .collect();
        v.sort_by(|a, b| a.capability.name.cmp(&b.capability.name));
        v
    }

    /// Whether `capability` is a call or a stream on this device.
    pub fn mode_of(&self, capability: &str) -> Option<Mode> {
        self.caps.get(capability).map(|r| r.capability.mode)
    }

    /// Handles one `call` request from an authenticated `subject`.
    pub async fn handle(&self, subject: Subject, request: Request) -> Response {
        match self.open(subject, request, Mode::Call).await {
            Ok(session) => session.run_call().await,
            Err(answer) => answer,
        }
    }

    /// Runs every check for a request (membership, capability, target, schema, policy,
    /// approval, indicator) and grants its lease. `Err` is the immediate answer: a
    /// refusal, or the capability list. A refusal is journaled here; a [`Session`]
    /// journals its outcome when it ends.
    pub async fn open(
        &self,
        subject: Subject,
        request: Request,
        mode: Mode,
    ) -> Result<Session<'_>, Response> {
        let mut event = Event {
            device: subject.device.to_string(),
            agent: subject.agent.as_deref().map(|a| truncate(a, 64)),
            capability: truncate(&request.capability, 96),
            target: request
                .target
                .as_deref()
                .map(|t| truncate(t, MAX_TARGET_LEN)),
            decision: "none".into(),
            ..Default::default()
        };
        match self.check(&subject, request, mode, &mut event).await {
            Ok((reg, target, input, verdict, indicator)) => {
                let lease = self.leases.grant(
                    subject.clone(),
                    &reg.capability.name,
                    target.clone(),
                    verdict.lease_secs,
                );
                if let Some(i) = &indicator {
                    i.show(lease.info());
                }
                Ok(Session {
                    bus: self,
                    reg,
                    subject,
                    target,
                    input,
                    lease,
                    indicator,
                    event,
                })
            }
            Err(answer) => {
                event.outcome = match &answer {
                    Response::Ok { .. } => "ok".into(),
                    Response::Error { code, .. } => code.as_str().into(),
                };
                if let Err(e) = self.journal.append(event) {
                    tracing::error!("journal write failed: {e}");
                }
                Err(answer)
            }
        }
    }

    #[allow(clippy::type_complexity)]
    async fn check(
        &self,
        subject: &Subject,
        request: Request,
        mode: Mode,
        event: &mut Event,
    ) -> Result<
        (
            &Registered,
            Option<String>,
            Value,
            Verdict,
            Option<Arc<dyn Indicator>>,
        ),
        Response,
    > {
        if !self.members.is_member(&subject.device) {
            return Err(Response::error(
                ErrorCode::NotMember,
                "this device is not a member of the group",
            ));
        }
        if subject
            .agent
            .as_deref()
            .is_some_and(|a| !valid_agent_name(a))
        {
            return Err(Response::error(
                ErrorCode::InvalidInput,
                "invalid agent name",
            ));
        }
        if request.capability == LIST_CAPABILITY {
            event.decision = "allow".into();
            return Err(Response::Ok {
                output: json!({ "capabilities": self.listing_for(subject) }),
            });
        }
        let Some(reg) = self.caps.get(&request.capability) else {
            return Err(Response::error(
                ErrorCode::UnknownCapability,
                "no such capability on this device",
            ));
        };
        let cap = &reg.capability;
        if cap.mode != mode {
            return Err(Response::error(
                ErrorCode::Unsupported,
                match cap.mode {
                    Mode::Stream => "this capability is a stream: open it as one",
                    Mode::Call => "this capability is a call, not a stream",
                },
            ));
        }
        match (&cap.target_kind, &request.target) {
            (Some(kind), None) => {
                return Err(Response::error(
                    ErrorCode::InvalidInput,
                    format!("a target of kind `{kind}` is required"),
                ));
            }
            (None, Some(_)) => {
                return Err(Response::error(
                    ErrorCode::InvalidInput,
                    "this capability takes no target",
                ));
            }
            (_, Some(t))
                if t.is_empty() || t.len() > MAX_TARGET_LEN || t.chars().any(char::is_control) =>
            {
                return Err(Response::error(ErrorCode::InvalidInput, "invalid target"));
            }
            _ => {}
        }
        if let Some(err) = reg.validator.iter_errors(&request.input).next() {
            // The path only: the error text may quote the input, which stays out of logs.
            return Err(Response::error(
                ErrorCode::InvalidInput,
                format!(
                    "input does not match the schema at `{}`",
                    err.instance_path()
                ),
            ));
        }

        let verdict = self.policy.read().expect("policy lock").evaluate(
            subject,
            &cap.name,
            request.target.as_deref(),
            cap.effect,
        );
        event.decision = match verdict.decision {
            Decision::Allow => "allow",
            Decision::Ask => "ask",
            Decision::Deny => "deny",
        }
        .into();
        match verdict.decision {
            Decision::Deny => return Err(Response::error(ErrorCode::Denied, "not allowed")),
            Decision::Allow => {}
            Decision::Ask => {
                let ask = ApprovalRequest {
                    subject: subject.clone(),
                    capability: cap.clone(),
                    target: request.target.clone(),
                    lease_secs: verdict.lease_secs,
                };
                match tokio::time::timeout(APPROVAL_TIMEOUT, self.approver.approve(&ask)).await {
                    Ok(ApprovalOutcome::Approved) => event.approved = Some(true),
                    Ok(ApprovalOutcome::Denied) => {
                        event.approved = Some(false);
                        return Err(Response::error(ErrorCode::Denied, "refused on the device"));
                    }
                    Err(_) => {
                        event.approved = Some(false);
                        return Err(Response::error(
                            ErrorCode::ApprovalTimeout,
                            "nobody answered in time",
                        ));
                    }
                }
            }
        }

        let indicator = match cap.indicator {
            IndicatorRequirement::Required => match &self.indicator {
                Some(i) => Some(i.clone()),
                None => {
                    return Err(Response::error(
                        ErrorCode::NoIndicator,
                        "this device cannot show the required indicator",
                    ));
                }
            },
            IndicatorRequirement::None => None,
        };

        // An approval can take a minute: the device may have been removed meanwhile.
        if !self.members.is_member(&subject.device) {
            return Err(Response::error(
                ErrorCode::NotMember,
                "this device is no longer a member of the group",
            ));
        }
        Ok((reg, request.target, request.input, verdict, indicator))
    }
}

/// An accepted request: the module may run, inside its lease.
pub struct Session<'a> {
    bus: &'a Bus,
    reg: &'a Registered,
    subject: Subject,
    target: Option<String>,
    input: Value,
    lease: LeaseHandle,
    indicator: Option<Arc<dyn Indicator>>,
    event: Event,
}

impl Session<'_> {
    /// The lease this session runs in.
    pub fn lease(&self) -> &LeaseHandle {
        &self.lease
    }

    fn ctx(&self) -> Ctx {
        Ctx {
            subject: self.subject.clone(),
            target: self.target.clone(),
            lease: self.lease.clone(),
        }
    }

    /// Runs a `call` capability.
    pub async fn run_call(self) -> Response {
        let ctx = self.ctx();
        let module = self.reg.module.clone();
        let name = self.reg.capability.name.clone();
        let input = self.input.clone();
        let lease = self.lease.clone();
        let result = tokio::select! {
            r = module.invoke(ctx, &name, input) => Some(r),
            reason = lease.ended() => { tracing::info!(?reason, "lease ended during invocation"); None }
        };
        self.finish(result)
    }

    /// Runs a `stream` capability with the bytes `io` carries. The transport has told the
    /// caller the stream is open before calling this.
    pub async fn run_stream(self, io: StreamIo) -> Response {
        let ctx = self.ctx();
        let module = self.reg.module.clone();
        let name = self.reg.capability.name.clone();
        let input = self.input.clone();
        let lease = self.lease.clone();
        let result = tokio::select! {
            r = module.invoke_stream(ctx, &name, input, io) => Some(r),
            reason = lease.ended() => { tracing::info!(?reason, "lease ended during the stream"); None }
        };
        self.finish(result)
    }

    fn finish(self, result: Option<Result<Value, ModuleError>>) -> Response {
        let interrupted = self.lease.state();
        let lease_id = self.lease.info().id;
        self.bus.leases.finish(lease_id);
        if let Some(i) = &self.indicator {
            i.hide(lease_id);
        }
        let response = match result {
            Some(Ok(output)) => Response::Ok { output },
            Some(Err(ModuleError::InvalidInput(m))) => Response::error(ErrorCode::InvalidInput, m),
            Some(Err(ModuleError::Unsupported(m))) => Response::error(ErrorCode::Unsupported, m),
            Some(Err(ModuleError::Failed(m))) => Response::error(ErrorCode::ModuleError, m),
            None => match interrupted {
                LeaseState::Ended(EndReason::Expired) => {
                    Response::error(ErrorCode::Interrupted, "the session expired")
                }
                _ => Response::error(
                    ErrorCode::Interrupted,
                    "the session was stopped on the device",
                ),
            },
        };
        let mut event = self.event;
        event.outcome = match &response {
            Response::Ok { .. } => "ok".into(),
            Response::Error { code, .. } => code.as_str().into(),
        };
        if let Err(e) = self.bus.journal.append(event) {
            tracing::error!("journal write failed: {e}");
        }
        response
    }
}

/// Bounded and printable: strings from the network reach journals, terminals and UIs.
fn truncate(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for c in s.chars() {
        let c = if c.is_control() || is_format_char(c) {
            '?'
        } else {
            c
        };
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

/// Invisible and bidirectional formatting characters.
pub fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{E0000}'..='\u{E0FFF}')
}

/// An agent name: 1 to 64 characters among letters, digits, `.`, `_`, `-`.
pub fn valid_agent_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Makes a network-provided string safe to show: no control, invisible or bidirectional
/// characters, at most `max` bytes.
pub fn printable(s: &str, max: usize) -> String {
    truncate(s, max)
}

#[cfg(test)]
mod tests;
