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

pub mod capability;
pub mod journal;
pub mod lease;
pub mod policy;
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
pub use wire::{ErrorCode, Request, Response};

/// Name of the built-in capability that lists what the requester may call.
pub const LIST_CAPABILITY: &str = "bus.capabilities";
/// How long a human has to answer an approval request.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest accepted target string.
pub const MAX_TARGET_LEN: usize = 256;

/// Read access to the group's membership, provided by whoever owns the device log.
pub trait MembershipView: Send + Sync {
    fn is_member(&self, device: &DeviceId) -> bool;
}

/// What an approver device is asked.
#[derive(Clone, Debug)]
pub struct ApprovalRequest {
    pub subject: Subject,
    pub capability: Capability,
    pub target: Option<String>,
    pub lease_secs: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    Denied,
}

/// Asks a human. Implementations route the request to approver devices (a notification
/// on the phone, a dialog on the PC) and return the first answer.
#[async_trait]
pub trait Approver: Send + Sync {
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
    fn show(&self, lease: &LeaseInfo);
    fn hide(&self, lease_id: u64);
}

/// What a module receives with each invocation.
pub struct Ctx {
    pub subject: Subject,
    pub target: Option<String>,
    /// Stop acting when this lease is no longer active.
    pub lease: LeaseHandle,
}

#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not supported here: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Failed(String),
}

/// A set of capabilities served by one piece of code.
#[async_trait]
pub trait Module: Send + Sync {
    fn manifest(&self) -> Manifest;
    async fn invoke(&self, ctx: Ctx, capability: &str, input: Value) -> Result<Value, ModuleError>;
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("capability `{0}` is declared twice")]
    Duplicate(String),
    #[error("capability name `{0}` is invalid")]
    BadName(String),
    #[error("capability `{0}` has an invalid input schema: {1}")]
    BadSchema(String, String),
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

    pub fn module(mut self, module: Arc<dyn Module>) -> Self {
        self.modules.push(module);
        self
    }

    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    pub fn approver(mut self, approver: Arc<dyn Approver>) -> Self {
        self.approver = approver;
        self
    }

    pub fn indicator(mut self, indicator: Arc<dyn Indicator>) -> Self {
        self.indicator = Some(indicator);
        self
    }

    pub fn journal(mut self, journal: Arc<Journal>) -> Self {
        self.journal = journal;
        self
    }

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
    pub fn builder(members: Arc<dyn MembershipView>) -> BusBuilder {
        BusBuilder::new(members)
    }

    pub fn leases(&self) -> &Leases {
        &self.leases
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    pub fn set_policy(&self, policy: Policy) {
        *self.policy.write().expect("policy lock") = policy;
    }

    /// The capabilities `subject` could invoke (everything not denied outright).
    pub fn capabilities_for(&self, subject: &Subject) -> Vec<Capability> {
        let policy = self.policy.read().expect("policy lock");
        let mut v: Vec<_> = self
            .caps
            .values()
            .filter(|r| {
                // Without a target we cannot know a per-target rule; show the capability
                // unless it is denied for every target.
                policy
                    .evaluate(subject, &r.capability.name, None, r.capability.effect)
                    .decision
                    != Decision::Deny
            })
            .map(|r| r.capability.clone())
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Handles one request from an authenticated `subject`.
    pub async fn handle(&self, subject: Subject, request: Request) -> Response {
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
        let response = self.process(&subject, request, &mut event).await;
        event.outcome = match &response {
            Response::Ok { .. } => "ok".into(),
            Response::Error { code, .. } => code.as_str().into(),
        };
        if let Err(e) = self.journal.append(event) {
            tracing::error!("journal write failed: {e}");
        }
        response
    }

    async fn process(&self, subject: &Subject, request: Request, event: &mut Event) -> Response {
        if !self.members.is_member(&subject.device) {
            return Response::error(
                ErrorCode::NotMember,
                "this device is not a member of the group",
            );
        }
        if subject
            .agent
            .as_deref()
            .is_some_and(|a| !valid_agent_name(a))
        {
            return Response::error(ErrorCode::InvalidInput, "invalid agent name");
        }
        if request.capability == LIST_CAPABILITY {
            event.decision = "allow".into();
            return Response::Ok {
                output: json!({ "capabilities": self.capabilities_for(subject) }),
            };
        }
        let Some(reg) = self.caps.get(&request.capability) else {
            return Response::error(
                ErrorCode::UnknownCapability,
                "no such capability on this device",
            );
        };
        let cap = &reg.capability;
        if cap.mode == Mode::Stream {
            return Response::error(ErrorCode::Unsupported, "streams are not implemented yet");
        }
        match (&cap.target_kind, &request.target) {
            (Some(kind), None) => {
                return Response::error(
                    ErrorCode::InvalidInput,
                    format!("a target of kind `{kind}` is required"),
                );
            }
            (None, Some(_)) => {
                return Response::error(ErrorCode::InvalidInput, "this capability takes no target");
            }
            (_, Some(t))
                if t.is_empty() || t.len() > MAX_TARGET_LEN || t.chars().any(char::is_control) =>
            {
                return Response::error(ErrorCode::InvalidInput, "invalid target");
            }
            _ => {}
        }
        if let Some(err) = reg.validator.iter_errors(&request.input).next() {
            // The path only: the error text may quote the input, which stays out of logs.
            return Response::error(
                ErrorCode::InvalidInput,
                format!(
                    "input does not match the schema at `{}`",
                    err.instance_path()
                ),
            );
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
            Decision::Deny => return Response::error(ErrorCode::Denied, "not allowed"),
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
                        return Response::error(ErrorCode::Denied, "refused on the device");
                    }
                    Err(_) => {
                        event.approved = Some(false);
                        return Response::error(
                            ErrorCode::ApprovalTimeout,
                            "nobody answered in time",
                        );
                    }
                }
            }
        }

        let indicator = match cap.indicator {
            IndicatorRequirement::Required => match &self.indicator {
                Some(i) => Some(i.clone()),
                None => {
                    return Response::error(
                        ErrorCode::NoIndicator,
                        "this device cannot show the required indicator",
                    );
                }
            },
            IndicatorRequirement::None => None,
        };

        // An approval can take a minute: the device may have been removed meanwhile.
        if !self.members.is_member(&subject.device) {
            return Response::error(
                ErrorCode::NotMember,
                "this device is no longer a member of the group",
            );
        }
        let lease = self.leases.grant(
            subject.clone(),
            &cap.name,
            request.target.clone(),
            verdict.lease_secs,
        );
        let lease_id = lease.info().id;
        if let Some(i) = &indicator {
            i.show(lease.info());
        }
        let ctx = Ctx {
            subject: subject.clone(),
            target: request.target,
            lease: lease.clone(),
        };
        let result = tokio::select! {
            r = reg.module.invoke(ctx, &cap.name, request.input) => Some(r),
            reason = lease.ended() => { tracing::info!(?reason, "lease ended during invocation"); None }
        };
        let interrupted = lease.state();
        self.leases.finish(lease_id);
        if let Some(i) = &indicator {
            i.hide(lease_id);
        }
        match result {
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
        }
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
