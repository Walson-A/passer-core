//! Human approval for sensitive capabilities.
//!
//! When the bus decides `ask`, the device that would act (the *target*) needs a human yes.
//! [`RemoteApprover`] asks, in parallel:
//!
//! - its own user, through a local [`Prompter`] (a dialog, a notification), when it has one
//!   — the preferred place, since the target is where the action happens;
//! - the group's other **approver** devices, by invoking their `approval.request`
//!   capability ([`ApprovalModule`]).
//!
//! The first answer wins. **The requesting device is never asked**: a request cannot
//! approve itself. Names shown in a prompt come from the approver's own copy of the
//! membership log, never from the message.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use iroh::Endpoint;
use passer_bus::{
    ApprovalOutcome, ApprovalRequest, Approver, Capability, Ctx, Effect, Manifest, Module,
    ModuleError, Request, Response,
};
use passer_identity::DeviceId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::task::JoinSet;

use crate::{Group, PeerBook, call_peer};

pub const APPROVAL_CAPABILITY: &str = "approval.request";

/// What a human is asked, in words they can judge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPrompt {
    /// The device that wants something done.
    pub requester: DeviceId,
    pub requester_name: String,
    /// Set when an AI agent asks through that device.
    pub agent: Option<String>,
    /// The device that would do it.
    pub target_device: DeviceId,
    pub target_device_name: String,
    pub capability: String,
    pub title: String,
    /// What the capability acts on (an app, a folder), if anything.
    pub target: Option<String>,
    pub lease_secs: u64,
}

/// Shows a prompt to the person in front of this device and returns their answer.
#[async_trait]
pub trait Prompter: Send + Sync {
    async fn ask(&self, prompt: &ApprovalPrompt) -> bool;
}

/// Always answers the same thing. For tests and unattended setups.
pub struct AutoPrompter(pub bool);

#[async_trait]
impl Prompter for AutoPrompter {
    async fn ask(&self, _: &ApprovalPrompt) -> bool {
        self.0
    }
}

#[derive(Serialize, Deserialize)]
struct WireRequest {
    requester: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent: Option<String>,
    capability: String,
    title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    lease_secs: u64,
}

fn name_of(group: &Group, device: &DeviceId) -> Option<String> {
    group
        .membership()
        .members
        .get(device)
        .map(|m| m.name.clone())
}

/// Serves `approval.request` on an approver device.
pub struct ApprovalModule {
    group: Arc<Group>,
    prompter: Arc<dyn Prompter>,
}

impl ApprovalModule {
    pub fn new(group: Arc<Group>, prompter: Arc<dyn Prompter>) -> Self {
        Self { group, prompter }
    }
}

#[async_trait]
impl Module for ApprovalModule {
    fn manifest(&self) -> Manifest {
        Manifest {
            module: "approval".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            capabilities: vec![Capability::call(
                APPROVAL_CAPABILITY,
                "Approve an action",
                "Asks the person using this device to approve a sensitive action on another device of the group.",
                Effect::Write,
                json!({
                    "type": "object",
                    "properties": {
                        "requester": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "agent": { "type": "string", "maxLength": 64 },
                        "capability": { "type": "string", "maxLength": 96 },
                        "title": { "type": "string", "maxLength": 128 },
                        "target": { "type": "string", "maxLength": 256 },
                        "lease_secs": { "type": "integer", "minimum": 1, "maximum": 86400 }
                    },
                    "required": ["requester", "capability", "title", "lease_secs"],
                    "additionalProperties": false
                }),
            )],
        }
    }

    async fn invoke(&self, ctx: Ctx, capability: &str, input: Value) -> Result<Value, ModuleError> {
        if capability != APPROVAL_CAPABILITY {
            return Err(ModuleError::Unsupported(capability.into()));
        }
        if ctx.subject.agent.is_some() {
            return Err(ModuleError::Failed(
                "agents cannot request approvals".into(),
            ));
        }
        let req: WireRequest =
            serde_json::from_value(input).map_err(|e| ModuleError::InvalidInput(e.to_string()))?;
        if req.requester == ctx.subject.device {
            return Err(ModuleError::InvalidInput(
                "a device cannot ask approval for itself".into(),
            ));
        }
        let requester_name = name_of(&self.group, &req.requester)
            .ok_or_else(|| ModuleError::InvalidInput("the requester is not a member".into()))?;
        let target_device_name = name_of(&self.group, &ctx.subject.device).unwrap_or_default();
        let prompt = ApprovalPrompt {
            requester: req.requester,
            requester_name,
            agent: req.agent,
            target_device: ctx.subject.device,
            target_device_name,
            capability: req.capability,
            title: req.title,
            target: req.target,
            lease_secs: req.lease_secs,
        };
        let approved = self.prompter.ask(&prompt).await;
        Ok(json!({ "approved": approved }))
    }
}

/// What the approver needs from the running node, attached after the node starts.
pub(crate) struct Link {
    pub endpoint: Endpoint,
    pub peers: PeerBook,
}

/// The bus's [`Approver`] on a device: asks its own user and the group's approvers.
pub struct RemoteApprover {
    group: Arc<Group>,
    local: Option<Arc<dyn Prompter>>,
    link: OnceLock<Link>,
}

impl RemoteApprover {
    pub fn new(group: Arc<Group>, local: Option<Arc<dyn Prompter>>) -> Arc<Self> {
        Arc::new(Self {
            group,
            local,
            link: OnceLock::new(),
        })
    }

    pub(crate) fn attach(&self, link: Link) {
        let _ = self.link.set(link);
    }
}

#[async_trait]
impl Approver for RemoteApprover {
    async fn approve(&self, request: &ApprovalRequest) -> ApprovalOutcome {
        let requester = request.subject.device;
        let mut answers: JoinSet<Option<bool>> = JoinSet::new();

        if let Some(local) = &self.local {
            let this = self.link.get().map(|l| l.endpoint.id());
            let prompt = ApprovalPrompt {
                requester,
                requester_name: name_of(&self.group, &requester).unwrap_or_default(),
                agent: request.subject.agent.clone(),
                target_device: this.unwrap_or(requester),
                target_device_name: this
                    .and_then(|t| name_of(&self.group, &t))
                    .unwrap_or_default(),
                capability: request.capability.name.clone(),
                title: request.capability.title.clone(),
                target: request.target.clone(),
                lease_secs: request.lease_secs,
            };
            let local = local.clone();
            answers.spawn(async move { Some(local.ask(&prompt).await) });
        }

        if let Some(link) = self.link.get() {
            let me = link.endpoint.id();
            let wire = serde_json::to_value(WireRequest {
                requester,
                agent: request.subject.agent.clone(),
                capability: request.capability.name.clone(),
                title: request.capability.title.clone(),
                target: request.target.clone(),
                lease_secs: request.lease_secs,
            })
            .expect("serializes");
            for approver in self.group.membership().approvers() {
                if *approver == me || *approver == requester {
                    continue;
                }
                let endpoint = link.endpoint.clone();
                let addr = link.peers.addr_of(approver);
                let call = Request::new(APPROVAL_CAPABILITY, wire.clone());
                answers.spawn(async move {
                    match call_peer(&endpoint, addr, call).await {
                        Ok(Response::Ok { output }) => output["approved"].as_bool(),
                        _ => None, // unreachable or refused: not an answer
                    }
                });
            }
        }

        while let Some(answer) = answers.join_next().await {
            match answer {
                Ok(Some(true)) => return ApprovalOutcome::Approved,
                Ok(Some(false)) => return ApprovalOutcome::Denied,
                _ => continue,
            }
        }
        // Nobody could be asked, or nobody answered: no.
        ApprovalOutcome::Denied
    }
}
