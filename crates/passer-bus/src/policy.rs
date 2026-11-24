//! The permission rules: who may invoke what, on which target, and for how long.

use passer_identity::DeviceId;
use serde::{Deserialize, Serialize};

use crate::capability::Effect;

/// The outcome of a policy check before any approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Run at once.
    Allow,
    /// Ask a human on an approver device first.
    Ask,
    /// Refuse.
    Deny,
}

/// Who is asking. The device is always the one the transport authenticated; `agent` is
/// set when the request comes through a bridge on behalf of an AI agent.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Subject {
    /// The member device, as the transport authenticated it.
    pub device: DeviceId,
    /// The AI agent's name, as the bridge asserts it. `None` for a device acting for itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

impl Subject {
    /// A device acting for itself, with no agent.
    pub fn device(device: DeviceId) -> Self {
        Self {
            device,
            agent: None,
        }
    }
}

/// Which requesters a rule applies to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Who {
    /// Any member device acting for itself (no agent).
    AnyDevice,
    /// One member device acting for itself.
    Device {
        /// The device.
        id: DeviceId,
    },
    /// Any agent, through any device.
    AnyAgent,
    /// A named agent. The agent's name is asserted by the bridge device that relays it,
    /// so a rule that grants an agent more than devices get should pin `via`.
    Agent {
        /// The agent's name.
        name: String,
        /// The only bridge device the agent may come through; any device if `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<DeviceId>,
    },
}

impl Who {
    fn matches(&self, s: &Subject) -> bool {
        match (self, &s.agent) {
            (Who::AnyDevice, None) => true,
            (Who::Device { id }, None) => *id == s.device,
            (Who::AnyAgent, Some(_)) => true,
            (Who::Agent { name, via }, Some(a)) => name == a && via.is_none_or(|v| v == s.device),
            _ => false,
        }
    }
}

/// One rule. Rules are checked in order; the first that matches decides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Which requesters it applies to.
    pub who: Who,
    /// Exact name, `prefix.*`, or `*`.
    pub capability: String,
    /// Exact target, or none to match any target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// What it decides.
    pub decision: Decision,
    /// How long an allowed or approved session lasts. Capped for sensitive capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u64>,
}

fn capability_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix(".*") {
        Some(prefix) => {
            name.len() > prefix.len()
                && name.starts_with(prefix)
                && name.as_bytes()[prefix.len()] == b'.'
        }
        None => pattern == name,
    }
}

/// A decision with its session length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// Allow, ask or deny.
    pub decision: Decision,
    /// Session length in seconds, already capped and at least 1.
    pub lease_secs: u64,
}

/// Default session length.
pub const DEFAULT_LEASE_SECS: u64 = 10 * 60;
/// No session ever lasts longer than this (a day).
pub const MAX_LEASE_SECS: u64 = 24 * 3600;
/// No session on a sensitive capability ever lasts longer than this.
pub const MAX_SENSITIVE_LEASE_SECS: u64 = 15 * 60;

/// Ordered rules plus the defaults that apply when none matches.
///
/// Defaults: an agent is denied everything (agents must be granted explicitly); a member
/// device may read and write; anything sensitive asks an approver.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// The rules, in order: the first that matches decides.
    pub rules: Vec<Rule>,
}

impl Policy {
    /// A policy with these rules.
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Decides for `subject` invoking `capability` (of `effect`) on `target`: the first
    /// matching rule, else the defaults. A rule with a target only matches that target.
    pub fn evaluate(
        &self,
        subject: &Subject,
        capability: &str,
        target: Option<&str>,
        effect: Effect,
    ) -> Verdict {
        let matched = self.rules.iter().find(|r| {
            r.who.matches(subject)
                && capability_matches(&r.capability, capability)
                && r.target.as_deref().is_none_or(|t| Some(t) == target)
        });
        let (decision, lease) = match matched {
            Some(rule) => (rule.decision, rule.lease_secs.unwrap_or(DEFAULT_LEASE_SECS)),
            None => (default_decision(subject, effect), DEFAULT_LEASE_SECS),
        };
        let lease_secs = if effect == Effect::Sensitive {
            lease.min(MAX_SENSITIVE_LEASE_SECS)
        } else {
            lease.min(MAX_LEASE_SECS)
        }
        .max(1);
        Verdict {
            decision,
            lease_secs,
        }
    }
}

fn default_decision(subject: &Subject, effect: Effect) -> Decision {
    if subject.agent.is_some() {
        return Decision::Deny;
    }
    match effect {
        Effect::Read | Effect::Write => Decision::Allow,
        Effect::Sensitive => Decision::Ask,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passer_identity::Identity;

    fn me() -> Subject {
        Subject::device(Identity::generate().id())
    }

    #[test]
    fn defaults() {
        let p = Policy::default();
        let dev = me();
        let agent = Subject {
            device: dev.device,
            agent: Some("claude".into()),
        };
        assert_eq!(
            p.evaluate(&dev, "device.info", None, Effect::Read).decision,
            Decision::Allow
        );
        assert_eq!(
            p.evaluate(&dev, "clipboard.read", None, Effect::Sensitive)
                .decision,
            Decision::Ask
        );
        assert_eq!(
            p.evaluate(&agent, "device.info", None, Effect::Read)
                .decision,
            Decision::Deny
        );
    }

    #[test]
    fn first_matching_rule_wins_and_targets_are_respected() {
        let dev = me();
        let p = Policy::new(vec![
            Rule {
                who: Who::AnyDevice,
                capability: "screen.input".into(),
                target: Some("bank.exe".into()),
                decision: Decision::Deny,
                lease_secs: None,
            },
            Rule {
                who: Who::AnyDevice,
                capability: "screen.*".into(),
                target: None,
                decision: Decision::Allow,
                lease_secs: Some(3600),
            },
        ]);
        assert_eq!(
            p.evaluate(&dev, "screen.input", Some("bank.exe"), Effect::Sensitive)
                .decision,
            Decision::Deny
        );
        let v = p.evaluate(&dev, "screen.input", Some("notepad.exe"), Effect::Sensitive);
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(
            v.lease_secs, MAX_SENSITIVE_LEASE_SECS,
            "sensitive sessions are capped"
        );
        assert_eq!(
            p.evaluate(&dev, "screen.view", None, Effect::Read)
                .lease_secs,
            3600
        );
    }

    #[test]
    fn wildcard_does_not_leak_to_similar_prefixes() {
        assert!(capability_matches("screen.*", "screen.view"));
        assert!(!capability_matches("screen.*", "screenshot.take"));
        assert!(!capability_matches("screen.*", "screen"));
        assert!(capability_matches("*", "anything.at.all"));
    }

    #[test]
    fn agent_rules_do_not_apply_to_devices_and_back() {
        let dev = me();
        let agent = Subject {
            device: dev.device,
            agent: Some("claude".into()),
        };
        let p = Policy::new(vec![Rule {
            who: Who::Agent {
                name: "claude".into(),
                via: Some(dev.device),
            },
            capability: "transfer.*".into(),
            target: None,
            decision: Decision::Allow,
            lease_secs: None,
        }]);
        assert_eq!(
            p.evaluate(&agent, "transfer.send", None, Effect::Write)
                .decision,
            Decision::Allow
        );
        assert_eq!(
            p.evaluate(&agent, "clipboard.read", None, Effect::Sensitive)
                .decision,
            Decision::Deny
        );
        let other = Subject {
            device: dev.device,
            agent: Some("gpt".into()),
        };
        assert_eq!(
            p.evaluate(&other, "transfer.send", None, Effect::Write)
                .decision,
            Decision::Deny
        );
        // Another member device claiming to relay "claude" does not get claude's grant.
        let impostor = Subject {
            device: Identity::generate().id(),
            agent: Some("claude".into()),
        };
        assert_eq!(
            p.evaluate(&impostor, "transfer.send", None, Effect::Write)
                .decision,
            Decision::Deny
        );
    }
}
