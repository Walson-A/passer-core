//! What this device knows about the other members beyond the device log: what they said
//! about themselves (`device.info`) and what they let this device call
//! (`bus.capabilities`), as of the last time they answered.
//!
//! Everything here comes from other devices, so it is treated as untrusted: strings are
//! made printable and bounded, unknown values become `unknown`, and a member that never
//! answered simply has no entry. The cache only decorates the UI; permissions are always
//! decided by the target device's bus.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use passer_bus::{
    Decision, Effect, LIST_CAPABILITY, Listed, MembershipView, Request, Response, printable,
};
use passer_identity::DeviceId;
use passer_node::{Node, now_secs};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// How long one member gets to answer a refresh.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);
/// Bounds on what a member can make this device store.
const MAX_CAPABILITIES: usize = 64;
const MAX_TEXT: usize = 160;

/// What a member said about itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Described {
    pub kind: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub arch: Option<String>,
    pub core_version: Option<String>,
    pub app_version: Option<String>,
}

/// One capability a member offers this device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offered {
    pub name: String,
    pub title: String,
    pub description: String,
    /// `read`, `write` or `sensitive`.
    pub effect: String,
    pub target_kind: Option<String>,
    /// A human approves each session first.
    pub needs_approval: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub described: Option<Described>,
    pub offered: Vec<Offered>,
    /// When the member last answered a refresh (Unix seconds).
    pub answered_at: u64,
}

/// The cache, kept in `members.json` next to the group.
pub struct MemberCache {
    path: PathBuf,
    entries: Mutex<HashMap<String, Entry>>,
}

impl MemberCache {
    pub fn open(path: PathBuf) -> Arc<Self> {
        let entries = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Arc::new(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    pub fn get(&self, device: &DeviceId) -> Option<Entry> {
        self.entries
            .lock()
            .expect("member cache lock")
            .get(&device.to_string())
            .cloned()
    }

    /// Drops what is known about devices that left the group.
    pub fn retain(&self, keep: impl Fn(&str) -> bool) {
        let mut entries = self.entries.lock().expect("member cache lock");
        entries.retain(|id, _| keep(id));
        self.save(&entries);
    }

    fn put(&self, device: &DeviceId, entry: Entry) {
        let mut entries = self.entries.lock().expect("member cache lock");
        entries.insert(device.to_string(), entry);
        self.save(&entries);
    }

    fn save(&self, entries: &HashMap<String, Entry>) {
        let text = serde_json::to_string_pretty(entries).expect("cache serializes");
        if let Err(e) = std::fs::write(&self.path, text) {
            tracing::warn!("cannot save the member cache: {e}");
        }
    }

    /// Asks every other member what it is and what it offers. Returns how many answered.
    /// Only calls `device.info` where it runs without asking anyone: a refresh never
    /// makes another device show an approval prompt.
    pub async fn refresh(self: &Arc<Self>, node: &Arc<Node>) -> u32 {
        let me = node.id();
        let members: Vec<DeviceId> = node
            .group()
            .membership()
            .members
            .into_keys()
            .filter(|d| *d != me)
            .collect();
        let mut tasks = tokio::task::JoinSet::new();
        for device in members {
            let node = node.clone();
            tasks.spawn(async move {
                let entry = tokio::time::timeout(ANSWER_WITHIN, ask(&node, device))
                    .await
                    .ok()
                    .flatten();
                (device, entry)
            });
        }
        let mut answered = 0;
        while let Some(Ok((device, entry))) = tasks.join_next().await {
            if let Some(entry) = entry {
                self.put(&device, entry);
                answered += 1;
            }
        }
        let group = node.group().clone();
        self.retain(|id| id.parse::<DeviceId>().is_ok_and(|d| group.is_member(&d)));
        answered
    }
}

async fn call(node: &Node, device: DeviceId, capability: &str) -> Option<Value> {
    let addr = node.peers().addr_of(&device);
    match node.call(addr, Request::new(capability, json!({}))).await {
        Ok(Response::Ok { output }) => Some(output),
        _ => None,
    }
}

async fn ask(node: &Node, device: DeviceId) -> Option<Entry> {
    let listing = call(node, device, LIST_CAPABILITY).await?;
    let offered = parse_listing(&listing);
    let info_allowed = offered
        .iter()
        .any(|o| o.name == passer_device_info::CAPABILITY && !o.needs_approval);
    let described = if info_allowed {
        call(node, device, passer_device_info::CAPABILITY)
            .await
            .map(|v| parse_info(&v))
    } else {
        None
    };
    Some(Entry {
        described,
        offered,
        answered_at: now_secs(),
    })
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(|s| printable(s, MAX_TEXT))
        .filter(|s| !s.is_empty())
}

pub fn parse_info(v: &Value) -> Described {
    Described {
        kind: passer_device_info::DeviceKind::parse(
            v.get("kind").and_then(Value::as_str).unwrap_or(""),
        )
        .as_str()
        .to_owned(),
        os: text(v, "os"),
        os_version: text(v, "os_version"),
        arch: text(v, "arch"),
        core_version: text(v, "version"),
        app_version: text(v, "app_version"),
    }
}

/// Reads a `bus.capabilities` answer entry by entry: one malformed entry does not hide
/// the others. A peer too old to send decisions is read as "allow" for read and write,
/// "ask" for sensitive, which is the default policy.
pub fn parse_listing(v: &Value) -> Vec<Offered> {
    let Some(items) = v.get("capabilities").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .take(MAX_CAPABILITIES)
        .filter_map(|item| {
            let mut item = item.clone();
            if item.get("decision").is_none()
                && let Some(obj) = item.as_object_mut()
            {
                let sensitive = obj.get("effect").and_then(Value::as_str) == Some("sensitive");
                obj.insert(
                    "decision".into(),
                    json!(if sensitive { "ask" } else { "allow" }),
                );
            }
            let listed: Listed = serde_json::from_value(item).ok()?;
            let c = listed.capability;
            Some(Offered {
                name: printable(&c.name, 96),
                title: printable(&c.title, MAX_TEXT),
                description: printable(&c.description, 400),
                effect: match c.effect {
                    Effect::Read => "read",
                    Effect::Write => "write",
                    Effect::Sensitive => "sensitive",
                }
                .into(),
                target_kind: c.target_kind.map(|k| printable(&k, 64)),
                needs_approval: listed.decision == Decision::Ask,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_survives_bad_entries_and_old_peers() {
        let v = json!({ "capabilities": [
            { "name": "device.info", "title": "Device info", "description": "d",
              "input_schema": {}, "effect": "read", "mode": "call", "decision": "allow" },
            { "name": "clipboard.read", "title": "Read\u{202E} clipboard", "description": "d",
              "input_schema": {}, "effect": "sensitive", "mode": "call" },
            { "name": "broken", "effect": "teleport" }
        ]});
        let offered = parse_listing(&v);
        assert_eq!(offered.len(), 2);
        assert!(!offered[0].needs_approval);
        assert!(
            offered[1].needs_approval,
            "an old peer's sensitive capability asks"
        );
        assert!(!offered[1].title.contains('\u{202E}'));
    }

    #[test]
    fn info_is_bounded_and_kind_is_known() {
        let long = "x".repeat(1000);
        let d = parse_info(&json!({ "kind": "toaster", "os": long, "version": "0.1.0" }));
        assert_eq!(d.kind, "unknown");
        assert!(d.os.unwrap().len() <= MAX_TEXT);
        assert_eq!(d.core_version.as_deref(), Some("0.1.0"));
    }
}
