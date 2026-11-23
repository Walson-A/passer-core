//! Leases: every allowed invocation runs inside a bounded session that the target device
//! can suspend or revoke at any moment (stop button, physical input, device removed).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use passer_identity::DeviceId;
use serde::Serialize;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::policy::Subject;

/// Why a lease is over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", content = "detail", rename_all = "snake_case")]
pub enum EndReason {
    Finished,
    Expired,
    Revoked(String),
}

/// Where a lease stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    /// Paused, e.g. because the user touched the mouse. Can resume.
    Suspended(String),
    Ended(EndReason),
}

/// What a lease covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LeaseInfo {
    pub id: u64,
    pub subject: Subject,
    pub capability: String,
    pub target: Option<String>,
    pub duration_secs: u64,
}

/// A handle on one lease, shared by the bus, the module and the indicator.
#[derive(Clone, Debug)]
pub struct LeaseHandle {
    info: Arc<LeaseInfo>,
    tx: Arc<watch::Sender<LeaseState>>,
    deadline: Instant,
}

impl LeaseHandle {
    pub fn info(&self) -> &LeaseInfo {
        &self.info
    }

    pub fn state(&self) -> LeaseState {
        let state = self.tx.borrow().clone();
        match state {
            LeaseState::Ended(_) => state,
            _ if Instant::now() >= self.deadline => LeaseState::Ended(EndReason::Expired),
            other => other,
        }
    }

    pub fn is_active(&self) -> bool {
        self.state() == LeaseState::Active
    }

    /// Pauses the session. A module must stop acting until it resumes.
    pub fn suspend(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.tx.send_if_modified(|s| match s {
            LeaseState::Active => {
                *s = LeaseState::Suspended(reason);
                true
            }
            _ => false,
        });
    }

    pub fn resume(&self) {
        self.tx.send_if_modified(|s| match s {
            LeaseState::Suspended(_) => {
                *s = LeaseState::Active;
                true
            }
            _ => false,
        });
    }

    /// Ends the session for good.
    pub fn revoke(&self, reason: impl Into<String>) {
        self.end(EndReason::Revoked(reason.into()));
    }

    pub(crate) fn end(&self, reason: EndReason) {
        self.tx.send_if_modified(|s| match s {
            LeaseState::Ended(_) => false,
            _ => {
                *s = LeaseState::Ended(reason);
                true
            }
        });
    }

    /// Resolves when the lease is revoked, finished or expired.
    pub async fn ended(&self) -> EndReason {
        let mut rx = self.tx.subscribe();
        loop {
            if let LeaseState::Ended(reason) = rx.borrow_and_update().clone() {
                return reason;
            }
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() {
                        return EndReason::Revoked("lease dropped".into());
                    }
                }
                _ = tokio::time::sleep_until(self.deadline) => {
                    self.end(EndReason::Expired);
                    return EndReason::Expired;
                }
            }
        }
    }
}

/// All live leases of a device.
#[derive(Default)]
pub struct Leases {
    next: AtomicU64,
    live: Mutex<HashMap<u64, LeaseHandle>>,
}

impl Leases {
    pub(crate) fn grant(
        &self,
        subject: Subject,
        capability: &str,
        target: Option<String>,
        secs: u64,
    ) -> LeaseHandle {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let info = LeaseInfo {
            id,
            subject,
            capability: capability.to_owned(),
            target,
            duration_secs: secs,
        };
        let (tx, _) = watch::channel(LeaseState::Active);
        let handle = LeaseHandle {
            info: Arc::new(info),
            tx: Arc::new(tx),
            deadline: Instant::now() + Duration::from_secs(secs),
        };
        self.live
            .lock()
            .expect("lease lock")
            .insert(id, handle.clone());
        handle
    }

    pub(crate) fn finish(&self, id: u64) {
        if let Some(h) = self.live.lock().expect("lease lock").remove(&id) {
            h.end(EndReason::Finished);
        }
    }

    /// The sessions currently open (for a "who is connected" view and the stop button).
    pub fn active(&self) -> Vec<LeaseInfo> {
        let mut v: Vec<_> = self
            .live
            .lock()
            .expect("lease lock")
            .values()
            .map(|h| h.info().clone())
            .collect();
        v.sort_by_key(|i| i.id);
        v
    }

    pub fn get(&self, id: u64) -> Option<LeaseHandle> {
        self.live.lock().expect("lease lock").get(&id).cloned()
    }

    /// The global stop button.
    pub fn revoke_all(&self, reason: &str) {
        for (_, h) in self.live.lock().expect("lease lock").drain() {
            h.revoke(reason);
        }
    }

    /// Called when a device is removed from the group.
    pub fn revoke_device(&self, device: &DeviceId, reason: &str) {
        self.live.lock().expect("lease lock").retain(|_, h| {
            if h.info().subject.device == *device {
                h.revoke(reason);
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passer_identity::Identity;

    fn subject() -> Subject {
        Subject::device(Identity::generate().id())
    }

    #[tokio::test(start_paused = true)]
    async fn lease_expires() {
        let leases = Leases::default();
        let h = leases.grant(subject(), "screen.view", None, 5);
        assert!(h.is_active());
        assert_eq!(h.ended().await, EndReason::Expired);
        assert!(!h.is_active());
    }

    #[tokio::test]
    async fn suspend_resume_revoke() {
        let leases = Leases::default();
        let h = leases.grant(subject(), "screen.input", Some("notepad.exe".into()), 60);
        h.suspend("physical input");
        assert_eq!(h.state(), LeaseState::Suspended("physical input".into()));
        h.resume();
        assert!(h.is_active());
        let waiter = {
            let h = h.clone();
            tokio::spawn(async move { h.ended().await })
        };
        h.revoke("stop button");
        assert_eq!(
            waiter.await.unwrap(),
            EndReason::Revoked("stop button".into())
        );
        // A revoked lease cannot be resumed.
        h.resume();
        assert!(!h.is_active());
    }

    #[tokio::test]
    async fn removing_a_device_revokes_its_sessions_only() {
        let leases = Leases::default();
        let a = subject();
        let b = subject();
        let ha = leases.grant(a.clone(), "x.y", None, 60);
        let hb = leases.grant(b, "x.y", None, 60);
        leases.revoke_device(&a.device, "removed from group");
        assert!(!ha.is_active());
        assert!(hb.is_active());
        assert_eq!(leases.active().len(), 1);
        leases.revoke_all("stop");
        assert!(!hb.is_active());
        assert!(leases.active().is_empty());
    }
}
