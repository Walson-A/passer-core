//! Tests for the issues found in the security review, and for concurrency.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use passer_bus::{
    Bus, Capability, Ctx, Effect, ErrorCode, Manifest, Module, ModuleError, Request, Response,
};
use passer_device_info::DeviceInfo;
use passer_identity::Identity;
use passer_membership::DeviceLog;
use passer_node::approval::{ApprovalPrompt, Prompter, RemoteApprover};
use passer_node::{Group, Network, Node, NodeOptions, join, now_secs};
use serde_json::{Value, json};
use tokio::sync::Notify;

/// A sensitive capability that takes as long as the test wants.
struct Slow(Arc<Notify>);

#[async_trait]
impl Module for Slow {
    fn manifest(&self) -> Manifest {
        Manifest {
            module: "slow".into(),
            version: "0".into(),
            capabilities: vec![
                Capability::call(
                    "slow.read",
                    "Slow",
                    "t",
                    Effect::Read,
                    json!({"type": "object"}),
                ),
                Capability::call(
                    "slow.secret",
                    "Secret",
                    "t",
                    Effect::Sensitive,
                    json!({"type": "object"}),
                ),
            ],
        }
    }
    async fn invoke(&self, _: Ctx, _: &str, _: Value) -> Result<Value, ModuleError> {
        self.0.notified().await;
        Ok(json!("done"))
    }
}

/// A prompt that waits until the test releases it, then says yes.
struct HeldPrompt(Arc<Notify>, Arc<Notify>);

#[async_trait]
impl Prompter for HeldPrompt {
    async fn ask(&self, _: &ApprovalPrompt) -> bool {
        self.0.notify_one(); // "the prompt is on screen"
        self.1.notified().await; // wait for the user
        true
    }
}

async fn pc_with(release: Arc<Notify>, prompter: Option<Arc<dyn Prompter>>) -> Arc<Node> {
    let id = Arc::new(Identity::generate());
    let log = DeviceLog::create(&id, "Walson", "PC", now_secs()).unwrap();
    let group = Arc::new(Group::new(log, None).unwrap());
    let approver = RemoteApprover::new(group.clone(), prompter);
    let bus = Arc::new(
        Bus::builder(group.clone())
            .module(Arc::new(Slow(release)))
            .module(Arc::new(DeviceInfo::new("PC")))
            .approver(approver.clone())
            .build()
            .unwrap(),
    );
    let opts = NodeOptions {
        approver: Some(approver),
        ..Default::default()
    };
    Arc::new(Node::spawn(id, group, bus, opts).await.unwrap())
}

async fn member_of(host: &Node, name: &str) -> Arc<Node> {
    let inv = host.invite(300).unwrap();
    let id = Identity::generate();
    let (log, _) = join(&id, &inv, name, Network::LocalOnly).await.unwrap();
    let group = Arc::new(Group::new(log, None).unwrap());
    let bus = Arc::new(Bus::builder(group.clone()).build().unwrap());
    Arc::new(
        Node::spawn(Arc::new(id), group, bus, NodeOptions::default())
            .await
            .unwrap(),
    )
}

/// Review finding 5: a removed device used to keep its open connection (and could keep
/// sending requests). Removal now cuts it and interrupts what it was running.
#[tokio::test]
async fn removal_cuts_the_connection_and_the_running_call() {
    let release = Arc::new(Notify::new());
    let pc = pc_with(release.clone(), None).await;
    let phone = member_of(&pc, "iPhone").await;

    let call = {
        let (phone, addr) = (phone.clone(), pc.addr());
        tokio::spawn(async move { phone.call(addr, Request::new("slow.read", json!({}))).await })
    };
    while pc.bus().leases().active().is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    pc.remove(phone.id()).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .unwrap()
        .unwrap();
    // Either the bus answered "interrupted" before the cut, or the connection was closed.
    assert!(
        outcome.is_err()
            || matches!(
                outcome,
                Ok(Response::Error {
                    code: ErrorCode::Interrupted,
                    ..
                })
            ),
        "got {outcome:?}"
    );
    assert!(pc.bus().leases().active().is_empty());
}

/// Review finding 7: a device removed while its approval prompt was open must not get a
/// session when the prompt is then approved.
#[tokio::test]
async fn removal_during_a_pending_approval_wins() {
    let release = Arc::new(Notify::new());
    let shown = Arc::new(Notify::new());
    let answer = Arc::new(Notify::new());
    let prompter: Arc<dyn Prompter> = Arc::new(HeldPrompt(shown.clone(), answer.clone()));
    let pc = pc_with(release, Some(prompter)).await;
    let phone = member_of(&pc, "iPhone").await;

    let call = {
        let (phone, addr) = (phone.clone(), pc.addr());
        tokio::spawn(async move {
            phone
                .call(addr, Request::new("slow.secret", json!({})))
                .await
        })
    };
    shown.notified().await; // the PC's user sees the prompt
    pc.remove(phone.id()).unwrap(); // meanwhile, the phone is removed
    answer.notify_one(); // the user, unaware, says yes
    let outcome = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .unwrap()
        .unwrap();
    assert!(
        outcome.is_err()
            || matches!(
                outcome,
                Ok(Response::Error {
                    code: ErrorCode::NotMember,
                    ..
                })
            ),
        "got {outcome:?}"
    );
    assert!(
        pc.bus().leases().active().is_empty(),
        "no session for a removed device"
    );
}

/// Many devices join at once: every admission lands in one valid log, none is lost.
#[tokio::test]
async fn concurrent_joins_all_land_in_one_valid_log() {
    let pc = pc_with(Arc::new(Notify::new()), None).await;
    let mut joins = tokio::task::JoinSet::new();
    for i in 0..12 {
        let inv = pc.invite(300).unwrap();
        joins.spawn(async move {
            let id = Identity::generate();
            join(&id, &inv, &format!("Device {i}"), Network::LocalOnly)
                .await
                .map(|_| id.id())
        });
    }
    let mut joined = Vec::new();
    while let Some(r) = joins.join_next().await {
        joined.push(r.unwrap().unwrap());
    }
    let m = pc.group().log().verify().unwrap();
    assert_eq!(m.members.len(), 13);
    assert!(joined.iter().all(|d| m.is_member(d)));
}

/// Many calls at once on one device: every one is answered and journaled.
#[tokio::test]
async fn concurrent_calls_are_all_answered() {
    let pc = pc_with(Arc::new(Notify::new()), None).await;
    let phone = member_of(&pc, "iPhone").await;
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..40 {
        let (phone, addr) = (phone.clone(), pc.addr());
        calls.spawn(async move {
            phone
                .call(addr, Request::new("device.info", json!({})))
                .await
        });
    }
    let mut ok = 0;
    while let Some(r) = calls.join_next().await {
        if matches!(r.unwrap().unwrap(), Response::Ok { .. }) {
            ok += 1;
        }
    }
    assert_eq!(ok, 40);
    assert_eq!(pc.bus().journal().recent().len(), 40);
}

/// Review finding 3: a joiner can no longer take a name that looks like an existing one.
#[tokio::test]
async fn a_joiner_cannot_impersonate_by_name() {
    let pc = pc_with(Arc::new(Notify::new()), None).await;
    for name in ["PC", "pc", "P\u{200B}C", "PC\u{202E}"] {
        let inv = pc.invite(300).unwrap();
        let r = join(&Identity::generate(), &inv, name, Network::LocalOnly).await;
        assert!(r.is_err(), "{name:?} was accepted");
    }
    assert_eq!(pc.group().membership().members.len(), 1);
}

/// Review follow-up: when this device's branch loses a fork, what it wrote is replayed on
/// the winner, so a removal made here is not lost.
#[tokio::test]
async fn the_losing_side_replays_its_removals() {
    let pc = pc_with(Arc::new(Notify::new()), None).await;
    // The laptop joins as an approver; two phones join as members.
    let inv = pc.invite_approver(300).unwrap();
    let laptop_id = Identity::generate();
    let (log, _) = join(&laptop_id, &inv, "Laptop", Network::LocalOnly)
        .await
        .unwrap();
    let p = member_of(&pc, "Phone P").await;
    let q = member_of(&pc, "Phone Q").await;
    let laptop_group = Arc::new(Group::new(log, None).unwrap());
    let laptop = Node::spawn(
        Arc::new(laptop_id),
        laptop_group.clone(),
        Arc::new(Bus::builder(laptop_group).build().unwrap()),
        NodeOptions::default(),
    )
    .await
    .unwrap();
    laptop.sync_log(pc.addr()).await.unwrap(); // laptop now knows both phones

    // Offline from each other: the PC removes P, the laptop removes Q.
    pc.remove(p.id()).unwrap();
    laptop.remove(q.id()).unwrap();

    // They meet. The founder's branch wins the tie; the laptop replays its removal.
    let m = laptop.adopt_log(pc.group().log()).unwrap();
    assert!(!m.is_member(&p.id()), "the PC's removal is kept");
    assert!(!m.is_member(&q.id()), "the laptop's removal was replayed");
    let m = pc.adopt_log(laptop.group().log()).unwrap();
    assert!(!m.is_member(&p.id()) && !m.is_member(&q.id()));
    assert_eq!(pc.group().log(), laptop.group().log(), "both converged");
}

/// Found testing the desktop app: an approval that takes longer than the request read
/// timeout made the caller give up. The caller now waits for the human.
#[tokio::test]
async fn a_slow_approval_does_not_time_out_the_caller() {
    struct SlowYes;
    #[async_trait]
    impl Prompter for SlowYes {
        async fn ask(&self, _: &ApprovalPrompt) -> bool {
            tokio::time::sleep(Duration::from_secs(17)).await; // longer than READ_TIMEOUT
            true
        }
    }
    let release = Arc::new(Notify::new());
    let pc = pc_with(release.clone(), Some(Arc::new(SlowYes))).await;
    let phone = member_of(&pc, "iPhone").await;
    let call = {
        let (phone, addr) = (phone.clone(), pc.addr());
        tokio::spawn(async move {
            phone
                .call(addr, Request::new("slow.secret", json!({})))
                .await
        })
    };
    // Let the module finish once approved.
    tokio::time::sleep(Duration::from_secs(18)).await;
    release.notify_one();
    let outcome = tokio::time::timeout(Duration::from_secs(30), call)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(outcome, Ok(Response::Ok { .. })),
        "got {outcome:?}"
    );
}
