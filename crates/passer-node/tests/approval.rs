//! Sensitive capabilities: who gets asked, and who never may answer.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use passer_bus::{
    Bus, Capability, Ctx, Effect, ErrorCode, Manifest, Module, ModuleError, Request, Response,
};
use passer_identity::Identity;
use passer_membership::DeviceLog;
use passer_node::approval::{
    ApprovalModule, ApprovalPrompt, AutoPrompter, Prompter, RemoteApprover,
};
use passer_node::{Group, Network, Node, NodeOptions, join, now_secs};
use serde_json::{Value, json};

/// A sensitive capability, standing in for "read the clipboard".
struct Secret;

#[async_trait]
impl Module for Secret {
    fn manifest(&self) -> Manifest {
        Manifest {
            module: "secret".into(),
            version: "0".into(),
            capabilities: vec![Capability::call(
                "clipboard.read",
                "Read the clipboard",
                "test",
                Effect::Sensitive,
                json!({"type": "object"}),
            )],
        }
    }
    async fn invoke(&self, _: Ctx, _: &str, _: Value) -> Result<Value, ModuleError> {
        Ok(json!({"text": "copied"}))
    }
}

#[derive(Default)]
struct Recording(Mutex<Vec<ApprovalPrompt>>, bool);

#[async_trait]
impl Prompter for Recording {
    async fn ask(&self, p: &ApprovalPrompt) -> bool {
        self.0.lock().unwrap().push(p.clone());
        self.1
    }
}

/// The PC acts (it has the clipboard); `local` is its own user's answer, if any.
async fn spawn_pc(local: Option<bool>) -> (Node, Identity) {
    let id = Arc::new(Identity::generate());
    let log = DeviceLog::create(&id, "Walson", "PC", now_secs()).unwrap();
    let group = Arc::new(Group::new(log, None).unwrap());
    let prompter: Option<Arc<dyn Prompter>> =
        local.map(|a| Arc::new(AutoPrompter(a)) as Arc<dyn Prompter>);
    let approver = RemoteApprover::new(group.clone(), prompter);
    let bus = Arc::new(
        Bus::builder(group.clone())
            .module(Arc::new(Secret))
            .approver(approver.clone())
            .build()
            .unwrap(),
    );
    let opts = NodeOptions {
        approver: Some(approver),
        ..Default::default()
    };
    let node = Node::spawn(id, group, bus, opts).await.unwrap();
    (node, Identity::generate())
}

/// A device that joins `host`, optionally as an approver answering with `prompter`.
async fn device(host: &Node, name: &str, approver: Option<Arc<dyn Prompter>>) -> Node {
    let inv = if approver.is_some() {
        host.invite_approver(300)
    } else {
        host.invite(300)
    }
    .unwrap();
    let id = Identity::generate();
    let (log, _) = join(&id, &inv, name, Network::LocalOnly).await.unwrap();
    let group = Arc::new(Group::new(log, None).unwrap());
    let mut builder = Bus::builder(group.clone());
    if let Some(p) = approver {
        builder = builder.module(Arc::new(ApprovalModule::new(group.clone(), p)));
    }
    let node = Node::spawn(
        Arc::new(id),
        group,
        Arc::new(builder.build().unwrap()),
        NodeOptions::default(),
    )
    .await
    .unwrap();
    host.peers().remember(node.addr());
    node
}

async fn read_clipboard(phone: &Node, pc: &Node) -> Response {
    phone
        .call(pc.addr(), Request::new("clipboard.read", json!({})))
        .await
        .unwrap()
}

#[tokio::test]
async fn another_approver_says_yes() {
    let (pc, _) = spawn_pc(None).await;
    let tablet_prompter = Arc::new(Recording(Mutex::default(), true));
    let tablet = device(&pc, "iPad", Some(tablet_prompter.clone())).await;
    let phone = device(&pc, "iPhone", None).await;
    tablet.sync_log(pc.addr()).await.unwrap(); // the tablet learns about the phone

    let r = read_clipboard(&phone, &pc).await;
    assert_eq!(
        r,
        Response::Ok {
            output: json!({"text": "copied"})
        }
    );

    let prompts = tablet_prompter.0.lock().unwrap();
    assert_eq!(prompts.len(), 1);
    assert_eq!(
        prompts[0].requester_name, "iPhone",
        "names come from the approver's own log"
    );
    assert_eq!(prompts[0].target_device_name, "PC");
    assert_eq!(prompts[0].title, "Read the clipboard");
}

#[tokio::test]
async fn another_approver_says_no() {
    let (pc, _) = spawn_pc(None).await;
    let _tablet = device(&pc, "iPad", Some(Arc::new(AutoPrompter(false)))).await;
    let phone = device(&pc, "iPhone", None).await;
    assert_eq!(
        read_clipboard(&phone, &pc).await.code(),
        Some(ErrorCode::Denied)
    );
}

#[tokio::test]
async fn a_request_never_approves_itself() {
    let (pc, _) = spawn_pc(None).await;
    // The phone is an approver that would say yes, but it is the one asking.
    let phone = device(&pc, "iPhone", Some(Arc::new(AutoPrompter(true)))).await;
    assert_eq!(
        read_clipboard(&phone, &pc).await.code(),
        Some(ErrorCode::Denied)
    );
}

#[tokio::test]
async fn the_target_user_can_approve_locally() {
    let (pc, _) = spawn_pc(Some(true)).await;
    let phone = device(&pc, "iPhone", None).await;
    assert!(read_clipboard(&phone, &pc).await.code().is_none());

    let (pc, _) = spawn_pc(Some(false)).await;
    let phone = device(&pc, "iPhone", None).await;
    assert_eq!(
        read_clipboard(&phone, &pc).await.code(),
        Some(ErrorCode::Denied)
    );
}

#[tokio::test]
async fn approval_requests_from_outside_the_group_are_refused() {
    let (pc, _) = spawn_pc(None).await;
    let tablet_prompter = Arc::new(Recording(Mutex::default(), true));
    let tablet = device(&pc, "iPad", Some(tablet_prompter.clone())).await;
    // A device of another group tries to make the tablet's user approve something.
    let other_id = Arc::new(Identity::generate());
    let other_log = DeviceLog::create(&other_id, "Other", "X", now_secs()).unwrap();
    let other_group = Arc::new(Group::new(other_log, None).unwrap());
    let other_bus = Arc::new(Bus::builder(other_group.clone()).build().unwrap());
    let other = Node::spawn(other_id, other_group, other_bus, NodeOptions::default())
        .await
        .unwrap();
    let r = other
        .call(tablet.addr(), Request::new("approval.request", json!({})))
        .await;
    assert!(r.is_err(), "not even a member of its own group view");
    assert!(
        tablet_prompter.0.lock().unwrap().is_empty(),
        "the tablet's user was never bothered"
    );
}
