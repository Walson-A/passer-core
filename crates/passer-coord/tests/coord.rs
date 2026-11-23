//! The coordination server distributes logs and addresses — and nothing it does can add a
//! device or resurrect a removed one.

use std::sync::Arc;

use passer_bus::{Bus, Request, Response};
use passer_coord::{Server, sync};
use passer_device_info::DeviceInfo;
use passer_identity::Identity;
use passer_membership::DeviceLog;
use passer_node::{Group, Network, Node, NodeOptions, join, now_secs};
use serde_json::json;

async fn node_from(identity: Identity, log: DeviceLog, name: &str) -> Node {
    let group = Arc::new(Group::new(log, None).unwrap());
    let bus = Arc::new(
        Bus::builder(group.clone())
            .module(Arc::new(DeviceInfo::new(name)))
            .build()
            .unwrap(),
    );
    Node::spawn(Arc::new(identity), group, bus, NodeOptions::default())
        .await
        .unwrap()
}

async fn joined(host: &Node, name: &str) -> Node {
    let inv = host.invite(300).unwrap();
    let id = Identity::generate();
    let (log, _) = join(&id, &inv, name, Network::LocalOnly).await.unwrap();
    node_from(id, log, name).await
}

async fn setup() -> (Server, Node, Node) {
    let server = Server::spawn(&Identity::generate(), 0).await.unwrap();
    let pc_id = Identity::generate();
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let pc = node_from(pc_id, log, "PC").await;
    let phone = joined(&pc, "iPhone").await;
    (server, pc, phone)
}

#[tokio::test]
async fn devices_find_each_other_through_the_server() {
    let (server, pc, phone) = setup().await;
    sync(&phone, server.addr()).await.unwrap();
    let outcome = sync(&pc, server.addr()).await.unwrap();
    assert_eq!(outcome.online.len(), 1);
    assert_eq!(outcome.online[0].device, phone.id());

    // The PC never saw the phone's address directly: it comes from the server.
    let r = pc
        .call(phone.id(), Request::new("device.info", json!({})))
        .await
        .unwrap();
    let Response::Ok { output } = r else {
        panic!("{r:?}")
    };
    assert_eq!(output["name"], "iPhone");
    assert_eq!(server.state().groups(), 1);
}

#[tokio::test]
async fn removals_reach_offline_devices_through_the_server() {
    let (server, pc, phone) = setup().await;
    let tablet = joined(&pc, "iPad").await;
    sync(&tablet, server.addr()).await.unwrap(); // tablet's log: PC, iPhone, iPad
    pc.remove(phone.id()).unwrap();
    sync(&pc, server.addr()).await.unwrap(); // server learns the removal

    let outcome = sync(&tablet, server.addr()).await.unwrap();
    assert!(!tablet.group().membership().is_member(&phone.id()));
    assert_eq!(outcome.members, 2);

    // The removed phone is told, and gets no addresses.
    let outcome = sync(&phone, server.addr()).await.unwrap();
    assert!(outcome.removed);
    assert!(!phone.group().membership().is_member(&phone.id()));
}

#[tokio::test]
async fn an_old_log_cannot_roll_the_server_back() {
    let (server, pc, phone) = setup().await;
    let stale = pc.group().log(); // before the removal
    pc.remove(phone.id()).unwrap();
    sync(&pc, server.addr()).await.unwrap();

    // The phone (or anyone) republishes the old log in which the phone was a member.
    let id = Identity::generate();
    let replay = node_from(id, stale, "replay").await;
    let err = sync(&replay, server.addr()).await.unwrap_err();
    assert!(err.to_string().contains("not a member"), "{err}");
    // The server still holds the log with the removal.
    let outcome = sync(&pc, server.addr()).await.unwrap();
    assert!(outcome.online.iter().all(|p| p.device != phone.id()));
}

#[tokio::test]
async fn a_stranger_learns_nothing_about_a_group() {
    let (server, pc, phone) = setup().await;
    sync(&phone, server.addr()).await.unwrap();
    // A stranger holding a copy of the group's log (it is not secret) publishes it.
    let stranger = node_from(Identity::generate(), pc.group().log(), "stranger").await;
    let err = sync(&stranger, server.addr()).await.unwrap_err();
    assert!(err.to_string().contains("not a member"), "{err}");
}

#[tokio::test]
async fn a_forked_history_is_refused() {
    let (server, pc, _phone) = setup().await;
    sync(&pc, server.addr()).await.unwrap(); // stored: genesis, add iPhone

    // A second history from the same genesis, validly signed by the founder (as if its key
    // had been copied): genesis, add "Other". The server keeps the history it has.
    let honest = pc.group().log();
    let mut v: serde_json::Value = serde_json::from_str(&honest.to_json()).unwrap();
    v["entries"].as_array_mut().unwrap().truncate(1);
    let mut fork = DeviceLog::from_json(&v.to_string()).unwrap();
    let other = Identity::generate();
    fork.append(
        pc.identity(),
        passer_membership::Op::Add {
            device: other.id(),
            name: "Other".into(),
            approver: false,
        },
        now_secs(),
    )
    .unwrap();
    assert!(fork.verify().is_ok(), "the fork is valid on its own");

    let forked = node_from(other, fork, "Other").await;
    let err = sync(&forked, server.addr()).await.unwrap_err();
    assert!(err.to_string().contains("conflicts"), "{err}");
}
