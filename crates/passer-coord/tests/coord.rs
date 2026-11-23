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
async fn concurrent_histories_converge() {
    let (server, pc, _phone) = setup().await;
    sync(&pc, server.addr()).await.unwrap(); // stored: genesis, add iPhone

    // A second history from the same genesis, also signed by the founder: genesis, add
    // "Other". Every party must end up with the same branch.
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
    let expected = match honest.prefer(&fork).unwrap() {
        passer_membership::Preferred::Theirs => fork.clone(),
        _ => honest.clone(),
    };
    let forked = node_from(other, fork, "Other").await;
    let forked_sync = sync(&forked, server.addr()).await;
    sync(&pc, server.addr()).await.unwrap();
    // Server and PC agree on the branch the rule picks, whichever arrived first.
    assert_eq!(pc.group().log(), expected);
    if expected == honest {
        // "Other" is not a member of the winning branch: it learns nothing.
        assert!(forked_sync.is_err());
    } else {
        assert_eq!(forked.group().log(), expected);
    }
}

/// The attack found in review, end to end: an approver phone is stolen and removed, but
/// the thief publishes a fork (made before the removal) first. The server and the other
/// devices still end up on the branch that removes the thief.
#[tokio::test]
async fn a_stolen_approver_cannot_take_over_through_the_server() {
    let server = Server::spawn(&Identity::generate(), 0).await.unwrap();
    let pc_id = Identity::generate();
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let pc = node_from(pc_id, log, "PC").await;
    let thief_inv = pc.invite_approver(300).unwrap();
    let thief_id = Identity::generate();
    let (thief_log, _) = join(&thief_id, &thief_inv, "Phone", Network::LocalOnly)
        .await
        .unwrap();
    let laptop = joined(&pc, "Laptop").await;
    sync(&laptop, server.addr()).await.unwrap();

    // The thief's fork: from its copy of the log, add an accomplice, remove the PC.
    let mut fork = thief_log;
    let accomplice = Identity::generate();
    fork.append(
        &thief_id,
        passer_membership::Op::Add {
            device: accomplice.id(),
            name: "Evil".into(),
            approver: true,
        },
        now_secs(),
    )
    .unwrap();
    fork.append(
        &thief_id,
        passer_membership::Op::Remove { device: pc.id() },
        now_secs(),
    )
    .unwrap();
    let thief = node_from(thief_id, fork, "Phone").await;
    sync(&thief, server.addr()).await.unwrap(); // published first

    // The owner removes the phone from the PC, then publishes.
    pc.remove(thief.id()).unwrap();
    sync(&pc, server.addr()).await.unwrap();

    // The laptop converges on the owner's branch; the thief is told it was removed.
    sync(&laptop, server.addr()).await.unwrap();
    let m = laptop.group().membership();
    assert!(m.is_member(&pc.id()));
    assert!(!m.is_member(&thief.id()));
    assert!(m.members.values().all(|x| x.name != "Evil"));
    assert!(sync(&thief, server.addr()).await.unwrap().removed);
}
