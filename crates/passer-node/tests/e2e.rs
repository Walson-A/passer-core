//! Two (and three) devices on one machine, talking over real iroh/QUIC connections.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::presets;
use passer_bus::{Bus, ErrorCode, Request, Response};
use passer_device_info::DeviceInfo;
use passer_identity::Identity;
use passer_membership::DeviceLog;
use passer_membership::pairing::Invitation;
use passer_node::{Group, Network, Node, frame, join, now_secs};
use serde_json::json;

const T: Duration = Duration::from_secs(20);

async fn spawn_node(identity: Identity, log: DeviceLog, name: &str) -> Node {
    let identity = Arc::new(identity);
    let group = Arc::new(Group::new(log, None).unwrap());
    let bus = Arc::new(
        Bus::builder(group.clone())
            .module(Arc::new(DeviceInfo::new(name)))
            .build()
            .unwrap(),
    );
    Node::spawn(identity, group, bus, Network::LocalOnly, None)
        .await
        .unwrap()
}

/// PC founds the group; the phone joins with an invitation and gets a node of its own.
async fn pc_and_phone() -> (Node, Node, String) {
    let pc_id = Identity::generate();
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let pc = spawn_node(pc_id, log, "PC").await;

    let invitation = pc.invite(300).unwrap();
    let scanned = Invitation::parse_link(&invitation.to_link()).unwrap();
    let phone_id = Identity::generate();
    let (phone_log, sas) =
        tokio::time::timeout(T, join(&phone_id, &scanned, "iPhone", Network::LocalOnly))
            .await
            .expect("join timed out")
            .unwrap();
    let phone = spawn_node(phone_id, phone_log, "iPhone").await;
    (pc, phone, sas)
}

#[tokio::test]
async fn join_then_call_both_ways() {
    let (pc, phone, sas) = pc_and_phone().await;
    assert_eq!(sas.len(), 6);
    assert!(pc.group().membership().is_member(&phone.id()));

    let r = tokio::time::timeout(
        T,
        phone.call(pc.addr(), Request::new("device.info", json!({}))),
    )
    .await
    .unwrap()
    .unwrap();
    let Response::Ok { output } = r else {
        panic!("unexpected {r:?}")
    };
    assert_eq!(output["name"], "PC");

    let r = tokio::time::timeout(
        T,
        pc.call(phone.addr(), Request::new("device.info", json!({}))),
    )
    .await
    .unwrap()
    .unwrap();
    let Response::Ok { output } = r else {
        panic!("unexpected {r:?}")
    };
    assert_eq!(output["name"], "iPhone");

    // The listing only shows what the caller may use.
    let r = phone
        .call(pc.addr(), Request::new("bus.capabilities", json!({})))
        .await
        .unwrap();
    let Response::Ok { output } = r else { panic!() };
    assert_eq!(output["capabilities"][0]["name"], "device.info");

    // Both sides journaled the calls, without content.
    assert!(
        pc.bus()
            .journal()
            .recent()
            .iter()
            .any(|l| l.record.capability == "device.info")
    );
}

#[tokio::test]
async fn invitation_cannot_be_reused() {
    let pc_id = Identity::generate();
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let pc = spawn_node(pc_id, log, "PC").await;
    let invitation = pc.invite(300).unwrap();

    join(
        &Identity::generate(),
        &invitation,
        "iPhone",
        Network::LocalOnly,
    )
    .await
    .unwrap();
    let second = join(
        &Identity::generate(),
        &invitation,
        "Intruder",
        Network::LocalOnly,
    )
    .await;
    assert!(
        second
            .unwrap_err()
            .to_string()
            .contains("no pending invitation")
    );
    assert_eq!(pc.group().membership().members.len(), 2);
}

#[tokio::test]
async fn stranger_is_cut_off_at_the_connection() {
    let (pc, _phone, _) = pc_and_phone().await;
    let stranger = Identity::generate();
    let ep = iroh::Endpoint::builder(presets::Minimal)
        .secret_key(stranger.secret_key().clone())
        .bind()
        .await
        .unwrap();
    let conn = ep.connect(pc.addr(), passer_node::BUS_ALPN).await.unwrap();
    let outcome = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        frame::write_frame(&mut send, &Request::new("device.info", json!({})))
            .await
            .map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())?;
        frame::read_frame::<Response>(&mut recv)
            .await
            .map_err(|e| e.to_string())
    }
    .await;
    assert!(
        outcome.is_err(),
        "a non-member must not get an answer, got {outcome:?}"
    );
    ep.close().await;
}

#[tokio::test]
async fn removed_device_loses_access_and_learns_it() {
    let (pc, phone, _) = pc_and_phone().await;
    pc.remove(phone.id()).unwrap();

    // The PC now refuses the phone's connections.
    let r = tokio::time::timeout(
        T,
        phone.call(pc.addr(), Request::new("device.info", json!({}))),
    )
    .await
    .unwrap();
    assert!(
        r.is_err()
            || matches!(
                r,
                Ok(Response::Error {
                    code: ErrorCode::NotMember,
                    ..
                })
            ),
        "got {r:?}"
    );

    // A third device, still a member, can fetch the signed removal; the server is not needed.
    let tablet_inv = pc.invite(300).unwrap();
    let tablet_id = Identity::generate();
    let (tablet_log, _) = join(&tablet_id, &tablet_inv, "iPad", Network::LocalOnly)
        .await
        .unwrap();
    let tablet = spawn_node(tablet_id, tablet_log, "iPad").await;
    let m = tablet.sync_log(pc.addr()).await.unwrap();
    assert!(!m.is_member(&phone.id()));
    assert!(m.revoked.contains(&phone.id()));
}

#[tokio::test]
async fn admission_hook_reports_the_same_code() {
    let pc_id = Arc::new(Identity::generate());
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let group = Arc::new(Group::new(log, None).unwrap());
    let bus = Arc::new(Bus::builder(group.clone()).build().unwrap());
    let seen = Arc::new(Mutex::new(None));
    let hook_seen = seen.clone();
    let hook: passer_node::AdmissionHook = Arc::new(move |_, name, sas| {
        *hook_seen.lock().unwrap() = Some((name.to_owned(), sas.to_owned()));
    });
    let pc = Node::spawn(pc_id, group, bus, Network::LocalOnly, Some(hook))
        .await
        .unwrap();
    let inv = pc.invite(300).unwrap();
    let (_, sas) = join(&Identity::generate(), &inv, "iPhone", Network::LocalOnly)
        .await
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), Some(("iPhone".to_owned(), sas)));
}
