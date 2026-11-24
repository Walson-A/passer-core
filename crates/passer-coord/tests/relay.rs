//! Devices that cannot reach each other directly: a self-hosted relay and the
//! coordination server are enough, nothing goes through n0.

use std::sync::Arc;
use std::time::Duration;

use iroh::EndpointAddr;
use passer_bus::{Bus, Request, Response};
use passer_coord::{Server, sync};
use passer_device_info::DeviceInfo;
use passer_identity::Identity;
use passer_membership::DeviceLog;
use passer_membership::pairing::Invitation;
use passer_node::{Group, Network, Node, NodeOptions, join, now_secs};
use serde_json::json;

const T: Duration = Duration::from_secs(30);

async fn node(identity: Identity, log: DeviceLog, network: Network) -> Node {
    let group = Arc::new(Group::new(log, None).unwrap());
    let bus = Arc::new(
        Bus::builder(group.clone())
            .module(Arc::new(DeviceInfo::new("x")))
            .build()
            .unwrap(),
    );
    let options = NodeOptions {
        network,
        ..Default::default()
    };
    Node::spawn(Arc::new(identity), group, bus, options)
        .await
        .unwrap()
}

#[tokio::test]
async fn join_and_call_through_a_self_hosted_relay() {
    let (_map, relay_url, _relay) = iroh::test_utils::run_relay_server().await.unwrap();
    let network = Network::InsecureTestRelay(relay_url.clone());

    let pc_id = Identity::generate();
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let pc = node(pc_id, log, network.clone()).await;
    tokio::time::timeout(T, pc.endpoint().online())
        .await
        .unwrap();

    // The invitation carries the relay; drop the direct addresses to prove it is enough.
    let mut invitation = Invitation::parse_link(&pc.invite(300).unwrap().to_link()).unwrap();
    assert_eq!(
        invitation.relay.as_deref(),
        Some(relay_url.to_string().as_str())
    );
    invitation.addrs.clear();

    let phone_id = Identity::generate();
    let (phone_log, sas) =
        tokio::time::timeout(T, join(&phone_id, &invitation, "iPhone", network.clone()))
            .await
            .expect("join through the relay timed out")
            .unwrap();
    assert_eq!(sas.len(), 6);
    let phone = node(phone_id, phone_log, network).await;
    tokio::time::timeout(T, phone.endpoint().online())
        .await
        .unwrap();

    // Both publish where they are; the phone learns the PC's relay from the server.
    let server = Server::spawn(&Identity::generate(), 0).await.unwrap();
    sync(&pc, server.addr()).await.unwrap();
    let outcome = sync(&phone, server.addr()).await.unwrap();
    let pc_presence = outcome.online.iter().find(|p| p.device == pc.id()).unwrap();
    assert_eq!(
        pc_presence.relay.as_deref(),
        Some(relay_url.to_string().as_str())
    );

    // Call the PC knowing only its relay.
    let only_relay = EndpointAddr::new(pc.id()).with_relay_url(relay_url);
    let r = tokio::time::timeout(
        T,
        phone.call(only_relay, Request::new("device.info", json!({}))),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(r, Response::Ok { .. }), "{r:?}");
}
