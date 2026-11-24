//! A device that publishes too often is slowed down, without affecting the others.

use std::sync::Arc;

use passer_bus::Bus;
use passer_coord::{Server, sync};
use passer_identity::Identity;
use passer_membership::DeviceLog;
use passer_node::{Group, Node, NodeOptions, now_secs};

async fn node(identity: Identity, log: DeviceLog) -> Node {
    let group = Arc::new(Group::new(log, None).unwrap());
    let bus = Arc::new(Bus::builder(group.clone()).build().unwrap());
    Node::spawn(Arc::new(identity), group, bus, NodeOptions::default())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_chatty_device_is_slowed_down_alone() {
    let server = Server::spawn(&Identity::generate(), 0).await.unwrap();
    let make = || async {
        let id = Identity::generate();
        let log = DeviceLog::create(&id, "Home", "PC", now_secs()).unwrap();
        node(id, log).await
    };
    let chatty = make().await;
    let quiet = make().await;

    let mut refused = 0;
    for _ in 0..20 {
        if let Err(e) = sync(&chatty, server.addr()).await {
            assert!(e.to_string().contains("too many requests"), "{e}");
            refused += 1;
        }
    }
    assert!(refused > 0, "20 syncs in a row must hit the limit");
    sync(&quiet, server.addr())
        .await
        .expect("another device is not affected");
}
