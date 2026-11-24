//! Waking a sleeping device: only members of the same group can ask, the server only
//! hands the opaque token to its hook, and not too often.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use passer_bus::Bus;
use passer_coord::{Server, WakeHook, sync, sync_with, wake};
use passer_identity::Identity;
use passer_membership::{DeviceLog, GroupId};
use passer_node::{Group, Network, Node, NodeOptions, join, now_secs};

#[derive(Default)]
struct Gateway(Mutex<Vec<String>>);

#[async_trait]
impl WakeHook for Gateway {
    async fn wake(&self, token: &str, _group: GroupId) -> anyhow::Result<()> {
        self.0.lock().unwrap().push(token.to_owned());
        Ok(())
    }
}

async fn node_from(identity: Identity, log: DeviceLog) -> Node {
    let group = Arc::new(Group::new(log, None).unwrap());
    let bus = Arc::new(Bus::builder(group.clone()).build().unwrap());
    Node::spawn(Arc::new(identity), group, bus, NodeOptions::default())
        .await
        .unwrap()
}

#[tokio::test]
async fn members_wake_members_and_nobody_else() {
    let gateway = Arc::new(Gateway::default());
    let server = Server::spawn_with(&Identity::generate(), 0, Some(gateway.clone()))
        .await
        .unwrap();

    let pc_id = Identity::generate();
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let pc = node_from(pc_id, log).await;
    let phone_id = Identity::generate();
    let (log, _) = join(
        &phone_id,
        &pc.invite(300).unwrap(),
        "iPhone",
        Network::LocalOnly,
    )
    .await
    .unwrap();
    let phone = node_from(phone_id, log).await;

    // Without a token there is nothing to send.
    sync(&pc, server.addr()).await.unwrap();
    sync(&phone, server.addr()).await.unwrap();
    assert!(!wake(&pc, server.addr(), phone.id()).await.unwrap());

    // The phone registers its token; the PC wakes it once, not twice in a row.
    sync_with(&phone, server.addr(), Some("apns-token-123".into()))
        .await
        .unwrap();
    assert!(wake(&pc, server.addr(), phone.id()).await.unwrap());
    assert!(!wake(&pc, server.addr(), phone.id()).await.unwrap());
    assert_eq!(*gateway.0.lock().unwrap(), vec!["apns-token-123"]);

    // A plain sync keeps the token; an empty one removes it.
    sync(&phone, server.addr()).await.unwrap();
    sync_with(&phone, server.addr(), Some(String::new()))
        .await
        .unwrap();

    // A stranger cannot wake anyone, even with the group's id.
    let stranger_id = Identity::generate();
    let other = DeviceLog::create(&stranger_id, "Other", "X", now_secs()).unwrap();
    let stranger = node_from(stranger_id, other).await;
    sync(&stranger, server.addr()).await.unwrap();
    assert!(wake(&stranger, server.addr(), phone.id()).await.is_err());
    assert_eq!(gateway.0.lock().unwrap().len(), 1);
}
