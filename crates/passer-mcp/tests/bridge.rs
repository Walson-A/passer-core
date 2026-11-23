//! An MCP client (as Claude Desktop would be) talks to the bridge on the laptop, which
//! reaches the PC over passer-core. The PC decides what the agent may do.

use std::sync::Arc;

use passer_bus::{Bus, Decision, Policy, Rule, Who};
use passer_device_info::DeviceInfo;
use passer_identity::Identity;
use passer_mcp::Bridge;
use passer_membership::DeviceLog;
use passer_node::{Group, Network, Node, NodeOptions, join, now_secs};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::json;

/// The PC (with `device.info`) and the laptop that runs the bridge for agent "claude".
async fn pc_and_laptop(grant: bool) -> (Arc<Node>, Arc<Node>) {
    let pc_id = Arc::new(Identity::generate());
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let pc_group = Arc::new(Group::new(log, None).unwrap());
    let pc_bus = Arc::new(
        Bus::builder(pc_group.clone())
            .module(Arc::new(DeviceInfo::new("PC")))
            .build()
            .unwrap(),
    );
    let pc = Arc::new(
        Node::spawn(pc_id, pc_group, pc_bus.clone(), NodeOptions::default())
            .await
            .unwrap(),
    );

    let inv = pc.invite(300).unwrap();
    let laptop_id = Identity::generate();
    let (log, _) = join(&laptop_id, &inv, "Laptop", Network::LocalOnly)
        .await
        .unwrap();
    if grant {
        pc_bus.set_policy(Policy::new(vec![Rule {
            who: Who::Agent {
                name: "claude".into(),
                via: Some(laptop_id.id()),
            },
            capability: "device.info".into(),
            target: None,
            decision: Decision::Allow,
            lease_secs: None,
        }]));
    }
    let laptop_group = Arc::new(Group::new(log, None).unwrap());
    let laptop_bus = Arc::new(Bus::builder(laptop_group.clone()).build().unwrap());
    let laptop = Arc::new(
        Node::spawn(
            Arc::new(laptop_id),
            laptop_group,
            laptop_bus,
            NodeOptions::default(),
        )
        .await
        .unwrap(),
    );
    laptop.peers().remember(pc.addr());
    (pc, laptop)
}

#[tokio::test]
async fn agent_sees_nothing_until_a_device_grants_it() {
    let (_pc, laptop) = pc_and_laptop(false).await;
    let bridge = Bridge::new(laptop, "claude");
    assert!(bridge.discover().await.is_empty());
    let r = bridge
        .invoke(
            "device_info",
            serde_json::Map::from_iter([("device".into(), json!("PC"))]),
        )
        .await;
    assert_eq!(r.is_error, Some(true));
}

#[tokio::test]
async fn granted_capability_becomes_a_tool_over_real_mcp() {
    let (pc, laptop) = pc_and_laptop(true).await;
    let bridge = Bridge::new(laptop.clone(), "claude");

    // A real MCP session over an in-memory pipe.
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let running = bridge.serve(server_io).await.unwrap();
        let _ = running.waiting().await;
    });
    let client = ().serve(client_io).await.unwrap();

    let tools = client.list_all_tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    let tool = &tools[0];
    assert_eq!(tool.name, "device_info");
    let annotations = tool.annotations.as_ref().unwrap();
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(
        tool.input_schema["properties"]["device"]["enum"],
        json!(["PC"])
    );
    assert_eq!(tool.input_schema["required"], json!(["device"]));

    let args = serde_json::Map::from_iter([("device".to_owned(), json!("PC"))]);
    let result = client
        .call_tool(CallToolRequestParams::new("device_info").with_arguments(args))
        .await
        .unwrap();
    assert_ne!(result.is_error, Some(true), "{result:?}");
    assert_eq!(result.structured_content.unwrap()["name"], "PC");

    // The PC journaled it as the agent, relayed by the laptop.
    let line = pc
        .bus()
        .journal()
        .recent()
        .into_iter()
        .rev()
        .find(|l| l.record.capability == "device.info")
        .unwrap();
    assert_eq!(line.record.agent.as_deref(), Some("claude"));
    assert_eq!(line.record.device, laptop.id().to_string());

    client.cancel().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn another_agent_name_gets_nothing() {
    let (_pc, laptop) = pc_and_laptop(true).await;
    let bridge = Bridge::new(laptop, "some-other-agent");
    assert!(bridge.discover().await.is_empty());
}
