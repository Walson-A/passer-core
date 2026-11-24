//! Streams between two devices over real QUIC connections: large uploads and downloads,
//! refusals, interruption by the stop button, and broken transfers that must not pass
//! for complete ones.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use passer_bus::{
    Bus, Capability, Ctx, Decision, Effect, ErrorCode, Manifest, Mode, Module, ModuleError, Policy,
    Request, Response, Rule, StreamIo, Who,
};
use passer_identity::Identity;
use passer_membership::DeviceLog;
use passer_membership::pairing::Invitation;
use passer_node::{Group, Network, Node, NodeOptions, join, now_secs};
use serde_json::{Value, json};

const T: Duration = Duration::from_secs(60);

/// A file store: `files.put` receives bytes, `files.get` sends `size` bytes back,
/// `files.slow` sends forever until stopped.
struct Files;

fn pattern(i: usize) -> u8 {
    (i % 251) as u8
}

fn stream_cap(name: &str, effect: Effect) -> Capability {
    let mut cap = Capability::call(name, name, name, effect, json!({ "type": "object" }));
    cap.mode = Mode::Stream;
    cap
}

#[async_trait]
impl Module for Files {
    fn manifest(&self) -> Manifest {
        Manifest {
            module: "files".into(),
            version: "1".into(),
            capabilities: vec![
                stream_cap("files.put", Effect::Write),
                stream_cap("files.get", Effect::Read),
                stream_cap("files.slow", Effect::Read),
            ],
        }
    }

    async fn invoke(&self, _: Ctx, c: &str, _: Value) -> Result<Value, ModuleError> {
        Err(ModuleError::Unsupported(c.into()))
    }

    async fn invoke_stream(
        &self,
        _ctx: Ctx,
        capability: &str,
        input: Value,
        mut io: StreamIo,
    ) -> Result<Value, ModuleError> {
        match capability {
            "files.put" => {
                let mut hasher = blake3::Hasher::new();
                let mut bytes = 0u64;
                loop {
                    match io.incoming.next().await {
                        Ok(Some(chunk)) => {
                            bytes += chunk.len() as u64;
                            hasher.update(&chunk);
                        }
                        Ok(None) => break,
                        Err(e) => return Err(ModuleError::Failed(e.to_string())),
                    }
                }
                Ok(json!({ "bytes": bytes, "hash": hasher.finalize().to_hex().to_string() }))
            }
            "files.get" => {
                let size = input["size"].as_u64().unwrap_or(0) as usize;
                let mut sent = 0;
                while sent < size {
                    let n = (size - sent).min(100_000);
                    let piece: Vec<u8> = (sent..sent + n).map(pattern).collect();
                    io.outgoing
                        .send(&piece)
                        .await
                        .map_err(|e| ModuleError::Failed(e.to_string()))?;
                    sent += n;
                }
                Ok(json!({ "bytes": sent }))
            }
            "files.slow" => loop {
                if io.outgoing.send(&[1u8; 1024]).await.is_err() {
                    return Err(ModuleError::Failed("reader gone".into()));
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            },
            other => Err(ModuleError::Unsupported(other.into())),
        }
    }
}

async fn spawn(identity: Identity, log: DeviceLog, policy: Policy) -> Node {
    let identity = Arc::new(identity);
    let group = Arc::new(Group::new(log, None).unwrap());
    let bus = Arc::new(
        Bus::builder(group.clone())
            .module(Arc::new(Files))
            .module(Arc::new(passer_device_info::DeviceInfo::new("x")))
            .policy(policy)
            .build()
            .unwrap(),
    );
    Node::spawn(identity, group, bus, NodeOptions::default())
        .await
        .unwrap()
}

async fn pc_and_phone(pc_policy: Policy) -> (Node, Node) {
    let pc_id = Identity::generate();
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let pc = spawn(pc_id, log, pc_policy).await;
    let invitation = Invitation::parse_link(&pc.invite(300).unwrap().to_link()).unwrap();
    let phone_id = Identity::generate();
    let (phone_log, _) = join(&phone_id, &invitation, "iPhone", Network::LocalOnly)
        .await
        .unwrap();
    let phone = spawn(phone_id, phone_log, Policy::default()).await;
    (pc, phone)
}

#[tokio::test]
async fn a_large_upload_arrives_whole() {
    let (pc, phone) = pc_and_phone(Policy::default()).await;
    let size = 5 * 1024 * 1024 + 123;
    let data: Vec<u8> = (0..size).map(pattern).collect();

    let open = phone
        .open_stream(pc.addr(), Request::new("files.put", json!({})))
        .await
        .unwrap()
        .expect("the PC accepts the stream");
    let sender = {
        let data = data.clone();
        let outgoing = open.io.outgoing;
        tokio::spawn(async move {
            for piece in data.chunks(64 * 1024) {
                outgoing.send(piece).await.unwrap();
            }
            // Dropping `outgoing` says this side is done.
        })
    };
    sender.await.unwrap();
    let result = tokio::time::timeout(T, open.done)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Response::Ok { output } = result else {
        panic!("unexpected {result:?}")
    };
    assert_eq!(output["bytes"], size as u64);
    assert_eq!(output["hash"], blake3::hash(&data).to_hex().to_string());

    // One journal line for the whole stream, on the PC.
    let lines = pc.bus().journal().recent();
    let line = lines
        .iter()
        .find(|l| l.record.capability == "files.put")
        .unwrap();
    assert_eq!(line.record.outcome, "ok");
}

#[tokio::test]
async fn a_large_download_arrives_whole() {
    let (pc, phone) = pc_and_phone(Policy::default()).await;
    let size = 3 * 1024 * 1024 + 7;
    let mut open = phone
        .open_stream(
            pc.addr(),
            Request::new("files.get", json!({ "size": size })),
        )
        .await
        .unwrap()
        .unwrap();
    drop(open.io.outgoing); // nothing to send
    let mut received = Vec::with_capacity(size);
    while let Some(chunk) = tokio::time::timeout(T, open.io.incoming.next())
        .await
        .unwrap()
        .unwrap()
    {
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received.len(), size);
    assert!(received.iter().enumerate().all(|(i, b)| *b == pattern(i)));
    let result = open.done.await.unwrap().unwrap();
    assert!(matches!(result, Response::Ok { .. }), "{result:?}");
}

#[tokio::test]
async fn streams_go_through_the_policy_and_modes_do_not_mix() {
    let deny = Policy {
        rules: vec![Rule {
            who: Who::AnyDevice,
            capability: "files.*".into(),
            target: None,
            decision: Decision::Deny,
            lease_secs: None,
        }],
    };
    let (pc, phone) = pc_and_phone(deny).await;
    let refused = phone
        .open_stream(pc.addr(), Request::new("files.put", json!({})))
        .await
        .unwrap();
    match refused {
        Err(r) => assert_eq!(r.code(), Some(ErrorCode::Denied)),
        Ok(_) => panic!("a denied stream must not open"),
    }

    // A stream capability called as a call, and a call opened as a stream.
    let (pc, phone) = pc_and_phone(Policy::default()).await;
    let r = phone
        .call(pc.addr(), Request::new("files.put", json!({})))
        .await
        .unwrap();
    assert_eq!(r.code(), Some(ErrorCode::Unsupported));
    match phone
        .open_stream(pc.addr(), Request::new("device.info", json!({})))
        .await
        .unwrap()
    {
        Err(r) => assert_eq!(r.code(), Some(ErrorCode::Unsupported)),
        Ok(_) => panic!("a call capability must not open as a stream"),
    }
}

#[tokio::test]
async fn the_stop_button_interrupts_a_stream() {
    let (pc, phone) = pc_and_phone(Policy::default()).await;
    let mut open = phone
        .open_stream(pc.addr(), Request::new("files.slow", json!({})))
        .await
        .unwrap()
        .unwrap();
    // Some bytes arrive, then the PC's user presses stop.
    assert!(open.io.incoming.next().await.unwrap().is_some());
    pc.bus().leases().revoke_all("stopped by the user");
    // Keep reading until the end marker, then the result tells why.
    while let Ok(Some(_)) = tokio::time::timeout(T, open.io.incoming.next())
        .await
        .unwrap()
    {}
    let result = tokio::time::timeout(T, open.done)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.code(), Some(ErrorCode::Interrupted));
}

#[tokio::test]
async fn a_broken_upload_is_not_taken_for_a_whole_one() {
    let (pc, phone) = pc_and_phone(Policy::default()).await;
    let open = phone
        .open_stream(pc.addr(), Request::new("files.put", json!({})))
        .await
        .unwrap()
        .unwrap();
    open.io.outgoing.send(&[9u8; 200_000]).await.unwrap();
    // The phone goes away mid-transfer: its node shuts down, without an end marker.
    open.done.abort();
    std::mem::forget(open.io.outgoing); // never send the end marker
    phone.shutdown().await.unwrap();

    // The PC journals the stream as failed, not as a complete upload.
    let deadline = tokio::time::Instant::now() + T;
    loop {
        let lines = pc.bus().journal().recent();
        if let Some(l) = lines.iter().find(|l| l.record.capability == "files.put") {
            assert_ne!(
                l.record.outcome, "ok",
                "an incomplete upload must not succeed"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the PC never ended the stream"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
