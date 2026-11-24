//! The whole wake-up path, with a stand-in for Apple: a phone registers its token, a PC
//! asks the coordination server to wake it, the server calls this gateway, the gateway
//! sends the push.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::routing::post;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use passer_bus::Bus;
use passer_coord::{HttpWakeHook, Server, WakeHook, sync, sync_with, wake};
use passer_identity::Identity;
use passer_membership::DeviceLog;
use passer_node::{Group, Network, Node, NodeOptions, join, now_secs};
use passer_push::{Apns, ApnsAuth, Gateway, router};

const SECRET: &str = "a-long-enough-test-secret";

#[derive(Default, Clone)]
struct FakeApple(Arc<Mutex<Vec<(String, HeaderMap, serde_json::Value)>>>);

async fn serve(app: Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn fake_apple() -> (FakeApple, String) {
    let seen = FakeApple::default();
    let record = seen.clone();
    let app = Router::new().route(
        "/3/device/{token}",
        post(
            move |uri: Uri, headers: HeaderMap, body: axum::body::Bytes| {
                let record = record.clone();
                async move {
                    let json = serde_json::from_slice(&body).unwrap_or_default();
                    record
                        .0
                        .lock()
                        .unwrap()
                        .push((uri.path().to_owned(), headers, json));
                    StatusCode::OK
                }
            },
        ),
    );
    let addr = serve(app).await;
    (seen, format!("http://{addr}"))
}

async fn gateway(apple: &str) -> String {
    let pem = SigningKey::from_bytes(&[9u8; 32].into())
        .unwrap()
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    let auth = ApnsAuth::new(&pem, "KEYID12345", "TEAMID6789").unwrap();
    let gateway = Arc::new(Gateway {
        secret: SECRET.into(),
        apns: Some(Apns::new(auth, "direct.passer.app", apple).unwrap()),
    });
    format!("http://{}/wake", serve(router(gateway)).await)
}

async fn node(identity: Identity, log: DeviceLog) -> Node {
    let group = Arc::new(Group::new(log, None).unwrap());
    let bus = Arc::new(Bus::builder(group.clone()).build().unwrap());
    Node::spawn(Arc::new(identity), group, bus, NodeOptions::default())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_pc_wakes_a_sleeping_iphone() {
    let (apple, apple_url) = fake_apple().await;
    let wake_url = gateway(&apple_url).await;
    let hook: Arc<dyn WakeHook> =
        Arc::new(HttpWakeHook::new(&wake_url, Some(SECRET.into())).unwrap());
    let server = Server::spawn_with(&Identity::generate(), 0, Some(hook))
        .await
        .unwrap();

    let pc_id = Identity::generate();
    let log = DeviceLog::create(&pc_id, "Walson", "PC", now_secs()).unwrap();
    let pc = node(pc_id, log).await;
    let phone_id = Identity::generate();
    let (log, _) = join(
        &phone_id,
        &pc.invite(300).unwrap(),
        "iPhone",
        Network::LocalOnly,
    )
    .await
    .unwrap();
    let phone = node(phone_id, log).await;

    sync(&pc, server.addr()).await.unwrap();
    sync_with(&phone, server.addr(), Some("apns:a1b2c3d4e5f6".into()))
        .await
        .unwrap();
    assert!(wake(&pc, server.addr(), phone.id()).await.unwrap());

    let seen = apple.0.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let (path, headers, body) = &seen[0];
    assert_eq!(path, "/3/device/a1b2c3d4e5f6");
    assert_eq!(headers["apns-topic"], "direct.passer.app");
    assert_eq!(headers["apns-push-type"], "background");
    assert_eq!(headers["apns-priority"], "5");
    assert!(
        headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("bearer ey")
    );
    assert_eq!(
        body,
        &serde_json::json!({ "aps": { "content-available": 1 } })
    );
}

#[tokio::test]
async fn the_gateway_only_obeys_its_server() {
    let (apple, apple_url) = fake_apple().await;
    let wake_url = gateway(&apple_url).await;
    let http = reqwest::Client::new();
    let post = |secret: &str, token: &str| {
        http.post(&wake_url)
            .header("authorization", format!("Bearer {secret}"))
            .json(&serde_json::json!({ "token": token, "group": "g" }))
            .send()
    };
    assert_eq!(
        post("wrong-secret", "apns:abcd").await.unwrap().status(),
        401
    );
    assert_eq!(post(SECRET, "apns:not-hex!").await.unwrap().status(), 502);
    assert_eq!(post(SECRET, "fcm:abcd").await.unwrap().status(), 502);
    assert_eq!(post(SECRET, "abcd").await.unwrap().status(), 502);
    assert!(apple.0.lock().unwrap().is_empty(), "nothing reached Apple");
    assert_eq!(post(SECRET, "apns:abcd").await.unwrap().status(), 200);
    assert_eq!(apple.0.lock().unwrap().len(), 1);
}

/// Reaches Apple's sandbox with a made-up key and token: Apple must answer (with a
/// refusal), which proves TLS and HTTP/2 work. Network access needed:
/// `cargo test -p passer-push -- --ignored`.
#[tokio::test]
#[ignore]
async fn apple_answers_over_http2() {
    let pem = SigningKey::from_bytes(&[3u8; 32].into())
        .unwrap()
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    let auth = ApnsAuth::new(&pem, "KEYID12345", "TEAMID6789").unwrap();
    let apns = Apns::new(auth, "direct.passer.app", passer_push::APNS_SANDBOX).unwrap();
    let err = apns.wake(&"0".repeat(64)).await.unwrap_err().to_string();
    assert!(err.contains("APNs answered"), "{err}");
    println!("{err}");
}
