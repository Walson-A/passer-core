//! Android wake-ups through FCM, against stand-ins for Google's token endpoint and FCM.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use passer_push::{Fcm, Gateway, router};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};

/// A throwaway key made for this test only (openssl genpkey). Not a real service account.
const TEST_ONLY_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCgwufluR/+YB4W
zt53HO4+2A2Pam7NuoMguJH8gAxWFFbGCj1+sKULoXs3uWiQsVLaFElC7iEHhI0Q
87IkSBDrKp4ZVa4E+KXorET4sjcEnbpyBpCPD5JBUGnsXXnl72A/Q08+qFSgciAA
siqrMUMb8AOZWWZBg+qUtUbfLKcXtZUKtzQnywm37pi8D7rNQ4XsrRhEk5nJBDqj
Yni0js++GRLT26QWRw6AwtW4OnfUWFyiKWRA2pRoc4yhMIW0hz9lxoRZ13VgCx/2
7Zx9sIB6s/SkQydhjTp1uU7FYkFfTZHLGr2FgmhF1AhHpC4TA13ajMx4NsdY0nfF
Pm2tctqTAgMBAAECggEANe17/iduUJYsscj+fqWRVDqEvf3dopy0/SZ9Ll9EBCI5
g6COxW97Rh4K6AQFzDf3y5kvhEi+greX3L5rHVmhd0nqFCSWRiuk+BrF3klmRGGm
2DZUivEVxlwz1Cr9R8FXn5E0RZgRH2t5SdJ6lsflM7t9cZU4RLT8XZs75YSknsJu
GqRHMksx3e5SUCh+cOatyE7XWARM51LUhX6DD+uf8Zi6TeD3IklQG6ibWVUT9iiE
SaYADCDGtFuXYdIJbAXrUx7ECsQx/QbS3auURdvdDLx1CrGNrQ/zztHzbK3DLyOK
o0BCtgFzFr58BsDhsh7dzsaKlVI5skDccgmBS7/uHQKBgQDXsl6VJF5G+4+JMy4k
0VPD5J/JkUh65u04rQ61g7R2dKIDbr9QBCIevdWjFHFefl7WtdAsFcgw/O2Jikqo
j8zkEbN7eeb6mM0mMuflY442FN3xpBtSyop5TrUWJFSX7803JTJa9ldNFi7+081x
qoAnUnBth8UDpEFRDbX1gAIjdQKBgQC+zMIfcMNFqncycIRmKT6CDO945uUInIo7
gv+/ClMfOvup70I4PMgPi60ojmmslCI3OLRUff6uj5PTV4gyrBAe6nr44W1XYc15
EG9DI+/k3KDCBC750+8DPOw4CiA+C2/eNHqtF9DFuXCXq6/uWJCJBShjwv33AXeQ
2MFvxeHs5wKBgQCtwAlgqoMnOs1M/+VT0yteyXPNszJnjk3ZMc5/eTCNmzZG/Zcu
paW2jcTiMT2BmNpcquieGo3AqH3QJY4uamfp8DhcZr4hb6UR+D/FEIUmG3kNhdxc
vLr/LN/CjlF2cr0khtohW/7HIe+JZqQ/w9Cn3EikcpHJdS8IU7sXn54ZYQKBgGRU
i6e4xhY2I2PUouqNuZ7tamerErjKiC3vHsi4hyke/QNJGwszewghrLZs3MixRKTB
HqJndqsYOOWjW605qWh4aJ3C/Jo8ha2ppLgrh5RTJ/2d8Y3Rkhejy5tUR8wYe4Tf
F7s5kMDIWJqI34R38dj7a1e6S429qb/zGxTJe5n1AoGAL9qNexnJz7GKhKtp1UlC
QHPdgPufNpTCZcPnoCVpYN0UReGnJH+6KmR38ZNMQfbBzF+cdIwHd+s1FP/KXi2Z
V9bTYcVnsVsHXQLDpRBSjluV52AAWGfCwMq5A0kvzm8FeFOYnz7wtFpsg74wzxMc
34CqvHEF0eVlwNIaW0OTyFc=
-----END PRIVATE KEY-----";

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn account(token_uri: &str) -> String {
    serde_json::json!({
        "type": "service_account",
        "project_id": "passer-test",
        "client_email": "gateway@passer-test.iam.gserviceaccount.com",
        "private_key": TEST_ONLY_KEY,
        "token_uri": token_uri,
    })
    .to_string()
}

fn der(pem: &str) -> Vec<u8> {
    use base64::Engine;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

#[test]
fn the_assertion_is_signed_with_the_service_account() {
    let fcm = Fcm::new(&account("https://oauth2.example/token"), "http://unused").unwrap();
    let jwt = fcm.assertion(1_700_000_000).unwrap();
    let (input, sig) = jwt.rsplit_once('.').unwrap();
    use base64::Engine;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig)
        .unwrap();
    let key = RsaKeyPair::from_pkcs8(&der(TEST_ONLY_KEY)).unwrap();
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public().as_ref())
        .verify(input.as_bytes(), &sig)
        .expect("Google would accept this signature");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["aud"], "https://oauth2.example/token");
    assert_eq!(
        claims["scope"],
        "https://www.googleapis.com/auth/firebase.messaging"
    );
}

#[tokio::test]
async fn an_android_phone_is_woken_with_one_access_token() {
    let grants = Arc::new(Mutex::new(0u32));
    let sent: Arc<Mutex<Vec<(String, HeaderMap, serde_json::Value)>>> = Arc::default();

    let g = grants.clone();
    let google = serve(Router::new().route(
        "/token",
        post(move |body: String| {
            let g = g.clone();
            async move {
                assert!(
                    body.contains(
                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
                    )
                );
                *g.lock().unwrap() += 1;
                axum::Json(serde_json::json!({ "access_token": "ya29.test", "expires_in": 3599 }))
            }
        }),
    ))
    .await;
    let s = sent.clone();
    let firebase = serve(Router::new().route(
        "/v1/projects/{project}/messages:send",
        post(
            move |uri: axum::http::Uri, headers: HeaderMap, body: axum::body::Bytes| {
                let s = s.clone();
                async move {
                    let json = serde_json::from_slice(&body).unwrap_or_default();
                    s.lock()
                        .unwrap()
                        .push((uri.path().to_owned(), headers, json));
                    StatusCode::OK
                }
            },
        ),
    ))
    .await;

    let fcm = Fcm::new(&account(&format!("{google}/token")), &firebase).unwrap();
    let gateway = Arc::new(Gateway {
        secret: "a-long-enough-test-secret".into(),
        apns: None,
        fcm: Some(fcm),
    });
    let url = format!("{}/wake", serve(router(gateway)).await);
    let http = reqwest::Client::new();
    for _ in 0..2 {
        let status = http
            .post(&url)
            .header("authorization", "Bearer a-long-enough-test-secret")
            .json(&serde_json::json!({ "token": "fcm:dQw4w9WgXcQ:APA91b_test", "group": "g" }))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200);
    }
    assert_eq!(*grants.lock().unwrap(), 1, "the access token is reused");
    let sent = sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    let (path, headers, body) = &sent[0];
    assert_eq!(path, "/v1/projects/passer-test/messages:send");
    assert_eq!(headers["authorization"], "Bearer ya29.test");
    assert_eq!(body["message"]["token"], "dQw4w9WgXcQ:APA91b_test");
    assert_eq!(body["message"]["android"]["priority"], "high");
    assert_eq!(body["message"]["data"]["passer"], "wake");
}
