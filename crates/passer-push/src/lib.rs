//! A reference push gateway for passer-core.
//!
//! The coordination server never holds Apple's or Google's credentials: when a member
//! wants to wake a sleeping device, it POSTs the device's push token here
//! (`passer-coord --wake-url http://<this>/wake --wake-secret <secret>`), and this gateway,
//! run by the app's vendor, sends the push.
//!
//! Tokens say which service they belong to: `apns:<hex device token>` for iPhones and iPads.
//! (`fcm:` for Android is not implemented yet.) The app registers its token with
//! `PasserDevice::set_push_token`.
//!
//! The push is a background notification with no content (`content-available`): it wakes
//! the app for a few seconds, enough to start its device and answer. iOS delivers these
//! on a best-effort basis and may delay them when the phone is in Low Power Mode.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::pkcs8::DecodePrivateKey;
use serde::Deserialize;
use subtle::ConstantTimeEq;

/// Apple's production and development (sandbox) endpoints. Builds installed from Xcode or
/// EAS development profiles use the sandbox; TestFlight and the App Store use production.
pub const APNS_PRODUCTION: &str = "https://api.push.apple.com";
pub const APNS_SANDBOX: &str = "https://api.sandbox.push.apple.com";
/// Apple refuses tokens older than an hour and asks not to renew them more than every 20
/// minutes.
const JWT_LIFETIME_SECS: u64 = 50 * 60;
/// Largest request body accepted on `/wake`.
const MAX_BODY: usize = 8 * 1024;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The provider token APNs expects: an ES256 JWT signed with the team's `.p8` key.
pub struct ApnsAuth {
    key: SigningKey,
    key_id: String,
    team_id: String,
    cached: Mutex<Option<(u64, String)>>,
}

impl ApnsAuth {
    /// `pem` is the content of the `.p8` file Apple gives (PKCS#8, P-256).
    pub fn new(pem: &str, key_id: &str, team_id: &str) -> anyhow::Result<Self> {
        let key = SigningKey::from_pkcs8_pem(pem).context("the APNs key is not a .p8 P-256 key")?;
        Ok(Self {
            key,
            key_id: key_id.to_owned(),
            team_id: team_id.to_owned(),
            cached: Mutex::new(None),
        })
    }

    /// A token valid now, reused for up to 50 minutes.
    pub fn token(&self) -> String {
        let now = now();
        let mut cached = self.cached.lock().expect("jwt lock");
        if let Some((at, jwt)) = cached.as_ref()
            && now.saturating_sub(*at) < JWT_LIFETIME_SECS
        {
            return jwt.clone();
        }
        let jwt = self.sign(now);
        *cached = Some((now, jwt.clone()));
        jwt
    }

    fn sign(&self, iat: u64) -> String {
        let header = serde_json::json!({ "alg": "ES256", "kid": self.key_id });
        let claims = serde_json::json!({ "iss": self.team_id, "iat": iat });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

/// Sends background pushes through APNs.
pub struct Apns {
    auth: ApnsAuth,
    /// The app's bundle id (`direct.passer.app`).
    topic: String,
    base: String,
    http: reqwest::Client,
}

impl Apns {
    pub fn new(auth: ApnsAuth, topic: &str, base: &str) -> anyhow::Result<Self> {
        // ring, as everywhere else in the workspace. Installing twice is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("building the HTTP client")?;
        Ok(Self {
            auth,
            topic: topic.to_owned(),
            base: base.trim_end_matches('/').to_owned(),
            http,
        })
    }

    /// One background push to `device_token` (hex).
    pub async fn wake(&self, device_token: &str) -> anyhow::Result<()> {
        if device_token.is_empty()
            || device_token.len() > 200
            || !device_token.chars().all(|c| c.is_ascii_hexdigit())
        {
            bail!("not an APNs device token");
        }
        let response = self
            .http
            .post(format!("{}/3/device/{device_token}", self.base))
            .header("authorization", format!("bearer {}", self.auth.token()))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "background")
            // Background pushes must use priority 5; expire at once rather than arrive late.
            .header("apns-priority", "5")
            .header("apns-expiration", "0")
            .json(&serde_json::json!({ "aps": { "content-available": 1 } }))
            .send()
            .await
            .context("reaching APNs")?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let reason = response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v["reason"].as_str().map(str::to_owned))
            .unwrap_or_default();
        Err(anyhow!("APNs answered {status}: {reason}"))
    }
}

/// What the gateway can send to.
pub struct Gateway {
    /// The bearer secret `passer-coord --wake-secret` sends.
    pub secret: String,
    pub apns: Option<Apns>,
}

#[derive(Deserialize)]
struct WakeBody {
    token: String,
    #[allow(dead_code)]
    group: String,
}

impl Gateway {
    async fn wake(&self, token: &str) -> anyhow::Result<()> {
        match token.split_once(':') {
            Some(("apns", device)) => match &self.apns {
                Some(apns) => apns.wake(device).await,
                None => bail!("this gateway has no APNs key"),
            },
            Some(("fcm", _)) => bail!("Android (FCM) is not supported yet"),
            _ => bail!("unknown token kind"),
        }
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        let given = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        !self.secret.is_empty() && bool::from(given.as_bytes().ct_eq(self.secret.as_bytes()))
    }
}

async fn wake(
    State(gateway): State<Arc<Gateway>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    if !gateway.authorized(&headers) {
        return StatusCode::UNAUTHORIZED;
    }
    if body.len() > MAX_BODY {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let Ok(request) = serde_json::from_slice::<WakeBody>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    match gateway.wake(&request.token).await {
        Ok(()) => StatusCode::OK,
        Err(e) => {
            // The token stays out of logs: it identifies a phone.
            tracing::warn!("push failed: {e:#}");
            StatusCode::BAD_GATEWAY
        }
    }
}

/// The HTTP routes: `POST /wake` (what `passer-coord` calls) and `GET /health`.
pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/wake", post(wake))
        .route("/health", get(|| async { "ok" }))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(gateway)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{VerifyingKey, signature::Verifier};
    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    pub(crate) fn test_key_pem() -> String {
        let key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
    }

    #[test]
    fn provider_tokens_verify_and_are_reused() {
        let auth = ApnsAuth::new(&test_key_pem(), "KEY123", "TEAM456").unwrap();
        let jwt = auth.token();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(
            header,
            serde_json::json!({ "alg": "ES256", "kid": "KEY123" })
        );
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "TEAM456");

        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        let verifying = VerifyingKey::from(&SigningKey::from_bytes(&[7u8; 32].into()).unwrap());
        verifying
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
        assert_eq!(
            auth.token(),
            jwt,
            "the token is reused, not re-signed each time"
        );
    }

    #[test]
    fn bad_keys_are_refused() {
        assert!(ApnsAuth::new("not a key", "k", "t").is_err());
    }
}
