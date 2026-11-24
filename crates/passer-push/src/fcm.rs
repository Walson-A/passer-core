//! Android: Firebase Cloud Messaging (HTTP v1).
//!
//! The gateway signs a short JWT with the Firebase service account's RSA key (with
//! `ring`, constant-time), trades it at Google's token endpoint for an access token
//! (cached for most of its hour), and sends a high-priority data message: it wakes the
//! app's `FirebaseMessagingService` without showing anything.

use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Deserialize;

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Firebase Cloud Messaging's endpoint.
pub const FCM_BASE: &str = "https://fcm.googleapis.com";

/// The fields of a Firebase service account file (`service-account.json`) used here.
#[derive(Deserialize)]
pub struct ServiceAccount {
    /// The Firebase project the app belongs to.
    pub project_id: String,
    /// The service account's email, the JWT's issuer.
    pub client_email: String,
    /// The account's RSA private key (PKCS#8 PEM). A secret: keep the file private.
    pub private_key: String,
    /// Google's endpoint that trades the signed JWT for an access token.
    pub token_uri: String,
}

/// Sends wake-up data messages through Firebase Cloud Messaging.
pub struct Fcm {
    account: ServiceAccount,
    key: RsaKeyPair,
    base: String,
    http: reqwest::Client,
    /// (expires at, access token)
    token: Mutex<Option<(u64, String)>>,
}

fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    STANDARD
        .decode(body)
        .context("the service account key is not PEM")
}

impl Fcm {
    /// `json` is the service account file Firebase gives (Project settings > Service
    /// accounts > Generate new private key).
    pub fn new(json: &str, base: &str) -> anyhow::Result<Self> {
        let account: ServiceAccount =
            serde_json::from_str(json).context("not a Firebase service account file")?;
        let key = RsaKeyPair::from_pkcs8(&pem_to_der(&account.private_key)?)
            .map_err(|e| anyhow!("the service account key is not an RSA PKCS#8 key: {e}"))?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            account,
            key,
            base: base.trim_end_matches('/').to_owned(),
            http,
            token: Mutex::new(None),
        })
    }

    /// The signed assertion traded for an access token.
    pub fn assertion(&self, now: u64) -> anyhow::Result<String> {
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let claims = serde_json::json!({
            "iss": self.account.client_email,
            "scope": SCOPE,
            "aud": self.account.token_uri,
            "iat": now,
            "exp": now + 3600,
        });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                input.as_bytes(),
                &mut sig,
            )
            .map_err(|_| anyhow!("signing failed"))?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }

    async fn access_token(&self) -> anyhow::Result<String> {
        let now = crate::now();
        if let Some((expires, token)) = self.token.lock().expect("token lock").as_ref()
            && *expires > now + 60
        {
            return Ok(token.clone());
        }
        #[derive(Deserialize)]
        struct Granted {
            access_token: String,
            expires_in: u64,
        }
        let response = self
            .http
            .post(&self.account.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &self.assertion(now)?),
            ])
            .send()
            .await
            .context("reaching Google's token endpoint")?;
        if !response.status().is_success() {
            bail!("Google refused the service account: {}", response.status());
        }
        let granted: Granted = response.json().await.context("reading the access token")?;
        *self.token.lock().expect("token lock") =
            Some((now + granted.expires_in, granted.access_token.clone()));
        Ok(granted.access_token)
    }

    /// One wake-up to `registration_token`.
    pub async fn wake(&self, registration_token: &str) -> anyhow::Result<()> {
        if registration_token.is_empty()
            || registration_token.len() > 4096
            || !registration_token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_:.".contains(c))
        {
            bail!("not an FCM registration token");
        }
        let response = self
            .http
            .post(format!(
                "{}/v1/projects/{}/messages:send",
                self.base, self.account.project_id
            ))
            .bearer_auth(self.access_token().await?)
            .json(&serde_json::json!({
                "message": {
                    "token": registration_token,
                    "android": { "priority": "high", "ttl": "30s" },
                    "data": { "passer": "wake" }
                }
            }))
            .send()
            .await
            .context("reaching FCM")?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let reason = response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v["error"]["status"].as_str().map(str::to_owned))
            .unwrap_or_default();
        Err(anyhow!("FCM answered {status}: {reason}"))
    }
}
