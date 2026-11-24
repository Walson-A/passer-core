//! Waking a sleeping device.
//!
//! A phone in a pocket is not listening: iOS and Android suspend apps. What still reaches
//! it is a push notification, sent by whoever holds the app's push credentials (Apple's,
//! Google's): the app's vendor, not passer-core. So the core only carries an opaque
//! token and asks:
//!
//! 1. the phone's app gives its push token to the core (`PasserDevice::set_push_token`),
//!    which publishes it to the coordination server with its presence;
//! 2. a member that cannot reach the phone asks the server to wake it ([`wake`]);
//! 3. the server checks that both are members of the same group, limits how often a
//!    device can be woken, and hands the token to a [`WakeHook`]: by default an HTTP
//!    POST to a push gateway the app vendor runs ([`HttpWakeHook`]);
//! 4. the gateway sends a silent notification; the phone's app starts its device for a
//!    moment, the caller retries.
//!
//! The server learns that someone in a group wanted a device; never what for.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use iroh::EndpointAddr;
use passer_identity::DeviceId;
use passer_membership::GroupId;
use passer_node::Node;
use passer_node::frame::{read_frame, write_frame};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The ALPN on which a member asks the server to wake another member.
pub const WAKE_ALPN: &[u8] = b"passer-core/wake/1";
/// A device is woken at most this often.
pub const WAKE_INTERVAL_SECS: u64 = 15;
/// Longest push token accepted (APNs and FCM tokens are far shorter).
pub const MAX_TOKEN: usize = 4096;

/// Sends the push. Implemented by whoever runs the server.
#[async_trait]
pub trait WakeHook: Send + Sync {
    /// `token` is what the device's app registered; `group` lets a gateway serving many
    /// apps tell them apart. Returns once the push is handed over.
    async fn wake(&self, token: &str, group: GroupId) -> anyhow::Result<()>;
}

/// POSTs `{"token": "...", "group": "..."}` to a push gateway over plain HTTP, with an
/// optional bearer secret. Meant for a gateway next to the server (same host or private
/// network); put a TLS proxy in front of one that is farther away.
pub struct HttpWakeHook {
    host: String,
    port: u16,
    path: String,
    secret: Option<String>,
}

impl HttpWakeHook {
    /// `url` is `http://host[:port]/path`.
    pub fn new(url: &str, secret: Option<String>) -> anyhow::Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| anyhow!("the wake URL must start with http://"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_owned()),
            None => (rest, "/".to_owned()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse()?),
            None => (authority.to_owned(), 80),
        };
        if host.is_empty() || path.contains(['\r', '\n', ' ']) {
            bail!("bad wake URL");
        }
        Ok(Self {
            host,
            port,
            path,
            secret: secret.filter(|s| !s.contains(['\r', '\n'])),
        })
    }
}

#[async_trait]
impl WakeHook for HttpWakeHook {
    async fn wake(&self, token: &str, group: GroupId) -> anyhow::Result<()> {
        let body = serde_json::to_vec(&serde_json::json!({
            "token": token,
            "group": group.to_string(),
        }))?;
        let mut request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.path,
            self.host,
            body.len()
        );
        if let Some(secret) = &self.secret {
            request.push_str(&format!("Authorization: Bearer {secret}\r\n"));
        }
        request.push_str("\r\n");
        let exchange = async {
            let mut stream =
                tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await?;
            stream.write_all(request.as_bytes()).await?;
            stream.write_all(&body).await?;
            let mut head = [0u8; 12];
            stream.read_exact(&mut head).await?;
            anyhow::Ok(head)
        };
        let head = tokio::time::timeout(Duration::from_secs(10), exchange)
            .await
            .map_err(|_| anyhow!("the push gateway did not answer"))??;
        // "HTTP/1.1 2xx"
        if head.get(9) != Some(&b'2') {
            bail!(
                "the push gateway refused: {}",
                String::from_utf8_lossy(&head)
            );
        }
        Ok(())
    }
}

/// What a member asks the server.
#[derive(Serialize, Deserialize)]
pub(crate) struct WakeRequest {
    pub group: GroupId,
    pub device: DeviceId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum WakeReply {
    /// The push was handed to the gateway.
    Sent,
    /// Nothing to do: no token for that device, too soon, or no gateway configured.
    Skipped {
        reason: String,
    },
    Error {
        message: String,
    },
}

/// Asks the coordination server to wake `device`. `Ok(true)` if a push went out; then
/// give the device a few seconds before calling it again.
pub async fn wake(node: &Node, server: EndpointAddr, device: DeviceId) -> anyhow::Result<bool> {
    let conn = node
        .endpoint()
        .connect(server, WAKE_ALPN)
        .await
        .map_err(|e| anyhow!("connecting to the coordination server: {e}"))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("opening a stream: {e}"))?;
    let request = WakeRequest {
        group: node.group().membership().group,
        device,
    };
    write_frame(&mut send, &request).await?;
    send.finish()?;
    let reply: WakeReply = read_frame(&mut recv).await?;
    conn.close(0u32.into(), b"done");
    match reply {
        WakeReply::Sent => Ok(true),
        WakeReply::Skipped { reason } => {
            tracing::debug!("no wake: {reason}");
            Ok(false)
        }
        WakeReply::Error { message } => bail!("the coordination server refused: {message}"),
    }
}

/// The hook a server uses, if any.
pub(crate) type Hook = Option<Arc<dyn WakeHook>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_urls() {
        let h = HttpWakeHook::new("http://push:8080/wake", Some("s".into())).unwrap();
        assert_eq!(
            (h.host.as_str(), h.port, h.path.as_str()),
            ("push", 8080, "/wake")
        );
        let h = HttpWakeHook::new("http://localhost", None).unwrap();
        assert_eq!((h.port, h.path.as_str()), (80, "/"));
        assert!(HttpWakeHook::new("https://x/wake", None).is_err());
        assert!(HttpWakeHook::new("http://x/a b", None).is_err());
    }
}
