//! The coordination server: the server half of passer-core.
//!
//! It does two things for the devices of each group:
//!
//! - **keeps the latest device log** and hands it to every member, so that additions and
//!   removals reach devices that were offline when they happened;
//! - **keeps presence**: the direct addresses each device last reported, so that devices
//!   find each other without being on the same network.
//!
//! It is untrusted by design. It cannot add a device (it has no approver key; it only
//! stores logs that verify and that extend the one it has), it never sees content (calls
//! go device to device, end-to-end encrypted), and it only answers members of a group
//! about that group. What it does see: which keys form a group, the device names in the
//! log, IP addresses, and when devices come online. A relay (`iroh-relay`) is deployed
//! next to it; it is a separate, standard binary.
//!
//! The same server runs as Passer's hosted service (many groups) or inside a self-hosted
//! Atlas engine (one group).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail};
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr};
use passer_identity::{DeviceId, Identity};
use passer_membership::{DeviceLog, GroupId, Op, Preferred};
use passer_node::frame::{READ_TIMEOUT, read_frame, write_frame};
use passer_node::{Node, now_secs};
use serde::{Deserialize, Serialize};

pub const COORD_ALPN: &[u8] = b"passer-core/coord/1";
/// A device not seen for this long is reported offline.
pub const PRESENCE_TTL_SECS: u64 = 5 * 60;
/// At most this many addresses per device.
const MAX_ADDRS: usize = 8;

/// A device's last known whereabouts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    pub device: DeviceId,
    pub addrs: Vec<SocketAddr>,
    /// The relay it is reachable through, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    pub seen_at: u64,
}

/// The only request: "here is my log and where I am; tell me the rest".
#[derive(Serialize, Deserialize)]
struct Publish {
    log: DeviceLog,
    addrs: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Reply {
    /// The server's current log and the other members' presence.
    Ok {
        log: DeviceLog,
        presence: Vec<Presence>,
    },
    /// The publishing device is no longer a member; here is the log that says so.
    Removed {
        log: DeviceLog,
    },
    Error {
        message: String,
    },
}

#[derive(Default)]
struct GroupState {
    log: Option<DeviceLog>,
    presence: HashMap<DeviceId, Presence>,
}

/// Most groups one server keeps. A hosted service adds accounts and quotas on top.
pub const MAX_GROUPS: usize = 100_000;

/// All groups served by one server. Each group has its own lock; signature checks run
/// outside every lock, on blocking threads.
#[derive(Default, Clone)]
pub struct State(Arc<Mutex<HashMap<GroupId, Arc<Mutex<GroupState>>>>>);

impl State {
    fn group(&self, id: GroupId) -> Option<Arc<Mutex<GroupState>>> {
        let mut groups = self.0.lock().expect("state lock");
        if let Some(g) = groups.get(&id) {
            return Some(g.clone());
        }
        if groups.len() >= MAX_GROUPS {
            return None;
        }
        Some(groups.entry(id).or_default().clone())
    }

    async fn publish(&self, from: DeviceId, msg: Publish, now: u64) -> Reply {
        // Expensive work (signature checks) first, without any lock.
        let incoming = msg.log;
        let Ok(Ok(membership)) = tokio::task::spawn_blocking({
            let log = incoming.clone();
            move || log.verify()
        })
        .await
        else {
            return Reply::Error {
                message: "the log does not verify".into(),
            };
        };
        let Some(group) = self.group(membership.group) else {
            return Reply::Error {
                message: "this server cannot take more groups".into(),
            };
        };

        // Decide which history to keep, then store it if nobody changed it meanwhile.
        let mut chosen = None;
        for _ in 0..3 {
            let stored = group.lock().expect("group lock").log.clone();
            let winner = match stored.clone() {
                None => incoming.clone(),
                Some(stored_log) => {
                    let candidate = incoming.clone();
                    let preferred =
                        tokio::task::spawn_blocking(move || stored_log.prefer(&candidate)).await;
                    match preferred {
                        Ok(Ok(Preferred::Theirs)) => incoming.clone(),
                        Ok(Ok(_)) => stored.clone().expect("checked"),
                        _ => {
                            return Reply::Error {
                                message: "the log belongs to another group".into(),
                            };
                        }
                    }
                }
            };
            let mut g = group.lock().expect("group lock");
            if g.log == stored {
                g.log = Some(winner.clone());
                chosen = Some(winner);
                break;
            }
        }
        let Some(stored) = chosen else {
            return Reply::Error {
                message: "busy, try again".into(),
            };
        };
        let current = tokio::task::spawn_blocking({
            let log = stored.clone();
            move || log.verify()
        })
        .await
        .ok()
        .and_then(Result::ok);
        let Some(current) = current else {
            return Reply::Error {
                message: "internal error".into(),
            };
        };

        let mut g = group.lock().expect("group lock");
        if !current.is_member(&from) {
            g.presence.remove(&from);
            return if current.revoked.contains(&from) {
                // Only the history up to this device's removal: what came after is none
                // of its business.
                let cut = stored
                    .entries()
                    .iter()
                    .position(|e| matches!(&e.op, Op::Remove { device } if *device == from))
                    .map_or(stored.entries().len(), |i| i + 1);
                Reply::Removed {
                    log: stored.prefix(cut),
                }
            } else {
                Reply::Error {
                    message: "this device is not a member of the group".into(),
                }
            };
        }

        let mut addrs = msg.addrs;
        addrs.truncate(MAX_ADDRS);
        let relay = msg
            .relay
            .filter(|u| passer_membership::pairing::valid_relay(u));
        g.presence.insert(
            from,
            Presence {
                device: from,
                addrs,
                relay,
                seen_at: now,
            },
        );
        g.presence.retain(|d, _| current.is_member(d));
        let presence = g
            .presence
            .values()
            .filter(|p| p.device != from && now.saturating_sub(p.seen_at) <= PRESENCE_TTL_SECS)
            .cloned()
            .collect();
        Reply::Ok {
            log: stored,
            presence,
        }
    }

    /// Number of groups known (for monitoring; reveals nothing else).
    pub fn groups(&self) -> usize {
        self.0.lock().expect("state lock").len()
    }
}

#[derive(Clone, Default)]
struct CoordProtocol {
    state: State,
}

impl std::fmt::Debug for CoordProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CoordProtocol")
    }
}

impl ProtocolHandler for CoordProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let from = connection.remote_id();
        let Ok(opened) = tokio::time::timeout(READ_TIMEOUT, connection.accept_bi()).await else {
            return Ok(());
        };
        let (mut send, mut recv) = opened?;
        let reply = match read_frame::<Publish>(&mut recv).await {
            Ok(msg) => self.state.publish(from, msg, now_secs()).await,
            Err(e) => Reply::Error {
                message: e.to_string(),
            },
        };
        write_frame(&mut send, &reply)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        let _ = tokio::time::timeout(READ_TIMEOUT, connection.closed()).await;
        Ok(())
    }
}

/// A running coordination server.
pub struct Server {
    router: Router,
    state: State,
}

impl Server {
    /// Starts a server whose identity is `identity` (devices pin it), bound to `port`
    /// (0 for any).
    pub async fn spawn(identity: &Identity, port: u16) -> anyhow::Result<Self> {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(identity.secret_key().clone())
            .alpns(vec![COORD_ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([0, 0, 0, 0], port)))
            .map_err(|e| anyhow!("bad bind address: {e}"))?
            .bind()
            .await
            .map_err(|e| anyhow!("binding: {e}"))?;
        let state = State::default();
        let router = Router::builder(endpoint)
            .accept(
                COORD_ALPN,
                CoordProtocol {
                    state: state.clone(),
                },
            )
            .spawn();
        Ok(Self { router, state })
    }

    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Addresses devices can use to reach the server (loopback if nothing better).
    pub fn addr(&self) -> EndpointAddr {
        let mut addr = self.endpoint().addr();
        if addr.ip_addrs().next().is_none() {
            for s in self.endpoint().bound_sockets() {
                if s.is_ipv4() {
                    addr = addr.with_ip_addr(SocketAddr::from(([127, 0, 0, 1], s.port())));
                }
            }
        }
        addr
    }

    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.router
            .shutdown()
            .await
            .map_err(|e| anyhow!("shutting down: {e}"))
    }
}

/// Parses a server address written as `<id>@<ip:port>[,<ip:port>...]` (or just `<id>`).
pub fn parse_server(s: &str) -> anyhow::Result<EndpointAddr> {
    use anyhow::Context;
    use std::net::ToSocketAddrs;
    let (id, addrs) = s.split_once('@').unwrap_or((s, ""));
    let id: DeviceId = id.parse().context("bad coordination server id")?;
    let mut addr = EndpointAddr::new(id);
    for a in addrs.split(',').filter(|a| !a.is_empty()) {
        // `ip:port`, or `host:port` resolved now (the server's key is what is trusted,
        // not its name: a wrong address only fails to connect).
        let resolved: Vec<SocketAddr> = match a.parse::<SocketAddr>() {
            Ok(sock) => vec![sock],
            Err(_) => a
                .to_socket_addrs()
                .with_context(|| format!("bad address {a}"))?
                .collect(),
        };
        for sock in resolved {
            addr = addr.with_ip_addr(sock);
        }
    }
    Ok(addr)
}

/// What a device learned from one exchange with the server.
#[derive(Debug)]
pub struct SyncOutcome {
    pub members: usize,
    pub online: Vec<Presence>,
    /// True when the server says this device has been removed from the group.
    pub removed: bool,
}

/// Publishes this node's log and addresses, adopts the server's log if it is newer, and
/// remembers where the other members are.
pub async fn sync(node: &Node, server: EndpointAddr) -> anyhow::Result<SyncOutcome> {
    let here = node.addr();
    let addrs: Vec<SocketAddr> = here.ip_addrs().copied().collect();
    let relay = here.relay_urls().next().map(ToString::to_string);
    let conn = node
        .endpoint()
        .connect(server, COORD_ALPN)
        .await
        .map_err(|e| anyhow!("connecting to the coordination server: {e}"))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("opening a stream: {e}"))?;
    write_frame(
        &mut send,
        &Publish {
            log: node.group().log(),
            addrs,
            relay,
        },
    )
    .await?;
    send.finish()?;
    let reply: Reply = read_frame(&mut recv).await?;
    conn.close(0u32.into(), b"done");
    match reply {
        Reply::Error { message } => bail!("the coordination server refused: {message}"),
        Reply::Removed { log } => {
            node.adopt_log(log)?;
            Ok(SyncOutcome {
                members: node.group().membership().members.len(),
                online: vec![],
                removed: true,
            })
        }
        Reply::Ok { log, presence } => {
            let membership = node.adopt_log(log)?;
            // Only remember addresses of devices our own verified log lists as members.
            let online: Vec<Presence> = presence
                .into_iter()
                .filter(|p| membership.is_member(&p.device))
                .collect();
            for p in &online {
                let mut addr = EndpointAddr::new(p.device);
                for a in &p.addrs {
                    addr = addr.with_ip_addr(*a);
                }
                if let Some(url) = p.relay.as_deref().and_then(|u| u.parse().ok()) {
                    addr = addr.with_relay_url(url);
                }
                node.peers().remember(addr);
            }
            Ok(SyncOutcome {
                members: membership.members.len(),
                online,
                removed: false,
            })
        }
    }
}

/// Keeps a node in sync with a server, every `every`, until the returned task is aborted.
pub fn spawn_sync_loop(
    node: Arc<Node>,
    server: EndpointAddr,
    every: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = sync(&node, server.clone()).await {
                tracing::warn!("coordination sync failed: {e:#}");
            }
            tokio::time::sleep(every).await;
        }
    })
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn servers_by_address_or_name() {
        let id = Identity::generate().id();
        let by_ip = parse_server(&format!("{id}@203.0.113.7:4433")).unwrap();
        assert_eq!(by_ip.ip_addrs().count(), 1);
        let by_name = parse_server(&format!("{id}@localhost:4433")).unwrap();
        assert!(
            by_name
                .ip_addrs()
                .all(|a| a.port() == 4433 && a.ip().is_loopback())
        );
        assert!(by_name.ip_addrs().count() >= 1);
        assert!(parse_server(&format!("{id}@no-port")).is_err());
        assert!(parse_server("not-an-id@1.2.3.4:1").is_err());
    }
}
