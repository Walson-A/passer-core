//! A passer-core device on the network.
//!
//! A [`Node`] owns an iroh endpoint whose key is the device's identity, and serves three
//! protocols, each on its own ALPN:
//!
//! - [`BUS_ALPN`]: capability calls. Only members may connect; every request then goes
//!   through the [`Bus`] (membership again, schema, policy, approval, lease, journal).
//! - [`LOG_ALPN`]: a member fetches the current device log, to learn about additions and
//!   removals. The receiver accepts it only as a signed extension of what it has.
//! - [`JOIN_ALPN`]: a new device redeems an invitation. This is the only protocol a
//!   non-member may use, and it does nothing without a valid one-time secret.
//!
//! The transport authenticates the remote key (QUIC/TLS 1.3 with raw public keys); the
//! node never trusts a device id written inside a message.

pub mod approval;
pub mod frame;

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, anyhow, bail};
use iroh::endpoint::{Connection, presets};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr};
use passer_bus::{Bus, MembershipView, Request, Response, Subject};
use passer_identity::{DeviceId, Identity};
use passer_membership::pairing::{Invitation, InvitationBook, JoinRequest};
use passer_membership::{DeviceLog, Membership, Op, Preferred};
use serde::{Deserialize, Serialize};

use crate::frame::{read_frame, write_frame};

pub const BUS_ALPN: &[u8] = b"passer-core/bus/1";
pub const LOG_ALPN: &[u8] = b"passer-core/log/1";
pub const JOIN_ALPN: &[u8] = b"passer-core/join/1";

/// QUIC close code sent to a device that is not (or no longer) a member.
const CLOSE_NOT_MEMBER: u32 = 403;

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------------
// Group state
// ---------------------------------------------------------------------------------------

struct GroupInner {
    log: DeviceLog,
    membership: Membership,
}

/// The group as this device knows it, optionally persisted to a file.
pub struct Group {
    inner: RwLock<GroupInner>,
    path: Option<PathBuf>,
}

impl Group {
    pub fn new(log: DeviceLog, path: Option<PathBuf>) -> anyhow::Result<Self> {
        let membership = log.verify().context("the device log does not verify")?;
        let group = Self {
            inner: RwLock::new(GroupInner { log, membership }),
            path,
        };
        group.save()?;
        Ok(group)
    }

    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let log = DeviceLog::from_json(&text).context("parsing the device log")?;
        Self::new(log, Some(path))
    }

    fn save(&self) -> anyhow::Result<()> {
        let inner = self.inner.read().expect("group lock");
        self.write_file(&inner.log)
    }

    /// Writes the log atomically: a unique temporary file, then a rename. Called with the
    /// group lock held, so writers never interleave.
    fn write_file(&self, log: &DeviceLog) -> anyhow::Result<()> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let tmp = path.with_extension(format!("{}.{n}.tmp", std::process::id()));
            std::fs::write(&tmp, log.to_json())?;
            std::fs::rename(&tmp, path)?;
        }
        Ok(())
    }

    pub fn membership(&self) -> Membership {
        self.inner.read().expect("group lock").membership.clone()
    }

    pub fn log(&self) -> DeviceLog {
        self.inner.read().expect("group lock").log.clone()
    }

    /// Appends a signed operation; returns the devices that stopped being members.
    pub fn append(&self, author: &Identity, op: Op) -> anyhow::Result<Vec<DeviceId>> {
        let mut inner = self.inner.write().expect("group lock");
        let mut log = inner.log.clone();
        log.append(author, op, now_secs())?;
        let membership = log.verify()?;
        self.write_file(&log)?;
        let removed = removed_between(&inner.membership, &membership);
        *inner = GroupInner { log, membership };
        Ok(removed)
    }

    /// Considers a log received from a peer or a server and keeps whichever of the two the
    /// fork-choice rule prefers ([`DeviceLog::prefer`]): a longer history, or, on a fork,
    /// the branch that revokes the other's authors.
    pub fn adopt(&self, received: DeviceLog) -> anyhow::Result<Adoption> {
        let mut inner = self.inner.write().expect("group lock");
        match inner.log.prefer(&received)? {
            Preferred::Ours | Preferred::Same => Ok(Adoption::default()),
            Preferred::Theirs => {
                let forked = !received.entries().starts_with(inner.log.entries());
                let membership = received.verify()?;
                self.write_file(&received)?;
                let removed = removed_between(&inner.membership, &membership);
                if forked {
                    tracing::warn!(
                        "the device log forked; switched to the branch that wins the fork choice"
                    );
                }
                *inner = GroupInner {
                    log: received,
                    membership,
                };
                Ok(Adoption {
                    changed: true,
                    forked,
                    removed,
                })
            }
        }
    }
}

/// What [`Group::adopt`] did.
#[derive(Debug, Default)]
pub struct Adoption {
    pub changed: bool,
    /// Our branch lost a fork: entries written here since the fork point were dropped
    /// (for instance a device this device had added must be invited again).
    pub forked: bool,
    /// Devices that are no longer members.
    pub removed: Vec<DeviceId>,
}

impl Group {}

fn removed_between(old: &Membership, new: &Membership) -> Vec<DeviceId> {
    let now: BTreeSet<_> = new.members.keys().collect();
    old.members
        .keys()
        .filter(|d| !now.contains(d))
        .copied()
        .collect()
}

impl MembershipView for Group {
    fn is_member(&self, device: &DeviceId) -> bool {
        self.inner
            .read()
            .expect("group lock")
            .membership
            .is_member(device)
    }
}

// ---------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------

/// How the endpoint reaches the outside world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// Direct addresses only, no relay, no address lookup. Tests and local networks.
    LocalOnly,
    /// n0's public relays and address lookup. **Development only**: n0 reserves them for
    /// development and hobby use, without guarantees. Production uses Passer's own relays.
    N0Dev,
}

async fn bind(
    identity: &Identity,
    network: Network,
    alpns: Vec<Vec<u8>>,
) -> anyhow::Result<Endpoint> {
    let builder = match network {
        Network::LocalOnly => Endpoint::builder(presets::Minimal),
        Network::N0Dev => Endpoint::builder(presets::N0),
    };
    let endpoint = builder
        .secret_key(identity.secret_key().clone())
        .alpns(alpns)
        .bind()
        .await
        .map_err(|e| anyhow!("binding the endpoint: {e}"))?;
    Ok(endpoint)
}

/// The addresses this endpoint can be dialed on, with wildcard IPs replaced by loopback
/// (for tests on one machine) when no better address is known.
fn dialable_addr(endpoint: &Endpoint) -> EndpointAddr {
    let mut addr = endpoint.addr();
    if addr.ip_addrs().next().is_none() {
        for s in endpoint.bound_sockets() {
            let ip = if s.ip().is_unspecified() {
                match s.ip() {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(_) => continue,
                }
            } else {
                s.ip()
            };
            addr = addr.with_ip_addr(SocketAddr::new(ip, s.port()));
        }
    }
    addr
}

// ---------------------------------------------------------------------------------------
// Protocol handlers
// ---------------------------------------------------------------------------------------

/// Open bus connections per remote device, so that removing a device cuts them.
#[derive(Clone, Default)]
pub(crate) struct Connections(Arc<Mutex<HashMap<DeviceId, Vec<Connection>>>>);

impl Connections {
    fn add(&self, device: DeviceId, conn: Connection) {
        let mut map = self.0.lock().expect("connections lock");
        let list = map.entry(device).or_default();
        list.retain(|c| c.close_reason().is_none());
        list.push(conn);
    }

    fn close(&self, device: &DeviceId) {
        if let Some(list) = self.0.lock().expect("connections lock").remove(device) {
            for c in list {
                c.close(CLOSE_NOT_MEMBER.into(), b"removed from the group");
            }
        }
    }
}

#[derive(Clone)]
struct BusProtocol {
    bus: Arc<Bus>,
    group: Arc<Group>,
    connections: Connections,
}

impl std::fmt::Debug for BusProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BusProtocol")
    }
}

impl ProtocolHandler for BusProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        if !self.group.is_member(&remote) {
            connection.close(CLOSE_NOT_MEMBER.into(), b"not a member");
            return Ok(());
        }
        self.connections.add(remote, connection.clone());
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(s) => s,
                Err(_) => return Ok(()), // the peer closed the connection
            };
            let bus = self.bus.clone();
            tokio::spawn(async move {
                let response = match read_frame::<Request>(&mut recv).await {
                    Ok(request) => {
                        let subject = Subject {
                            device: remote,
                            agent: request.agent.clone(),
                        };
                        bus.handle(subject, request).await
                    }
                    Err(e) => Response::error(passer_bus::ErrorCode::Protocol, e.to_string()),
                };
                if write_frame(&mut send, &response).await.is_ok() {
                    let _ = send.finish();
                }
            });
        }
    }
}

#[derive(Clone)]
struct LogProtocol {
    group: Arc<Group>,
}

impl std::fmt::Debug for LogProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogProtocol")
    }
}

impl ProtocolHandler for LogProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        if !self.group.is_member(&connection.remote_id()) {
            connection.close(CLOSE_NOT_MEMBER.into(), b"not a member");
            return Ok(());
        }
        let Ok(opened) = tokio::time::timeout(frame::READ_TIMEOUT, connection.accept_bi()).await
        else {
            return Ok(());
        };
        let (mut send, _recv) = opened?;
        write_frame(&mut send, &self.group.log())
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        let _ = tokio::time::timeout(frame::READ_TIMEOUT, connection.closed()).await;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum JoinReply {
    Ok { log: DeviceLog, sas: String },
    Error { message: String },
}

/// Called when a device has been admitted, with its id, name and the SAS code to show.
pub type AdmissionHook = Arc<dyn Fn(DeviceId, &str, &str) + Send + Sync>;

#[derive(Clone)]
struct JoinProtocol {
    identity: Arc<Identity>,
    group: Arc<Group>,
    book: Arc<Mutex<InvitationBook>>,
    on_admitted: Option<AdmissionHook>,
}

impl std::fmt::Debug for JoinProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JoinProtocol")
    }
}

impl ProtocolHandler for JoinProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        let Ok(opened) = tokio::time::timeout(frame::READ_TIMEOUT, connection.accept_bi()).await
        else {
            return Ok(());
        };
        let (mut send, mut recv) = opened?;
        let reply = match read_frame::<JoinRequest>(&mut recv).await {
            Err(e) => JoinReply::Error {
                message: e.to_string(),
            },
            Ok(request) => {
                let redeemed =
                    self.book
                        .lock()
                        .expect("book lock")
                        .redeem(&request, &remote, now_secs());
                match redeemed {
                    Err(e) => JoinReply::Error {
                        message: e.to_string(),
                    },
                    Ok(admission) => {
                        let op = Op::Add {
                            device: admission.device,
                            name: admission.name.clone(),
                            approver: admission.approver,
                        };
                        match self.group.append(&self.identity, op) {
                            Err(e) => JoinReply::Error {
                                message: e.to_string(),
                            },
                            Ok(_) => {
                                if let Some(hook) = &self.on_admitted {
                                    hook(admission.device, &admission.name, &admission.sas);
                                }
                                JoinReply::Ok {
                                    log: self.group.log(),
                                    sas: admission.sas,
                                }
                            }
                        }
                    }
                }
            }
        };
        write_frame(&mut send, &reply)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        let _ = tokio::time::timeout(frame::READ_TIMEOUT, connection.closed()).await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------------------

/// Known direct addresses of other devices. Filled from invitations, explicit addresses
/// and (later) the coordination server; without an entry, address lookup is used.
#[derive(Clone, Default)]
pub struct PeerBook(Arc<RwLock<HashMap<DeviceId, EndpointAddr>>>);

impl PeerBook {
    /// Adds addresses for a device, keeping the ones already known (at most 8, newest
    /// first), so that a bad hint cannot erase a good one.
    pub fn remember(&self, addr: EndpointAddr) {
        let new: Vec<SocketAddr> = addr.ip_addrs().copied().collect();
        if new.is_empty() {
            return;
        }
        let mut map = self.0.write().expect("peers lock");
        let mut merged = new;
        if let Some(old) = map.get(&addr.id) {
            for a in old.ip_addrs() {
                if !merged.contains(a) {
                    merged.push(*a);
                }
            }
        }
        merged.truncate(8);
        let mut entry = EndpointAddr::new(addr.id);
        for a in merged {
            entry = entry.with_ip_addr(a);
        }
        map.insert(addr.id, entry);
    }

    pub fn addr_of(&self, device: &DeviceId) -> EndpointAddr {
        self.0
            .read()
            .expect("peers lock")
            .get(device)
            .cloned()
            .unwrap_or_else(|| EndpointAddr::new(*device))
    }
}

/// One request, one response, on a fresh connection.
pub(crate) async fn call_peer(
    endpoint: &Endpoint,
    peer: EndpointAddr,
    request: Request,
) -> anyhow::Result<Response> {
    let conn = endpoint
        .connect(peer, BUS_ALPN)
        .await
        .map_err(|e| anyhow!("connecting: {e}"))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("opening a stream: {e}"))?;
    write_frame(&mut send, &request).await?;
    send.finish()?;
    let response: Response = read_frame(&mut recv).await?;
    conn.close(0u32.into(), b"done");
    Ok(response)
}

/// How to run a node.
#[derive(Clone)]
pub struct NodeOptions {
    pub network: Network,
    /// Told about each admitted device, with the SAS code to show.
    pub on_admitted: Option<AdmissionHook>,
    /// The approver the bus was built with, so it can reach other devices once the node
    /// is running.
    pub approver: Option<Arc<approval::RemoteApprover>>,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            network: Network::LocalOnly,
            on_admitted: None,
            approver: None,
        }
    }
}

/// A running device.
pub struct Node {
    identity: Arc<Identity>,
    group: Arc<Group>,
    bus: Arc<Bus>,
    book: Arc<Mutex<InvitationBook>>,
    peers: PeerBook,
    connections: Connections,
    router: Router,
}

impl Node {
    pub async fn spawn(
        identity: Arc<Identity>,
        group: Arc<Group>,
        bus: Arc<Bus>,
        options: NodeOptions,
    ) -> anyhow::Result<Self> {
        let NodeOptions {
            network,
            on_admitted,
            approver,
        } = options;
        let endpoint = bind(
            &identity,
            network,
            vec![BUS_ALPN.to_vec(), LOG_ALPN.to_vec(), JOIN_ALPN.to_vec()],
        )
        .await?;
        let peers = PeerBook::default();
        if let Some(approver) = &approver {
            approver.attach(approval::Link {
                endpoint: endpoint.clone(),
                peers: peers.clone(),
            });
        }
        let book = Arc::new(Mutex::new(InvitationBook::default()));
        let connections = Connections::default();
        let router = Router::builder(endpoint)
            .accept(
                BUS_ALPN,
                BusProtocol {
                    bus: bus.clone(),
                    group: group.clone(),
                    connections: connections.clone(),
                },
            )
            .accept(
                LOG_ALPN,
                LogProtocol {
                    group: group.clone(),
                },
            )
            .accept(
                JOIN_ALPN,
                JoinProtocol {
                    identity: identity.clone(),
                    group: group.clone(),
                    book: book.clone(),
                    on_admitted,
                },
            )
            .spawn();
        Ok(Self {
            identity,
            group,
            bus,
            book,
            peers,
            connections,
            router,
        })
    }

    /// Known addresses of other devices.
    pub fn peers(&self) -> &PeerBook {
        &self.peers
    }

    pub fn id(&self) -> DeviceId {
        self.identity.id()
    }

    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }

    pub fn group(&self) -> &Arc<Group> {
        &self.group
    }

    pub fn bus(&self) -> &Arc<Bus> {
        &self.bus
    }

    /// Where peers can reach this node directly.
    pub fn addr(&self) -> EndpointAddr {
        dialable_addr(self.endpoint())
    }

    /// Issues a one-time invitation for a plain member. Only an approver may invite.
    pub fn invite(&self, ttl_secs: u64) -> anyhow::Result<Invitation> {
        self.invite_with(ttl_secs, false)
    }

    /// Issues a one-time invitation for a device that will be an approver.
    pub fn invite_approver(&self, ttl_secs: u64) -> anyhow::Result<Invitation> {
        self.invite_with(ttl_secs, true)
    }

    fn invite_with(&self, ttl_secs: u64, approver: bool) -> anyhow::Result<Invitation> {
        let membership = self.group.membership();
        if !membership.is_approver(&self.id()) {
            bail!("only an approver device can invite");
        }
        let addrs = self.addr().ip_addrs().map(ToString::to_string).collect();
        let mut invitation =
            Invitation::new(membership.group, self.id(), ttl_secs, now_secs(), addrs);
        if approver {
            invitation = invitation.as_approver();
        }
        self.book
            .lock()
            .expect("book lock")
            .issue(invitation.clone());
        Ok(invitation)
    }

    /// Calls a capability on another member device.
    pub async fn call(
        &self,
        peer: impl Into<EndpointAddr>,
        request: Request,
    ) -> anyhow::Result<Response> {
        let peer = peer.into();
        if !self.group.is_member(&peer.id) {
            bail!("{} is not a member of this group", peer.id.fmt_short());
        }
        self.peers.remember(peer.clone());
        call_peer(self.endpoint(), self.peers.addr_of(&peer.id), request).await
    }

    /// Fetches the device log from a peer and adopts it if it is a valid extension.
    pub async fn sync_log(&self, peer: impl Into<EndpointAddr>) -> anyhow::Result<Membership> {
        let conn = self
            .endpoint()
            .connect(peer.into(), LOG_ALPN)
            .await
            .map_err(|e| anyhow!("connecting: {e}"))?;
        let (send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("opening a stream: {e}"))?;
        drop(send);
        let log: DeviceLog = read_frame(&mut recv).await?;
        conn.close(0u32.into(), b"done");
        self.adopt_log(log)
    }

    /// Adopts a log received from anywhere (a peer, a coordination server).
    ///
    /// - a signed extension of ours: adopted, and sessions of removed devices revoked;
    /// - a prefix of ours (the sender is behind): ignored;
    /// - anything else (another group, a fork, a forgery): refused.
    pub fn adopt_log(&self, log: DeviceLog) -> anyhow::Result<Membership> {
        let adoption = self.group.adopt(log)?;
        self.revoke(&adoption.removed);
        Ok(self.group.membership())
    }

    /// This node's identity (for publishing to a coordination server, for example).
    pub fn identity(&self) -> &Arc<Identity> {
        &self.identity
    }

    /// Removes a device from the group (approver only, or the device itself).
    pub fn remove(&self, device: DeviceId) -> anyhow::Result<()> {
        let removed = self.group.append(&self.identity, Op::Remove { device })?;
        self.revoke(&removed);
        Ok(())
    }

    fn revoke(&self, removed: &[DeviceId]) {
        for d in removed {
            self.bus.leases().revoke_device(d, "removed from the group");
            self.connections.close(d);
        }
    }

    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.router
            .shutdown()
            .await
            .map_err(|e| anyhow!("shutting down: {e}"))
    }
}

/// Joins a group with an invitation. Returns the verified log and the SAS code to compare
/// with the one shown on the inviting device.
pub async fn join(
    identity: &Identity,
    invitation: &Invitation,
    device_name: &str,
    network: Network,
) -> anyhow::Result<(DeviceLog, String)> {
    let endpoint = bind(identity, network, vec![]).await?;
    let mut addr = EndpointAddr::new(invitation.inviter);
    for a in &invitation.addrs {
        if let Ok(sock) = a.parse::<SocketAddr>() {
            addr = addr.with_ip_addr(sock);
        }
    }
    let result = async {
        let conn = endpoint
            .connect(addr, JOIN_ALPN)
            .await
            .map_err(|e| anyhow!("connecting to the inviter: {e}"))?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("opening a stream: {e}"))?;
        write_frame(
            &mut send,
            &JoinRequest::new(identity, invitation, device_name),
        )
        .await?;
        send.finish()?;
        let reply: JoinReply = read_frame(&mut recv).await?;
        conn.close(0u32.into(), b"done");
        match reply {
            JoinReply::Error { message } => bail!("the inviter refused: {message}"),
            JoinReply::Ok { log, sas } => {
                let membership = log.verify().context("the received log does not verify")?;
                if membership.group != invitation.group {
                    bail!("the inviter answered for another group");
                }
                if !membership.is_member(&identity.id()) {
                    bail!("the received log does not include this device");
                }
                Ok((log, sas))
            }
        }
    }
    .await;
    endpoint.close().await;
    result
}
