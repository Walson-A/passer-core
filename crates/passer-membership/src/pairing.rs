//! Pairing: how a new device joins a group.
//!
//! 1. An approver issues an [`Invitation`]: a one-time 32-byte secret, valid a few
//!    minutes, shown as a QR code or link ([`Invitation::to_link`]). The link carries the
//!    secret, so it must not be shared or screenshotted.
//! 2. The new device builds a [`JoinRequest`]: its public key and name, a MAC keyed by the
//!    secret (proving it saw the invitation) and a signature by its own key (proving it
//!    holds that key). It sends the request to the inviter over the transport, which
//!    already authenticates the same key.
//! 3. The inviter redeems it through its [`InvitationBook`]: secret matched in constant
//!    time, not expired, never used before, key authenticated by the transport. It then
//!    appends a signed `Add` to the log. The server never sees the secret.
//! 4. Both screens can show [`sas_code`], a 6-digit code derived from the secret and both
//!    keys. If the codes differ, someone is in the middle: cancel.
//!
//! A password-authenticated key exchange (SPAKE2) can replace the MAC later, so that a
//! short typed code is enough; the QR path does not need it.

use std::collections::HashMap;

use passer_identity::{DeviceId, Identity, Signature, verify};
use serde::{Deserialize, Serialize};

use crate::{Digest, GroupId};

const JOIN_CONTEXT: &str = "membership/join/v1";
const LINK_PREFIX: &str = "passer-core://join?";

/// Invitations live at most this long.
pub const MAX_TTL_SECS: u64 = 15 * 60;

/// An offer, from an approver, to add one device to the group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    /// The group the device is invited into.
    pub group: GroupId,
    /// The approver who issued it, and to whom the join request is sent.
    pub inviter: DeviceId,
    /// One-time random secret that keys the join MAC and the SAS code. Whoever holds it
    /// can join, so it travels only in the link.
    pub secret: [u8; 32],
    /// Unix seconds after which the invitation is no longer accepted.
    pub expires_at: u64,
    /// Where the inviter can be reached directly (`ip:port`), for the local network.
    pub addrs: Vec<String>,
    /// The relay the inviter uses (an `https://` URL), to reach it from anywhere.
    pub relay: Option<String>,
    /// Whether the new device becomes an approver. Decided by the inviter: the joining
    /// device cannot change it.
    pub approver: bool,
}

/// Errors while pairing.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    /// Not a join link, or a required parameter is missing or malformed.
    #[error("not a passer-core join link")]
    BadLink,
    /// The link's format version is newer than this build understands.
    #[error("this link uses a newer format; update the app")]
    UnsupportedVersion,
    /// No pending, unexpired invitation matches the request's group, inviter and MAC.
    #[error("no pending invitation matches this request")]
    UnknownInvitation,
    /// The invitation's expiry time has passed.
    #[error("the invitation has expired")]
    Expired,
    /// The request's device key is not the key the transport authenticated.
    #[error("the request does not match the invitation")]
    Mismatch,
    /// The request's signature does not verify against its device key.
    #[error("the request is not signed by the connecting device")]
    BadSignature,
    /// The inviter does not have the approver role in the group.
    #[error("the inviter is not an approver of this group")]
    NotApprover,
    /// The requested device name fails [`crate::is_valid_name`].
    #[error("the device name is not acceptable")]
    BadName,
}

impl Invitation {
    /// A fresh invitation with a random secret, valid `ttl_secs` from `now` (Unix seconds),
    /// capped at [`MAX_TTL_SECS`]. No relay, and the joiner will not be an approver.
    pub fn new(
        group: GroupId,
        inviter: DeviceId,
        ttl_secs: u64,
        now: u64,
        addrs: Vec<String>,
    ) -> Self {
        let mut secret = [0u8; 32];
        rand::fill(&mut secret);
        Self {
            group,
            inviter,
            secret,
            expires_at: now + ttl_secs.min(MAX_TTL_SECS),
            addrs,
            relay: None,
            approver: false,
        }
    }

    /// The relay the inviter can be reached through. Ignored if it is not a plausible URL.
    pub fn with_relay(mut self, url: impl Into<String>) -> Self {
        let url = url.into();
        if valid_relay(&url) {
            self.relay = Some(url);
        }
        self
    }

    /// The joining device will be an approver (for a second phone, a laptop...).
    pub fn as_approver(mut self) -> Self {
        self.approver = true;
        self
    }

    /// The link to show as a QR code. It contains the secret.
    pub fn to_link(&self) -> String {
        let mut link = format!(
            "{LINK_PREFIX}v=1&g={}&i={}&s={}&e={}",
            self.group,
            self.inviter,
            hex::encode(self.secret),
            self.expires_at
        );
        if !self.addrs.is_empty() {
            link.push_str("&a=");
            link.push_str(&self.addrs.join(","));
        }
        if let Some(relay) = &self.relay {
            // Hex keeps the link free of characters that need escaping.
            link.push_str("&u=");
            link.push_str(&hex::encode(relay));
        }
        if self.approver {
            link.push_str("&r=approver");
        }
        link
    }

    /// Parses a link. Unknown parameters are ignored; a newer major version is refused.
    pub fn parse_link(link: &str) -> Result<Self, PairingError> {
        let query = link
            .strip_prefix(LINK_PREFIX)
            .ok_or(PairingError::BadLink)?;
        let mut params: HashMap<&str, &str> = HashMap::new();
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').ok_or(PairingError::BadLink)?;
            params.insert(k, v);
        }
        match params.get("v") {
            Some(&"1") => {}
            Some(_) => return Err(PairingError::UnsupportedVersion),
            None => return Err(PairingError::BadLink),
        }
        let hex32 = |key: &str| -> Result<[u8; 32], PairingError> {
            let raw = hex::decode(params.get(key).ok_or(PairingError::BadLink)?)
                .map_err(|_| PairingError::BadLink)?;
            raw.try_into().map_err(|_| PairingError::BadLink)
        };
        let inviter: DeviceId = params
            .get("i")
            .ok_or(PairingError::BadLink)?
            .parse()
            .map_err(|_| PairingError::BadLink)?;
        let expires_at = params
            .get("e")
            .ok_or(PairingError::BadLink)?
            .parse()
            .map_err(|_| PairingError::BadLink)?;
        let addrs = params
            .get("a")
            .map(|a| {
                a.split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            group: Digest(hex32("g")?),
            inviter,
            secret: hex32("s")?,
            expires_at,
            addrs,
            // An unreadable relay is dropped, not fatal: direct addresses may still work.
            relay: params
                .get("u")
                .and_then(|u| hex::decode(u).ok())
                .and_then(|b| String::from_utf8(b).ok())
                .filter(|u| valid_relay(u)),
            approver: params.get("r") == Some(&"approver"),
        })
    }

    fn mac(&self, device: &DeviceId, name: &str) -> blake3::Hash {
        blake3::keyed_hash(
            &self.secret,
            &join_bytes(&self.group, &self.inviter, device, name),
        )
    }
}

/// A relay URL worth trying: `https://` (or `http://` for tests), printable, bounded.
pub fn valid_relay(url: &str) -> bool {
    url.len() <= 256
        && (url.starts_with("https://") || url.starts_with("http://"))
        && url.chars().all(|c| c.is_ascii_graphic())
}

/// What a joining device sends to the inviter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    /// The group named in the invitation.
    pub group: GroupId,
    /// The inviter named in the invitation.
    pub inviter: DeviceId,
    /// The joining device's key.
    pub device: DeviceId,
    /// The name it asks to join under.
    pub name: String,
    /// Keyed BLAKE3 of group, inviter, device and name under the invitation secret:
    /// proves the joiner saw the invitation without revealing the secret.
    #[serde(with = "crate::hex_array")]
    pub mac: [u8; 32],
    /// The joiner's signature over the same fields: proves it holds `device`'s key.
    #[serde(with = "crate::hex_sig")]
    pub sig: Signature,
}

impl JoinRequest {
    /// Builds and signs the request `joiner` sends to answer `invitation` under `name`.
    pub fn new(joiner: &Identity, invitation: &Invitation, name: &str) -> Self {
        let device = joiner.id();
        let bytes = join_bytes(&invitation.group, &invitation.inviter, &device, name);
        Self {
            group: invitation.group,
            inviter: invitation.inviter,
            device,
            name: name.to_owned(),
            mac: *invitation.mac(&device, name).as_bytes(),
            sig: joiner.sign(JOIN_CONTEXT, &bytes),
        }
    }
}

fn join_bytes(group: &GroupId, inviter: &DeviceId, device: &DeviceId, name: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(100 + name.len());
    b.extend_from_slice(&group.0);
    b.extend_from_slice(inviter.as_bytes());
    b.extend_from_slice(device.as_bytes());
    b.extend_from_slice(&(name.len() as u32).to_be_bytes());
    b.extend_from_slice(name.as_bytes());
    b
}

/// Six digits both devices can display, to compare by eye.
pub fn sas_code(secret: &[u8; 32], inviter: &DeviceId, joiner: &DeviceId) -> String {
    let mut data = Vec::with_capacity(72);
    data.extend_from_slice(b"sas/v1");
    data.extend_from_slice(inviter.as_bytes());
    data.extend_from_slice(joiner.as_bytes());
    let h = blake3::keyed_hash(secret, &data);
    let n = u32::from_be_bytes(h.as_bytes()[..4].try_into().expect("4 bytes")) % 1_000_000;
    format!("{n:06}")
}

/// The invitations an approver has issued and not yet seen redeemed.
#[derive(Default)]
pub struct InvitationBook {
    pending: Vec<Invitation>,
}

/// A redeemed invitation: who joins, and the code to show.
#[derive(Debug, PartialEq, Eq)]
pub struct Admission {
    /// The joining device's key, as authenticated by the transport.
    pub device: DeviceId,
    /// The name it asked for (valid, but not yet checked for uniqueness in the group).
    pub name: String,
    /// The 6-digit [`sas_code`] to show, for comparison with the joiner's screen.
    pub sas: String,
    /// Taken from the inviter's own copy of the invitation, never from the request.
    pub approver: bool,
}

impl InvitationBook {
    /// Records an invitation as pending, so a matching join request can redeem it.
    pub fn issue(&mut self, invitation: Invitation) {
        self.pending.push(invitation);
    }

    /// How many invitations are pending, expired ones included until the next
    /// [`InvitationBook::redeem`] prunes them.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Whether any invitation is still valid at `now`: without one, a join cannot succeed
    /// and need not even be read.
    pub fn has_open(&self, now: u64) -> bool {
        self.pending.iter().any(|inv| inv.expires_at > now)
    }

    /// Checks a join request. `authenticated` is the key the transport proved the remote
    /// holds. On success the invitation is consumed: a second use fails.
    pub fn redeem(
        &mut self,
        request: &JoinRequest,
        authenticated: &DeviceId,
        now: u64,
    ) -> Result<Admission, PairingError> {
        self.pending.retain(|inv| inv.expires_at > now);
        // Check the name before consuming anything, so a bad name does not burn the
        // invitation. (Uniqueness is checked when the inviter appends to the log.)
        if !crate::is_valid_name(&request.name) {
            return Err(PairingError::BadName);
        }
        if request.device != *authenticated {
            return Err(PairingError::Mismatch);
        }
        let bytes = join_bytes(
            &request.group,
            &request.inviter,
            &request.device,
            &request.name,
        );
        verify(&request.device, JOIN_CONTEXT, &bytes, &request.sig)
            .map_err(|_| PairingError::BadSignature)?;
        let expected = blake3::Hash::from_bytes(request.mac);
        let index = self
            .pending
            .iter()
            .position(|inv| {
                // blake3::Hash compares in constant time.
                inv.group == request.group
                    && inv.inviter == request.inviter
                    && inv.mac(&request.device, &request.name) == expected
            })
            .ok_or(PairingError::UnknownInvitation)?;
        let inv = self.pending.remove(index);
        Ok(Admission {
            device: request.device,
            name: request.name.clone(),
            sas: sas_code(&inv.secret, &inv.inviter, &request.device),
            approver: inv.approver,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceLog, Op};

    fn setup() -> (Identity, DeviceLog, Invitation, InvitationBook) {
        let pc = Identity::generate();
        let log = DeviceLog::create(&pc, "Walson", "PC", 100).unwrap();
        let inv = Invitation::new(
            log.group_id().unwrap(),
            pc.id(),
            300,
            100,
            vec!["192.168.1.10:4433".into()],
        );
        let mut book = InvitationBook::default();
        book.issue(inv.clone());
        (pc, log, inv, book)
    }

    #[test]
    fn link_roundtrip() {
        let (_, _, inv, _) = setup();
        assert_eq!(Invitation::parse_link(&inv.to_link()).unwrap(), inv);
        let newer = inv.to_link().replace("v=1", "v=2");
        assert_eq!(
            Invitation::parse_link(&newer),
            Err(PairingError::UnsupportedVersion)
        );
        assert_eq!(
            Invitation::parse_link("https://example.com"),
            Err(PairingError::BadLink)
        );
    }

    #[test]
    fn full_join_then_log_append() {
        let (pc, mut log, inv, mut book) = setup();
        let phone = Identity::generate();
        let scanned = Invitation::parse_link(&inv.to_link()).unwrap();
        let req = JoinRequest::new(&phone, &scanned, "iPhone");
        let admission = book.redeem(&req, &phone.id(), 150).unwrap();
        assert_eq!(
            admission.sas,
            sas_code(&scanned.secret, &pc.id(), &phone.id())
        );
        log.append(
            &pc,
            Op::Add {
                device: admission.device,
                name: admission.name,
                approver: false,
            },
            150,
        )
        .unwrap();
        assert!(log.verify().unwrap().is_member(&phone.id()));
    }

    #[test]
    fn invitation_is_single_use() {
        let (_, _, inv, mut book) = setup();
        let phone = Identity::generate();
        let req = JoinRequest::new(&phone, &inv, "iPhone");
        book.redeem(&req, &phone.id(), 150).unwrap();
        assert_eq!(
            book.redeem(&req, &phone.id(), 151),
            Err(PairingError::UnknownInvitation)
        );
    }

    #[test]
    fn expired_invitation_is_refused() {
        let (_, _, inv, mut book) = setup();
        let phone = Identity::generate();
        let req = JoinRequest::new(&phone, &inv, "iPhone");
        assert_eq!(
            book.redeem(&req, &phone.id(), 100 + 301),
            Err(PairingError::UnknownInvitation)
        );
    }

    #[test]
    fn wrong_secret_is_refused() {
        let (pc, log, _, mut book) = setup();
        let guessed = Invitation::new(log.group_id().unwrap(), pc.id(), 300, 100, vec![]);
        let phone = Identity::generate();
        let req = JoinRequest::new(&phone, &guessed, "iPhone");
        assert_eq!(
            book.redeem(&req, &phone.id(), 150),
            Err(PairingError::UnknownInvitation)
        );
    }

    #[test]
    fn request_must_come_from_its_own_key() {
        let (_, _, inv, mut book) = setup();
        let phone = Identity::generate();
        let attacker = Identity::generate();
        let req = JoinRequest::new(&phone, &inv, "iPhone");
        // Someone replays the phone's request from another connection.
        assert_eq!(
            book.redeem(&req, &attacker.id(), 150),
            Err(PairingError::Mismatch)
        );
        // Someone swaps the name: the MAC and signature no longer match.
        let mut renamed = req.clone();
        renamed.name = "Evil".into();
        assert_eq!(
            book.redeem(&renamed, &phone.id(), 150),
            Err(PairingError::BadSignature)
        );
        // The genuine request still works afterwards.
        assert!(book.redeem(&req, &phone.id(), 150).is_ok());
    }

    #[test]
    fn role_comes_from_the_inviter_not_the_link() {
        let (pc, log, _, mut book) = setup();
        let plain = Invitation::new(log.group_id().unwrap(), pc.id(), 300, 100, vec![]);
        book.issue(plain.clone());
        // The joiner edits its copy of the link to ask for the approver role.
        let tampered = Invitation::parse_link(&format!("{}&r=approver", plain.to_link())).unwrap();
        assert!(tampered.approver);
        let phone = Identity::generate();
        let admission = book
            .redeem(
                &JoinRequest::new(&phone, &tampered, "iPhone"),
                &phone.id(),
                150,
            )
            .unwrap();
        assert!(!admission.approver, "the inviter's copy decides");

        let promoted =
            Invitation::new(log.group_id().unwrap(), pc.id(), 300, 100, vec![]).as_approver();
        book.issue(promoted.clone());
        let laptop = Identity::generate();
        let parsed = Invitation::parse_link(&promoted.to_link()).unwrap();
        assert!(
            book.redeem(
                &JoinRequest::new(&laptop, &parsed, "Laptop"),
                &laptop.id(),
                150
            )
            .unwrap()
            .approver
        );
    }

    #[test]
    fn ttl_is_capped() {
        let inv = Invitation::new(
            Digest::ZERO,
            Identity::generate().id(),
            10 * 3600,
            0,
            vec![],
        );
        assert_eq!(inv.expires_at, MAX_TTL_SECS);
    }
}
