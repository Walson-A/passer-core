//! Membership: which devices belong to a group, and who said so.
//!
//! A group is defined by an append-only [`DeviceLog`]. Each [`Entry`] is signed by a
//! device that was already a member when it was written, and chained to the previous
//! entry by hash. Every device verifies the whole chain before trusting a key, so a
//! coordination server that stores and forwards the log **cannot add a device on its
//! own**: it has no member key to sign with. It can only withhold updates, which
//! [`DeviceLog::accept_update`] detects as long as the device already saw them.
//!
//! Rules enforced by [`DeviceLog::verify`]:
//! - the first entry is a `Genesis` signed by its author, who becomes the first approver;
//! - only an approver may add a device or remove another one; any member may remove itself;
//! - a removed key is revoked for good and can never be added back;
//! - the last approver cannot be removed (the group would become unmanageable).
//!
//! Pairing (adding a device) lives in [`pairing`].

pub mod pairing;

use std::collections::{BTreeMap, BTreeSet};

use passer_identity::{DeviceId, Identity, Signature, verify};
use serde::{Deserialize, Serialize};

/// Signature context for log entries.
const ENTRY_CONTEXT: &str = "membership/entry/v1";
/// Longest device name accepted, in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// A 32-byte BLAKE3 digest.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(#[serde(with = "hex_array")] pub [u8; 32]);

impl Digest {
    pub const ZERO: Digest = Digest([0; 32]);
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &hex::encode(self.0)[..12])
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// A group is identified by the hash of its genesis entry.
pub type GroupId = Digest;

/// What an entry does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Creates the group. Its author becomes the first member, with the approver role.
    Genesis { group: String, device_name: String },
    /// Adds a device. Only an approver may write it.
    Add {
        device: DeviceId,
        name: String,
        approver: bool,
    },
    /// Removes (revokes) a device. An approver may remove anyone; a member may remove itself.
    Remove { device: DeviceId },
}

/// One signed line of the log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub prev: Digest,
    /// Unix seconds, as claimed by the author. Informative only: clocks differ.
    pub at: u64,
    pub author: DeviceId,
    #[serde(flatten)]
    pub op: Op,
    #[serde(with = "hex_sig")]
    pub sig: Signature,
}

impl Entry {
    /// The exact bytes covered by the signature. Hand-written and length-prefixed, so
    /// that verification never depends on a serializer's choices.
    fn signed_bytes(seq: u64, prev: &Digest, at: u64, author: &DeviceId, op: &Op) -> Vec<u8> {
        let mut b = Vec::with_capacity(160);
        b.extend_from_slice(&seq.to_be_bytes());
        b.extend_from_slice(&prev.0);
        b.extend_from_slice(&at.to_be_bytes());
        b.extend_from_slice(author.as_bytes());
        match op {
            Op::Genesis { group, device_name } => {
                b.push(0);
                put_str(&mut b, group);
                put_str(&mut b, device_name);
            }
            Op::Add {
                device,
                name,
                approver,
            } => {
                b.push(1);
                b.extend_from_slice(device.as_bytes());
                put_str(&mut b, name);
                b.push(u8::from(*approver));
            }
            Op::Remove { device } => {
                b.push(2);
                b.extend_from_slice(device.as_bytes());
            }
        }
        b
    }

    /// Hash of the entry including its signature; the next entry points to it.
    pub fn digest(&self) -> Digest {
        let mut h = blake3::Hasher::new();
        h.update(b"passer-core/entry-digest/v1");
        h.update(&Self::signed_bytes(
            self.seq,
            &self.prev,
            self.at,
            &self.author,
            &self.op,
        ));
        h.update(&self.sig.to_bytes());
        Digest(*h.finalize().as_bytes())
    }

    fn signature_ok(&self) -> bool {
        let bytes = Self::signed_bytes(self.seq, &self.prev, self.at, &self.author, &self.op);
        verify(&self.author, ENTRY_CONTEXT, &bytes, &self.sig).is_ok()
    }
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&(s.len() as u32).to_be_bytes());
    b.extend_from_slice(s.as_bytes());
}

/// A member, as derived from the log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Member {
    pub name: String,
    pub approver: bool,
    pub added_by: DeviceId,
    pub added_at_seq: u64,
}

/// The verified state of a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    pub group: GroupId,
    pub name: String,
    pub members: BTreeMap<DeviceId, Member>,
    pub revoked: BTreeSet<DeviceId>,
    pub head: Digest,
    pub len: u64,
}

impl Membership {
    pub fn is_member(&self, device: &DeviceId) -> bool {
        self.members.contains_key(device)
    }

    pub fn is_approver(&self, device: &DeviceId) -> bool {
        self.members.get(device).is_some_and(|m| m.approver)
    }

    pub fn approvers(&self) -> impl Iterator<Item = &DeviceId> {
        self.members
            .iter()
            .filter(|(_, m)| m.approver)
            .map(|(id, _)| id)
    }
}

/// Why a log was rejected.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    #[error("the log is empty")]
    Empty,
    #[error("entry {0}: the first entry must be a genesis")]
    NoGenesis(u64),
    #[error("entry {0}: genesis may only appear first")]
    LateGenesis(u64),
    #[error("entry {0}: wrong sequence number")]
    BadSeq(u64),
    #[error("entry {0}: does not chain to the previous entry")]
    BrokenChain(u64),
    #[error("entry {0}: invalid signature")]
    BadSignature(u64),
    #[error("entry {0}: author is not a member")]
    AuthorNotMember(u64),
    #[error("entry {0}: author is not allowed to do this")]
    NotAllowed(u64),
    #[error("entry {0}: device is already a member")]
    AlreadyMember(u64),
    #[error("entry {0}: device was revoked and cannot come back")]
    Revoked(u64),
    #[error("entry {0}: device is not a member")]
    NotMember(u64),
    #[error("entry {0}: cannot remove the last approver")]
    LastApprover(u64),
    #[error("entry {0}: invalid device name")]
    BadName(u64),
    #[error("the update does not extend the log this device already has (fork or rollback)")]
    NotAnExtension,
    #[error("the update belongs to another group")]
    OtherGroup,
}

/// The append-only, signed list of membership changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLog {
    entries: Vec<Entry>,
}

impl DeviceLog {
    /// Creates a new group whose first member (and approver) is `founder`.
    pub fn create(
        founder: &Identity,
        group_name: &str,
        founder_device_name: &str,
        now: u64,
    ) -> Result<Self, MembershipError> {
        let mut log = Self {
            entries: Vec::new(),
        };
        let op = Op::Genesis {
            group: group_name.to_owned(),
            device_name: founder_device_name.to_owned(),
        };
        log.append(founder, op, now)?;
        Ok(log)
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn group_id(&self) -> Option<GroupId> {
        self.entries.first().map(Entry::digest)
    }

    /// Verifies the whole chain and returns the resulting membership.
    pub fn verify(&self) -> Result<Membership, MembershipError> {
        let first = self.entries.first().ok_or(MembershipError::Empty)?;
        let mut state = State::default();
        for (i, entry) in self.entries.iter().enumerate() {
            let i = i as u64;
            if entry.seq != i {
                return Err(MembershipError::BadSeq(i));
            }
            let expected_prev = if i == 0 { Digest::ZERO } else { state.head };
            if entry.prev != expected_prev {
                return Err(MembershipError::BrokenChain(i));
            }
            if !entry.signature_ok() {
                return Err(MembershipError::BadSignature(i));
            }
            state.apply(i, entry)?;
            state.head = entry.digest();
        }
        let group_name = match &first.op {
            Op::Genesis { group, .. } => group.clone(),
            _ => unreachable!("checked by State::apply"),
        };
        Ok(Membership {
            group: first.digest(),
            name: group_name,
            members: state.members,
            revoked: state.revoked,
            head: state.head,
            len: self.entries.len() as u64,
        })
    }

    /// Signs and appends an operation, after checking it against the current state.
    pub fn append(&mut self, author: &Identity, op: Op, now: u64) -> Result<(), MembershipError> {
        self.push_signed(author, op, now);
        if let Err(e) = self.verify() {
            self.entries.pop();
            return Err(e);
        }
        Ok(())
    }

    /// Accepts a log received from elsewhere (a peer, the server) only if it is a valid
    /// extension of this one: same group, same history, possibly more entries.
    pub fn accept_update(&self, update: &DeviceLog) -> Result<Membership, MembershipError> {
        let membership = update.verify()?;
        if self.group_id() != update.group_id() {
            return Err(MembershipError::OtherGroup);
        }
        if update.entries.len() < self.entries.len()
            || update.entries[..self.entries.len()] != self.entries[..]
        {
            return Err(MembershipError::NotAnExtension);
        }
        Ok(membership)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("log serializes")
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    fn push_signed(&mut self, author: &Identity, op: Op, now: u64) {
        let seq = self.entries.len() as u64;
        let prev = self.entries.last().map_or(Digest::ZERO, Entry::digest);
        let bytes = Entry::signed_bytes(seq, &prev, now, &author.id(), &op);
        let sig = author.sign(ENTRY_CONTEXT, &bytes);
        self.entries.push(Entry {
            seq,
            prev,
            at: now,
            author: author.id(),
            op,
            sig,
        });
    }
}

#[derive(Default)]
struct State {
    members: BTreeMap<DeviceId, Member>,
    revoked: BTreeSet<DeviceId>,
    head: Digest,
}

impl State {
    fn apply(&mut self, i: u64, e: &Entry) -> Result<(), MembershipError> {
        match &e.op {
            Op::Genesis { group, device_name } => {
                if i != 0 {
                    return Err(MembershipError::LateGenesis(i));
                }
                check_name(group).map_err(|_| MembershipError::BadName(i))?;
                check_name(device_name).map_err(|_| MembershipError::BadName(i))?;
                self.members.insert(
                    e.author,
                    Member {
                        name: device_name.clone(),
                        approver: true,
                        added_by: e.author,
                        added_at_seq: 0,
                    },
                );
                Ok(())
            }
            _ if i == 0 => Err(MembershipError::NoGenesis(0)),
            Op::Add {
                device,
                name,
                approver,
            } => {
                let author = self
                    .members
                    .get(&e.author)
                    .ok_or(MembershipError::AuthorNotMember(i))?;
                if !author.approver {
                    return Err(MembershipError::NotAllowed(i));
                }
                check_name(name).map_err(|_| MembershipError::BadName(i))?;
                if self.revoked.contains(device) {
                    return Err(MembershipError::Revoked(i));
                }
                if self.members.contains_key(device) {
                    return Err(MembershipError::AlreadyMember(i));
                }
                self.members.insert(
                    *device,
                    Member {
                        name: name.clone(),
                        approver: *approver,
                        added_by: e.author,
                        added_at_seq: i,
                    },
                );
                Ok(())
            }
            Op::Remove { device } => {
                let author = self
                    .members
                    .get(&e.author)
                    .ok_or(MembershipError::AuthorNotMember(i))?;
                if !author.approver && *device != e.author {
                    return Err(MembershipError::NotAllowed(i));
                }
                let target = self
                    .members
                    .get(device)
                    .ok_or(MembershipError::NotMember(i))?;
                if target.approver && self.members.values().filter(|m| m.approver).count() == 1 {
                    return Err(MembershipError::LastApprover(i));
                }
                self.members.remove(device);
                self.revoked.insert(*device);
                Ok(())
            }
        }
    }
}

fn check_name(name: &str) -> Result<(), ()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.chars().any(char::is_control) {
        Err(())
    } else {
        Ok(())
    }
}

pub(crate) mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

pub(crate) mod hex_sig {
    use passer_identity::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 64] = v
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group() -> (Identity, DeviceLog) {
        let founder = Identity::generate();
        let log = DeviceLog::create(&founder, "Walson", "PC", 1).unwrap();
        (founder, log)
    }

    #[test]
    fn founder_is_the_first_approver() {
        let (founder, log) = group();
        let m = log.verify().unwrap();
        assert!(m.is_approver(&founder.id()));
        assert_eq!(m.members[&founder.id()].name, "PC");
        assert_eq!(m.members.len(), 1);
    }

    #[test]
    fn approver_adds_and_removes() {
        let (founder, mut log) = group();
        let phone = Identity::generate();
        log.append(
            &founder,
            Op::Add {
                device: phone.id(),
                name: "iPhone".into(),
                approver: false,
            },
            2,
        )
        .unwrap();
        assert!(log.verify().unwrap().is_member(&phone.id()));
        log.append(&founder, Op::Remove { device: phone.id() }, 3)
            .unwrap();
        let m = log.verify().unwrap();
        assert!(!m.is_member(&phone.id()));
        assert!(m.revoked.contains(&phone.id()));
    }

    #[test]
    fn revoked_key_never_comes_back() {
        let (founder, mut log) = group();
        let phone = Identity::generate();
        log.append(
            &founder,
            Op::Add {
                device: phone.id(),
                name: "iPhone".into(),
                approver: false,
            },
            2,
        )
        .unwrap();
        log.append(&founder, Op::Remove { device: phone.id() }, 3)
            .unwrap();
        let again = log.append(
            &founder,
            Op::Add {
                device: phone.id(),
                name: "iPhone".into(),
                approver: false,
            },
            4,
        );
        assert_eq!(again, Err(MembershipError::Revoked(3)));
        assert_eq!(
            log.entries().len(),
            3,
            "a rejected append leaves the log unchanged"
        );
    }

    #[test]
    fn plain_member_cannot_add_but_can_leave() {
        let (founder, mut log) = group();
        let phone = Identity::generate();
        let stranger = Identity::generate();
        log.append(
            &founder,
            Op::Add {
                device: phone.id(),
                name: "iPhone".into(),
                approver: false,
            },
            2,
        )
        .unwrap();
        let add = log.append(
            &phone,
            Op::Add {
                device: stranger.id(),
                name: "x".into(),
                approver: false,
            },
            3,
        );
        assert_eq!(add, Err(MembershipError::NotAllowed(2)));
        let kick = log.append(
            &phone,
            Op::Remove {
                device: founder.id(),
            },
            3,
        );
        assert_eq!(kick, Err(MembershipError::NotAllowed(2)));
        log.append(&phone, Op::Remove { device: phone.id() }, 3)
            .unwrap();
    }

    #[test]
    fn last_approver_stays() {
        let (founder, mut log) = group();
        let r = log.append(
            &founder,
            Op::Remove {
                device: founder.id(),
            },
            2,
        );
        assert_eq!(r, Err(MembershipError::LastApprover(1)));
    }

    /// The core promise: whoever stores the log (a server) cannot add a device, because it
    /// has no member key. Forging, re-signing or splicing are all detected.
    #[test]
    fn server_cannot_inject_a_device() {
        let (founder, log) = group();
        let server = Identity::generate();
        let spy = Identity::generate();

        // 1. The server signs an Add with its own key.
        let mut forged = log.clone();
        forged.push_signed(
            &server,
            Op::Add {
                device: spy.id(),
                name: "spy".into(),
                approver: true,
            },
            9,
        );
        assert_eq!(forged.verify(), Err(MembershipError::AuthorNotMember(1)));

        // 2. The server claims the founder wrote it, but cannot produce the signature.
        let mut spoofed = log.clone();
        spoofed.push_signed(
            &server,
            Op::Add {
                device: spy.id(),
                name: "spy".into(),
                approver: true,
            },
            9,
        );
        spoofed.entries.last_mut().unwrap().author = founder.id();
        assert_eq!(spoofed.verify(), Err(MembershipError::BadSignature(1)));

        // 3. The server rewrites an existing entry's payload.
        let phone = Identity::generate();
        let mut tampered = log.clone();
        tampered
            .append(
                &founder,
                Op::Add {
                    device: phone.id(),
                    name: "iPhone".into(),
                    approver: false,
                },
                2,
            )
            .unwrap();
        if let Op::Add { device, .. } = &mut tampered.entries[1].op {
            *device = spy.id();
        }
        assert_eq!(tampered.verify(), Err(MembershipError::BadSignature(1)));

        // 4. The server replaces the group with one it founded itself.
        let other = DeviceLog::create(&server, "Walson", "PC", 1).unwrap();
        assert_eq!(log.accept_update(&other), Err(MembershipError::OtherGroup));
    }

    #[test]
    fn rollback_and_fork_are_refused() {
        let (founder, mut log) = group();
        let old = log.clone();
        let phone = Identity::generate();
        log.append(
            &founder,
            Op::Remove {
                device: founder.id(),
            },
            2,
        )
        .unwrap_err();
        log.append(
            &founder,
            Op::Add {
                device: phone.id(),
                name: "iPhone".into(),
                approver: false,
            },
            2,
        )
        .unwrap();
        log.append(&founder, Op::Remove { device: phone.id() }, 3)
            .unwrap();

        // A server serving the old log would "un-revoke" the phone: refused.
        assert_eq!(
            log.accept_update(&old),
            Err(MembershipError::NotAnExtension)
        );
        // The normal direction works.
        assert!(old.accept_update(&log).is_ok());

        // A fork: same prefix, different continuation.
        let mut fork = old.clone();
        let tablet = Identity::generate();
        fork.append(
            &founder,
            Op::Add {
                device: tablet.id(),
                name: "iPad".into(),
                approver: false,
            },
            2,
        )
        .unwrap();
        assert_eq!(
            log.accept_update(&fork),
            Err(MembershipError::NotAnExtension)
        );
    }

    #[test]
    fn json_roundtrip_keeps_signatures_valid() {
        let (founder, mut log) = group();
        let phone = Identity::generate();
        log.append(
            &founder,
            Op::Add {
                device: phone.id(),
                name: "iPhone".into(),
                approver: false,
            },
            2,
        )
        .unwrap();
        let back = DeviceLog::from_json(&log.to_json()).unwrap();
        assert_eq!(back, log);
        assert_eq!(back.verify().unwrap(), log.verify().unwrap());
    }

    #[test]
    fn names_are_bounded() {
        let (founder, mut log) = group();
        let phone = Identity::generate();
        let long = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            log.append(
                &founder,
                Op::Add {
                    device: phone.id(),
                    name: long,
                    approver: false
                },
                2
            ),
            Err(MembershipError::BadName(1))
        );
        assert_eq!(
            log.append(
                &founder,
                Op::Add {
                    device: phone.id(),
                    name: "a\nb".into(),
                    approver: false
                },
                2
            ),
            Err(MembershipError::BadName(1))
        );
    }
}
