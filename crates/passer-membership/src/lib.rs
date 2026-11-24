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

#![warn(missing_docs)]

pub mod pairing;

use std::collections::{BTreeMap, BTreeSet};

use passer_identity::{DeviceId, Identity, Signature, verify};
use serde::{Deserialize, Serialize};

/// Signature context for log entries.
const ENTRY_CONTEXT: &str = "membership/entry/v1";
/// Longest device name accepted, in bytes.
pub const MAX_NAME_LEN: usize = 64;
/// Longest log accepted. Bounds the work any peer or server can ask of a verifier.
pub const MAX_LOG_ENTRIES: usize = 4096;

/// A 32-byte BLAKE3 digest.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(#[serde(with = "hex_array")] pub [u8; 32]);

impl Digest {
    /// All zeros: the `prev` of the genesis entry.
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
    Genesis {
        /// The group's display name.
        group: String,
        /// The founding device's name.
        device_name: String,
    },
    /// Adds a device. Only an approver may write it.
    Add {
        /// The new member's key.
        device: DeviceId,
        /// Its name, unique in the group (see [`same_name`]).
        name: String,
        /// Whether it may add and remove devices too.
        approver: bool,
    },
    /// Removes (revokes) a device. An approver may remove anyone; a member may remove itself.
    Remove {
        /// The device to revoke.
        device: DeviceId,
    },
}

/// One signed line of the log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Position in the log, from 0.
    pub seq: u64,
    /// [`Entry::digest`] of the previous entry, [`Digest::ZERO`] for the genesis.
    pub prev: Digest,
    /// Unix seconds, as claimed by the author. Informative only: clocks differ.
    pub at: u64,
    /// The member who wrote and signed the entry.
    pub author: DeviceId,
    /// The change it makes.
    #[serde(flatten)]
    pub op: Op,
    /// The author's signature over `seq`, `prev`, `at`, `author` and `op`.
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
    /// The device's name, unique in the group.
    pub name: String,
    /// Whether it may add and remove devices.
    pub approver: bool,
    /// The approver that added it (itself for the founder).
    pub added_by: DeviceId,
    /// `seq` of the entry that added it (0 for the founder); lower is more senior.
    pub added_at_seq: u64,
}

/// The verified state of a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    /// The group's id (digest of the genesis entry).
    pub group: GroupId,
    /// The group's display name.
    pub name: String,
    /// Current members by key.
    pub members: BTreeMap<DeviceId, Member>,
    /// Every key ever removed; none of them can be added again.
    pub revoked: BTreeSet<DeviceId>,
    /// Digest of the last entry.
    pub head: Digest,
    /// Number of entries in the log.
    pub len: u64,
}

impl Membership {
    /// Whether `device` is currently a member.
    pub fn is_member(&self, device: &DeviceId) -> bool {
        self.members.contains_key(device)
    }

    /// Whether `device` is currently a member with the approver role.
    pub fn is_approver(&self, device: &DeviceId) -> bool {
        self.members.get(device).is_some_and(|m| m.approver)
    }

    /// The current approvers' keys.
    pub fn approvers(&self) -> impl Iterator<Item = &DeviceId> {
        self.members
            .iter()
            .filter(|(_, m)| m.approver)
            .map(|(id, _)| id)
    }
}

/// Why a log was rejected.
///
/// Where a variant carries a `u64`, it is the index of the offending entry.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    /// The log has no entries.
    #[error("the log is empty")]
    Empty,
    /// The first entry is not a `Genesis`.
    #[error("entry {0}: the first entry must be a genesis")]
    NoGenesis(u64),
    /// A `Genesis` appears after the first entry.
    #[error("entry {0}: genesis may only appear first")]
    LateGenesis(u64),
    /// An entry's `seq` is not its position in the log.
    #[error("entry {0}: wrong sequence number")]
    BadSeq(u64),
    /// An entry's `prev` is not the digest of the entry before it.
    #[error("entry {0}: does not chain to the previous entry")]
    BrokenChain(u64),
    /// An entry's signature does not verify against its author.
    #[error("entry {0}: invalid signature")]
    BadSignature(u64),
    /// An entry's author is not a member at that point of the log.
    #[error("entry {0}: author is not a member")]
    AuthorNotMember(u64),
    /// The author lacks the right: a non-approver adding a device or removing another.
    #[error("entry {0}: author is not allowed to do this")]
    NotAllowed(u64),
    /// The added device is already a member.
    #[error("entry {0}: device is already a member")]
    AlreadyMember(u64),
    /// The added device was removed earlier; a revoked key never comes back.
    #[error("entry {0}: device was revoked and cannot come back")]
    Revoked(u64),
    /// The removed device is not a member.
    #[error("entry {0}: device is not a member")]
    NotMember(u64),
    /// The entry would remove the group's last approver.
    #[error("entry {0}: cannot remove the last approver")]
    LastApprover(u64),
    /// A group or device name fails [`is_valid_name`].
    #[error("entry {0}: invalid device name")]
    BadName(u64),
    /// The added name is the [`same_name`] as an existing member's.
    #[error("entry {0}: another member already has this name")]
    NameTaken(u64),
    /// The log has more than [`MAX_LOG_ENTRIES`] entries.
    #[error("the log is longer than {MAX_LOG_ENTRIES} entries")]
    TooLong,
    /// The update is not this log plus new entries (a fork or a rollback).
    #[error("the update does not extend the log this device already has (fork or rollback)")]
    NotAnExtension,
    /// The other log belongs to a different group.
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

    /// All entries, oldest first.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// How many leading entries two logs share.
    pub fn common_prefix_len(&self, other: &DeviceLog) -> usize {
        self.entries
            .iter()
            .zip(&other.entries)
            .take_while(|(a, b)| a == b)
            .count()
    }

    /// The first `n` entries (a genuine, older state of the same log).
    pub fn prefix(&self, n: usize) -> DeviceLog {
        DeviceLog {
            entries: self.entries[..n.min(self.entries.len())].to_vec(),
        }
    }

    /// The group's id (digest of the first entry), `None` for an empty log.
    pub fn group_id(&self) -> Option<GroupId> {
        self.entries.first().map(Entry::digest)
    }

    /// Verifies the whole chain and returns the resulting membership.
    pub fn verify(&self) -> Result<Membership, MembershipError> {
        if self.entries.len() > MAX_LOG_ENTRIES {
            return Err(MembershipError::TooLong);
        }
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

    /// Decides which of two logs of the same group should be kept. Both must verify.
    ///
    /// When one extends the other, the longer one. When they **fork** (same history up to
    /// a point, then different signed entries), a deterministic rule that every device and
    /// server applies alike, so that all converge on the same branch:
    ///
    /// 1. **Revocation wins.** If one branch removes a device that wrote entries in the
    ///    other branch, and not the reverse, it wins. A removed (e.g. stolen) approver
    ///    cannot keep its own branch alive by publishing it first.
    /// 2. If both branches revoke each other's authors, the branch that keeps more of the
    ///    approvers present at the fork point wins.
    /// 3. If neither does, a branch whose removals strictly contain the other's wins:
    ///    a removal is never dropped for a branch that removes less.
    /// 4. Then the branch whose first divergent entry comes from the more senior device
    ///    (added earlier) wins; then the lower entry digest, so the choice is never a tie.
    ///
    /// A device whose branch loses replays its own entries on the winner
    /// (`passer_node::Node::adopt_log`), so a removal it made is re-applied.
    ///
    /// With only two approvers that revoke each other, rule 3 decides; recovery beyond
    /// that needs a recovery code (not implemented yet).
    pub fn prefer(&self, other: &DeviceLog) -> Result<Preferred, MembershipError> {
        let ours_m = self.verify()?;
        let theirs_m = other.verify()?;
        if self.group_id() != other.group_id() {
            return Err(MembershipError::OtherGroup);
        }
        let k = self
            .entries
            .iter()
            .zip(&other.entries)
            .take_while(|(a, b)| a == b)
            .count();
        match (k == self.entries.len(), k == other.entries.len()) {
            (true, true) => return Ok(Preferred::Same),
            (true, false) => return Ok(Preferred::Theirs),
            (false, true) => return Ok(Preferred::Ours),
            (false, false) => {}
        }
        let base = DeviceLog {
            entries: self.entries[..k].to_vec(),
        }
        .verify()?;
        let (ours, theirs) = (&self.entries[k..], &other.entries[k..]);
        let authors = |branch: &[Entry]| branch.iter().map(|e| e.author).collect::<BTreeSet<_>>();
        let removed = |branch: &[Entry]| {
            branch
                .iter()
                .filter_map(|e| match &e.op {
                    Op::Remove { device } => Some(*device),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
        };
        let ours_revokes_theirs = !removed(ours).is_disjoint(&authors(theirs));
        let theirs_revokes_ours = !removed(theirs).is_disjoint(&authors(ours));
        match (ours_revokes_theirs, theirs_revokes_ours) {
            (true, false) => return Ok(Preferred::Ours),
            (false, true) => return Ok(Preferred::Theirs),
            (true, true) => {
                // Mutual: the branch that keeps more of the fork point's approvers.
                let kept = |m: &Membership| base.approvers().filter(|a| m.is_approver(a)).count();
                match kept(&ours_m).cmp(&kept(&theirs_m)) {
                    std::cmp::Ordering::Greater => return Ok(Preferred::Ours),
                    std::cmp::Ordering::Less => return Ok(Preferred::Theirs),
                    std::cmp::Ordering::Equal => {}
                }
            }
            (false, false) => {
                // Neither touches the other's authors: never drop a removal in favour of a
                // branch that removes less. (Incomparable removals fall through; the
                // losing device replays its own entries on the winner, see passer-node.)
                let (ro, rt) = (removed(ours), removed(theirs));
                if ro.is_superset(&rt) && ro != rt {
                    return Ok(Preferred::Ours);
                }
                if rt.is_superset(&ro) && ro != rt {
                    return Ok(Preferred::Theirs);
                }
            }
        }
        let seniority = |e: &Entry| {
            base.members
                .get(&e.author)
                .map_or(u64::MAX, |m| m.added_at_seq)
        };
        let key = |e: &Entry| (seniority(e), e.digest());
        Ok(if key(&ours[0]) <= key(&theirs[0]) {
            Preferred::Ours
        } else {
            Preferred::Theirs
        })
    }

    /// The log as pretty-printed JSON, the form it is stored and exchanged in.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("log serializes")
    }

    /// Parses a log from JSON. Does not verify it: call [`DeviceLog::verify`] or
    /// [`DeviceLog::accept_update`] before trusting it.
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

/// The outcome of [`DeviceLog::prefer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preferred {
    /// Keep this log.
    Ours,
    /// Switch to the other log.
    Theirs,
    /// The two logs are identical.
    Same,
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
                if self.members.values().any(|m| same_name(&m.name, name)) {
                    return Err(MembershipError::NameTaken(i));
                }
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
    if is_valid_name(name) { Ok(()) } else { Err(()) }
}

/// A device or group name: 1 to 64 bytes, with no control, invisible or bidirectional
/// formatting characters (which could make two names look alike or reorder text), and
/// not only spaces.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.trim().is_empty()
        && !name
            .chars()
            .any(|c| c.is_control() || is_invisible_or_bidi(c))
}

fn is_invisible_or_bidi(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}'
        | '\u{FFA0}' | '\u{FFF0}'..='\u{FFFB}' | '\u{E0000}'..='\u{E0FFF}')
}

/// Two names that a person could take for each other: compared without case, spaces or
/// punctuation. (Look-alike letters from other scripts are not caught; apps also show a
/// short device id.)
pub fn same_name(a: &str, b: &str) -> bool {
    let key = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect()
    };
    key(a) == key(b)
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

    /// The attack found in review: a removed (stolen) approver forks from before its
    /// removal and publishes first. Whatever order the branches arrive in, every device
    /// keeps the branch that revokes the thief.
    #[test]
    fn a_removed_approver_cannot_win_a_fork() {
        let (founder, mut base) = group();
        let thief = Identity::generate();
        let evil = Identity::generate();
        base.append(
            &founder,
            Op::Add {
                device: thief.id(),
                name: "Phone".into(),
                approver: true,
            },
            2,
        )
        .unwrap();

        let mut honest = base.clone();
        honest
            .append(&founder, Op::Remove { device: thief.id() }, 3)
            .unwrap();

        let mut fork = base.clone();
        fork.append(
            &thief,
            Op::Add {
                device: evil.id(),
                name: "Evil".into(),
                approver: true,
            },
            3,
        )
        .unwrap();
        fork.append(
            &thief,
            Op::Remove {
                device: founder.id(),
            },
            4,
        )
        .unwrap();
        assert!(fork.verify().is_ok(), "the fork is valid on its own");

        // Whichever side a device is on, both agree on the honest branch.
        assert_eq!(honest.prefer(&fork), Ok(Preferred::Ours));
        assert_eq!(fork.prefer(&honest), Ok(Preferred::Theirs));

        // Same result when the thief's branch does not even remove the founder.
        let mut quiet = base.clone();
        quiet
            .append(
                &thief,
                Op::Add {
                    device: evil.id(),
                    name: "Evil".into(),
                    approver: true,
                },
                3,
            )
            .unwrap();
        assert_eq!(honest.prefer(&quiet), Ok(Preferred::Ours));
        assert_eq!(quiet.prefer(&honest), Ok(Preferred::Theirs));
    }

    #[test]
    fn concurrent_benign_changes_converge() {
        let (founder, mut base) = group();
        let second = Identity::generate();
        base.append(
            &founder,
            Op::Add {
                device: second.id(),
                name: "Laptop".into(),
                approver: true,
            },
            2,
        )
        .unwrap();
        let (x, y) = (Identity::generate(), Identity::generate());
        let mut a = base.clone();
        a.append(
            &founder,
            Op::Add {
                device: x.id(),
                name: "X".into(),
                approver: false,
            },
            3,
        )
        .unwrap();
        let mut b = base.clone();
        b.append(
            &second,
            Op::Add {
                device: y.id(),
                name: "Y".into(),
                approver: false,
            },
            3,
        )
        .unwrap();
        // Deterministic and antisymmetric: both sides pick the same branch (the founder's).
        assert_eq!(a.prefer(&b), Ok(Preferred::Ours));
        assert_eq!(b.prefer(&a), Ok(Preferred::Theirs));
        assert_eq!(a.prefer(&a.clone()), Ok(Preferred::Same));
        assert_eq!(base.prefer(&a), Ok(Preferred::Theirs));
        assert_eq!(a.prefer(&base), Ok(Preferred::Ours));
    }

    #[test]
    fn mutual_removal_keeps_the_branch_with_more_approvers() {
        let (founder, mut base) = group();
        let laptop = Identity::generate();
        let thief = Identity::generate();
        base.append(
            &founder,
            Op::Add {
                device: laptop.id(),
                name: "Laptop".into(),
                approver: true,
            },
            2,
        )
        .unwrap();
        base.append(
            &founder,
            Op::Add {
                device: thief.id(),
                name: "Phone".into(),
                approver: true,
            },
            3,
        )
        .unwrap();
        let mut honest = base.clone();
        honest
            .append(&laptop, Op::Remove { device: thief.id() }, 4)
            .unwrap();
        let mut fork = base.clone();
        fork.append(
            &thief,
            Op::Remove {
                device: laptop.id(),
            },
            4,
        )
        .unwrap();
        fork.append(
            &thief,
            Op::Remove {
                device: founder.id(),
            },
            5,
        )
        .unwrap();
        assert_eq!(honest.prefer(&fork), Ok(Preferred::Ours));
        assert_eq!(fork.prefer(&honest), Ok(Preferred::Theirs));
    }

    #[test]
    fn look_alike_and_invisible_names_are_refused() {
        let (founder, mut log) = group(); // the founder is "PC"
        for name in ["PC", "pc", " P-C ", "P.C"] {
            let d = Identity::generate();
            assert_eq!(
                log.append(
                    &founder,
                    Op::Add {
                        device: d.id(),
                        name: name.into(),
                        approver: false
                    },
                    2
                ),
                Err(MembershipError::NameTaken(1)),
                "{name:?}"
            );
        }
        for name in ["PC\u{202E}", "P\u{200B}C", "\u{FEFF}Phone", "   "] {
            let d = Identity::generate();
            assert_eq!(
                log.append(
                    &founder,
                    Op::Add {
                        device: d.id(),
                        name: name.into(),
                        approver: false
                    },
                    2
                ),
                Err(MembershipError::BadName(1)),
                "{name:?}"
            );
        }
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
