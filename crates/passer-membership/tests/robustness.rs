//! Property tests: thousands of random mutations and inputs. Nothing may panic, and no
//! modified log may verify as anything other than what was signed.

use passer_identity::Identity;
use passer_membership::pairing::{Invitation, InvitationBook, JoinRequest};
use passer_membership::{DeviceLog, Op, Preferred};
use proptest::prelude::*;

/// A log with a few members and a removal, built once for all cases.
fn sample_log() -> (&'static Identity, DeviceLog) {
    static SAMPLE: std::sync::LazyLock<(Identity, DeviceLog)> =
        std::sync::LazyLock::new(build_sample);
    (&SAMPLE.0, SAMPLE.1.clone())
}

fn build_sample() -> (Identity, DeviceLog) {
    let founder = Identity::generate();
    let mut log = DeviceLog::create(&founder, "Group", "PC", 10).unwrap();
    let phone = Identity::generate();
    let tablet = Identity::generate();
    log.append(
        &founder,
        Op::Add {
            device: phone.id(),
            name: "Phone".into(),
            approver: false,
        },
        11,
    )
    .unwrap();
    log.append(
        &founder,
        Op::Add {
            device: tablet.id(),
            name: "Tablet".into(),
            approver: true,
        },
        12,
    )
    .unwrap();
    log.append(&tablet, Op::Remove { device: phone.id() }, 13)
        .unwrap();
    (founder, log)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Flipping any single byte of the serialized log either breaks parsing, breaks
    /// verification, or leaves the meaning unchanged (e.g. whitespace). It never yields a
    /// different, valid membership.
    #[test]
    fn single_byte_mutation_never_forges(index in any::<prop::sample::Index>(), new_byte in any::<u8>()) {
        let (_, log) = sample_log();
        let original = log.verify().unwrap();
        let mut bytes = log.to_json().into_bytes();
        let i = index.index(bytes.len());
        bytes[i] = new_byte;
        if let Ok(text) = String::from_utf8(bytes)
            && let Ok(mutated) = DeviceLog::from_json(&text)
            && let Ok(m) = mutated.verify()
        {
            prop_assert_eq!(m, original);
        }
    }

    /// Re-ordering, dropping or duplicating entries never verifies, except dropping a tail
    /// (an older but genuine state), which `accept_update` then refuses as a rollback.
    #[test]
    fn reshuffled_entries_are_refused(ops in prop::collection::vec(0u8..3, 1..4), at in 1usize..4) {
        let (_, log) = sample_log();
        let mut v: serde_json::Value = serde_json::from_str(&log.to_json()).unwrap();
        let entries = v["entries"].as_array_mut().unwrap();
        for op in ops {
            let i = at.min(entries.len() - 1);
            match op {
                0 => { let e = entries.remove(i); entries.insert(0, e); }
                1 => { let e = entries[i].clone(); entries.push(e); }
                _ => { entries.remove(i); }
            }
        }
        let shuffled = DeviceLog::from_json(&v.to_string()).unwrap();
        if shuffled.verify().is_ok() {
            // Only a genuine prefix can verify, and it cannot replace the newer log.
            prop_assert!(log.entries().starts_with(shuffled.entries()));
            prop_assert!(log.accept_update(&shuffled).is_err() || shuffled == log);
        }
    }

    /// Any string fed to the link parser returns, never panics.
    #[test]
    fn link_parser_never_panics(s in ".{0,400}") {
        let _ = Invitation::parse_link(&s);
        let _ = Invitation::parse_link(&format!("passer-core://join?{s}"));
    }

    /// Random parameters around a valid link: parse or refuse, never panic.
    #[test]
    fn mangled_links_never_panic(extra in "[a-z]{1,3}=[^&]{0,80}", cut in 0usize..300) {
        let inv = Invitation::new(passer_membership::Digest([7; 32]), Identity::generate().id(), 300, 0, vec!["1.2.3.4:5".into()]);
        let link = format!("{}&{extra}", inv.to_link());
        let cut = cut.min(link.len());
        if link.is_char_boundary(cut) {
            let _ = Invitation::parse_link(&link[..cut]);
        }
        let _ = Invitation::parse_link(&link);
    }

    /// A join request with any field changed is refused, and the invitation stays usable
    /// for the genuine request.
    #[test]
    fn tampered_join_requests_are_refused(which in 0u8..5, byte in any::<u8>()) {
        let (founder, log) = sample_log();
        let inv = Invitation::new(log.group_id().unwrap(), founder.id(), 300, 100, vec![]);
        let mut book = InvitationBook::default();
        book.issue(inv.clone());
        let joiner = Identity::generate();
        let genuine = JoinRequest::new(&joiner, &inv, "Laptop");
        let mut bad = genuine.clone();
        match which {
            0 => bad.mac[0] ^= byte.max(1),
            1 => bad.name.push(char::from(b'a' + byte % 26)),
            2 => bad.group.0[0] ^= byte.max(1),
            3 => bad.inviter = Identity::generate().id(),
            _ => bad.device = Identity::generate().id(),
        }
        let authenticated = bad.device;
        prop_assert!(book.redeem(&bad, &authenticated, 150).is_err());
        prop_assert!(book.redeem(&genuine, &joiner.id(), 150).is_ok());
    }
}

/// Review follow-up: the owner removes a stolen phone that wrote nothing, while another
/// approver adds a device. The removal must win, even though it leaves fewer approvers.
#[test]
fn a_removal_is_never_dropped_for_a_branch_that_removes_less() {
    let founder = Identity::generate();
    let laptop = Identity::generate();
    let stolen = Identity::generate();
    let mut base = DeviceLog::create(&founder, "G", "PC", 1).unwrap();
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
            device: stolen.id(),
            name: "Phone".into(),
            approver: true,
        },
        3,
    )
    .unwrap();
    let mut removal = base.clone();
    removal
        .append(
            &founder,
            Op::Remove {
                device: stolen.id(),
            },
            4,
        )
        .unwrap();
    let mut addition = base.clone();
    let d = Identity::generate();
    addition
        .append(
            &laptop,
            Op::Add {
                device: d.id(),
                name: "Tablet".into(),
                approver: false,
            },
            4,
        )
        .unwrap();
    assert_eq!(removal.prefer(&addition), Ok(Preferred::Ours));
    assert_eq!(addition.prefer(&removal), Ok(Preferred::Theirs));
}

/// Builds a random valid branch on top of `base`, written by the given approvers.
fn random_branch(base: &DeviceLog, authors: &[&Identity], plan: &[(u8, u8)]) -> DeviceLog {
    let mut log = base.clone();
    for (i, (who, what)) in plan.iter().enumerate() {
        let author = authors[*who as usize % authors.len()];
        let m = log.verify().unwrap();
        let op = if what % 2 == 0 {
            let d = Identity::generate();
            Op::Add {
                device: d.id(),
                name: format!("N{}x{}", i, what),
                approver: what % 4 == 0,
            }
        } else {
            let others: Vec<_> = m
                .members
                .keys()
                .filter(|k| **k != author.id())
                .copied()
                .collect();
            if others.is_empty() {
                continue;
            }
            Op::Remove {
                device: others[*what as usize % others.len()],
            }
        };
        let _ = log.append(author, op, 10 + i as u64); // invalid ops are simply skipped
    }
    log
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// The choice is the same from both sides, whatever the branches contain, so every
    /// device and the server converge.
    #[test]
    fn fork_choice_is_antisymmetric(
        a in prop::collection::vec((0u8..3, 0u8..8), 0..4),
        b in prop::collection::vec((0u8..3, 0u8..8), 0..4),
    ) {
        let founder = Identity::generate();
        let x = Identity::generate();
        let y = Identity::generate();
        let mut base = DeviceLog::create(&founder, "G", "PC", 1).unwrap();
        base.append(&founder, Op::Add { device: x.id(), name: "X".into(), approver: true }, 2).unwrap();
        base.append(&founder, Op::Add { device: y.id(), name: "Y".into(), approver: true }, 3).unwrap();
        let authors = [&founder, &x, &y];
        let la = random_branch(&base, &authors, &a);
        let lb = random_branch(&base, &authors, &b);
        let ab = la.prefer(&lb).unwrap();
        let ba = lb.prefer(&la).unwrap();
        match ab {
            Preferred::Same => prop_assert_eq!(ba, Preferred::Same),
            Preferred::Ours => prop_assert_eq!(ba, Preferred::Theirs),
            Preferred::Theirs => prop_assert_eq!(ba, Preferred::Ours),
        }
        if ab == Preferred::Same {
            prop_assert_eq!(la, lb);
        }
    }
}
