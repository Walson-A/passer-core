//! The local journal: one line per invocation, chained by hash so that a deleted or
//! edited line shows. It records who asked for what and what happened, **never the
//! content** (no inputs, no outputs).
//!
//! Most lines are calls this device received (`device` is the requester). A line with
//! `to` is a call this device made to that member.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// How many records are kept in memory for quick display.
const RECENT: usize = 200;

/// What gets written, without its own hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Position in the chain, from 0.
    pub seq: u64,
    /// When it was written, in seconds since the Unix epoch.
    pub at: u64,
    /// The requester; on calls this device made, this device.
    pub device: String,
    /// Set on calls this device made: the member it called. Absent on received calls,
    /// so lines written before this field existed keep their hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// The AI agent the request came through, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Capability name, as requested.
    pub capability: String,
    /// Target, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `allow`, `ask` or `deny`, before any approval.
    pub decision: String,
    /// Set when a human was asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    /// `ok` or an error code.
    pub outcome: String,
    /// Hash of the previous line (all zeros for the first).
    pub prev: String,
}

/// A record and its hash, as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Line {
    /// What was recorded.
    #[serde(flatten)]
    pub record: Record,
    /// BLAKE3 hash of the record, in hex. The next line's `prev`.
    pub hash: String,
}

/// Fields the bus fills in; the journal adds sequence, time and chaining.
#[derive(Clone, Debug, Default)]
pub struct Event {
    /// The requester; on calls this device made, this device.
    pub device: String,
    /// The member called, on calls this device made.
    pub to: Option<String>,
    /// The AI agent the request came through, if any.
    pub agent: Option<String>,
    /// Capability name.
    pub capability: String,
    /// Target, if any.
    pub target: Option<String>,
    /// `allow`, `ask`, `deny`, or `none` when no policy check ran.
    pub decision: String,
    /// Set when a human was asked: their answer.
    pub approved: Option<bool>,
    /// `ok` or an error code.
    pub outcome: String,
}

/// Why the journal could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// Reading or writing the file failed.
    #[error("journal I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A line is not a valid [`Line`]. The number is its position, from 0.
    #[error("journal line {0} is malformed")]
    Malformed(u64),
    /// A line does not follow from the one before (sequence, `prev` or hash): a line was
    /// edited or removed. The number is its position, from 0.
    #[error("journal line {0} breaks the chain: a line was edited or removed")]
    Broken(u64),
}

struct Inner {
    file: Option<File>,
    head: String,
    seq: u64,
    recent: VecDeque<Line>,
}

/// Append-only, hash-chained journal, optionally backed by a JSON-lines file.
pub struct Journal {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn hash_record(r: &Record) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"passer-core/journal/v1");
    h.update(&serde_json::to_vec(r).expect("record serializes"));
    h.finalize().to_hex().to_string()
}

impl Journal {
    /// A journal kept only in memory: nothing survives the process.
    pub fn in_memory() -> Self {
        Self {
            path: None,
            inner: Mutex::new(Inner {
                file: None,
                head: GENESIS.into(),
                seq: 0,
                recent: VecDeque::new(),
            }),
        }
    }

    /// Opens (or creates) a journal file, verifying the existing chain first.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let path = path.into();
        let (head, seq, recent) = match File::open(&path) {
            Ok(f) => Self::read_chain(f)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                (GENESIS.to_owned(), 0, VecDeque::new())
            }
            Err(e) => return Err(e.into()),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(Inner {
                file: Some(file),
                head,
                seq,
                recent,
            }),
        })
    }

    /// Verifies a journal file; returns how many lines it holds.
    pub fn verify_file(path: &Path) -> Result<u64, JournalError> {
        Self::read_chain(File::open(path)?).map(|(_, n, _)| n)
    }

    fn read_chain(f: File) -> Result<(String, u64, VecDeque<Line>), JournalError> {
        let mut head = GENESIS.to_owned();
        let mut n = 0u64;
        let mut recent = VecDeque::new();
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let parsed: Line =
                serde_json::from_str(&line).map_err(|_| JournalError::Malformed(n))?;
            if parsed.record.seq != n
                || parsed.record.prev != head
                || hash_record(&parsed.record) != parsed.hash
            {
                return Err(JournalError::Broken(n));
            }
            head = parsed.hash.clone();
            n += 1;
            recent.push_back(parsed);
            if recent.len() > RECENT {
                recent.pop_front();
            }
        }
        Ok((head, n, recent))
    }

    /// The file behind the journal, `None` when in memory.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Adds one line for `event`, chained to the previous one, and writes it to the file if any.
    pub fn append(&self, event: Event) -> Result<Line, JournalError> {
        let mut inner = self.inner.lock().expect("journal lock");
        let record = Record {
            seq: inner.seq,
            at: now_secs(),
            device: event.device,
            to: event.to,
            agent: event.agent,
            capability: event.capability,
            target: event.target,
            decision: event.decision,
            approved: event.approved,
            outcome: event.outcome,
            prev: inner.head.clone(),
        };
        let line = Line {
            hash: hash_record(&record),
            record,
        };
        if let Some(file) = inner.file.as_mut() {
            let mut bytes = serde_json::to_vec(&line).expect("line serializes");
            bytes.push(b'\n');
            file.write_all(&bytes)?;
            file.flush()?;
        }
        inner.head = line.hash.clone();
        inner.seq += 1;
        inner.recent.push_back(line.clone());
        if inner.recent.len() > RECENT {
            inner.recent.pop_front();
        }
        Ok(line)
    }

    /// The most recent lines, newest last.
    pub fn recent(&self) -> Vec<Line> {
        self.inner
            .lock()
            .expect("journal lock")
            .recent
            .iter()
            .cloned()
            .collect()
    }
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(cap: &str) -> Event {
        Event {
            device: "dev".into(),
            capability: cap.into(),
            decision: "allow".into(),
            outcome: "ok".into(),
            ..Default::default()
        }
    }

    #[test]
    fn lines_without_to_keep_their_hash() {
        // A line written before `to` existed: its JSON has no `to` key.
        let r = Record {
            seq: 0,
            at: 1,
            device: "dev".into(),
            to: None,
            agent: None,
            capability: "a.one".into(),
            target: None,
            decision: "allow".into(),
            approved: None,
            outcome: "ok".into(),
            prev: GENESIS.into(),
        };
        assert!(!serde_json::to_string(&r).unwrap().contains("\"to\""));
        let out = Record {
            to: Some("peer".into()),
            ..r.clone()
        };
        assert_ne!(hash_record(&r), hash_record(&out));
    }

    #[test]
    fn file_journal_survives_reopen_and_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.jsonl");
        {
            let j = Journal::open(&path).unwrap();
            j.append(ev("a.one")).unwrap();
            j.append(ev("a.two")).unwrap();
        }
        let j = Journal::open(&path).unwrap();
        j.append(ev("a.three")).unwrap();
        assert_eq!(Journal::verify_file(&path).unwrap(), 3);
        assert_eq!(j.recent().len(), 3);

        // Delete the middle line: the chain breaks there.
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(matches!(
            Journal::verify_file(&path),
            Err(JournalError::Broken(1))
        ));

        // Edit a field: the hash no longer matches.
        std::fs::write(&path, text.replace("a.one", "a.won")).unwrap();
        assert!(matches!(
            Journal::verify_file(&path),
            Err(JournalError::Broken(0))
        ));
        assert!(
            Journal::open(&path).is_err(),
            "a broken journal is not silently extended"
        );
    }
}
