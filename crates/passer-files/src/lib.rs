//! Files between devices: a ready-made module built on streams.
//!
//! - `file.drop` (write): the caller sends a file, saved into this device's inbox folder
//!   under its base name, never overwriting (`photo (1).jpg`).
//! - `file.get` (read): the caller gets a file from this device's shared folder, by name.
//!   Only files directly in that folder: no paths, no links leading out of it.
//!
//! The bus decides who may call them (by default member devices may, agents may not), and
//! journals every transfer without its content. A transfer that breaks leaves nothing
//! behind: the inbox only ever holds complete files.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use passer_bus::{Capability, Ctx, Effect, Manifest, Mode, Module, ModuleError, StreamIo};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const DROP: &str = "file.drop";
pub const GET: &str = "file.get";

/// Largest file `file.drop` accepts unless told otherwise.
pub const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Longest file name kept, in bytes.
const MAX_NAME: usize = 200;

/// The module. Without an inbox, `file.drop` is not offered; without a shared folder,
/// `file.get` is not.
pub struct Files {
    inbox: Option<PathBuf>,
    shared: Option<PathBuf>,
    max_bytes: u64,
}

impl Files {
    pub fn new() -> Self {
        Self {
            inbox: None,
            shared: None,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }

    /// Where received files go.
    pub fn inbox(mut self, dir: impl Into<PathBuf>) -> Self {
        self.inbox = Some(dir.into());
        self
    }

    /// The folder other devices may get files from.
    pub fn shared(mut self, dir: impl Into<PathBuf>) -> Self {
        self.shared = Some(dir.into());
        self
    }

    pub fn max_bytes(mut self, max: u64) -> Self {
        self.max_bytes = max;
        self
    }
}

impl Default for Files {
    fn default() -> Self {
        Self::new()
    }
}

fn name_schema() -> Value {
    json!({
        "type": "object",
        "properties": { "name": { "type": "string", "minLength": 1, "maxLength": 255 } },
        "required": ["name"],
        "additionalProperties": false
    })
}

fn stream(name: &str, title: &str, description: &str, effect: Effect) -> Capability {
    let mut cap = Capability::call(name, title, description, effect, name_schema());
    cap.mode = Mode::Stream;
    cap
}

/// A file name another device sent, made safe to use in one folder: its last path
/// component, without control or reserved characters, not `.` or `..`, bounded.
/// `None` if nothing usable is left.
pub fn safe_name(raw: &str) -> Option<String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let mut name: String = base
        .chars()
        .map(|c| {
            if c.is_control() || passer_bus::is_format_char(c) || "<>:\"|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    // Windows ignores trailing dots and spaces; leading dots would hide the file.
    name = name.trim_matches(|c: char| c == ' ' || c == '.').to_owned();
    while name.len() > MAX_NAME {
        name.pop();
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    if name.is_empty() || reserved {
        None
    } else {
        Some(name)
    }
}

/// `name`, or `name (1).ext`, `name (2).ext`... whichever does not exist yet.
fn free_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (1..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .expect("an unused name exists")
}

fn requested_name(input: &Value) -> Result<String, ModuleError> {
    let raw = input["name"].as_str().unwrap_or("");
    safe_name(raw).ok_or_else(|| ModuleError::InvalidInput("unusable file name".into()))
}

fn failed(e: impl std::fmt::Display) -> ModuleError {
    ModuleError::Failed(e.to_string())
}

impl Files {
    async fn receive(&self, input: Value, io: StreamIo) -> Result<Value, ModuleError> {
        let inbox = self
            .inbox
            .as_ref()
            .ok_or_else(|| ModuleError::Unsupported(DROP.into()))?;
        let name = requested_name(&input)?;
        tokio::fs::create_dir_all(inbox).await.map_err(failed)?;
        // Received under a hidden temporary name, renamed once complete.
        let part = inbox.join(format!(".{name}.{}.part", std::process::id()));
        let StreamIo { mut incoming, .. } = io;
        let written = async {
            let mut file = tokio::fs::File::create(&part).await.map_err(failed)?;
            let mut size = 0u64;
            loop {
                match incoming.next().await {
                    Ok(Some(bytes)) => {
                        size += bytes.len() as u64;
                        if size > self.max_bytes {
                            return Err(ModuleError::InvalidInput(format!(
                                "the file is larger than {} bytes",
                                self.max_bytes
                            )));
                        }
                        file.write_all(&bytes).await.map_err(failed)?;
                    }
                    Ok(None) => break,
                    Err(e) => return Err(failed(e)),
                }
            }
            file.flush().await.map_err(failed)?;
            Ok(size)
        }
        .await;
        let size = match written {
            Ok(size) => size,
            Err(e) => {
                let _ = tokio::fs::remove_file(&part).await;
                return Err(e);
            }
        };
        let path = free_path(inbox, &name);
        if let Err(e) = tokio::fs::rename(&part, &path).await {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(failed(e));
        }
        let saved = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or(name);
        Ok(json!({ "name": saved, "bytes": size }))
    }

    async fn send(&self, input: Value, io: StreamIo) -> Result<Value, ModuleError> {
        let shared = self
            .shared
            .as_ref()
            .ok_or_else(|| ModuleError::Unsupported(GET.into()))?;
        let name = requested_name(&input)?;
        // The real location must still be inside the shared folder (no link out of it).
        let root = tokio::fs::canonicalize(shared).await.map_err(failed)?;
        let path = tokio::fs::canonicalize(shared.join(&name))
            .await
            .map_err(|_| ModuleError::InvalidInput("no such file".into()))?;
        if path.parent() != Some(root.as_path()) || !path.is_file() {
            return Err(ModuleError::InvalidInput("no such file".into()));
        }
        let mut file = tokio::fs::File::open(&path).await.map_err(failed)?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut sent = 0u64;
        loop {
            let n = file.read(&mut buf).await.map_err(failed)?;
            if n == 0 {
                break;
            }
            io.outgoing.send(&buf[..n]).await.map_err(failed)?;
            sent += n as u64;
        }
        Ok(json!({ "name": name, "bytes": sent }))
    }
}

#[async_trait]
impl Module for Files {
    fn manifest(&self) -> Manifest {
        let mut capabilities = Vec::new();
        if self.inbox.is_some() {
            capabilities.push(stream(
                DROP,
                "Send a file",
                "Saves the file you send into this device's inbox folder, under its name \
                 (never overwriting). Input: the file name.",
                Effect::Write,
            ));
        }
        if self.shared.is_some() {
            capabilities.push(stream(
                GET,
                "Get a shared file",
                "Sends back a file from this device's shared folder, by name.",
                Effect::Read,
            ));
        }
        Manifest {
            module: "files".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            capabilities,
        }
    }

    async fn invoke(&self, _: Ctx, capability: &str, _: Value) -> Result<Value, ModuleError> {
        Err(ModuleError::Unsupported(format!(
            "`{capability}` is a stream"
        )))
    }

    async fn invoke_stream(
        &self,
        _ctx: Ctx,
        capability: &str,
        input: Value,
        io: StreamIo,
    ) -> Result<Value, ModuleError> {
        match capability {
            DROP => self.receive(input, io).await,
            GET => self.send(input, io).await,
            other => Err(ModuleError::Unsupported(other.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_stay_in_their_folder() {
        assert_eq!(safe_name("photo.jpg").as_deref(), Some("photo.jpg"));
        assert_eq!(safe_name("../../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(
            safe_name("C:\\Windows\\win.ini").as_deref(),
            Some("win.ini")
        );
        assert_eq!(safe_name("..").as_deref(), None);
        assert_eq!(safe_name("").as_deref(), None);
        assert_eq!(safe_name("CON.txt").as_deref(), None);
        assert_eq!(safe_name("com1").as_deref(), None);
        assert_eq!(safe_name(" .hidden. ").as_deref(), Some("hidden"));
        assert_eq!(safe_name("a\u{202E}gpj.exe").as_deref(), Some("a_gpj.exe"));
        assert_eq!(safe_name("what?.txt").as_deref(), Some("what_.txt"));
        assert!(safe_name(&"x".repeat(500)).unwrap().len() <= MAX_NAME);
    }

    #[test]
    fn existing_files_are_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"1").unwrap();
        std::fs::write(dir.path().join("a (1).txt"), b"2").unwrap();
        assert_eq!(free_path(dir.path(), "a.txt"), dir.path().join("a (2).txt"));
        assert_eq!(free_path(dir.path(), "b"), dir.path().join("b"));
    }
}
