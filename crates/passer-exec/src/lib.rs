//! A stream capability that runs a command, with its stdin and stdout wired to the
//! stream: what the caller sends goes to the command's stdin, what the command writes on
//! stdout goes back to the caller.
//!
//! It exists for helpers such as a screen-sharing tool (`vasistas share`), which speak
//! their own protocol over stdio. The safety rules:
//!
//! - **The host fixes the command and its arguments.** The caller cannot change them; its
//!   JSON input is not passed to the command at all.
//! - The only values filled in are **placeholders the core knows for certain**:
//!   `{caller_name}` (the caller's name in the group) and `{caller_id}` (its key, hex).
//!   No shell is involved: each argument reaches the program as one argv entry. A caller
//!   whose name starts with `-` is refused, so it cannot pass for an option.
//! - **The command dies with the session**: when the lease ends (stop button, device
//!   removed, expiry) the bus drops the invocation and the process is killed.
//! - The host chooses the effect and whether an indicator is required; for anything that
//!   shows or controls the device, declare it `Sensitive` with an indicator.

#![warn(missing_docs)]

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use passer_bus::{
    Capability, Ctx, Effect, IndicatorRequirement, Manifest, Mode, Module, ModuleError, StreamIo,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Finds a member's name in the group from its id (hex), as the host's membership says.
/// `None`: not a member (the bus refuses those first; this is a safety net).
pub type NameLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// One command offered as a stream capability.
#[derive(Clone, Debug)]
pub struct Command {
    /// Capability name, e.g. `screen.view`.
    pub name: String,
    /// Short human title, shown in approvals.
    pub title: String,
    /// What it does, in a sentence.
    pub description: String,
    /// What it does to the device; sets who may call it by default.
    pub effect: Effect,
    /// Whether the device must show a visible indicator while it runs.
    pub indicator: bool,
    /// The program to run.
    pub program: PathBuf,
    /// Its arguments; `{caller_name}` and `{caller_id}` are filled in.
    pub args: Vec<String>,
}

/// The module: a set of [`Command`]s.
pub struct Exec {
    commands: Vec<Command>,
    names: NameLookup,
}

impl Exec {
    /// `names` gives the caller's name for `{caller_name}`.
    pub fn new(commands: Vec<Command>, names: NameLookup) -> Self {
        Self { commands, names }
    }
}

fn failed(e: impl std::fmt::Display) -> ModuleError {
    ModuleError::Failed(e.to_string())
}

/// The arguments with the placeholders filled in.
pub fn fill(args: &[String], caller_name: &str, caller_id: &str) -> Vec<String> {
    args.iter()
        .map(|a| {
            a.replace("{caller_name}", caller_name)
                .replace("{caller_id}", caller_id)
        })
        .collect()
}

#[async_trait]
impl Module for Exec {
    fn manifest(&self) -> Manifest {
        let capabilities = self
            .commands
            .iter()
            .map(|c| {
                let mut cap = Capability::call(
                    &c.name,
                    &c.title,
                    &c.description,
                    c.effect,
                    json!({ "type": "object", "additionalProperties": false }),
                );
                cap.mode = Mode::Stream;
                if c.indicator {
                    cap.indicator = IndicatorRequirement::Required;
                }
                cap
            })
            .collect();
        Manifest {
            module: "exec".into(),
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
        ctx: Ctx,
        capability: &str,
        _input: Value,
        io: StreamIo,
    ) -> Result<Value, ModuleError> {
        let command = self
            .commands
            .iter()
            .find(|c| c.name == capability)
            .ok_or_else(|| ModuleError::Unsupported(capability.to_owned()))?;
        let caller_id = ctx.subject.device.to_string();
        let caller_name = (self.names)(&caller_id)
            .ok_or_else(|| ModuleError::Failed("the caller is not a member".into()))?;
        if caller_name.starts_with('-') {
            return Err(ModuleError::InvalidInput(
                "a device whose name starts with '-' cannot run commands".into(),
            ));
        }

        let mut process = tokio::process::Command::new(&command.program);
        process
            .args(fill(&command.args, &caller_name, &caller_id))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            // Killed when the invocation is dropped: the lease ended.
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            // No console window flashing up from a desktop app.
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            process.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = process
            .spawn()
            .map_err(|e| failed(format!("cannot start {}: {e}", command.program.display())))?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let StreamIo {
            mut incoming,
            outgoing,
        } = io;

        // Caller to stdin. Returns when the caller is done (stdin then closes, which
        // tells the command) or the stream broke (the caller vanished).
        let mut to_child = Box::pin(async move {
            loop {
                match incoming.next().await {
                    Ok(Some(bytes)) => {
                        if stdin.write_all(&bytes).await.is_err() {
                            return Input::Done;
                        }
                    }
                    Ok(None) => return Input::Done,
                    Err(_) => return Input::Broken,
                }
            }
        });
        // stdout to caller. `true`: the command closed it; `false`: the caller is gone.
        let mut from_child = Box::pin(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) | Err(_) => return true,
                    Ok(n) => {
                        if outgoing.send(&buf[..n]).await.is_err() {
                            return false;
                        }
                    }
                }
            }
        });

        // Whichever side ends first decides. A caller that left cleanly gives the
        // command a moment to finish on its own; a caller that vanished, or a command
        // that does not finish in time, gets it killed: never wait on it forever, or the
        // session (and the indicator saying someone is there) would never end.
        let mut grace: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
        let kill = loop {
            tokio::select! {
                input = &mut to_child, if grace.is_none() => match input {
                    Input::Done => grace = Some(Box::pin(tokio::time::sleep(GRACE))),
                    Input::Broken => break true,
                },
                closed = &mut from_child => break !closed,
                _ = async { grace.as_mut().expect("guarded").await }, if grace.is_some() => {
                    break true;
                }
            }
        };
        // Closes both pipes: a command blocked writing to us is released.
        drop(to_child);
        drop(from_child);
        if kill {
            let _ = child.start_kill();
        }
        let status = match tokio::time::timeout(GRACE, child.wait()).await {
            Ok(status) => status.map_err(failed)?,
            Err(_) => {
                let _ = child.start_kill();
                child.wait().await.map_err(failed)?
            }
        };
        Ok(json!({ "exit": status.code() }))
    }
}

/// How the caller's side ended.
enum Input {
    /// It finished sending.
    Done,
    /// The stream broke: the caller is gone.
    Broken,
}

/// How long a command gets to finish once its caller is done, before it is killed.
const GRACE: std::time::Duration = std::time::Duration::from_secs(3);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_filled_and_nothing_else() {
        let args = vec![
            "share".to_owned(),
            "--viewer={caller_name}".to_owned(),
            "{caller_id}".to_owned(),
            "{other}".to_owned(),
        ];
        assert_eq!(
            fill(&args, "iPhone", "abc"),
            vec!["share", "--viewer=iPhone", "abc", "{other}"]
        );
    }
}
