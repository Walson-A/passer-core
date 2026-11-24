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
        let outgoing = Arc::new(outgoing);

        // Caller to stdin. Ends when the caller is done (stdin closes) or the stream breaks.
        let to_child = async move {
            while let Ok(Some(bytes)) = incoming.next().await {
                if stdin.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            drop(stdin);
        };
        // stdout to caller, until the command closes it.
        let from_child = async {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if outgoing.send(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        };
        // The command's output decides when it is over; the input side may stop earlier.
        let input = tokio::spawn(to_child);
        from_child.await;
        input.abort();
        let status = child.wait().await.map_err(failed)?;
        Ok(json!({ "exit": status.code() }))
    }
}

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
