//! Two devices in one process, through the same API the phone and desktop apps use:
//! a group, an invitation, a call, and a file sent with progress.
//!
//! ```text
//! cargo run -p passer-ffi --example two_devices
//! ```
//!
//! In an app, each device runs on its own machine; the invitation link travels as a QR
//! code, and the two screens show the same 6-digit code to compare.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use passer_ffi::{
    ApprovalInfo, ApprovalPrompter, CallerInfo, CapabilityHandler, CapabilitySpec, DeviceKind,
    EffectKind, KeyVault, NetworkKind, PasserDevice, PasserError, StreamKind, TransferProgress,
};

/// Where the device key lives. An app uses the Keychain or the Android Keystore.
#[derive(Default)]
struct MemoryVault(Mutex<Option<Vec<u8>>>);

impl KeyVault for MemoryVault {
    fn load(&self) -> Option<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
    fn store(&self, secret: Vec<u8>) -> Result<(), PasserError> {
        *self.0.lock().unwrap() = Some(secret);
        Ok(())
    }
}

/// The user's answer to approval requests. An app shows a sheet or a notification.
struct AlwaysYes;

#[async_trait]
impl ApprovalPrompter for AlwaysYes {
    async fn ask(&self, request: ApprovalInfo) -> bool {
        println!(
            "[PC] {} asks: {} (for {} min) -> allowed",
            request.requester_name, request.title, request.duration_minutes
        );
        true
    }
}

/// What the PC does for the others: a greeting, and an inbox for files.
struct PcCapabilities {
    inbox: std::path::PathBuf,
}

#[async_trait]
impl CapabilityHandler for PcCapabilities {
    async fn invoke(
        &self,
        _capability: String,
        _target: Option<String>,
        _input_json: String,
        caller: CallerInfo,
    ) -> Result<String, PasserError> {
        Ok(format!(r#"{{"greeting":"hello {}"}}"#, caller.device_name))
    }

    async fn receive_file(
        &self,
        _capability: String,
        _target: Option<String>,
        input_json: String,
        _caller: CallerInfo,
        path: String,
    ) -> Result<String, PasserError> {
        let input: serde_json::Value = serde_json::from_str(&input_json).unwrap_or_default();
        let name = input["name"].as_str().unwrap_or("file");
        let dest = self.inbox.join(name);
        std::fs::rename(&path, &dest).map_err(|e| PasserError::Storage {
            message: e.to_string(),
        })?;
        Ok(format!(r#"{{"saved":"{}"}}"#, dest.display()).replace('\\', "/"))
    }

    async fn provide_file(
        &self,
        _: String,
        _: Option<String>,
        _: String,
        _: CallerInfo,
    ) -> Result<String, PasserError> {
        Err(PasserError::Invalid {
            message: "nothing to download here".into(),
        })
    }
}

struct Bar;

impl TransferProgress for Bar {
    fn progress(&self, done: u64, total: Option<u64>) {
        println!("[phone] sent {done} of {} bytes", total.unwrap_or(0));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let home = |name: &str| dir.path().join(name).to_string_lossy().into_owned();

    // The PC: creates the group, declares what it offers, starts.
    let pc = PasserDevice::new(home("pc"), Arc::new(MemoryVault::default()))?;
    pc.set_device_details(DeviceKind::Laptop, None, Some("example".into()));
    pc.create_group("Home".into(), "PC".into())?;
    let spec = |name: &str, effect, stream| CapabilitySpec {
        name: name.into(),
        title: name.into(),
        description: name.into(),
        input_schema_json: r#"{"type":"object"}"#.into(),
        effect,
        target_kind: None,
        indicator_required: false,
        stream,
        max_bytes: None,
    };
    let inbox = dir.path().join("inbox");
    std::fs::create_dir_all(&inbox)?;
    pc.add_capabilities(
        vec![
            spec("hello.say", EffectKind::Sensitive, None),
            spec("inbox.put", EffectKind::Write, Some(StreamKind::Upload)),
        ],
        Arc::new(PcCapabilities { inbox }),
    );
    pc.set_approval_prompter(Arc::new(AlwaysYes));
    pc.start(NetworkKind::LocalOnly, None).await?;

    // The phone scans the PC's QR code.
    let link = pc.invite(5, false).await?.link;
    let phone = PasserDevice::new(home("phone"), Arc::new(MemoryVault::default()))?;
    phone.set_device_details(DeviceKind::Phone, Some("18.2".into()), None);
    let joined = phone
        .join(link, "iPhone".into(), NetworkKind::LocalOnly)
        .await?;
    println!(
        "[phone] joined {:?}; both screens show {}",
        joined.group_name, joined.sas
    );
    phone.start(NetworkKind::LocalOnly, None).await?;
    // On one machine, tell the phone where the PC listens (a coordination server does
    // this across networks).
    phone
        .add_peer_address("PC".into(), pc.addresses().await?.remove(0))
        .await?;

    // A sensitive call: the PC's user approves it first.
    let answer = phone
        .call("PC".into(), "hello.say".into(), "{}".into())
        .await?;
    println!("[phone] PC answered {answer}");

    // A file, with progress.
    let file = dir.path().join("photo.jpg");
    std::fs::write(&file, vec![42u8; 3 * 1024 * 1024])?;
    let saved = phone
        .send_file(
            "PC".into(),
            "inbox.put".into(),
            r#"{"name":"photo.jpg"}"#.into(),
            file.to_string_lossy().into_owned(),
            Some(Arc::new(Bar)),
        )
        .await?;
    println!("[phone] PC answered {saved}");

    // What the phone knows about the PC, and its history with it.
    phone.refresh_members().await?;
    for m in phone.members()? {
        println!(
            "[phone] member {} ({:?}){}",
            m.name,
            m.kind,
            if m.this_device { ", this device" } else { "" }
        );
    }
    for line in phone.journal_recent(10, Some("PC".into())).await? {
        println!(
            "[phone] journal: {} {} -> {}",
            if line.outgoing {
                "called"
            } else {
                "was called"
            },
            line.capability,
            line.outcome
        );
    }

    phone.stop().await;
    pc.stop().await;
    Ok(())
}
