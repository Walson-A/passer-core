//! The app-facing API, driven the way Swift or Kotlin would drive it: callbacks for the
//! key vault, the approval prompt and the app's own capabilities.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use passer_ffi::{
    ApprovalInfo, ApprovalPrompter, CallerInfo, CapabilityHandler, CapabilitySpec, EffectKind,
    KeyVault, NetworkKind, PasserDevice, PasserError,
};

/// Stands in for the Keychain / Keystore.
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

/// Stands in for a native approval sheet.
struct Sheet(bool, Mutex<Vec<ApprovalInfo>>);

#[async_trait]
impl ApprovalPrompter for Sheet {
    async fn ask(&self, request: ApprovalInfo) -> bool {
        self.1.lock().unwrap().push(request);
        self.0
    }
}

/// Stands in for the app's clipboard code.
struct Clipboard(Mutex<Vec<CallerInfo>>);

#[async_trait]
impl CapabilityHandler for Clipboard {
    async fn invoke(
        &self,
        capability: String,
        _target: Option<String>,
        input_json: String,
        caller: CallerInfo,
    ) -> Result<String, PasserError> {
        assert_eq!(capability, "clipboard.read");
        assert_eq!(input_json, "{}");
        self.0.lock().unwrap().push(caller);
        Ok(r#"{"text":"hello from the PC"}"#.into())
    }

    async fn receive_file(
        &self,
        _: String,
        _: Option<String>,
        _: String,
        _: CallerInfo,
        _: String,
    ) -> Result<String, PasserError> {
        unreachable!("no upload capability here")
    }

    async fn provide_file(
        &self,
        _: String,
        _: Option<String>,
        _: String,
        _: CallerInfo,
    ) -> Result<String, PasserError> {
        unreachable!("no download capability here")
    }
}

fn clipboard_spec() -> CapabilitySpec {
    CapabilitySpec {
        name: "clipboard.read".into(),
        title: "Read the clipboard".into(),
        description: "Returns the text currently copied on this device.".into(),
        input_schema_json: r#"{"type":"object","additionalProperties":false}"#.into(),
        effect: EffectKind::Sensitive,
        target_kind: None,
        indicator_required: false,
        stream: None,
        max_bytes: None,
    }
}

fn device(dir: &tempfile::TempDir, name: &str, vault: Arc<MemoryVault>) -> Arc<PasserDevice> {
    PasserDevice::new(dir.path().join(name).to_string_lossy().into(), vault).unwrap()
}

#[tokio::test]
async fn the_vault_keeps_the_identity() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(MemoryVault::default());
    let first = device(&dir, "pc", vault.clone()).device_id();
    let again = device(&dir, "pc", vault.clone()).device_id();
    assert_eq!(first, again);
    assert_eq!(vault.0.lock().unwrap().as_ref().unwrap().len(), 32);
}

#[tokio::test]
async fn phone_joins_and_reads_the_pc_clipboard_after_approval() {
    let dir = tempfile::tempdir().unwrap();

    // The PC: creates the group, implements clipboard.read, asks its user.
    let pc = device(&dir, "pc", Arc::default());
    pc.create_group("Walson".into(), "PC".into()).unwrap();
    let clipboard = Arc::new(Clipboard(Mutex::default()));
    pc.add_capabilities(vec![clipboard_spec()], clipboard.clone());
    let sheet = Arc::new(Sheet(true, Mutex::default()));
    pc.set_approval_prompter(sheet.clone());
    pc.start(NetworkKind::LocalOnly, None).await.unwrap();

    // The phone scans the QR code.
    let invite = pc.invite(5, false).await.unwrap();
    let phone = device(&dir, "phone", Arc::default());
    assert!(matches!(phone.members(), Err(PasserError::NoGroup)));
    let joined = phone
        .join(invite.link, "iPhone".into(), NetworkKind::LocalOnly)
        .await
        .unwrap();
    assert_eq!(joined.group_name, "Walson");
    assert_eq!(joined.sas.len(), 6);
    phone.start(NetworkKind::LocalOnly, None).await.unwrap();
    let pc_addr = pc.addresses().await.unwrap().remove(0);
    phone.add_peer_address("PC".into(), pc_addr).await.unwrap();

    let members = phone.members().unwrap();
    assert_eq!(members.len(), 2);
    assert!(
        members
            .iter()
            .any(|m| m.name == "iPhone" && m.this_device && !m.approver)
    );

    // A plain read works without asking.
    let info = phone
        .call("PC".into(), "device.info".into(), String::new())
        .await
        .unwrap();
    assert!(info.contains("\"name\":\"PC\""));

    // A sensitive read asks the PC's user first, then runs the app's handler.
    let text = phone
        .call("PC".into(), "clipboard.read".into(), "{}".into())
        .await
        .unwrap();
    assert_eq!(text, r#"{"text":"hello from the PC"}"#);
    let asked = sheet.1.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].requester_name, "iPhone");
    assert_eq!(asked[0].title, "Read the clipboard");
    let callers = clipboard.0.lock().unwrap().clone();
    assert_eq!(callers[0].device_name, "iPhone");
    assert_eq!(callers[0].agent, None);

    pc.stop().await;
    phone.stop().await;
}

#[tokio::test]
async fn a_refusal_reaches_the_app_as_a_typed_error() {
    let dir = tempfile::tempdir().unwrap();
    let pc = device(&dir, "pc", Arc::default());
    pc.create_group("Walson".into(), "PC".into()).unwrap();
    pc.add_capabilities(
        vec![clipboard_spec()],
        Arc::new(Clipboard(Mutex::default())),
    );
    pc.set_approval_prompter(Arc::new(Sheet(false, Mutex::default())));
    pc.start(NetworkKind::LocalOnly, None).await.unwrap();

    let invite = pc.invite(5, false).await.unwrap();
    let phone = device(&dir, "phone", Arc::default());
    phone
        .join(invite.link, "iPhone".into(), NetworkKind::LocalOnly)
        .await
        .unwrap();
    phone.start(NetworkKind::LocalOnly, None).await.unwrap();
    phone
        .add_peer_address("PC".into(), pc.addresses().await.unwrap().remove(0))
        .await
        .unwrap();

    match phone
        .call("PC".into(), "clipboard.read".into(), "{}".into())
        .await
    {
        Err(PasserError::Refused { code, .. }) => assert_eq!(code, "denied"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(matches!(
        phone
            .call("Nobody".into(), "device.info".into(), String::new())
            .await,
        Err(PasserError::Invalid { .. })
    ));
    pc.stop().await;
    phone.stop().await;
}

#[tokio::test]
async fn calls_before_start_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pc = device(&dir, "pc", Arc::default());
    pc.create_group("Walson".into(), "PC".into()).unwrap();
    assert!(matches!(
        pc.invite(5, false).await,
        Err(PasserError::NotStarted)
    ));
    assert!(matches!(
        pc.create_group("Again".into(), "PC".into()),
        Err(PasserError::AlreadyInGroup)
    ));
}

struct Admissions(Mutex<Vec<(String, String)>>);

impl passer_ffi::AdmissionListener for Admissions {
    fn admitted(&self, _device_id: String, device_name: String, sas: String) {
        self.0.lock().unwrap().push((device_name, sas));
    }
}

#[tokio::test]
async fn the_inviting_app_is_told_who_joined_with_the_same_code() {
    let dir = tempfile::tempdir().unwrap();
    let pc = PasserDevice::open_on_desktop(dir.path().join("pc")).unwrap();
    pc.create_group("Walson".into(), "PC".into()).unwrap();
    let seen = Arc::new(Admissions(Mutex::default()));
    pc.set_admission_listener(seen.clone());
    pc.start(NetworkKind::LocalOnly, None).await.unwrap();
    assert!(pc.is_running().await);
    assert_eq!(pc.group_name().as_deref(), Some("Walson"));

    let invite = pc.invite(5, false).await.unwrap();
    let phone = device(&dir, "phone", Arc::default());
    let joined = phone
        .join(invite.link, "iPhone".into(), NetworkKind::LocalOnly)
        .await
        .unwrap();
    assert_eq!(
        *seen.0.lock().unwrap(),
        vec![("iPhone".to_owned(), joined.sas)]
    );
    pc.stop().await;
}

#[tokio::test]
async fn members_describe_themselves_and_both_sides_keep_a_journal() {
    use passer_ffi::DeviceKind;

    let dir = tempfile::tempdir().unwrap();
    let pc = device(&dir, "pc", Arc::default());
    pc.create_group("Walson".into(), "PC".into()).unwrap();
    pc.set_device_details(
        DeviceKind::Laptop,
        Some("10.0.26100".into()),
        Some("1.4.0".into()),
    );
    pc.add_capabilities(
        vec![clipboard_spec()],
        Arc::new(Clipboard(Mutex::default())),
    );
    let sheet = Arc::new(Sheet(true, Mutex::default()));
    pc.set_approval_prompter(sheet.clone());
    pc.start(NetworkKind::LocalOnly, None).await.unwrap();

    let invite = pc.invite(5, false).await.unwrap();
    let phone_vault = Arc::new(MemoryVault::default());
    let phone = device(&dir, "phone", phone_vault.clone());
    phone
        .join(invite.link, "iPhone".into(), NetworkKind::LocalOnly)
        .await
        .unwrap();
    phone.set_device_details(DeviceKind::Phone, Some("17.4".into()), None);
    phone.start(NetworkKind::LocalOnly, None).await.unwrap();
    phone
        .add_peer_address("PC".into(), pc.addresses().await.unwrap().remove(0))
        .await
        .unwrap();

    // Before any answer, the PC is known only by the log.
    let me = phone.members().unwrap();
    let mine = me.iter().find(|m| m.this_device).unwrap();
    assert_eq!(mine.kind, DeviceKind::Phone);
    assert_eq!(mine.os_version.as_deref(), Some("17.4"));

    assert_eq!(phone.refresh_members().await.unwrap(), 1);
    let members = phone.members().unwrap();
    let the_pc = members.iter().find(|m| m.name == "PC").unwrap();
    assert_eq!(the_pc.kind, DeviceKind::Laptop);
    assert_eq!(the_pc.os_version.as_deref(), Some("10.0.26100"));
    assert_eq!(the_pc.app_version.as_deref(), Some("1.4.0"));
    assert!(the_pc.answered_at.is_some());

    // What the PC offers, and which of it needs the PC user's approval.
    let offered = phone.member_capabilities("PC".into()).unwrap();
    let info = offered.iter().find(|c| c.name == "device.info").unwrap();
    assert!(!info.needs_approval);
    let clip = offered.iter().find(|c| c.name == "clipboard.read").unwrap();
    assert!(clip.needs_approval);
    assert_eq!(clip.effect, EffectKind::Sensitive);
    // Refreshing never makes the PC ask its user anything.
    assert!(sheet.1.lock().unwrap().is_empty());

    // A call shows on both sides: outgoing on the phone, received on the PC.
    phone
        .call("PC".into(), "clipboard.read".into(), "{}".into())
        .await
        .unwrap();
    let sent = phone.journal_recent(10, Some("PC".into())).await.unwrap();
    assert_eq!(sent[0].capability, "clipboard.read");
    assert!(sent[0].outgoing);
    assert_eq!(sent[0].peer_name, "PC");
    assert_eq!(sent[0].outcome, "ok");
    let received = pc.journal_recent(10, Some("iPhone".into())).await.unwrap();
    let read = received
        .iter()
        .find(|e| e.capability == "clipboard.read")
        .unwrap();
    assert!(!read.outgoing);
    assert_eq!(read.decision, "ask");
    assert_eq!(read.approved, Some(true));

    // What the PC said survives a restart of the app, before any new answer.
    phone.stop().await;
    let again = device(&dir, "phone", phone_vault);
    let cached = again.members().unwrap();
    let the_pc = cached.iter().find(|m| m.name == "PC").unwrap();
    assert_eq!(the_pc.kind, DeviceKind::Laptop);
    assert_eq!(
        again.member_capabilities("PC".into()).unwrap().len(),
        offered.len()
    );
    assert!(!again.journal_recent(5, None).await.unwrap().is_empty());
    pc.stop().await;
}

/// Stands in for the app's file code: keeps what it receives, serves one file.
struct Drop {
    kept: std::path::PathBuf,
    served: std::path::PathBuf,
}

#[async_trait]
impl CapabilityHandler for Drop {
    async fn invoke(
        &self,
        _: String,
        _: Option<String>,
        _: String,
        _: CallerInfo,
    ) -> Result<String, PasserError> {
        unreachable!()
    }

    async fn receive_file(
        &self,
        capability: String,
        _: Option<String>,
        input_json: String,
        caller: CallerInfo,
        path: String,
    ) -> Result<String, PasserError> {
        assert_eq!(capability, "file.put");
        assert_eq!(caller.device_name, "iPhone");
        let name: serde_json::Value = serde_json::from_str(&input_json).unwrap();
        assert_eq!(name["name"], "video.mp4");
        std::fs::rename(&path, &self.kept).unwrap();
        Ok(r#"{"saved":true}"#.into())
    }

    async fn provide_file(
        &self,
        capability: String,
        _: Option<String>,
        _: String,
        _: CallerInfo,
    ) -> Result<String, PasserError> {
        assert_eq!(capability, "file.get");
        Ok(self.served.to_string_lossy().into_owned())
    }
}

#[derive(Default)]
struct Seen(Mutex<Vec<(u64, Option<u64>)>>);

impl passer_ffi::TransferProgress for Seen {
    fn progress(&self, done: u64, total: Option<u64>) {
        self.0.lock().unwrap().push((done, total));
    }
}

fn file_spec(name: &str, kind: passer_ffi::StreamKind, max: Option<u64>) -> CapabilitySpec {
    CapabilitySpec {
        name: name.into(),
        title: name.into(),
        description: name.into(),
        input_schema_json: r#"{"type":"object"}"#.into(),
        effect: EffectKind::Write,
        target_kind: None,
        indicator_required: false,
        stream: Some(kind),
        max_bytes: max,
    }
}

#[tokio::test]
async fn files_go_both_ways_whole_or_not_at_all() {
    use passer_ffi::StreamKind;

    let dir = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..6 * 1024 * 1024 + 5).map(|i| (i % 253) as u8).collect();
    let source = dir.path().join("source.bin");
    std::fs::write(&source, &data).unwrap();

    let pc = device(&dir, "pc", Arc::default());
    pc.create_group("Walson".into(), "PC".into()).unwrap();
    let kept = dir.path().join("kept.mp4");
    pc.add_capabilities(
        vec![
            file_spec("file.put", StreamKind::Upload, None),
            file_spec("file.small", StreamKind::Upload, Some(1024)),
            file_spec("file.get", StreamKind::Download, None),
        ],
        Arc::new(Drop {
            kept: kept.clone(),
            served: source.clone(),
        }),
    );
    pc.start(NetworkKind::LocalOnly, None).await.unwrap();
    let invite = pc.invite(5, false).await.unwrap();
    let phone = device(&dir, "phone", Arc::default());
    phone
        .join(invite.link, "iPhone".into(), NetworkKind::LocalOnly)
        .await
        .unwrap();
    phone.start(NetworkKind::LocalOnly, None).await.unwrap();
    phone
        .add_peer_address("PC".into(), pc.addresses().await.unwrap().remove(0))
        .await
        .unwrap();

    // Phone to PC, with progress.
    let seen = Arc::new(Seen::default());
    let out = phone
        .send_file(
            "PC".into(),
            "file.put".into(),
            r#"{"name":"video.mp4"}"#.into(),
            source.to_string_lossy().into(),
            Some(seen.clone()),
        )
        .await
        .unwrap();
    assert_eq!(out, r#"{"saved":true}"#);
    assert_eq!(std::fs::read(&kept).unwrap(), data);
    let seen = seen.0.lock().unwrap().clone();
    assert!(seen.len() >= 6, "progress along the way: {seen:?}");
    assert_eq!(
        *seen.last().unwrap(),
        (data.len() as u64, Some(data.len() as u64))
    );

    // Too large for the capability: refused, and nothing is left on the PC.
    match phone
        .send_file(
            "PC".into(),
            "file.small".into(),
            "{}".into(),
            source.to_string_lossy().into(),
            None,
        )
        .await
    {
        Err(PasserError::Refused { code, .. }) => assert_eq!(code, "module_error"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let incoming = dir.path().join("pc").join("incoming");
    assert_eq!(std::fs::read_dir(&incoming).unwrap().count(), 0);

    // PC to phone.
    let destination = dir.path().join("fetched.bin");
    let out = phone
        .fetch_file(
            "PC".into(),
            "file.get".into(),
            "{}".into(),
            destination.to_string_lossy().into(),
            None,
        )
        .await
        .unwrap();
    assert!(out.contains(&format!("\"bytes\":{}", data.len())), "{out}");
    assert_eq!(std::fs::read(&destination).unwrap(), data);

    // Both transfers show in the phone's journal.
    let lines = phone.journal_recent(10, Some("PC".into())).await.unwrap();
    assert!(
        lines
            .iter()
            .any(|l| l.capability == "file.get" && l.outgoing && l.outcome == "ok")
    );
    assert!(
        lines
            .iter()
            .any(|l| l.capability == "file.small" && l.outcome != "ok")
    );

    pc.stop().await;
    phone.stop().await;
}
