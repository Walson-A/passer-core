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
