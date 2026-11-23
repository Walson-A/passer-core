//! Device identity.
//!
//! Every device generates its own Ed25519 key pair. The public key *is* the device's
//! identity ([`DeviceId`]); it is also the iroh `EndpointId`, so the transport layer
//! authenticates exactly the key the membership log knows about.
//!
//! The private key never leaves the device. Where it is kept is the job of a
//! [`KeyStore`]. This crate ships only [`FileKeyStore`], meant for development and tests:
//! production builds must use the operating system's vault (Keychain with
//! `ThisDeviceOnly` on iOS, DPAPI or TPM on Windows, Keystore on Android). See
//! `docs/security.md` for why the transport key is Ed25519 and how a hardware-bound
//! root key is meant to sign it.

use std::fmt;
use std::path::{Path, PathBuf};

pub use iroh_base::{PublicKey, SecretKey, Signature, SignatureError};

/// The identity of a device: its Ed25519 public key.
pub type DeviceId = PublicKey;

/// Errors from this crate.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("key store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key file is malformed")]
    Malformed,
}

/// A device's own key pair. Not `Clone`: a key has one owner.
pub struct Identity {
    secret: SecretKey,
}

impl Identity {
    /// Generates a fresh identity from the operating system's random source.
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(),
        }
    }

    /// Rebuilds an identity from its 32 secret bytes (for key stores only).
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            secret: SecretKey::from_bytes(bytes),
        }
    }

    /// The public identity of this device.
    pub fn id(&self) -> DeviceId {
        self.secret.public()
    }

    /// Signs `message` under a domain-separation `context`.
    ///
    /// Every signature in passer-core carries a context, so that a signature made for
    /// one purpose (a membership entry, a join request) can never be replayed as another.
    pub fn sign(&self, context: &str, message: &[u8]) -> Signature {
        self.secret.sign(&framed(context, message))
    }

    /// The secret key, for handing to the transport. It stays in this process.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("id", &self.id().fmt_short().to_string())
            .finish_non_exhaustive()
    }
}

/// Verifies a signature produced by [`Identity::sign`] with the same `context`.
pub fn verify(
    signer: &DeviceId,
    context: &str,
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    signer.verify(&framed(context, message), signature)
}

fn framed(context: &str, message: &[u8]) -> Vec<u8> {
    const TAG: &[u8] = b"passer-core/sig/v1";
    let mut out = Vec::with_capacity(TAG.len() + 5 + context.len() + message.len());
    out.extend_from_slice(TAG);
    out.push(0);
    out.extend_from_slice(&(context.len() as u32).to_be_bytes());
    out.extend_from_slice(context.as_bytes());
    out.extend_from_slice(message);
    out
}

/// Where a device keeps its private key.
pub trait KeyStore {
    /// Loads the identity, creating and persisting a new one on first use.
    fn load_or_create(&self) -> Result<Identity, IdentityError>;
}

/// Development key store: the secret key in a file.
///
/// **Not for production.** The file is protected only by the file system. Release builds
/// must use the platform vault; this type exists so the CLI and the tests run anywhere.
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    v: u8,
    secret: String,
}

impl KeyStore for FileKeyStore {
    fn load_or_create(&self) -> Result<Identity, IdentityError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let file: KeyFile =
                    serde_json::from_slice(&bytes).map_err(|_| IdentityError::Malformed)?;
                if file.v != 1 {
                    return Err(IdentityError::Malformed);
                }
                let raw = hex::decode(&file.secret).map_err(|_| IdentityError::Malformed)?;
                let secret: [u8; 32] = raw.try_into().map_err(|_| IdentityError::Malformed)?;
                Ok(Identity::from_secret_bytes(&secret))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let identity = Identity::generate();
                if let Some(parent) = self.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let file = KeyFile {
                    v: 1,
                    secret: hex::encode(identity.secret.to_bytes()),
                };
                let json = serde_json::to_vec(&file).expect("key file serializes");
                write_new_file(&self.path, &json)?;
                Ok(identity)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Creates the file exclusively, so two processes never overwrite each other's key.
fn write_new_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(contents)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_bound_to_its_context() {
        let id = Identity::generate();
        let sig = id.sign("membership", b"hello");
        assert!(verify(&id.id(), "membership", b"hello", &sig).is_ok());
        assert!(verify(&id.id(), "join", b"hello", &sig).is_err());
        assert!(verify(&id.id(), "membership", b"hellO", &sig).is_err());
        let other = Identity::generate();
        assert!(verify(&other.id(), "membership", b"hello", &sig).is_err());
    }

    #[test]
    fn context_and_message_cannot_be_shifted() {
        // ("ab", "c") and ("a", "bc") must not sign the same bytes.
        assert_ne!(framed("ab", b"c"), framed("a", b"bc"));
    }

    #[test]
    fn file_store_creates_once_then_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path().join("keys").join("device.key"));
        let first = store.load_or_create().unwrap();
        let again = store.load_or_create().unwrap();
        assert_eq!(first.id(), again.id());
    }

    #[test]
    fn file_store_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        std::fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            FileKeyStore::new(path).load_or_create(),
            Err(IdentityError::Malformed)
        ));
    }
}
