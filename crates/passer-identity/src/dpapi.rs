//! Windows key store: the secret key encrypted with DPAPI, bound to the user account.
//!
//! The file on disk holds only a DPAPI blob. Windows decrypts it for the same user on the
//! same machine (the master key derives from the user's credentials); copied to another
//! machine or read by another account, it is useless. It does not protect against
//! malware running as the same user, which no user-level store can.
//!
//! A TPM-bound root key is the next step (see `docs/security.md`).

use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

use crate::{Identity, IdentityError, KeyStore, write_new_file};

/// Extra entropy: a blob protected by another program with DPAPI cannot be passed off
/// as ours, and ours cannot be decrypted by a program that does not know this string.
const ENTROPY: &[u8] = b"passer-core/device-key/v1";

#[derive(serde::Serialize, serde::Deserialize)]
struct DpapiFile {
    v: u8,
    kind: String,
    blob: String,
}

/// Stores the device key encrypted with DPAPI (current user scope).
pub struct DpapiKeyStore {
    path: PathBuf,
}

impl DpapiKeyStore {
    /// A store for the DPAPI-protected key file at `path`. Nothing is read or written
    /// until [`KeyStore::load_or_create`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Where the protected key file lives.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl KeyStore for DpapiKeyStore {
    fn load_or_create(&self) -> Result<Identity, IdentityError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let file: DpapiFile =
                    serde_json::from_slice(&bytes).map_err(|_| IdentityError::Malformed)?;
                if file.v != 1 || file.kind != "dpapi" {
                    return Err(IdentityError::Malformed);
                }
                let blob = hex::decode(&file.blob).map_err(|_| IdentityError::Malformed)?;
                let mut secret = unprotect(&blob)?;
                let identity = (secret.len() == 32).then(|| {
                    let bytes: [u8; 32] = secret[..].try_into().expect("checked length");
                    Identity::from_secret_bytes(&bytes)
                });
                secret.fill(0);
                identity.ok_or(IdentityError::Malformed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let identity = Identity::generate();
                let mut secret = identity.secret_key().to_bytes();
                let blob = protect(&secret);
                secret.fill(0);
                let file = DpapiFile {
                    v: 1,
                    kind: "dpapi".into(),
                    blob: hex::encode(blob?),
                };
                if let Some(parent) = self.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                write_new_file(&self.path, &serde_json::to_vec(&file).expect("serializes"))?;
                Ok(identity)
            }
            Err(e) => Err(e.into()),
        }
    }
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// Copies a DPAPI output blob into a Vec and frees the system allocation.
///
/// # Safety
/// `out` must have been filled by a successful DPAPI call.
unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: DPAPI returned `cbData` valid bytes at `pbData`, allocated with LocalAlloc.
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    // SAFETY: the buffer was allocated by DPAPI with LocalAlloc and is not used afterwards.
    unsafe {
        ptr::write_bytes(out.pbData, 0, out.cbData as usize);
        LocalFree(out.pbData.cast());
    }
    v
}

fn protect(plain: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let input = blob(plain);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: all pointers are valid for the duration of the call; `out` is written by
    // the API and released by `take`.
    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(IdentityError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: the call succeeded.
    Ok(unsafe { take(out) })
}

fn unprotect(sealed: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let input = blob(sealed);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: as in `protect`.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        // Wrong user, wrong machine, wrong entropy or a modified blob.
        return Err(IdentityError::Malformed);
    }
    // SAFETY: the call succeeded.
    Ok(unsafe { take(out) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_no_plain_secret_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = DpapiKeyStore::new(dir.path().join("device.key"));
        let first = store.load_or_create().unwrap();
        let again = store.load_or_create().unwrap();
        assert_eq!(first.id(), again.id());
        let on_disk = std::fs::read_to_string(store.path()).unwrap();
        assert!(!on_disk.contains(&hex::encode(first.secret_key().to_bytes())));
    }

    #[test]
    fn tampered_blob_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = DpapiKeyStore::new(dir.path().join("device.key"));
        store.load_or_create().unwrap();
        let mut file: DpapiFile =
            serde_json::from_slice(&std::fs::read(store.path()).unwrap()).unwrap();
        let mut raw = hex::decode(&file.blob).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        file.blob = hex::encode(raw);
        std::fs::write(store.path(), serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(matches!(
            store.load_or_create(),
            Err(IdentityError::Malformed)
        ));
    }

    #[test]
    fn foreign_dpapi_blob_is_refused() {
        // Same user, but protected without our entropy: must not decrypt.
        let input = blob(&[7u8; 32]);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        assert_ne!(ok, 0);
        let foreign = unsafe { take(out) };
        assert!(unprotect(&foreign).is_err());
    }
}
