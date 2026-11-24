//! The device key in the system keyring: the Keychain on macOS, the Secret Service
//! (GNOME Keyring, KWallet) on Linux.
//!
//! One entry per key path, so several homes on one machine (tests, several CLI devices)
//! keep separate keys. A key left in a file by an earlier version is moved into the
//! keyring once it reads back identical, then the file is deleted.
//!
//! A Linux machine without a Secret Service (a headless server) has nowhere better to
//! keep the key: there, the store falls back to a file readable only by its owner.

use std::path::PathBuf;

use crate::{FileKeyStore, Identity, IdentityError, KeyStore};

const SERVICE: &str = "passer-core";

pub struct KeyringKeyStore {
    path: PathBuf,
}

impl KeyringKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn entry(&self) -> Result<keyring::Entry, keyring::Error> {
        let account = std::path::absolute(&self.path)
            .unwrap_or_else(|_| self.path.clone())
            .to_string_lossy()
            .into_owned();
        keyring::Entry::new(SERVICE, &account)
    }

    fn from_keyring(entry: &keyring::Entry) -> Result<Option<Identity>, keyring::Error> {
        match entry.get_secret() {
            Ok(bytes) => {
                let secret: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| keyring::Error::Invalid("secret".into(), "length".into()))?;
                Ok(Some(Identity::from_secret_bytes(&secret)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn store(entry: &keyring::Entry, identity: &Identity) -> Result<(), keyring::Error> {
        entry.set_secret(&identity.secret.to_bytes())?;
        // Read it back: a keyring that accepted the write but loses it would cost the
        // device its identity.
        match Self::from_keyring(entry)? {
            Some(back) if back.id() == identity.id() => Ok(()),
            _ => Err(keyring::Error::Invalid(
                "secret".into(),
                "did not read back".into(),
            )),
        }
    }
}

impl KeyStore for KeyringKeyStore {
    fn load_or_create(&self) -> Result<Identity, IdentityError> {
        let file = FileKeyStore::new(&self.path);
        let entry = match self.entry() {
            Ok(entry) => entry,
            Err(_) => return file.load_or_create(),
        };
        match Self::from_keyring(&entry) {
            Ok(Some(identity)) => return Ok(identity),
            Ok(None) => {}
            // No usable keyring (no Secret Service, locked and no prompt possible).
            Err(_) => return file.load_or_create(),
        }
        // Nothing in the keyring: move a key from an earlier version, or create one.
        let identity = if self.path.exists() {
            file.load_or_create()?
        } else {
            Identity::generate()
        };
        match Self::store(&entry, &identity) {
            Ok(()) => {
                if self.path.exists() {
                    let _ = std::fs::remove_file(&self.path);
                }
                Ok(identity)
            }
            Err(_) if self.path.exists() => Ok(identity),
            // The keyring refused the write: keep the new key in a file rather than lose it.
            Err(_) => {
                if let Some(parent) = self.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                crate::write_key_file(&self.path, &identity)?;
                Ok(identity)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touches the real keyring: run with `PASSER_CORE_TEST_KEYRING=1`.
    #[test]
    fn keeps_and_migrates_keys() {
        if std::env::var_os("PASSER_CORE_TEST_KEYRING").is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");

        // An earlier version left the key in a file: it moves into the keyring.
        let old = FileKeyStore::new(&path).load_or_create().unwrap();
        let store = KeyringKeyStore::new(&path);
        assert_eq!(store.load_or_create().unwrap().id(), old.id());
        assert!(
            !path.exists(),
            "the file is gone once the keyring holds the key"
        );
        assert_eq!(store.load_or_create().unwrap().id(), old.id());

        // Clean up the test entry.
        store.entry().unwrap().delete_credential().unwrap();
    }
}
