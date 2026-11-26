//! The engine's [`Keychain`] port on the OS keychain: Windows Credential Manager, macOS
//! Keychain, Secret Service on Linux, through the `keyring` crate as in the sister app.
//!
//! The engine keeps its device identity and the account's epoch secrets there (project rule:
//! secrets exclusively in the OS keychain), under service `hangar-drive` (a development build:
//! `hangar-drive-dev`, [`SERVICE`]) and the engine's key as
//! the account name (`device-identity`, `epoch-3`). Values are bytes; they are wiped once read
//! ([`Zeroizing`]), and neither a value nor a keyring error text that could carry one ever
//! reaches a log, an error or the window.
//!
//! The store sits behind [`SecretStore`], so the tests run against a fake and never touch the
//! user's keychain.

use hangar_drive_sync::ports::{Keychain, KeychainError};
use zeroize::Zeroizing;

/// The keychain service: `hangar-drive`, and `hangar-drive-dev` for a development build, so a
/// build from source never reads or overwrites the installed app's secrets (security review
/// I4).
pub const SERVICE: &str = if cfg!(debug_assertions) {
    "hangar-drive-dev"
} else {
    "hangar-drive"
};
/// Engine keys are short ASCII names; anything else is a mistake, not a key.
const MAX_KEY_LEN: usize = 64;
/// Windows keeps at most 2560 bytes per credential; the engine stores 32 to 96.
const MAX_SECRET_LEN: usize = 2048;

/// Byte secrets by account name.
pub trait SecretStore {
    /// `Ok(None)` when nothing is stored under `account`.
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreFailure>;
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), StoreFailure>;
    /// Deleting what is not there is not an error.
    fn delete(&self, account: &str) -> Result<(), StoreFailure>;
}

/// Why the store failed, in the shell's own words (never a keyring text, which can carry the
/// stored bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFailure {
    /// No keychain on this system (no Secret Service running, for example).
    Unavailable,
    /// The keychain refused access (locked, denied by the person).
    Denied,
    /// Anything else.
    Failed,
}

impl StoreFailure {
    fn text(self) -> &'static str {
        match self {
            StoreFailure::Unavailable => "no keychain on this system",
            StoreFailure::Denied => "the keychain refused access",
            StoreFailure::Failed => "the keychain failed",
        }
    }
}

/// The engine's port over any [`SecretStore`].
pub struct OsKeychain<S: SecretStore> {
    store: S,
}

impl<S: SecretStore> OsKeychain<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

fn check_key(key: &str) -> Result<(), KeychainError> {
    let ok = !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(KeychainError::Unavailable("invalid key name".into()))
    }
}

fn failure(error: StoreFailure) -> KeychainError {
    KeychainError::Unavailable(error.text().into())
}

impl<S: SecretStore> Keychain for OsKeychain<S> {
    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        check_key(key)?;
        self.store.get(key).map_err(failure)
    }

    fn store(&mut self, key: &str, secret: &[u8]) -> Result<(), KeychainError> {
        check_key(key)?;
        if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return Err(KeychainError::Unavailable(
                "the secret does not fit the keychain".into(),
            ));
        }
        self.store.set(key, secret).map_err(failure)
    }

    fn delete(&mut self, key: &str) -> Result<(), KeychainError> {
        check_key(key)?;
        self.store.delete(key).map_err(failure)
    }
}

/// The platform keychain through `keyring`.
#[derive(Debug, Clone, Copy)]
pub struct KeyringStore {
    service: &'static str,
}

impl Default for KeyringStore {
    fn default() -> Self {
        Self { service: SERVICE }
    }
}

impl KeyringStore {
    /// On Windows with local persistence: the default, Enterprise, roams with the user's
    /// profile to other machines of a domain, and the device identity must never leave this
    /// one (same reasoning as the sister app).
    #[cfg(windows)]
    fn entry(&self, account: &str) -> Result<keyring_core::Entry, StoreFailure> {
        if keyring::Entry::store_status().is_err() {
            return Err(StoreFailure::Unavailable);
        }
        let local = std::collections::HashMap::from([("persistence", "Local")]);
        keyring_core::Entry::new_with_modifiers(self.service, account, &local).map_err(map_error)
    }

    #[cfg(not(windows))]
    fn entry(&self, account: &str) -> Result<keyring_core::Entry, StoreFailure> {
        keyring::Entry::new(self.service, account)
            .map(|entry| entry.inner)
            .map_err(map_error)
    }
}

impl SecretStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreFailure> {
        match self.entry(account)?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(map_error(error)),
        }
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), StoreFailure> {
        self.entry(account)?.set_secret(secret).map_err(map_error)
    }

    fn delete(&self, account: &str) -> Result<(), StoreFailure> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }
}

/// Only the kind of the error survives: `BadEncoding` and `BadDataFormat` carry the stored
/// bytes, `Ambiguous` debug output of entries.
fn map_error(error: keyring::Error) -> StoreFailure {
    match error {
        keyring::Error::NoDefaultStore => StoreFailure::Unavailable,
        keyring::Error::NoStorageAccess(_) => StoreFailure::Denied,
        _ => StoreFailure::Failed,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    /// An in-memory store; `fail` makes every call fail like a locked keychain.
    #[derive(Default)]
    struct FakeStore {
        values: RefCell<BTreeMap<String, Vec<u8>>>,
        fail: Option<StoreFailure>,
    }

    impl SecretStore for FakeStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreFailure> {
            if let Some(f) = self.fail {
                return Err(f);
            }
            Ok(self
                .values
                .borrow()
                .get(account)
                .map(|v| Zeroizing::new(v.clone())))
        }

        fn set(&self, account: &str, secret: &[u8]) -> Result<(), StoreFailure> {
            if let Some(f) = self.fail {
                return Err(f);
            }
            self.values
                .borrow_mut()
                .insert(account.to_owned(), secret.to_vec());
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), StoreFailure> {
            if let Some(f) = self.fail {
                return Err(f);
            }
            self.values.borrow_mut().remove(account);
            Ok(())
        }
    }

    #[test]
    fn a_development_build_has_its_own_service() {
        let expected = if cfg!(debug_assertions) {
            "hangar-drive-dev"
        } else {
            "hangar-drive"
        };
        assert_eq!(SERVICE, expected);
        assert_eq!(KeyringStore::default().service, expected);
    }

    #[test]
    fn secrets_round_trip_through_the_port() {
        let mut keychain = OsKeychain::new(FakeStore::default());
        assert_eq!(keychain.load("device-identity").unwrap(), None);
        keychain.store("device-identity", &[1, 2, 3]).unwrap();
        keychain.store("epoch-1", &[9; 32]).unwrap();
        assert_eq!(
            keychain.load("device-identity").unwrap().as_deref(),
            Some(&vec![1u8, 2, 3])
        );
        keychain.delete("device-identity").unwrap();
        keychain.delete("device-identity").unwrap();
        assert_eq!(keychain.load("device-identity").unwrap(), None);
        assert!(keychain.load("epoch-1").unwrap().is_some());
    }

    #[test]
    fn odd_keys_and_sizes_are_refused_before_the_store() {
        let mut keychain = OsKeychain::new(FakeStore::default());
        for bad in ["", "a/b", "a b", "ü", &"k".repeat(MAX_KEY_LEN + 1)] {
            assert!(keychain.load(bad).is_err(), "{bad:?}");
            assert!(keychain.store(bad, &[1]).is_err(), "{bad:?}");
        }
        assert!(keychain.store("epoch-2", &[]).is_err());
        assert!(keychain
            .store("epoch-2", &vec![0; MAX_SECRET_LEN + 1])
            .is_err());
        assert!(keychain.store.values.borrow().is_empty());
    }

    #[test]
    fn a_failing_store_reports_its_kind_only() {
        let mut keychain = OsKeychain::new(FakeStore {
            fail: Some(StoreFailure::Denied),
            ..FakeStore::default()
        });
        let error = keychain.store("epoch-1", b"secret-bytes").unwrap_err();
        let text = error.to_string();
        assert!(text.contains("refused access"), "{text}");
        assert!(!text.contains("secret-bytes"));
        assert!(keychain.load("epoch-1").is_err());
    }
}
