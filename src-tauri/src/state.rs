//! What the shell keeps between commands: the engine handle, its settings file, the recovery
//! code on screen, open pairing links, the newest snapshot and the notification policy.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use hangar_drive_sync::api::Snapshot;
use hangar_drive_sync::engine::{EngineCore, EngineHandle};
use hangar_drive_sync::error::SyncError;

use crate::documents::ShownCode;
use crate::error::CommandError;
use crate::notifications::Policy;
use crate::settings::Stored;

/// Pairing links kept for "copy link" (ux-concept 5); older offers fall out.
const MAX_OFFERS: usize = 8;
/// Folder places the window holds a token for; older ones fall out.
const MAX_PLACES: usize = 32;

/// Folder places the backend chose (a picked folder, the proposed default, the proposed place
/// of an account folder), each behind a random token (security review L2). The window only ever
/// hands back a token, so a compromised page cannot make the backend sync, create or count a
/// path of its own choosing.
#[derive(Debug, Default)]
pub struct Places(Mutex<Vec<(String, PathBuf)>>);

impl Places {
    /// A new token for `path`.
    pub fn issue(&self, path: PathBuf) -> Result<String, CommandError> {
        use hangar_drive_crypto::Entropy as _;
        let mut bytes = [0u8; 16];
        hangar_drive_crypto::OsEntropy
            .fill(&mut bytes)
            .map_err(|_| CommandError::unexpected("no randomness for a folder token"))?;
        let token = hangar_drive_protocol::ids::base64url(&bytes);
        let mut places = lock(&self.0);
        places.push((token.clone(), path));
        let excess = places.len().saturating_sub(MAX_PLACES);
        places.drain(..excess);
        Ok(token)
    }

    /// The path behind `token`.
    pub fn path(&self, token: &str) -> Result<PathBuf, CommandError> {
        lock(&self.0)
            .iter()
            .find(|(t, _)| t == token)
            .map(|(_, p)| p.clone())
            .ok_or_else(|| CommandError::invalid("unknown folder token"))
    }

    /// The path behind `token`, which is used up.
    pub fn take(&self, token: &str) -> Result<PathBuf, CommandError> {
        let mut places = lock(&self.0);
        let at = places
            .iter()
            .position(|(t, _)| t == token)
            .ok_or_else(|| CommandError::invalid("unknown folder token"))?;
        Ok(places.remove(at).1)
    }
}

pub struct Shell {
    engine: Result<EngineHandle, String>,
    pub tz_offset_minutes: i32,
    pub settings_path: Option<PathBuf>,
    pub settings: Mutex<Stored>,
    pub shown: Mutex<Option<ShownCode>>,
    offers: Mutex<Vec<(String, String)>>,
    /// The device name chosen before the device belongs to an account (pairing, recovery).
    pub device_name: Mutex<Option<String>>,
    pub snapshot: Mutex<Option<Snapshot>>,
    pub policy: Mutex<Policy>,
    /// A file dialog is open; a second one waits for nothing and is refused as busy.
    pub dialog_open: AtomicBool,
    /// Counts clipboard writes, so a delayed clear never removes what was copied after it.
    pub clipboard_writes: Arc<AtomicU64>,
    /// Folder places behind tokens (security review L2).
    pub places: Places,
}

/// Locks a mutex; a poisoned lock still holds a usable value for the shell's plain data.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Shell {
    pub fn new(
        engine: Result<EngineHandle, String>,
        tz_offset_minutes: i32,
        settings_path: Option<PathBuf>,
        settings: Stored,
    ) -> Self {
        Self {
            engine,
            tz_offset_minutes,
            settings_path,
            settings: Mutex::new(settings),
            shown: Mutex::new(None),
            offers: Mutex::new(Vec::new()),
            device_name: Mutex::new(None),
            snapshot: Mutex::new(None),
            policy: Mutex::new(Policy::default()),
            dialog_open: AtomicBool::new(false),
            clipboard_writes: Arc::new(AtomicU64::new(0)),
            places: Places::default(),
        }
    }

    /// Why the engine did not start, for the error report.
    pub fn engine_error(&self) -> Option<&str> {
        self.engine.as_ref().err().map(String::as_str)
    }

    /// The language of the backend texts: the chosen one, or the system's.
    pub fn language(&self) -> &'static str {
        let chosen = lock(&self.settings).language.clone();
        language_of(&chosen)
    }

    /// Runs `command` on the engine thread, off the main thread, and flattens both errors.
    pub async fn engine<T: Send + 'static>(
        &self,
        command: impl FnOnce(&mut EngineCore) -> Result<T, SyncError> + Send + 'static,
    ) -> Result<T, CommandError> {
        let handle = self
            .engine
            .as_ref()
            .map_err(|e| CommandError::unexpected(format!("the sync engine did not start: {e}")))?
            .clone();
        tauri::async_runtime::spawn_blocking(move || handle.call(command))
            .await
            .map_err(|e| CommandError::unexpected(e.to_string()))?
            .map_err(CommandError::from)?
            .map_err(CommandError::from)
    }

    pub fn remember_offer(&self, id: String, link: String) {
        let mut offers = lock(&self.offers);
        offers.retain(|(i, _)| *i != id);
        offers.push((id, link));
        let excess = offers.len().saturating_sub(MAX_OFFERS);
        offers.drain(..excess);
    }

    pub fn offer_link(&self, id: &str) -> Option<String> {
        lock(&self.offers)
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, l)| l.clone())
    }

    pub fn save_settings(&self) -> Result<(), CommandError> {
        let Some(path) = &self.settings_path else {
            return Err(CommandError::unexpected("no config folder"));
        };
        lock(&self.settings).save(path).map_err(CommandError::from)
    }
}

/// The language of a choice of the settings: `system` asks the OS.
pub fn language_of(choice: &str) -> &'static str {
    if choice == "system" {
        crate::texts::resolve(&crate::platform::os_language().unwrap_or_default())
    } else {
        crate::texts::resolve(choice)
    }
}

/// While it lives, the shell's one file dialog is open.
#[derive(Debug)]
pub struct DialogGuard<'a>(&'a AtomicBool);

impl<'a> DialogGuard<'a> {
    pub fn enter(flag: &'a AtomicBool) -> Result<Self, CommandError> {
        if flag.swap(true, Ordering::SeqCst) {
            return Err(CommandError::busy("a dialog is open"));
        }
        Ok(Self(flag))
    }
}

impl Drop for DialogGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Pairing links by offer id, newest last (for tests of the bound).
#[cfg(test)]
pub fn offers_of(shell: &Shell) -> std::collections::BTreeMap<String, String> {
    lock(&shell.offers).iter().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell() -> Shell {
        Shell::new(Err("not started".into()), 0, None, Stored::default())
    }

    #[test]
    fn offers_are_bounded_and_found_by_id() {
        let shell = shell();
        for i in 0..10 {
            shell.remember_offer(format!("o{i}"), format!("hangar-drive://pair#{i}"));
        }
        assert_eq!(offers_of(&shell).len(), MAX_OFFERS);
        assert_eq!(shell.offer_link("o0"), None);
        assert_eq!(
            shell.offer_link("o9").as_deref(),
            Some("hangar-drive://pair#9")
        );
    }

    #[test]
    fn one_dialog_at_a_time() {
        let shell = shell();
        let first = DialogGuard::enter(&shell.dialog_open).unwrap();
        assert_eq!(
            DialogGuard::enter(&shell.dialog_open).unwrap_err().code,
            "busy"
        );
        drop(first);
        assert!(DialogGuard::enter(&shell.dialog_open).is_ok());
    }

    #[test]
    fn without_an_engine_commands_fail_cleanly() {
        let shell = shell();
        let result = tauri::async_runtime::block_on(shell.engine(|core| Ok(core.snapshot())));
        let error = result.unwrap_err();
        assert_eq!(error.code, "unexpected");
        assert!(error.message.contains("did not start"));
        assert_eq!(shell.engine_error(), Some("not started"));
    }

    #[test]
    fn folder_tokens_name_only_backend_places() {
        let shell = shell();
        let token = shell
            .places
            .issue(PathBuf::from("C:\\Users\\a\\Docs"))
            .unwrap();
        assert_eq!(token.len(), 22);
        assert_eq!(
            shell.places.path(&token).unwrap(),
            PathBuf::from("C:\\Users\\a\\Docs")
        );
        assert!(
            shell.places.path("C:\\Windows").is_err(),
            "a path is no token"
        );
        assert!(shell.places.take(&token).is_ok());
        assert!(shell.places.take(&token).is_err(), "used up");
        let first = shell.places.issue(PathBuf::from("a")).unwrap();
        for i in 0..MAX_PLACES {
            shell.places.issue(PathBuf::from(format!("p{i}"))).unwrap();
        }
        assert!(shell.places.path(&first).is_err(), "older tokens fall out");
    }
}
