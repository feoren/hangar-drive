//! `--uninstall-cleanup` (security review L1): the Windows uninstaller starts the app with this
//! argument before it removes the files (src-tauri/windows/hooks.nsh, not on an update), and
//! the app forgets the account on this device: the device identity and every epoch secret leave
//! the OS keychain, and the index and settings files are removed. The synced files stay where
//! they are. Nothing else of the app runs: no window, no engine, no single instance check, so a
//! running instance cannot swallow the argument.

use std::path::Path;

use hangar_drive_sync::ports::Keychain;

/// The argument the uninstaller passes.
pub const ARG: &str = "--uninstall-cleanup";

/// Forgets the account behind the index at `index` with `keychain`, then removes the index and
/// settings files next to it. Every step is tried; the first failure is returned as a line for the log.
pub fn forget(index: &Path, keychain: &mut dyn Keychain) -> Result<(), String> {
    let mut first: Option<String> = None;
    if index.exists() {
        match hangar_drive_sync::index::SqliteStore::open(index) {
            Ok(mut store) => {
                if let Err(e) = hangar_drive_sync::account::forget(&mut store, keychain) {
                    first.get_or_insert(e.to_string());
                }
            }
            Err(e) => {
                first.get_or_insert(e.to_string());
                // Without a readable index the secrets still go, up to the margin.
                if let Err(e) = hangar_drive_sync::account::forget_secrets(keychain, 64) {
                    first.get_or_insert(e.to_string());
                }
            }
        }
    } else if let Err(e) = hangar_drive_sync::account::forget_secrets(keychain, 64) {
        first.get_or_insert(e.to_string());
    }
    // Only the app's own files: with a per-user install the program files live in the same
    // folder (`%LOCALAPPDATA%\Hangar Drive`), and the uninstaller removes the folder itself once
    // it is empty.
    if let Some(dir) = index.parent() {
        let index_name = index.file_name().map(|n| n.to_string_lossy().into_owned());
        let mut names: Vec<String> = vec![
            crate::settings::FILE_NAME.to_owned(),
            format!("{}.tmp", crate::settings::FILE_NAME),
        ];
        if let Some(index_name) = index_name {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                names.push(format!("{index_name}{suffix}"));
            }
        }
        for name in names {
            let path = dir.join(name);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    first.get_or_insert(format!("an app file was not removed: {}", e.kind()));
                }
            }
        }
        // The folder of a development build's index holds nothing else.
        let _ = std::fs::remove_dir(dir);
    }
    first.map_or(Ok(()), Err)
}

/// The cleanup with the real keychain and index.
pub fn run() -> i32 {
    let Some(index) = crate::settings::index_path() else {
        return 0;
    };
    let mut keychain = crate::keychain::OsKeychain::new(crate::keychain::KeyringStore::default());
    match forget(&index, &mut keychain) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("hangar-drive: cleanup incomplete: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_drive_sync::memory::MemKeychain;

    #[test]
    fn the_cleanup_forgets_the_secrets_and_the_folder() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(".tmp")
            .join("cleanup")
            .join("Hangar Drive");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let index = dir.join("index.sqlite3");
        drop(hangar_drive_sync::index::SqliteStore::open(&index).unwrap());
        std::fs::write(dir.join("settings.json"), b"{}").unwrap();
        // A per-user install keeps its program files in the same folder; they stay.
        std::fs::write(dir.join("hangar-drive.exe"), b"program").unwrap();
        let mut keychain = MemKeychain::default();
        for key in ["device-identity", "epoch-1", "epoch-2"] {
            keychain.store(key, &[7; 32]).unwrap();
        }
        forget(&index, &mut keychain).unwrap();
        assert_eq!(keychain.keys(), Vec::<String>::new());
        assert!(!index.exists() && !dir.join("settings.json").exists());
        assert!(dir.join("hangar-drive.exe").exists(), "program files stay");
        // Again, with nothing left: not an error.
        forget(&index, &mut keychain).unwrap();
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn the_uninstall_hook_runs_the_cleanup_except_on_updates() {
        let hook = include_str!("../windows/hooks.nsh");
        assert!(hook.contains("NSIS_HOOK_PREUNINSTALL"));
        assert!(hook.contains(ARG));
        assert!(hook.contains("$UpdateMode <> 1"));
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(
            conf["bundle"]["windows"]["nsis"]["installerHooks"],
            "windows/hooks.nsh"
        );
    }
}
