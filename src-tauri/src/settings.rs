//! The shell's own settings (ux-concept 11) in `settings.json` next to the sync index in the
//! platform's local config folder (`%LOCALAPPDATA%\Hangar Drive`, `~/Library/Application
//! Support/Hangar Drive`, `~/.config/Hangar Drive`), never in a sync folder. Whether the app
//! starts at sign-in is the OS's own state (the autostart plugin); stored here is only whether
//! the default "on" was applied once, so a person who switched it off keeps it off.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const FILE_NAME: &str = "settings.json";
/// A settings file larger than this is not ours.
const MAX_FILE_LEN: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Stored {
    /// A language of `texts::LANGUAGES` or `system`.
    pub language: String,
    /// The default "start at sign-in" was applied once.
    pub autostart_applied: bool,
    /// The one-time "keeps running in the notification area" was shown (ux-concept 3).
    pub close_hint_shown: bool,
}

impl Default for Stored {
    fn default() -> Self {
        Self {
            language: "system".into(),
            autostart_applied: false,
            close_hint_shown: false,
        }
    }
}

impl Stored {
    /// Reads the file; a missing, oversized or unreadable file gives the defaults, and an
    /// unknown language becomes `system`.
    pub fn load(path: &Path) -> Self {
        let read = std::fs::metadata(path)
            .ok()
            .filter(|m| m.len() <= MAX_FILE_LEN)
            .and_then(|_| std::fs::read(path).ok());
        let mut stored: Self = read
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        if !is_language_choice(&stored.language) {
            stored.language = "system".into();
        }
        stored
    }

    /// Writes the file through a temporary file and a rename, so a crash never leaves half a
    /// file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, bytes)?;
        std::fs::rename(&temp, path)
    }
}

/// `system` or one of the twelve languages.
pub fn is_language_choice(value: &str) -> bool {
    value == "system" || crate::texts::LANGUAGES.contains(&value)
}

/// The sync index: the engine's default (`<local config>/Hangar Drive/index.sqlite3`), and for
/// a development build `dev/index.sqlite3` inside that folder (security review I4), so a build
/// from source never opens the installed app's index. The folder stays the one the root check
/// refuses as a sync root.
pub fn index_path() -> Option<PathBuf> {
    let index = hangar_drive_sync::index::default_index_path()?;
    if cfg!(debug_assertions) {
        let dir = index.parent()?.join("dev");
        Some(dir.join(index.file_name()?))
    } else {
        Some(index)
    }
}

/// The settings file next to the sync index ([`index_path`]).
pub fn default_path() -> Option<PathBuf> {
    index_path().and_then(|index| index.parent().map(|dir| dir.join(FILE_NAME)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(".tmp")
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn settings_round_trip_and_bad_files_give_defaults() {
        let dir = dir("settings");
        let path = dir.join(FILE_NAME);
        assert_eq!(Stored::load(&path), Stored::default());
        let stored = Stored {
            language: "fr".into(),
            autostart_applied: true,
            close_hint_shown: true,
        };
        stored.save(&path).unwrap();
        assert_eq!(Stored::load(&path), stored);
        std::fs::write(&path, b"{\"language\": \"xx\", \"closeHintShown\": true}").unwrap();
        let read = Stored::load(&path);
        assert_eq!(read.language, "system");
        assert!(read.close_hint_shown);
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(Stored::load(&path), Stored::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_lives_next_to_the_index_and_never_in_a_sync_folder() {
        if let (Some(settings), Some(index), Some(release)) = (
            default_path(),
            index_path(),
            hangar_drive_sync::index::default_index_path(),
        ) {
            assert_eq!(settings.parent(), index.parent());
            // A development build keeps its own index inside the app's folder.
            if cfg!(debug_assertions) {
                assert_ne!(index, release);
                assert!(index.starts_with(release.parent().unwrap()));
            } else {
                assert_eq!(index, release);
            }
        }
        assert!(is_language_choice("system"));
        assert!(is_language_choice("zh"));
        assert!(!is_language_choice("EN"));
    }
}
