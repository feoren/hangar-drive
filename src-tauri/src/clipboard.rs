//! The clipboard: codes and links are copied as secrets and cleared after a minute (security
//! review M1), and only text that looks like a Hangar Drive link or code is read back for the
//! window (security review L2).
//!
//! Copying goes through `write_secret` of `tauri-plugin-clipboard-manager` 2.5.0, which sets the
//! text through arboard and then marks it (plugin `src/secret.rs`, arboard
//! `platform/windows.rs` `add_clipboard_exclusions`): on Windows with the registered format
//! `ExcludeClipboardContentFromMonitorProcessing`, which keeps it out of the clipboard history
//! and the cloud clipboard; on macOS with `org.nspasteboard.ConcealedType` and on Linux with the
//! `x-kde-passwordManagerHint` hint, which clipboard managers that honour them leave out of
//! their history. The OS behaviour behind those hints is Microsoft's and the managers' own
//! [UNVERIFIED on a running system].
//!
//! The policy sits behind [`Clipboard`], so the tests run against a fake.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

/// Clipboard text longer than this is neither a link nor a code.
pub const MAX_READ_CHARS: usize = 16 * 1024;
/// The clipboard is cleared this long after a code or link was copied (ux-concept 4.2, 5).
pub const CLEAR_AFTER: Duration = Duration::from_secs(60);

/// Why the clipboard failed, without its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the clipboard is not available")]
pub struct ClipboardError;

/// What the shell needs of the system clipboard.
pub trait Clipboard: Send + Sync + 'static {
    /// Writes `text` marked as secret (no history, no cloud clipboard).
    fn write_secret(&self, text: &str) -> Result<(), ClipboardError>;
    /// Writes plain text (an error report, the empty text that clears a code).
    fn write_text(&self, text: &str) -> Result<(), ClipboardError>;
    /// The text on the clipboard, if any.
    fn read_text(&self) -> Option<String>;
}

/// Copies `text` as a secret and, after `after`, clears the clipboard if it still holds that
/// text and nothing was copied through the shell since. `writes` counts the shell's copies.
pub fn copy_and_clear<C: Clipboard>(
    clipboard: Arc<C>,
    writes: Arc<AtomicU64>,
    text: Zeroizing<String>,
    after: Duration,
) -> Result<(), ClipboardError> {
    clipboard.write_secret(text.as_str())?;
    let write = writes.fetch_add(1, Ordering::SeqCst) + 1;
    let cleaner = Arc::clone(&clipboard);
    let spawned = std::thread::Builder::new()
        .name("hangar-drive-clipboard".into())
        .spawn(move || {
            std::thread::sleep(after);
            let still_ours = writes.load(Ordering::SeqCst) == write;
            let same = cleaner
                .read_text()
                .map(Zeroizing::new)
                .is_some_and(|now| now.as_str() == text.as_str());
            if still_ours && same {
                let _ = cleaner.write_text("");
            }
        });
    // Without the thread the code would stay; take it off again at once.
    if spawned.is_err() {
        let _ = clipboard.write_text("");
        return Err(ClipboardError);
    }
    Ok(())
}

/// The clipboard text the window may see: a `hangar-drive://` link, an `http(s)://` invite or
/// join link, or a code of Crockford base32 groups (recovery and pairing codes); `""` for
/// anything else, so the window never reads unrelated clipboard contents.
pub fn readable(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_READ_CHARS {
        return String::new();
    }
    if looks_like_link(trimmed) || looks_like_code(trimmed) {
        trimmed.to_owned()
    } else {
        String::new()
    }
}

fn looks_like_link(text: &str) -> bool {
    // White space inside a pasted link is removed by the window; a line break or a control
    // character is not part of one.
    if text.chars().any(char::is_control) {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    if [
        "hangar-drive://join#",
        "hangar-drive://pair#",
        "hangar-drive://recover#",
    ]
    .iter()
    .any(|p| lower.starts_with(p))
    {
        return true;
    }
    // An invite as the server prints it: `https://host/join#...` (http only for localhost,
    // which the engine's parser decides).
    (lower.starts_with("https://") || lower.starts_with("http://"))
        && lower.contains("/join#")
        && !lower.contains(char::is_whitespace)
}

/// A recovery or pairing code: groups of two to eight Crockford base32 characters (the letters
/// I, L and O the window maps to digits included, U never), separated by `-` or spaces, 8 to 80
/// characters in all and at least one digit, so a line of ordinary words is not one.
fn looks_like_code(text: &str) -> bool {
    let groups: Vec<&str> = text.split(['-', ' ']).filter(|g| !g.is_empty()).collect();
    let crockford = |c: char| c.is_ascii_alphanumeric() && !c.eq_ignore_ascii_case(&'u');
    let letters: usize = groups.iter().map(|g| g.len()).sum();
    !groups.is_empty()
        && groups
            .iter()
            .all(|g| (2..=8).contains(&g.len()) && g.chars().all(crockford))
        && (8..=80).contains(&letters)
        && text.chars().any(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        text: Mutex<Option<String>>,
        secret: Mutex<bool>,
    }

    impl Clipboard for Fake {
        fn write_secret(&self, text: &str) -> Result<(), ClipboardError> {
            *self.text.lock().unwrap() = Some(text.to_owned());
            *self.secret.lock().unwrap() = true;
            Ok(())
        }
        fn write_text(&self, text: &str) -> Result<(), ClipboardError> {
            *self.text.lock().unwrap() = Some(text.to_owned());
            *self.secret.lock().unwrap() = false;
            Ok(())
        }
        fn read_text(&self) -> Option<String> {
            self.text.lock().unwrap().clone()
        }
    }

    const SHORT: Duration = Duration::from_millis(40);
    const WAIT: Duration = Duration::from_millis(400);

    #[test]
    fn a_code_is_copied_as_a_secret_and_cleared() {
        let clipboard = Arc::new(Fake::default());
        let writes = Arc::new(AtomicU64::new(0));
        copy_and_clear(
            clipboard.clone(),
            writes.clone(),
            Zeroizing::new("D7KQ-M2XP".into()),
            SHORT,
        )
        .unwrap();
        assert_eq!(clipboard.read_text().as_deref(), Some("D7KQ-M2XP"));
        assert!(*clipboard.secret.lock().unwrap(), "marked as secret");
        std::thread::sleep(WAIT);
        assert_eq!(clipboard.read_text().as_deref(), Some(""));
    }

    #[test]
    fn something_copied_later_is_not_cleared() {
        let clipboard = Arc::new(Fake::default());
        let writes = Arc::new(AtomicU64::new(0));
        copy_and_clear(
            clipboard.clone(),
            writes.clone(),
            Zeroizing::new("first".into()),
            SHORT,
        )
        .unwrap();
        // The person copies something else in another program.
        clipboard.write_text("mine").unwrap();
        // And a second code through the shell, cleared on its own schedule.
        copy_and_clear(
            clipboard.clone(),
            writes.clone(),
            Zeroizing::new("second".into()),
            Duration::from_secs(30),
        )
        .unwrap();
        std::thread::sleep(WAIT);
        assert_eq!(clipboard.read_text().as_deref(), Some("second"));
    }

    #[test]
    fn only_links_and_codes_are_read() {
        for good in [
            "hangar-drive://pair#AQIDBA",
            "  HANGAR-DRIVE://recover#AQID  ",
            "https://drive.example/join#abc.def",
            "D7KQ-M2XP-9H4T-RW8C-ZB3N-F6JA-Q1VE-K5SY",
            "d7kq m2xp 9h4t rw8c",
            "07GE-3RQ3-WKJY-DSZ8-X7NE-QV7D-XVQJ-SKJC",
        ] {
            assert_eq!(readable(good), good.trim(), "{good:?}");
        }
        for bad in [
            "",
            "my bank password",
            "hello world again",
            "summer 2026 trip",
            "D7KQ_M2XP_9H4T",
            "https://example.com/login",
            "hangar-drive://pair#a\nsecond line",
            "short",
            "äöü-äöü-äöü",
            &"A".repeat(MAX_READ_CHARS + 1),
        ] {
            assert_eq!(readable(bad), "", "{bad:?}");
        }
    }
}
