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
//! A copied secret is also kept, wiped on drop, until its minute is over ([`HeldSecret`]): the
//! app ends without waiting for the minute (quit, the tray's Quit, an update that restarts it),
//! and [`clear_now`] then takes the secret off the clipboard first if it is still there
//! (security review LOW 2).
//!
//! The policy sits behind [`Clipboard`], so the tests run against a fake.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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

/// The secret the shell copied last, while its clearing is still due (module docs).
pub type HeldSecret = Arc<Mutex<Option<Zeroizing<String>>>>;

fn hold(
    held: &Mutex<Option<Zeroizing<String>>>,
) -> std::sync::MutexGuard<'_, Option<Zeroizing<String>>> {
    held.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Whether the clipboard, holding `now`, still holds the copied `secret` and is to be cleared.
pub fn still_holds(now: Option<&str>, secret: &str) -> bool {
    now.is_some_and(|now| now == secret)
}

/// Copies `text` as a secret and, after `after`, clears the clipboard if it still holds that
/// text and nothing was copied through the shell since. `writes` counts the shell's copies;
/// `held` keeps the text for [`clear_now`] until then.
///
/// A copy and its clearing each run under the lock of `held`: before, a clearing that checked
/// its copy was the last one could drop the next copy's secret from `held` right after that copy
/// put it there, and ending the app then left the new code on the clipboard (review, info).
pub fn copy_and_clear<C: Clipboard>(
    clipboard: Arc<C>,
    writes: Arc<AtomicU64>,
    held: HeldSecret,
    text: Zeroizing<String>,
    after: Duration,
) -> Result<(), ClipboardError> {
    let write = {
        let mut slot = hold(&held);
        clipboard.write_secret(text.as_str())?;
        *slot = Some(text.clone());
        writes.fetch_add(1, Ordering::SeqCst) + 1
    };
    let cleaner = Arc::clone(&clipboard);
    let held_by_thread = Arc::clone(&held);
    let spawned = std::thread::Builder::new()
        .name("hangar-drive-clipboard".into())
        .spawn(move || {
            std::thread::sleep(after);
            let mut slot = hold(&held_by_thread);
            let still_ours = writes.load(Ordering::SeqCst) == write
                && slot.as_ref().is_some_and(|h| h.as_str() == text.as_str());
            if !still_ours {
                return;
            }
            let now = cleaner.read_text().map(Zeroizing::new);
            if still_holds(now.as_ref().map(|n| n.as_str()), text.as_str()) {
                let _ = cleaner.write_text("");
            }
            *slot = None;
        });
    // Without the thread the code would stay; take it off again at once.
    if spawned.is_err() {
        let _ = clipboard.write_text("");
        *hold(&held) = None;
        return Err(ClipboardError);
    }
    Ok(())
}

/// Clears the clipboard now if it still holds the secret in `held`, which is dropped either
/// way; called synchronously before the app ends (module docs). Whatever the person copied
/// since stays.
pub fn clear_now<C: Clipboard>(clipboard: &C, held: &Mutex<Option<Zeroizing<String>>>) {
    let Some(secret) = hold(held).take() else {
        return;
    };
    let now = clipboard.read_text().map(Zeroizing::new);
    if still_holds(now.as_ref().map(|n| n.as_str()), secret.as_str()) {
        let _ = clipboard.write_text("");
    }
}

/// The clipboard text the window may see: a `hangar-drive://join#`, `pair#` or `recover#` link,
/// an `http(s)://<host>/join#` invite, or a recovery or pairing code in its exact printed form;
/// `""` for anything else, so the window never reads unrelated clipboard contents (security
/// review L2, N10).
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

/// The app's own link prefixes.
const APP_LINKS: [&str; 3] = [
    "hangar-drive://join#",
    "hangar-drive://pair#",
    "hangar-drive://recover#",
];

/// A link's fragment: base64url and the `.` an invite uses between its parts.
fn fragment_ok(fragment: &str) -> bool {
    !fragment.is_empty()
        && fragment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn looks_like_link(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if let Some(prefix) = APP_LINKS.iter().find(|p| lower.starts_with(*p)) {
        return fragment_ok(&text[prefix.len()..]);
    }
    // An invite as the server prints it: `https://host/join#...`, the path exactly `/join`
    // (http only for localhost, which the engine's parser decides).
    let Some(rest) = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
    else {
        return false;
    };
    let Some((authority, fragment)) = rest.split_once("/join#") else {
        return false;
    };
    let authority_ok = !authority.is_empty()
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':' | b'[' | b']'));
    // The fragment from the original text, its case kept.
    authority_ok && fragment_ok(&text[text.len() - fragment.len()..])
}

/// Crockford's base32 alphabet, as the codes are printed (no I, L, O or U).
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// A recovery or pairing code: eight groups of four characters.
const CODE_GROUPS: usize = 8;
const GROUP_LEN: usize = 4;

/// A recovery or pairing code exactly as the app prints it: eight groups of four Crockford
/// base32 characters, in any case, separated by `-` or by single spaces.
fn looks_like_code(text: &str) -> bool {
    let separator = if text.contains('-') { '-' } else { ' ' };
    let groups: Vec<&str> = text.split(separator).collect();
    groups.len() == CODE_GROUPS
        && groups.iter().all(|g| {
            g.len() == GROUP_LEN
                && g.bytes()
                    .all(|b| CROCKFORD.contains(&b.to_ascii_uppercase()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        text: Mutex<Option<String>>,
        secret: Mutex<bool>,
        /// A read that takes this long, to widen the window between a clearing's check and its
        /// end.
        slow_read: Mutex<Option<Duration>>,
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
            let slow = *self.slow_read.lock().unwrap();
            if let Some(slow) = slow {
                std::thread::sleep(slow);
            }
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
            HeldSecret::default(),
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
            HeldSecret::default(),
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
            HeldSecret::default(),
            Zeroizing::new("second".into()),
            Duration::from_secs(30),
        )
        .unwrap();
        std::thread::sleep(WAIT);
        assert_eq!(clipboard.read_text().as_deref(), Some("second"));
    }

    // Security review LOW 2: the app ends before the minute is over; the secret comes off the
    // clipboard first, unless the person copied something else since.
    #[test]
    fn ending_the_app_clears_a_secret_still_on_the_clipboard() {
        let clipboard = Arc::new(Fake::default());
        let writes = Arc::new(AtomicU64::new(0));
        let held = HeldSecret::default();
        copy_and_clear(
            clipboard.clone(),
            writes.clone(),
            held.clone(),
            Zeroizing::new("D7KQ-M2XP".into()),
            Duration::from_secs(60),
        )
        .unwrap();
        clear_now(clipboard.as_ref(), &held);
        assert_eq!(clipboard.read_text().as_deref(), Some(""));
        assert!(held.lock().unwrap().is_none(), "the secret is dropped");

        copy_and_clear(
            clipboard.clone(),
            writes.clone(),
            held.clone(),
            Zeroizing::new("D7KQ-M2XP".into()),
            Duration::from_secs(60),
        )
        .unwrap();
        clipboard.write_text("mine").unwrap();
        clear_now(clipboard.as_ref(), &held);
        assert_eq!(clipboard.read_text().as_deref(), Some("mine"));
        assert!(held.lock().unwrap().is_none());

        // Nothing copied: nothing is touched.
        clear_now(clipboard.as_ref(), &held);
        assert_eq!(clipboard.read_text().as_deref(), Some("mine"));
    }

    // Review, info: a clearing that runs while the next code is copied never drops that code
    // from `held`, so ending the app still takes it off the clipboard.
    #[test]
    fn a_clearing_never_drops_the_next_copy() {
        let clipboard = Arc::new(Fake::default());
        let writes = Arc::new(AtomicU64::new(0));
        let held = HeldSecret::default();
        *clipboard.slow_read.lock().unwrap() = Some(Duration::from_millis(200));
        copy_and_clear(
            clipboard.clone(),
            writes.clone(),
            held.clone(),
            Zeroizing::new("first".into()),
            SHORT,
        )
        .unwrap();
        // The first clearing is busy reading the clipboard when the second code is copied.
        std::thread::sleep(SHORT + Duration::from_millis(60));
        copy_and_clear(
            clipboard.clone(),
            writes.clone(),
            held.clone(),
            Zeroizing::new("second".into()),
            Duration::from_secs(60),
        )
        .unwrap();
        std::thread::sleep(WAIT);
        assert_eq!(
            held.lock().unwrap().as_ref().map(|h| h.as_str().to_owned()),
            Some("second".to_owned())
        );
        *clipboard.slow_read.lock().unwrap() = None;
        clear_now(clipboard.as_ref(), &held);
        assert_eq!(clipboard.read_text().as_deref(), Some(""));
    }

    #[test]
    fn the_held_secret_goes_with_its_minute() {
        let clipboard = Arc::new(Fake::default());
        let held = HeldSecret::default();
        copy_and_clear(
            clipboard.clone(),
            Arc::new(AtomicU64::new(0)),
            held.clone(),
            Zeroizing::new("code".into()),
            SHORT,
        )
        .unwrap();
        assert!(held.lock().unwrap().is_some());
        std::thread::sleep(WAIT);
        assert!(held.lock().unwrap().is_none());
        assert!(still_holds(Some("a"), "a"));
        assert!(!still_holds(Some("b"), "a"));
        assert!(!still_holds(None, "a"));
    }

    #[test]
    fn only_links_and_codes_are_read() {
        for good in [
            "hangar-drive://pair#AQIDBA",
            "  HANGAR-DRIVE://recover#AQID  ",
            "hangar-drive://join#AQ_d-x",
            "https://drive.example/join#abc.def",
            "http://localhost:8080/join#CQkJ",
            "D7KQ-M2XP-9H4T-RW8C-ZB3N-F6JA-Q1VE-K5SY",
            "d7kq m2xp 9h4t rw8c zb3n f6ja q1ve k5sy",
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

    // Security review N10: only the exact code format and the link prefixes pass; text that
    // merely contains a link part or looks a bit like a code stays on the clipboard.
    #[test]
    fn near_misses_are_not_read() {
        for bad in [
            // Codes of the wrong shape: too few or too many groups, a wrong group length, a
            // letter outside Crockford's alphabet, mixed or doubled separators.
            "d7kq m2xp 9h4t rw8c",
            "PIN 1234-5678",
            "4711-0815-2342-1337",
            "D7KQ-M2XP-9H4T-RW8C-ZB3N-F6JA-Q1VE-K5SY-ABCD",
            "D7KQM-2XP-9H4T-RW8C-ZB3N-F6JA-Q1VE-K5SY",
            "D7KQ-M2XP-9H4T-RW8C-ZB3N-F6JA-Q1VE-K5SU",
            "D7KQ-M2XP-9H4T-RW8C ZB3N-F6JA-Q1VE-K5SY",
            "D7KQ  M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY",
            "ab12 cd34 ef56 gh78 jk90 mn12 pq34 rs5o",
            // Links that only contain a prefix or a path part.
            "see https://drive.example/join#abc",
            "https://evil.example/x?/join#abc",
            "https://user@drive.example/join#abc",
            "https://drive.example/join#abc def",
            "https://drive.example/join#",
            "https://drive.example/join#abc!x",
            "hangar-drive://pair#",
            "hangar-drive://pair#AQ ID",
            "hangar-drive://pair#AQID?x=1",
            "hangar-drive://other#AQID",
            "ftp://drive.example/join#abc",
        ] {
            assert_eq!(readable(bad), "", "{bad:?}");
        }
    }
}
