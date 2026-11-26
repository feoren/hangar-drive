//! The cross-platform name policy (ADR 0001, section 7): comparison keys, collisions, names
//! Windows cannot hold, and the built-in ignore list.
//!
//! These rules are part of the protocol and change only with [`crate::PROTOCOL_VERSION`], so
//! every device decides the same and no device uploads what another ignores.
//!
//! - **Names are UTF-8.** The exact bytes from disk are kept in the directory node (a macOS
//!   name may be decomposed). A name that is not valid UTF-8 (possible on Linux) cannot be
//!   compared in NFC and is marked "cannot sync on this device" by the client (conclusion of
//!   this crate; the ADR is silent on it).
//! - **Comparison key:** the name in NFC. Two entries of one directory never share it.
//! - **Case keys:** two names with different comparison keys collide by case as soon as **any**
//!   of three keys of their comparison keys is equal ([`CaseKeys`]), each normalized to NFC
//!   again:
//!   1. [`case_key`]: Unicode's full lowercase mapping (Rust's `str::to_lowercase`);
//!   2. [`fold_key`]: full Unicode case folding (CaseFolding.txt, status C and F, through
//!      `unicase`), which joins `ſ` with `s`, `ς` with `σ`, `µ` with `μ`, `ϐ` with `β`;
//!   3. [`upper_key`]: per character the simple uppercase (`char::to_uppercase` where it gives
//!      exactly one character, the character itself otherwise), which joins `ı` with `i`, as
//!      NTFS's upcase table does.
//!
//!   Case-insensitive file systems differ in detail (NTFS uses a per-volume upcase table, APFS
//!   its own folding) `[UNVERIFIED: exact tables per Windows and macOS version]`. Three keys
//!   together call more names equal than any one file system; a false collision only makes a
//!   conflict copy, while a missed one would let two names land on one file. False positives
//!   are allowed, false negatives are not.
//! - **Display names** (device, folder and pairing names, [`check_display_name`]): no control
//!   characters, no format characters (General Category Cf, which holds every bidirectional
//!   control), no line or paragraph separators (Zl, Zp), so a name cannot reorder or hide the
//!   text around it in a prompt such as `Add device <name>?`. A name also needs a visible
//!   character and must not start or end with white space: a blank name, a name made only of
//!   Hangul fillers ([`FILLER_CHARACTERS`]) or a name with a padded edge would look empty, or
//!   like the name of another device, in that prompt.
//! - **Windows:** [`windows_problem`] says why Windows cannot hold a name. The tree itself
//!   allows `\` and `:` (Linux and macOS can hold them), so the sync engine must call
//!   [`windows_problem`] on every name **before** it builds a local path from it on Windows:
//!   otherwise a name such as `..\x` or `C:x` would be read as a path. A name it refuses is
//!   marked "cannot sync on this device" and never renamed silently.

use thiserror::Error;
use unicase::UniCase;
use unicode_normalization::UnicodeNormalization;

/// The longest name in UTF-8 bytes. Windows allows 255 UTF-16 units per name, which are at
/// most 765 bytes of UTF-8; Linux allows 255 bytes. The protocol bound is above both.
pub const MAX_NAME_LEN: usize = 1024;

/// The reserved directory at the sync root (root marker, temporary downloads). Never synced.
pub const RESERVED_ROOT_DIR: &str = ".hangar-drive";

/// Why a name can never be part of a tree, on any platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NameError {
    /// The empty name.
    #[error("the name is empty")]
    Empty,
    /// `.` or `..`.
    #[error("the name is a dot name")]
    DotName,
    /// A `/`, the path separator everywhere.
    #[error("the name contains a slash")]
    Slash,
    /// A NUL character, which no file system allows.
    #[error("the name contains a NUL character")]
    Nul,
    /// Longer than [`MAX_NAME_LEN`] bytes.
    #[error("the name is too long")]
    TooLong,
}

/// Checks that `name` may be an entry of a directory node.
pub fn check_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }
    if name == "." || name == ".." {
        return Err(NameError::DotName);
    }
    if name.contains('/') {
        return Err(NameError::Slash);
    }
    if name.contains('\0') {
        return Err(NameError::Nul);
    }
    Ok(())
}

/// The comparison key of a name: its NFC form.
pub fn comparison_key(name: &str) -> String {
    name.nfc().collect()
}

/// The case key of a name: the comparison key in lowercase, in NFC again (module docs).
pub fn case_key(name: &str) -> String {
    comparison_key(name).to_lowercase().nfc().collect()
}

/// The fold key of a name: the comparison key under full Unicode case folding, in NFC again
/// (module docs).
pub fn fold_key(name: &str) -> String {
    UniCase::unicode(comparison_key(name))
        .to_folded_case()
        .nfc()
        .collect()
}

/// The upper key of a name: per character of the comparison key its simple uppercase, or the
/// character itself where the uppercase has more than one character, in NFC again (module
/// docs).
pub fn upper_key(name: &str) -> String {
    comparison_key(name)
        .chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(single), None) => single,
                _ => c,
            }
        })
        .collect::<String>()
        .nfc()
        .collect()
}

/// The three case keys of a name. Two names collide by case when any of the three is equal, so
/// a directory index keeps one map per key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CaseKeys {
    /// [`case_key`].
    pub lower: String,
    /// [`fold_key`].
    pub fold: String,
    /// [`upper_key`].
    pub upper: String,
}

impl CaseKeys {
    /// The keys of `name`.
    pub fn of(name: &str) -> Self {
        Self {
            lower: case_key(name),
            fold: fold_key(name),
            upper: upper_key(name),
        }
    }

    /// Whether any key is shared.
    pub fn collides(&self, other: &CaseKeys) -> bool {
        self.lower == other.lower || self.fold == other.fold || self.upper == other.upper
    }
}

/// How two different names of one directory collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collision {
    /// Different bytes, the same comparison key (for example composed and decomposed `é`).
    Normalization,
    /// Different comparison keys that differ only in case.
    Case,
}

/// Whether two names of one directory collide. Equal bytes are the same name, not a collision.
pub fn collision(a: &str, b: &str) -> Option<Collision> {
    if a == b {
        return None;
    }
    let (key_a, key_b) = (comparison_key(a), comparison_key(b));
    if key_a == key_b {
        return Some(Collision::Normalization);
    }
    if CaseKeys::of(&key_a).collides(&CaseKeys::of(&key_b)) {
        return Some(Collision::Case);
    }
    None
}

/// Code point ranges of General Category Cf (format characters, every bidirectional control
/// among them), Zl and Zp, Unicode 16.0. Generated from Python's `unicodedata` (Unicode 16.0);
/// `test_vectors.py` recomputes the list and compares it (vector `name.format_ranges`). A format
/// character added by a later Unicode version passes until this table is updated; it can then
/// only make a name look odd, not move or hide text that this table knows.
pub const FORMAT_CHARACTER_RANGES: [(u32, u32); 23] = [
    (0x00ad, 0x00ad),
    (0x0600, 0x0605),
    (0x061c, 0x061c),
    (0x06dd, 0x06dd),
    (0x070f, 0x070f),
    (0x0890, 0x0891),
    (0x08e2, 0x08e2),
    (0x180e, 0x180e),
    (0x200b, 0x200f),
    (0x2028, 0x202e),
    (0x2060, 0x2064),
    (0x2066, 0x206f),
    (0xfeff, 0xfeff),
    (0xfff9, 0xfffb),
    (0x110bd, 0x110bd),
    (0x110cd, 0x110cd),
    (0x13430, 0x1343f),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0001, 0xe0001),
    (0xe0020, 0xe007f),
    // The bidirectional controls, listed again on their own so the rule does not depend on
    // their category: ALM, LRM, RLM, LRE to RLO, LRI to PDI.
    (0x200e, 0x200f),
    (0x2066, 0x2069),
];

/// Whether `c` is a format character, a line or paragraph separator or a bidirectional control
/// ([`FORMAT_CHARACTER_RANGES`]).
pub fn is_format_character(c: char) -> bool {
    let c = u32::from(c);
    FORMAT_CHARACTER_RANGES
        .iter()
        .any(|&(low, high)| (low..=high).contains(&c))
}

/// Characters that render as nothing in most fonts but are letters (General Category Lo), so
/// neither [`char::is_whitespace`] nor [`is_format_character`] catches them: the Hangul fillers
/// U+115F, U+1160 and U+3164 and the halfwidth U+FFA0. A display name made only of these and
/// white space is blank. Inside a name they stay allowed, since Korean text may use them.
pub const FILLER_CHARACTERS: [char; 4] = ['\u{115f}', '\u{1160}', '\u{3164}', '\u{ffa0}'];

/// Why a device, folder or pairing name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DisplayNameError {
    /// The empty name.
    #[error("the name is empty")]
    Empty,
    /// More bytes than allowed.
    #[error("the name is too long")]
    TooLong,
    /// A control character (General Category Cc).
    #[error("the name contains a control character")]
    Control,
    /// A format character, line or paragraph separator or bidirectional control.
    #[error("the name contains an invisible formatting character")]
    Format,
    /// Only white space and [`FILLER_CHARACTERS`]: nothing visible.
    #[error("the name has no visible character")]
    Blank,
    /// White space at the start or the end.
    #[error("the name starts or ends with white space")]
    EdgeWhitespace,
}

/// Checks a device, folder or pairing name of at most `max_len` UTF-8 bytes (module docs).
pub fn check_display_name(name: &str, max_len: usize) -> Result<(), DisplayNameError> {
    if name.is_empty() {
        return Err(DisplayNameError::Empty);
    }
    if name.len() > max_len {
        return Err(DisplayNameError::TooLong);
    }
    if name.chars().any(char::is_control) {
        return Err(DisplayNameError::Control);
    }
    if name.chars().any(is_format_character) {
        return Err(DisplayNameError::Format);
    }
    if name
        .chars()
        .all(|c| c.is_whitespace() || FILLER_CHARACTERS.contains(&c))
    {
        return Err(DisplayNameError::Blank);
    }
    // Refused, not trimmed: the name is signed and sealed as given, so every device shows the
    // bytes the owner entered. Callers trim user input before they submit it.
    if name.starts_with(char::is_whitespace) || name.ends_with(char::is_whitespace) {
        return Err(DisplayNameError::EdgeWhitespace);
    }
    Ok(())
}

/// The most UTF-16 code units of one name on Windows (NTFS and the Win32 API).
pub const MAX_WINDOWS_NAME_UNITS: usize = 255;

/// Why Windows cannot hold a name. The client marks such an entry "cannot sync on this
/// device" and never renames it silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WindowsNameProblem {
    /// A reserved device name, also with an extension (`CON`, `nul.txt`, `COM1.tar.gz`).
    #[error("the name is reserved on Windows")]
    Reserved,
    /// One of `< > : " / \ | ? *`.
    #[error("the name contains a character Windows does not allow: {0:?}")]
    ForbiddenCharacter(char),
    /// A control character (U+0001 to U+001F; U+0000 is refused everywhere).
    #[error("the name contains a control character")]
    ControlCharacter,
    /// A trailing dot or space, which Windows strips.
    #[error("the name ends with a dot or a space")]
    TrailingDotOrSpace,
    /// More than [`MAX_WINDOWS_NAME_UNITS`] UTF-16 code units.
    #[error("the name is too long for Windows")]
    TooLong,
}

/// Device names Windows reserves in every directory. `COM` and `LPT` take the digits 0 to 9
/// and the superscript digits ¹ ² ³ `[UNVERIFIED: Microsoft documents COM0 and LPT0 as
/// reserved too; behavior on every Windows version not tested]`. Refusing a name Windows would
/// accept only marks it "cannot sync on this device". `CONIN$` and `CONOUT$` are console
/// devices.
const RESERVED_STEMS: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];

fn is_reserved_stem(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    if RESERVED_STEMS.contains(&upper.as_str()) {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(rest) = upper.strip_prefix(prefix) {
            let mut chars = rest.chars();
            if let (Some(digit), None) = (chars.next(), chars.next()) {
                if matches!(digit, '0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}') {
                    return true;
                }
            }
        }
    }
    false
}

/// What keeps Windows from holding `name`, or `None` when it can. The sync engine calls it
/// before it builds any local path from a name on Windows (module docs).
///
/// A reserved name counts with any extension: the part before the first dot, with trailing
/// spaces removed, is compared without regard to ASCII case (`con .txt` is reserved too).
pub fn windows_problem(name: &str) -> Option<WindowsNameProblem> {
    if name.encode_utf16().count() > MAX_WINDOWS_NAME_UNITS {
        return Some(WindowsNameProblem::TooLong);
    }
    if let Some(c) = name
        .chars()
        .find(|c| matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
    {
        return Some(WindowsNameProblem::ForbiddenCharacter(c));
    }
    if name.chars().any(|c| ('\u{1}'..='\u{1f}').contains(&c)) {
        return Some(WindowsNameProblem::ControlCharacter);
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some(WindowsNameProblem::TrailingDotOrSpace);
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    if is_reserved_stem(stem) {
        return Some(WindowsNameProblem::Reserved);
    }
    None
}

/// Whole names on the ignore list, compared without regard to ASCII case, since Windows and
/// macOS create them in either spelling.
const IGNORED_NAMES: [&str; 9] = [
    "desktop.ini",
    "thumbs.db",
    "ehthumbs.db",
    ".ds_store",
    "$recycle.bin",
    "system volume information",
    ".trashes",
    ".spotlight-v100",
    ".fseventsd",
];

/// Whether `name` is on the built-in ignore list and is never added to a tree. `at_root` is
/// true for entries directly in the sync root, where [`RESERVED_ROOT_DIR`] is ignored too.
///
/// The list (ADR 0001, section 7): `desktop.ini`, `Thumbs.db`, `ehthumbs.db`, `.DS_Store`,
/// names starting with `._`, `Icon\r`, `$RECYCLE.BIN`, `System Volume Information`,
/// `.Trashes`, `.Spotlight-V100`, `.fseventsd`, Office owner files `~$*`, Office temporary
/// files `~*.tmp`, LibreOffice lock files `.~lock.*#`, and `.hangar-drive` at the sync root.
/// Whole names ignore ASCII case; patterns match exactly, except the `.tmp` ending, which
/// ignores case like the Office programs that write it.
pub fn is_ignored(name: &str, at_root: bool) -> bool {
    let lower = name.to_ascii_lowercase();
    if IGNORED_NAMES.contains(&lower.as_str()) {
        return true;
    }
    if at_root && lower == RESERVED_ROOT_DIR {
        return true;
    }
    if name == "Icon\r" {
        return true;
    }
    if name.starts_with("._") || name.starts_with("~$") {
        return true;
    }
    if name.starts_with('~') && lower.ends_with(".tmp") && name.len() > "~.tmp".len() {
        return true;
    }
    if name.starts_with(".~lock.") && name.ends_with('#') && name.len() > ".~lock.#".len() {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPOSED: &str = "caf\u{e9}";
    const DECOMPOSED: &str = "cafe\u{301}";

    #[test]
    fn protocol_names_refuse_the_impossible() {
        assert_eq!(check_name("a.txt"), Ok(()));
        assert_eq!(check_name(""), Err(NameError::Empty));
        assert_eq!(check_name("."), Err(NameError::DotName));
        assert_eq!(check_name(".."), Err(NameError::DotName));
        assert_eq!(check_name("..."), Ok(()));
        assert_eq!(check_name("a/b"), Err(NameError::Slash));
        assert_eq!(check_name("a\0b"), Err(NameError::Nul));
        assert_eq!(check_name(&"a".repeat(MAX_NAME_LEN)), Ok(()));
        assert_eq!(
            check_name(&"a".repeat(MAX_NAME_LEN + 1)),
            Err(NameError::TooLong)
        );
        // Windows-only problems are not protocol errors: Linux can hold these.
        assert_eq!(check_name("a:b"), Ok(()));
        assert_eq!(check_name("CON"), Ok(()));
    }

    #[test]
    fn comparison_key_is_nfc() {
        assert_eq!(comparison_key(DECOMPOSED), COMPOSED);
        assert_eq!(comparison_key(COMPOSED), COMPOSED);
        // Hangul syllable from jamo.
        assert_eq!(comparison_key("\u{1100}\u{1161}"), "\u{ac00}");
        // NFC, not NFKC: compatibility characters stay.
        assert_eq!(comparison_key("\u{fb01}"), "\u{fb01}");
    }

    #[test]
    fn collisions_by_normalization_and_case() {
        assert_eq!(
            collision(COMPOSED, DECOMPOSED),
            Some(Collision::Normalization)
        );
        assert_eq!(collision("Report.txt", "report.TXT"), Some(Collision::Case));
        assert_eq!(collision("CAF\u{c9}", DECOMPOSED), Some(Collision::Case));
        assert_eq!(collision("\u{3a3}", "\u{3c3}"), Some(Collision::Case));
        assert_eq!(collision("a", "a"), None);
        assert_eq!(collision("a", "b"), None);
        assert_eq!(collision("a", "a "), None);
        assert_eq!(case_key("\u{c4}BC"), "\u{e4}bc");
    }

    #[test]
    fn case_collisions_that_lowercase_alone_misses() {
        // long s / s, dotless i / i, final sigma / sigma, micro sign / mu, curled beta / beta.
        for (a, b) in [
            ("\u{17f}", "s"),
            ("\u{131}", "i"),
            ("\u{3c2}", "\u{3c3}"),
            ("\u{b5}", "\u{3bc}"),
            ("\u{3d0}", "\u{3b2}"),
            ("Ma\u{17f}\u{17f}e.txt", "MASSE.txt"),
            ("f\u{131}le", "FILE"),
        ] {
            assert_eq!(collision(a, b), Some(Collision::Case), "{a:?} / {b:?}");
            assert_eq!(collision(b, a), Some(Collision::Case), "{b:?} / {a:?}");
        }
        // Which key catches which pair.
        assert_eq!(fold_key("\u{17f}"), "s");
        assert_eq!(fold_key("\u{3c2}"), "\u{3c3}");
        assert_eq!(fold_key("\u{b5}"), "\u{3bc}");
        assert_eq!(fold_key("\u{3d0}"), "\u{3b2}");
        assert_eq!(
            fold_key("Stra\u{df}e"),
            "strasse",
            "full folding of sharp s"
        );
        assert_eq!(upper_key("\u{131}"), "I");
        assert_eq!(upper_key("i"), "I");
        assert_eq!(
            upper_key("\u{df}"),
            "\u{df}",
            "a multi-character uppercase keeps the character"
        );
        assert_ne!(case_key("\u{131}"), case_key("i"));
        // Different letters stay different.
        assert_eq!(collision("\u{3c3}", "s"), None);
        assert_eq!(collision("\u{131}", "j"), None);
        let keys = CaseKeys::of("\u{17f}");
        assert!(keys.collides(&CaseKeys::of("S")));
        assert!(!keys.collides(&CaseKeys::of("t")));
    }

    #[test]
    fn display_names_refuse_invisible_and_reordering_characters() {
        assert_eq!(check_display_name("Laptop", 128), Ok(()));
        assert_eq!(check_display_name("Caf\u{e9} \u{1f600}", 128), Ok(()));
        assert_eq!(check_display_name("", 128), Err(DisplayNameError::Empty));
        assert_eq!(check_display_name("abc", 2), Err(DisplayNameError::TooLong));
        assert_eq!(
            check_display_name("a\nb", 128),
            Err(DisplayNameError::Control)
        );
        assert_eq!(
            check_display_name("a\u{7f}b", 128),
            Err(DisplayNameError::Control)
        );
        for c in [
            '\u{ad}',
            '\u{61c}',
            '\u{200b}',
            '\u{200d}',
            '\u{200e}',
            '\u{200f}',
            '\u{2028}',
            '\u{2029}',
            '\u{202a}',
            '\u{202e}',
            '\u{2066}',
            '\u{2069}',
            '\u{feff}',
            '\u{e0041}',
        ] {
            assert_eq!(
                check_display_name(&format!("ab{c}cd"), 128),
                Err(DisplayNameError::Format),
                "{c:?}"
            );
        }
        assert!(!is_format_character('a'));
        assert!(!is_format_character('\u{2030}'));
    }

    #[test]
    fn display_names_need_a_visible_character_and_no_padded_edge() {
        for name in [
            " ",
            "   ",
            "\u{a0}",
            "\u{3000}",
            "\u{3164}",
            "\u{115f}",
            "\u{1160}",
            "\u{ffa0}",
            "\u{3164}\u{3164}",
            "\u{3164} \u{ffa0}",
        ] {
            assert_eq!(
                check_display_name(name, 128),
                Err(DisplayNameError::Blank),
                "{name:?}"
            );
        }
        for name in [
            " Laptop",
            "Laptop ",
            " Laptop ",
            "\u{a0}Laptop",
            "Laptop\u{3000}",
            "Laptop\u{2003}",
        ] {
            assert_eq!(
                check_display_name(name, 128),
                Err(DisplayNameError::EdgeWhitespace),
                "{name:?}"
            );
        }
        // White space and fillers inside a name, or a filler next to a visible character, stay
        // allowed.
        for name in [
            "My Laptop",
            "a\u{3000}b",
            "\u{d55c}\u{3164}",
            "\u{3164}a",
            "x",
        ] {
            assert_eq!(check_display_name(name, 128), Ok(()), "{name:?}");
        }
        // A tab or a line break is a control character before it is white space.
        assert_eq!(
            check_display_name("\t", 128),
            Err(DisplayNameError::Control)
        );
        assert_eq!(
            check_display_name("Laptop\n", 128),
            Err(DisplayNameError::Control)
        );
    }

    #[test]
    fn windows_reserved_names_also_with_extensions() {
        for name in [
            "CON",
            "con",
            "Con.txt",
            "NUL.tar.gz",
            "aux",
            "PRN.",
            "COM1",
            "com9.log",
            "LPT3",
            "COM\u{b9}",
            "lpt\u{b2}.txt",
            "CONIN$",
            "conout$.x",
            "con .txt",
            "COM0",
            "lpt0.txt",
        ] {
            assert!(windows_problem(name).is_some(), "{name:?} must be refused");
        }
        assert_eq!(
            windows_problem("nul.txt"),
            Some(WindowsNameProblem::Reserved)
        );
        assert_eq!(windows_problem("COM1"), Some(WindowsNameProblem::Reserved));
        for name in [
            "CONSOLE",
            "COM10",
            "LPT",
            "xCON",
            "con_",
            "AUX1",
            ".con",
            "a.con",
            "COM\u{b4}",
        ] {
            assert_eq!(windows_problem(name), None, "{name:?} must be allowed");
        }
    }

    #[test]
    fn windows_forbidden_characters_control_and_trailing() {
        for c in ['<', '>', ':', '"', '\\', '|', '?', '*', '/'] {
            assert_eq!(
                windows_problem(&format!("a{c}b")),
                Some(WindowsNameProblem::ForbiddenCharacter(c))
            );
        }
        assert_eq!(
            windows_problem("a\u{1}b"),
            Some(WindowsNameProblem::ControlCharacter)
        );
        assert_eq!(
            windows_problem("tab\there"),
            Some(WindowsNameProblem::ControlCharacter)
        );
        assert_eq!(windows_problem("a\u{7f}b"), None);
        assert_eq!(
            windows_problem("name."),
            Some(WindowsNameProblem::TrailingDotOrSpace)
        );
        assert_eq!(
            windows_problem("name "),
            Some(WindowsNameProblem::TrailingDotOrSpace)
        );
        assert_eq!(windows_problem(" name"), None);
        assert_eq!(windows_problem(".gitignore"), None);
        assert_eq!(windows_problem(COMPOSED), None);
    }

    #[test]
    fn windows_names_above_255_utf16_units_cannot_sync() {
        assert_eq!(windows_problem(&"a".repeat(255)), None);
        assert_eq!(
            windows_problem(&"a".repeat(256)),
            Some(WindowsNameProblem::TooLong)
        );
        // 128 characters outside the BMP are 256 UTF-16 units but only 128 chars.
        let astral = "\u{1f600}".repeat(128);
        assert_eq!(windows_problem(&astral), Some(WindowsNameProblem::TooLong));
        assert_eq!(windows_problem(&"\u{1f600}".repeat(127)), None);
        // 255 units of 3-byte characters are within the protocol's byte bound.
        assert!(check_name(&"\u{20ac}".repeat(255)).is_ok());
        assert_eq!(windows_problem(&"\u{20ac}".repeat(255)), None);
    }

    #[test]
    fn ignore_list() {
        for name in [
            "desktop.ini",
            "Desktop.ini",
            "Thumbs.db",
            "thumbs.db",
            "ehthumbs.db",
            ".DS_Store",
            "._photo.jpg",
            "Icon\r",
            "$RECYCLE.BIN",
            "System Volume Information",
            ".Trashes",
            ".Spotlight-V100",
            ".fseventsd",
            "~$report.docx",
            "~WRL0001.tmp",
            "~abc.TMP",
            ".~lock.report.odt#",
        ] {
            assert!(is_ignored(name, false), "{name:?} must be ignored");
        }
        assert!(is_ignored(".hangar-drive", true));
        assert!(!is_ignored(".hangar-drive", false));
        for name in [
            "Icon",
            "icon\r",
            "report.tmp",
            "~",
            "~.tmp",
            ".~lock.#",
            ".~lock.a",
            "_photo.jpg",
            ".DS_Store2",
            "thumbs.db.bak",
            "notes.txt",
        ] {
            assert!(!is_ignored(name, true), "{name:?} must be synced");
        }
    }
}
