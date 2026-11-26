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
//!   character ([`is_visible`]: a letter, number, punctuation or symbol that is not one of the
//!   [`FILLER_CHARACTERS`]) and must not start or end with white space or an
//!   [`is_edge_filler`] character: a blank name, a name made only of fillers or a name with a
//!   padded edge would look empty, or like the name of another device, in that prompt.
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

/// Code points HFS+ ignores when it compares names (security review N15): ZWNJ, ZWJ, LRM and
/// RLM (U+200C to U+200F), the embedding and override controls U+202A to U+202E, the
/// deprecated format controls U+206A to U+206F and the byte order mark U+FEFF. Two names that
/// differ only in them are one file on HFS+ (Apple, Technical Note TN1150, "Unicode Subtleties"
/// and its case folding table [UNVERIFIED: taken from TN1150, not measured on a volume]), so
/// the case keys drop them and such names collide by case: a false collision only makes a
/// conflict copy. The comparison key keeps them, since the exact bytes stay the name.
pub fn is_hfs_ignorable(c: char) -> bool {
    matches!(
        u32::from(c),
        0x200c..=0x200f | 0x202a..=0x202e | 0x206a..=0x206f | 0xfeff
    )
}

/// The comparison key without the [`is_hfs_ignorable`] code points, the start of every case key.
fn case_base(name: &str) -> String {
    comparison_key(name)
        .chars()
        .filter(|c| !is_hfs_ignorable(*c))
        .collect()
}

/// The case key of a name: the comparison key without the code points HFS+ ignores, in
/// lowercase, in NFC again (module docs).
pub fn case_key(name: &str) -> String {
    case_base(name).to_lowercase().nfc().collect()
}

/// The fold key of a name: the comparison key under full Unicode case folding, in NFC again
/// (module docs).
pub fn fold_key(name: &str) -> String {
    UniCase::unicode(case_base(name))
        .to_folded_case()
        .nfc()
        .collect()
}

/// The upper key of a name: per character of the comparison key its simple uppercase, or the
/// character itself where the uppercase has more than one character, in NFC again (module
/// docs).
pub fn upper_key(name: &str) -> String {
    case_base(name)
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

/// Characters that render as nothing in most fonts but are letters or symbols (General
/// Category Lo, So), so neither [`char::is_whitespace`] nor [`is_format_character`] catches
/// them: the Hangul fillers U+115F, U+1160 and U+3164, the halfwidth U+FFA0 and the blank
/// Braille pattern U+2800 (security review N12). They never count as visible, and a display
/// name may not start or end with one. Inside a name they stay allowed, since Korean text may
/// use the fillers.
pub const FILLER_CHARACTERS: [char; 5] =
    ['\u{115f}', '\u{1160}', '\u{3164}', '\u{ffa0}', '\u{2800}'];

/// Whether `c` makes a display name visible (security review N12): a letter, number,
/// punctuation or symbol (General Category L, N, P, S), not one of the [`FILLER_CHARACTERS`].
/// Decided by what it is not: white space, a control or format character, a combining mark
/// (General Category M, which holds the combining grapheme joiner U+034F and every variation
/// selector), a private use character (Co) or a default ignorable code point
/// ([`DEFAULT_IGNORABLE_RANGES`], reserved ones included). Any other unassigned code point (Cn)
/// counts as visible until the Unicode tables of `unicode-normalization` and
/// [`FORMAT_CHARACTER_RANGES`] know it, as for the format characters; a renderer shows it as a
/// replacement glyph, so it can only look odd, not blank out a known name.
pub fn is_visible(c: char) -> bool {
    !c.is_whitespace()
        && !c.is_control()
        && !is_format_character(c)
        && !unicode_normalization::char::is_combining_mark(c)
        && !FILLER_CHARACTERS.contains(&c)
        && !is_private_use(c)
        && !is_default_ignorable(c)
}

fn is_private_use(c: char) -> bool {
    matches!(
        u32::from(c),
        0xe000..=0xf8ff | 0xf0000..=0xffffd | 0x10_0000..=0x10_fffd
    )
}

/// Whether `c` pads the edge of a display name (security review N12): white space, the
/// [`FILLER_CHARACTERS`], the combining grapheme joiner U+034F and the variation selectors
/// U+FE00 to U+FE0F and U+E0100 to U+E01EF. A variation selector right after a visible
/// character belongs to it (U+2764 U+FE0F is one emoji) and is no edge.
pub fn is_edge_filler(c: char) -> bool {
    c.is_whitespace()
        || FILLER_CHARACTERS.contains(&c)
        || c == '\u{34f}'
        || is_variation_selector(c)
        || is_default_ignorable(c)
}

/// The code points Unicode marks `Default_Ignorable_Code_Point` (DerivedCoreProperties.txt,
/// Unicode 15.1), unassigned ones included: a renderer shows them as nothing, whether or not
/// its tables know them yet. Most are format characters, fillers, the combining grapheme
/// joiner or variation selectors and refused or handled above already; the others are the
/// Khmer inherent vowels U+17B4 and U+17B5, the Mongolian free variation selectors U+180B to
/// U+180D and U+180F, and the reserved U+2065, U+FFF0 to U+FFF8 and the rest of U+E0000 to
/// U+E0FFF. A name made only of them would look blank, and one at the edge pads it.
pub const DEFAULT_IGNORABLE_RANGES: [(u32, u32); 17] = [
    (0x00ad, 0x00ad),
    (0x034f, 0x034f),
    (0x061c, 0x061c),
    (0x115f, 0x1160),
    (0x17b4, 0x17b5),
    (0x180b, 0x180f),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x206f),
    (0x3164, 0x3164),
    (0xfe00, 0xfe0f),
    (0xfeff, 0xfeff),
    (0xffa0, 0xffa0),
    (0xfff0, 0xfff8),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0000, 0xe0fff),
];

/// Whether `c` is in [`DEFAULT_IGNORABLE_RANGES`].
pub fn is_default_ignorable(c: char) -> bool {
    let c = u32::from(c);
    DEFAULT_IGNORABLE_RANGES
        .iter()
        .any(|&(low, high)| (low..=high).contains(&c))
}

fn is_variation_selector(c: char) -> bool {
    matches!(u32::from(c), 0xfe00..=0xfe0f | 0xe0100..=0xe01ef)
}

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
    /// No [`is_visible`] character.
    #[error("the name has no visible character")]
    Blank,
    /// White space or another [`is_edge_filler`] character at the start or the end.
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
    if !name.chars().any(is_visible) {
        return Err(DisplayNameError::Blank);
    }
    // Refused, not trimmed: the name is signed and sealed as given, so every device shows the
    // bytes the owner entered. Callers trim user input before they submit it. Trailing
    // variation selectors right after a visible character belong to it (an emoji).
    let first = name.chars().next();
    let base = name.trim_end_matches(is_variation_selector);
    let last = match base.chars().next_back() {
        Some(c) if base.len() < name.len() && is_visible(c) => Some(c),
        _ => name.chars().next_back(),
    };
    if first.is_some_and(is_edge_filler) || last.is_some_and(is_edge_filler) {
        return Err(DisplayNameError::EdgeWhitespace);
    }
    Ok(())
}

/// Letters of Latin, Cyrillic and Greek that look like a basic Latin letter, and two digits,
/// each with that letter: a small part of the single code point mappings of `confusables.txt` of
/// Unicode Technical Standard #39, "Unicode Security Mechanisms" (Unicode 16.0), restricted to
/// the three scripts device names of this app are most likely written in, plus the digits 0 and
/// 1, which the standard maps to `O` and `l`. The full table has more than 6,000 entries and
/// changes with every Unicode version; the device name check only has to catch the obvious
/// look-alikes in a short list of names one person gave their own devices. [UNVERIFIED: entries
/// chosen from the standard's table and the glyphs of common fonts, not checked line by line
/// against the file.]
///
/// Capital and small letters are listed separately, since a capital look-alike (Cyrillic `В`
/// for `B`) folds to a small letter that looks like nothing Latin (`в`): [`display_skeletons`]
/// applies the table once before and once after case folding.
pub const HOMOGLYPHS: [(char, char); 66] = [
    // Cyrillic capitals.
    ('\u{0410}', 'A'),
    ('\u{0412}', 'B'),
    ('\u{0415}', 'E'),
    ('\u{041A}', 'K'),
    ('\u{041C}', 'M'),
    ('\u{041D}', 'H'),
    ('\u{041E}', 'O'),
    ('\u{0420}', 'P'),
    ('\u{0421}', 'C'),
    ('\u{0422}', 'T'),
    ('\u{0423}', 'Y'),
    ('\u{0425}', 'X'),
    ('\u{0405}', 'S'),
    ('\u{0406}', 'I'),
    ('\u{0408}', 'J'),
    ('\u{051A}', 'Q'),
    ('\u{051C}', 'W'),
    // Cyrillic small letters.
    ('\u{0430}', 'a'),
    ('\u{0435}', 'e'),
    ('\u{043E}', 'o'),
    ('\u{0440}', 'p'),
    ('\u{0441}', 'c'),
    ('\u{0443}', 'y'),
    ('\u{0445}', 'x'),
    ('\u{0455}', 's'),
    ('\u{0456}', 'i'),
    ('\u{0458}', 'j'),
    ('\u{04BB}', 'h'),
    ('\u{0501}', 'd'),
    ('\u{051B}', 'q'),
    ('\u{051D}', 'w'),
    ('\u{04CF}', 'l'),
    // Greek capitals.
    ('\u{0391}', 'A'),
    ('\u{0392}', 'B'),
    ('\u{0395}', 'E'),
    ('\u{0396}', 'Z'),
    ('\u{0397}', 'H'),
    ('\u{0399}', 'I'),
    ('\u{039A}', 'K'),
    ('\u{039C}', 'M'),
    ('\u{039D}', 'N'),
    ('\u{039F}', 'O'),
    ('\u{03A1}', 'P'),
    ('\u{03A4}', 'T'),
    ('\u{03A5}', 'Y'),
    ('\u{03A7}', 'X'),
    // Greek small letters.
    ('\u{03B1}', 'a'),
    ('\u{03B3}', 'y'),
    ('\u{03B9}', 'i'),
    ('\u{03BD}', 'v'),
    ('\u{03BF}', 'o'),
    ('\u{03C1}', 'p'),
    // Latin letters outside basic Latin.
    ('\u{0131}', 'i'),
    ('\u{0237}', 'j'),
    ('\u{0251}', 'a'),
    ('\u{0261}', 'g'),
    ('\u{01C0}', 'l'),
    ('\u{0269}', 'i'),
    ('\u{028F}', 'y'),
    ('\u{0274}', 'n'),
    ('\u{0280}', 'r'),
    ('\u{1D04}', 'c'),
    ('\u{1D0F}', 'o'),
    ('\u{1D1C}', 'u'),
    // Digits the standard maps to letters.
    ('0', 'o'),
    ('1', 'l'),
];

fn homoglyph(c: char) -> char {
    HOMOGLYPHS
        .iter()
        .find(|(from, _)| *from == c)
        .map_or(c, |(_, to)| *to)
}

fn fold(text: &str) -> String {
    UniCase::unicode(text).to_folded_case()
}

/// The two skeletons of a display name, which [`looks_alike`] compares: NFKC (fullwidth forms,
/// ligatures, superscripts and other compatibility forms become their plain letters), without
/// the [`is_default_ignorable`] code points, every run of white space as one space, then the
/// [`HOMOGLYPHS`] table applied before and after full case folding, each skeleton folded and in
/// NFC at the end.
pub fn display_skeletons(name: &str) -> [String; 2] {
    let mut plain = String::with_capacity(name.len());
    let mut space = false;
    for c in name.nfkc().filter(|c| !is_default_ignorable(*c)) {
        if c.is_whitespace() {
            space = true;
            continue;
        }
        if space && !plain.is_empty() {
            plain.push(' ');
        }
        space = false;
        plain.push(c);
    }
    let before: String = plain.chars().map(homoglyph).collect();
    let after: String = fold(&plain).chars().map(homoglyph).collect();
    [fold(&before).nfc().collect(), fold(&after).nfc().collect()]
}

/// Whether two device names look the same to a person (the skeleton check of device names):
/// equal skeletons in either order of [`display_skeletons`]. A false positive costs a hint and
/// one more question, a miss lets a stranger's device pass for one of the person's own, so the
/// check calls more names alike than a strict confusable test would.
pub fn looks_alike(a: &str, b: &str) -> bool {
    let (a, b) = (display_skeletons(a), display_skeletons(b));
    a[0] == b[0] || a[1] == b[1]
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
    /// The shape of an 8.3 short name alias (`HANGAR~1`, `REPORT~2.DOC`), see
    /// [`is_short_name_alias`].
    #[error("the name looks like a Windows short name")]
    ShortNameAlias,
}

/// Whether `name` has the shape of an 8.3 short name alias that NTFS and FAT make for long
/// names (security review N14): a base of at most eight characters that ends in `~` and one or
/// more digits, then optionally a dot and at most three characters, every character one a
/// short name may hold, compared without regard to ASCII case.
///
/// Windows opens a path by its short name as well as by its long name, so a name of that shape
/// can address another entry of the same directory: `HANGAR~1` at the sync root is usually the
/// reserved directory `.hangar-drive`, and a file the engine writes under that name would land
/// in the root marker's directory or the quarantine, past the ignore list. Which short names a
/// directory holds depends on the volume and on the order the entries were made, so the engine
/// cannot tell an alias from a real name; every name of that shape is refused on Windows
/// ("cannot sync on this device"), not only the reserved one. Real files with such names are
/// rare, and they stay in the tree and sync on every other platform.
pub fn is_short_name_alias(name: &str) -> bool {
    let allowed = |c: char| c.is_ascii_alphanumeric() || "!#$%&'()-@^_`{}~".contains(c);
    let (base, extension) = match name.split_once('.') {
        Some((base, extension)) => (base, Some(extension)),
        None => (name, None),
    };
    if base.is_empty() || base.len() > 8 || !base.chars().all(allowed) {
        return false;
    }
    if let Some(extension) = extension {
        if extension.len() > 3 || !extension.chars().all(|c| allowed(c) && c != '~') {
            return false;
        }
    }
    let Some((stem, digits)) = base.rsplit_once('~') else {
        return false;
    };
    !stem.is_empty() && !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
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
    if is_short_name_alias(name) {
        return Some(WindowsNameProblem::ShortNameAlias);
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
    // The reserved directory is compared with the case keys of the name policy, not only in
    // ASCII: a case-insensitive file system may fold a name such as `.hangar-dr\u{131}ve`
    // (dotless i) onto the real directory, and an entry written there could reach the root
    // marker, the temporary files or the quarantine.
    if at_root
        && (lower == RESERVED_ROOT_DIR
            || CaseKeys::of(name).collides(&CaseKeys::of(RESERVED_ROOT_DIR)))
    {
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

    // The skeleton check of device names: names that only look the same are found, others not.
    #[test]
    fn look_alike_device_names_are_found() {
        for (a, b) in [
            ("Laptop", "laptop"),
            ("Laptop", "LAPTOP"),
            // Cyrillic small a and o in Latin "Laptop".
            ("Laptop", "L\u{0430}pt\u{043E}p"),
            // Cyrillic capitals for B, O and B.
            ("BOB", "\u{0412}\u{041E}\u{0412}"),
            ("bob", "\u{0412}\u{041E}\u{0412}"),
            // Greek capitals.
            ("PC", "\u{03A1}C"),
            // Fullwidth letters through NFKC.
            ("Desk", "\u{FF24}\u{FF45}\u{FF53}\u{FF4B}"),
            // A soft hyphen and a zero width space are dropped.
            ("Desktop", "Desk\u{00AD}to\u{200B}p"),
            // Digits that look like letters, and doubled white space.
            ("Hallo PC", "Hall0  PC"),
            ("lan", "1an"),
            // Dotless i.
            ("Mini", "M\u{0131}n\u{0131}"),
        ] {
            assert!(looks_alike(a, b), "{a:?} and {b:?}");
            assert!(looks_alike(b, a), "{b:?} and {a:?}");
        }
        for (a, b) in [
            ("Laptop", "Desktop"),
            ("Laptop", "Laptop 2"),
            ("Feos PC", "Feos Mac"),
            // A Cyrillic word that looks like no Latin word stays apart.
            ("\u{0414}\u{043E}\u{043C}", "Dom"),
        ] {
            assert!(!looks_alike(a, b), "{a:?} and {b:?}");
        }
    }

    #[test]
    fn the_homoglyph_table_maps_only_to_basic_latin_and_once() {
        let mut seen = std::collections::BTreeSet::new();
        for (from, to) in HOMOGLYPHS {
            assert!(to.is_ascii_alphabetic(), "{from:?}");
            assert!(seen.insert(from), "{from:?} twice");
        }
    }

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
        // Security review N12: blank symbols, joiners and selectors are no visible character,
        // and a filler at the edge pads the name like white space.
        for name in [
            "\u{2800}",
            "\u{34f}",
            "\u{fe0f}",
            "\u{e0100}",
            "\u{e000}",
            "\u{301}",
            // Default ignorable code points, reserved ones included, render as nothing.
            "\u{2065}",
            "\u{fff0}",
            "\u{e0fff}",
            "\u{180b}\u{17b4}",
        ] {
            assert_eq!(
                check_display_name(name, 128),
                Err(DisplayNameError::Blank),
                "{name:?}"
            );
        }
        for name in [
            "\u{d55c}\u{3164}",
            "\u{3164}a",
            "a\u{2800}",
            "\u{34f}Laptop",
            "Laptop\u{34f}",
            "\u{fe0f}Laptop",
            "Laptop \u{fe0f}",
            "\u{180b}Laptop",
            "Laptop\u{17b4}",
            "Laptop\u{e0080}",
            "\u{2065}Laptop",
        ] {
            assert_eq!(
                check_display_name(name, 128),
                Err(DisplayNameError::EdgeWhitespace),
                "{name:?}"
            );
        }
        // White space and fillers inside a name stay allowed, and a variation selector that
        // follows its emoji is part of it.
        for name in [
            "My Laptop",
            "a\u{3000}b",
            "\u{d55c}\u{3164}\u{d55c}",
            "x",
            "Anna \u{2764}\u{fe0f}",
            "Caf\u{e9}",
            "Cafe\u{301}",
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

    // Security review N14: a name of the shape of a short name alias can address another
    // entry on Windows, `HANGAR~1` the reserved directory at the root.
    #[test]
    fn short_name_aliases_cannot_sync_on_windows() {
        for name in [
            "HANGAR~1",
            "hangar~2",
            "REPOR~12.DOC",
            "A~1",
            "ab~1.t",
            "X~123456",
        ] {
            assert_eq!(
                windows_problem(name),
                Some(WindowsNameProblem::ShortNameAlias),
                "{name:?}"
            );
        }
        for name in [
            ".hangar-drive",
            "~1",
            "REPORT~.DOC",
            "LONGNAME~1",
            "REPORT~1.DOCX",
            "a~1.b.c",
            "a~b",
            "Notes ~1.txt",
            "report~1x.txt",
        ] {
            assert_eq!(windows_problem(name), None, "{name:?}");
        }
    }

    // Security review N15: names that differ only in code points HFS+ ignores are one file on
    // HFS+, so they collide by case (the comparison keys stay different).
    #[test]
    fn code_points_hfs_ignores_do_not_hide_a_collision() {
        for (a, b) in [
            ("report.txt", "re\u{200d}port.txt"),
            ("report.txt", "\u{feff}report.txt"),
            ("report.txt", "report\u{200c}.txt"),
            ("Report.txt", "re\u{202e}port.txt"),
            ("abc", "a\u{206a}bc"),
        ] {
            assert_eq!(collision(a, b), Some(Collision::Case), "{a:?} {b:?}");
        }
        assert_ne!(comparison_key("a\u{200d}b"), comparison_key("ab"));
        assert_eq!(
            collision("ab", "a\u{200b}b"),
            None,
            "U+200B is not ignored by HFS+"
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
        // Case variants beyond ASCII that a case-insensitive file system may fold onto the
        // reserved directory: the dotless i has the simple uppercase `I`.
        for name in [
            ".HANGAR-DRIVE",
            ".hangar-dr\u{131}ve",
            ".Hangar-Dr\u{131}ve",
        ] {
            assert!(
                is_ignored(name, true),
                "{name:?} must be ignored at the root"
            );
            assert!(!is_ignored(name, false));
        }
        assert!(!is_ignored(".hangar-drives", true));
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
