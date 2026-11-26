//! Names the merge gives to conflict copies and restored items (ADR 0001, sections 3 and 5).
//!
//! `<name> (<word> <device> <date>).<ext>` for a conflict copy and `<name> (<word> <date>).<ext>`
//! for a restored item. The word is passed in by the caller in the device's UI language
//! (`conflict`, `Konflikt`, `restored`, ...); the whole name is only a label for people, no rule
//! reads it. `<ext>` is everything after the last dot unless that dot is the first character.
//! A taken name gets ` 2`, ` 3` and so on inside the parentheses.
//!
//! [`DirNames`] answers the same questions for a whole directory at once: whether a name
//! collides with an entry, and which copy name is the first free one.

use std::collections::{BTreeMap, HashMap};

use hangar_drive_protocol::name::{CaseKeys, MAX_WINDOWS_NAME_UNITS};

/// The words of the labels, in the merging device's UI language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelWords {
    /// The word for a conflict copy, for example `conflict` or `Konflikt`.
    pub conflict: String,
    /// The word for a restored item, for example `restored` or `wiederhergestellt`.
    pub restored: String,
}

impl Default for LabelWords {
    /// English, the fallback of ADR 0001.
    fn default() -> Self {
        Self {
            conflict: "conflict".into(),
            restored: "restored".into(),
        }
    }
}

/// A device name made safe for a file name (security review N6): path separators and the
/// characters Windows refuses (`/ \ :` and `< > " | ? *`), control and format characters become
/// `_`, so a device called `..\x` or `C:` can never turn a conflict copy name into a path.
/// An empty result becomes `device`.
pub fn sanitize_label(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
                || c.is_control()
                || hangar_drive_protocol::name::is_format_character(c)
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "device".into()
    } else {
        trimmed.to_owned()
    }
}

/// Splits `name` into stem and extension (with its dot) by the rule of the module docs.
pub fn split_extension(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(0) | None => (name, ""),
        Some(at) => name.split_at(at),
    }
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// The longest prefix of `text` with at most `units` UTF-16 units, cut between characters, so a
/// surrogate pair is never split.
fn take_units(text: &str, units: usize) -> &str {
    let mut used = 0;
    for (at, c) in text.char_indices() {
        if used + c.len_utf16() > units {
            return &text[..at];
        }
        used += c.len_utf16();
    }
    text
}

/// A labelled name in its parts: `<stem> (<label><number>)<ext>`, where `<number>` is empty or
/// ` n`. How much of stem, label and extension fits depends only on the number of units the
/// number takes, so every number with as many digits gets the same parts.
struct Fit<'a> {
    stem: &'a str,
    label: &'a str,
    ext: &'a str,
}

impl<'a> Fit<'a> {
    /// Fits the parts into Windows' limit for a number of `number_units` UTF-16 units (0 for no
    /// number, else the space and the digits). The stem is shortened first, down to its first
    /// character, then the extension (security review LOW 3: a long extension made names longer
    /// than the limit), and the label only when it alone would not fit (a very long device
    /// name). An extension cut short loses trailing dots and spaces, which Windows strips; the
    /// stem never ends the name, since the label follows it.
    fn new(name: &'a str, label: &'a str, number_units: usize) -> Self {
        let (stem, ext) = split_extension(name);
        let first = stem.chars().next().map_or(0, char::len_utf16);
        // " (" and ")".
        let room = MAX_WINDOWS_NAME_UNITS.saturating_sub(3 + number_units);
        let label = take_units(label, room.saturating_sub(first));
        let room = room.saturating_sub(utf16_len(label));
        let (stem_units, ext_units) = (utf16_len(stem), utf16_len(ext));
        if stem_units + ext_units <= room {
            return Self { stem, label, ext };
        }
        let stem = take_units(stem, room.saturating_sub(ext_units).max(first));
        let mut ext = take_units(ext, room.saturating_sub(utf16_len(stem)));
        if ext.len() < split_extension(name).1.len() {
            ext = ext.trim_end_matches(['.', ' ']);
        }
        Self { stem, label, ext }
    }

    fn name(&self, number: &str) -> String {
        format!("{} ({}{number}){}", self.stem, self.label, self.ext)
    }
}

/// Builds `<stem> (<label>[ n])<ext>`, shortened so the name fits Windows' limit ([`Fit::new`]).
fn labelled(name: &str, label: &str, n: u32) -> String {
    let number = if n <= 1 {
        String::new()
    } else {
        format!(" {n}")
    };
    Fit::new(name, label, number.len()).name(&number)
}

/// The first label name for `name` that `taken` does not refuse.
pub(crate) fn first_free(name: &str, label: &str, taken: &dyn Fn(&str) -> bool) -> String {
    let mut n = 1u32;
    loop {
        let candidate = labelled(name, label, n);
        if !taken(&candidate) || n == u32::MAX {
            return candidate;
        }
        n += 1;
    }
}

/// The label of a conflict copy made by device `device` on `date`.
pub fn conflict_label(words: &LabelWords, device: &str, date: &str) -> String {
    format!(
        "{} {} {}",
        sanitize_label(&words.conflict),
        sanitize_label(device),
        sanitize_label(date)
    )
}

/// The name of a conflict copy of `name` made by device `device` on `date` (`YYYY-MM-DD`).
pub fn conflict_copy_name(
    name: &str,
    words: &LabelWords,
    device: &str,
    date: &str,
    taken: &dyn Fn(&str) -> bool,
) -> String {
    first_free(name, &conflict_label(words, device, date), taken)
}

/// The name of a restored item whose target name is taken by a different item.
pub fn restored_name(
    name: &str,
    words: &LabelWords,
    date: &str,
    taken: &dyn Fn(&str) -> bool,
) -> String {
    let label = format!(
        "{} {}",
        sanitize_label(&words.restored),
        sanitize_label(date)
    );
    first_free(name, &label, taken)
}

/// `YYYY-MM-DD` of a time in milliseconds since the Unix epoch, shifted by `offset_minutes`
/// (the device's local time zone offset, which the app supplies).
pub fn date_label(at_ms: i64, offset_minutes: i32) -> String {
    let secs = at_ms.div_euclid(1000) + i64::from(offset_minutes) * 60;
    let days = secs.div_euclid(86_400);
    // Civil from days (Howard Hinnant's algorithm), proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// The three case keys of a name, equal to [`CaseKeys::of`] (tested), computed directly for an
/// ASCII name: there NFC changes nothing, no character is one HFS+ ignores, and the full
/// lowercase mapping, full case folding and simple uppercase are the ASCII mappings. The merge
/// and the executor compute the keys of every entry they look at, and most names are ASCII.
pub fn case_keys(name: &str) -> CaseKeys {
    #[cfg(test)]
    tests::count_key();
    if name.is_ascii() {
        let lower = name.to_ascii_lowercase();
        CaseKeys {
            fold: lower.clone(),
            upper: name.to_ascii_uppercase(),
            lower,
        }
    } else {
        CaseKeys::of(name)
    }
}

fn key_parts(keys: &CaseKeys) -> [&str; 3] {
    [&keys.lower, &keys.fold, &keys.upper]
}

/// Numbers in runs of consecutive values: start to end, end exclusive, runs neither overlap
/// nor touch.
#[derive(Debug, Default)]
struct Runs(BTreeMap<u32, u32>);

impl Runs {
    /// The end of the run that holds `n`.
    fn end_of_run(&self, n: u32) -> Option<u32> {
        self.0
            .range(..=n)
            .next_back()
            .filter(|(_, end)| n < **end)
            .map(|(_, end)| *end)
    }

    /// Adds `n` (below `u32::MAX`).
    fn insert(&mut self, n: u32) {
        if self.end_of_run(n).is_some() {
            return;
        }
        let mut start = n;
        let left = self.0.range(..n).next_back().map(|(s, e)| (*s, *e));
        if let Some((s, e)) = left {
            if e == n {
                start = s;
                self.0.remove(&s);
            }
        }
        let end = self.0.remove(&(n + 1)).unwrap_or(n + 1);
        self.0.insert(start, end);
    }

    /// Removes `n` (below `u32::MAX`).
    fn remove(&mut self, n: u32) {
        let Some((start, end)) = self.0.range(..=n).next_back().map(|(s, e)| (*s, *e)) else {
            return;
        };
        if n >= end {
            return;
        }
        self.0.remove(&start);
        if start < n {
            self.0.insert(start, n);
        }
        if n + 1 < end {
            self.0.insert(n + 1, end);
        }
    }
}

/// The names of one directory by their case keys: whether a name collides with one of them,
/// and the conflict copy name [`conflict_copy_name`] would choose, in time about linear in the
/// number of entries (security review HIGH 2: comparing every name with every other one made
/// the merge of a directory of 8,000 files take minutes).
///
/// Searching a copy name tries ` 2`, ` 3` and so on, and many losers of one directory, such as
/// case variants of one name, would each try every number taken before. The index therefore
/// learns which numbered names are taken. Every number with as many digits gets the same
/// shortened stem, label and extension ([`Fit`]), so the name with number `n` is `P + n + Q`
/// for a fixed prefix `P` ending in a space and a tail `Q` starting with `)`. A space, the
/// digits and `)` are stable in NFC (they never combine with a neighbour), map to themselves
/// under every case mapping and end the context of a final sigma, so each case key of the name
/// is `key(P) + n + key(Q)`. The index checks that split on every name it tries and learns, per
/// key kind, the numbers `n` whose key `key(P) + n + key(Q)` is taken; another loser with the
/// same `key(P)` and `key(Q)` skips them. When such a key leaves the directory, the number is
/// forgotten again, so the result is always the first free name.
#[derive(Debug, Default)]
pub struct DirNames {
    /// Per key kind (lower, fold, upper): how many entries have each key.
    counts: [HashMap<String, u32>; 3],
    /// Per key kind, prefix key and tail key: the numbers whose name key is taken.
    taken_numbers: [HashMap<String, HashMap<String, Runs>>; 3],
    /// How many keys are shared by two or more entries.
    shared: usize,
}

impl DirNames {
    /// Adds an entry with these keys.
    pub fn add(&mut self, keys: &CaseKeys) {
        for (kind, key) in key_parts(keys).into_iter().enumerate() {
            let count = self.counts[kind].entry(key.to_owned()).or_insert(0);
            *count += 1;
            if *count == 2 {
                self.shared += 1;
            }
        }
    }

    /// Removes an entry with these keys.
    pub fn remove(&mut self, keys: &CaseKeys) {
        for (kind, key) in key_parts(keys).into_iter().enumerate() {
            let Some(count) = self.counts[kind].get_mut(key) else {
                continue;
            };
            *count -= 1;
            if *count == 1 {
                self.shared -= 1;
            }
            if *count == 0 {
                self.counts[kind].remove(key);
                self.forget(kind, key);
            }
        }
    }

    /// Whether some entry collides with a name of these keys.
    pub fn taken(&self, keys: &CaseKeys) -> bool {
        key_parts(keys)
            .into_iter()
            .enumerate()
            .any(|(kind, key)| self.counts[kind].contains_key(key))
    }

    /// Whether two entries collide.
    pub fn any_collision(&self) -> bool {
        self.shared > 0
    }

    /// A key left the directory: every number it stood for is free again. The key is split at
    /// each run of digits between a space and `)`; a split nobody learned is not found.
    fn forget(&mut self, kind: usize, key: &str) {
        let bytes = key.as_bytes();
        let mut at = 1;
        while at < bytes.len() {
            if bytes[at - 1] != b' ' || !bytes[at].is_ascii_digit() {
                at += 1;
                continue;
            }
            let mut end = at;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end < bytes.len() && bytes[end] == b')' && bytes[at] != b'0' && end - at <= 10 {
                if let Ok(n) = key[at..end].parse::<u32>() {
                    let runs = self.taken_numbers[kind]
                        .get_mut(&key[..at])
                        .and_then(|tails| tails.get_mut(&key[end..]));
                    if let (Some(runs), true) = (runs, n < u32::MAX) {
                        runs.remove(n);
                    }
                }
            }
            at = end;
        }
    }

    /// The name [`conflict_copy_name`] gives `name` with the label `label` ([`conflict_label`])
    /// in a directory of these entries.
    pub fn copy_name(&mut self, name: &str, label: &str) -> String {
        let first = labelled(name, label, 1);
        if !self.taken(&case_keys(&first)) {
            return first;
        }
        let mut n = 2u32;
        while n < u32::MAX {
            let digits = n.ilog10() + 1;
            // The numbers with as many digits as `n`; ten digits run up to the last number.
            let end = if digits >= 10 {
                u32::MAX
            } else {
                10u32.pow(digits)
            };
            let fit = Fit::new(name, label, digits as usize + 1);
            let prefix = case_keys(&format!("{} ({} ", fit.stem, fit.label));
            let tail = case_keys(&format!("){}", fit.ext));
            let (prefix, tail) = (key_parts(&prefix), key_parts(&tail));
            while n < end {
                let candidate = fit.name(&format!(" {n}"));
                let keys = case_keys(&candidate);
                let keys = key_parts(&keys);
                let blocked: Vec<usize> = (0..3)
                    .filter(|kind| self.counts[*kind].contains_key(keys[*kind]))
                    .collect();
                if blocked.is_empty() {
                    return candidate;
                }
                let split = (0..3).all(|kind| {
                    let key = keys[kind];
                    let number = n.to_string();
                    key.len() == prefix[kind].len() + number.len() + tail[kind].len()
                        && key.starts_with(prefix[kind])
                        && key.ends_with(tail[kind])
                        && key[prefix[kind].len()..].starts_with(number.as_str())
                });
                n += 1;
                if !split {
                    // Not seen so far; without the split the search tries every number.
                    continue;
                }
                for kind in blocked {
                    self.taken_numbers[kind]
                        .entry(prefix[kind].to_owned())
                        .or_default()
                        .entry(tail[kind].to_owned())
                        .or_default()
                        .insert(n - 1);
                }
                // Skip the numbers known to be taken under any key kind.
                loop {
                    let mut moved = false;
                    for kind in 0..3 {
                        let skip = self.taken_numbers[kind]
                            .get(prefix[kind])
                            .and_then(|tails| tails.get(tail[kind]))
                            .and_then(|runs| runs.end_of_run(n));
                        if let Some(skip) = skip {
                            let skip = skip.min(end);
                            if skip > n {
                                n = skip;
                                moved = true;
                            }
                        }
                    }
                    if !moved || n >= end {
                        break;
                    }
                }
            }
        }
        labelled(name, label, u32::MAX)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static KEYS: Cell<u64> = const { Cell::new(0) };
    }

    /// Counts a computation of [`case_keys`] on this thread.
    pub(crate) fn count_key() {
        KEYS.with(|keys| keys.set(keys.get() + 1));
    }

    /// How often [`case_keys`] ran on this thread: the work bound of the complexity tests.
    pub(crate) fn keys_computed() -> u64 {
        KEYS.with(Cell::get)
    }

    /// A small deterministic generator for the randomized tests (SplitMix64).
    pub(crate) struct Rng(pub(crate) u64);

    impl Rng {
        pub(crate) fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        /// A number below `n` (`n` > 0).
        pub(crate) fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        pub(crate) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[self.below(items.len())]
        }
    }

    /// Pieces of names that collide in every way the case keys know: case, NFC, long s, final
    /// sigma, the Kelvin sign, dotted and dotless i, an ignorable code point, combining marks.
    pub(crate) const PIECES: [&str; 22] = [
        "a", "A", "b", "s", "S", "\u{17f}", "e\u{301}", "\u{e9}", "\u{3a3}", "\u{3c3}", "\u{3c2}",
        "\u{212a}", "k", "i", "I", "\u{131}", "\u{130}", "\u{200d}", "\u{301}", " ", ".", "1",
    ];

    fn free(_: &str) -> bool {
        false
    }

    #[test]
    fn fast_keys_equal_the_protocol_keys() {
        let mut rng = Rng(7);
        for _ in 0..5000 {
            let len = 1 + rng.below(12);
            let ascii: String = (0..len)
                .map(|_| char::from(32 + rng.below(95) as u8))
                .collect();
            assert_eq!(case_keys(&ascii), CaseKeys::of(&ascii), "{ascii:?}");
            let mixed: String = (0..1 + rng.below(6)).map(|_| *rng.pick(&PIECES)).collect();
            assert_eq!(case_keys(&mixed), CaseKeys::of(&mixed), "{mixed:?}");
        }
    }

    /// The claim [`DirNames`] rests on: each case key of `P + n + Q` is `key(P) + n + key(Q)`
    /// for a prefix ending in a space and a tail starting with `)`.
    #[test]
    fn keys_split_at_the_number() {
        let mut rng = Rng(11);
        for _ in 0..5000 {
            let stem: String = (0..rng.below(8)).map(|_| *rng.pick(&PIECES)).collect();
            let label: String = (0..rng.below(4)).map(|_| *rng.pick(&PIECES)).collect();
            let ext: String = (0..rng.below(4)).map(|_| *rng.pick(&PIECES)).collect();
            let prefix = format!("{stem} ({label} ");
            let tail = format!("){ext}");
            let n = 2 + rng.below(100_000);
            let whole = CaseKeys::of(&format!("{prefix}{n}{tail}"));
            let (p, t) = (CaseKeys::of(&prefix), CaseKeys::of(&tail));
            assert_eq!(
                whole.lower,
                format!("{}{n}{}", p.lower, t.lower),
                "{prefix:?}"
            );
            assert_eq!(whole.fold, format!("{}{n}{}", p.fold, t.fold), "{prefix:?}");
            assert_eq!(
                whole.upper,
                format!("{}{n}{}", p.upper, t.upper),
                "{prefix:?}"
            );
        }
    }

    #[test]
    fn runs_merge_and_split() {
        let mut runs = Runs::default();
        for n in [5, 3, 4, 9, 2] {
            runs.insert(n);
        }
        assert_eq!(runs.end_of_run(2), Some(6));
        assert_eq!(runs.end_of_run(6), None);
        assert_eq!(runs.end_of_run(9), Some(10));
        runs.remove(4);
        assert_eq!(runs.end_of_run(3), Some(4));
        assert_eq!(runs.end_of_run(4), None);
        assert_eq!(runs.end_of_run(5), Some(6));
        runs.remove(2);
        runs.remove(7);
        assert_eq!(
            runs.0.into_iter().collect::<Vec<_>>(),
            vec![(3, 4), (5, 6), (9, 10)]
        );
    }

    /// [`DirNames::copy_name`] picks exactly the name of [`conflict_copy_name`] while entries
    /// come and go, including entries that look like numbered copies.
    #[test]
    fn indexed_copy_names_equal_the_plain_search() {
        let mut rng = Rng(3);
        let words = LabelWords::default();
        let label = conflict_label(&words, "PC", "2026-11-26");
        let stems = ["a", "A", "\u{17f}s", "s\u{17f}", "SS", "\u{3a3}", "\u{3c2}"];
        for round in 0..300 {
            let mut index = DirNames::default();
            let mut names: Vec<String> = Vec::new();
            for _ in 0..40 {
                let name = format!(
                    "{}{}",
                    rng.pick(&stems),
                    rng.pick(&[".txt", ".TXT", "", ".t\u{17f}"])
                );
                match rng.below(5) {
                    0 if !names.is_empty() => {
                        let gone = names.swap_remove(rng.below(names.len()));
                        index.remove(&case_keys(&gone));
                    }
                    1 => {
                        // An entry that looks like a numbered copy.
                        let taken = labelled(&name, &label, 2 + rng.below(6) as u32);
                        index.add(&case_keys(&taken));
                        names.push(taken);
                    }
                    _ => {
                        let plain = conflict_copy_name(&name, &words, "PC", "2026-11-26", &|c| {
                            let keys = CaseKeys::of(c);
                            names.iter().any(|n| CaseKeys::of(n).collides(&keys))
                        });
                        let indexed = index.copy_name(&name, &label);
                        assert_eq!(indexed, plain, "round {round}, {name:?}");
                        index.add(&case_keys(&indexed));
                        names.push(indexed);
                    }
                }
            }
        }
    }

    /// Many losers of one name each find their number in a few steps (security review HIGH 2).
    #[test]
    fn copy_names_for_many_variants_take_linear_work() {
        let label = conflict_label(&LabelWords::default(), "PC", "2026-11-26");
        let mut index = DirNames::default();
        let variants = 3000u64;
        let before = keys_computed();
        for i in 0..variants {
            // Case variants of one name, and variants by long s that share only fold and upper.
            let name: String = "sssssssssssss.txt"
                .chars()
                .enumerate()
                .map(|(at, c)| match (i >> (2 * at)) & 3 {
                    1 if c == 's' => 'S',
                    2 if c == 's' => '\u{17f}',
                    _ => c,
                })
                .collect();
            let copy = index.copy_name(&name, &label);
            index.add(&case_keys(&copy));
        }
        let work = keys_computed() - before;
        // A few per copy and digit of its number.
        assert!(work <= 20 * variants, "{work} key computations");
    }

    #[test]
    fn extension_rule() {
        assert_eq!(split_extension("a.txt"), ("a", ".txt"));
        assert_eq!(split_extension("a.tar.gz"), ("a.tar", ".gz"));
        assert_eq!(split_extension(".bashrc"), (".bashrc", ""));
        assert_eq!(split_extension("Makefile"), ("Makefile", ""));
    }

    #[test]
    fn conflict_names_follow_the_adr() {
        let words = LabelWords::default();
        assert_eq!(
            conflict_copy_name("Plan.docx", &words, "Laptop", "2026-11-26", &free),
            "Plan (conflict Laptop 2026-11-26).docx"
        );
        assert_eq!(
            conflict_copy_name(".env", &words, "PC", "2026-11-26", &free),
            ".env (conflict PC 2026-11-26)"
        );
        let german = LabelWords {
            conflict: "Konflikt".into(),
            restored: "wiederhergestellt".into(),
        };
        let taken = |n: &str| n == "a (Konflikt PC 2026-01-02).txt";
        assert_eq!(
            conflict_copy_name("a.txt", &german, "PC", "2026-01-02", &taken),
            "a (Konflikt PC 2026-01-02 2).txt"
        );
        assert_eq!(
            restored_name("a.txt", &german, "2026-01-02", &free),
            "a (wiederhergestellt 2026-01-02).txt"
        );
    }

    #[test]
    fn device_names_cannot_inject_paths() {
        let words = LabelWords::default();
        let name = conflict_copy_name("a.txt", &words, "..\\evil/x:y", "2026-11-26", &free);
        assert_eq!(name, "a (conflict .._evil_x_y 2026-11-26).txt");
        assert!(hangar_drive_protocol::name::windows_problem(&name).is_none());
        assert_eq!(sanitize_label("  "), "device");
        assert_eq!(sanitize_label("a\u{202e}b\n"), "a_b_");
    }

    #[test]
    fn long_names_fit_windows() {
        let long = "x".repeat(300) + ".txt";
        let name = conflict_copy_name(&long, &LabelWords::default(), "PC", "2026-11-26", &free);
        assert!(name.encode_utf16().count() <= MAX_WINDOWS_NAME_UNITS);
        assert!(name.ends_with("(conflict PC 2026-11-26).txt"));
    }

    /// Security review LOW 3: a long extension is shortened too, after the stem, and the name
    /// stays one Windows can hold.
    #[test]
    fn long_extensions_fit_windows() {
        let words = LabelWords::default();
        for (name, keep) in [
            (format!("a.{}", "e".repeat(250)), "a ("),
            (format!("{}.{}", "x".repeat(40), "e".repeat(250)), "x ("),
            (format!("a.{}   {}", "e".repeat(227), "y".repeat(50)), "a ("),
            (
                format!("\u{1f600}.{}\u{1f600}", "e".repeat(240)),
                "\u{1f600} (",
            ),
            (format!("b.{}", "\u{1f600}".repeat(200)), "b ("),
        ] {
            for taken in [false, true] {
                let copy = conflict_copy_name(&name, &words, "PC", "2026-11-26", &|c| {
                    taken && !c.contains(" 2)")
                });
                assert!(
                    copy.encode_utf16().count() <= MAX_WINDOWS_NAME_UNITS,
                    "{copy}"
                );
                assert!(copy.starts_with(keep), "{copy}");
                assert!(copy.contains("(conflict PC 2026-11-26"), "{copy}");
                assert_eq!(hangar_drive_protocol::name::windows_problem(&copy), None);
            }
        }
        // A label longer than the limit is shortened last.
        let device = "D".repeat(400);
        let copy = conflict_copy_name("a.txt", &words, &device, "2026-11-26", &free);
        assert!(copy.encode_utf16().count() <= MAX_WINDOWS_NAME_UNITS);
        assert!(copy.starts_with("a (conflict DDD"));
        assert_eq!(hangar_drive_protocol::name::windows_problem(&copy), None);
    }

    #[test]
    fn dates() {
        assert_eq!(date_label(0, 0), "1970-01-01");
        assert_eq!(date_label(1_795_651_200_000, 0), "2026-11-26");
        assert_eq!(date_label(1_795_651_200_000 - 1, 0), "2026-11-25");
        assert_eq!(date_label(1_795_651_200_000 - 1, 60), "2026-11-26");
    }
}
