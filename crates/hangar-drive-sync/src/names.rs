//! Names the merge gives to conflict copies and restored items (ADR 0001, sections 3 and 5).
//!
//! `<name> (<word> <device> <date>).<ext>` for a conflict copy and `<name> (<word> <date>).<ext>`
//! for a restored item. The word is passed in by the caller in the device's UI language
//! (`conflict`, `Konflikt`, `restored`, ...); the whole name is only a label for people, no rule
//! reads it. `<ext>` is everything after the last dot unless that dot is the first character.
//! A taken name gets ` 2`, ` 3` and so on inside the parentheses.

use hangar_drive_protocol::name::MAX_WINDOWS_NAME_UNITS;

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

/// Builds `<stem> (<label>[ n])<ext>`, shortening the stem so the name fits Windows' limit.
fn labelled(name: &str, label: &str, n: u32) -> String {
    let (stem, ext) = split_extension(name);
    let suffix = if n <= 1 {
        format!(" ({label})")
    } else {
        format!(" ({label} {n})")
    };
    let budget = MAX_WINDOWS_NAME_UNITS.saturating_sub(utf16_len(&suffix) + utf16_len(ext));
    let mut short = String::new();
    for c in stem.chars() {
        if utf16_len(&short) + c.len_utf16() > budget {
            break;
        }
        short.push(c);
    }
    format!("{short}{suffix}{ext}")
}

/// The first label name for `name` that `taken` does not refuse.
fn first_free(name: &str, label: &str, taken: &dyn Fn(&str) -> bool) -> String {
    let mut n = 1u32;
    loop {
        let candidate = labelled(name, label, n);
        if !taken(&candidate) || n == u32::MAX {
            return candidate;
        }
        n += 1;
    }
}

/// The name of a conflict copy of `name` made by device `device` on `date` (`YYYY-MM-DD`).
pub fn conflict_copy_name(
    name: &str,
    words: &LabelWords,
    device: &str,
    date: &str,
    taken: &dyn Fn(&str) -> bool,
) -> String {
    let label = format!(
        "{} {} {}",
        sanitize_label(&words.conflict),
        sanitize_label(device),
        sanitize_label(date)
    );
    first_free(name, &label, taken)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn free(_: &str) -> bool {
        false
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

    #[test]
    fn dates() {
        assert_eq!(date_label(0, 0), "1970-01-01");
        assert_eq!(date_label(1_795_651_200_000, 0), "2026-11-26");
        assert_eq!(date_label(1_795_651_200_000 - 1, 0), "2026-11-25");
        assert_eq!(date_label(1_795_651_200_000 - 1, 60), "2026-11-26");
    }
}
