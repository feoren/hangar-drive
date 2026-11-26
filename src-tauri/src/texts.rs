//! The texts the backend shows itself (notifications, the recovery file, the engine's conflict
//! and restore words), taken from src/i18n.ts at build time (build.rs), and the plural rules of
//! the twelve languages for whole numbers, as `Intl.PluralRules` gives them in the window.

use std::collections::BTreeMap;

include!(concat!(env!("OUT_DIR"), "/texts.rs"));

/// The twelve languages of the window (src/i18n.ts, `LANGUAGES`).
pub const LANGUAGES: [&str; 12] = [
    "de", "en", "el", "es", "fr", "it", "ja", "pl", "pt", "ru", "tr", "zh",
];

/// A language of [`LANGUAGES`] or English.
pub fn resolve(language: &str) -> &'static str {
    let base = language
        .split(['-', '_'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    LANGUAGES
        .iter()
        .find(|l| **l == base)
        .copied()
        .unwrap_or("en")
}

/// The text of `key`, in `language`, else English (the window's fallback).
pub fn text(language: &str, key: &str) -> Option<&'static str> {
    let find = |lang: &str| {
        TEXTS
            .iter()
            .find(|(l, k, _)| *l == lang && *k == key)
            .map(|(_, _, t)| *t)
    };
    find(language).or_else(|| find("en"))
}

/// The CLDR plural category of a whole number in `language` (what the window's
/// `Intl.PluralRules` answers for an integer).
pub fn plural_category(language: &str, n: u64) -> &'static str {
    let (n10, n100) = (n % 10, n % 100);
    match language {
        "ja" | "zh" => "other",
        "fr" => match n {
            0 | 1 => "one",
            _ if n != 0 && n.is_multiple_of(1_000_000) => "many",
            _ => "other",
        },
        "pt" => match n {
            0 | 1 => "one",
            _ if n.is_multiple_of(1_000_000) => "many",
            _ => "other",
        },
        "es" | "it" => match n {
            1 => "one",
            _ if n != 0 && n.is_multiple_of(1_000_000) => "many",
            _ => "other",
        },
        "pl" => match n {
            1 => "one",
            _ if (2..=4).contains(&n10) && !(12..=14).contains(&n100) => "few",
            _ => "many",
        },
        "ru" => {
            if n10 == 1 && n100 != 11 {
                "one"
            } else if (2..=4).contains(&n10) && !(12..=14).contains(&n100) {
                "few"
            } else {
                "many"
            }
        }
        _ => {
            if n == 1 {
                "one"
            } else {
                "other"
            }
        }
    }
}

/// The plural text of `base` for `n` (`base.one`, `base.few`, ...), falling back to
/// `base.other`, then to English.
pub fn plural(language: &str, base: &str, n: u64) -> Option<&'static str> {
    let category = plural_category(language, n);
    let exact = |lang: &str, cat: &str| {
        let key = format!("{base}.{cat}");
        TEXTS
            .iter()
            .find(|(l, k, _)| *l == lang && *k == key)
            .map(|(_, _, t)| *t)
    };
    exact(language, category)
        .or_else(|| exact(language, "other"))
        .or_else(|| exact("en", plural_category("en", n)))
        .or_else(|| exact("en", "other"))
}

/// First strong isolate and pop directional isolate (Unicode UAX #9).
const FSI: char = '\u{2068}';
const PDI: char = '\u{2069}';

/// The character a bidi control of a name is shown as.
const REPLACEMENT: char = '\u{FFFD}';

/// Whether `c` is a bidi control (UAX #9): the Arabic letter mark, LRM and RLM, the embeddings
/// and overrides, and the isolates; `BIDI_CONTROLS` in src/i18n.ts.
fn bidi_control(c: char) -> bool {
    matches!(c,
        '\u{061C}'
        | '\u{200E}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}')
}

/// Whether `c` is a right-to-left letter: Hebrew to Arabic Extended-A and the Hebrew and Arabic
/// presentation forms; `RTL_LETTERS` in src/i18n.ts.
fn right_to_left(c: char) -> bool {
    matches!(c,
        '\u{0590}'..='\u{08FF}'
        | '\u{FB1D}'..='\u{FDFF}'
        | '\u{FE70}'..='\u{FEFC}')
}

/// A file, folder or device name inside a sentence. Its bidi controls are shown as U+FFFD first:
/// a name never needs one, and a PDI inside it would close the isolate early and let the rest of
/// the name act on the sentence (security review N9). The result is isolated (FSI ... PDI) when
/// it carries right-to-left letters or had a control, so it cannot reorder or spoof the text
/// around it (security review L7); the window's `isolateName` in src/i18n.ts does the same.
pub fn isolate_name(value: &str) -> String {
    let had_control = value.chars().any(bidi_control);
    let cleaned: String = value
        .chars()
        .map(|c| if bidi_control(c) { REPLACEMENT } else { c })
        .collect();
    if had_control || cleaned.chars().any(right_to_left) {
        format!("{FSI}{cleaned}{PDI}")
    } else {
        cleaned
    }
}

/// Fills `{name}` placeholders, each value isolated ([`isolate_name`]); `{app}` is always the
/// product name.
pub fn fill(language: &str, text: &str, params: &BTreeMap<&str, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                match params.get(name) {
                    Some(value) => out.push_str(&isolate_name(value)),
                    None if name == "app" => {
                        out.push_str(text_or(language, "app.name", "Hangar Drive"))
                    }
                    None => {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn text_or(language: &str, key: &str, fallback: &'static str) -> &'static str {
    text(language, key).unwrap_or(fallback)
}

/// The engine's words for conflict and restore labels in `language`.
pub fn label_words(language: &str) -> hangar_drive_sync::names::LabelWords {
    let default = hangar_drive_sync::names::LabelWords::default();
    hangar_drive_sync::names::LabelWords {
        conflict: text(language, "conflict.fileWord")
            .map(str::to_owned)
            .unwrap_or(default.conflict),
        restored: text(language, "restore.fileWord")
            .map(str::to_owned)
            .unwrap_or(default.restored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_language_has_the_texts_the_backend_needs() {
        for lang in LANGUAGES {
            for key in [
                "app.name",
                "tray.stillRunning",
                "missing.title",
                "older.title",
                "suspect.title",
                "suspect.titleFolder",
            ] {
                assert!(
                    TEXTS.iter().any(|(l, k, _)| *l == lang && *k == key),
                    "{lang} {key}"
                );
            }
            assert!(plural(lang, "conflict.noticeMany", 3).is_some(), "{lang}");
            assert!(plural(lang, "deletes.title", 1).is_some(), "{lang}");
        }
    }

    #[test]
    fn plural_rules_follow_cldr_for_whole_numbers() {
        assert_eq!(plural_category("de", 1), "one");
        assert_eq!(plural_category("de", 0), "other");
        assert_eq!(plural_category("fr", 0), "one");
        assert_eq!(plural_category("fr", 2), "other");
        assert_eq!(plural_category("fr", 1_000_000), "many");
        assert_eq!(plural_category("ru", 21), "one");
        assert_eq!(plural_category("ru", 11), "many");
        assert_eq!(plural_category("ru", 23), "few");
        assert_eq!(plural_category("ru", 13), "many");
        assert_eq!(plural_category("pl", 1), "one");
        assert_eq!(plural_category("pl", 22), "few");
        assert_eq!(plural_category("pl", 25), "many");
        assert_eq!(plural_category("pl", 21), "many");
        assert_eq!(plural_category("ja", 1), "other");
        assert_eq!(plural_category("pt", 0), "one");
    }

    #[test]
    fn placeholders_are_filled_and_unknown_ones_stay() {
        let params = BTreeMap::from([("folder", "Docs".to_owned())]);
        assert_eq!(fill("en", "{folder} and {x}", &params), "Docs and {x}");
        assert_eq!(fill("de", "{app}!", &BTreeMap::new()), "Hangar Drive!");
        assert_eq!(fill("en", "open {", &params), "open {");
    }

    // Security review L7: a name with right-to-left letters or bidi controls is isolated, so a
    // device named with an override cannot turn the sentence around it.
    #[test]
    fn names_with_bidi_characters_are_isolated() {
        let spoof = "Laptop\u{202E}txt.exe".to_owned();
        let params = BTreeMap::from([("device", spoof)]);
        assert_eq!(
            fill("en", "{device} wants to join", &params),
            "\u{2068}Laptop\u{FFFD}txt.exe\u{2069} wants to join"
        );
        let hebrew = BTreeMap::from([("folder", "\u{05D0}\u{05D1}".to_owned())]);
        assert!(fill("de", "„{folder}“", &hebrew).contains('\u{2068}'));
        // Plain names stay plain.
        assert_eq!(isolate_name("Docs"), "Docs");
        assert_eq!(isolate_name("Fotos 2026 ü"), "Fotos 2026 ü");
    }

    // Security review N9: a PDI inside a name would close the isolate early; every bidi control
    // is shown as U+FFFD before the name is isolated.
    #[test]
    fn bidi_controls_in_a_name_are_replaced_before_isolating() {
        let isolated = isolate_name("a\u{2069}\u{202E}b\u{2066}c\u{200F}\u{061C}");
        assert_eq!(
            isolated,
            "\u{2068}a\u{FFFD}\u{FFFD}b\u{FFFD}c\u{FFFD}\u{FFFD}\u{2069}"
        );
        assert_eq!(isolated.matches('\u{2069}').count(), 1);
        assert_eq!(isolate_name("\u{05D0}"), "\u{2068}\u{05D0}\u{2069}");
        // A folder name in a native question is cleaned the same way.
        let params = BTreeMap::from([("folder", "x\u{2069}y".to_owned())]);
        assert_eq!(
            fill("en", "Delete “{folder}”?", &params),
            "Delete “\u{2068}x\u{FFFD}y\u{2069}”?"
        );
    }

    #[test]
    fn languages_resolve_to_the_twelve_or_english() {
        assert_eq!(resolve("de-DE"), "de");
        assert_eq!(resolve("pt_BR"), "pt");
        assert_eq!(resolve("nl"), "en");
        assert_eq!(resolve(""), "en");
        assert_eq!(text("xx", "app.name"), Some("Hangar Drive"));
        assert_eq!(label_words("de").conflict, "Konflikt");
    }
}
