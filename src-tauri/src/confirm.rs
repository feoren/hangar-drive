//! Native confirmations for the actions a compromised page must not trigger on its own
//! (security review L2): accepting a pairing request, which adds a device with every key of the
//! account, deleting a folder everywhere, and trusting a new server key after the server number
//! comparison (ADR 0001, section 6, "Pin rotation"). The window asks first, as before; then the
//! backend asks again in a dialog of the operating system that names the device and its safety
//! number, the folder, or the server number, so a click the person never made changes nothing.
//! The words come from src/i18n.ts (build.rs, `texts`).

use crate::texts;

/// A confirmation in words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub title: String,
    pub message: String,
    pub yes: String,
    pub no: String,
}

fn word(language: &str, key: &str, fallback: &str) -> String {
    let text = texts::text(language, key).unwrap_or(fallback);
    texts::fill(language, text, &Default::default())
}

/// "Add this device?" with its name and the safety number the new device shows.
pub fn pairing(language: &str, device_name: &str, safety: &[String]) -> Confirm {
    let params = std::collections::BTreeMap::from([("device", device_name.to_owned())]);
    let title = texts::text(language, "pair.confirm.title").unwrap_or("{device}");
    let body = word(language, "pair.confirm.body", "");
    // The rows as the window shows them: groups of five digits, four to a line.
    let rows: Vec<String> = safety.chunks(4).map(|row| row.join("  ")).collect();
    Confirm {
        title: word(language, "app.name", "Hangar Drive"),
        message: format!(
            "{}\n\n{}\n\n{}",
            texts::fill(language, title, &params),
            body,
            rows.join("\n")
        ),
        yes: word(language, "pair.confirm.yes", "Add"),
        no: word(language, "pair.confirm.no", "Cancel"),
    }
}

/// "Same numbers as the operator's?" with the server number of the key the server presents now,
/// in the words of the window's comparison dialog.
pub fn server_number(language: &str, number: &[String]) -> Confirm {
    let rows: Vec<String> = number.chunks(3).map(|row| row.join("  ")).collect();
    Confirm {
        title: word(language, "app.name", "Hangar Drive"),
        message: format!(
            "{}\n\n{}\n{}",
            word(
                language,
                "server.fix.compareTitle",
                "Compare the server number"
            ),
            word(language, "server.number.label", "Server number"),
            rows.join("\n")
        ),
        yes: word(language, "server.fix.yes", "Connect"),
        no: word(language, "server.fix.no", "Cancel"),
    }
}

/// "Delete this folder on every device?" with its name, and how many days it can be brought
/// back (`folder.delete.body`, the window's own sentence).
pub fn delete_everywhere(language: &str, folder_name: &str, days: u32) -> Confirm {
    let params = std::collections::BTreeMap::from([
        ("folder", folder_name.to_owned()),
        ("days", days.to_string()),
    ]);
    let title = texts::text(language, "folder.delete.title").unwrap_or("{folder}");
    let body = texts::plural(language, "folder.delete.body", u64::from(days)).unwrap_or("");
    Confirm {
        title: word(language, "app.name", "Hangar Drive"),
        message: format!(
            "{}\n\n{}",
            texts::fill(language, title, &params),
            texts::fill(language, body, &params)
        ),
        yes: word(language, "folder.delete.confirm", "Delete"),
        no: word(language, "common.cancel", "Cancel"),
    }
}

/// Asks `confirm` in a native dialog and waits for the answer; `false` for "no" and for a
/// dialog that could not be shown.
pub fn ask(app: &tauri::AppHandle, confirm: Confirm) -> bool {
    use tauri_plugin_dialog::{DialogExt as _, MessageDialogButtons, MessageDialogKind};
    let mut dialog = app
        .dialog()
        .message(confirm.message)
        .title(confirm.title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            confirm.yes,
            confirm.no,
        ));
    if let Some(window) = tauri::Manager::get_webview_window(app, crate::tray::MAIN_WINDOW) {
        dialog = dialog.parent(&window);
    }
    dialog.blocking_show()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pairing_question_names_the_device_and_the_safety_number() {
        let safety: Vec<String> = (1..=8).map(|i| format!("{i:05}")).collect();
        let c = pairing("de", "Feos Laptop", &safety);
        assert!(c.message.contains("„Feos Laptop“"), "{}", c.message);
        assert!(
            c.message.contains("00001  00002  00003  00004\n00005"),
            "{}",
            c.message
        );
        assert_eq!(c.yes, "Ja, gleiche Zahlen, hinzufügen");
        assert_eq!(c.no, "Nein, abbrechen");
        // A spoofing name is isolated (security review L7).
        let c = pairing("en", "x\u{202E}gpj", &safety);
        assert!(c.message.contains("\u{2068}x\u{202E}gpj\u{2069}"));
    }

    #[test]
    fn the_delete_question_names_the_folder_and_the_days_to_bring_it_back() {
        let c = delete_everywhere("en", "Photos", 30);
        assert!(c.message.contains("Photos"), "{}", c.message);
        assert!(c.message.contains("For 30 days"), "{}", c.message);
        assert!(!c.message.contains('{'));
        assert!(!c.yes.is_empty() && !c.no.is_empty());
        let c = delete_everywhere("de", "Fotos", 1);
        assert!(c.message.contains("1 Tag lang"), "{}", c.message);
        for lang in texts::LANGUAGES {
            let c = delete_everywhere(lang, "Photos", 30);
            assert!(
                c.message.contains("30") && !c.message.contains('{'),
                "{lang}: {}",
                c.message
            );
        }
    }

    #[test]
    fn the_server_question_shows_the_server_number() {
        let number: Vec<String> = (1..=6).map(|i| format!("{i:05}")).collect();
        let c = server_number("de", &number);
        assert!(
            c.message.starts_with("Servernummer vergleichen"),
            "{}",
            c.message
        );
        assert!(
            c.message
                .contains("00001  00002  00003\n00004  00005  00006"),
            "{}",
            c.message
        );
        assert_eq!(c.yes, "Ja, gleiche Zahlen, verbinden");
        assert_eq!(c.no, "Nein, nicht verbinden");
    }

    #[test]
    fn every_language_has_the_confirmation_texts() {
        for lang in texts::LANGUAGES {
            for key in [
                "pair.confirm.title",
                "pair.confirm.body",
                "pair.confirm.yes",
                "pair.confirm.no",
                "folder.delete.title",
                "folder.delete.confirm",
                "common.cancel",
                "heads.title",
                "server.fix.compareTitle",
                "server.number.label",
                "server.fix.yes",
                "server.fix.no",
            ] {
                assert!(
                    texts::TEXTS.iter().any(|(l, k, _)| *l == lang && *k == key),
                    "{lang} {key}"
                );
            }
            assert!(
                texts::plural(lang, "folder.delete.body", 30).is_some(),
                "{lang} folder.delete.body"
            );
        }
    }
}
