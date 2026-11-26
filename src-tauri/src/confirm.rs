//! Native confirmations for the actions a compromised page must not trigger on its own
//! (security review L2, M4, H1): accepting a pairing request, which adds a device with every key
//! of the account, deleting a folder everywhere, trusting a new server key after the server
//! number comparison (ADR 0001, section 6, "Pin rotation"), removing a device, resetting or
//! disconnecting this device, taking a renewed recovery code, continuing a folder with an older
//! state, taking in the changes of a removed device, deleting many files, turning autostart off,
//! installing an update, joining a place that already holds files, resetting a folder to an
//! earlier state, removing old devices after a recovery and naming a device like another one
//! of the account (follow-up check N-1, N-2, skeleton check). The backend asks in a
//! dialog of the operating system that names what the action changes, with what the backend
//! itself knows (the device, the folder, the number of files, the place and the server), so a
//! click the person never made changes nothing. Where the window's own step would only ask the
//! same question again, the window asks nothing before it. The words come from src/i18n.ts
//! (build.rs, `texts`).

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

/// "Add this device?" with its name and the safety number the new device shows; when its name
/// looks like the name of a device of the account (`similar_to`), the question says so first.
pub fn pairing(
    language: &str,
    device_name: &str,
    safety: &[String],
    similar_to: Option<&str>,
) -> Confirm {
    let params = std::collections::BTreeMap::from([("device", device_name.to_owned())]);
    let title = texts::text(language, "pair.confirm.title").unwrap_or("{device}");
    let body = word(language, "pair.confirm.body", "");
    let look_alike = similar_to
        .map(|other| {
            let params = Params::from([("device", other.to_owned())]);
            format!(
                "{}\n\n",
                filled(language, "pair.request.lookAlike", &params)
            )
        })
        .unwrap_or_default();
    // The rows as the window shows them: groups of five digits, four to a line.
    let rows: Vec<String> = safety.chunks(4).map(|row| row.join("  ")).collect();
    Confirm {
        title: word(language, "app.name", "Hangar Drive"),
        message: format!(
            "{}\n\n{look_alike}{}\n\n{}",
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

/// `key` filled with `params`, or `""` when no language has it.
fn filled(language: &str, key: &str, params: &Params) -> String {
    texts::text(language, key)
        .map(|text| texts::fill(language, text, params))
        .unwrap_or_default()
}

/// The plural text of `key` for `n`, filled with `params`.
fn counted(language: &str, key: &str, n: u64, params: &Params) -> String {
    texts::plural(language, key, n)
        .map(|text| texts::fill(language, text, params))
        .unwrap_or_default()
}

type Params = std::collections::BTreeMap<&'static str, String>;

/// The paragraphs of a question, the empty ones left out.
fn paragraphs(parts: &[String]) -> String {
    parts
        .iter()
        .filter(|p| !p.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// A question with the product name as its title.
fn question(language: &str, parts: &[String], yes: &str, no: &str) -> Confirm {
    Confirm {
        title: word(language, "app.name", "Hangar Drive"),
        message: paragraphs(parts),
        yes: word(language, yes, "OK"),
        no: word(language, no, "Cancel"),
    }
}

/// "Remove this device?" with its name and what the removal does (ux-concept 10.2), in the
/// window's words; the window asks nothing before it.
pub fn remove_device(language: &str, device_name: &str) -> Confirm {
    let params = Params::from([("device", device_name.to_owned())]);
    question(
        language,
        &[
            filled(language, "devices.remove.title", &params),
            filled(language, "devices.remove.body", &params),
            filled(language, "devices.remove.lost", &params),
        ],
        "devices.remove",
        "common.cancel",
    )
}

/// "Disconnect this device", with the warning for the last device of the account (ux-concept
/// 10.2) in the same question.
pub fn disconnect(language: &str, last_one: bool) -> Confirm {
    let none = Params::new();
    question(
        language,
        &[
            filled(language, "devices.disconnect", &none),
            filled(language, "devices.disconnect.body", &none),
            if last_one {
                filled(language, "devices.lastOne", &none)
            } else {
                String::new()
            },
        ],
        if last_one {
            "devices.lastOne.confirm"
        } else {
            "devices.disconnect"
        },
        "common.cancel",
    )
}

/// "Really reset this device?" (ux-concept 11, security review L1).
pub fn reset(language: &str) -> Confirm {
    let none = Params::new();
    question(
        language,
        &[
            filled(language, "reset.question", &none),
            filled(language, "reset.body", &none),
        ],
        "reset.confirm",
        "common.cancel",
    )
}

/// "Take the new recovery code?" once its group was typed back (ux-concept 10.3): the old code
/// stops working.
pub fn renew_code(language: &str) -> Confirm {
    let none = Params::new();
    question(
        language,
        &[
            filled(language, "devices.recovery.renewConfirm", &none),
            filled(language, "devices.recovery.renewBody", &none),
        ],
        "devices.recovery.renewYes",
        "common.cancel",
    )
}

/// "Continue this folder with the server's state?" (ux-concept 8.6), with the warning of the
/// path without a comparison when the person did not compare.
pub fn reanchor(language: &str, folder_name: &str, compared: bool) -> Confirm {
    let params = Params::from([("folder", folder_name.to_owned())]);
    let (title, blind) = if compared {
        (
            filled(language, "older.confirm.title", &params),
            String::new(),
        )
    } else {
        (
            filled(language, "older.blind.title", &params),
            filled(language, "older.blind.body", &params),
        )
    };
    question(
        language,
        &[
            title,
            blind,
            filled(language, "older.confirm.merge", &params),
            filled(language, "older.confirm.loss", &params),
        ],
        if compared {
            "older.confirm.go"
        } else {
            "older.blind.go"
        },
        "common.cancel",
    )
}

/// "Take in the changes of a removed device?" (ux-concept 8.9) with the folder and the devices,
/// in the window's sentence (`headsBody` of src/problems/RemovedHeadsDialog.tsx).
pub fn accept_heads(language: &str, folder_name: &str, devices: &[String]) -> Confirm {
    let only = match devices {
        [one] if !one.is_empty() => Some(one.clone()),
        _ => None,
    };
    let mut params = Params::from([("folder", folder_name.to_owned())]);
    let body = match only {
        Some(device) => {
            params.insert("device", device);
            filled(language, "heads.body", &params)
        }
        None => {
            let count = devices.len().max(1) as u64;
            params.insert("count", count.to_string());
            counted(language, "heads.bodyMany", count, &params)
        }
    };
    question(
        language,
        &[
            filled(language, "heads.title", &params),
            body,
            filled(language, "heads.confirm", &params),
        ],
        "heads.accept",
        "common.cancel",
    )
}

/// "Delete these files on the other devices too?" with the folder and the number (ux-concept
/// 8.1).
pub fn mass_delete(language: &str, folder_name: &str, count: u64) -> Confirm {
    let params = Params::from([
        ("folder", folder_name.to_owned()),
        ("count", count.to_string()),
    ]);
    question(
        language,
        &[
            counted(language, "deletes.title", count, &params),
            counted(language, "deletes.body", count, &params),
        ],
        "deletes.confirm",
        "common.cancel",
    )
}

/// "Stop starting at sign-in?" (ux-concept 11).
pub fn autostart_off(language: &str) -> Confirm {
    let none = Params::new();
    question(
        language,
        &[
            filled(language, "settings.autostart.offTitle", &none),
            filled(language, "settings.autostart.offBody", &none),
        ],
        "settings.autostart.offConfirm",
        "common.cancel",
    )
}

/// "Was this device removed from your account?" after the server said so (security review H2).
pub fn removal_reported(language: &str) -> Confirm {
    let none = Params::new();
    question(
        language,
        &[
            filled(language, "removalReported.question", &none),
            filled(language, "removalReported.questionBody", &none),
        ],
        "removalReported.yes",
        "common.cancel",
    )
}

/// "Install version X?" for a signed update the updater found.
pub fn install_update(language: &str, version: &str) -> Confirm {
    let params = Params::from([("version", version.to_owned())]);
    question(
        language,
        &[filled(language, "update.confirm.title", &params)],
        "update.confirm.yes",
        "common.cancel",
    )
}

/// "This folder already holds files" (ux-concept 6.5) with the place, the account folder, the
/// number of files and the server they are uploaded to (security review H1). "No" means
/// "choose another folder".
pub fn join_folder(
    language: &str,
    path: &str,
    folder_name: &str,
    count: u64,
    host: &str,
) -> Confirm {
    let params = Params::from([
        ("folder", folder_name.to_owned()),
        ("count", count.to_string()),
        ("host", host.to_owned()),
    ]);
    question(
        language,
        &[
            counted(language, "merge.title", count, &params),
            counted(language, "merge.body", count, &params),
            texts::isolate_name(path),
            filled(language, "merge.host", &params),
        ],
        "merge.confirm",
        "merge.chooseOther",
    )
}

/// "Reset this folder on all devices?" with its name and how many files disappear (follow-up
/// check N-1), asked before every reset, since it changes the folder on every device.
pub fn reset_folder(language: &str, folder_name: &str, vanishing: u64) -> Confirm {
    let params = Params::from([
        ("folder", folder_name.to_owned()),
        ("count", vanishing.to_string()),
    ]);
    let gone = if vanishing == 0 {
        filled(language, "restore.folder.askNoneGone", &params)
    } else {
        counted(language, "restore.folder.askGone", vanishing, &params)
    };
    question(
        language,
        &[
            filled(language, "restore.folder.ask", &params),
            gone,
            filled(language, "restore.folder.askBody", &params),
        ],
        "restore.folder.confirm",
        "common.cancel",
    )
}

/// "Remove these devices from your account?" with their names, at the end of a recovery
/// (follow-up check N-2).
pub fn recovery_cleanup(language: &str, devices: &[String]) -> Confirm {
    let count = devices.len() as u64;
    let params = Params::from([("count", count.to_string())]);
    let names: Vec<String> = devices
        .iter()
        .map(|name| texts::isolate_name(name))
        .collect();
    question(
        language,
        &[
            counted(language, "recover.cleanup.ask", count, &params),
            names.join("\n"),
            filled(language, "recover.cleanup.askBody", &params),
        ],
        "devices.remove",
        "common.cancel",
    )
}

/// "This name looks like another device's; use it anyway?" when a device is named or renamed
/// (skeleton check of device names).
pub fn look_alike_name(language: &str, name: &str, other: &str) -> Confirm {
    let params = Params::from([("name", name.to_owned()), ("device", other.to_owned())]);
    question(
        language,
        &[filled(language, "devices.lookAlike.question", &params)],
        "devices.lookAlike.yes",
        "common.cancel",
    )
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
        let c = pairing("de", "Feos Laptop", &safety, None);
        assert!(c.message.contains("„Feos Laptop“"), "{}", c.message);
        assert!(
            c.message.contains("00001  00002  00003  00004\n00005"),
            "{}",
            c.message
        );
        assert_eq!(c.yes, "Ja, gleiche Zahlen, hinzufügen");
        assert_eq!(c.no, "Nein, abbrechen");
        // A spoofing name is isolated (security review L7).
        let c = pairing("en", "x\u{202E}gpj", &safety, None);
        assert!(c.message.contains("\u{2068}x\u{FFFD}gpj\u{2069}"));
        assert!(!c.message.contains("already a device"));
        // A name that looks like one of the account's: the question names that device.
        let c = pairing("de", "L\u{0430}ptop", &safety, Some("Laptop"));
        assert!(
            c.message
                .contains("Es gibt schon ein Gerät, das so heißt: „Laptop“"),
            "{}",
            c.message
        );
    }

    // Follow-up check N-1, N-2 and the skeleton check: the questions name what they change.
    #[test]
    fn the_follow_up_questions_name_what_they_change() {
        let c = reset_folder("de", "Fotos", 3);
        assert!(
            c.message
                .starts_with("„Fotos“ auf allen Geräten auf diesen Stand zurücksetzen?"),
            "{}",
            c.message
        );
        assert!(
            c.message.contains("verschwinden 3 Dateien"),
            "{}",
            c.message
        );
        assert_eq!(
            (c.yes.as_str(), c.no.as_str()),
            ("Zurücksetzen", "Abbrechen")
        );
        let c = reset_folder("de", "Fotos", 1);
        assert!(c.message.contains("verschwindet 1 Datei,"), "{}", c.message);
        let c = reset_folder("de", "Fotos", 0);
        assert!(c.message.contains("keine Datei"), "{}", c.message);

        let c = recovery_cleanup("de", &["Alter Laptop".to_owned(), "PC".to_owned()]);
        assert!(
            c.message
                .starts_with("2 Geräte aus deinem Konto entfernen?"),
            "{}",
            c.message
        );
        assert!(c.message.contains("Alter Laptop\nPC"), "{}", c.message);
        assert_eq!(c.yes, "Entfernen");
        // A name is isolated, so it cannot reorder the question (security review L7).
        let c = recovery_cleanup("en", &["x\u{202E}gpj".to_owned()]);
        assert!(c.message.starts_with("Remove 1 device"), "{}", c.message);
        assert!(c.message.contains("\u{2068}x\u{FFFD}gpj\u{2069}"));

        let c = look_alike_name("de", "LAPT0P", "Laptop");
        assert!(
            c.message.contains("„LAPT0P“ sieht aus wie „Laptop“"),
            "{}",
            c.message
        );
        assert_eq!(c.yes, "Trotzdem so nennen");

        for lang in texts::LANGUAGES {
            for c in [
                reset_folder(lang, "F", 0),
                reset_folder(lang, "F", 1),
                reset_folder(lang, "F", 5),
                reset_folder(lang, "F", 22),
                recovery_cleanup(lang, &["A".to_owned()]),
                recovery_cleanup(lang, &["A".to_owned(), "B".to_owned(), "C".to_owned()]),
                look_alike_name(lang, "N", "D"),
                pairing(lang, "N", &[], Some("D")),
            ] {
                assert!(complete(&c), "{lang}: {c:?}");
            }
        }
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

    /// Whether a question is complete: no placeholder left, both buttons named.
    fn complete(c: &Confirm) -> bool {
        !c.message.contains('{') && !c.yes.is_empty() && !c.no.is_empty() && c.yes != "OK"
    }

    // Security review M4: every destructive action asks natively, with what the backend knows.
    #[test]
    fn the_new_questions_name_what_they_change() {
        let c = remove_device("de", "Alter Laptop");
        assert!(
            c.message.starts_with("„Alter Laptop“ entfernen?"),
            "{}",
            c.message
        );
        assert!(c.message.contains("Verloren oder gestohlen?"));
        assert_eq!((c.yes.as_str(), c.no.as_str()), ("Entfernen", "Abbrechen"));

        let c = disconnect("de", true);
        assert!(
            c.message.contains("Das ist dein einziges Gerät."),
            "{}",
            c.message
        );
        assert_eq!(c.yes, "Trotzdem trennen");
        let c = disconnect("de", false);
        assert!(!c.message.contains("einziges"));
        assert_eq!(c.yes, "Dieses Gerät trennen");

        let c = reset("de");
        assert!(c.message.starts_with("Dieses Gerät wirklich zurücksetzen?"));
        assert!(
            c.message.contains("Hangar Drive hört hier auf"),
            "{}",
            c.message
        );
        assert_eq!(c.yes, "Zurücksetzen");

        let c = renew_code("en");
        assert!(
            c.message.contains("The old one stops working"),
            "{}",
            c.message
        );

        let c = reanchor("de", "Fotos", true);
        assert!(
            c.message.starts_with("„Fotos“ fortsetzen?"),
            "{}",
            c.message
        );
        assert_eq!(c.yes, "Fortsetzen");
        let c = reanchor("de", "Fotos", false);
        assert!(c.message.contains("Ohne zweites Gerät"), "{}", c.message);
        assert_eq!(c.yes, "Ohne Vergleich fortsetzen");

        let c = accept_heads("de", "Fotos", &["Alter Laptop".to_owned()]);
        assert!(c.message.contains("von „Alter Laptop“"), "{}", c.message);
        assert_eq!(c.yes, "Übernehmen");
        let c = accept_heads("en", "Photos", &["A".to_owned(), "B".to_owned()]);
        assert!(c.message.contains("from 2 devices"), "{}", c.message);

        let c = mass_delete("de", "Fotos", 342);
        assert!(
            c.message.starts_with("342 Dateien gelöscht"),
            "{}",
            c.message
        );
        assert!(c.message.contains("In „Fotos“ wurden 342 Dateien"));
        assert_eq!(c.yes, "Ja, löschen");

        let c = autostart_off("de");
        assert!(c.message.contains("Hangar Drive"), "{}", c.message);

        let c = install_update("en", "0.2.0");
        assert!(c.message.contains("0.2.0"), "{}", c.message);

        let c = join_folder("de", "C:\\Users\\x\\Fotos", "Fotos", 214, "drive.example");
        assert!(c.message.contains("214 Dateien"), "{}", c.message);
        assert!(c.message.contains("C:\\Users\\x\\Fotos"));
        assert!(c.message.contains("drive.example"));
        assert_eq!(c.yes, "Zusammenführen");
        assert_eq!(c.no, "Anderen Ordner wählen");

        for lang in texts::LANGUAGES {
            for c in [
                remove_device(lang, "X"),
                disconnect(lang, true),
                disconnect(lang, false),
                reset(lang),
                renew_code(lang),
                reanchor(lang, "F", true),
                reanchor(lang, "F", false),
                accept_heads(lang, "F", &["X".to_owned()]),
                accept_heads(lang, "F", &[]),
                mass_delete(lang, "F", 3),
                autostart_off(lang),
                install_update(lang, "1.0.0"),
                removal_reported(lang),
                join_folder(lang, "/home/x/F", "F", 2, "h"),
            ] {
                assert!(complete(&c), "{lang}: {c:?}");
            }
        }
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
