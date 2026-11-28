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

/// "Discard the recovery and reset?" while a recovery is pending (follow-up review LOW 7): this
/// device's new key may be the account's only one, so the account may be lost for good.
pub fn reset_discarding_recovery(language: &str) -> Confirm {
    let none = Params::new();
    question(
        language,
        &[
            filled(language, "reset.pending.question", &none),
            filled(language, "reset.pending.body", &none),
        ],
        "reset.pending.anyway",
        "common.cancel",
    )
}

/// "Take the new recovery code?" once its group was typed back (ux-concept 10.3): the old code
/// stops working. Without a valid code (`has_code` false, warning `noRecoveryCode`) there is no
/// old one, so the question says what the new one is for instead.
pub fn renew_code(language: &str, has_code: bool) -> Confirm {
    let none = Params::new();
    question(
        language,
        &[
            filled(language, "devices.recovery.renewConfirm", &none),
            filled(
                language,
                if has_code {
                    "devices.recovery.renewBody"
                } else {
                    "noRecoveryCode.confirmBody"
                },
                &none,
            ),
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

/// "Delete these files here too?" for deletes another device made, with the folder and the
/// number (ux-concept 8.1, incoming deletes).
pub fn incoming_delete(language: &str, folder_name: &str, count: u64) -> Confirm {
    let params = Params::from([
        ("folder", folder_name.to_owned()),
        ("count", count.to_string()),
    ]);
    question(
        language,
        &[
            counted(language, "incoming.ask", count, &params),
            filled(language, "incoming.askBody", &params),
        ],
        "incoming.confirm",
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

/// "Remove these devices from your account?" with their labels
/// ([`recovery_device_label`]), at the end of a recovery (follow-up check N-2).
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

/// How [`recovery_cleanup`] names a device: its name, or, before the new device joined (the
/// recovery session cannot open the sealed names), "Device, added on {date}" with the local
/// day its add entry was issued.
pub fn recovery_device_label(
    language: &str,
    name: &str,
    added_ms: i64,
    tz_offset_minutes: i32,
) -> String {
    if !name.trim().is_empty() {
        return name.to_owned();
    }
    let params = Params::from([("date", local_date(added_ms, tz_offset_minutes))]);
    filled(language, "recover.cleanup.device", &params)
}

/// The local day of `ms` as `YYYY-MM-DD`: the backend has no locale date format, and this one
/// reads the same in every language.
fn local_date(ms: i64, tz_offset_minutes: i32) -> String {
    const DAY: i64 = 86_400_000;
    let local = ms.saturating_add(i64::from(tz_offset_minutes) * 60_000);
    let (year, month, day) = civil_from_days(local.div_euclid(DAY));
    format!("{year:04}-{month:02}-{day:02}")
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    // Both are in range by construction (1..=31, 1..=12).
    (year, month as u32, day as u32)
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

/// The button a native question starts on, the one Enter and Space press.
// Only the Windows dialog names both buttons; elsewhere the plugin's dialog decides.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultButton {
    Yes,
    No,
}

/// Every question of this module guards a change a page must not make on its own, most of them
/// destructive (a device removed, a folder deleted everywhere, files deleted, a new server key
/// trusted, a device added). A key press meant for the window, Enter in a field or Space on a
/// button, must never answer one with "yes", so each starts on "no" (security review LOW 1): the
/// person confirms with a click, or with Tab and then Enter.
pub fn default_button() -> DefaultButton {
    DefaultButton::No
}

/// The IDs of the two buttons of the Windows question; from 100 on, clear of the common IDs
/// (`IDOK` 1, `IDCANCEL` 2 ...).
#[cfg(any(windows, test))]
const YES_ID: i32 = 100;
#[cfg(any(windows, test))]
const NO_ID: i32 = 101;

/// The Windows ID of `button`.
#[cfg(any(windows, test))]
fn button_id(button: DefaultButton) -> i32 {
    match button {
        DefaultButton::Yes => YES_ID,
        DefaultButton::No => NO_ID,
    }
}

/// Whether the Windows question's answer `button` is "yes"; Escape and the title bar's close
/// button answer `IDCANCEL`, which is "no" like every other value.
#[cfg(any(windows, test))]
fn answered_yes(button: i32) -> bool {
    button == button_id(DefaultButton::Yes)
}

/// Asks `confirm` in a native dialog and waits for the answer; `false` for "no" and for a
/// dialog that could not be shown.
///
/// Windows: a task dialog of its own, so "no" is the default button ([`default_button`]); the
/// plugin's dialog always starts on its first button. macOS: the plugin's `NSAlert` with the
/// buttons in reverse order, so "no" is the first button, which takes Return, and "yes" stands
/// left of it [UNVERIFIED on a running macOS]. Linux: the plugin's dialog as it is; which button
/// GTK or the desktop portal focuses is theirs to decide [UNVERIFIED on a running desktop].
pub fn ask(app: &tauri::AppHandle, confirm: Confirm) -> bool {
    use tauri_plugin_dialog::{
        DialogExt as _, MessageDialogButtons, MessageDialogKind, MessageDialogResult,
    };
    let window = tauri::Manager::get_webview_window(app, crate::tray::MAIN_WINDOW);
    #[cfg(windows)]
    {
        let parent = window.as_ref().and_then(|w| w.hwnd().ok()).map(|h| h.0);
        if let Some(answer) = windows_dialog::ask(parent, &confirm) {
            return answer;
        }
    }
    let reverse = cfg!(target_os = "macos") && default_button() == DefaultButton::No;
    let yes = confirm.yes.clone();
    let buttons = if reverse {
        MessageDialogButtons::OkCancelCustom(confirm.no, confirm.yes)
    } else {
        MessageDialogButtons::OkCancelCustom(confirm.yes, confirm.no)
    };
    let mut dialog = app
        .dialog()
        .message(confirm.message)
        .title(confirm.title)
        .kind(MessageDialogKind::Warning)
        .buttons(buttons);
    if let Some(window) = &window {
        dialog = dialog.parent(window);
    }
    match dialog.blocking_show_with_result() {
        MessageDialogResult::Custom(chosen) => chosen == yes,
        MessageDialogResult::Ok | MessageDialogResult::Yes => !reverse,
        _ => false,
    }
}

/// The Windows question through `TaskDialogIndirect` (comctl32 6, which the app manifest and
/// the dialog plugin already require), with "no" as its default button.
#[cfg(windows)]
mod windows_dialog {
    use super::{answered_yes, button_id, default_button, Confirm, NO_ID, YES_ID};
    use windows_sys::Win32::UI::Controls::{
        TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOG_BUTTON,
        TDF_ALLOW_DIALOG_CANCELLATION, TDF_POSITION_RELATIVE_TO_WINDOW, TDF_SIZE_TO_CONTENT,
        TD_WARNING_ICON,
    };

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    /// The answer, or `None` when the dialog could not be shown.
    pub(super) fn ask(parent: Option<*mut core::ffi::c_void>, confirm: &Confirm) -> Option<bool> {
        let title = wide(&confirm.title);
        let message = wide(&confirm.message);
        let yes = wide(&confirm.yes);
        let no = wide(&confirm.no);
        let buttons = [
            TASKDIALOG_BUTTON {
                nButtonID: YES_ID,
                pszButtonText: yes.as_ptr(),
            },
            TASKDIALOG_BUTTON {
                nButtonID: NO_ID,
                pszButtonText: no.as_ptr(),
            },
        ];
        let config = TASKDIALOGCONFIG {
            cbSize: core::mem::size_of::<TASKDIALOGCONFIG>() as u32,
            hwndParent: parent.unwrap_or(core::ptr::null_mut()),
            dwFlags: TDF_ALLOW_DIALOG_CANCELLATION
                | TDF_SIZE_TO_CONTENT
                | TDF_POSITION_RELATIVE_TO_WINDOW,
            pszWindowTitle: title.as_ptr(),
            Anonymous1: TASKDIALOGCONFIG_0 {
                pszMainIcon: TD_WARNING_ICON,
            },
            pszContent: message.as_ptr(),
            cButtons: buttons.len() as u32,
            pButtons: buttons.as_ptr(),
            nDefaultButton: button_id(default_button()),
            ..Default::default()
        };
        let mut pressed = 0i32;
        // SAFETY: `config` is fully initialized with its own size; every string it points to
        // (`title`, `message`, `yes`, `no`) and the `buttons` array are NUL-terminated or
        // counted and outlive the call, which returns only when the dialog closed. The radio
        // button and verification out pointers may be null as the API documents. The parent
        // is the main window's handle or null; the call is modal to it.
        let hr = unsafe {
            TaskDialogIndirect(
                &config,
                &mut pressed,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        (hr >= 0).then(|| answered_yes(pressed))
    }
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

        // Before the join a device has no name: it is named by the local day it was added.
        // 2026-11-24 23:30 UTC is already the 25th in UTC+1.
        let added = 1_795_563_000_000;
        assert_eq!(
            recovery_device_label("de", "", added, 0),
            "Gerät, hinzugefügt am 2026-11-24"
        );
        assert_eq!(
            recovery_device_label("de", "  ", added, 60),
            "Gerät, hinzugefügt am 2026-11-25"
        );
        assert_eq!(recovery_device_label("de", "PC", added, 0), "PC");
        let c = recovery_cleanup(
            "de",
            &[
                recovery_device_label("de", "", added, 0),
                recovery_device_label("de", "", 0, 0),
            ],
        );
        assert!(
            c.message
                .contains("Gerät, hinzugefügt am 2026-11-24\nGerät, hinzugefügt am 1970-01-01"),
            "{}",
            c.message
        );

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
                recovery_cleanup(lang, &[recovery_device_label(lang, "", 0, 0)]),
                look_alike_name(lang, "N", "D"),
                pairing(lang, "N", &[], Some("D")),
            ] {
                assert!(complete(&c), "{lang}: {c:?}");
            }
        }
    }

    #[test]
    fn local_dates_follow_the_gregorian_calendar() {
        assert_eq!(local_date(0, 0), "1970-01-01");
        assert_eq!(local_date(951_825_600_000, 0), "2000-02-29");
        assert_eq!(local_date(-3_600_000, 0), "1969-12-31");
        assert_eq!(local_date(-3_600_000, 120), "1970-01-01");
        assert_eq!(local_date(1_795_651_200_000, -1), "2026-11-25");
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

        let c = renew_code("en", true);
        assert!(
            c.message.contains("The old one stops working"),
            "{}",
            c.message
        );
        // Without a valid code there is no old one to speak of.
        let c = renew_code("de", false);
        assert!(!c.message.contains("ersetzt den alten"), "{}", c.message);
        assert!(
            c.message
                .contains("Für dein Konto gilt gerade kein Wiederherstellungscode."),
            "{}",
            c.message
        );
        assert_eq!(c.yes, "Neuen Code übernehmen");

        let c = reset_discarding_recovery("de");
        assert!(
            c.message
                .starts_with("Wiederherstellung verwerfen und zurücksetzen?"),
            "{}",
            c.message
        );
        assert!(
            c.message.contains("nie mehr an dein Konto"),
            "{}",
            c.message
        );
        assert_eq!(c.yes, "Trotzdem zurücksetzen");
        assert_eq!(c.no, "Abbrechen");

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

        let c = incoming_delete("de", "Fotos", 342);
        assert!(
            c.message
                .starts_with("342 Dateien in „Fotos“ auch hier löschen?"),
            "{}",
            c.message
        );
        assert!(c.message.contains("Papierkorb"), "{}", c.message);
        assert_eq!(c.yes, "Ja, hier löschen");
        assert_eq!(c.no, "Abbrechen");
        let c = incoming_delete("ru", "F", 102);
        assert!(c.message.contains("102 файла"), "{}", c.message);

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
                renew_code(lang, true),
                renew_code(lang, false),
                reset_discarding_recovery(lang),
                reanchor(lang, "F", true),
                reanchor(lang, "F", false),
                accept_heads(lang, "F", &["X".to_owned()]),
                accept_heads(lang, "F", &[]),
                mass_delete(lang, "F", 3),
                incoming_delete(lang, "F", 1),
                incoming_delete(lang, "F", 120),
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

#[cfg(test)]
mod default_button_tests {
    use super::*;

    // Security review LOW 1: Enter or Space on a native question answers "no"; only the "yes"
    // button itself says yes, Escape and closing the dialog say no.
    #[test]
    fn a_key_press_never_confirms() {
        assert_eq!(default_button(), DefaultButton::No);
        assert_eq!(button_id(default_button()), NO_ID);
        assert_ne!(button_id(DefaultButton::Yes), button_id(DefaultButton::No));
        assert!(answered_yes(button_id(DefaultButton::Yes)));
        assert!(!answered_yes(button_id(default_button())));
        // IDCANCEL (Escape, the close button) and a failed dialog's 0.
        for other in [0, 1, 2, 6, 7] {
            assert!(!answered_yes(other), "{other}");
        }
    }

    // The Windows question is the app's own task dialog, not the plugin's, whose first button
    // ("yes") would be the default.
    #[test]
    fn windows_asks_in_its_own_task_dialog() {
        let source = include_str!("confirm.rs");
        let ask = &source[source.find("pub fn ask(").unwrap()..];
        let ask = &ask[..ask.find("\n}\n").unwrap()];
        let ours = ask.find("windows_dialog::ask").unwrap();
        let plugin = ask.find(".blocking_show_with_result()").unwrap();
        assert!(ours < plugin, "the task dialog comes first");
        assert!(source.contains("nDefaultButton: button_id(default_button())"));
    }
}
