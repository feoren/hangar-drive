//! `--uninstall-cleanup` (security review L1): the Windows uninstaller starts the app with this
//! argument before it removes the files (src-tauri/windows/hooks.nsh), but only when the person
//! ticked the uninstaller's box to delete the app data and this PC's device keys, never on an
//! update or an upgrade that uninstalls first; then the app forgets the account on this device:
//! the device identity and every epoch secret leave the OS keychain, and the index and settings
//! files are removed. The synced files stay where they are. Nothing else of the app runs: no
//! window, no engine, no single instance check, so a running instance cannot swallow the argument.

use std::path::Path;

use hangar_drive_sync::ports::Keychain;

/// The argument the uninstaller passes.
pub const ARG: &str = "--uninstall-cleanup";

/// Whether the process was started for the cleanup: the program and exactly this one argument,
/// as the uninstaller passes it (security review M5). The argument anywhere else, for example
/// behind a `hangar-drive://` link another program hands over, starts the app as usual.
pub fn requested(args: &[String]) -> bool {
    args.len() == 2 && args[1] == ARG
}

/// Forgets the account behind the index at `index` with `keychain`, then removes the index and
/// settings files next to it. Every step is tried; the first failure is returned as a line for the log.
pub fn forget(index: &Path, keychain: &mut dyn Keychain) -> Result<(), String> {
    let mut first: Option<String> = None;
    if index.exists() {
        match hangar_drive_sync::index::SqliteStore::open(index) {
            Ok(mut store) => {
                if let Err(e) = hangar_drive_sync::account::forget(&mut store, keychain) {
                    first.get_or_insert(e.to_string());
                }
            }
            Err(e) => {
                first.get_or_insert(e.to_string());
                // Without a readable index the secrets still go, up to the margin.
                if let Err(e) = hangar_drive_sync::account::forget_secrets(keychain, 64) {
                    first.get_or_insert(e.to_string());
                }
            }
        }
    } else if let Err(e) = hangar_drive_sync::account::forget_secrets(keychain, 64) {
        first.get_or_insert(e.to_string());
    }
    // Only the app's own files: with a per-user install the program files live in the same
    // folder (`%LOCALAPPDATA%\Hangar Drive`), and the uninstaller removes the folder itself once
    // it is empty.
    if let Some(dir) = index.parent() {
        let index_name = index.file_name().map(|n| n.to_string_lossy().into_owned());
        let mut names: Vec<String> = vec![
            crate::settings::FILE_NAME.to_owned(),
            format!("{}.tmp", crate::settings::FILE_NAME),
        ];
        if let Some(index_name) = index_name {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                names.push(format!("{index_name}{suffix}"));
            }
        }
        for name in names {
            let path = dir.join(name);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    first.get_or_insert(format!("an app file was not removed: {}", e.kind()));
                }
            }
        }
        // The folder of a development build's index holds nothing else.
        let _ = std::fs::remove_dir(dir);
    }
    first.map_or(Ok(()), Err)
}

/// The cleanup with the real keychain and index.
pub fn run() -> i32 {
    let Some(index) = crate::settings::index_path() else {
        return 0;
    };
    let mut keychain = crate::keychain::OsKeychain::new(crate::keychain::KeyringStore::default());
    match forget(&index, &mut keychain) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("hangar-drive: cleanup incomplete: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_drive_sync::memory::MemKeychain;

    #[test]
    fn the_cleanup_forgets_the_secrets_and_the_folder() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(".tmp")
            .join("cleanup")
            .join("Hangar Drive");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let index = dir.join("index.sqlite3");
        drop(hangar_drive_sync::index::SqliteStore::open(&index).unwrap());
        std::fs::write(dir.join("settings.json"), b"{}").unwrap();
        // A per-user install keeps its program files in the same folder; they stay.
        std::fs::write(dir.join("hangar-drive.exe"), b"program").unwrap();
        let mut keychain = MemKeychain::default();
        for key in ["device-identity", "epoch-1", "epoch-2"] {
            keychain.store(key, &[7; 32]).unwrap();
        }
        forget(&index, &mut keychain).unwrap();
        assert_eq!(keychain.keys(), Vec::<String>::new());
        assert!(!index.exists() && !dir.join("settings.json").exists());
        assert!(dir.join("hangar-drive.exe").exists(), "program files stay");
        // Again, with nothing left: not an error.
        forget(&index, &mut keychain).unwrap();
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    // Security review M5: only `<program> --uninstall-cleanup` runs the cleanup.
    #[test]
    fn only_the_exact_argument_runs_the_cleanup() {
        let args = |list: &[&str]| list.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
        assert!(requested(&args(&["hangar-drive.exe", ARG])));
        for other in [
            vec!["hangar-drive.exe"],
            vec!["hangar-drive.exe", "--autostart"],
            vec!["hangar-drive.exe", "hangar-drive://pair#AQID", ARG],
            vec!["hangar-drive.exe", ARG, "hangar-drive://pair#AQID"],
            vec!["hangar-drive.exe", "--autostart", ARG],
            vec!["hangar-drive.exe", "--uninstall-cleanup=1"],
            vec![ARG],
        ] {
            assert!(!requested(&args(&other)), "{other:?}");
        }
        // The app's start uses this check, not a search through the arguments.
        let lib = include_str!("lib.rs");
        assert!(lib.contains("cleanup::requested(&args)"));
        assert!(!lib.contains("any(|a| a == cleanup::ARG)"));
    }

    /// Runs the body of the hook's `NSIS_HOOK_PREUNINSTALL` with the given NSIS variables and
    /// tells whether it reaches the line that starts the cleanup. It knows only what the hook
    /// uses: LogicLib's `${If}`, `${AndIf}`, `${OrIf}`, `${Else}` and `${EndIf}` with `$Var = N`
    /// and `$Var <> N`, integer comparisons where an empty variable counts as 0, as in NSIS.
    /// Anything else fails, so a changed hook needs a look at this test.
    fn hook_reaches_the_cleanup(hook: &str, vars: &[(&str, &str)]) -> bool {
        let body = hook
            .split("!macro NSIS_HOOK_PREUNINSTALL")
            .nth(1)
            .and_then(|rest| rest.split("!macroend").next())
            .expect("the hook defines NSIS_HOOK_PREUNINSTALL");
        let eval = |condition: &str| -> bool {
            let parts: Vec<&str> = condition.split_whitespace().collect();
            let [var, op, value] = parts[..] else {
                panic!("unknown condition: {condition}");
            };
            let name = var.strip_prefix('$').expect("a variable on the left");
            let current = vars.iter().find(|(n, _)| *n == name).map_or("", |(_, v)| v);
            let number = |text: &str| text.parse::<i64>().unwrap_or(0);
            match op {
                "=" => number(current) == number(value),
                "<>" => number(current) != number(value),
                _ => panic!("unknown operator: {condition}"),
            }
        };
        // One entry per open `${If}`: whether its condition held, and whether `${Else}` came.
        let mut open: Vec<(bool, bool)> = Vec::new();
        let mut reached = false;
        for line in body.lines().map(str::trim) {
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            if let Some(condition) = line.strip_prefix("${If} ") {
                open.push((eval(condition), false));
            } else if let Some(condition) = line.strip_prefix("${AndIf} ") {
                let top = open.last_mut().expect("${AndIf} inside ${If}");
                top.0 = top.0 && eval(condition);
            } else if let Some(condition) = line.strip_prefix("${OrIf} ") {
                let top = open.last_mut().expect("${OrIf} inside ${If}");
                top.0 = top.0 || eval(condition);
            } else if line == "${Else}" {
                open.last_mut().expect("${Else} inside ${If}").1 = true;
            } else if line == "${EndIf}" {
                open.pop().expect("${EndIf} closes an ${If}");
            } else if line.starts_with("!insertmacro CheckIfAppIsRunning ") {
                // Closes a running app first; it decides nothing.
            } else if line.starts_with("DeleteRegValue HKCU ")
                && line.ends_with("\\StartupApproved\\Run\" \"${PRODUCTNAME}\"")
            {
                // The autostart's on/off value: removed on an uninstall, kept by an update.
                let runs = open.iter().all(|(held, in_else)| held != in_else);
                let update = vars.iter().any(|(n, v)| *n == "UpdateMode" && *v == "1");
                assert_eq!(
                    runs, !update,
                    "the autostart value outside update mode only"
                );
            } else if line.starts_with("ExecWait ") && line.contains(ARG) {
                reached |= open.iter().all(|(held, in_else)| held != in_else);
            } else {
                panic!("unknown line in the hook: {line}");
            }
        }
        assert!(open.is_empty(), "every ${{If}} is closed");
        reached
    }

    // The installer upgrade finding: an interactive upgrade or downgrade runs the old
    // uninstaller without /UPDATE, so only the person's tick in the confirmation page may start
    // the cleanup, never an update, and never a silent or passive uninstall, which leaves the
    // box's state empty.
    #[test]
    fn the_uninstall_hook_runs_the_cleanup_only_when_the_person_ticked_it() {
        let hook = include_str!("../windows/hooks.nsh");
        for update in ["", "0", "1"] {
            for ticked in ["", "0", "1"] {
                let vars = [
                    ("UpdateMode", update),
                    ("DeleteAppDataCheckboxState", ticked),
                ];
                assert_eq!(
                    hook_reaches_the_cleanup(hook, &vars),
                    update != "1" && ticked == "1",
                    "UpdateMode {update:?}, box {ticked:?}"
                );
            }
        }
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(
            conf["bundle"]["windows"]["nsis"]["installerHooks"],
            "windows/hooks.nsh"
        );
    }

    // The box that starts the cleanup says that the device keys go, in every installer
    // language, and the custom language files (which replace the CLI's built-in ones as a
    // whole) define the same strings.
    #[test]
    fn the_delete_box_names_the_device_keys_in_every_installer_language() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let nsis = &conf["bundle"]["windows"]["nsis"];
        let files = [
            (
                "German",
                include_str!("../windows/German.nsh"),
                "Geräteschlüssel",
            ),
            (
                "English",
                include_str!("../windows/English.nsh"),
                "device keys",
            ),
        ];
        let languages: Vec<&str> = nsis["languages"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|l| l.as_str())
            .collect();
        assert_eq!(languages, ["German", "English"]);
        let names = |text: &str| -> Vec<String> {
            let mut names: Vec<String> = text
                .lines()
                .filter_map(|l| l.strip_prefix("LangString "))
                .filter_map(|l| l.split_whitespace().next())
                .map(str::to_owned)
                .collect();
            names.sort();
            names
        };
        let expected = names(files[0].1);
        assert!(expected.len() >= 28, "the whole built-in set");
        for (language, text, keys) in files {
            assert_eq!(
                nsis["customLanguageFiles"][language],
                format!("windows/{language}.nsh")
            );
            assert_eq!(names(text), expected, "{language}");
            let label = text
                .lines()
                .find(|l| l.starts_with("LangString deleteAppData "))
                .expect("deleteAppData");
            assert!(label.contains(keys), "{language}: {label}");
            assert!(!text.contains("{{"), "{language}: no unfilled placeholder");
        }
    }
}
