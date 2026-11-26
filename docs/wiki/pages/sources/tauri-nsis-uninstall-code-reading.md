---
title: "Code reading: Tauri's NSIS template on upgrade and uninstall"
type: source
tags: [tauri, nsis, windows, installer, uninstall, keychain]
sources: []
raw: raw/2026-11-26-tauri-nsis-uninstall-code-reading.md
url: https://raw.githubusercontent.com/tauri-apps/tauri/tauri-cli-v2.12.6/crates/tauri-bundler/src/bundle/windows/nsis/mod.rs
retrieved: 2026-11-26
created: 2026-11-26
updated: 2026-11-26
---

# Code reading: Tauri's NSIS template on upgrade and uninstall

Own reading of the template embedded in tauri-cli 2.12.6 and of the bundler source at that tag,
plus a compiled and run NSIS harness around `src-tauri/windows/hooks.nsh` (NSIS 3.13). No Hangar
Drive installer was installed or uninstalled.

## Key points
- **`/UPDATE` only from the updater:** the installer sets `$UpdateMode` from its own `/UPDATE`
  argument, and `PageLeaveReinstall` passes `/UPDATE` to the old uninstaller only then. An
  interactive upgrade or downgrade has "uninstall before installing" preselected and runs the
  installed version's uninstaller without `/UPDATE`, with its normal pages.
- **The "delete app data" box:** always shown on the uninstaller's confirmation page, unchecked;
  its state reaches `$DeleteAppDataCheckboxState` in `un.ConfirmLeave`, before `Section Uninstall`
  and `NSIS_HOOK_PREUNINSTALL`. Silent (`/S`) and passive (`/P`) uninstalls skip the page and leave
  the variable empty (compared as 0).
- **Language files:** an entry in `customLanguageFiles` replaces the built-in file of that
  language as a whole; language files are not rendered, so the built-in `{{product_name}}`
  placeholder stays literal. The hooks file is included before the languages.
- **Measured:** the hook with `${If} $UpdateMode <> 1` `${AndIf} $DeleteAppDataCheckboxState = 1`
  starts the cleanup only for a ticked box outside update mode; makensis compiles the hook and both
  custom language files without warnings.

## Significance for Hangar Drive
- A check of `$UpdateMode` alone made every manual upgrade forget the device's keys and index;
  the cleanup now needs the tick, see the amendment "Installer upgrade keeps the device keys" in
  [[0001-foundation]].
- The custom German and English files must be compared with the built-in ones after every CLI
  update; the release checklist in [[0002-version-scheme]] carries the manual installer check.
