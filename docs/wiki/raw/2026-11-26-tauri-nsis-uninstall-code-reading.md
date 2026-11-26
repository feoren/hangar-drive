# Code reading and measurement: the Tauri NSIS template on upgrade and uninstall

- Date: 2026-11-26
- Method: reading the template embedded in the installed CLI, reading the bundler source, and
  compiling and running a small NSIS harness around the hook. No Hangar Drive installer was built,
  installed or uninstalled.
- Platform: Windows 11 Pro x64 (10.0.26300), NSIS 3.13 (`%LOCALAPPDATA%\tauri\NSIS\Bin\makensis.exe`,
  downloaded by the Tauri CLI).

## 1. Which template

- `pnpm tauri --version` prints `tauri-cli 2.12.6` (package `@tauri-apps/cli` 2.12.6 with the native
  module `@tauri-apps/cli-win32-x64-msvc` 2.12.6).
- The bundler embeds `installer.nsi` and the language files in that native module
  (`cli.win32-x64-msvc.node`); the text was cut out of the binary from `Unicode true` up to the end of
  the template (1022 lines) and read in full. Line numbers below refer to that extract.

## 2. When the old uninstaller gets `/UPDATE`

- `.onInit` (line 521 to 524): `${GetOptions} $CMDLINE "/UPDATE" $UpdateMode`, so `$UpdateMode` is 1
  only when the installer itself was started with `/UPDATE` (the updater does that).
- `PageReinstall` (line 219 to 324; lines 261 and 267): for an older installed version the
  first radio button is `$(uninstallBeforeInstalling)` ("Vor der Installation deinstallieren" /
  "Uninstall before installing"), for a newer one too; the first button is checked unless the person
  picked the second one before (`${If} $ReinstallPageCheck <> 2`, `BM_SETCHECK` on `$R2`).
- `PageLeaveReinstall` (line 327 to 395): with `$UpdateMode = 1` it skips the uninstall
  (`Goto reinst_done`); on an upgrade (`$R0 = 1`) or downgrade (`$R0 = -1`) with the first button
  checked it goes to `reinst_uninstall`. There it reads the old `UninstallString` and appends
  ` /UPDATE` only `${IfThen} $UpdateMode = 1`, ` /P` only in passive mode, then `_?=<install dir>`,
  and `ExecWait`s it. Without `/P` and `/S` the old uninstaller runs with its own pages.
- In passive mode (`/P`) `PageReinstall` calls `PageLeaveReinstall` directly, with the first button's
  state as read by `${NSD_GetState}`.

Result: an interactive upgrade or downgrade with the default choice runs the installed version's
uninstaller without `/UPDATE`, so `$UpdateMode` is empty there.

## 3. Where `$DeleteAppDataCheckboxState` is set

- `un.ConfirmShow` (line 455 to 483), the SHOW function of `MUI_UNPAGE_CONFIRM`, creates the check
  box with the text `$(deleteAppData)`, unchecked, always (no setting of `tauri.conf.json` turns it on
  or off).
- `un.ConfirmLeave` (line 485 to 487), the LEAVE function of that page:
  `SendMessage $DeleteAppDataCheckbox ${BM_GETCHECK} 0 0 $DeleteAppDataCheckboxState`.
- The page has `MUI_PAGE_CUSTOMFUNCTION_PRE un.SkipIfPassive`, which `Abort`s in passive mode; an
  aborted PRE skips the page, so SHOW and LEAVE do not run. A silent uninstall (`/S`) shows no page.
- `Section Uninstall` (line 821) runs on the following `MUI_UNPAGE_INSTFILES` page and starts with
  `!insertmacro NSIS_HOOK_PREUNINSTALL` (line 823 to 825). The template's own app data removal
  (line 915 to 929) is `${If} $DeleteAppDataCheckboxState = 1` `${AndIf} $UpdateMode <> 1` and deletes
  `$APPDATA\${BUNDLEID}` and `$LOCALAPPDATA\${BUNDLEID}`.

Result: the box's state is set when the confirmation page is left, before the uninstall section and
its pre-uninstall hook run; in silent and passive mode it stays an empty variable, which `= 1`
compares as 0. This also holds for the uninstall run from `PageLeaveReinstall`, because that is the
same uninstaller with the same pages.

## 4. Hooks and language files

- The hooks file is included at the top (line 35 to 37, `!include "{{installer_hooks}}"`), before
  the language files, so a hook cannot use `${LANG_GERMAN}`.
- Bundler source `crates/tauri-bundler/src/bundle/windows/nsis/mod.rs`, tag `tauri-cli-v2.12.6`,
  retrieved 2026-11-26 from
  https://raw.githubusercontent.com/tauri-apps/tauri/tauri-cli-v2.12.6/crates/tauri-bundler/src/bundle/windows/nsis/mod.rs:
  a language with an entry in `custom_language_files` uses that file instead of the built-in one
  (`dunce::canonicalize(path)`, read and written with a UTF-8 BOM, `write_utf8_with_bom`); language
  files are not rendered through handlebars.
- The built-in German and English files have 28 `LangString` entries each, among them
  `deleteAppData` ("Lösche die Anwendungsdaten" / "Delete the application data"); four of them
  (`appRunning`, `noPermissionToCloseApp`, `appRunningOkKill`, `failedToKillApp`) carry the
  placeholder `{{product_name}}`. The template reads every other entry, plus `choowHowToInstall`,
  which it defaults to an empty string itself.

## 5. Measurement: the hook compiled and run

A harness script (`SilentInstall silent`) declared `$UpdateMode` and `$DeleteAppDataCheckboxState`,
stubbed `CheckIfAppIsRunning`, included `src-tauri/windows/hooks.nsh` and both custom language files
after `MUI_LANGUAGE "German"` and `"English"`, set the two variables from its command line and
inserted `NSIS_HOOK_PREUNINSTALL`. `MAINBINARYNAME` pointed to a probe program that only writes its
command line to a file next to itself.

`makensis -V2 -WX -INPUTCHARSET UTF8 harness.nsi`: exit 0, no warnings.

| `$UpdateMode` | box state | probe started |
| --- | --- | --- |
| empty | empty | no |
| empty | 0 | no |
| empty | 1 | yes, `"...\probe.exe" --uninstall-cleanup` |
| 1 | empty, 0 or 1 | no |
| 0 | empty | no |
| 0 | 0 | no |
| 0 | 1 | yes |
