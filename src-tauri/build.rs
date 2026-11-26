// The build script does three things:
//
// 1. Registers the app's commands (`COMMANDS`), so Tauri generates one permission per command
//    (allow-<command>) and the window may only call what capabilities/default.json grants.
// 2. Rasterizes the tray icons of src/tray/icons/*.svg with resvg at 16, 20, 24 and 32 px for a
//    light and a dark taskbar, as straight RGBA, into OUT_DIR (`tray_icons.rs`). The window's
//    icons.ts writes the SVGs and a test there keeps them equal, so the geometry has one source.
// 3. Extracts the texts the backend shows itself (notifications, native confirmations) from
//    src/i18n.ts for all twelve languages into OUT_DIR (`texts.rs`), so there is still only one
//    text catalog (project rule: every UI text lives in the i18n module).
//
// A build script reports errors to Cargo by panicking; that is the intended interface.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Every command of src/commands.rs; lib.rs registers the same list.
const COMMANDS: &[&str] = &[
    "get_snapshot",
    "read_clipboard_text",
    "check_invite",
    "inspect_link",
    "default_device_name",
    "begin_account",
    "print_recovery_sheet",
    "save_recovery_file",
    "copy_recovery_code",
    "confirm_recovery_group",
    "default_folder_place",
    "pick_folder",
    "count_local_files",
    "finish_setup",
    "scan_with_camera",
    "start_pairing",
    "cancel_pairing",
    "list_account_folders",
    "join_folders",
    "recover_account",
    "set_device_name",
    "recovery_devices",
    "finish_recovery_cleanup",
    "open_folder",
    "pause",
    "resume",
    "sync_now",
    "retry_connection",
    "pause_folder",
    "resume_folder",
    "add_folder",
    "add_account_folder",
    "stop_folder",
    "delete_folder_everywhere",
    "list_not_synced",
    "get_folder_number",
    "list_mass_delete",
    "resolve_mass_delete",
    "find_missing_folder",
    "check_older_state",
    "reanchor",
    "dismiss_suspect",
    "accept_removed_heads",
    "open_storage_settings",
    "copy_error_report",
    "preview_error_report",
    "save_error_report",
    "list_conflicts",
    "open_conflict",
    "keep_conflict_version",
    "keep_both_conflict",
    "list_name_issues",
    "rename_name_issue",
    "ignore_name_issue",
    "get_timeline",
    "get_tree_at",
    "restore_file",
    "reset_folder",
    "find_before_device",
    "get_trash",
    "restore_trash",
    "list_devices",
    "rename_device",
    "get_safety_number",
    "remove_device",
    "create_pairing_offer",
    "copy_pairing_link",
    "answer_pair_request",
    "renew_recovery_code",
    "reset_device",
    "disconnect_this_device",
    "undo",
    "restore_deleted_folder",
    "cancel_restore",
    "redownload_folder",
    "get_server_number",
    "confirm_server_number",
    "fix_server_with_offer",
    "restore_remote_deleted",
    "confirm_device_removed",
    "install_update",
    "get_settings",
    "set_autostart",
    "set_language",
    "get_about",
    "update_tray",
    "show_window",
    "quit",
];

/// The tray icons by state, as named in src/tray/icons.ts (`iconFileName`).
const TRAY_ICONS: &[(&str, &str)] = &[
    ("attention", "tray-attention.svg"),
    ("paused", "tray-paused.svg"),
    ("offline", "tray-offline.svg"),
    ("syncing", "tray-syncing.svg"),
    ("upToDate", "tray-up-to-date.svg"),
    ("setup", "tray-setup.svg"),
];
const TRAY_SIZES: &[u32] = &[16, 20, 24, 32];
/// Glyph colors per taskbar: the window's `--text` and `--error` tokens of the light and the
/// dark theme (src/styles.css), so tray and window speak one language.
const THEMES: &[(&str, &str, &str)] = &[
    // (theme, glyph, attention)
    ("light", "#1f2328", "#cf222e"),
    ("dark", "#ffffff", "#f47067"),
];

/// Text keys the backend shows itself; a key ending in `.` takes every key with that prefix.
const TEXT_KEYS: &[&str] = &[
    "app.name",
    "tray.stillRunning",
    "conflict.noticeMany.",
    "conflict.fileWord",
    "restore.fileWord",
    "deletes.title.",
    "missing.title",
    "older.title",
    "suspect.title",
    "suspect.titleFolder",
    "removedHeads.title",
    "quotaFull.title",
    "serverDisk.title",
    "disk.title",
    "heads.title",
    // The native confirmations (security review L2, src/confirm.rs).
    "pair.confirm.title",
    "pair.confirm.body",
    "pair.confirm.yes",
    "pair.confirm.no",
    "folder.delete.title",
    "folder.delete.confirm",
    "folder.delete.body.",
    "common.cancel",
    "server.fix.compareTitle",
    "server.number.label",
    "server.fix.yes",
    "server.fix.no",
    // The native confirmations of the overall security review (M4, H1).
    "devices.remove",
    "devices.remove.title",
    "devices.remove.body",
    "devices.remove.lost",
    "devices.disconnect",
    "devices.disconnect.body",
    "devices.lastOne",
    "devices.lastOne.confirm",
    "reset.question",
    "reset.body",
    "reset.confirm",
    "devices.recovery.renewConfirm",
    "devices.recovery.renewBody",
    "devices.recovery.renewYes",
    "older.confirm.title",
    "older.confirm.merge",
    "older.confirm.loss",
    "older.confirm.go",
    "older.blind.title",
    "older.blind.body",
    "older.blind.go",
    "heads.body",
    "heads.bodyMany.",
    "heads.confirm",
    "heads.accept",
    "deletes.body.",
    "deletes.confirm",
    "settings.autostart.offTitle",
    "settings.autostart.offBody",
    "settings.autostart.offConfirm",
    "update.confirm.title",
    "update.confirm.yes",
    "merge.title.",
    "merge.body.",
    "merge.host",
    "merge.confirm",
    "merge.chooseOther",
    "removalReported.question",
    "removalReported.questionBody",
    "removalReported.yes",
    // The native questions of the follow-up check (N-1, N-2) and the device name skeleton check.
    "restore.folder.ask",
    "restore.folder.askGone.",
    "restore.folder.askNoneGone",
    "restore.folder.askBody",
    "restore.folder.confirm",
    "recover.cleanup.ask.",
    "recover.cleanup.askBody",
    "pair.request.lookAlike",
    "devices.lookAlike.question",
    "devices.lookAlike.yes",
];

fn main() {
    let manifest_dir = PathBuf::from(env("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.join("..");
    let out = PathBuf::from(env("OUT_DIR"));
    tray_icons(&root.join("src").join("tray").join("icons"), &out);
    texts(&root.join("src").join("i18n.ts"), &out);

    let windows = tauri_build::WindowsAttributes::new()
        .app_manifest(include_str!("windows-app-manifest.xml"));
    let attributes = tauri_build::Attributes::new()
        .windows_attributes(windows)
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    println!("cargo:rerun-if-changed=windows-app-manifest.xml");
    if let Err(error) = tauri_build::try_build(attributes) {
        panic!("Tauri build failed: {error:#}");
    }
}

fn env(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(_) => panic!("{name} is not set"),
    }
}

fn tray_icons(dir: &Path, out: &Path) {
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut code = String::from(
        "/// (icon, theme, size, straight RGBA) of every tray icon, rasterized by build.rs.\n\
         pub const TRAY_ICONS: &[(&str, &str, u32, &[u8])] = &[\n",
    );
    for (icon, file) in TRAY_ICONS {
        let path = dir.join(file);
        println!("cargo:rerun-if-changed={}", path.display());
        let svg = match std::fs::read_to_string(&path) {
            Ok(svg) => svg,
            Err(error) => panic!("cannot read {}: {error}", path.display()),
        };
        for (theme, glyph, attention) in THEMES {
            let color = if *icon == "attention" {
                attention
            } else {
                glyph
            };
            for size in TRAY_SIZES {
                let rgba = rasterize(&svg.replace("currentColor", color), *size, file);
                let name = format!("tray-{icon}-{theme}-{size}.rgba");
                if let Err(error) = std::fs::write(out.join(&name), &rgba) {
                    panic!("cannot write {name}: {error}");
                }
                let _ = writeln!(
                    code,
                    "    ({icon:?}, {theme:?}, {size}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{name}\"))),"
                );
            }
        }
    }
    code.push_str("];\n");
    if let Err(error) = std::fs::write(out.join("tray_icons.rs"), code) {
        panic!("cannot write tray_icons.rs: {error}");
    }
}

/// The SVG drawn into a `size` square, as straight (not premultiplied) RGBA.
fn rasterize(svg: &str, size: u32, file: &str) -> Vec<u8> {
    use resvg::{tiny_skia, usvg};
    let tree = match usvg::Tree::from_str(svg, &usvg::Options::default()) {
        Ok(tree) => tree,
        Err(error) => panic!("{file} does not parse: {error}"),
    };
    let Some(mut pixmap) = tiny_skia::Pixmap::new(size, size) else {
        panic!("no pixmap of {size} px");
    };
    let scale = size as f32 / tree.size().width().max(tree.size().height());
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for pixel in pixmap.pixels() {
        let c = pixel.demultiply();
        rgba.extend_from_slice(&[c.red(), c.green(), c.blue(), c.alpha()]);
    }
    rgba
}

fn texts(i18n: &Path, out: &Path) {
    println!("cargo:rerun-if-changed={}", i18n.display());
    let source = match std::fs::read_to_string(i18n) {
        Ok(source) => source,
        Err(error) => panic!("cannot read {}: {error}", i18n.display()),
    };
    let entries = parse_dictionaries(&source);
    if !entries
        .iter()
        .any(|(lang, key, _)| lang == "de" && key == "app.name")
    {
        panic!("src/i18n.ts: no German dictionary with app.name found");
    }
    let mut code = String::from(
        "/// (language, key, text) of the texts the backend shows, from src/i18n.ts.\n\
         pub const TEXTS: &[(&str, &str, &str)] = &[\n",
    );
    for (lang, key, text) in &entries {
        let _ = writeln!(code, "    ({lang:?}, {key:?}, {text:?}),");
    }
    code.push_str("];\n");
    if let Err(error) = std::fs::write(out.join("texts.rs"), code) {
        panic!("cannot write texts.rs: {error}");
    }
}

fn wanted(key: &str) -> bool {
    TEXT_KEYS.iter().any(|wanted| {
        if wanted.ends_with('.') {
            key.starts_with(wanted)
        } else {
            key == *wanted
        }
    })
}

/// Every `"key": "text"` of every `const xx = {` or `const xx: Dictionary = {` block. The
/// catalog's format is regular (one double-quoted text per key, the text on the key's line or
/// the next one, no escapes and no concatenation); anything else fails the build loudly.
fn parse_dictionaries(source: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut lang: Option<String> = None;
    let mut pending: Option<String> = None;
    for (number, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("const ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase())
                .collect();
            if name.len() == 2 && (trimmed.ends_with("= {") || trimmed.ends_with("Dictionary = {"))
            {
                lang = Some(name);
                continue;
            }
        }
        let Some(current) = &lang else {
            continue;
        };
        if trimmed == "};" {
            lang = None;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        if let Some(key) = pending.take() {
            push(&mut out, current, key, trimmed, number);
            continue;
        }
        let Some(rest) = trimmed.strip_prefix('"') else {
            continue;
        };
        let Some((key, value)) = rest.split_once("\":") else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            pending = Some(key.to_owned());
        } else {
            push(&mut out, current, key.to_owned(), value, number);
        }
    }
    out
}

/// Takes a wanted key's text; a wanted key's text in another form fails the build, other keys
/// are not looked at.
fn push(
    out: &mut Vec<(String, String, String)>,
    lang: &str,
    key: String,
    value: &str,
    number: usize,
) {
    if !wanted(&key) {
        return;
    }
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix("\",").or_else(|| v.strip_suffix('"')));
    match inner {
        Some(text) if !text.contains('"') && !text.contains('\\') => {
            out.push((lang.to_owned(), key, text.to_owned()))
        }
        _ => panic!(
            "src/i18n.ts line {}: expected one plain double-quoted text",
            number + 1
        ),
    }
}
