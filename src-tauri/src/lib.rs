//! Hangar Drive backend: owns all file and network access, the frontend only renders.
//!
//! The shell around the sync engine (`hangar_drive_sync`): it starts the engine thread with
//! the real ports (the SQLite index in the platform's config folder, the OS keychain, the
//! local file system, the HTTP client), answers the window's commands ([`commands`]), forwards
//! the engine's events on `hangar-drive://event` ([`events`]) and owns everything of the
//! operating system: tray, single instance, `hangar-drive://` links, autostart, dialogs,
//! notifications, clipboard and the file manager.

mod cleanup;
mod clipboard;
mod commands;
mod confirm;
mod deeplink;
mod documents;
mod error;
mod events;
mod keychain;
mod notifications;
mod platform;
mod print;
mod qr;
mod settings;
mod state;
mod texts;
mod tray;
mod updater;

use std::time::Duration;

use hangar_drive_sync::engine::{
    real_fs_factory, real_root_check, real_server_factory, Engine, EngineCore, EngineHandle,
    EnginePorts, EngineSettings,
};
use hangar_drive_sync::error::SyncError;
use tauri::{AppHandle, Manager as _, Url, WindowEvent};
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_deep_link::DeepLinkExt as _;

use crate::state::{lock, Shell};

/// The pause between two passes of the engine's control loop while no command arrives: a
/// local change syncs within this, and an idle device asks the server about this often.
const ENGINE_TICK: Duration = Duration::from_secs(5);
/// The argument the autostart entry passes, so a start at sign-in stays in the tray.
const AUTOSTART_ARG: &str = "--autostart";

/// The engine with the real ports, built on the engine thread.
fn open_engine(settings: EngineSettings) -> Result<EngineCore, SyncError> {
    let index =
        settings::index_path().ok_or(SyncError::NotSetUp("no config folder on this system"))?;
    let store = hangar_drive_sync::index::SqliteStore::open(&index)?;
    let ports = EnginePorts {
        store: Box::new(store),
        keychain: Box::new(keychain::OsKeychain::new(keychain::KeyringStore::default())),
        clock: Box::new(hangar_drive_sync::ports::SystemClock),
        entropy: Box::new(hangar_drive_crypto::OsEntropy),
        fs: real_fs_factory(),
        server: real_server_factory(),
        roots: real_root_check(),
    };
    EngineCore::open(ports, settings)
}

/// Hands an opened link to the window and brings it to the front. A link the app was started
/// with waits until the window listens (it is sent after the first `get_snapshot`); a link that
/// arrives later goes out at once.
fn open_link(app: &AppHandle, text: &str, at_start: bool) -> bool {
    let Some(link) = deeplink::classify(text) else {
        return false;
    };
    if at_start {
        app.state::<deeplink::Pending>().put(link);
    } else {
        events::emit_open_link(app, &link.link);
    }
    tray::show_main_window(app);
    true
}

/// Closing the main window hides it; the first time, a notification says the app keeps
/// running (ux-concept 3). Quitting is in the tray menu only.
fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
    let WindowEvent::CloseRequested { api, .. } = event else {
        return;
    };
    if window.label() != tray::MAIN_WINDOW {
        return;
    }
    api.prevent_close();
    if let Err(error) = window.hide() {
        eprintln!("hangar-drive: window not hidden: {error}");
    }
    let app = window.app_handle();
    let shell = app.state::<Shell>();
    let first = {
        let mut settings = lock(&shell.settings);
        !std::mem::replace(&mut settings.close_hint_shown, true)
    };
    if first {
        let language = shell.language();
        if let Some(text) = texts::text(language, "tray.stillRunning") {
            let body = texts::fill(language, text, &Default::default());
            let title = texts::text(language, "app.name").unwrap_or("Hangar Drive");
            events::notify(app, title, &body);
        }
        let _ = shell.save_settings();
    }
}

/// The dev server of `pnpm tauri dev` (tauri.conf.json `build.devUrl`).
const DEV_ORIGIN: (&str, &str, u16) = ("http", "localhost", 1420);

/// Whether the main window may load `url` (security review L3): only the app's own origin
/// (`tauri://localhost` on macOS and Linux, `http://tauri.localhost` on Windows, where WebView2
/// maps the scheme), and in a development build the dev server too. Everything else, a link in
/// a file name or a page a compromised script navigates to, stays out of the window.
pub fn main_may_navigate(url: &Url, development: bool) -> bool {
    let host = url.host_str();
    let own = match url.scheme() {
        "tauri" => host == Some("localhost"),
        "http" | "https" => host == Some("tauri.localhost") && url.port().is_none(),
        _ => false,
    };
    let dev = development
        && url.scheme() == DEV_ORIGIN.0
        && host == Some(DEV_ORIGIN.1)
        && url.port() == Some(DEV_ORIGIN.2);
    own || dev
}

/// The main window, built here rather than from tauri.conf.json so it gets its navigation
/// guard; hidden until `show_main_window`.
fn build_main_window(app: &tauri::App) -> tauri::Result<()> {
    tauri::WebviewWindowBuilder::new(
        app,
        tray::MAIN_WINDOW,
        tauri::WebviewUrl::App("index.html".into()),
    )
    .title("Hangar Drive")
    .inner_size(720.0, 520.0)
    .min_inner_size(640.0, 420.0)
    .visible(false)
    // A file dropped on the window would reach the page as a drop event with its path; the
    // window has no use for it, and the backend takes places only through its own dialogs
    // (security review, information finding).
    .disable_drag_drop_handler()
    .on_navigation(|url| main_may_navigate(url, cfg!(debug_assertions)))
    // `window.open` and links with a target would open a second WebView without the navigation
    // guard; the page needs none (security review, hardening).
    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
    .build()
    .map(drop)
}

/// Whether the device is set up, asked of the engine directly (no event has come yet).
fn is_set_up(engine: &EngineHandle) -> bool {
    engine
        .call(|core| core.snapshot().setup == hangar_drive_sync::api::SetupState::Done)
        .unwrap_or(false)
}

fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let handle = app.handle().clone();
    let settings_path = settings::default_path();
    let stored = settings_path
        .as_deref()
        .map(settings::Stored::load)
        .unwrap_or_default();
    let tz = platform::tz_offset_minutes();
    let engine_settings = EngineSettings {
        words: texts::label_words(state::language_of(&stored.language)),
        tz_offset_minutes: tz,
        camera: false,
    };
    let (engine, receiver) = match Engine::spawn(move || open_engine(engine_settings), ENGINE_TICK)
    {
        Ok((engine, receiver)) => (Ok(engine), Some(receiver)),
        Err(error) => {
            eprintln!("hangar-drive: the sync engine did not start: {error}");
            (Err(error.to_string()), None)
        }
    };
    let set_up = engine.as_ref().is_ok_and(is_set_up);
    let shell = Shell::new(engine, tz, settings_path, stored);
    // Autostart is on by default (ux-concept 3, 11), applied once; a release build only, so a
    // development build never registers itself to start at sign-in.
    if !cfg!(debug_assertions) && !lock(&shell.settings).autostart_applied {
        if let Err(error) = handle.autolaunch().enable() {
            eprintln!("hangar-drive: autostart not enabled: {error}");
        }
        lock(&shell.settings).autostart_applied = true;
        let _ = shell.save_settings();
    }
    app.manage(shell);
    app.manage(deeplink::Pending::default());
    app.manage(tray::TrayState::default());
    app.manage(print::PrintPage::default());
    build_main_window(app)?;
    tray::create(&handle)?;
    if let Some(receiver) = receiver {
        events::forward(handle.clone(), receiver);
    }

    // `hangar-drive://` links: registered for this user on Windows and Linux (macOS through
    // the bundle's Info.plist); a release build only, so a development build never takes the
    // scheme from the installed app.
    #[cfg(any(windows, target_os = "linux"))]
    if !cfg!(debug_assertions) {
        if let Err(error) = handle.deep_link().register_all() {
            eprintln!("hangar-drive: link scheme not registered: {error}");
        }
    }
    let links = handle.clone();
    handle.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            open_link(&links, url.as_str(), false);
        }
    });
    let mut started_with_link = false;
    if let Ok(Some(urls)) = handle.deep_link().get_current() {
        for url in &urls {
            started_with_link |= open_link(&handle, url.as_str(), true);
        }
    }

    // A start at sign-in stays in the tray once the device is set up; every other start, and
    // every start before the setup is done, shows the window (ux-concept 3).
    let autostarted = std::env::args().any(|a| a == AUTOSTART_ARG);
    if !autostarted || !set_up || started_with_link {
        tray::show_main_window(&handle);
    }
    Ok(())
}

/// Starts the app and returns once it quits. With [`cleanup::ARG`] (the uninstaller) it only
/// forgets the account on this device and exits.
pub fn run() -> tauri::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if cleanup::requested(&args) {
        std::process::exit(cleanup::run());
    }
    let context = tauri::generate_context!();
    let updates = updater::Updates {
        enabled: updater::configured(context.config().plugins.0.get("updater")),
    };
    let mut builder = tauri::Builder::default();
    // Registered only with a public key and an endpoint in tauri.conf.json: its configuration
    // needs both, and without them no update may run (`install_update` refuses).
    if updates.enabled {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }
    builder
        // First: a second start hands its link to this one and exits before anything else of
        // it runs. With the `deep-link` feature the link arrives through `on_open_url`.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![AUTOSTART_ARG]),
        ))
        .manage(updates)
        .register_uri_scheme_protocol(print::SCHEME, print::respond)
        .setup(setup)
        .on_window_event(on_window_event)
        .invoke_handler(command_handler!())
        .build(context)?
        .run(|app, event| match event {
            // The tray keeps the app alive without a visible window; only `quit` (an exit
            // with a code) ends it.
            tauri::RunEvent::ExitRequested {
                code: None, api, ..
            } => api.prevent_exit(),
            // Every way out (the window's and the tray's Quit, the system ending the session)
            // passes here; a copied code must not outlive the app (security review LOW 2).
            tauri::RunEvent::Exit => commands::clear_copied_secret(app),
            _ => {}
        });
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    // Security review L3: the main window loads only the app's own origin, and the dev server
    // only in a development build.
    #[test]
    fn the_main_window_stays_on_its_own_origin() {
        let url = |t: &str| tauri::Url::parse(t).unwrap();
        for own in [
            "tauri://localhost/",
            "tauri://localhost/index.html#/settings",
            "http://tauri.localhost/",
            "https://tauri.localhost/index.html",
        ] {
            assert!(super::main_may_navigate(&url(own), false), "{own}");
        }
        assert!(super::main_may_navigate(
            &url("http://localhost:1420/"),
            true
        ));
        assert!(!super::main_may_navigate(
            &url("http://localhost:1420/"),
            false
        ));
        for other in [
            "https://drive.example/",
            "http://localhost:1421/",
            "http://tauri.localhost.evil/",
            "http://tauri.localhost:8080/",
            "file:///C:/Windows/",
            "hangar-print://localhost/x",
            "http://hangar-print.localhost/x",
            "javascript:alert(1)",
            "data:text/html,x",
        ] {
            assert!(!super::main_may_navigate(&url(other), true), "{other}");
        }
        // The main window is built in code (with the guard), not from the config.
        let conf: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["app"]["windows"], serde_json::json!([]));
    }

    /// The source of `build_main_window`, up to the next function.
    fn main_window_builder() -> &'static str {
        let source = include_str!("lib.rs");
        let start = source.find("fn build_main_window").unwrap();
        let end = start
            + source[start..]
                .find(
                    "
}
",
                )
                .unwrap();
        &source[start..end]
    }

    // Security review, information finding: files dropped on the main window never reach the
    // page; the builder turns the WebView's drag and drop handler off.
    #[test]
    fn the_main_window_takes_no_dropped_files() {
        let builder = main_window_builder();
        assert!(
            builder.contains(".disable_drag_drop_handler()"),
            "{builder}"
        );
        assert!(builder.contains(".build()"));
    }

    // Hardening: neither window lets its page open another one, and the page's prototypes are
    // frozen; the CSP names every source kind the page does not use.
    #[test]
    fn the_pages_open_no_windows_and_load_only_their_own_scripts() {
        let deny = ".on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)";
        assert!(main_window_builder().contains(deny));
        let commands = include_str!("commands.rs");
        let print = &commands[commands.find("crate::print::WINDOW,").unwrap()..];
        assert!(print[..print.find(".build()").unwrap()].contains(deny));
        let conf: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let security = &conf["app"]["security"];
        assert_eq!(security["freezePrototype"], Value::Bool(true));
        let csp = security["csp"].as_str().unwrap();
        for directive in [
            "default-src 'self'",
            "script-src 'self'",
            "frame-src 'none'",
            "worker-src 'none'",
            "object-src 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ] {
            assert!(csp.split("; ").any(|d| d == directive), "{directive}");
        }
        assert!(!csp.contains("unsafe-eval"));
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
    }

    // ADR 0001, section 8: the installer ships the notices of the MPL-2.0 and BSL-1.0 crates
    // (generated by tools/third_party_notices.py, checked against Cargo.lock there).
    #[test]
    fn the_bundle_ships_the_third_party_notices() {
        let conf: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(
            conf["bundle"]["resources"]["../THIRD_PARTY_NOTICES.md"],
            "THIRD_PARTY_NOTICES.md"
        );
        let notices = include_str!("../../THIRD_PARTY_NOTICES.md");
        for name in [
            "option-ext",
            "cssparser",
            "selectors",
            "dtoa-short",
            "xxhash-rust",
        ] {
            assert!(notices.contains(&format!("\n| {name} | ")), "{name}");
        }
        assert!(notices.contains("Mozilla Public License Version 2.0"));
    }

    fn version_in(json: &str) -> String {
        let value: Value = serde_json::from_str(json).unwrap();
        value["version"].as_str().unwrap().to_owned()
    }

    // The code always carries the upcoming version, in all three places at once: the crate, the
    // Tauri config (installer and window) and package.json (frontend).
    #[test]
    fn crate_tauri_config_and_package_json_carry_the_same_version() {
        let crate_version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            version_in(include_str!("../tauri.conf.json")),
            crate_version,
            "tauri.conf.json"
        );
        assert_eq!(
            version_in(include_str!("../../package.json")),
            crate_version,
            "package.json"
        );
    }

    /// X.Y.Z of `X.Y.Z` or `X.Y.Z+B` (ADR 0002); `None` for anything else, such as `X.Y.Z-B`.
    fn base_version(version: &str) -> Option<[u64; 3]> {
        let (base, build) = match version.split_once('+') {
            Some((base, build)) => (base, Some(build)),
            None => (version, None),
        };
        if build.is_some_and(|build| build.is_empty() || !build.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        let mut parts = base.split('.').map(|part| {
            (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                .then(|| part.parse::<u64>().ok())
                .flatten()
        });
        let parsed = [parts.next()??, parts.next()??, parts.next()??];
        parts.next().is_none().then_some(parsed)
    }

    #[test]
    fn base_version_reads_only_the_internal_forms() {
        assert_eq!(base_version("0.12.224+1548"), Some([0, 12, 224]));
        assert_eq!(base_version("0.10.0"), Some([0, 10, 0]));
        assert_eq!(base_version("0.1.0-12"), None);
        assert_eq!(base_version("0.1.0+"), None);
        assert_eq!(base_version("0.1"), None);
        assert_eq!(base_version("0.1.0.4"), None);
    }

    // The internal form is X.Y.Z or X.Y.Z+B: NSIS takes the Windows file version X.Y.Z.B only from
    // the build metadata after "+", and "-B" would make it a pre-release.
    #[test]
    fn the_crate_version_follows_the_scheme() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(base_version(version).is_some(), "{version}");
    }

    // The code carries the upcoming version, so its X.Y.Z is the highest entry in the changelog.
    #[test]
    fn the_crate_version_is_the_highest_changelog_entry() {
        let changelog: Value =
            serde_json::from_str(include_str!("../../src/changelog.json")).unwrap();
        let highest = changelog
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| base_version(entry["version"].as_str().unwrap()).unwrap())
            .max()
            .unwrap();
        assert_eq!(
            base_version(env!("CARGO_PKG_VERSION")).unwrap(),
            highest,
            "changelog.json"
        );
    }
}
