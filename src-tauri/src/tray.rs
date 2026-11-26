//! The tray (ux-concept 3, 6.1, 6.2). The window computes icon, tooltip and menu
//! (src/tray/trayModel.ts) and hands them over with `update_tray`; this module checks the model,
//! draws it natively and reports a chosen item back as the event `trayAction` with the item's
//! id. Two items act here directly, so the app stays usable even if the window's script is
//! stuck: "quit" ends the app, "openApp" brings the window to the front (and is reported too).
//! A left click shows the window, a double click runs the default item.
//!
//! The icons are rasterized at build time from src/tray/icons/*.svg (build.rs) for a light and a
//! dark taskbar at 16, 20, 24 and 32 px; the size follows the display scale.

use std::collections::BTreeSet;
use std::sync::Mutex;

use serde::Deserialize;
use tauri::image::Image;
use tauri::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager as _, Runtime, Wry};

include!(concat!(env!("OUT_DIR"), "/tray_icons.rs"));

pub const TRAY_ID: &str = "main";
pub const MAIN_WINDOW: &str = "main";
/// Labels are UI texts of one line; longer ones are a mistake, not a translation.
const MAX_LABEL_CHARS: usize = 96;
/// Windows cuts tray tooltips at 127 characters (`NOTIFYICONDATAW::szTip`).
const MAX_TOOLTIP_CHARS: usize = 127;
const MAX_ITEMS: usize = 64;
const MAX_ID_LEN: usize = 160;
pub const QUIT_ID: &str = "quit";
pub const OPEN_APP_ID: &str = "openApp";

/// The icon states of src/tray/trayModel.ts (`TrayIcon`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrayIcon {
    Attention,
    Paused,
    Offline,
    Syncing,
    UpToDate,
    Setup,
}

impl TrayIcon {
    pub fn name(self) -> &'static str {
        match self {
            TrayIcon::Attention => "attention",
            TrayIcon::Paused => "paused",
            TrayIcon::Offline => "offline",
            TrayIcon::Syncing => "syncing",
            TrayIcon::UpToDate => "upToDate",
            TrayIcon::Setup => "setup",
        }
    }
}

/// One item of the window's menu (`TrayMenuItem`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum TrayMenuItem {
    Label {
        label: String,
        muted: bool,
    },
    Separator,
    Action {
        id: String,
        label: String,
        #[serde(rename = "isDefault")]
        is_default: bool,
    },
    Submenu {
        label: String,
        items: Vec<TrayMenuItem>,
    },
}

/// The window's model (`TrayModel`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrayModel {
    pub icon: TrayIcon,
    pub tooltip: String,
    pub menu: Vec<TrayMenuItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrayError {
    #[error("the tray menu has more than {MAX_ITEMS} items")]
    TooManyItems,
    #[error("a tray submenu holds another submenu")]
    TooDeep,
    #[error("a tray menu id is not valid")]
    BadId,
}

/// The ids the current menu may report, and the default item.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MenuIds {
    pub actions: BTreeSet<String>,
    pub default: Option<String>,
}

/// The tray's state between updates.
#[derive(Debug, Default)]
pub struct TrayState {
    pub ids: Mutex<MenuIds>,
}

fn clean(text: &str, max: usize, keep_newlines: bool) -> String {
    let text: String = text
        .chars()
        .map(|c| {
            if c == '\n' && keep_newlines {
                c
            } else if c.is_control() {
                ' '
            } else {
                c
            }
        })
        .take(max)
        .collect();
    text.trim().to_owned()
}

/// A label as the native menu shows it: one line, and `&` doubled, because the menu reads a
/// single `&` as the mark of an access key.
fn menu_label(text: &str) -> String {
    clean(text, MAX_LABEL_CHARS, false).replace('&', "&&")
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_'))
}

impl TrayModel {
    /// Checks the model and returns it cleaned with its ids: at most [`MAX_ITEMS`] items, one
    /// level of submenus, ids of `[A-Za-z0-9:_-]`, one line per label, the tooltip within the
    /// platform's limit.
    pub fn checked(mut self) -> Result<(Self, MenuIds), TrayError> {
        let mut ids = MenuIds::default();
        let mut count = 0usize;
        fn walk(
            items: &mut [TrayMenuItem],
            depth: usize,
            ids: &mut MenuIds,
            count: &mut usize,
        ) -> Result<(), TrayError> {
            for item in items {
                *count += 1;
                if *count > MAX_ITEMS {
                    return Err(TrayError::TooManyItems);
                }
                match item {
                    TrayMenuItem::Label { label, .. } => *label = menu_label(label),
                    TrayMenuItem::Separator => {}
                    TrayMenuItem::Action {
                        id,
                        label,
                        is_default,
                    } => {
                        if !valid_id(id) {
                            return Err(TrayError::BadId);
                        }
                        *label = menu_label(label);
                        ids.actions.insert(id.clone());
                        if *is_default && ids.default.is_none() {
                            ids.default = Some(id.clone());
                        }
                    }
                    TrayMenuItem::Submenu { label, items } => {
                        if depth > 0 {
                            return Err(TrayError::TooDeep);
                        }
                        *label = menu_label(label);
                        walk(items, depth + 1, ids, count)?;
                    }
                }
            }
            Ok(())
        }
        walk(&mut self.menu, 0, &mut ids, &mut count)?;
        self.tooltip = clean(&self.tooltip, MAX_TOOLTIP_CHARS, true);
        Ok((self, ids))
    }
}

/// The tray icon size for a display scale: 16 px at 100 %, 20 at 125 %, 24 at 150 %, 32 from
/// 200 %.
pub fn icon_size(scale: f64) -> u32 {
    if scale >= 1.75 {
        32
    } else if scale >= 1.375 {
        24
    } else if scale >= 1.125 {
        20
    } else {
        16
    }
}

/// The rasterized icon (straight RGBA) of a state for a taskbar theme and size.
pub fn icon_rgba(icon: TrayIcon, dark_taskbar: bool, size: u32) -> Option<&'static [u8]> {
    let theme = if dark_taskbar { "dark" } else { "light" };
    TRAY_ICONS
        .iter()
        .find(|(name, t, s, _)| *name == icon.name() && *t == theme && *s == size)
        .map(|(_, _, _, rgba)| *rgba)
}

fn image(icon: TrayIcon, scale: f64) -> Option<Image<'static>> {
    let size = icon_size(scale);
    // The macOS menu bar tints a template image itself; it gets the dark glyph.
    let dark = !cfg!(target_os = "macos") && crate::platform::taskbar_is_dark();
    icon_rgba(icon, dark, size).map(|rgba| Image::new(rgba, size, size))
}

fn scale<R: Runtime>(app: &AppHandle<R>) -> f64 {
    app.get_webview_window(MAIN_WINDOW)
        .and_then(|w| w.scale_factor().ok())
        .unwrap_or(1.0)
}

/// Shows, unminimizes and focuses the main window.
pub fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        // Each step may fail harmlessly (already visible, not minimized).
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// What a chosen id does: quit and open the window here; every known id is reported.
fn on_action(app: &AppHandle, id: &str) {
    if id == QUIT_ID {
        app.exit(0);
        return;
    }
    let known = app
        .state::<TrayState>()
        .ids
        .lock()
        .map(|ids| ids.actions.contains(id))
        .unwrap_or(false);
    if id == OPEN_APP_ID {
        show_main_window(app);
    }
    if known {
        crate::events::emit_tray_action(app, id);
    }
}

/// Builds the icon once at start, before the window sent a model.
pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip(crate::texts::text("en", "app.name").unwrap_or("Hangar Drive"))
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| on_action(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| match event {
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } => show_main_window(tray.app_handle()),
            TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => {
                let app = tray.app_handle();
                let default = app
                    .state::<TrayState>()
                    .ids
                    .lock()
                    .ok()
                    .and_then(|ids| ids.default.clone());
                if let Some(id) = default {
                    on_action(app, &id);
                }
            }
            _ => {}
        });
    if let Some(icon) = image(TrayIcon::Setup, scale(app)) {
        builder = builder.icon(icon);
    }
    #[cfg(target_os = "macos")]
    {
        builder = builder.icon_as_template(true);
    }
    builder.build(app)?;
    Ok(())
}

fn build_items(
    app: &AppHandle,
    items: &[TrayMenuItem],
) -> tauri::Result<Vec<Box<dyn IsMenuItem<Wry>>>> {
    let mut out: Vec<Box<dyn IsMenuItem<Wry>>> = Vec::new();
    for item in items {
        match item {
            TrayMenuItem::Label { label, .. } => {
                out.push(Box::new(MenuItem::new(app, label, false, None::<&str>)?));
            }
            TrayMenuItem::Separator => out.push(Box::new(PredefinedMenuItem::separator(app)?)),
            TrayMenuItem::Action { id, label, .. } => {
                out.push(Box::new(MenuItem::with_id(
                    app,
                    id.as_str(),
                    label,
                    true,
                    None::<&str>,
                )?));
            }
            TrayMenuItem::Submenu { label, items } => {
                let children = build_items(app, items)?;
                let refs: Vec<&dyn IsMenuItem<Wry>> = children.iter().map(|c| c.as_ref()).collect();
                out.push(Box::new(Submenu::with_items(app, label, true, &refs)?));
            }
        }
    }
    Ok(out)
}

/// Draws a checked model: icon, tooltip and menu, on the main thread.
pub fn apply(app: &AppHandle, model: TrayModel, ids: MenuIds) -> tauri::Result<()> {
    if let Ok(mut current) = app.state::<TrayState>().ids.lock() {
        *current = ids;
    }
    let handle = app.clone();
    app.run_on_main_thread(move || {
        let Some(tray) = handle.tray_by_id(TRAY_ID) else {
            return;
        };
        let result = (|| -> tauri::Result<()> {
            let items = build_items(&handle, &model.menu)?;
            let refs: Vec<&dyn IsMenuItem<Wry>> = items.iter().map(|c| c.as_ref()).collect();
            let menu = Menu::with_items(&handle, &refs)?;
            tray.set_menu(Some(menu))?;
            tray.set_tooltip(Some(&model.tooltip))?;
            if let Some(icon) = image(model.icon, scale(&handle)) {
                tray.set_icon(Some(icon))?;
            }
            #[cfg(target_os = "macos")]
            tray.set_icon_as_template(true)?;
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("hangar-drive: tray not updated: {error}");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn model(menu: serde_json::Value) -> TrayModel {
        serde_json::from_value(
            json!({ "icon": "upToDate", "tooltip": "Hangar Drive: up to date", "menu": menu }),
        )
        .unwrap()
    }

    #[test]
    fn the_window_model_reads_as_the_tray_model_writes_it() {
        let (checked, ids) = model(json!([
            { "type": "label", "label": "All up to date", "muted": false },
            { "type": "label", "label": "Last: Plan & Co.docx", "muted": true },
            { "type": "separator" },
            { "type": "action", "id": "open-folder:0123", "label": "Open folder", "isDefault": true },
            { "type": "action", "id": "openApp", "label": "Open Hangar Drive", "isDefault": false },
            { "type": "submenu", "label": "Pause", "items": [
                { "type": "action", "id": "pause:hour", "label": "For 1 hour", "isDefault": false }
            ] },
            { "type": "action", "id": "quit", "label": "Quit", "isDefault": false }
        ]))
        .checked()
        .unwrap();
        assert_eq!(checked.icon, TrayIcon::UpToDate);
        assert_eq!(ids.default.as_deref(), Some("open-folder:0123"));
        assert!(ids.actions.contains("pause:hour"));
        assert_eq!(ids.actions.len(), 4);
        assert_eq!(
            checked.menu[1],
            TrayMenuItem::Label {
                label: "Last: Plan && Co.docx".into(),
                muted: true
            }
        );
    }

    #[test]
    fn odd_models_are_refused_or_cleaned() {
        let deep = model(json!([{ "type": "submenu", "label": "a", "items": [
            { "type": "submenu", "label": "b", "items": [] }
        ] }]));
        assert_eq!(deep.checked(), Err(TrayError::TooDeep));
        let bad_id =
            model(json!([{ "type": "action", "id": "a b", "label": "x", "isDefault": false }]));
        assert_eq!(bad_id.checked(), Err(TrayError::BadId));
        let many: Vec<_> = (0..65).map(|_| json!({ "type": "separator" })).collect();
        assert_eq!(model(json!(many)).checked(), Err(TrayError::TooManyItems));
        let (long, _) =
            model(json!([{ "type": "label", "label": "x\r\n".repeat(200), "muted": false }]))
                .checked()
                .unwrap();
        let TrayMenuItem::Label { label, .. } = &long.menu[0] else {
            panic!("label");
        };
        assert!(label.chars().count() <= MAX_LABEL_CHARS);
        assert!(!label.contains('\n'));
        let mut m = model(json!([]));
        m.tooltip = format!("Hangar Drive: up to date\nfiles wait{}", "!".repeat(300));
        let (m, _) = m.checked().unwrap();
        assert!(m.tooltip.contains('\n'));
        assert!(m.tooltip.chars().count() <= MAX_TOOLTIP_CHARS);
        assert!(serde_json::from_value::<TrayModel>(
            json!({ "icon": "x", "tooltip": "", "menu": [] })
        )
        .is_err());
    }

    #[test]
    fn every_state_has_an_icon_per_theme_and_size() {
        for icon in [
            TrayIcon::Attention,
            TrayIcon::Paused,
            TrayIcon::Offline,
            TrayIcon::Syncing,
            TrayIcon::UpToDate,
            TrayIcon::Setup,
        ] {
            for dark in [false, true] {
                for size in [16, 20, 24, 32] {
                    let rgba = icon_rgba(icon, dark, size).unwrap();
                    assert_eq!(rgba.len(), (size * size * 4) as usize);
                    // Something is drawn, and the corners stay transparent.
                    assert!(rgba.chunks(4).any(|p| p[3] > 200), "{icon:?} {size}");
                    assert_eq!(rgba[3], 0);
                }
            }
        }
        // The glyph follows the taskbar: dark on light, light on dark.
        let light = icon_rgba(TrayIcon::UpToDate, false, 32).unwrap();
        let dark = icon_rgba(TrayIcon::UpToDate, true, 32).unwrap();
        let opaque = |rgba: &[u8]| rgba.chunks(4).find(|p| p[3] == 255).map(|p| p[0]).unwrap();
        assert!(opaque(light) < 0x40);
        assert!(opaque(dark) > 0xc0);
        assert_eq!(icon_size(1.0), 16);
        assert_eq!(icon_size(1.25), 20);
        assert_eq!(icon_size(1.5), 24);
        assert_eq!(icon_size(2.0), 32);
    }
}
