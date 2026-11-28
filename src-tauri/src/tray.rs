//! The tray (ux-concept 3, 6.1, 6.2). The window computes icon, tooltip and menu
//! (src/tray/trayModel.ts) and hands them over with `update_tray`; this module checks the model,
//! draws it natively and reports a chosen item back as the event `trayAction` with the item's
//! id. Two items act here directly, so the app stays usable even if the window's script is
//! stuck: "quit" ends the app, "openApp" brings the window to the front (and is reported too).
//! A left click shows the window, a double click runs the default item.
//!
//! The icon is the app logo with a small state dot in the bottom right corner (ux-concept 6.1),
//! rasterized at build time from app-icon.svg (build.rs) at 16, 20, 24 and 32 px; the size
//! follows the display scale. The tooltip names the state, so the dot's color is never the only
//! signal.

use std::collections::BTreeSet;
use std::sync::Mutex;

use serde::Deserialize;
use tauri::image::Image;
use tauri::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager as _, Runtime, Wry};

use crate::state::lock;

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

/// The state dot on the logo (build.rs `TRAY_BADGES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    /// The plain logo.
    None,
    /// Green: everything is up to date.
    Ok,
    /// Red: something needs the person.
    Error,
    /// Gray: nothing moves on purpose or for now.
    Idle,
}

impl Badge {
    pub fn name(self) -> &'static str {
        match self {
            Badge::None => "none",
            Badge::Ok => "ok",
            Badge::Error => "error",
            Badge::Idle => "idle",
        }
    }
}

impl TrayIcon {
    /// Which dot a state shows. Syncing has none: it is a passing state between two others, and
    /// a dot that changed color with every saved file would draw the eye all day. Setup has none
    /// either: it is also the icon at start, before the window sent its first model, and nothing
    /// is known yet. Paused and offline are gray: nothing moves, but nothing is wrong (offline
    /// is promoted to "needs you" after 24 hours, ux-concept 8.3).
    pub fn badge(self) -> Badge {
        match self {
            TrayIcon::Attention => Badge::Error,
            TrayIcon::Paused | TrayIcon::Offline => Badge::Idle,
            TrayIcon::Syncing | TrayIcon::Setup => Badge::None,
            TrayIcon::UpToDate => Badge::Ok,
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
#[derive(Default)]
pub struct TrayState {
    pub ids: Mutex<MenuIds>,
    /// The model last handed to [`apply`] with its sequence number; the same model again is
    /// not drawn twice, and only the newest one is drawn.
    requested: Mutex<Requested>,
    /// What the tray shows (the model and the icon size), touched on the main thread only.
    drawn: Mutex<Option<(TrayModel, u32)>>,
    /// The native items of the drawn menu in [`menu_plan`] order, for a change of labels.
    native: Mutex<Vec<NativeItem>>,
}

impl TrayState {
    /// Whether `model` differs from the one last handed over, and if so, takes it as the new
    /// one. The window sends a model for every snapshot, mostly an unchanged one; rebuilding
    /// the native menu for each made the tray flicker and cost the main thread every time.
    ///
    /// Returns the model's sequence number. Two `update_tray` calls can reach the main thread
    /// in the other order than they passed here (security review LOW 4), so the draw checks
    /// [`TrayState::is_newest`] and an overtaken older model is never drawn over a newer one.
    pub fn changes(&self, model: &TrayModel) -> Option<u64> {
        let mut requested = lock(&self.requested);
        if requested.model.as_ref() == Some(model) {
            return None;
        }
        requested.seq += 1;
        requested.model = Some(model.clone());
        Some(requested.seq)
    }

    /// Whether `seq` is the newest model handed over, the only one worth drawing.
    pub fn is_newest(&self, seq: u64) -> bool {
        lock(&self.requested).seq == seq
    }

    /// After a failed draw of `seq`: what the tray shows is unknown, so the same model again
    /// is drawn rather than skipped. A newer model already on its way is left alone.
    fn forget(&self, seq: u64) {
        let mut requested = lock(&self.requested);
        if requested.seq == seq {
            requested.model = None;
        }
    }
}

/// The newest model handed over and its sequence number (0 before the first).
#[derive(Default)]
struct Requested {
    seq: u64,
    model: Option<TrayModel>,
}

/// A native item of the drawn menu; separators carry no text.
enum NativeItem {
    Item(MenuItem<Wry>),
    Submenu(Submenu<Wry>),
    Separator,
}

impl NativeItem {
    fn set_text(&self, text: &str) -> tauri::Result<()> {
        match self {
            NativeItem::Item(item) => item.set_text(text),
            NativeItem::Submenu(submenu) => submenu.set_text(text),
            NativeItem::Separator => Ok(()),
        }
    }
}

/// How the drawn menu becomes the next one.
#[derive(Debug, PartialEq, Eq)]
pub enum MenuPlan {
    /// Nothing in the menu changed (only the tooltip or the icon, if anything).
    Keep,
    /// Same items, new labels: (index in depth-first order, label). A count of files that
    /// moves while syncing changes only a label, and relabeling keeps an open menu open.
    Relabel(Vec<(usize, String)>),
    /// The items themselves changed.
    Rebuild,
}

/// Compares the drawn menu with the next one. Items match when their kind, id and children
/// match; `isDefault` and `muted` are not drawn natively, so they never force a rebuild.
pub fn menu_plan(drawn: Option<&[TrayMenuItem]>, next: &[TrayMenuItem]) -> MenuPlan {
    fn walk(
        old: &[TrayMenuItem],
        new: &[TrayMenuItem],
        index: &mut usize,
        labels: &mut Vec<(usize, String)>,
    ) -> bool {
        if old.len() != new.len() {
            return false;
        }
        for (a, b) in old.iter().zip(new) {
            let at = *index;
            *index += 1;
            let label = match (a, b) {
                (TrayMenuItem::Separator, TrayMenuItem::Separator) => continue,
                (TrayMenuItem::Label { label: x, .. }, TrayMenuItem::Label { label: y, .. }) => {
                    (x, y)
                }
                (
                    TrayMenuItem::Action {
                        id: i, label: x, ..
                    },
                    TrayMenuItem::Action {
                        id: j, label: y, ..
                    },
                ) if i == j => (x, y),
                (
                    TrayMenuItem::Submenu { label: x, items: c },
                    TrayMenuItem::Submenu { label: y, items: d },
                ) => {
                    if x != y {
                        labels.push((at, y.clone()));
                    }
                    if !walk(c, d, index, labels) {
                        return false;
                    }
                    continue;
                }
                _ => return false,
            };
            if label.0 != label.1 {
                labels.push((at, label.1.clone()));
            }
        }
        true
    }
    let Some(old) = drawn else {
        return MenuPlan::Rebuild;
    };
    let mut labels = Vec::new();
    if !walk(old, next, &mut 0, &mut labels) {
        MenuPlan::Rebuild
    } else if labels.is_empty() {
        MenuPlan::Keep
    } else {
        MenuPlan::Relabel(labels)
    }
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

/// The rasterized icon (straight RGBA) of a state at a size. The logo brings its own dark tile,
/// so one icon serves light and dark taskbars.
pub fn icon_rgba(icon: TrayIcon, size: u32) -> Option<&'static [u8]> {
    let badge = icon.badge().name();
    TRAY_ICONS
        .iter()
        .find(|(name, s, _)| *name == badge && *s == size)
        .map(|(_, _, rgba)| *rgba)
}

fn image(icon: TrayIcon, scale: f64) -> Option<Image<'static>> {
    let size = icon_size(scale);
    icon_rgba(icon, size).map(|rgba| Image::new(rgba, size, size))
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
    // No template image on macOS: the menu bar would flatten the colored logo and its dot into
    // one silhouette.
    if let Some(icon) = image(TrayIcon::Setup, scale(app)) {
        builder = builder.icon(icon);
    }
    builder.build(app)?;
    Ok(())
}

/// The native items of `items`; `native` collects them in [`menu_plan`] order (an item, then
/// the children of a submenu).
fn build_items(
    app: &AppHandle,
    items: &[TrayMenuItem],
    native: &mut Vec<NativeItem>,
) -> tauri::Result<Vec<Box<dyn IsMenuItem<Wry>>>> {
    let mut out: Vec<Box<dyn IsMenuItem<Wry>>> = Vec::new();
    for item in items {
        match item {
            TrayMenuItem::Label { label, .. } => {
                let item = MenuItem::new(app, label, false, None::<&str>)?;
                native.push(NativeItem::Item(item.clone()));
                out.push(Box::new(item));
            }
            TrayMenuItem::Separator => {
                native.push(NativeItem::Separator);
                out.push(Box::new(PredefinedMenuItem::separator(app)?));
            }
            TrayMenuItem::Action { id, label, .. } => {
                let item = MenuItem::with_id(app, id.as_str(), label, true, None::<&str>)?;
                native.push(NativeItem::Item(item.clone()));
                out.push(Box::new(item));
            }
            TrayMenuItem::Submenu { label, items } => {
                let at = native.len();
                native.push(NativeItem::Separator);
                let children = build_items(app, items, native)?;
                let refs: Vec<&dyn IsMenuItem<Wry>> = children.iter().map(|c| c.as_ref()).collect();
                let submenu = Submenu::with_items(app, label, true, &refs)?;
                native[at] = NativeItem::Submenu(submenu.clone());
                out.push(Box::new(submenu));
            }
        }
    }
    Ok(out)
}

/// Draws a checked model on the main thread, touching only what changed against the drawn one:
/// labels are set on the existing items where only they changed, the menu is rebuilt only when
/// its items changed, tooltip and icon only when they differ. `seq` is the number
/// [`TrayState::changes`] gave the model; a model that a newer one overtook is skipped, and its
/// ids are taken only together with its menu.
pub fn apply(app: &AppHandle, seq: u64, model: TrayModel, ids: MenuIds) -> tauri::Result<()> {
    let handle = app.clone();
    app.run_on_main_thread(move || {
        let state = handle.state::<TrayState>();
        if !state.is_newest(seq) {
            return;
        }
        let Some(tray) = handle.tray_by_id(TRAY_ID) else {
            return;
        };
        *lock(&state.ids) = ids;
        let mut drawn = lock(&state.drawn);
        let mut native = lock(&state.native);
        let size = icon_size(scale(&handle));
        let before = drawn.as_ref();
        let mut plan = menu_plan(before.map(|(m, _)| m.menu.as_slice()), &model.menu);
        if let MenuPlan::Relabel(labels) = &plan {
            if labels.iter().any(|(at, _)| *at >= native.len()) {
                plan = MenuPlan::Rebuild;
            }
        }
        let result = (|| -> tauri::Result<()> {
            match plan {
                MenuPlan::Keep => {}
                MenuPlan::Relabel(labels) => {
                    for (at, label) in labels {
                        if let Some(item) = native.get(at) {
                            item.set_text(&label)?;
                        }
                    }
                }
                MenuPlan::Rebuild => {
                    let mut fresh = Vec::new();
                    let items = build_items(&handle, &model.menu, &mut fresh)?;
                    let refs: Vec<&dyn IsMenuItem<Wry>> =
                        items.iter().map(|c| c.as_ref()).collect();
                    let menu = Menu::with_items(&handle, &refs)?;
                    tray.set_menu(Some(menu))?;
                    *native = fresh;
                }
            }
            if before.map(|(m, _)| m.tooltip.as_str()) != Some(model.tooltip.as_str()) {
                tray.set_tooltip(Some(&model.tooltip))?;
            }
            if before.map(|(m, s)| (m.icon, *s)) != Some((model.icon, size)) {
                if let Some(icon) = image(model.icon, scale(&handle)) {
                    tray.set_icon(Some(icon))?;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => *drawn = Some((model, size)),
            Err(error) => {
                // Unknown what the tray shows now: the next model draws everything again.
                *drawn = None;
                native.clear();
                state.forget(seq);
                eprintln!("hangar-drive: tray not updated: {error}");
            }
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

    fn menu(value: serde_json::Value) -> Vec<TrayMenuItem> {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn the_same_model_is_handed_over_once() {
        let state = TrayState::default();
        let first = model(json!([{ "type": "separator" }]));
        assert!(state.changes(&first).is_some());
        assert!(
            state.changes(&first.clone()).is_none(),
            "an unchanged model is skipped"
        );
        let mut other = first.clone();
        other.tooltip = "Hangar Drive: syncing".into();
        assert!(state.changes(&other).is_some());
        assert!(state.changes(&first).is_some(), "going back is a change");
    }

    // Security review LOW 4: model A passes `changes` before B, but A's draw reaches the main
    // thread after B's. A is skipped there, so the tray ends on B, and B again stays skipped
    // as unchanged because B is what the tray shows.
    #[test]
    fn an_overtaken_model_is_never_drawn_over_a_newer_one() {
        let state = TrayState::default();
        let a = model(json!([{ "type": "separator" }]));
        let mut b = a.clone();
        b.tooltip = "Hangar Drive: syncing".into();
        let seq_a = state.changes(&a).unwrap();
        let seq_b = state.changes(&b).unwrap();
        // The main thread runs B's draw first, then A's.
        assert!(state.is_newest(seq_b), "B is drawn");
        assert!(!state.is_newest(seq_a), "A arrives late and is skipped");
        assert!(state.changes(&b).is_none(), "the tray shows B already");
        // A failed draw of an overtaken model leaves the newer one alone ...
        state.forget(seq_a);
        assert!(state.changes(&b).is_none());
        // ... and a failed draw of the newest lets the same model through again.
        state.forget(seq_b);
        let again = state.changes(&b).unwrap();
        assert!(state.is_newest(again));
    }

    #[test]
    fn only_changed_labels_are_set_and_new_items_rebuild_the_menu() {
        let drawn = menu(json!([
            { "type": "label", "label": "Syncing 3 files", "muted": false },
            { "type": "separator" },
            { "type": "action", "id": "openApp", "label": "Open", "isDefault": true },
            { "type": "submenu", "label": "Pause", "items": [
                { "type": "action", "id": "pause:hour", "label": "For 1 hour", "isDefault": false }
            ] },
            { "type": "action", "id": "quit", "label": "Quit", "isDefault": false }
        ]));
        assert_eq!(menu_plan(None, &drawn), MenuPlan::Rebuild);
        assert_eq!(menu_plan(Some(&drawn), &drawn), MenuPlan::Keep);

        let mut counted = drawn.clone();
        counted[0] = TrayMenuItem::Label {
            label: "Syncing 2 files".into(),
            muted: true,
        };
        counted[4] = TrayMenuItem::Action {
            id: "quit".into(),
            label: "Beenden".into(),
            is_default: true,
        };
        // Index 5 is the action after the submenu (3) and its one child (4).
        assert_eq!(
            menu_plan(Some(&drawn), &counted),
            MenuPlan::Relabel(vec![(0, "Syncing 2 files".into()), (5, "Beenden".into())])
        );
        let TrayMenuItem::Submenu { items, .. } = &mut counted[3] else {
            panic!("submenu");
        };
        items[0] = TrayMenuItem::Action {
            id: "pause:hour".into(),
            label: "1 Stunde".into(),
            is_default: false,
        };
        assert_eq!(
            menu_plan(Some(&drawn), &counted),
            MenuPlan::Relabel(vec![
                (0, "Syncing 2 files".into()),
                (4, "1 Stunde".into()),
                (5, "Beenden".into())
            ])
        );

        let mut resumed = drawn.clone();
        resumed[3] = TrayMenuItem::Action {
            id: "resume".into(),
            label: "Resume".into(),
            is_default: false,
        };
        assert_eq!(menu_plan(Some(&drawn), &resumed), MenuPlan::Rebuild);
        let mut other_id = drawn.clone();
        other_id[2] = TrayMenuItem::Action {
            id: "showProblem".into(),
            label: "Open".into(),
            is_default: true,
        };
        assert_eq!(menu_plan(Some(&drawn), &other_id), MenuPlan::Rebuild);
        assert_eq!(menu_plan(Some(&drawn), &drawn[..4]), MenuPlan::Rebuild);
    }

    const ALL: [TrayIcon; 6] = [
        TrayIcon::Attention,
        TrayIcon::Paused,
        TrayIcon::Offline,
        TrayIcon::Syncing,
        TrayIcon::UpToDate,
        TrayIcon::Setup,
    ];

    fn rgb(hex: &str) -> [u8; 3] {
        let channel = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
        [channel(1), channel(3), channel(5)]
    }

    fn pixel(rgba: &[u8], size: u32, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * size + x) * 4) as usize;
        [rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]]
    }

    fn badge_color(badge: Badge) -> Option<[u8; 3]> {
        TRAY_BADGE_COLORS
            .iter()
            .find(|(name, _)| *name == badge.name())
            .map(|(_, hex)| rgb(hex))
    }

    /// A token of the dark theme (`:root`) in src/styles.css.
    fn dark_token(name: &str) -> String {
        let css = include_str!("../../src/styles.css");
        let start = css.find(":root {").unwrap();
        let block = &css[start..start + css[start..].find("\n}").unwrap()];
        let needle = format!("--{name}: ");
        let at = block.find(&needle).unwrap() + needle.len();
        block[at..at + 7].to_owned()
    }

    #[test]
    fn every_state_shows_its_dot() {
        assert_eq!(TrayIcon::UpToDate.badge(), Badge::Ok);
        assert_eq!(TrayIcon::Attention.badge(), Badge::Error);
        assert_eq!(TrayIcon::Paused.badge(), Badge::Idle);
        assert_eq!(TrayIcon::Offline.badge(), Badge::Idle);
        assert_eq!(TrayIcon::Syncing.badge(), Badge::None);
        assert_eq!(TrayIcon::Setup.badge(), Badge::None);
    }

    #[test]
    fn every_state_has_an_icon_per_size_with_its_dot() {
        for icon in ALL {
            for size in [16, 20, 24, 32] {
                let rgba = icon_rgba(icon, size).unwrap();
                assert_eq!(rgba.len(), (size * size * 4) as usize);
                // The logo's rounded corners stay transparent; the ring's edge reaches into the
                // bottom right one only when there is a dot.
                assert_eq!(pixel(rgba, size, 0, 0)[3], 0, "{icon:?} {size}");
                assert_eq!(pixel(rgba, size, size - 1, 0)[3], 0, "{icon:?} {size}");
                if icon.badge() == Badge::None {
                    let corner = pixel(rgba, size, size - 1, size - 1);
                    assert_eq!(corner[3], 0, "{icon:?} {size}");
                }
                // The middle of the dot carries the state's color, solid.
                let c = TRAY_BADGE_CENTER * size / 256;
                let middle = pixel(rgba, size, c, c);
                match badge_color(icon.badge()) {
                    Some(color) => assert_eq!(middle, [color[0], color[1], color[2], 255]),
                    None => {
                        for (_, hex) in TRAY_BADGE_COLORS {
                            assert_ne!(middle[..3], rgb(hex), "{icon:?} {size}");
                        }
                    }
                }
            }
        }
        // The dark ring separates the dot from the D (32 px, between dot and D).
        let ring = rgb(TRAY_BADGE_RING);
        let rgba = icon_rgba(TrayIcon::UpToDate, 32).unwrap();
        assert_eq!(pixel(rgba, 32, 20, 20), [ring[0], ring[1], ring[2], 255]);
        assert_eq!(icon_size(1.0), 16);
        assert_eq!(icon_size(1.25), 20);
        assert_eq!(icon_size(1.5), 24);
        assert_eq!(icon_size(2.0), 32);
    }

    #[test]
    fn the_small_icons_leave_out_the_cream_squares() {
        let cream = rgb(&dark_token("logo-squares"));
        let has_cream = |size: u32| {
            icon_rgba(TrayIcon::Syncing, size)
                .unwrap()
                .chunks(4)
                .any(|p| p[..3] == cream && p[3] == 255)
        };
        assert!(!has_cream(16));
        assert!(!has_cream(20));
        assert!(has_cream(24));
        assert!(has_cream(32));
    }

    #[test]
    fn the_dot_colors_follow_the_window_tokens() {
        let hex = |badge: Badge| {
            TRAY_BADGE_COLORS
                .iter()
                .find(|(name, _)| *name == badge.name())
                .map(|(_, hex)| *hex)
                .unwrap()
        };
        assert_eq!(hex(Badge::Error), dark_token("error"));
        assert_eq!(hex(Badge::Idle), dark_token("muted"));
        assert_eq!(TRAY_BADGE_RING, dark_token("logo-tile"));
        // The green dot is not the logo's green, or it would read as part of the D.
        assert_ne!(hex(Badge::Ok), dark_token("logo-fold"));
        let [r, g, b] = rgb(hex(Badge::Ok));
        assert!(g > r && g > b, "the up to date dot is green");
        assert_eq!(TRAY_BADGE_COLORS.len(), 3);
    }
}
