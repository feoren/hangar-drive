//! The one event channel to the window, `hangar-drive://event` (src/backend/tauri/
//! tauriBackend.ts). The engine's events go out as they are (`BackendEvent`); the shell adds
//! its own: a chosen tray item (`trayAction`) and an opened link (`openLink`). Every snapshot
//! also feeds the notification policy.

use std::sync::mpsc::Receiver;

use hangar_drive_sync::api::BackendEvent;
use serde::Serialize;
use tauri::{AppHandle, Emitter as _, Manager as _};
use tauri_plugin_notification::NotificationExt as _;

use crate::state::{lock, Shell};

pub const CHANNEL: &str = "hangar-drive://event";

fn emit<T: Serialize + Clone>(app: &AppHandle, payload: T) {
    if let Err(error) = app.emit(CHANNEL, payload) {
        eprintln!("hangar-drive: event not sent: {error}");
    }
}

pub fn emit_tray_action(app: &AppHandle, id: &str) {
    emit(app, ShellEvent::tray(id));
}

pub fn emit_open_link(app: &AppHandle, link: &str) {
    emit(
        app,
        ShellEvent::OpenLink {
            link: link.to_owned(),
        },
    );
}

/// The shell's own events, in the window's `BackendEvent` shape.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ShellEvent {
    #[serde(rename_all = "camelCase")]
    TrayAction { action_id: String },
    /// The OS handed the app a `hangar-drive://` link; the window decides what it opens.
    OpenLink { link: String },
}

impl ShellEvent {
    fn tray(id: &str) -> Self {
        Self::TrayAction {
            action_id: id.to_owned(),
        }
    }
}

/// Sends a desktop notification in the backend's language.
pub fn notify(app: &AppHandle, title: &str, body: &str) {
    if let Err(error) = app.notification().builder().title(title).body(body).show() {
        eprintln!("hangar-drive: notification not shown: {error}");
    }
}

/// Forwards the engine's events until the engine stops: every snapshot is kept for the shell
/// and checked by the notification policy, then everything goes to the window.
pub fn forward(app: AppHandle, events: Receiver<BackendEvent>) {
    let spawned = std::thread::Builder::new()
        .name("hangar-drive-events".into())
        .spawn(move || {
            for event in events {
                if let BackendEvent::Snapshot { snapshot } = &event {
                    let shell = app.state::<Shell>();
                    let now = now_ms();
                    let notices = lock(&shell.policy).on_snapshot(snapshot, now);
                    let language = shell.language();
                    for notice in notices {
                        if let Some((title, body)) = crate::notifications::render(language, &notice)
                        {
                            notify(&app, &title, &body);
                        }
                    }
                    *lock(&shell.snapshot) = Some((**snapshot).clone());
                }
                if let Err(error) = app.emit(CHANNEL, &event) {
                    eprintln!("hangar-drive: event not sent: {error}");
                }
            }
        });
    if let Err(error) = spawned {
        eprintln!("hangar-drive: event thread not started: {error}");
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shell_events_have_the_window_shape() {
        assert_eq!(
            serde_json::to_value(ShellEvent::tray("pause:hour")).unwrap(),
            json!({ "type": "trayAction", "actionId": "pause:hour" })
        );
        assert_eq!(
            serde_json::to_value(ShellEvent::OpenLink {
                link: "hangar-drive://pair#AQID".into()
            })
            .unwrap(),
            json!({ "type": "openLink", "link": "hangar-drive://pair#AQID" })
        );
    }
}
