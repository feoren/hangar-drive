//! The traffic line of the main window: once a second a sampler thread reads the HTTP client's
//! byte counters ([`hangar_drive_sync::traffic`]), never the engine thread, and sends the rates
//! on `hangar-drive://traffic` to the main window, only while the window is on screen and the
//! last minute had traffic. A window that missed readings asks for the last minute with
//! `get_traffic` (src/main/trafficStore.ts).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hangar_drive_sync::traffic::{TrafficCounter, TrafficHistory, TrafficMeter, TrafficSample};
use tauri::{AppHandle, Emitter as _, Manager as _};

use crate::state::lock;

/// The window's channel for traffic readings, apart from the engine's events, so a reading
/// every second reaches only the traffic line and not the whole window.
pub const CHANNEL: &str = "hangar-drive://traffic";
/// One reading per second, the sparklines' step.
const PERIOD: Duration = Duration::from_secs(1);

/// The counter the HTTP client adds to and the meter the sampler keeps.
#[derive(Debug, Default)]
pub struct Traffic {
    counter: Arc<TrafficCounter>,
    meter: Mutex<TrafficMeter>,
}

impl Traffic {
    /// The counter to hand to the server factory.
    pub fn counter(&self) -> Arc<TrafficCounter> {
        Arc::clone(&self.counter)
    }

    /// Takes one reading now.
    pub fn sample(&self, now: Instant) -> TrafficSample {
        lock(&self.meter).sample(self.counter.totals(), now)
    }

    /// Whether the last minute had traffic worth showing.
    pub fn active(&self) -> bool {
        lock(&self.meter).active()
    }

    /// The last minute, for `get_traffic`.
    pub fn history(&self) -> TrafficHistory {
        lock(&self.meter).history()
    }
}

/// Whether the main window is on screen: shown and not minimized. Asked from the sampler
/// thread; the window methods queue onto the event loop and wait there, never in a callback of
/// it.
fn window_on_screen(app: &AppHandle) -> bool {
    let Some(window) = app.get_webview_window(crate::tray::MAIN_WINDOW) else {
        return false;
    };
    window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(false)
}

/// Quiet readings sent after the last active one. The window keeps one reading more than the
/// meter (`HISTORY_LENGTH` in src/main/traffic.ts: the minute plus the reading that scrolls out),
/// so it needs two quiet readings before its whole history is quiet and it hides the line.
const QUIET_READINGS_OWED: u8 = 2;

/// Decides which readings go to the window: every reading of a minute with traffic, then the
/// quiet ones the window still needs to hide its line, then nothing until traffic starts again.
#[derive(Debug, Default)]
struct Sender {
    owed: u8,
}

impl Sender {
    /// Whether to send the reading just taken. `on_screen` is asked only when the answer
    /// depends on it, since it waits for the event loop.
    fn send(&mut self, active: bool, on_screen: impl FnOnce() -> bool) -> bool {
        if !active && self.owed == 0 {
            return false;
        }
        if !on_screen() {
            // A hidden window misses readings; once shown again it fetches the last minute
            // through the tick gap, which is quiet by then or not.
            return false;
        }
        if active {
            self.owed = QUIET_READINGS_OWED;
        } else {
            self.owed -= 1;
        }
        true
    }
}

/// Starts the sampler thread. It runs as long as the app does.
pub fn spawn(app: AppHandle) {
    let spawned = std::thread::Builder::new()
        .name("hangar-drive-traffic".into())
        .spawn(move || {
            let mut sender = Sender::default();
            loop {
                std::thread::sleep(PERIOD);
                let traffic = app.state::<Traffic>();
                let sample = traffic.sample(Instant::now());
                // Quiet for a minute: after the readings that let the window hide its line,
                // nothing more is sent; when traffic starts again, the tick gap makes the window
                // fetch the last minute.
                if !sender.send(traffic.active(), || window_on_screen(&app)) {
                    continue;
                }
                if let Err(error) = app.emit_to(crate::tray::MAIN_WINDOW, CHANNEL, sample) {
                    eprintln!("hangar-drive: traffic not sent: {error}");
                }
            }
        });
    if let Err(error) = spawned {
        eprintln!("hangar-drive: traffic thread not started: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Acceptance review: the meter turns quiet with the reading that ends the minute, and that
    // reading was never sent, so the window kept its last line on screen for good. The window
    // keeps one reading more than the meter, so it needs two quiet readings to hide its line.
    #[test]
    fn the_window_gets_the_quiet_readings_it_needs_to_hide_its_line() {
        let mut sender = Sender::default();
        assert!(!sender.send(false, || true), "nothing while it was quiet");
        assert!(sender.send(true, || true));
        assert!(sender.send(true, || true));
        assert!(sender.send(false, || true), "the first quiet reading");
        assert!(sender.send(false, || true), "the second quiet reading");
        assert!(!sender.send(false, || true), "then nothing");
        assert!(!sender.send(false, || panic!("not asked while nothing is owed")));
        // A hidden window gets nothing; shown again, it fetches the last minute itself.
        assert!(sender.send(true, || true));
        assert!(!sender.send(true, || false));
        assert!(!sender.send(false, || false));
        assert!(sender.send(false, || true));
    }

    #[test]
    fn readings_reach_the_window_in_its_shape() {
        let traffic = Traffic::default();
        let start = Instant::now();
        traffic.sample(start);
        traffic.counter().add_sent(4_000_000);
        traffic.counter().add_received(250_000);
        let sample = traffic.sample(start + Duration::from_secs(2));
        assert_eq!(
            serde_json::to_value(sample).unwrap(),
            json!({ "tick": 2, "up": 2_000_000, "down": 125_000, "sent": 4_000_000, "received": 250_000 })
        );
        assert!(traffic.active());
        assert_eq!(
            serde_json::to_value(traffic.history()).unwrap(),
            json!({
                "tick": 2,
                "up": [0, 2_000_000],
                "down": [0, 125_000],
                "sent": 4_000_000,
                "received": 250_000
            })
        );
    }
}
