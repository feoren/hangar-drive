//! Live progress of a running round.
//!
//! The engine sends a snapshot after every pass, about once per second while it works. Within a
//! pass a round reports the bytes it moved (an object the server confirmed, a chunk written to
//! the disk) through a [`Progress`], and the engine turns them into throttled snapshots
//! ([`LIVE_EVERY`]) whose bytes left go down meanwhile, so the window moves smoothly during a
//! long upload or the download of a large file without a storm of events.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::api::{BackendEvent, Snapshot};

/// The least time between two live snapshots: at most five per second.
pub const LIVE_EVERY: Duration = Duration::from_millis(200);

/// Where a round reports the bytes it moved. The default reports nowhere.
#[derive(Clone, Default)]
pub struct Progress(Option<Arc<dyn Fn(u64) + Send + Sync>>);

impl std::fmt::Debug for Progress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Progress").field(&self.0.is_some()).finish()
    }
}

impl Progress {
    /// Reports through `report`.
    pub fn new(report: impl Fn(u64) + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(report)))
    }

    /// `bytes` more of the transfer are done.
    pub fn moved(&self, bytes: u64) {
        if let Some(report) = &self.0 {
            report(bytes);
        }
    }
}

/// The engine's side: the snapshot the pass started from and what moved since.
#[derive(Default)]
struct LiveState {
    base: Option<Snapshot>,
    moved: u64,
    last: Option<Instant>,
    events: Option<std::sync::mpsc::Sender<BackendEvent>>,
}

/// Turns the bytes a pass moved into throttled snapshots for the window.
#[derive(Clone, Default)]
pub struct Live(Arc<Mutex<LiveState>>);

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live").finish_non_exhaustive()
    }
}

impl Live {
    fn lock(&self) -> std::sync::MutexGuard<'_, LiveState> {
        // Plain values; one written by a thread that panicked is still whole.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Live snapshots go to `events` from now on.
    pub fn send_to(&self, events: std::sync::mpsc::Sender<BackendEvent>) {
        self.lock().events = Some(events);
    }

    /// A pass starts from `base`, the snapshot the window shows.
    pub fn start(&self, base: Option<Snapshot>) {
        let mut state = self.lock();
        state.base = base;
        state.moved = 0;
    }

    /// The [`Progress`] the rounds report to.
    pub fn progress(&self) -> Progress {
        let live = self.clone();
        Progress::new(move |bytes| live.moved(bytes, Instant::now()))
    }

    fn moved(&self, bytes: u64, now: Instant) {
        let mut state = self.lock();
        state.moved = state.moved.saturating_add(bytes);
        if state
            .last
            .is_some_and(|at| now.saturating_duration_since(at) < LIVE_EVERY)
        {
            return;
        }
        let (Some(base), Some(events)) = (&state.base, &state.events) else {
            return;
        };
        let mut snapshot = base.clone();
        snapshot.sync.bytes_left = snapshot.sync.bytes_left.saturating_sub(state.moved);
        if events
            .send(BackendEvent::Snapshot {
                snapshot: Box::new(snapshot),
            })
            .is_ok()
        {
            state.last = Some(now);
        }
    }
}
