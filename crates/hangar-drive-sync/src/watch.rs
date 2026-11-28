//! The change watcher: `notify` 9 only as the trigger (ADR 0001, section 3). The truth is the
//! scan: a watcher event names paths for a partial scan, and a rescan event (Windows dropped
//! details or overflowed its buffer, FSEvents `MustScanSubDirs` or dropped events, inotify
//! `IN_Q_OVERFLOW`) asks for a full scan at once. The engine adds a full scan every hour, so a
//! lost event is found within the hour even when the platform does not report the loss.
//!
//! Events are collected without blocking the watcher's thread; the engine drains them on its
//! control thread ([`FolderWatcher::drain`]). Each event also rings the engine's [`Waker`], so a
//! local change starts a pass after a short debounce instead of waiting for the loop's pause.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::localfs::LocalFs;
use crate::ports::FsError;

/// What the watcher found since the last drain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// Paths below the root that changed (with 8.3 names resolved).
    pub paths: BTreeSet<Vec<String>>,
    /// The platform lost events: scan everything.
    pub rescan: bool,
}

/// Changed paths one drain keeps at most; beyond, a full scan is cheaper than a partial scan of
/// that many paths, and the list would otherwise grow with every event of a mass change
/// (security review, info).
pub const MAX_CHANGED_PATHS: usize = 10_000;

impl Changes {
    /// Whether nothing happened.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && !self.rescan
    }

    /// Notes a changed path; past [`MAX_CHANGED_PATHS`] the list goes and a full scan is due.
    pub fn add_path(&mut self, path: Vec<String>) {
        if self.rescan {
            return;
        }
        self.paths.insert(path);
        if self.paths.len() > MAX_CHANGED_PATHS {
            self.set_rescan();
        }
    }

    /// A full scan is due; the paths are not needed any more.
    pub fn set_rescan(&mut self) {
        self.rescan = true;
        self.paths.clear();
    }
}

/// Wakes the engine loop from another thread (the watcher's). Cheap to clone; ringing it never
/// blocks, and the engine debounces the rings itself.
#[derive(Clone)]
pub struct Waker(Arc<dyn Fn() + Send + Sync>);

impl Waker {
    /// A waker that calls `wake` on every ring.
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(wake))
    }

    /// Asks the engine loop for a pass soon.
    pub fn wake(&self) {
        (self.0)()
    }
}

impl std::fmt::Debug for Waker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Waker").finish_non_exhaustive()
    }
}

/// The waker a change source rings, set once the engine loop runs.
type WakerSlot = Arc<Mutex<Option<Waker>>>;

fn ring(slot: &WakerSlot) {
    let waker = match slot.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn set_slot(slot: &WakerSlot, waker: Waker) {
    match slot.lock() {
        Ok(mut guard) => *guard = Some(waker),
        Err(poisoned) => *poisoned.into_inner() = Some(waker),
    }
}

/// Anything that reports changes of a sync root: the real watcher, or the event log of the
/// in-memory file system in tests.
pub trait ChangeSource {
    /// Every change since the last call, waiting up to `wait` for the first one.
    fn drain(&self, wait: Duration) -> Changes;

    /// Rings `waker` on every later change, so the engine loop wakes for it. A source that
    /// cannot ring leaves the change to the loop's next regular pass.
    fn set_waker(&self, _waker: Waker) {}
}

impl ChangeSource for FolderWatcher {
    fn drain(&self, wait: Duration) -> Changes {
        FolderWatcher::drain(self, wait)
    }

    fn set_waker(&self, waker: Waker) {
        set_slot(&self.waker, waker);
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ChangeSource for std::sync::Arc<crate::memory::MemFs> {
    fn drain(&self, _wait: Duration) -> Changes {
        let paths: BTreeSet<Vec<String>> = self
            .take_events()
            .into_iter()
            .filter(|p| {
                !p.first().is_some_and(|n| {
                    n.eq_ignore_ascii_case(hangar_drive_protocol::name::RESERVED_ROOT_DIR)
                })
            })
            .collect();
        Changes {
            paths,
            rescan: false,
        }
    }

    fn set_waker(&self, waker: Waker) {
        self.set_user_waker(waker);
    }
}

enum Raw {
    Paths(Vec<PathBuf>),
    Rescan,
}

/// Watches one sync root.
pub struct FolderWatcher {
    // Dropping the watcher stops it.
    _watcher: RecommendedWatcher,
    events: Receiver<Raw>,
    root: LocalFs,
    waker: WakerSlot,
}

impl std::fmt::Debug for FolderWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderWatcher")
            .field("root", &self.root.root())
            .finish_non_exhaustive()
    }
}

impl FolderWatcher {
    /// Starts watching `root` recursively.
    pub fn start(root: &LocalFs) -> Result<Self, FsError> {
        let (tx, rx) = channel();
        let waker: WakerSlot = Arc::default();
        let slot = Arc::clone(&waker);
        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
                let raw = match result {
                    Ok(event) if event.need_rescan() => Raw::Rescan,
                    Ok(event) => Raw::Paths(event.paths),
                    // An error of the backend: the events may be incomplete.
                    Err(_) => Raw::Rescan,
                };
                // The receiver is gone only when the engine dropped the watcher.
                let _ = tx.send(raw);
                ring(&slot);
            })
            .map_err(|e| FsError::Io(e.to_string()))?;
        watcher
            .watch(root.root(), RecursiveMode::Recursive)
            .map_err(|e| FsError::Io(e.to_string()))?;
        Ok(Self {
            _watcher: watcher,
            events: rx,
            root: root.clone(),
            waker,
        })
    }

    /// Collects every event that arrived, waiting up to `wait` for the first one.
    pub fn drain(&self, wait: Duration) -> Changes {
        let mut changes = Changes::default();
        let first = match self.events.recv_timeout(wait) {
            Ok(raw) => Some(raw),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                changes.set_rescan();
                None
            }
        };
        for raw in first.into_iter().chain(self.events.try_iter()) {
            match raw {
                Raw::Rescan => changes.set_rescan(),
                Raw::Paths(paths) => {
                    for path in paths {
                        self.add(&path, &mut changes);
                    }
                }
            }
        }
        changes
    }

    fn add(&self, path: &Path, changes: &mut Changes) {
        match self.root.relative(path) {
            // Our own reserved directory (temporary files, park) is no change of the folder.
            Some(rel)
                if rel.first().is_some_and(|n| {
                    n.eq_ignore_ascii_case(hangar_drive_protocol::name::RESERVED_ROOT_DIR)
                }) => {}
            Some(rel) => changes.add_path(rel),
            // A path the watcher reports outside the root or not as UTF-8: scan everything.
            None => changes.set_rescan(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn many_changed_paths_become_a_full_scan() {
        let mut changes = Changes::default();
        for n in 0..MAX_CHANGED_PATHS {
            changes.add_path(vec![format!("f{n}")]);
        }
        assert!(!changes.rescan);
        assert_eq!(changes.paths.len(), MAX_CHANGED_PATHS);
        changes.add_path(vec!["one more".into()]);
        assert!(changes.rescan && changes.paths.is_empty());
        // Later paths are not kept again.
        changes.add_path(vec!["later".into()]);
        assert!(changes.paths.is_empty() && !changes.is_empty());
    }
}
