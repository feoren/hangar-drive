//! The change watcher: `notify` 9 only as the trigger (ADR 0001, section 3). The truth is the
//! scan: a watcher event names paths for a partial scan, and a rescan event (Windows dropped
//! details or overflowed its buffer, FSEvents `MustScanSubDirs` or dropped events, inotify
//! `IN_Q_OVERFLOW`) asks for a full scan at once. The engine adds a full scan every hour, so a
//! lost event is found within the hour even when the platform does not report the loss.
//!
//! Events are collected without blocking the watcher's thread; the engine drains them on its
//! control thread ([`FolderWatcher::drain`]).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
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

impl Changes {
    /// Whether nothing happened.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && !self.rescan
    }
}

/// Anything that reports changes of a sync root: the real watcher, or the event log of the
/// in-memory file system in tests.
pub trait ChangeSource {
    /// Every change since the last call, waiting up to `wait` for the first one.
    fn drain(&self, wait: Duration) -> Changes;
}

impl ChangeSource for FolderWatcher {
    fn drain(&self, wait: Duration) -> Changes {
        FolderWatcher::drain(self, wait)
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
            })
            .map_err(|e| FsError::Io(e.to_string()))?;
        watcher
            .watch(root.root(), RecursiveMode::Recursive)
            .map_err(|e| FsError::Io(e.to_string()))?;
        Ok(Self {
            _watcher: watcher,
            events: rx,
            root: root.clone(),
        })
    }

    /// Collects every event that arrived, waiting up to `wait` for the first one.
    pub fn drain(&self, wait: Duration) -> Changes {
        let mut changes = Changes::default();
        let first = match self.events.recv_timeout(wait) {
            Ok(raw) => Some(raw),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                changes.rescan = true;
                None
            }
        };
        for raw in first.into_iter().chain(self.events.try_iter()) {
            match raw {
                Raw::Rescan => changes.rescan = true,
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
            Some(rel) => {
                changes.paths.insert(rel);
            }
            // A path the watcher reports outside the root or not as UTF-8: scan everything.
            None => changes.rescan = true,
        }
    }
}
