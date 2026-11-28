//! Commands that wait for the engine thread.
//!
//! The engine thread runs the person's commands between passes of its control loop, and a pass
//! may work for its whole budget ([`crate::engine::WORK_BUDGET_MS`]). An [`Interrupt`] counts the
//! commands sent but not started yet, so a round with a budget stops at its next clean point
//! (between hash batches, downloaded files and uploaded objects) as soon as one waits, instead of
//! at the end of its budget. A round without a budget (a person's action, a test that expects a
//! whole round) never looks at it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The count of commands waiting for the engine thread, shared by the handles that send them and
/// the rounds that yield to them. The default is a counter of its own that nobody raises.
#[derive(Debug, Clone, Default)]
pub struct Interrupt(Arc<AtomicUsize>);

impl Interrupt {
    /// Whether a command waits.
    pub fn pending(&self) -> bool {
        self.0.load(Ordering::Acquire) > 0
    }

    /// Counts one more waiting command until the returned guard drops, which the command does
    /// when it starts (or when it could not be sent).
    pub fn raise(&self) -> Waiting {
        self.0.fetch_add(1, Ordering::AcqRel);
        Waiting(Arc::clone(&self.0))
    }
}

/// One waiting command of an [`Interrupt`].
#[derive(Debug)]
pub struct Waiting(Arc<AtomicUsize>);

impl Drop for Waiting {
    fn drop(&mut self) {
        // Every guard came from one increment, so the count never goes below zero here.
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_is_pending_until_its_guard_drops() {
        let interrupt = Interrupt::default();
        assert!(!interrupt.pending());
        let first = interrupt.raise();
        let second = interrupt.clone().raise();
        assert!(interrupt.pending());
        drop(first);
        assert!(interrupt.pending(), "one command still waits");
        drop(second);
        assert!(!interrupt.pending());
    }
}
