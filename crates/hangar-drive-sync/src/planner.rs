//! The planner: one pure step from the three trees to what the folder does next.
//!
//! The merged tree `P = merge3(synced, remote, local)` is the target of both sides. If it
//! differs from the remote tree, the device publishes it; then the disk is brought to it by the
//! executor ([`crate::apply`]). The order is fixed: publish first, so a local version that loses
//! a merge is in a commit (the side commit or the merged tree) before the disk changes, and
//! only then the disk.
//!
//! Two guards of ADR 0001, section 5, change the local input:
//!
//! - **Delayed deletes:** a local delete younger than the delay is not propagated yet; the
//!   planner takes the item as present (its synced version) and never touches it on disk.
//! - **Mass delete:** above the threshold the engine holds every local delete of the round the
//!   same way, until the person decides; "restore" then recreates the items on disk.
//!
//! A third guard works on the remote input, for deletes another device made (ADR 0001,
//! amendment "incoming mass deletes"): [`hold_deletes`] decides when the folder keeps them on
//! this disk until the person decides, and the folder leaves those items to the executor's skip
//! set. The same rule over the long window also guards this device's own deletes, so a slow
//! delete below the per round threshold adds up.

use std::collections::BTreeSet;

use hangar_drive_protocol::ids::ItemId;

use crate::merge::{merge3, ConflictCopy, ItemIds, MergeLabels, Rekey};
use crate::tree::{Tree, ROOT};

/// The deletes of one round from which the engine asks the person first (ADR 0001, section 5;
/// Nextcloud's default).
pub const MASS_DELETE_THRESHOLD: usize = 100;

/// Incoming file deletes within the window from which the person is always asked, whatever
/// the share of the folder (ADR 0001, amendment "incoming mass deletes").
pub const INCOMING_DELETE_ALWAYS: u64 = 1000;
/// The fewest incoming file deletes within the window that ask at all: a folder of fewer files
/// never asks, and tidying up a few files never interrupts.
pub const INCOMING_DELETE_MIN: u64 = 100;
/// From this share of the folder's files (in percent), at least [`INCOMING_DELETE_MIN`] of them,
/// incoming deletes are held.
pub const INCOMING_DELETE_PERCENT: u64 = 25;

/// Whether `deleted` file deletes within a window, of a folder that held `files` files before
/// it, wait for the person: at least [`INCOMING_DELETE_ALWAYS`], or at least
/// [`INCOMING_DELETE_MIN`] and at least [`INCOMING_DELETE_PERCENT`] percent of the files. Moves,
/// directories and files that only just arrived are not counted by the caller, and `files` is
/// the fewest the folder held over the window, so files added before a delete do not dilute
/// it (security review M3).
pub fn hold_deletes(deleted: u64, files: u64) -> bool {
    deleted >= INCOMING_DELETE_ALWAYS
        || (deleted >= INCOMING_DELETE_MIN
            && deleted.saturating_mul(100) >= files.saturating_mul(INCOMING_DELETE_PERCENT))
}

/// What the planner reads.
#[derive(Debug, Clone, Copy)]
pub struct PlanInput<'a> {
    /// The tree of the verified server head.
    pub remote: &'a Tree,
    /// The merge base.
    pub synced: &'a Tree,
    /// The disk.
    pub local: &'a Tree,
    /// Local deletes not propagated yet: taken as present, never touched on disk.
    pub delayed: &'a BTreeSet<ItemId>,
    /// Local deletes the person undid: taken as present and recreated on disk.
    pub restore: &'a BTreeSet<ItemId>,
}

/// One planned round.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The target tree `P`.
    pub merged: Tree,
    /// What the disk holds now, under the merged item IDs: the executor's starting point.
    pub disk: Tree,
    /// Local items that `P` knows under another ID.
    pub rekeys: Vec<Rekey>,
    /// Conflict copies.
    pub copies: Vec<ConflictCopy>,
    /// Local moves the remote side overrode.
    pub dropped_local_moves: usize,
    /// `P` differs from the remote tree: publish it.
    pub publish: bool,
    /// Items `P` drops because of a local delete.
    pub local_deletes: Vec<ItemId>,
    /// Items the executor must not touch.
    pub skip: BTreeSet<ItemId>,
}

/// The local tree with these synced items put back, with their missing parents.
fn with_present(local: &Tree, synced: &Tree, ids: &BTreeSet<ItemId>) -> (Tree, BTreeSet<ItemId>) {
    let mut out = local.clone();
    let mut inserted = BTreeSet::new();
    for id in ids {
        let mut at = *id;
        while at != ROOT && !out.contains(&at) {
            let Some(node) = synced.get(&at) else {
                break;
            };
            out.insert(at, node.clone());
            inserted.insert(at);
            at = node.parent;
        }
    }
    (out, inserted)
}

/// Plans one round (module docs).
pub fn plan(input: PlanInput<'_>, labels: &MergeLabels<'_>, ids: &mut dyn ItemIds) -> Plan {
    // Restored items first, so a parent both need is recreated rather than skipped.
    let (local, restored) = with_present(input.local, input.synced, input.restore);
    let (local, delayed) = with_present(&local, input.synced, input.delayed);
    let out = merge3(input.synced, input.remote, &local, labels, ids);
    let mut disk = out.local;
    for id in restored.iter().chain(delayed.iter()) {
        disk.remove(id);
    }
    disk.clear_dirty();
    let local_deletes = input
        .synced
        .iter()
        .filter(|(id, node)| {
            input.remote.get(id) == Some(*node) && !local.contains(id) && !out.tree.contains(id)
        })
        .map(|(id, _)| *id)
        .collect();
    // A parent put back only for a delayed child stays untouched as well.
    let skip = delayed;
    Plan {
        publish: out.tree != *input.remote,
        merged: out.tree,
        disk,
        rekeys: out.rekeys,
        copies: out.copies,
        dropped_local_moves: out.dropped_local_moves,
        local_deletes,
        skip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::LabelWords;
    use crate::tree::tests::{file, id};
    use crate::tree::Node;

    struct Ids(u8);

    impl ItemIds for Ids {
        fn new_item_id(&mut self) -> ItemId {
            self.0 += 1;
            id(150 + self.0)
        }
    }

    fn labels(words: &LabelWords) -> MergeLabels<'_> {
        MergeLabels {
            words,
            device: "D",
            date: "2026-11-26",
        }
    }

    fn base() -> Tree {
        let mut t = Tree::new();
        t.insert(id(1), Node::dir(ROOT, "d"));
        t.insert(id(2), Node::file(id(1), "a", file(2)));
        t.insert(id(3), Node::file(ROOT, "b", file(3)));
        t
    }

    #[test]
    fn incoming_deletes_are_held_from_the_thresholds_on() {
        // A folder of fewer than 100 files never asks, even when everything goes.
        assert!(!hold_deletes(99, 99));
        assert!(hold_deletes(100, 100));
        // From 100 deletes, a quarter of the folder asks.
        assert!(!hold_deletes(100, 401));
        assert!(hold_deletes(100, 400));
        assert!(!hold_deletes(249, 1000));
        assert!(hold_deletes(250, 1000));
        // From 1000 deletes, the share does not matter.
        assert!(!hold_deletes(999, 100_000));
        assert!(hold_deletes(1000, 100_000));
        // Honest tidying up does not ask.
        assert!(!hold_deletes(20, 400));
        assert!(!hold_deletes(0, 0));
        // No overflow at the edge.
        assert!(hold_deletes(u64::MAX, u64::MAX));
    }

    #[test]
    fn in_sync_needs_nothing() {
        let t = base();
        let empty = BTreeSet::new();
        let words = LabelWords::default();
        let p = plan(
            PlanInput {
                remote: &t,
                synced: &t,
                local: &t,
                delayed: &empty,
                restore: &empty,
            },
            &labels(&words),
            &mut Ids(0),
        );
        assert!(!p.publish);
        assert_eq!(p.merged, t);
        assert_eq!(p.disk, t);
    }

    #[test]
    fn delayed_deletes_are_not_published_and_not_touched() {
        let t = base();
        let mut local = t.clone();
        local.remove(&id(2));
        local.remove(&id(1));
        let delayed: BTreeSet<ItemId> = [id(2), id(1)].into();
        let empty = BTreeSet::new();
        let words = LabelWords::default();
        let p = plan(
            PlanInput {
                remote: &t,
                synced: &t,
                local: &local,
                delayed: &delayed,
                restore: &empty,
            },
            &labels(&words),
            &mut Ids(0),
        );
        assert!(!p.publish);
        assert!(p.local_deletes.is_empty());
        assert!(p.skip.contains(&id(2)) && p.skip.contains(&id(1)));
        assert!(!p.disk.contains(&id(2)));
        // Once the delay is over the delete goes through.
        let p = plan(
            PlanInput {
                remote: &t,
                synced: &t,
                local: &local,
                delayed: &empty,
                restore: &empty,
            },
            &labels(&words),
            &mut Ids(0),
        );
        assert!(p.publish);
        assert_eq!(p.local_deletes.len(), 2);
    }

    #[test]
    fn restore_recreates_held_deletes() {
        let t = base();
        let mut local = t.clone();
        local.remove(&id(3));
        let restore: BTreeSet<ItemId> = [id(3)].into();
        let empty = BTreeSet::new();
        let words = LabelWords::default();
        let p = plan(
            PlanInput {
                remote: &t,
                synced: &t,
                local: &local,
                delayed: &empty,
                restore: &restore,
            },
            &labels(&words),
            &mut Ids(0),
        );
        assert!(!p.publish);
        assert!(p.skip.is_empty());
        assert!(p.merged.contains(&id(3)) && !p.disk.contains(&id(3)));
    }
}
