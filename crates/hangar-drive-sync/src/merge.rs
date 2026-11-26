//! The three-way tree merge of ADR 0001, section 3, "File contents are never merged".
//!
//! Inputs are the base (the synced tree, or the empty tree for a join or a re-anchor without a
//! base), the remote tree (the server head) and the local tree. Items are matched by item ID.
//! Who keeps a name depends only on server order: the remote version keeps it and the local
//! version becomes the conflict copy.
//!
//! | Case (base, remote, local) | Result |
//! | --- | --- |
//! | changed on one side | that side |
//! | the same content on both sides | taken once, server metadata |
//! | content changed differently | remote keeps name and ID, local becomes a copy with a new ID |
//! | change against delete | the change wins; a deleted directory stays for changed items |
//! | adds under one comparison key | remote keeps the name; equal new files once, new directories merged, otherwise a copy |
//! | item moved differently, or a cycle | the remote move wins |
//! | move on one side, content on the other | both apply |
//! | only metadata changed on both sides | remote wins |
//!
//! A **join** of a non-empty local folder is the merge with the empty base, where every local
//! item is new: the collision rules then match local items to remote items by comparison key,
//! directory by directory, and nothing is deleted on either side.
//!
//! The merge is pure and deterministic given the fresh item IDs it draws.

use std::collections::{BTreeMap, BTreeSet};

use hangar_drive_protocol::ids::ItemId;
use hangar_drive_protocol::name::CaseKeys;

use crate::names::{conflict_copy_name, LabelWords};
use crate::tree::{Node, NodeKind, Tree, ROOT};

/// Draws fresh, random item IDs for conflict copies.
pub trait ItemIds {
    /// A new item ID, never [`ROOT`].
    fn new_item_id(&mut self) -> ItemId;
}

/// Labels for conflict copies.
#[derive(Debug, Clone)]
pub struct MergeLabels<'a> {
    /// The words in the device's UI language.
    pub words: &'a LabelWords,
    /// The merging device's name.
    pub device: &'a str,
    /// Its local date, `YYYY-MM-DD`.
    pub date: &'a str,
}

/// Why a conflict copy was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyReason {
    /// Both sides changed the content differently.
    Content,
    /// Two items collided by comparison key or case.
    Collision,
}

/// A conflict copy of the merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConflictCopy {
    /// The item that kept the name.
    pub original: ItemId,
    /// The copy.
    pub copy: ItemId,
    /// Why.
    pub reason: CopyReason,
}

/// A local item that the merged tree knows under another ID: a content conflict copy, a new
/// file taken once under the remote ID, a new directory merged into the remote one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rekey {
    /// The ID in the local tree.
    pub from: ItemId,
    /// The ID in the merged tree.
    pub to: ItemId,
}

/// The result of a merge.
#[derive(Debug, Clone)]
pub struct MergeOutcome {
    /// The merged tree.
    pub tree: Tree,
    /// The local tree with the rekeys applied: what the disk holds, under merged IDs.
    pub local: Tree,
    /// The rekeys, from the original local ID to the merged ID.
    pub rekeys: Vec<Rekey>,
    /// The conflict copies made.
    pub copies: Vec<ConflictCopy>,
    /// Local moves the remote side overrode.
    pub dropped_local_moves: usize,
}

struct Merger<'a, 'l> {
    base: &'a Tree,
    remote: &'a Tree,
    local: Tree,
    m: Tree,
    labels: &'a MergeLabels<'l>,
    from_local: BTreeSet<ItemId>,
    rekeys: BTreeMap<ItemId, ItemId>,
    copies: Vec<ConflictCopy>,
    content_copies: BTreeSet<ItemId>,
    dropped_local_moves: usize,
}

/// Merges `local` into `remote` with `base` as the merge base (module docs).
pub fn merge3(
    base: &Tree,
    remote: &Tree,
    local: &Tree,
    labels: &MergeLabels<'_>,
    ids: &mut dyn ItemIds,
) -> MergeOutcome {
    let mut merger = Merger {
        base,
        remote,
        local: local.clone(),
        m: remote.clone(),
        labels,
        from_local: BTreeSet::new(),
        rekeys: BTreeMap::new(),
        copies: Vec::new(),
        content_copies: BTreeSet::new(),
        dropped_local_moves: 0,
    };
    merger.split_kind_changes(ids);
    merger.apply_local(ids);
    merger.settle();
    merger.drop_dangling_links();
    let mut tree = merger.m;
    tree.clear_dirty();
    let mut local = merger.local;
    local.clear_dirty();
    MergeOutcome {
        tree,
        local,
        rekeys: merger
            .rekeys
            .into_iter()
            .filter(|(from, to)| from != to)
            .map(|(from, to)| Rekey { from, to })
            .collect(),
        copies: merger.copies,
        dropped_local_moves: merger.dropped_local_moves,
    }
}

/// The join of a non-empty local folder: [`merge3`] with the empty base (module docs).
pub fn join(
    remote: &Tree,
    local: &Tree,
    labels: &MergeLabels<'_>,
    ids: &mut dyn ItemIds,
) -> MergeOutcome {
    merge3(&Tree::new(), remote, local, labels, ids)
}

fn names_collide(a: &str, b: &str) -> bool {
    let (ka, kb) = (
        hangar_drive_protocol::name::comparison_key(a),
        hangar_drive_protocol::name::comparison_key(b),
    );
    ka == kb || CaseKeys::of(&ka).collides(&CaseKeys::of(&kb))
}

impl Merger<'_, '_> {
    /// Records that the local item now called `from` is called `to`.
    fn record_rekey(&mut self, from: ItemId, to: ItemId) {
        let mut found = false;
        for value in self.rekeys.values_mut() {
            if *value == from {
                *value = to;
                found = true;
            }
        }
        if !found {
            self.rekeys.insert(from, to);
        }
    }

    /// An item that is a file on one side and a directory on the other under one ID: the local
    /// one gets a new ID first (a kind change is a delete plus an add).
    fn split_kind_changes(&mut self, ids: &mut dyn ItemIds) {
        let mismatched: Vec<ItemId> = self
            .local
            .iter()
            .filter(|(id, l)| {
                self.remote
                    .get(id)
                    .is_some_and(|r| r.is_dir() != l.is_dir())
                    || self.base.get(id).is_some_and(|b| b.is_dir() != l.is_dir())
            })
            .map(|(id, _)| *id)
            .collect();
        for id in mismatched {
            let fresh = ids.new_item_id();
            self.local.rekey(&id, fresh);
            self.record_rekey(id, fresh);
        }
    }

    fn apply_local(&mut self, ids: &mut dyn ItemIds) {
        let all: BTreeSet<ItemId> = self.base.ids().chain(self.local.ids()).copied().collect();
        let mut content_rekeys = Vec::new();
        for id in all {
            let b = self.base.get(&id);
            let l = self.local.get(&id).cloned();
            let r = self.remote.get(&id);
            match (b, l) {
                (None, None) => {}
                (Some(b), None) => {
                    if r == Some(b) {
                        self.m.remove(&id);
                    }
                    // Otherwise the remote side changed it (it wins against the delete) or
                    // deleted it too.
                }
                (None, Some(l)) => match r {
                    None => {
                        self.m.insert(id, l);
                        self.from_local.insert(id);
                    }
                    Some(r) => {
                        let r = r.clone();
                        if let Some(copy) = self.both(id, None, &r, &l, ids) {
                            content_rekeys.push((id, copy));
                        }
                    }
                },
                (Some(b), Some(l)) => {
                    if l == *b {
                        continue;
                    }
                    match r {
                        Some(r) if r != b => {
                            let (b, r) = (b.clone(), r.clone());
                            if let Some(copy) = self.both(id, Some(&b), &r, &l, ids) {
                                content_rekeys.push((id, copy));
                            }
                        }
                        _ => {
                            // Remote unchanged, or deleted (the change wins).
                            let mut node = l.clone();
                            if b.conflict_of.is_some()
                                && (l.location() != b.location() || l.conflict_of.is_none())
                            {
                                node.conflict_of = None;
                            }
                            self.m.insert(id, node);
                            self.from_local.insert(id);
                        }
                    }
                }
            }
        }
        for (from, to) in content_rekeys {
            self.local.rekey(&from, to);
            self.record_rekey(from, to);
        }
    }

    /// Both sides have the item. Returns the ID of a content conflict copy.
    fn both(
        &mut self,
        id: ItemId,
        b: Option<&Node>,
        r: &Node,
        l: &Node,
        ids: &mut dyn ItemIds,
    ) -> Option<ItemId> {
        let mut node = r.clone();
        let local_moved = b.is_some_and(|b| l.location() != b.location());
        let remote_moved = b.is_some_and(|b| r.location() != b.location());
        if local_moved && !remote_moved {
            node.parent = l.parent;
            node.name = l.name.clone();
            self.from_local.insert(id);
        } else if local_moved && l.location() != r.location() {
            self.dropped_local_moves += 1;
        }
        node.conflict_of = match b {
            Some(b) => {
                if b.conflict_of.is_some()
                    && (l.conflict_of.is_none() || r.conflict_of.is_none() || local_moved)
                {
                    None
                } else if l.conflict_of != b.conflict_of && r.conflict_of == b.conflict_of {
                    l.conflict_of
                } else {
                    r.conflict_of
                }
            }
            None => r.conflict_of,
        };
        let mut copy = None;
        if let (NodeKind::File(rv), NodeKind::File(lv)) = (&r.kind, &l.kind) {
            let bv = b.and_then(|b| b.kind.file());
            let local_content = bv.is_none_or(|bv| !lv.same_content(bv));
            let remote_content = bv.is_none_or(|bv| !rv.same_content(bv));
            let mut v = *rv;
            if local_content && remote_content && !lv.same_content(rv) {
                let fresh = ids.new_item_id();
                let mut copy_node = Node::file(node.parent, node.name.clone(), *lv);
                copy_node.conflict_of = Some(node.conflict_of.unwrap_or(id));
                self.m.insert(fresh, copy_node);
                self.from_local.insert(fresh);
                self.content_copies.insert(fresh);
                self.copies.push(ConflictCopy {
                    original: id,
                    copy: fresh,
                    reason: CopyReason::Content,
                });
                copy = Some(fresh);
            } else if let Some(bv) = bv {
                if local_content && !remote_content {
                    v.size = lv.size;
                    v.content = lv.content;
                    v.mtime_ms = lv.mtime_ms;
                } else if !local_content
                    && !remote_content
                    && lv.mtime_ms != bv.mtime_ms
                    && rv.mtime_ms == bv.mtime_ms
                {
                    v.mtime_ms = lv.mtime_ms;
                }
                if lv.executable != bv.executable && rv.executable == bv.executable {
                    v.executable = lv.executable;
                }
            }
            node.kind = NodeKind::File(v);
        }
        self.m.insert(id, node);
        copy
    }

    /// Orphans, cycles and collisions, until nothing changes.
    fn settle(&mut self) {
        // Each round resolves at least one problem; the bound only guards against a bug.
        let limit = 4 * (self.m.len() + 4);
        for _ in 0..limit {
            let mut changed = self.fix_orphans();
            changed |= self.fix_cycles();
            changed |= self.fix_collisions();
            if !changed {
                return;
            }
        }
    }

    /// A node whose parent is gone: the parent stays (a change beats a delete).
    fn fix_orphans(&mut self) -> bool {
        let mut changed = false;
        let orphans: Vec<(ItemId, ItemId)> = self
            .m
            .iter()
            .filter(|(_, n)| n.parent != ROOT && !self.m.get(&n.parent).is_some_and(Node::is_dir))
            .map(|(id, n)| (*id, n.parent))
            .collect();
        for (child, parent) in orphans {
            if self.m.contains(&parent) {
                // The parent is a file: the child moves to the root.
                self.move_to_root(child);
                changed = true;
                continue;
            }
            let restored = self
                .remote
                .get(&parent)
                .or_else(|| self.local.get(&parent))
                .or_else(|| self.base.get(&parent))
                .filter(|n| n.is_dir())
                .cloned();
            match restored {
                Some(node) => self.m.insert(parent, node),
                None => self.move_to_root(child),
            }
            changed = true;
        }
        changed
    }

    fn move_to_root(&mut self, id: ItemId) {
        if let Some(mut node) = self.m.get(&id).cloned() {
            node.parent = ROOT;
            self.m.insert(id, node);
        }
    }

    /// Moves that form a cycle: the local moves in it fall back to the remote place.
    fn fix_cycles(&mut self) -> bool {
        let mut changed = false;
        let ids: Vec<ItemId> = self.m.ids().copied().collect();
        for id in ids {
            if self.m.path(&id).is_some() {
                continue;
            }
            let mut cycle = Vec::new();
            let mut seen = BTreeSet::new();
            let mut at = id;
            while at != ROOT && seen.insert(at) {
                cycle.push(at);
                match self.m.get(&at) {
                    Some(n) => at = n.parent,
                    None => break,
                }
            }
            let mut reverted = false;
            for node_id in cycle.iter().rev() {
                if !self.from_local.contains(node_id) {
                    continue;
                }
                let Some(mut node) = self.m.get(node_id).cloned() else {
                    continue;
                };
                let fallback = self.remote.get(node_id).or_else(|| self.base.get(node_id));
                match fallback {
                    Some(place) => {
                        node.parent = place.parent;
                        node.name = place.name.clone();
                    }
                    None => node.parent = ROOT,
                }
                self.m.insert(*node_id, node);
                self.from_local.remove(node_id);
                self.dropped_local_moves += 1;
                reverted = true;
                break;
            }
            if !reverted {
                // A cycle without a local move cannot come from a valid remote tree; break it.
                self.move_to_root(id);
            }
            changed = true;
        }
        changed
    }

    fn priority(&self, parent: &ItemId, id: &ItemId) -> (u8, ItemId) {
        let node = self.m.get(id);
        let same_place = |tree: &Tree| {
            tree.get(id)
                .zip(node)
                .is_some_and(|(t, n)| t.parent == *parent && t.name == n.name)
        };
        let rank = if same_place(self.remote) {
            0
        } else if same_place(self.base) {
            1
        } else if self.remote.contains(id) {
            2
        } else {
            3
        };
        (rank, *id)
    }

    fn fix_collisions(&mut self) -> bool {
        let mut dirs: Vec<ItemId> = vec![ROOT];
        dirs.extend(self.m.iter().filter(|(_, n)| n.is_dir()).map(|(id, _)| *id));
        for dir in dirs {
            if dir != ROOT && !self.m.contains(&dir) {
                continue;
            }
            let mut kids: Vec<ItemId> = self.m.children(&dir).copied().collect();
            if kids.len() < 2 {
                continue;
            }
            kids.sort_by_key(|k| self.priority(&dir, k));
            let mut accepted: Vec<ItemId> = Vec::new();
            for kid in kids {
                let Some(node) = self.m.get(&kid).cloned() else {
                    continue;
                };
                let winner = accepted.iter().copied().find(|a| {
                    self.m
                        .get(a)
                        .is_some_and(|w| names_collide(&w.name, &node.name))
                });
                let Some(winner) = winner else {
                    accepted.push(kid);
                    continue;
                };
                let Some(win) = self.m.get(&winner).cloned() else {
                    continue;
                };
                let is_new = !self.base.contains(&kid)
                    && !self.remote.contains(&kid)
                    && !self.content_copies.contains(&kid);
                let local_can_rekey = !self.local.contains(&winner) && self.local.contains(&kid);
                match (&win.kind, &node.kind) {
                    (NodeKind::File(wv), NodeKind::File(nv))
                        if is_new && local_can_rekey && wv.same_content(nv) =>
                    {
                        self.m.remove(&kid);
                        self.local.rekey(&kid, winner);
                        self.record_rekey(kid, winner);
                        return true;
                    }
                    (NodeKind::Directory, NodeKind::Directory) if is_new && local_can_rekey => {
                        let grandkids: Vec<ItemId> = self.m.children(&kid).copied().collect();
                        for g in grandkids {
                            if let Some(mut gn) = self.m.get(&g).cloned() {
                                gn.parent = winner;
                                self.m.insert(g, gn);
                            }
                        }
                        self.m.remove(&kid);
                        self.local.rekey(&kid, winner);
                        self.record_rekey(kid, winner);
                        return true;
                    }
                    _ => {
                        self.rename_loser(dir, kid, &node, winner, &win);
                        return true;
                    }
                }
            }
        }
        false
    }

    fn rename_loser(&mut self, dir: ItemId, kid: ItemId, node: &Node, winner: ItemId, win: &Node) {
        let siblings: Vec<String> = self
            .m
            .children(&dir)
            .filter(|s| **s != kid)
            .filter_map(|s| self.m.get(s).map(|n| n.name.clone()))
            .collect();
        let taken = |candidate: &str| siblings.iter().any(|s| names_collide(s, candidate));
        let name = conflict_copy_name(
            &node.name,
            self.labels.words,
            self.labels.device,
            self.labels.date,
            &taken,
        );
        let mut renamed = node.clone();
        renamed.name = name;
        renamed.conflict_of = Some(win.conflict_of.unwrap_or(winner));
        if renamed.conflict_of == Some(kid) {
            renamed.conflict_of = None;
        }
        self.m.insert(kid, renamed);
        if !self.content_copies.contains(&kid) {
            self.copies.push(ConflictCopy {
                original: winner,
                copy: kid,
                reason: CopyReason::Collision,
            });
        }
    }

    /// A conflict link whose original is not in the merged tree is dropped.
    fn drop_dangling_links(&mut self) {
        let dangling: Vec<ItemId> = self
            .m
            .iter()
            .filter(|(id, n)| {
                n.conflict_of
                    .is_some_and(|o| o == **id || !self.m.contains(&o))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in dangling {
            if let Some(mut node) = self.m.get(&id).cloned() {
                node.conflict_of = None;
                self.m.insert(id, node);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests::{content, file, id};
    use crate::tree::FileVersion;

    struct Counter(u8);

    impl ItemIds for Counter {
        fn new_item_id(&mut self) -> ItemId {
            self.0 += 1;
            id(200 + self.0)
        }
    }

    fn run(base: &Tree, remote: &Tree, local: &Tree) -> MergeOutcome {
        let words = LabelWords::default();
        let labels = MergeLabels {
            words: &words,
            device: "Laptop",
            date: "2026-11-26",
        };
        let out = merge3(base, remote, local, &labels, &mut Counter(0));
        assert_eq!(out.tree.check(), Ok(()), "merged tree must be valid");
        out
    }

    fn names(t: &Tree) -> Vec<String> {
        let mut v: Vec<String> = t.ids().filter_map(|i| t.path_string(i)).collect();
        v.sort();
        v
    }

    fn base_tree() -> Tree {
        let mut t = Tree::new();
        t.insert(id(1), Node::dir(ROOT, "docs"));
        t.insert(id(2), Node::file(id(1), "a.txt", file(2)));
        t.insert(id(3), Node::file(ROOT, "b.txt", file(3)));
        t
    }

    fn with(t: &Tree, item: ItemId, f: impl FnOnce(&mut Node)) -> Tree {
        let mut out = t.clone();
        let mut node = out.get(&item).unwrap().clone();
        f(&mut node);
        out.insert(item, node);
        out
    }

    fn version(n: u8, mtime: i64) -> FileVersion {
        FileVersion {
            size: u64::from(n),
            mtime_ms: mtime,
            executable: false,
            content: content(n),
        }
    }

    #[test]
    fn one_sided_changes_win() {
        let b = base_tree();
        let local = with(&b, id(2), |n| n.kind = NodeKind::File(file(9)));
        let out = run(&b, &b, &local);
        assert_eq!(out.tree, local);
        let remote = with(&b, id(3), |n| n.name = "c.txt".into());
        let out = run(&b, &remote, &b);
        assert_eq!(out.tree, remote);
    }

    #[test]
    fn same_change_twice_is_taken_once() {
        let b = base_tree();
        let changed = with(&b, id(2), |n| n.kind = NodeKind::File(version(9, 5)));
        let other_mtime = with(&b, id(2), |n| n.kind = NodeKind::File(version(9, 7)));
        let out = run(&b, &changed, &other_mtime);
        assert!(out.copies.is_empty());
        assert_eq!(out.tree, changed, "server metadata wins");
    }

    #[test]
    fn content_conflict_makes_a_local_copy() {
        let b = base_tree();
        let remote = with(&b, id(2), |n| n.kind = NodeKind::File(file(8)));
        let local = with(&b, id(2), |n| n.kind = NodeKind::File(file(9)));
        let out = run(&b, &remote, &local);
        assert_eq!(out.copies.len(), 1);
        let copy = out.copies[0];
        assert_eq!(copy.original, id(2));
        assert_eq!(copy.reason, CopyReason::Content);
        assert_eq!(out.tree.get(&id(2)).unwrap().kind, NodeKind::File(file(8)));
        let c = out.tree.get(&copy.copy).unwrap();
        assert_eq!(c.name, "a (conflict Laptop 2026-11-26).txt");
        assert_eq!(c.kind, NodeKind::File(file(9)));
        assert_eq!(c.conflict_of, Some(id(2)));
        assert_eq!(
            out.rekeys,
            vec![Rekey {
                from: id(2),
                to: copy.copy
            }]
        );
        // The local tree under merged IDs: the disk file now belongs to the copy.
        assert!(out.local.contains(&copy.copy) && !out.local.contains(&id(2)));
    }

    #[test]
    fn change_beats_delete_and_directory_stays() {
        let b = base_tree();
        // Local deletes the directory and its file; remote changes the file.
        let mut local = b.clone();
        local.remove(&id(2));
        local.remove(&id(1));
        let remote = with(&b, id(2), |n| n.kind = NodeKind::File(file(7)));
        let out = run(&b, &remote, &local);
        assert_eq!(out.tree, remote);
        // Remote deletes, local changes.
        let mut remote = b.clone();
        remote.remove(&id(2));
        remote.remove(&id(1));
        let local = with(&b, id(2), |n| n.kind = NodeKind::File(file(7)));
        let out = run(&b, &remote, &local);
        assert_eq!(names(&out.tree), vec!["b.txt", "docs", "docs/a.txt"]);
        // Unchanged on the other side: the delete goes through.
        let mut local = b.clone();
        local.remove(&id(3));
        assert!(!run(&b, &b, &local).tree.contains(&id(3)));
    }

    #[test]
    fn competing_moves_keep_the_remote_move() {
        let b = base_tree();
        let remote = with(&b, id(3), |n| n.name = "remote.txt".into());
        let local = with(&b, id(3), |n| n.name = "local.txt".into());
        let out = run(&b, &remote, &local);
        assert_eq!(out.tree.get(&id(3)).unwrap().name, "remote.txt");
        assert_eq!(out.dropped_local_moves, 1);
    }

    #[test]
    fn move_on_one_side_content_on_the_other_both_apply() {
        let b = base_tree();
        let remote = with(&b, id(2), |n| n.kind = NodeKind::File(file(5)));
        let local = with(&b, id(2), |n| n.parent = ROOT);
        let out = run(&b, &remote, &local);
        let node = out.tree.get(&id(2)).unwrap();
        assert_eq!(node.parent, ROOT);
        assert_eq!(node.kind, NodeKind::File(file(5)));
    }

    #[test]
    fn metadata_only_on_both_sides_takes_the_remote() {
        let b = base_tree();
        let remote = with(&b, id(3), |n| n.kind = NodeKind::File(version(3, 111)));
        let local = with(&b, id(3), |n| n.kind = NodeKind::File(version(3, 222)));
        let out = run(&b, &remote, &local);
        assert!(out.copies.is_empty());
        assert_eq!(out.tree, remote);
    }

    #[test]
    fn cycles_drop_the_local_move() {
        let mut b = Tree::new();
        b.insert(id(1), Node::dir(ROOT, "a"));
        b.insert(id(2), Node::dir(ROOT, "b"));
        let remote = with(&b, id(1), |n| n.parent = id(2));
        let local = with(&b, id(2), |n| n.parent = id(1));
        let out = run(&b, &remote, &local);
        assert_eq!(out.tree.get(&id(1)).unwrap().parent, id(2));
        assert_eq!(out.tree.get(&id(2)).unwrap().parent, ROOT);
    }

    #[test]
    fn adds_under_one_name() {
        let b = Tree::new();
        let mut remote = Tree::new();
        remote.insert(id(1), Node::file(ROOT, "x.txt", file(1)));
        // Different content: the local add becomes the copy.
        let mut local = Tree::new();
        local.insert(id(9), Node::file(ROOT, "X.TXT", file(2)));
        let out = run(&b, &remote, &local);
        assert_eq!(
            out.tree.get(&id(9)).unwrap().name,
            "X (conflict Laptop 2026-11-26).TXT"
        );
        assert_eq!(out.tree.get(&id(9)).unwrap().conflict_of, Some(id(1)));
        // Same content: taken once under the remote ID.
        let mut local = Tree::new();
        local.insert(id(9), Node::file(ROOT, "x.txt", version(1, 99)));
        let out = run(&b, &remote, &local);
        assert_eq!(out.tree, remote);
        assert_eq!(
            out.rekeys,
            vec![Rekey {
                from: id(9),
                to: id(1)
            }]
        );
    }

    #[test]
    fn join_merges_directories_by_name() {
        let mut remote = Tree::new();
        remote.insert(id(1), Node::dir(ROOT, "Photos"));
        remote.insert(id(2), Node::file(id(1), "a.jpg", file(2)));
        remote.insert(id(3), Node::file(id(1), "b.jpg", file(3)));
        let mut local = Tree::new();
        local.insert(id(11), Node::dir(ROOT, "photos"));
        local.insert(id(12), Node::file(id(11), "a.jpg", file(2)));
        local.insert(id(13), Node::file(id(11), "b.jpg", file(4)));
        local.insert(id(14), Node::file(id(11), "c.jpg", file(5)));
        let words = LabelWords::default();
        let labels = MergeLabels {
            words: &words,
            device: "PC",
            date: "2026-11-26",
        };
        let out = join(&remote, &local, &labels, &mut Counter(0));
        assert_eq!(
            names(&out.tree),
            vec![
                "Photos",
                "Photos/a.jpg",
                "Photos/b (conflict PC 2026-11-26).jpg",
                "Photos/b.jpg",
                "Photos/c.jpg"
            ]
        );
        // Nothing remote was deleted or changed.
        for (rid, rnode) in remote.iter() {
            assert_eq!(out.tree.get(rid), Some(rnode));
        }
        assert!(out.rekeys.contains(&Rekey {
            from: id(11),
            to: id(1)
        }));
        assert!(out.rekeys.contains(&Rekey {
            from: id(12),
            to: id(2)
        }));
        assert_eq!(out.local.get(&id(13)).unwrap().parent, id(1));
    }

    #[test]
    fn copy_of_a_copy_names_the_first_original() {
        let mut b = Tree::new();
        b.insert(id(1), Node::file(ROOT, "a.txt", file(1)));
        let mut c = Node::file(ROOT, "a (conflict X 2026-01-01).txt", file(2));
        c.conflict_of = Some(id(1));
        b.insert(id(2), c);
        let remote = with(&b, id(2), |n| n.kind = NodeKind::File(file(3)));
        let local = with(&b, id(2), |n| n.kind = NodeKind::File(file(4)));
        let out = run(&b, &remote, &local);
        let copy = out.copies[0].copy;
        assert_eq!(out.tree.get(&copy).unwrap().conflict_of, Some(id(1)));
    }

    #[test]
    fn conflict_link_dropped_by_rename_and_when_dangling() {
        let mut b = Tree::new();
        b.insert(id(1), Node::file(ROOT, "a.txt", file(1)));
        let mut c = Node::file(ROOT, "copy.txt", file(2));
        c.conflict_of = Some(id(1));
        b.insert(id(2), c);
        let local = with(&b, id(2), |n| n.name = "renamed.txt".into());
        assert_eq!(
            run(&b, &b, &local).tree.get(&id(2)).unwrap().conflict_of,
            None
        );
        let mut remote = b.clone();
        remote.remove(&id(1));
        assert_eq!(
            run(&b, &remote, &b).tree.get(&id(2)).unwrap().conflict_of,
            None
        );
    }

    #[test]
    fn kind_change_is_delete_plus_add() {
        let b = base_tree();
        let mut local = b.clone();
        local.insert(id(3), Node::dir(ROOT, "b.txt"));
        let out = run(&b, &b, &local);
        assert!(!out.tree.contains(&id(3)));
        let fresh = out.rekeys[0].to;
        assert!(out.tree.get(&fresh).unwrap().is_dir());
    }
}
