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
//!
//! **Collisions in linear time** (security review HIGH 2). The rule is defined round by round:
//! look at the directories in order (the root, then by item ID), sort the first directory's
//! entries that has a collision by [`Merger::priority`], keep each entry that collides with no
//! entry kept before it, fix the first one that does, and start again. Run literally, that is
//! cubic in the size of a directory. [`Merger::fix_collisions`] takes the same fixes in the
//! same order in one walk: an entry's case keys are computed once per walk of its directory and
//! looked up in hash maps, and a walk goes on where the last fix left it, since a fix never
//! changes the entries ahead of it or the order among them: a renamed loser collides with no
//! entry any more and a removed one is gone. Only a merge of two directories adds entries to
//! another directory; that directory is walked again from its start, before the current one
//! goes on if it comes first in the order, exactly as the round by round search would.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use hangar_drive_protocol::ids::ItemId;
use hangar_drive_protocol::name::CaseKeys;

use crate::names::{case_keys, conflict_label, DirNames, LabelWords};
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

struct Merger<'a> {
    base: &'a Tree,
    remote: &'a Tree,
    local: Tree,
    m: Tree,
    /// The label of the conflict copies ([`conflict_label`]).
    copy_label: String,
    from_local: BTreeSet<ItemId>,
    rekeys: BTreeMap<ItemId, ItemId>,
    /// `rekeys` backwards: per merged ID the local IDs that point to it.
    rekey_sources: HashMap<ItemId, BTreeSet<ItemId>>,
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
        copy_label: conflict_label(labels.words, labels.device, labels.date),
        from_local: BTreeSet::new(),
        rekeys: BTreeMap::new(),
        rekey_sources: HashMap::new(),
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

/// The walk of one directory in [`Merger::fix_collisions`].
struct DirWalk {
    /// The entries in priority order, as at the start of the walk; empty when nothing collides.
    order: Vec<ItemId>,
    /// The next entry to look at.
    next: usize,
    /// The case keys of the entries.
    keys: HashMap<ItemId, CaseKeys>,
    /// The names of the entries, for collisions and copy names.
    names: DirNames,
    /// Per key kind (lower, fold, upper): the kept entries by key, with their place in `order`.
    /// Kept entries never collide with each other, so a key names at most one of them.
    kept: [HashMap<String, (usize, ItemId)>; 3],
}

impl DirWalk {
    /// The first kept entry in priority order that collides with an entry of these keys.
    fn winner(&self, keys: &CaseKeys) -> Option<ItemId> {
        [&keys.lower, &keys.fold, &keys.upper]
            .into_iter()
            .zip(&self.kept)
            .filter_map(|(key, kept)| kept.get(key.as_str()))
            .min()
            .map(|(_, id)| *id)
    }

    fn keep(&mut self, place: usize, id: ItemId, keys: &CaseKeys) {
        for (key, kept) in [&keys.lower, &keys.fold, &keys.upper]
            .into_iter()
            .zip(&mut self.kept)
        {
            kept.insert(key.clone(), (place, id));
        }
    }
}

/// How a walk of a directory ended.
enum WalkEnd {
    /// No collision is left in the directory.
    Done,
    /// It stopped for a directory that comes first in the order, or for the fix budget.
    Paused,
}

impl Merger<'_> {
    /// Records that the local item now called `from` is called `to`: every local item that
    /// pointed to `from` points to `to` now; if none did, `from` itself does. The backward map
    /// finds them without a pass over all rekeys (a join rekeys every local item).
    fn record_rekey(&mut self, from: ItemId, to: ItemId) {
        let sources = self.rekey_sources.remove(&from).unwrap_or_default();
        if sources.is_empty() {
            if let Some(old) = self.rekeys.insert(from, to) {
                if let Some(set) = self.rekey_sources.get_mut(&old) {
                    set.remove(&from);
                }
            }
            self.rekey_sources.entry(to).or_default().insert(from);
            return;
        }
        let target = self.rekey_sources.entry(to).or_default();
        for source in sources {
            self.rekeys.insert(source, to);
            target.insert(source);
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

    /// Orphans, cycles and collisions, round by round until nothing changes; a round fixes the
    /// orphans and cycles it finds and then one collision.
    fn settle(&mut self) {
        // Each round resolves at least one problem; the bound only guards against a bug.
        let limit = 4 * (self.m.len() + 4);
        for round in 1..=limit {
            let mut changed = self.fix_orphans();
            changed |= self.fix_cycles();
            if changed {
                self.fix_collisions(1);
                continue;
            }
            // Fixing a collision makes no orphan and no cycle: it renames an entry, removes a
            // file, or moves a directory's entries into a directory next to it. So every later
            // round would only fix the next collision; take them all now, one per round left.
            self.fix_collisions(limit - round + 1);
            return;
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

    /// Whether every item reaches the root through its parents: one walk down from the root,
    /// instead of a path per item, which [`Merger::fix_cycles`] needs only when one does not.
    fn all_reach_root(&self) -> bool {
        // A node with the root's ID has a path by definition and is never walked into, so a
        // parent link to itself cannot loop.
        let mut reached = usize::from(self.m.contains(&ROOT));
        let mut stack = vec![ROOT];
        while let Some(at) = stack.pop() {
            for kid in self.m.children(&at) {
                if *kid != ROOT {
                    reached += 1;
                    stack.push(*kid);
                }
            }
        }
        reached == self.m.len()
    }

    /// The items that reach the root through their parents (a node with the root's ID
    /// included, as [`Tree::path`] gives it a path), found by one walk down from the root.
    fn reached_from_root(&self) -> HashSet<ItemId> {
        let mut reached = HashSet::new();
        if self.m.contains(&ROOT) {
            reached.insert(ROOT);
        }
        self.reach_below(ROOT, &mut reached);
        reached
    }

    /// Adds everything below `at` to `reached`.
    fn reach_below(&self, at: ItemId, reached: &mut HashSet<ItemId>) {
        let mut stack = vec![at];
        while let Some(dir) = stack.pop() {
            for kid in self.m.children(&dir) {
                if *kid != ROOT && reached.insert(*kid) {
                    stack.push(*kid);
                }
            }
        }
    }

    /// Moves that form a cycle: the local moves in it fall back to the remote place.
    ///
    /// Which items reach the root is kept in one set, grown as the fixes link items back
    /// (security review, LOW 3): asking [`Tree::path`] per item walked up to n steps for each
    /// item on a cycle. A fix only moves an item that does not reach the root, so no item that
    /// does ever loses its path; the set only grows, by what a fix links below a reached item.
    fn fix_cycles(&mut self) -> bool {
        if self.all_reach_root() {
            return false;
        }
        let mut reached = self.reached_from_root();
        let mut changed = false;
        let ids: Vec<ItemId> = self.m.ids().copied().collect();
        for id in ids {
            if reached.contains(&id) {
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
                let parent = node.parent;
                self.m.insert(*node_id, node);
                self.from_local.remove(node_id);
                self.dropped_local_moves += 1;
                self.link_if_reached(*node_id, parent, &mut reached);
                reverted = true;
                break;
            }
            if !reverted {
                // A cycle without a local move cannot come from a valid remote tree; break it.
                self.move_to_root(id);
                self.link_if_reached(id, ROOT, &mut reached);
            }
            changed = true;
        }
        changed
    }

    /// After `moved` got the parent `parent`: if that parent reaches the root, so does
    /// `moved` with everything below it.
    fn link_if_reached(&self, moved: ItemId, parent: ItemId, reached: &mut HashSet<ItemId>) {
        if (parent == ROOT || reached.contains(&parent)) && self.m.contains(&moved) {
            reached.insert(moved);
            self.reach_below(moved, reached);
        }
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

    /// Fixes collisions, at most `budget` of them, in the order of the round by round search
    /// (module docs): the first directory in the order that has a collision, there the first
    /// entry in priority order that collides with an entry kept before it. Returns how many
    /// were fixed.
    fn fix_collisions(&mut self, budget: usize) -> usize {
        // The directories that may hold a collision, in the order of the search: the root's
        // all-zero ID sorts first.
        let mut open: BTreeSet<ItemId> = std::iter::once(ROOT)
            .chain(self.m.iter().filter(|(_, n)| n.is_dir()).map(|(id, _)| *id))
            .collect();
        let mut paused: HashMap<ItemId, DirWalk> = HashMap::new();
        let mut fixed = 0;
        while fixed < budget {
            let Some(dir) = open.first().copied() else {
                break;
            };
            if dir != ROOT && !self.m.contains(&dir) {
                open.remove(&dir);
                paused.remove(&dir);
                continue;
            }
            let mut walk = match paused.remove(&dir) {
                Some(walk) => walk,
                None => self.start_walk(dir),
            };
            match self.walk(dir, &mut walk, &mut open, &mut paused, &mut fixed, budget) {
                WalkEnd::Done => {
                    open.remove(&dir);
                }
                WalkEnd::Paused => {
                    paused.insert(dir, walk);
                }
            }
        }
        fixed
    }

    /// The walk of `dir` from its start: the entries' keys, and their priority order if any
    /// two of them collide.
    fn start_walk(&self, dir: ItemId) -> DirWalk {
        let mut names = DirNames::default();
        let mut keys = HashMap::new();
        for kid in self.m.children(&dir) {
            if let Some(node) = self.m.get(kid) {
                let k = case_keys(&node.name);
                names.add(&k);
                keys.insert(*kid, k);
            }
        }
        let mut order = Vec::new();
        if keys.len() >= 2 && names.any_collision() {
            order = self.m.children(&dir).copied().collect();
            order.sort_by_cached_key(|k| self.priority(&dir, k));
        }
        DirWalk {
            order,
            next: 0,
            keys,
            names,
            kept: Default::default(),
        }
    }

    /// Walks `dir` on from where it stopped, fixing each collision, until it ends or a merge
    /// of two directories adds entries to a directory that comes first in the order.
    fn walk(
        &mut self,
        dir: ItemId,
        walk: &mut DirWalk,
        open: &mut BTreeSet<ItemId>,
        paused: &mut HashMap<ItemId, DirWalk>,
        fixed: &mut usize,
        budget: usize,
    ) -> WalkEnd {
        while walk.next < walk.order.len() {
            if *fixed >= budget {
                return WalkEnd::Paused;
            }
            let place = walk.next;
            let kid = walk.order[place];
            walk.next += 1;
            let (Some(node), Some(keys)) = (self.m.get(&kid).cloned(), walk.keys.get(&kid)) else {
                continue;
            };
            let Some(winner) = walk.winner(keys) else {
                let keys = keys.clone();
                walk.keep(place, kid, &keys);
                continue;
            };
            let Some(win) = self.m.get(&winner).cloned() else {
                continue;
            };
            *fixed += 1;
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
                    if let Some(keys) = walk.keys.remove(&kid) {
                        walk.names.remove(&keys);
                    }
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
                    if let Some(keys) = walk.keys.remove(&kid) {
                        walk.names.remove(&keys);
                    }
                    open.remove(&kid);
                    paused.remove(&kid);
                    // The winner has new entries: walk it again from its start.
                    paused.remove(&winner);
                    open.insert(winner);
                    if winner < dir {
                        return WalkEnd::Paused;
                    }
                }
                _ => self.rename_loser(walk, kid, &node, winner, &win),
            }
        }
        WalkEnd::Done
    }

    fn rename_loser(
        &mut self,
        walk: &mut DirWalk,
        kid: ItemId,
        node: &Node,
        winner: ItemId,
        win: &Node,
    ) {
        // The copy name must not collide with any other entry of the directory.
        if let Some(keys) = walk.keys.remove(&kid) {
            walk.names.remove(&keys);
        }
        let name = walk.names.copy_name(&node.name, &self.copy_label);
        let keys = case_keys(&name);
        walk.names.add(&keys);
        walk.keys.insert(kid, keys);
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
    use crate::names::tests::{keys_computed, Rng};
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

    /// The collision fixing as it was before security review HIGH 2, round by round with a pair
    /// comparison of names, kept as the reference the linear version must equal.
    mod reference {
        use super::super::*;
        use crate::names::first_free;

        fn names_collide(a: &str, b: &str) -> bool {
            let (ka, kb) = (
                hangar_drive_protocol::name::comparison_key(a),
                hangar_drive_protocol::name::comparison_key(b),
            );
            ka == kb || CaseKeys::of(&ka).collides(&CaseKeys::of(&kb))
        }

        /// The old `record_rekey`, a pass over all rekeys.
        pub(super) fn record_rekey(
            rekeys: &mut BTreeMap<ItemId, ItemId>,
            from: ItemId,
            to: ItemId,
        ) {
            let mut found = false;
            for value in rekeys.values_mut() {
                if *value == from {
                    *value = to;
                    found = true;
                }
            }
            if !found {
                rekeys.insert(from, to);
            }
        }

        /// [`merge3`] with the old settle.
        pub(super) fn merge3(
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
                copy_label: conflict_label(labels.words, labels.device, labels.date),
                from_local: BTreeSet::new(),
                rekeys: BTreeMap::new(),
                rekey_sources: HashMap::new(),
                copies: Vec::new(),
                content_copies: BTreeSet::new(),
                dropped_local_moves: 0,
            };
            merger.split_kind_changes(ids);
            merger.apply_local(ids);
            merger.settle_reference();
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

        impl Merger<'_> {
            fn settle_reference(&mut self) {
                let limit = 4 * (self.m.len() + 4);
                for _ in 0..limit {
                    let mut changed = self.fix_orphans();
                    changed |= self.fix_cycles_reference();
                    changed |= self.fix_collisions_reference();
                    if !changed {
                        return;
                    }
                }
            }

            fn fix_cycles_reference(&mut self) -> bool {
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
                        self.move_to_root(id);
                    }
                    changed = true;
                }
                changed
            }

            fn fix_collisions_reference(&mut self) -> bool {
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
                        let local_can_rekey =
                            !self.local.contains(&winner) && self.local.contains(&kid);
                        match (&win.kind, &node.kind) {
                            (NodeKind::File(wv), NodeKind::File(nv))
                                if is_new && local_can_rekey && wv.same_content(nv) =>
                            {
                                self.m.remove(&kid);
                                self.local.rekey(&kid, winner);
                                record_rekey(&mut self.rekeys, kid, winner);
                                return true;
                            }
                            (NodeKind::Directory, NodeKind::Directory)
                                if is_new && local_can_rekey =>
                            {
                                let grandkids: Vec<ItemId> =
                                    self.m.children(&kid).copied().collect();
                                for g in grandkids {
                                    if let Some(mut gn) = self.m.get(&g).cloned() {
                                        gn.parent = winner;
                                        self.m.insert(g, gn);
                                    }
                                }
                                self.m.remove(&kid);
                                self.local.rekey(&kid, winner);
                                record_rekey(&mut self.rekeys, kid, winner);
                                return true;
                            }
                            _ => {
                                self.rename_loser_reference(dir, kid, &node, winner, &win);
                                return true;
                            }
                        }
                    }
                }
                false
            }

            fn rename_loser_reference(
                &mut self,
                dir: ItemId,
                kid: ItemId,
                node: &Node,
                winner: ItemId,
                win: &Node,
            ) {
                let siblings: Vec<String> = self
                    .m
                    .children(&dir)
                    .filter(|s| **s != kid)
                    .filter_map(|s| self.m.get(s).map(|n| n.name.clone()))
                    .collect();
                let taken = |candidate: &str| siblings.iter().any(|s| names_collide(s, candidate));
                let name = first_free(&node.name, &self.copy_label, &taken);
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
        }
    }

    /// Fresh IDs in a range of their own, for any number of copies.
    struct Fresh(u64);

    impl ItemIds for Fresh {
        fn new_item_id(&mut self) -> ItemId {
            self.0 += 1;
            let mut bytes = [0xee; 16];
            bytes[8..].copy_from_slice(&self.0.to_be_bytes());
            ItemId::from_bytes(bytes)
        }
    }

    fn labels_for(words: &LabelWords) -> MergeLabels<'_> {
        MergeLabels {
            words,
            device: "Laptop",
            date: "2026-11-26",
        }
    }

    /// A random tree over a small pool of IDs and colliding names: directories and files, parents
    /// from the pool (so some are missing or files, which makes orphans and cycles), contents from
    /// a small set (so equal new files are taken once).
    fn random_tree(rng: &mut Rng, pool: &[ItemId], names: &[String], size: usize) -> Tree {
        let mut t = Tree::new();
        for _ in 0..size {
            let item = *rng.pick(pool);
            let parent = if rng.below(3) == 0 {
                ROOT
            } else {
                *rng.pick(pool)
            };
            let name = rng.pick(names).clone();
            let node = if rng.below(3) == 0 {
                Node::dir(parent, name)
            } else {
                Node::file(parent, name, file(1 + rng.below(3) as u8))
            };
            t.insert(item, node);
        }
        t
    }

    /// Changes some nodes of `t`: names, parents, contents, deletes and adds.
    fn mutate(rng: &mut Rng, t: &Tree, pool: &[ItemId], names: &[String]) -> Tree {
        let mut out = t.clone();
        for _ in 0..1 + rng.below(6) {
            let item = *rng.pick(pool);
            match (rng.below(5), out.get(&item).cloned()) {
                (0, Some(_)) => {
                    out.remove(&item);
                }
                (1, Some(mut node)) => {
                    node.name = rng.pick(names).clone();
                    out.insert(item, node);
                }
                (2, Some(mut node)) => {
                    node.parent = if rng.below(2) == 0 {
                        ROOT
                    } else {
                        *rng.pick(pool)
                    };
                    out.insert(item, node);
                }
                (3, Some(mut node)) if !node.is_dir() => {
                    node.kind = NodeKind::File(file(1 + rng.below(3) as u8));
                    out.insert(item, node);
                }
                _ => {
                    let parent = if rng.below(2) == 0 {
                        ROOT
                    } else {
                        *rng.pick(pool)
                    };
                    let name = rng.pick(names).clone();
                    let node = if rng.below(3) == 0 {
                        Node::dir(parent, name)
                    } else {
                        Node::file(parent, name, file(1 + rng.below(3) as u8))
                    };
                    out.insert(item, node);
                }
            }
        }
        out
    }

    fn assert_same(new: &MergeOutcome, old: &MergeOutcome, case: usize) {
        assert_eq!(new.tree, old.tree, "case {case}: merged tree");
        assert_eq!(new.local, old.local, "case {case}: local tree");
        assert_eq!(new.rekeys, old.rekeys, "case {case}: rekeys");
        assert_eq!(new.copies, old.copies, "case {case}: copies");
        assert_eq!(
            new.dropped_local_moves, old.dropped_local_moves,
            "case {case}: dropped moves"
        );
    }

    /// Security review HIGH 2: the linear collision fixing gives exactly the result of the round
    /// by round search, on random trees full of case, NFC, long s and sigma collisions, numbered
    /// copy names, merges of new directories into remote ones, orphans and cycles.
    #[test]
    fn linear_collision_fixing_equals_the_reference() {
        let words = LabelWords::default();
        let labels = labels_for(&words);
        let mut rng = Rng(0x5eed);
        let mut names: Vec<String> = [
            "a", "A", "b", "B", "x.txt", "X.TXT", "X.txt", "e\u{301}", "\u{e9}", "\u{c9}", "s",
            "\u{17f}", "S", "\u{3a3}", "\u{3c3}", "\u{3c2}", "\u{212a}", "k", "K",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        names.push("x (conflict Laptop 2026-11-26).txt".into());
        names.push("X (conflict Laptop 2026-11-26 2).TXT".into());
        names.push("a (conflict Laptop 2026-11-26)".into());
        for case in 0..4000 {
            // Pools of different sizes and ID orders, so winners come before and after their
            // directory in the order.
            let pool: Vec<ItemId> = (0..4 + rng.below(14))
                .map(|_| id(1 + rng.below(200) as u8))
                .collect();
            let size = rng.below(10);
            let base = random_tree(&mut rng, &pool, &names, size);
            let (remote, local) = match rng.below(3) {
                // A join: the empty base, new items on both sides.
                0 => {
                    let (r, l) = (2 + rng.below(12), 2 + rng.below(12));
                    (
                        random_tree(&mut rng, &pool, &names, r),
                        random_tree(&mut rng, &pool, &names, l),
                    )
                }
                _ => (
                    mutate(&mut rng, &base, &pool, &names),
                    mutate(&mut rng, &base, &pool, &names),
                ),
            };
            let base = if rng.below(3) == 0 { Tree::new() } else { base };
            let new = merge3(&base, &remote, &local, &labels, &mut Fresh(0));
            let old = reference::merge3(&base, &remote, &local, &labels, &mut Fresh(0));
            assert_same(&new, &old, case);
        }
    }

    /// Larger directories: many local new directories that collide with remote ones by case, each
    /// with colliding entries, some nested, in both ID orders.
    #[test]
    fn nested_directory_merges_equal_the_reference() {
        let words = LabelWords::default();
        let labels = labels_for(&words);
        let mut rng = Rng(77);
        let variants = ["d", "D", "\u{17f}", "s", "S"];
        for case in 0..150 {
            let mut remote = Tree::new();
            let mut local = Tree::new();
            let mut next = 1u8;
            let mut fresh = |rng: &mut Rng| {
                next = next.wrapping_add(1 + rng.below(3) as u8);
                id(next)
            };
            let mut remote_dirs = vec![ROOT];
            let mut local_dirs = vec![ROOT];
            for _ in 0..30 {
                let name = format!("{}{}", rng.pick(&variants), rng.below(2));
                let (tree, dirs) = if rng.below(2) == 0 {
                    (&mut remote, &mut remote_dirs)
                } else {
                    (&mut local, &mut local_dirs)
                };
                let parent = *rng.pick(dirs);
                let item = fresh(&mut rng);
                if tree.contains(&item) {
                    continue;
                }
                if rng.below(2) == 0 {
                    tree.insert(item, Node::dir(parent, name));
                    dirs.push(item);
                } else {
                    tree.insert(item, Node::file(parent, name, file(1 + rng.below(2) as u8)));
                }
            }
            let new = join(&remote, &local, &labels, &mut Fresh(0));
            let old = reference::merge3(&Tree::new(), &remote, &local, &labels, &mut Fresh(0));
            assert_same(&new, &old, case);
        }
    }

    /// The backward map of `record_rekey` gives the rekeys of the old pass over all of them.
    #[test]
    fn record_rekey_equals_the_reference() {
        let empty = Tree::new();
        let mut rng = Rng(5);
        for case in 0..2000 {
            let mut merger = Merger {
                base: &empty,
                remote: &empty,
                local: Tree::new(),
                m: Tree::new(),
                copy_label: String::new(),
                from_local: BTreeSet::new(),
                rekeys: BTreeMap::new(),
                rekey_sources: HashMap::new(),
                copies: Vec::new(),
                content_copies: BTreeSet::new(),
                dropped_local_moves: 0,
            };
            let mut old = BTreeMap::new();
            for _ in 0..12 {
                let (from, to) = (id(rng.below(8) as u8), id(rng.below(8) as u8));
                merger.record_rekey(from, to);
                reference::record_rekey(&mut old, from, to);
                assert_eq!(merger.rekeys, old, "case {case}");
            }
        }
    }

    /// 10,000 local moves that make two directories each other's parent: every cycle is broken
    /// with a few units of work per item. Asking for the path of each item on a cycle walked up
    /// to n steps for it (security review, LOW 3; 4 * 10^8 steps here).
    #[test]
    fn many_cycles_take_linear_work() {
        let words = LabelWords::default();
        let labels = labels_for(&words);
        let pairs = 10_000u32;
        let wide = |n: u32, hi: u8| {
            let mut bytes = [0u8; 16];
            bytes[0] = hi;
            bytes[12..].copy_from_slice(&n.to_be_bytes());
            ItemId::from_bytes(bytes)
        };
        let base = Tree::from_nodes((0..pairs).flat_map(|i| {
            [
                (wide(i, 1), Node::dir(ROOT, format!("a{i}"))),
                (wide(i, 2), Node::dir(ROOT, format!("b{i}"))),
            ]
        }));
        let local = Tree::from_nodes((0..pairs).flat_map(|i| {
            [
                (wide(i, 1), Node::dir(wide(i, 2), format!("a{i}"))),
                (wide(i, 2), Node::dir(wide(i, 1), format!("b{i}"))),
            ]
        }));
        let before = crate::tree::tests::work_done();
        let out = merge3(&base, &base, &local, &labels, &mut Fresh(0));
        let work = crate::tree::tests::work_done() - before;
        assert_eq!(out.tree.check(), Ok(()));
        assert_eq!(out.dropped_local_moves, pairs as usize);
        assert!(work <= 20 * u64::from(pairs), "{work} units of work");
    }

    /// Work bounds that hold in a debug build without a clock (security review HIGH 2): the keys
    /// of a name are computed a few times per entry, not once per pair or per round.
    #[test]
    fn collisions_take_linear_work() {
        let words = LabelWords::default();
        let labels = labels_for(&words);
        let wide = |n: u32, hi: u8| {
            let mut bytes = [0u8; 16];
            bytes[0] = hi;
            bytes[12..].copy_from_slice(&n.to_be_bytes());
            ItemId::from_bytes(bytes)
        };
        let version = |n: u32| FileVersion {
            size: u64::from(n),
            mtime_ms: 0,
            executable: false,
            content: crate::tree::ContentKey([(n % 251) as u8; 32]),
        };

        // An unchanged folder of 50,000 files.
        let files = 50_000u32;
        let t = Tree::from_nodes((0..files).map(|i| {
            (
                wide(i, 1),
                Node::file(ROOT, format!("f{i:06}.jpg"), version(i)),
            )
        }));
        let before = keys_computed();
        let out = merge3(&t, &t, &t, &labels, &mut Fresh(0));
        assert_eq!(out.tree, t);
        let work = keys_computed() - before;
        assert!(
            work <= 2 * u64::from(files),
            "unchanged: {work} key computations"
        );

        // A join of 5,000 identical files: each is taken once under the remote ID.
        let n = 5_000u32;
        let remote = Tree::from_nodes((0..n).map(|i| {
            (
                wide(i, 1),
                Node::file(ROOT, format!("f{i:05}.jpg"), version(i)),
            )
        }));
        let local = Tree::from_nodes((0..n).map(|i| {
            (
                wide(i, 2),
                Node::file(ROOT, format!("F{i:05}.JPG"), version(i)),
            )
        }));
        let before = keys_computed();
        let out = join(&remote, &local, &labels, &mut Fresh(0));
        assert_eq!(out.tree, remote);
        assert_eq!(out.rekeys.len(), n as usize);
        let work = keys_computed() - before;
        assert!(work <= 4 * u64::from(n), "join: {work} key computations");

        // 2,048 case variants of one name on the server: one keeps it, the others become copies.
        let variants = 2_048u32;
        let remote = Tree::from_nodes((0..variants).map(|i| {
            let name: String = "abcdefghijk.txt"
                .chars()
                .enumerate()
                .map(|(at, c)| {
                    if (i >> at) & 1 == 1 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();
            (wide(i, 3), Node::file(ROOT, name, version(i)))
        }));
        let before = keys_computed();
        let out = merge3(&remote, &remote, &remote, &labels, &mut Fresh(0));
        assert_eq!(out.tree.check(), Ok(()));
        assert_eq!(out.copies.len(), variants as usize - 1);
        let work = keys_computed() - before;
        // A few per copy and digit of its number.
        assert!(
            work <= 20 * u64::from(variants),
            "variants: {work} key computations"
        );
    }
}
