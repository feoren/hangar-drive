//! The executor: brings the disk from the working tree to the merged tree, one item at a time.
//!
//! The order is not precomputed. Each pass runs every operation whose preconditions hold in the
//! working tree (the parent exists, the target name is free, a directory to delete is empty),
//! until nothing is left or nothing can run. Two moves that need each other's names (a swap or a
//! longer cycle) are broken by parking one item in the reserved directory and putting it in
//! place once its name is free.
//!
//! An operation that has to wait is registered under what it waits for (the creation of its
//! parent, a name in a directory, the directory to empty) and tried again only once exactly that
//! changed, so a chain of n renames, each onto the name the next one gives up, takes O(n) steps
//! instead of one pass over every waiting item per rename (security review of the executor,
//! MEDIUM 1: 65 s for a chain of 16,000).
//!
//! Every operation checks its precondition on the disk itself ([`DiskActions`]): a file that the
//! person changed since the scan is never overwritten or deleted. A failed operation leaves the
//! item as it was in both the working tree and the synced tree, so the next round merges it
//! again; it never blocks the other items.
//!
//! Whether a target name is free is looked up in [`Siblings`], an index of the working tree by
//! case key per directory, not by comparing the name with every entry of the directory: a run
//! over a directory of many new files checks a name for each of them (security review HIGH 2).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use hangar_drive_protocol::ids::ItemId;
use hangar_drive_protocol::name::CaseKeys;

use crate::names::case_keys;
use crate::tree::{FileVersion, Node, NodeKind, Tree, ROOT};

/// Why one disk operation did not run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionError {
    /// The disk no longer holds what the scan saw: the person changed it. Rescan.
    #[error("the item changed on disk since the scan")]
    Changed,
    /// Creating reported "already exists" for a name the tree says is free (security review
    /// N3): another name the file system takes as the same, for example by case or an 8.3
    /// alias. The item is marked "cannot sync on this device".
    #[error("the file system reports that the name already exists")]
    Exists,
    /// This device cannot hold the name or the entry (ADR 0001, section 7).
    #[error("this device cannot hold this item: {0}")]
    CannotSync(String),
    /// The file is open in another program; retried later with backoff.
    #[error("the file is locked by another program")]
    Locked,
    /// The content could not be fetched (network, server).
    #[error("the content is not available right now")]
    Unavailable,
    /// The disk is full.
    #[error("the disk is full")]
    DiskFull,
    /// Another I/O error.
    #[error("i/o error: {0}")]
    Io(String),
    /// The operation waited for another one that failed.
    #[error("the operation depends on another one that failed")]
    Blocked,
}

/// The disk operations the executor needs. Paths are lists of names from the folder root.
pub trait DiskActions {
    /// Creates a directory; [`ActionError::Exists`] if the name is taken on disk.
    fn create_dir(&mut self, path: &[String]) -> Result<(), ActionError>;
    /// Writes `version` of file `item` atomically (temporary file and rename). With `expect`,
    /// it replaces the file only if the disk still holds that version; without, it creates the
    /// file and refuses an existing name with [`ActionError::Exists`].
    fn write_file(
        &mut self,
        item: &ItemId,
        path: &[String],
        version: &FileVersion,
        expect: Option<&FileVersion>,
    ) -> Result<(), ActionError>;
    /// Sets modification time and execute flag of file `item` that still holds `expect`.
    fn set_meta(
        &mut self,
        item: &ItemId,
        path: &[String],
        version: &FileVersion,
        expect: &FileVersion,
    ) -> Result<(), ActionError>;
    /// Renames without replacing; [`ActionError::Exists`] if the target name is taken.
    fn rename(&mut self, from: &[String], to: &[String]) -> Result<(), ActionError>;
    /// Deletes file `item`, which still holds `expect`, because the merged tree no longer has
    /// it (an incoming delete).
    fn remove_file(
        &mut self,
        item: &ItemId,
        path: &[String],
        expect: &FileVersion,
    ) -> Result<(), ActionError>;
    /// Deletes an empty directory; [`ActionError::Changed`] if it is not empty.
    fn remove_dir(&mut self, path: &[String]) -> Result<(), ActionError>;
    /// Moves an item into the reserved park directory under its item ID.
    fn park(&mut self, item: &ItemId, path: &[String]) -> Result<(), ActionError>;
    /// Moves a parked item to `path`.
    fn unpark(&mut self, item: &ItemId, path: &[String]) -> Result<(), ActionError>;
}

/// What a run of the executor did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Items now on disk as in the merged tree.
    pub done: Vec<ItemId>,
    /// Items that failed, with the reason.
    pub failed: Vec<(ItemId, ActionError)>,
    /// Items still parked because their place never became free; they are put back at the next
    /// run (the caller keeps them in the working tree at their old place).
    pub parked: Vec<ItemId>,
}

fn full_path(tree: &Tree, parent: &ItemId, name: &str) -> Option<Vec<String>> {
    let mut path = if *parent == ROOT {
        Vec::new()
    } else {
        tree.path(parent)?
    };
    path.push(name.to_owned());
    Some(path)
}

fn parent_ready(work: &Tree, parent: &ItemId) -> bool {
    *parent == ROOT || work.get(parent).is_some_and(Node::is_dir)
}

fn key_parts(keys: &CaseKeys) -> [&str; 3] {
    [&keys.lower, &keys.fold, &keys.upper]
}

/// A change of the working tree that an operation may wait for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    /// An entry named `name` left directory `parent` (moved away, renamed, removed, parked).
    Left { parent: ItemId, name: String },
    /// An item is in the working tree now that was not.
    Arrived(ItemId),
    /// An item changed its place or left the working tree.
    Moved(ItemId),
    /// A parked item came back with what was below it.
    Unparked,
}

/// The working tree's entries by case key, per directory: a directory is indexed when it is
/// first asked about, and every change of the working tree during a run goes through
/// [`Siblings::insert`] and [`Siblings::remove`], which keep the index in step and record each
/// change as an [`Event`]. Answers what [`Tree::colliding_children`] answers, without a pass
/// over the directory.
#[derive(Default)]
struct Siblings {
    /// Per indexed directory and key kind (lower, fold, upper): the entries with each key.
    dirs: HashMap<ItemId, [HashMap<String, BTreeSet<ItemId>>; 3]>,
    /// Per entry of an indexed directory: the directory, the name and its keys.
    entries: HashMap<ItemId, (ItemId, String, CaseKeys)>,
    /// The changes since the executor last took them.
    events: Vec<Event>,
}

impl Siblings {
    /// The entries of `parent` that collide with `name`, `except` left out, in ID order.
    fn colliding(
        &mut self,
        work: &Tree,
        parent: &ItemId,
        name: &str,
        except: &ItemId,
    ) -> Vec<ItemId> {
        self.index(work, parent);
        let keys = case_keys(name);
        let Some(maps) = self.dirs.get(parent) else {
            return Vec::new();
        };
        let mut out = BTreeSet::new();
        for (key, map) in key_parts(&keys).into_iter().zip(maps) {
            if let Some(ids) = map.get(key) {
                out.extend(ids.iter().filter(|id| *id != except).copied());
            }
        }
        out.into_iter().collect()
    }

    fn free(&mut self, work: &Tree, parent: &ItemId, name: &str, except: &ItemId) -> bool {
        self.colliding(work, parent, name, except).is_empty()
    }

    fn index(&mut self, work: &Tree, parent: &ItemId) {
        if self.dirs.contains_key(parent) {
            return;
        }
        self.dirs.insert(*parent, Default::default());
        let kids: Vec<(ItemId, String)> = work
            .children(parent)
            .filter_map(|kid| work.get(kid).map(|node| (*kid, node.name.clone())))
            .collect();
        for (kid, name) in kids {
            let keys = case_keys(&name);
            self.link(kid, *parent, name, keys);
        }
    }

    fn link(&mut self, id: ItemId, parent: ItemId, name: String, keys: CaseKeys) {
        if let Some(maps) = self.dirs.get_mut(&parent) {
            for (key, map) in key_parts(&keys).into_iter().zip(maps.iter_mut()) {
                map.entry(key.to_owned()).or_default().insert(id);
            }
            self.entries.insert(id, (parent, name, keys));
        }
    }

    /// Takes `id` out of the index; returns its name and keys if it was in.
    fn unlink(&mut self, id: &ItemId) -> Option<(String, CaseKeys)> {
        let (parent, name, keys) = self.entries.remove(id)?;
        if let Some(maps) = self.dirs.get_mut(&parent) {
            for (key, map) in key_parts(&keys).into_iter().zip(maps.iter_mut()) {
                if let Some(ids) = map.get_mut(key) {
                    ids.remove(id);
                    if ids.is_empty() {
                        map.remove(key);
                    }
                }
            }
        }
        Some((name, keys))
    }

    /// `work.insert` with the index kept in step.
    fn insert(&mut self, work: &mut Tree, id: ItemId, node: Node) {
        match work.get(&id) {
            None => self.events.push(Event::Arrived(id)),
            Some(before) if before.location() != node.location() => {
                self.events.push(Event::Left {
                    parent: before.parent,
                    name: before.name.clone(),
                });
                self.events.push(Event::Moved(id));
            }
            Some(_) => {}
        }
        let old = self.unlink(&id);
        if self.dirs.contains_key(&node.parent) {
            let keys = match old {
                Some((name, keys)) if name == node.name => keys,
                _ => case_keys(&node.name),
            };
            self.link(id, node.parent, node.name.clone(), keys);
        }
        work.insert(id, node);
    }

    /// `work.remove` with the index kept in step.
    fn remove(&mut self, work: &mut Tree, id: &ItemId) -> Option<Node> {
        self.unlink(id);
        let node = work.remove(id)?;
        self.events.push(Event::Left {
            parent: node.parent,
            name: node.name.clone(),
        });
        self.events.push(Event::Moved(*id));
        Some(node)
    }
}

/// What a waiting operation waits for ([`Step::Wait`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reason {
    /// The item is below a parked directory.
    Parked,
    /// The directory to delete still has entries.
    Children(ItemId),
    /// The target parent is not a directory of the working tree yet.
    Parent(ItemId),
    /// The target name is taken in the target directory.
    Name(ItemId, String),
    /// The target directory lies below the item itself.
    Ancestor(ItemId),
    /// Anything else: tried again after the next change of the working tree.
    Again,
}

/// Waiting operations by what they wait for, woken by the [`Event`]s that end the wait.
#[derive(Default)]
struct Waits {
    parent: HashMap<ItemId, Vec<ItemId>>,
    name: HashMap<(ItemId, usize, String), Vec<ItemId>>,
    children: HashMap<ItemId, Vec<ItemId>>,
    moved: HashMap<ItemId, Vec<ItemId>>,
    parked: Vec<ItemId>,
    again: Vec<ItemId>,
}

impl Waits {
    fn register(&mut self, id: ItemId, reason: Reason, work: &Tree) {
        match reason {
            Reason::Parked => self.parked.push(id),
            Reason::Children(dir) => self.children.entry(dir).or_default().push(id),
            Reason::Parent(parent) => self.parent.entry(parent).or_default().push(id),
            Reason::Name(parent, name) => {
                let keys = case_keys(&name);
                for (kind, key) in key_parts(&keys).into_iter().enumerate() {
                    self.name
                        .entry((parent, kind, key.to_owned()))
                        .or_default()
                        .push(id);
                }
            }
            Reason::Ancestor(target) => {
                // The target lies below `id` as long as every directory between them keeps
                // its place; a move of any of them may end the wait.
                let mut at = target;
                let mut steps = 0usize;
                while at != id && at != ROOT && steps <= work.len() {
                    self.moved.entry(at).or_default().push(id);
                    match work.get(&at) {
                        Some(node) => at = node.parent,
                        None => break,
                    }
                    steps += 1;
                }
            }
            Reason::Again => self.again.push(id),
        }
    }

    /// Adds to `out` the operations `event` may let run.
    fn wake(&mut self, event: &Event, out: &mut Vec<ItemId>) {
        match event {
            Event::Left { parent, name } => {
                if self.name.keys().next().is_some() {
                    let keys = case_keys(name);
                    for (kind, key) in key_parts(&keys).into_iter().enumerate() {
                        if let Some(ids) = self.name.remove(&(*parent, kind, key.to_owned())) {
                            out.extend(ids);
                        }
                    }
                }
                if let Some(ids) = self.children.remove(parent) {
                    out.extend(ids);
                }
            }
            Event::Arrived(id) => {
                if let Some(ids) = self.parent.remove(id) {
                    out.extend(ids);
                }
            }
            Event::Moved(id) => {
                if let Some(ids) = self.moved.remove(id) {
                    out.extend(ids);
                }
            }
            Event::Unparked => out.append(&mut self.parked),
        }
    }
}

/// Brings the disk from `work` (what it holds now) to `target`; `work` and `synced` are updated
/// per finished item. Items in `skip` are left alone.
pub fn apply(
    target: &Tree,
    work: &mut Tree,
    synced: &mut Tree,
    skip: &BTreeSet<ItemId>,
    disk: &mut dyn DiskActions,
) -> ApplyReport {
    let mut report = ApplyReport::default();
    let mut pending: BTreeSet<ItemId> = target
        .ids()
        .chain(work.ids())
        .filter(|id| !skip.contains(id) && work.get(id) != target.get(id))
        .copied()
        .collect();
    // Items already equal on disk and in the target are synced.
    let equal: Vec<ItemId> = target
        .iter()
        .filter(|(id, node)| work.get(id) == Some(*node) && synced.get(id) != Some(*node))
        .map(|(id, _)| *id)
        .collect();
    for id in equal {
        if let Some(node) = target.get(&id) {
            synced.insert(id, node.clone());
        }
    }
    let mut parked = Parked::default();
    let mut names = Siblings::default();
    // Passes in ID order as before, but a pass tries only the operations that may run: all of
    // them at first, later those an event woke. One woken before the place the pass has reached
    // runs in the next pass, as it would have.
    let mut ready: BTreeSet<ItemId> = pending.clone();
    let mut waits = Waits::default();
    let mut cursor: Option<ItemId> = None;
    let mut woken = Vec::new();
    // Each operation runs once and waits a few times; the bound only guards against a bug.
    let limit = 64usize.saturating_mul(pending.len() + 2);
    let mut steps = 0usize;
    while !pending.is_empty() && steps < limit {
        let next = cursor
            .and_then(|at| {
                ready
                    .range((std::ops::Bound::Excluded(at), std::ops::Bound::Unbounded))
                    .next()
                    .copied()
            })
            .or_else(|| ready.first().copied());
        let Some(id) = next else {
            // Nothing can run: break a cycle by parking one item, which frees its name.
            if !park_one(&pending, target, work, &mut names, &mut parked, disk) {
                break;
            }
            wake_all(&mut names, &mut waits, &mut woken, &pending, &mut ready);
            cursor = None;
            continue;
        };
        ready.remove(&id);
        cursor = Some(id);
        steps += 1;
        match step(&id, target, work, &mut names, &mut parked, disk) {
            Step::Done => {
                pending.remove(&id);
                if let Some(node) = target.get(&id) {
                    if work.get(&id) == Some(node) {
                        synced.insert(id, node.clone());
                    }
                } else {
                    synced.remove(&id);
                }
                report.done.push(id);
            }
            Step::Wait(reason) => waits.register(id, reason, work),
            Step::Failed(error) => {
                pending.remove(&id);
                report.failed.push((id, error));
            }
        }
        wake_all(&mut names, &mut waits, &mut woken, &pending, &mut ready);
    }
    for id in pending {
        report.failed.push((id, ActionError::Blocked));
    }
    // A parked item whose place never became free goes back where it was, or, if that name
    // was taken meanwhile, under a free name next to it: an item must never stay in the park,
    // where the scan would not see it and would take it for deleted.
    let roots: Vec<ItemId> = parked.roots.keys().copied().collect();
    for id in roots {
        let Some(mut nodes) = parked.roots.remove(&id) else {
            continue;
        };
        let Some((_, node)) = nodes.first().cloned() else {
            continue;
        };
        let mut placed = None;
        for candidate in fallback_places(work, &mut names, &node) {
            let Some(path) = full_path(work, &candidate.0, &candidate.1) else {
                continue;
            };
            if disk.unpark(&id, &path).is_ok() {
                placed = Some(candidate);
                break;
            }
        }
        match placed {
            Some((parent, name)) => {
                if let Some(first) = nodes.first_mut() {
                    first.1.parent = parent;
                    first.1.name = name;
                }
                for (member, n) in nodes {
                    parked.members.remove(&member);
                    names.insert(work, member, n);
                }
            }
            None => report.parked.push(id),
        }
    }
    report
}

/// Wakes the operations the recorded events may let run. Any change of the working tree also
/// wakes those that wait for no particular change ([`Reason::Again`]).
fn wake_all(
    names: &mut Siblings,
    waits: &mut Waits,
    woken: &mut Vec<ItemId>,
    pending: &BTreeSet<ItemId>,
    ready: &mut BTreeSet<ItemId>,
) {
    let events = std::mem::take(&mut names.events);
    if events.is_empty() {
        return;
    }
    for event in &events {
        waits.wake(event, woken);
    }
    woken.append(&mut waits.again);
    for id in woken.drain(..) {
        if pending.contains(&id) {
            ready.insert(id);
        }
    }
}

/// Where a parked item can go back: its old place, then free names next to it, then the root.
fn fallback_places(work: &Tree, names: &mut Siblings, node: &Node) -> Vec<(ItemId, String)> {
    let mut out = Vec::new();
    let parents: Vec<ItemId> =
        if node.parent == ROOT || work.get(&node.parent).is_some_and(Node::is_dir) {
            vec![node.parent, ROOT]
        } else {
            vec![ROOT]
        };
    // No item has the root's ID, so no entry is left out of the check.
    for parent in parents {
        if names.free(work, &parent, &node.name, &ROOT) {
            out.push((parent, node.name.clone()));
        }
        let (stem, ext) = crate::names::split_extension(&node.name);
        for n in 2..50u32 {
            let name = format!("{stem} ({n}){ext}");
            if names.free(work, &parent, &name, &ROOT) {
                out.push((parent, name));
                break;
            }
        }
    }
    out
}

/// Items moved into the park directory, each with the subtree it took along.
#[derive(Default)]
struct Parked {
    /// Per parked item: its node first, then every node below it.
    roots: BTreeMap<ItemId, Vec<(ItemId, Node)>>,
    /// Every item below a parked item (not the parked items themselves).
    members: BTreeSet<ItemId>,
}

enum Step {
    Done,
    Wait(Reason),
    Failed(ActionError),
}

fn step(
    id: &ItemId,
    target: &Tree,
    work: &mut Tree,
    names: &mut Siblings,
    parked: &mut Parked,
    disk: &mut dyn DiskActions,
) -> Step {
    #[cfg(test)]
    tests::count_step();
    if parked.members.contains(id) {
        // Below a parked directory: wait until it is back in the tree.
        return Step::Wait(Reason::Parked);
    }
    let current = work.get(id).cloned();
    let wanted = target.get(id).cloned();
    match (current, wanted) {
        (None, None) => Step::Done,
        (Some(have), None) => {
            let Some(path) = work.path(id) else {
                return Step::Failed(ActionError::Blocked);
            };
            let result = match &have.kind {
                NodeKind::Directory => {
                    if work.children(id).next().is_some() {
                        return Step::Wait(Reason::Children(*id));
                    }
                    disk.remove_dir(&path)
                }
                NodeKind::File(version) => disk.remove_file(id, &path, version),
            };
            match result {
                Ok(()) => {
                    names.remove(work, id);
                    Step::Done
                }
                Err(e) => Step::Failed(e),
            }
        }
        (None, Some(want)) => {
            if !parent_ready(work, &want.parent) {
                return Step::Wait(Reason::Parent(want.parent));
            }
            if !names.free(work, &want.parent, &want.name, id) {
                return Step::Wait(Reason::Name(want.parent, want.name.clone()));
            }
            let Some(path) = full_path(work, &want.parent, &want.name) else {
                return Step::Wait(Reason::Again);
            };
            if let Some(nodes) = parked.roots.get(id).cloned() {
                return match disk.unpark(id, &path) {
                    Ok(()) => {
                        parked.roots.remove(id);
                        let mut nodes = nodes.into_iter();
                        let Some((_, mut placed)) = nodes.next() else {
                            return Step::Failed(ActionError::Blocked);
                        };
                        placed.parent = want.parent;
                        placed.name = want.name.clone();
                        names.insert(work, *id, placed);
                        for (member, node) in nodes {
                            parked.members.remove(&member);
                            names.insert(work, member, node);
                        }
                        // Content or metadata may still differ; the next pass handles it.
                        names.events.push(Event::Unparked);
                        if work.get(id) == Some(&want) {
                            Step::Done
                        } else {
                            Step::Wait(Reason::Again)
                        }
                    }
                    Err(e) => Step::Failed(e),
                };
            }
            let result = match &want.kind {
                NodeKind::Directory => disk.create_dir(&path),
                NodeKind::File(version) => disk.write_file(id, &path, version, None),
            };
            match result {
                Ok(()) => {
                    names.insert(work, *id, want);
                    Step::Done
                }
                Err(e) => Step::Failed(e),
            }
        }
        (Some(have), Some(want)) => {
            if have.location() != want.location() {
                if !parent_ready(work, &want.parent) {
                    return Step::Wait(Reason::Parent(want.parent));
                }
                if !names.free(work, &want.parent, &want.name, id) {
                    return Step::Wait(Reason::Name(want.parent, want.name.clone()));
                }
                if work.is_ancestor_or_self(id, &want.parent) {
                    return Step::Wait(Reason::Ancestor(want.parent));
                }
                let (Some(from), Some(to)) =
                    (work.path(id), full_path(work, &want.parent, &want.name))
                else {
                    return Step::Wait(Reason::Again);
                };
                if let Err(e) = disk.rename(&from, &to) {
                    return Step::Failed(e);
                }
                let mut moved = have.clone();
                moved.parent = want.parent;
                moved.name = want.name.clone();
                names.insert(work, *id, moved);
                return if work.get(id) == Some(&want) {
                    Step::Done
                } else {
                    Step::Wait(Reason::Again)
                };
            }
            match (&have.kind, &want.kind) {
                (NodeKind::File(h), NodeKind::File(w)) if h != w => {
                    let Some(path) = work.path(id) else {
                        return Step::Wait(Reason::Again);
                    };
                    let result = if h.same_content(w) {
                        disk.set_meta(id, &path, w, h)
                    } else {
                        disk.write_file(id, &path, w, Some(h))
                    };
                    match result {
                        Ok(()) => {
                            names.insert(work, *id, want);
                            Step::Done
                        }
                        Err(e) => Step::Failed(e),
                    }
                }
                (NodeKind::Directory, NodeKind::File(_))
                | (NodeKind::File(_), NodeKind::Directory) => {
                    // The merge never changes a kind under one ID.
                    Step::Failed(ActionError::Blocked)
                }
                _ => {
                    // Only the conflict link differs; nothing on disk.
                    names.insert(work, *id, want);
                    Step::Done
                }
            }
        }
    }
}

/// Parks one pending move whose target is taken by another pending item, to break a cycle.
fn park_one(
    pending: &BTreeSet<ItemId>,
    target: &Tree,
    work: &mut Tree,
    names: &mut Siblings,
    parked: &mut Parked,
    disk: &mut dyn DiskActions,
) -> bool {
    for id in pending {
        let (Some(have), Some(want)) = (work.get(id).cloned(), target.get(id)) else {
            continue;
        };
        if have.location() == want.location() || parked.roots.contains_key(id) {
            continue;
        }
        // An item whose target lies below itself would take its own new parent into the park.
        if work.contains(&want.parent) && work.is_ancestor_or_self(id, &want.parent) {
            continue;
        }
        // Parking helps only if the target parent exists or will: never for a parent the run
        // skips (a delayed delete), whose child would stay parked.
        let parent_reachable = want.parent == ROOT
            || work.contains(&want.parent)
            || pending.contains(&want.parent)
            || parked.roots.contains_key(&want.parent);
        if !parent_reachable {
            continue;
        }
        let blockers = names.colliding(work, &want.parent, &want.name, id);
        if !blockers.iter().all(|b| pending.contains(b)) {
            continue;
        }
        let Some(path) = work.path(id) else {
            continue;
        };
        if disk.park(id, &path).is_ok() {
            // A directory takes everything below it along.
            let subtree = work.subtree(id);
            let mut nodes = Vec::with_capacity(subtree.len());
            for member in subtree.iter().rev() {
                if let Some(node) = names.remove(work, member) {
                    nodes.push((*member, node));
                }
            }
            nodes.reverse();
            for (member, _) in nodes.iter().skip(1) {
                parked.members.insert(*member);
            }
            parked.roots.insert(*id, nodes);
            return true;
        }
    }
    false
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tree::tests::{file, id};
    use std::collections::BTreeMap;

    /// What a parked item took along: paths below it and their contents.
    pub(crate) type Parked = Vec<(Vec<String>, Option<FileVersion>)>;

    /// A disk of paths for the executor tests.
    #[derive(Default)]
    pub(crate) struct PathDisk {
        pub(crate) entries: BTreeMap<Vec<String>, Option<FileVersion>>,
        pub(crate) parked: BTreeMap<ItemId, Parked>,
        pub(crate) fail_writes: bool,
    }

    impl PathDisk {
        pub(crate) fn of(tree: &Tree) -> Self {
            let mut disk = Self::default();
            for (item, node) in tree.iter() {
                disk.entries
                    .insert(tree.path(item).unwrap(), node.kind.file().copied());
            }
            disk
        }

        fn taken(&self, path: &[String]) -> bool {
            let key = |p: &[String]| {
                p.iter()
                    .map(|n| hangar_drive_protocol::name::case_key(n))
                    .collect::<Vec<_>>()
            };
            self.entries.keys().any(|k| key(k) == key(path))
        }
    }

    impl DiskActions for PathDisk {
        fn create_dir(&mut self, path: &[String]) -> Result<(), ActionError> {
            if self.taken(path) {
                return Err(ActionError::Exists);
            }
            self.entries.insert(path.to_vec(), None);
            Ok(())
        }
        fn write_file(
            &mut self,
            _item: &ItemId,
            path: &[String],
            version: &FileVersion,
            expect: Option<&FileVersion>,
        ) -> Result<(), ActionError> {
            if self.fail_writes {
                return Err(ActionError::Unavailable);
            }
            match expect {
                None if self.taken(path) => return Err(ActionError::Exists),
                Some(e) if self.entries.get(path) != Some(&Some(*e)) => {
                    return Err(ActionError::Changed)
                }
                _ => {}
            }
            self.entries.insert(path.to_vec(), Some(*version));
            Ok(())
        }
        fn set_meta(
            &mut self,
            _item: &ItemId,
            path: &[String],
            version: &FileVersion,
            expect: &FileVersion,
        ) -> Result<(), ActionError> {
            self.write_file(&id(0), path, version, Some(expect))
        }
        fn rename(&mut self, from: &[String], to: &[String]) -> Result<(), ActionError> {
            if self.taken(to) {
                return Err(ActionError::Exists);
            }
            let moved: Vec<(Vec<String>, Option<FileVersion>)> = self
                .entries
                .iter()
                .filter(|(k, _)| k.starts_with(from))
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            for (k, v) in moved {
                self.entries.remove(&k);
                let mut nk = to.to_vec();
                nk.extend_from_slice(&k[from.len()..]);
                self.entries.insert(nk, v);
            }
            Ok(())
        }
        fn remove_file(
            &mut self,
            _item: &ItemId,
            path: &[String],
            expect: &FileVersion,
        ) -> Result<(), ActionError> {
            if self.entries.get(path) != Some(&Some(*expect)) {
                return Err(ActionError::Changed);
            }
            self.entries.remove(path);
            Ok(())
        }
        fn remove_dir(&mut self, path: &[String]) -> Result<(), ActionError> {
            if self
                .entries
                .keys()
                .any(|k| k.len() > path.len() && k.starts_with(path))
            {
                return Err(ActionError::Changed);
            }
            self.entries.remove(path);
            Ok(())
        }
        fn park(&mut self, item: &ItemId, path: &[String]) -> Result<(), ActionError> {
            let moved: Vec<(Vec<String>, Option<FileVersion>)> = self
                .entries
                .iter()
                .filter(|(k, _)| k.starts_with(path))
                .map(|(k, v)| (k[path.len()..].to_vec(), *v))
                .collect();
            if moved.is_empty() {
                return Err(ActionError::Changed);
            }
            self.entries.retain(|k, _| !k.starts_with(path));
            self.parked.insert(*item, moved);
            Ok(())
        }
        fn unpark(&mut self, item: &ItemId, path: &[String]) -> Result<(), ActionError> {
            let moved = self.parked.remove(item).ok_or(ActionError::Changed)?;
            for (rest, v) in moved {
                let mut k = path.to_vec();
                k.extend(rest);
                self.entries.insert(k, v);
            }
            Ok(())
        }
    }

    fn tree(nodes: &[(u8, u8, &str, Option<u8>)]) -> Tree {
        let mut t = Tree::new();
        for &(item, parent, name, f) in nodes {
            let parent = if parent == 0 { ROOT } else { id(parent) };
            let node = match f {
                Some(n) => Node::file(parent, name, file(n)),
                None => Node::dir(parent, name),
            };
            t.insert(id(item), node);
        }
        t
    }

    fn run(from: &Tree, to: &Tree) -> (PathDisk, Tree, ApplyReport) {
        let mut disk = PathDisk::of(from);
        let mut work = from.clone();
        let mut synced = from.clone();
        let report = apply(to, &mut work, &mut synced, &BTreeSet::new(), &mut disk);
        (disk, work, report)
    }

    #[test]
    fn creates_moves_and_deletes_in_a_working_order() {
        let from = tree(&[
            (1, 0, "a", None),
            (2, 1, "x", Some(2)),
            (3, 0, "old", Some(3)),
        ]);
        let to = tree(&[
            (4, 0, "new", None),
            (1, 4, "a", None),
            (2, 1, "y", Some(5)),
            (6, 4, "z", Some(6)),
        ]);
        let (disk, work, report) = run(&from, &to);
        assert!(report.failed.is_empty(), "{report:?}");
        assert_eq!(work, to);
        assert_eq!(disk, PathDisk::of(&to));
    }

    #[test]
    fn a_directory_moving_out_of_its_deleted_parent_onto_its_name() {
        // d/x (a directory with a file) moves to the root under the name "d", and d goes away.
        let from = tree(&[(1, 0, "d", None), (2, 1, "d", None), (3, 2, "f", Some(3))]);
        let to = tree(&[(2, 0, "d", None), (3, 2, "f", Some(3))]);
        let (disk, work, report) = run(&from, &to);
        assert!(report.failed.is_empty(), "{report:?}");
        assert_eq!(work, to);
        assert_eq!(disk, PathDisk::of(&to));
    }

    #[test]
    fn nothing_is_parked_for_a_skipped_parent_and_nothing_leaves_the_tree() {
        // d/f must move into the skipped p/ and a new file takes the name "d".
        let from = tree(&[(1, 0, "d", None), (2, 1, "f", Some(2))]);
        let to = tree(&[
            (9, 0, "p", None),
            (1, 9, "d", None),
            (2, 1, "f", Some(2)),
            (3, 0, "d", Some(3)),
        ]);
        let mut disk = PathDisk::of(&from);
        let mut work = from.clone();
        let mut synced = from.clone();
        let skip: BTreeSet<ItemId> = [id(9)].into();
        let report = apply(&to, &mut work, &mut synced, &skip, &mut disk);
        assert!(disk.parked.is_empty());
        assert!(work.contains(&id(1)) && work.contains(&id(2)), "{work:?}");
        assert_eq!(disk, PathDisk::of(&work));
        assert!(!report.failed.is_empty());
    }

    #[test]
    fn a_parent_and_its_child_swap_places_and_names() {
        // x/ holds y/; afterwards y/ is at the root under x's name and holds x/ as "inner".
        let from = tree(&[(1, 0, "x", None), (2, 1, "y", None), (3, 1, "f", Some(3))]);
        let to = tree(&[
            (2, 0, "x", None),
            (1, 2, "inner", None),
            (3, 1, "f", Some(3)),
        ]);
        let (disk, work, report) = run(&from, &to);
        assert!(report.failed.is_empty(), "{report:?}");
        assert_eq!(work, to);
        assert_eq!(disk, PathDisk::of(&to));
    }

    #[test]
    fn swaps_are_broken_by_parking() {
        let from = tree(&[(1, 0, "a", Some(1)), (2, 0, "b", Some(2))]);
        let to = tree(&[(1, 0, "b", Some(1)), (2, 0, "a", Some(2))]);
        let (disk, work, report) = run(&from, &to);
        assert!(report.failed.is_empty(), "{report:?}");
        assert_eq!(work, to);
        assert_eq!(disk, PathDisk::of(&to));
        assert!(disk.parked.is_empty());
    }

    #[test]
    fn a_changed_file_is_never_overwritten_or_deleted() {
        let from = tree(&[(1, 0, "a", Some(1)), (2, 0, "b", Some(2))]);
        let to = tree(&[(1, 0, "a", Some(9))]);
        let mut disk = PathDisk::of(&from);
        // The person edits both files after the scan.
        disk.entries.insert(vec!["a".into()], Some(file(7)));
        disk.entries.insert(vec!["b".into()], Some(file(8)));
        let mut work = from.clone();
        let mut synced = from.clone();
        let report = apply(&to, &mut work, &mut synced, &BTreeSet::new(), &mut disk);
        assert_eq!(report.failed.len(), 2);
        assert_eq!(work, from);
        assert_eq!(synced, from);
        assert_eq!(
            disk.entries.get(&vec!["a".to_string()]),
            Some(&Some(file(7)))
        );
    }

    #[test]
    fn failures_block_only_their_dependants() {
        let from = Tree::new();
        let to = tree(&[(1, 0, "d", None), (2, 1, "x", Some(2)), (3, 0, "y", None)]);
        let mut disk = PathDisk {
            fail_writes: true,
            ..PathDisk::default()
        };
        let mut work = from.clone();
        let mut synced = from.clone();
        let report = apply(&to, &mut work, &mut synced, &BTreeSet::new(), &mut disk);
        assert_eq!(report.failed, vec![(id(2), ActionError::Unavailable)]);
        assert!(work.contains(&id(1)) && work.contains(&id(3)));
    }

    #[test]
    fn exists_reports_names_the_tree_did_not_know() {
        let to = tree(&[(1, 0, "x", Some(1))]);
        let mut disk = PathDisk::default();
        disk.entries.insert(vec!["X".into()], Some(file(5)));
        let mut work = Tree::new();
        let mut synced = Tree::new();
        let report = apply(&to, &mut work, &mut synced, &BTreeSet::new(), &mut disk);
        assert_eq!(report.failed, vec![(id(1), ActionError::Exists)]);
    }

    /// The index answers what a pass over the directory answers, while entries are added,
    /// renamed, moved and removed through it (security review HIGH 2).
    #[test]
    fn sibling_index_equals_the_pass_over_the_directory() {
        use crate::names::tests::{Rng, PIECES};
        let mut rng = Rng(21);
        for case in 0..300 {
            let mut work = Tree::new();
            let mut names = Siblings::default();
            let dirs = [ROOT, id(1), id(2)];
            work.insert(id(1), Node::dir(ROOT, "d1"));
            work.insert(id(2), Node::dir(ROOT, "d2"));
            for _ in 0..60 {
                let item = id(3 + rng.below(20) as u8);
                let name: String = (0..1 + rng.below(3)).map(|_| *rng.pick(&PIECES)).collect();
                let parent = *rng.pick(&dirs);
                match rng.below(4) {
                    0 => {
                        names.remove(&mut work, &item);
                    }
                    _ => names.insert(&mut work, item, Node::file(parent, name, file(1))),
                }
                let probe: String = (0..1 + rng.below(3)).map(|_| *rng.pick(&PIECES)).collect();
                let except = id(3 + rng.below(20) as u8);
                let dir = *rng.pick(&dirs);
                assert_eq!(
                    names.colliding(&work, &dir, &probe, &except),
                    work.colliding_children(&dir, &probe, &except),
                    "case {case}, {probe:?}"
                );
            }
        }
    }

    /// A disk that takes every operation, for the work bound below.
    struct AcceptingDisk;

    impl DiskActions for AcceptingDisk {
        fn create_dir(&mut self, _: &[String]) -> Result<(), ActionError> {
            Ok(())
        }
        fn write_file(
            &mut self,
            _: &ItemId,
            _: &[String],
            _: &FileVersion,
            _: Option<&FileVersion>,
        ) -> Result<(), ActionError> {
            Ok(())
        }
        fn set_meta(
            &mut self,
            _: &ItemId,
            _: &[String],
            _: &FileVersion,
            _: &FileVersion,
        ) -> Result<(), ActionError> {
            Ok(())
        }
        fn rename(&mut self, _: &[String], _: &[String]) -> Result<(), ActionError> {
            Ok(())
        }
        fn remove_file(
            &mut self,
            _: &ItemId,
            _: &[String],
            _: &FileVersion,
        ) -> Result<(), ActionError> {
            Ok(())
        }
        fn remove_dir(&mut self, _: &[String]) -> Result<(), ActionError> {
            Ok(())
        }
        fn park(&mut self, _: &ItemId, _: &[String]) -> Result<(), ActionError> {
            Ok(())
        }
        fn unpark(&mut self, _: &ItemId, _: &[String]) -> Result<(), ActionError> {
            Ok(())
        }
    }

    /// Writing 20,000 new files into one directory computes a few keys per file, not one per
    /// file and sibling (security review HIGH 2).
    #[test]
    fn many_new_files_take_linear_work() {
        let n = 20_000u32;
        let wide = |i: u32| {
            let mut bytes = [7u8; 16];
            bytes[12..].copy_from_slice(&i.to_be_bytes());
            ItemId::from_bytes(bytes)
        };
        let target = Tree::from_nodes((0..n).map(|i| {
            (
                wide(i),
                Node::file(ROOT, format!("new-{i:06}.bin"), file(1)),
            )
        }));
        let mut work = Tree::new();
        let mut synced = Tree::new();
        let before = crate::names::tests::keys_computed();
        let report = apply(
            &target,
            &mut work,
            &mut synced,
            &BTreeSet::new(),
            &mut AcceptingDisk,
        );
        assert_eq!(report.done.len(), n as usize);
        assert_eq!(work, target);
        let work_done = crate::names::tests::keys_computed() - before;
        assert!(
            work_done <= 3 * u64::from(n),
            "{work_done} key computations"
        );
    }

    thread_local! {
        static STEPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    pub(super) fn count_step() {
        STEPS.with(|s| s.set(s.get() + 1));
    }

    fn steps_taken() -> u64 {
        STEPS.with(std::cell::Cell::get)
    }

    /// The earlier scheduling, kept as the reference: every pass tries every pending item, and
    /// a pass without progress parks one item.
    fn apply_reference(
        target: &Tree,
        work: &mut Tree,
        synced: &mut Tree,
        skip: &BTreeSet<ItemId>,
        disk: &mut dyn DiskActions,
    ) -> ApplyReport {
        let mut report = ApplyReport::default();
        let mut pending: BTreeSet<ItemId> = target
            .ids()
            .chain(work.ids())
            .filter(|id| !skip.contains(id) && work.get(id) != target.get(id))
            .copied()
            .collect();
        let equal: Vec<ItemId> = target
            .iter()
            .filter(|(id, node)| work.get(id) == Some(*node) && synced.get(id) != Some(*node))
            .map(|(id, _)| *id)
            .collect();
        for id in equal {
            if let Some(node) = target.get(&id) {
                synced.insert(id, node.clone());
            }
        }
        let mut parked = super::Parked::default();
        let mut names = Siblings::default();
        let limit = 4 * (pending.len() + 2);
        for _ in 0..limit {
            if pending.is_empty() {
                break;
            }
            let mut progress = false;
            names.events.clear();
            let snapshot: Vec<ItemId> = pending.iter().copied().collect();
            for id in snapshot {
                match step(&id, target, work, &mut names, &mut parked, disk) {
                    Step::Done => {
                        pending.remove(&id);
                        progress = true;
                        if let Some(node) = target.get(&id) {
                            if work.get(&id) == Some(node) {
                                synced.insert(id, node.clone());
                            }
                        } else {
                            synced.remove(&id);
                        }
                        report.done.push(id);
                    }
                    Step::Wait(_) => {}
                    Step::Failed(error) => {
                        pending.remove(&id);
                        progress = true;
                        report.failed.push((id, error));
                    }
                }
            }
            // One correction of the earlier passes: a move that leaves the content to the
            // next pass changed the working tree and counts as progress. Before, such a move
            // as the last pending operation ended the run with that item blocked until the
            // next round; the scheduling by events finishes it.
            progress |= !names.events.is_empty();
            if !progress && !park_one(&pending, target, work, &mut names, &mut parked, disk) {
                break;
            }
        }
        for id in pending {
            report.failed.push((id, ActionError::Blocked));
        }
        let roots: Vec<ItemId> = parked.roots.keys().copied().collect();
        for id in roots {
            let Some(mut nodes) = parked.roots.remove(&id) else {
                continue;
            };
            let Some((_, node)) = nodes.first().cloned() else {
                continue;
            };
            let mut placed = None;
            for candidate in fallback_places(work, &mut names, &node) {
                let Some(path) = full_path(work, &candidate.0, &candidate.1) else {
                    continue;
                };
                if disk.unpark(&id, &path).is_ok() {
                    placed = Some(candidate);
                    break;
                }
            }
            match placed {
                Some((parent, name)) => {
                    if let Some(first) = nodes.first_mut() {
                        first.1.parent = parent;
                        first.1.name = name;
                    }
                    for (member, n) in nodes {
                        parked.members.remove(&member);
                        names.insert(work, member, n);
                    }
                }
                None => report.parked.push(id),
            }
        }
        report
    }

    /// A random working tree: directories and files over a small pool of IDs and colliding
    /// names, parents from the pool, so the target below moves items into each other, swaps
    /// names, makes chains and cycles of renames and moves directories below themselves.
    fn random_tree(rng: &mut crate::names::tests::Rng, pool: &[ItemId], names: &[&str]) -> Tree {
        let mut t = Tree::new();
        let mut dirs = vec![ROOT];
        for item in pool {
            if rng.below(4) == 0 {
                continue;
            }
            let parent = *rng.pick(&dirs);
            let name = (*rng.pick(names)).to_owned();
            if t.colliding_children(&parent, &name, item).is_empty() {
                if rng.below(3) == 0 {
                    t.insert(*item, Node::dir(parent, name));
                    dirs.push(*item);
                } else {
                    t.insert(
                        *item,
                        Node::file(parent, name, file(1 + rng.below(3) as u8)),
                    );
                }
            }
        }
        t
    }

    /// The target: the same items with the same kinds, mostly at other places and names, some
    /// deleted, some new; a valid tree (no cycle, no collision), as the merge gives it.
    fn random_target(
        rng: &mut crate::names::tests::Rng,
        from: &Tree,
        pool: &[ItemId],
        names: &[&str],
    ) -> Tree {
        for _ in 0..50 {
            let mut t = Tree::new();
            let mut dirs = vec![ROOT];
            for item in pool {
                let kind = match from.get(item) {
                    Some(n) if rng.below(6) == 0 => {
                        let _ = n;
                        continue;
                    }
                    Some(n) => Some(n.is_dir()),
                    None if rng.below(3) == 0 => Some(rng.below(2) == 0),
                    None => None,
                };
                let Some(is_dir) = kind else {
                    continue;
                };
                let parent = *rng.pick(&dirs);
                let name = (*rng.pick(names)).to_owned();
                if !t.colliding_children(&parent, &name, item).is_empty() {
                    continue;
                }
                if is_dir {
                    t.insert(*item, Node::dir(parent, name));
                    dirs.push(*item);
                } else {
                    let version = match from.get(item).and_then(|n| n.kind.file()) {
                        Some(v) if rng.below(2) == 0 => *v,
                        _ => file(1 + rng.below(3) as u8),
                    };
                    t.insert(*item, Node::file(parent, name, version));
                }
            }
            // Every directory of the target that was a file in `from` breaks the kind rule.
            if t.check().is_ok() {
                return t;
            }
        }
        from.clone()
    }

    /// Security review of the executor, MEDIUM 1: the scheduling by events gives the result of
    /// the passes over all pending items, on random runs with chains, swaps, cycles, moves into
    /// the own subtree, deletes of directories that empty late and skipped items.
    #[test]
    fn event_scheduling_equals_the_passes() {
        let mut rng = crate::names::tests::Rng(0xa991);
        let names = ["a", "A", "b", "B", "c", "d", "e\u{301}", "\u{e9}"];
        for case in 0..3000 {
            let pool: Vec<ItemId> = (0..3 + rng.below(10))
                .map(|_| id(1 + rng.below(30) as u8))
                .collect::<BTreeSet<ItemId>>()
                .into_iter()
                .collect();
            let from = random_tree(&mut rng, &pool, &names);
            let to = random_target(&mut rng, &from, &pool, &names);
            let skip: BTreeSet<ItemId> = pool
                .iter()
                .filter(|_| rng.below(12) == 0)
                .copied()
                .collect();
            let run_with = |reference: bool| {
                let mut disk = PathDisk::of(&from);
                let mut work = from.clone();
                let mut synced = from.clone();
                let mut report = if reference {
                    apply_reference(&to, &mut work, &mut synced, &skip, &mut disk)
                } else {
                    apply(&to, &mut work, &mut synced, &skip, &mut disk)
                };
                report.done.sort();
                report.failed.sort_by_key(|(id, _)| *id);
                report.parked.sort();
                (disk, work, synced, report)
            };
            let (new_disk, new_work, new_synced, new_report) = run_with(false);
            let (old_disk, old_work, old_synced, old_report) = run_with(true);
            assert_eq!(new_work, old_work, "case {case}: work");
            assert_eq!(new_synced, old_synced, "case {case}: synced");
            assert_eq!(new_disk, old_disk, "case {case}: disk");
            assert_eq!(new_report, old_report, "case {case}: report");
        }
    }

    /// A chain of 20,000 renames in one directory, each item onto the name of the next one and
    /// the last onto a free name: about two steps per item. The passes took one step per item
    /// and pass, and the chain freed one name per pass (about 2 * 10^8 steps here).
    #[test]
    fn a_chain_of_renames_takes_linear_steps() {
        let n = 20_000u32;
        let wide = |i: u32| {
            let mut bytes = [5u8; 16];
            bytes[12..].copy_from_slice(&i.to_be_bytes());
            ItemId::from_bytes(bytes)
        };
        let from = Tree::from_nodes(
            (0..n).map(|i| (wide(i), Node::file(ROOT, format!("f{i:06}"), file(1)))),
        );
        let to = Tree::from_nodes(
            (0..n).map(|i| (wide(i), Node::file(ROOT, format!("f{:06}", i + 1), file(1)))),
        );
        let mut work = from.clone();
        let mut synced = from.clone();
        let before = steps_taken();
        let report = apply(
            &to,
            &mut work,
            &mut synced,
            &BTreeSet::new(),
            &mut AcceptingDisk,
        );
        let steps = steps_taken() - before;
        assert_eq!(report.done.len(), n as usize, "{:?}", report.failed.first());
        assert_eq!(work, to);
        assert!(steps <= 3 * u64::from(n), "{steps} steps");
    }

    impl PartialEq for PathDisk {
        fn eq(&self, other: &Self) -> bool {
            self.entries == other.entries
        }
    }

    impl std::fmt::Debug for PathDisk {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.entries)
        }
    }
}
