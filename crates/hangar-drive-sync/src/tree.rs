//! The tree model of the sync core (ADR 0001, section 3, after Dropbox Nucleus).
//!
//! A folder has three trees of the same shape:
//!
//! - **remote:** the tree of the verified server head (the frontier);
//! - **local:** what the disk holds, from the scan and the local index;
//! - **synced:** per item the last state both sides agreed on, the merge base.
//!
//! Items are keyed by their stable [`ItemId`]; a node names its parent's item ID and its own
//! name, so a move or a rename changes one node and never looks like a delete plus an add. The
//! root of a folder is the reserved [`ROOT`] ID and is not a node.
//!
//! A tree records which items changed since the last [`Tree::take_delta`], so the local index
//! persists only those rows instead of the whole tree after every step.

use std::collections::{BTreeMap, BTreeSet};

use hangar_drive_protocol::ids::{ItemId, ObjectId};
use hangar_drive_protocol::name::{comparison_key, CaseKeys};
use sha2::{Digest, Sha256};

/// The parent of every top level item. No node has this ID; a tree from the server that holds it
/// is refused ([`Tree::check`]).
pub const ROOT: ItemId = ItemId::from_bytes([0; 16]);

const CONTENT_LABEL: &[u8] = b"hangar-drive/v1/sync-content-key";

/// Identifies a file's content: SHA-256 over its chunk IDs in order. Equal keys mean equal chunk
/// lists under the same generation; the engine compares contents only through this key, so the
/// core never sees file bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentKey(pub [u8; 32]);

impl ContentKey {
    /// The key of a chunk ID list.
    pub fn of_chunks(chunks: &[ObjectId]) -> Self {
        let mut hash = Sha256::new();
        hash.update((CONTENT_LABEL.len() as u64).to_be_bytes());
        hash.update(CONTENT_LABEL);
        hash.update((chunks.len() as u64).to_be_bytes());
        for chunk in chunks {
            hash.update(chunk.as_bytes());
        }
        Self(hash.finalize().into())
    }
}

impl std::fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ContentKey({:02x}{:02x}{:02x}{:02x})",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// One version of a file: what a directory entry and its manifest say about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileVersion {
    /// Bytes.
    pub size: u64,
    /// Modification time, milliseconds since the Unix epoch.
    pub mtime_ms: i64,
    /// The execute flag (bit 0 of the entry flags).
    pub executable: bool,
    /// The content.
    pub content: ContentKey,
}

impl FileVersion {
    /// Same content (size follows content).
    pub fn same_content(&self, other: &FileVersion) -> bool {
        self.content == other.content && self.size == other.size
    }
}

/// File or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A directory, also an empty one.
    Directory,
    /// A regular file.
    File(FileVersion),
}

impl NodeKind {
    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        matches!(self, NodeKind::Directory)
    }

    /// The file version, if this is a file.
    pub fn file(&self) -> Option<&FileVersion> {
        match self {
            NodeKind::File(version) => Some(version),
            NodeKind::Directory => None,
        }
    }
}

/// One item of a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The parent directory's item ID, or [`ROOT`].
    pub parent: ItemId,
    /// The exact name from disk (or from the tree).
    pub name: String,
    /// File or directory.
    pub kind: NodeKind,
    /// For a conflict copy: the item that kept the name (ADR 0001, section 3, `conflict_of`).
    pub conflict_of: Option<ItemId>,
}

impl Node {
    /// A directory node.
    pub fn dir(parent: ItemId, name: impl Into<String>) -> Self {
        Self {
            parent,
            name: name.into(),
            kind: NodeKind::Directory,
            conflict_of: None,
        }
    }

    /// A file node.
    pub fn file(parent: ItemId, name: impl Into<String>, version: FileVersion) -> Self {
        Self {
            parent,
            name: name.into(),
            kind: NodeKind::File(version),
            conflict_of: None,
        }
    }

    /// The comparison key of the name (NFC).
    pub fn key(&self) -> String {
        comparison_key(&self.name)
    }

    /// Parent and name.
    pub fn location(&self) -> (ItemId, &str) {
        (self.parent, self.name.as_str())
    }

    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.kind.is_dir()
    }
}

/// Why a tree is not a valid folder tree.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TreeError {
    /// A node uses the reserved root ID.
    #[error("a node uses the reserved root id")]
    RootId,
    /// A node's parent is missing or is a file.
    #[error("a node's parent is not a directory of the tree")]
    Parent,
    /// The parent links form a cycle.
    #[error("the parent links form a cycle")]
    Cycle,
    /// Two entries of one directory share a comparison key.
    #[error("two entries of a directory share a comparison key")]
    DuplicateName,
}

/// Item IDs whose rows changed since the last [`Tree::take_delta`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeDelta {
    /// Items added or changed, with their node.
    pub upsert: Vec<(ItemId, Node)>,
    /// Items removed.
    pub remove: Vec<ItemId>,
}

impl TreeDelta {
    /// Whether nothing changed.
    pub fn is_empty(&self) -> bool {
        self.upsert.is_empty() && self.remove.is_empty()
    }
}

/// A folder tree keyed by item ID.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    nodes: BTreeMap<ItemId, Node>,
    children: BTreeMap<ItemId, BTreeSet<ItemId>>,
    dirty: BTreeSet<ItemId>,
}

impl PartialEq for Tree {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
    }
}

impl Eq for Tree {}

impl Tree {
    /// The empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// A tree of these nodes; nothing is dirty.
    pub fn from_nodes(nodes: impl IntoIterator<Item = (ItemId, Node)>) -> Self {
        let mut tree = Self::new();
        for (id, node) in nodes {
            tree.insert(id, node);
        }
        tree.dirty.clear();
        tree
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree has no items.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The node of `id`.
    pub fn get(&self, id: &ItemId) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// Whether `id` is an item.
    pub fn contains(&self, id: &ItemId) -> bool {
        self.nodes.contains_key(id)
    }

    /// Every item in ID order.
    pub fn iter(&self) -> impl Iterator<Item = (&ItemId, &Node)> {
        self.nodes.iter()
    }

    /// Every item ID in order.
    pub fn ids(&self) -> impl Iterator<Item = &ItemId> {
        self.nodes.keys()
    }

    /// The children of `parent` ([`ROOT`] for the top level).
    pub fn children(&self, parent: &ItemId) -> impl Iterator<Item = &ItemId> {
        self.children.get(parent).into_iter().flatten()
    }

    /// Inserts or replaces a node.
    pub fn insert(&mut self, id: ItemId, node: Node) {
        if let Some(old) = self.nodes.get(&id) {
            let old_parent = old.parent;
            if old_parent != node.parent {
                self.unlink(&old_parent, &id);
            }
        }
        self.children.entry(node.parent).or_default().insert(id);
        self.nodes.insert(id, node);
        self.dirty.insert(id);
    }

    /// Removes a node (not its children) and returns it.
    pub fn remove(&mut self, id: &ItemId) -> Option<Node> {
        let node = self.nodes.remove(id)?;
        self.unlink(&node.parent, id);
        self.dirty.insert(*id);
        Some(node)
    }

    fn unlink(&mut self, parent: &ItemId, id: &ItemId) {
        if let Some(set) = self.children.get_mut(parent) {
            set.remove(id);
            if set.is_empty() {
                self.children.remove(parent);
            }
        }
    }

    /// The child of `parent` whose comparison key is `key`.
    pub fn child_by_key(&self, parent: &ItemId, key: &str) -> Option<ItemId> {
        self.children(parent)
            .find(|id| self.nodes.get(id).is_some_and(|n| n.key() == key))
            .copied()
    }

    /// The children of `parent` that collide with `name` by comparison key or case (ADR 0001,
    /// section 7), `except` left out.
    pub fn colliding_children(&self, parent: &ItemId, name: &str, except: &ItemId) -> Vec<ItemId> {
        let key = comparison_key(name);
        let keys = CaseKeys::of(&key);
        self.children(parent)
            .filter(|id| *id != except)
            .filter(|id| {
                self.nodes
                    .get(id)
                    .is_some_and(|n| n.key() == key || CaseKeys::of(&n.key()).collides(&keys))
            })
            .copied()
            .collect()
    }

    /// The names from the root to `id`; `None` for an item not in the tree or a broken chain.
    pub fn path(&self, id: &ItemId) -> Option<Vec<String>> {
        let mut names = Vec::new();
        let mut at = *id;
        let mut steps = 0usize;
        while at != ROOT {
            let node = self.nodes.get(&at)?;
            names.push(node.name.clone());
            at = node.parent;
            steps += 1;
            if steps > self.nodes.len() {
                return None;
            }
        }
        names.reverse();
        Some(names)
    }

    /// The path as a "/" separated string, for display and logs.
    pub fn path_string(&self, id: &ItemId) -> Option<String> {
        self.path(id).map(|p| p.join("/"))
    }

    /// The item at a path of names, matched by comparison key.
    pub fn lookup(&self, path: &[String]) -> Option<ItemId> {
        let mut at = ROOT;
        for name in path {
            at = self.child_by_key(&at, &comparison_key(name))?;
        }
        (at != ROOT).then_some(at)
    }

    /// The item at a path of exact names (byte for byte), falling back to the comparison key
    /// per step only where no exact name matches.
    pub fn lookup_exact(&self, path: &[String]) -> Option<ItemId> {
        let mut at = ROOT;
        for name in path {
            let exact = self
                .children(&at)
                .find(|id| self.nodes.get(id).is_some_and(|n| n.name == *name))
                .copied();
            at = match exact {
                Some(id) => id,
                None => self.child_by_key(&at, &comparison_key(name))?,
            };
        }
        (at != ROOT).then_some(at)
    }

    /// Whether `ancestor` is `id` or one of its ancestors.
    pub fn is_ancestor_or_self(&self, ancestor: &ItemId, id: &ItemId) -> bool {
        let mut at = *id;
        let mut steps = 0usize;
        loop {
            if at == *ancestor {
                return true;
            }
            if at == ROOT {
                return false;
            }
            match self.nodes.get(&at) {
                Some(node) => at = node.parent,
                None => return false,
            }
            steps += 1;
            if steps > self.nodes.len() + 1 {
                return false;
            }
        }
    }

    /// `id` and every item below it, parents before children.
    pub fn subtree(&self, id: &ItemId) -> Vec<ItemId> {
        let mut out = Vec::new();
        let mut stack = vec![*id];
        let mut seen = BTreeSet::new();
        while let Some(at) = stack.pop() {
            if !seen.insert(at) {
                continue;
            }
            if at != ROOT {
                out.push(at);
            }
            let mut kids: Vec<ItemId> = self.children(&at).copied().collect();
            kids.reverse();
            stack.extend(kids);
        }
        out
    }

    /// Depth of `id` (1 for a top level item); 0 for a broken chain.
    pub fn depth(&self, id: &ItemId) -> usize {
        self.path(id).map_or(0, |p| p.len())
    }

    /// Checks that this is a valid folder tree: no root ID as a node, parents are directories,
    /// no cycles, no two entries of a directory with one comparison key.
    pub fn check(&self) -> Result<(), TreeError> {
        if self.nodes.contains_key(&ROOT) {
            return Err(TreeError::RootId);
        }
        for node in self.nodes.values() {
            if node.parent != ROOT && !self.nodes.get(&node.parent).is_some_and(Node::is_dir) {
                return Err(TreeError::Parent);
            }
        }
        for id in self.nodes.keys() {
            if self.path(id).is_none() {
                return Err(TreeError::Cycle);
            }
        }
        for (parent, kids) in &self.children {
            let _ = parent;
            let mut keys = BTreeSet::new();
            for kid in kids {
                if let Some(node) = self.nodes.get(kid) {
                    if !keys.insert(node.key()) {
                        return Err(TreeError::DuplicateName);
                    }
                }
            }
        }
        Ok(())
    }

    /// The rows changed since the last call; clears the record.
    pub fn take_delta(&mut self) -> TreeDelta {
        let mut delta = TreeDelta::default();
        for id in std::mem::take(&mut self.dirty) {
            match self.nodes.get(&id) {
                Some(node) => delta.upsert.push((id, node.clone())),
                None => delta.remove.push(id),
            }
        }
        delta
    }

    /// Forgets the record of changed rows (after loading from storage).
    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
    }

    /// Moves item `from` to the ID `to`: the node keeps its place and its children follow.
    /// Nothing happens if `from` is missing or `to` exists.
    pub fn rekey(&mut self, from: &ItemId, to: ItemId) {
        if self.nodes.contains_key(&to) {
            return;
        }
        let Some(node) = self.remove(from) else {
            return;
        };
        let kids: Vec<ItemId> = self.children(from).copied().collect();
        self.insert(to, node);
        for kid in kids {
            if let Some(mut child) = self.nodes.get(&kid).cloned() {
                child.parent = to;
                self.insert(kid, child);
            }
        }
    }

    /// Counts files and directories.
    pub fn count_files(&self) -> usize {
        self.nodes.values().filter(|n| !n.is_dir()).count()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn id(n: u8) -> ItemId {
        ItemId::from_bytes([n; 16])
    }

    pub(crate) fn content(n: u8) -> ContentKey {
        ContentKey([n; 32])
    }

    pub(crate) fn file(n: u8) -> FileVersion {
        FileVersion {
            size: u64::from(n),
            mtime_ms: i64::from(n) * 1000,
            executable: false,
            content: content(n),
        }
    }

    #[test]
    fn paths_lookup_and_subtrees() {
        let mut t = Tree::new();
        t.insert(id(1), Node::dir(ROOT, "docs"));
        t.insert(id(2), Node::file(id(1), "a.txt", file(2)));
        t.insert(id(3), Node::dir(id(1), "sub"));
        t.insert(id(4), Node::file(id(3), "b", file(4)));
        assert_eq!(t.path_string(&id(4)).unwrap(), "docs/sub/b");
        assert_eq!(t.lookup(&["docs".into(), "A.txt".into()]), None);
        assert_eq!(t.lookup(&["docs".into(), "a.txt".into()]), Some(id(2)));
        assert_eq!(t.subtree(&id(1)), vec![id(1), id(2), id(3), id(4)]);
        assert!(t.is_ancestor_or_self(&id(1), &id(4)));
        assert!(!t.is_ancestor_or_self(&id(4), &id(1)));
        assert_eq!(t.check(), Ok(()));
    }

    #[test]
    fn moves_relink_children_and_deltas_record_rows() {
        let mut t = Tree::new();
        t.insert(id(1), Node::dir(ROOT, "a"));
        t.insert(id(2), Node::dir(ROOT, "b"));
        t.insert(id(3), Node::file(id(1), "x", file(3)));
        t.take_delta();
        let mut moved = t.get(&id(3)).unwrap().clone();
        moved.parent = id(2);
        t.insert(id(3), moved);
        assert_eq!(t.children(&id(1)).count(), 0);
        assert_eq!(t.children(&id(2)).copied().collect::<Vec<_>>(), vec![id(3)]);
        let delta = t.take_delta();
        assert_eq!(delta.upsert.len(), 1);
        t.remove(&id(3));
        assert_eq!(t.take_delta().remove, vec![id(3)]);
    }

    #[test]
    fn check_refuses_broken_trees() {
        let mut t = Tree::new();
        t.insert(id(1), Node::file(id(9), "x", file(1)));
        assert_eq!(t.check(), Err(TreeError::Parent));
        let mut t = Tree::new();
        t.insert(id(1), Node::dir(id(2), "a"));
        t.insert(id(2), Node::dir(id(1), "b"));
        assert_eq!(t.check(), Err(TreeError::Cycle));
        let mut t = Tree::new();
        t.insert(id(1), Node::dir(ROOT, "e\u{301}"));
        t.insert(id(2), Node::dir(ROOT, "\u{e9}"));
        assert_eq!(t.check(), Err(TreeError::DuplicateName));
        let mut t = Tree::new();
        t.insert(ROOT, Node::dir(ROOT, "r"));
        assert_eq!(t.check(), Err(TreeError::RootId));
    }

    #[test]
    fn rekey_keeps_place_and_children() {
        let mut t = Tree::new();
        t.insert(id(1), Node::dir(ROOT, "a"));
        t.insert(id(2), Node::file(id(1), "x", file(2)));
        t.rekey(&id(1), id(7));
        assert!(!t.contains(&id(1)));
        assert_eq!(t.get(&id(2)).unwrap().parent, id(7));
        assert_eq!(t.path_string(&id(2)).unwrap(), "a/x");
    }

    #[test]
    fn collisions_by_case_and_normalization() {
        let mut t = Tree::new();
        t.insert(id(1), Node::file(ROOT, "Report.txt", file(1)));
        assert_eq!(
            t.colliding_children(&ROOT, "report.TXT", &id(9)),
            vec![id(1)]
        );
        assert!(t.colliding_children(&ROOT, "Report.txt", &id(1)).is_empty());
        assert!(t.colliding_children(&ROOT, "other", &id(9)).is_empty());
    }
}
