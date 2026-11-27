//! Trees to encrypted objects and back: directory nodes and file manifests of
//! `hangar-drive-protocol::format`, sealed and opened through `hangar-drive-crypto::object`.
//!
//! **Encoding** builds the directory nodes bottom-up. The ID of every node and manifest is the
//! keyed hash of its plaintext; an object cache maps the SHA-256 of a plaintext to the ID of an
//! object the server is known to hold (uploaded or downloaded by this device), so an unchanged
//! subtree keeps its IDs across commits and key generations and only the new nodes on the path
//! to the root are sealed and uploaded.
//!
//! **Decoding** opens the server's objects from the root down, checks every format rule, the
//! keyed ID of every object, that no item ID appears twice and that the tree is valid, and
//! records the chunk list of every file under its content key.
//!
//! **Limits** (security review M3): a tree is a server's input, so decoding stops at
//! [`MAX_TREE_DEPTH`] levels and [`MAX_TREE_ITEMS`] items, before more objects are fetched,
//! and [`reachable`] lists a tree's objects without building it, up to
//! [`MAX_REACHABLE_OBJECTS`], for the commit that replaces a tree beyond the limits.

use std::collections::{BTreeMap, BTreeSet};

use hangar_drive_crypto::folder_keys::FolderKeyRing;
use hangar_drive_crypto::object::{object_header, ObjectError, ObjectKeys};
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::format::{DirectoryEntry, DirectoryNode, FileManifest, FormatError};
use hangar_drive_protocol::ids::{AccountId, FolderId, Generation, ItemId, ObjectId};
use hangar_drive_protocol::object::{EntryFlags, EntryKind, ObjectType};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::chunker::DynEntropy;
use crate::ports::{ChunkList, NetError, ServerApi, Store, StoreError};
use crate::tree::{ContentKey, FileVersion, Node, NodeKind, Tree, TreeError, ROOT};

/// The deepest tree a device decodes (security review M3): 512 levels. A path of 512 names
/// needs at least 1024 bytes (one character and one separator per level), which is macOS's
/// `PATH_MAX`, so no deeper tree can exist on every platform of version 1; Linux allows 4096
/// bytes and Windows with `\\?\` paths 32,767 UTF-16 units, but a tree a macOS device cannot
/// create is not worth decoding. 512 levels also keep every walk from an item to the root short.
pub const MAX_TREE_DEPTH: usize = 512;

/// The most items (files and directories) a decoded tree may hold (security review M3): 2^20.
/// A device holds three trees per folder in memory, a few hundred bytes per item, so this keeps
/// one folder below about a gigabyte; it is more than three times the 300,000 files OneDrive and
/// Dropbox name as the size up to which their clients stay fast [UNVERIFIED].
pub const MAX_TREE_ITEMS: usize = 1 << 20;

/// The most objects [`reachable`] lists for one tree: eight per item of a tree at
/// [`MAX_TREE_ITEMS`] (its node or manifest and the chunks of its files), more than any quota
/// of version 1 holds in 4 MiB chunks next to a full tree.
pub const MAX_REACHABLE_OBJECTS: usize = 8 * MAX_TREE_ITEMS;

/// Why a tree was not encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// The local index failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The server failed.
    #[error(transparent)]
    Net(#[from] NetError),
    /// An object did not seal or open.
    #[error(transparent)]
    Object(#[from] ObjectError),
    /// A plaintext breaks the format.
    #[error(transparent)]
    Format(#[from] FormatError),
    /// The decoded tree is not valid.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// The chunk list of a file is unknown (it was never hashed or downloaded).
    #[error("the chunk list of a file is unknown")]
    UnknownContent,
    /// An item ID appears twice, or a manifest disagrees with its entry.
    #[error("the server's tree is inconsistent")]
    Inconsistent,
    /// The server's tree is deeper than [`MAX_TREE_DEPTH`] or holds more than
    /// [`MAX_TREE_ITEMS`] items, or more objects than [`MAX_REACHABLE_OBJECTS`] (M3).
    #[error("the server's tree is beyond the limits of a folder")]
    Limit,
}

/// The object keys of every generation of a folder's ring, and the generation new objects use.
pub struct FolderCrypto {
    folder: FolderId,
    keys: BTreeMap<u32, ObjectKeys>,
    writable: Generation,
}

impl std::fmt::Debug for FolderCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderCrypto")
            .field("folder", &self.folder)
            .field("writable", &self.writable)
            .finish_non_exhaustive()
    }
}

impl FolderCrypto {
    /// The keys of `ring`; new objects use `writable` (from
    /// `hangar_drive_crypto::folder_keys::writable_generation`).
    pub fn new(
        account: &AccountId,
        ring: &FolderKeyRing,
        writable: Generation,
    ) -> Result<Self, ObjectError> {
        let mut keys = BTreeMap::new();
        for g in 1..=ring.newest_generation().0 {
            keys.insert(g, ObjectKeys::from_ring(account, ring, Generation(g))?);
        }
        if !keys.contains_key(&writable.0) {
            return Err(ObjectError::UnknownGeneration(writable.0));
        }
        Ok(Self {
            folder: *ring.folder(),
            keys,
            writable,
        })
    }

    /// The folder.
    pub fn folder(&self) -> &FolderId {
        &self.folder
    }

    /// The generation new objects use.
    pub fn writable_generation(&self) -> Generation {
        self.writable
    }

    /// The keys new objects use.
    pub fn writable(&self) -> Result<&ObjectKeys, ObjectError> {
        self.keys
            .get(&self.writable.0)
            .ok_or(ObjectError::UnknownGeneration(self.writable.0))
    }

    /// The keys of `generation`.
    pub fn keys(&self, generation: Generation) -> Result<&ObjectKeys, ObjectError> {
        self.keys
            .get(&generation.0)
            .ok_or(ObjectError::UnknownGeneration(generation.0))
    }

    /// Every generation's keys, for the hashing workers.
    pub fn all_keys(&self) -> &BTreeMap<u32, ObjectKeys> {
        &self.keys
    }

    /// Opens a blob referenced as `expected` of type `kind` with the keys of the generation in
    /// its header.
    pub fn open(
        &self,
        expected: &ObjectId,
        kind: ObjectType,
        blob: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ObjectError> {
        let (generation, _) = object_header(blob).ok_or(ObjectError::Malformed)?;
        self.keys(generation)?.open(expected, kind, blob)
    }
}

/// The cache key of a plaintext: SHA-256 over the type byte and the plaintext.
pub fn plaintext_digest(kind: ObjectType, plaintext: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([kind.to_byte()]);
    hash.update(plaintext);
    hash.finalize().into()
}

/// An encoded tree.
#[derive(Debug, Clone)]
pub struct Encoded {
    /// The root directory node.
    pub root: ObjectId,
    /// Nodes and manifests sealed now: not known to be on the server.
    pub sealed: BTreeMap<ObjectId, Vec<u8>>,
    /// Plaintext digests of the sealed objects, to cache once they are uploaded.
    pub digests: BTreeMap<ObjectId, [u8; 32]>,
    /// Every object reachable from the root: nodes, manifests and chunks.
    pub reachable: BTreeSet<ObjectId>,
    /// Chunks per content of the tree's files.
    pub chunks: BTreeMap<ContentKey, Vec<ObjectId>>,
}

/// Encodes `tree` (module docs). Chunk lists come from the store.
pub fn encode(
    tree: &Tree,
    crypto: &FolderCrypto,
    store: &dyn Store,
    entropy: &mut dyn Entropy,
) -> Result<Encoded, CodecError> {
    encode_with(tree, crypto, store, entropy, false)
}

/// Encodes `tree` with every directory node and manifest sealed now, also those the store knows
/// as uploaded, so all of them are in [`Encoded::sealed`] and can be uploaded again. A full
/// reference delta that repairs the server's live set needs this: the collection may have
/// deleted objects that the store still lists as on the server (ADR 0001, amendment
/// "reference deltas bound to the tree"). Objects sealed under the writable generation get the
/// same IDs again; others get new ones, which only renames them.
pub fn encode_fresh(
    tree: &Tree,
    crypto: &FolderCrypto,
    store: &dyn Store,
    entropy: &mut dyn Entropy,
) -> Result<Encoded, CodecError> {
    encode_with(tree, crypto, store, entropy, true)
}

fn encode_with(
    tree: &Tree,
    crypto: &FolderCrypto,
    store: &dyn Store,
    entropy: &mut dyn Entropy,
    fresh: bool,
) -> Result<Encoded, CodecError> {
    let mut out = Encoded {
        root: ObjectId::from_bytes([0; 32]),
        sealed: BTreeMap::new(),
        digests: BTreeMap::new(),
        reachable: BTreeSet::new(),
        chunks: BTreeMap::new(),
    };
    let folder = *crypto.folder();
    let mut ids: BTreeMap<ItemId, ObjectId> = BTreeMap::new();
    // Children before their parents, so every child ID is known when its parent is encoded:
    // the breadth-first order reversed, O(n) (security review M3; the depth of every directory
    // was O(n x depth)).
    let mut order = tree.dirs_top_down();
    order.reverse();
    order.push(ROOT);
    for dir in order {
        let mut entries = Vec::new();
        for child in tree.children(&dir) {
            let node = tree.get(child).ok_or(CodecError::Inconsistent)?;
            let entry = match &node.kind {
                NodeKind::Directory => DirectoryEntry {
                    name: node.name.clone(),
                    item: *child,
                    kind: EntryKind::Directory,
                    child: *ids.get(child).ok_or(CodecError::Inconsistent)?,
                    size: 0,
                    mtime_ms: 0,
                    flags: EntryFlags::NONE,
                    conflict_of: node.conflict_of,
                },
                NodeKind::File(v) => {
                    let manifest =
                        encode_manifest(v, crypto, store, &folder, entropy, fresh, &mut out)?;
                    DirectoryEntry {
                        name: node.name.clone(),
                        item: *child,
                        kind: EntryKind::File,
                        child: manifest,
                        size: v.size,
                        mtime_ms: v.mtime_ms,
                        flags: EntryFlags::executable(v.executable),
                        conflict_of: node.conflict_of,
                    }
                }
            };
            entries.push(entry);
        }
        let plaintext = DirectoryNode::new(entries)?.encode()?;
        let id = put_object(
            ObjectType::DirectoryNode,
            &plaintext,
            crypto,
            store,
            &folder,
            entropy,
            fresh,
            &mut out,
        )?;
        if dir == ROOT {
            out.root = id;
        } else {
            ids.insert(dir, id);
        }
    }
    Ok(out)
}

fn encode_manifest(
    v: &FileVersion,
    crypto: &FolderCrypto,
    store: &dyn Store,
    folder: &FolderId,
    entropy: &mut dyn Entropy,
    fresh: bool,
    out: &mut Encoded,
) -> Result<ObjectId, CodecError> {
    let chunks = match out.chunks.get(&v.content) {
        Some(c) => c.clone(),
        None => {
            let list = store
                .chunk_list(folder, &v.content)?
                .ok_or(CodecError::UnknownContent)?;
            out.chunks.insert(v.content, list.chunks.clone());
            list.chunks
        }
    };
    out.reachable.extend(chunks.iter().copied());
    let manifest = FileManifest::new(
        v.size,
        v.mtime_ms,
        EntryFlags::executable(v.executable),
        chunks,
    )?;
    let plaintext = manifest.encode()?;
    put_object(
        ObjectType::FileManifest,
        &plaintext,
        crypto,
        store,
        folder,
        entropy,
        fresh,
        out,
    )
}

#[allow(clippy::too_many_arguments)]
fn put_object(
    kind: ObjectType,
    plaintext: &[u8],
    crypto: &FolderCrypto,
    store: &dyn Store,
    folder: &FolderId,
    entropy: &mut dyn Entropy,
    fresh: bool,
    out: &mut Encoded,
) -> Result<ObjectId, CodecError> {
    let digest = plaintext_digest(kind, plaintext);
    let known = if fresh {
        None
    } else {
        store.object_for(folder, &digest)?
    };
    let id = match known {
        Some(id) => id,
        None => {
            let sealed = crypto
                .writable()?
                .seal(kind, plaintext, &mut DynEntropy(entropy))?;
            out.digests.insert(sealed.id, digest);
            out.sealed.insert(sealed.id, sealed.blob);
            sealed.id
        }
    };
    out.reachable.insert(id);
    Ok(id)
}

/// Fetches an object's plaintext: from the cache, or from the server, opened and checked.
fn fetch_plaintext(
    id: &ObjectId,
    kind: ObjectType,
    crypto: &FolderCrypto,
    store: &mut dyn Store,
    server: &mut dyn ServerApi,
) -> Result<(Vec<u8>, Option<Generation>), CodecError> {
    let folder = *crypto.folder();
    if let Some(plain) = store.plaintext(&folder, id)? {
        return Ok((plain, None));
    }
    let blob = server.get_object(&folder, id)?;
    let generation = object_header(&blob).map(|(g, _)| g);
    let plain = crypto.open(id, kind, &blob)?;
    store.put_plaintext(&folder, id, &plain)?;
    store.put_object_for(&folder, &plaintext_digest(kind, &plain), id)?;
    Ok((plain.to_vec(), generation))
}

/// Decodes the tree under `root` (module docs).
pub fn decode(
    root: &ObjectId,
    crypto: &FolderCrypto,
    store: &mut dyn Store,
    server: &mut dyn ServerApi,
) -> Result<Tree, CodecError> {
    let folder = *crypto.folder();
    let mut tree = Tree::new();
    // Each directory node with the depth of its entries: the root's entries are at depth 1.
    let mut stack = vec![(ROOT, *root, 1usize)];
    let mut seen_nodes = BTreeSet::new();
    while let Some((dir, node_id, depth)) = stack.pop() {
        if !seen_nodes.insert((dir, node_id)) {
            return Err(CodecError::Inconsistent);
        }
        let (plain, _) =
            fetch_plaintext(&node_id, ObjectType::DirectoryNode, crypto, store, server)?;
        let node = DirectoryNode::decode(&plain)?;
        // The limits are checked before the entries' objects are fetched (M3), so a tree beyond
        // them costs at most one level or one node's entries more.
        if tree.len().saturating_add(node.entries().len()) > MAX_TREE_ITEMS
            || (depth > MAX_TREE_DEPTH && !node.entries().is_empty())
        {
            return Err(CodecError::Limit);
        }
        for entry in node.entries() {
            if entry.item == ROOT || tree.contains(&entry.item) {
                return Err(CodecError::Inconsistent);
            }
            let kind = match entry.kind {
                EntryKind::Directory => {
                    stack.push((entry.item, entry.child, depth + 1));
                    NodeKind::Directory
                }
                EntryKind::File => {
                    let (plain, generation) = fetch_plaintext(
                        &entry.child,
                        ObjectType::FileManifest,
                        crypto,
                        store,
                        server,
                    )?;
                    let manifest = FileManifest::decode(&plain)?;
                    if manifest.size() != entry.size
                        || manifest.mtime_ms() != entry.mtime_ms
                        || manifest.flags() != entry.flags
                    {
                        return Err(CodecError::Inconsistent);
                    }
                    let content = ContentKey::of_chunks(manifest.chunks());
                    if store.chunk_list(&folder, &content)?.is_none() {
                        store.put_chunk_list(
                            &folder,
                            &content,
                            &ChunkList {
                                generation: generation.map(|g| g.0),
                                chunks: manifest.chunks().to_vec(),
                            },
                        )?;
                    }
                    NodeKind::File(FileVersion {
                        size: entry.size,
                        mtime_ms: entry.mtime_ms,
                        executable: entry.flags.is_executable(),
                        content,
                    })
                }
            };
            tree.insert(
                entry.item,
                Node {
                    parent: dir,
                    name: entry.name.clone(),
                    kind,
                    conflict_of: entry.conflict_of,
                },
            );
        }
    }
    tree.check()?;
    tree.clear_dirty();
    Ok(tree)
}

/// Every object reachable from `root` (its directory nodes, manifests and chunks), without
/// building a tree and without the tree checks (security review M3): the commit that replaces
/// a tree beyond the limits ("Undo a device") must name what it drops relative to that tree.
/// The walk is iterative, visits every directory node once, opens and checks every object as
/// [`decode`] does, and stops at [`MAX_REACHABLE_OBJECTS`].
pub fn reachable(
    root: &ObjectId,
    crypto: &FolderCrypto,
    store: &mut dyn Store,
    server: &mut dyn ServerApi,
) -> Result<BTreeSet<ObjectId>, CodecError> {
    Ok(reachable_typed(root, crypto, store, server)?.all)
}

/// The objects reachable from a root, with the directory nodes and manifests among them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reachable {
    /// Every object: directory nodes, manifests and chunks.
    pub all: BTreeSet<ObjectId>,
    /// The directory nodes.
    pub dirs: BTreeSet<ObjectId>,
    /// The file manifests.
    pub manifests: BTreeSet<ObjectId>,
}

impl Reachable {
    /// The chunks: everything that is neither a directory node nor a manifest.
    pub fn chunks(&self) -> impl Iterator<Item = &ObjectId> {
        self.all
            .iter()
            .filter(|id| !self.dirs.contains(id) && !self.manifests.contains(id))
    }
}

/// [`reachable`] with the kind of each object known from the walk.
pub fn reachable_typed(
    root: &ObjectId,
    crypto: &FolderCrypto,
    store: &mut dyn Store,
    server: &mut dyn ServerApi,
) -> Result<Reachable, CodecError> {
    let mut out = Reachable::default();
    let mut stack = vec![*root];
    out.all.insert(*root);
    out.dirs.insert(*root);
    while let Some(node_id) = stack.pop() {
        let (plain, _) =
            fetch_plaintext(&node_id, ObjectType::DirectoryNode, crypto, store, server)?;
        let node = DirectoryNode::decode(&plain)?;
        for entry in node.entries() {
            if !out.all.insert(entry.child) {
                continue;
            }
            match entry.kind {
                EntryKind::Directory => {
                    out.dirs.insert(entry.child);
                    stack.push(entry.child);
                }
                EntryKind::File => {
                    out.manifests.insert(entry.child);
                    let (plain, _) = fetch_plaintext(
                        &entry.child,
                        ObjectType::FileManifest,
                        crypto,
                        store,
                        server,
                    )?;
                    out.all
                        .extend(FileManifest::decode(&plain)?.chunks().iter().copied());
                }
            }
            if out.all.len() > MAX_REACHABLE_OBJECTS {
                return Err(CodecError::Limit);
            }
        }
    }
    Ok(out)
}

/// What a walk over a tree's objects reads of one object: the entries of a directory node, the
/// chunks of a manifest. [`StoreGraph`] reads them through the store's plaintext cache and the
/// server; tests use a graph in memory.
pub trait ObjectGraph {
    /// The entries of directory node `id`: each child with its kind, in order, repeats kept.
    fn dir_entries(&mut self, id: &ObjectId) -> Result<Vec<(ObjectId, EntryKind)>, CodecError>;
    /// The chunks of manifest `id`, in order, repeats kept.
    fn manifest_chunks(&mut self, id: &ObjectId) -> Result<Vec<ObjectId>, CodecError>;
}

/// The objects of a folder, opened and checked as [`decode`] does (store cache first).
pub struct StoreGraph<'a> {
    /// The folder's keys.
    pub crypto: &'a FolderCrypto,
    /// The local index.
    pub store: &'a mut dyn Store,
    /// The server.
    pub server: &'a mut dyn ServerApi,
}

impl ObjectGraph for StoreGraph<'_> {
    fn dir_entries(&mut self, id: &ObjectId) -> Result<Vec<(ObjectId, EntryKind)>, CodecError> {
        let (plain, _) = fetch_plaintext(
            id,
            ObjectType::DirectoryNode,
            self.crypto,
            self.store,
            self.server,
        )?;
        Ok(DirectoryNode::decode(&plain)?
            .entries()
            .iter()
            .map(|e| (e.child, e.kind))
            .collect())
    }

    fn manifest_chunks(&mut self, id: &ObjectId) -> Result<Vec<ObjectId>, CodecError> {
        let (plain, _) = fetch_plaintext(
            id,
            ObjectType::FileManifest,
            self.crypto,
            self.store,
            self.server,
        )?;
        Ok(FileManifest::decode(&plain)?.chunks().to_vec())
    }
}

/// The kind of an object in a [`ReachState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// A directory node.
    Dir,
    /// A file manifest.
    Manifest,
    /// A chunk.
    Chunk,
}

impl ObjectKind {
    fn of_entry(kind: EntryKind) -> Self {
        match kind {
            EntryKind::Directory => ObjectKind::Dir,
            EntryKind::File => ObjectKind::Manifest,
        }
    }

    fn slot(self) -> usize {
        match self {
            ObjectKind::Dir => 0,
            ObjectKind::Manifest => 1,
            ObjectKind::Chunk => 2,
        }
    }
}

/// What one [`ReachState::goto`] changed: the objects reachable from the new root but not from
/// the old one, and those reachable from the old root but not from the new one, both in
/// ascending order, and the kinds of the dropped ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transition {
    /// Newly reachable objects, ascending.
    pub added: Vec<ObjectId>,
    /// No longer reachable objects, ascending.
    pub dropped: Vec<ObjectId>,
    /// Dropped manifests.
    pub dropped_manifests: u64,
    /// Dropped chunks.
    pub dropped_chunks: u64,
}

/// The reachable set of one root as reference counts (security review of the delta check,
/// HIGH 2): every object reachable from the root, with the number of references to it from
/// reachable directory nodes and manifests (repeats counted), and its kind.
///
/// Moving to another root ([`ReachState::goto`]) first counts the references of the new root's
/// objects that were not reachable yet, then takes away those of the old root's objects that
/// lose their last reference. A subtree both roots share is never read: its root's count stays
/// above zero. The work is that of the change, not of the tree, and only one set is held, so a
/// delta of many commits over a large tree no longer reads and keeps every tree (the earlier
/// check held one set per root, 15 to 20 GB for 200 commits over a million files).
///
/// The objects form a graph without cycles (an ID is the keyed hash of a plaintext that names
/// its children's IDs), so an object loses its last reference exactly when no object of the new
/// root reaches it: [`Transition::added`] and [`Transition::dropped`] are the set differences of
/// the two reachable sets, as [`reachable_typed`] gives them. An object keeps the kind it was
/// first reached as; only a forged tree names one ID as two kinds, and the counts stay
/// consistent for it as well (they are expanded by the kept kind both ways).
#[derive(Debug, Clone, Default)]
pub struct ReachState {
    root: Option<ObjectId>,
    counts: BTreeMap<ObjectId, (u64, ObjectKind)>,
    kinds: [u64; 3],
}

impl ReachState {
    /// The empty set (no root).
    pub fn new() -> Self {
        Self::default()
    }

    /// The root the set is of.
    pub fn root(&self) -> Option<ObjectId> {
        self.root
    }

    /// Objects in the set.
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Manifests in the set.
    pub fn manifests(&self) -> u64 {
        self.kinds[ObjectKind::Manifest.slot()]
    }

    /// Chunks in the set.
    pub fn chunks(&self) -> u64 {
        self.kinds[ObjectKind::Chunk.slot()]
    }

    /// Every object of the set, ascending.
    pub fn ids(&self) -> impl Iterator<Item = &ObjectId> {
        self.counts.keys()
    }

    /// Moves the set to the objects reachable from `target` (none for `None`) and returns what
    /// changed. A set beyond [`MAX_REACHABLE_OBJECTS`] is [`CodecError::Limit`]. On any error
    /// the set is cleared (to no root), since it may be half moved.
    pub fn goto(
        &mut self,
        target: Option<ObjectId>,
        graph: &mut dyn ObjectGraph,
    ) -> Result<Transition, CodecError> {
        if target == self.root {
            return Ok(Transition::default());
        }
        match self.walk(target, graph) {
            Ok(t) => Ok(t),
            Err(e) => {
                self.root = None;
                self.counts.clear();
                self.kinds = [0; 3];
                Err(e)
            }
        }
    }

    fn walk(
        &mut self,
        target: Option<ObjectId>,
        graph: &mut dyn ObjectGraph,
    ) -> Result<Transition, CodecError> {
        let start = self.counts.len();
        let mut added = Vec::new();
        let mut stack: Vec<ObjectId> = Vec::new();
        if let Some(root) = target {
            self.inc(root, ObjectKind::Dir, &mut added, &mut stack);
        }
        while let Some(id) = stack.pop() {
            // Above the old set plus the limit, the new set alone is beyond the limit: stop
            // before more is read.
            if self.counts.len() > start.saturating_add(MAX_REACHABLE_OBJECTS) {
                return Err(CodecError::Limit);
            }
            for (child, kind) in self.children(&id, graph)? {
                self.inc(child, kind, &mut added, &mut stack);
            }
        }
        let mut t = Transition::default();
        if let Some(old) = self.root {
            self.dec(old, &mut t, &mut stack);
        }
        while let Some(id) = stack.pop() {
            for (child, _) in self.children(&id, graph)? {
                self.dec(child, &mut t, &mut stack);
            }
            // Its references are taken away; the node goes.
            self.counts.remove(&id);
        }
        if self.counts.len() > MAX_REACHABLE_OBJECTS {
            return Err(CodecError::Limit);
        }
        added.sort_unstable();
        t.dropped.sort_unstable();
        t.added = added;
        self.root = target;
        Ok(t)
    }

    /// The references an object holds, by the kind it is kept as.
    fn children(
        &self,
        id: &ObjectId,
        graph: &mut dyn ObjectGraph,
    ) -> Result<Vec<(ObjectId, ObjectKind)>, CodecError> {
        match self.counts.get(id).map(|(_, kind)| *kind) {
            Some(ObjectKind::Dir) => Ok(graph
                .dir_entries(id)?
                .into_iter()
                .map(|(child, kind)| (child, ObjectKind::of_entry(kind)))
                .collect()),
            Some(ObjectKind::Manifest) => Ok(graph
                .manifest_chunks(id)?
                .into_iter()
                .map(|c| (c, ObjectKind::Chunk))
                .collect()),
            // Only objects of the set are expanded.
            None => Err(CodecError::Inconsistent),
            Some(ObjectKind::Chunk) => Ok(Vec::new()),
        }
    }

    fn inc(
        &mut self,
        id: ObjectId,
        kind: ObjectKind,
        added: &mut Vec<ObjectId>,
        stack: &mut Vec<ObjectId>,
    ) {
        let entry = self.counts.entry(id).or_insert((0, kind));
        entry.0 += 1;
        if entry.0 == 1 {
            self.kinds[entry.1.slot()] += 1;
            added.push(id);
            if entry.1 != ObjectKind::Chunk {
                stack.push(id);
            }
        }
    }

    fn dec(&mut self, id: ObjectId, t: &mut Transition, stack: &mut Vec<ObjectId>) {
        let Some(entry) = self.counts.get_mut(&id) else {
            return;
        };
        // Zero: dropped already in this walk; never true for consistent counts.
        if entry.0 == 0 {
            return;
        }
        entry.0 -= 1;
        if entry.0 > 0 {
            return;
        }
        let kind = entry.1;
        self.kinds[kind.slot()] = self.kinds[kind.slot()].saturating_sub(1);
        t.dropped.push(id);
        match kind {
            ObjectKind::Manifest => t.dropped_manifests += 1,
            ObjectKind::Chunk => t.dropped_chunks += 1,
            ObjectKind::Dir => {}
        }
        if kind == ObjectKind::Chunk {
            self.counts.remove(&id);
        } else {
            // A node keeps its entry with count zero until its own references are taken away
            // ([`Self::children`] reads its kind from it).
            stack.push(id);
        }
    }
}

/// The directory nodes and manifests reachable from `roots` whose plaintexts the store holds,
/// without the server: a node the cache lacks is not entered (the cleanup of the cache, which
/// must not download anything).
pub fn cached_reachable(
    roots: &[ObjectId],
    folder: &FolderId,
    store: &dyn Store,
) -> Result<BTreeSet<ObjectId>, StoreError> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<(ObjectId, bool)> = roots.iter().map(|r| (*r, true)).collect();
    while let Some((id, dir)) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(plain) = store.plaintext(folder, &id)? else {
            continue;
        };
        if !dir {
            continue;
        }
        // A plaintext that does not decode was checked when it was stored; skip it here.
        if let Ok(node) = DirectoryNode::decode(&plain) {
            for entry in node.entries() {
                stack.push((entry.child, entry.kind == EntryKind::Directory));
            }
        }
    }
    Ok(seen)
}

/// Remembers that the server now holds the sealed objects of `encoded`.
pub fn remember_uploaded(
    encoded: &Encoded,
    folder: &FolderId,
    store: &mut dyn Store,
) -> Result<(), StoreError> {
    for (id, digest) in &encoded.digests {
        store.put_object_for(folder, digest, id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::tests::Rng;
    use std::collections::HashMap;

    /// Objects in memory, with a count of every read.
    #[derive(Default)]
    struct MemGraph {
        dirs: HashMap<ObjectId, Vec<(ObjectId, EntryKind)>>,
        manifests: HashMap<ObjectId, Vec<ObjectId>>,
        reads: u64,
    }

    impl ObjectGraph for MemGraph {
        fn dir_entries(&mut self, id: &ObjectId) -> Result<Vec<(ObjectId, EntryKind)>, CodecError> {
            self.reads += 1;
            self.dirs.get(id).cloned().ok_or(CodecError::Inconsistent)
        }
        fn manifest_chunks(&mut self, id: &ObjectId) -> Result<Vec<ObjectId>, CodecError> {
            self.reads += 1;
            self.manifests
                .get(id)
                .cloned()
                .ok_or(CodecError::Inconsistent)
        }
    }

    impl MemGraph {
        /// A content addressed ID, so equal contents share one object as they do on a server.
        fn id_of(tag: u8, parts: &[(ObjectId, u8)]) -> ObjectId {
            let mut h = Sha256::new();
            h.update([tag]);
            for (id, k) in parts {
                h.update(id.as_bytes());
                h.update([*k]);
            }
            ObjectId::from_bytes(h.finalize().into())
        }

        fn manifest(&mut self, chunks: Vec<ObjectId>) -> ObjectId {
            let parts: Vec<(ObjectId, u8)> = chunks.iter().map(|c| (*c, 0)).collect();
            let id = Self::id_of(1, &parts);
            self.manifests.insert(id, chunks);
            id
        }

        fn dir(&mut self, entries: Vec<(ObjectId, EntryKind)>) -> ObjectId {
            let parts: Vec<(ObjectId, u8)> = entries
                .iter()
                .map(|(c, k)| (*c, u8::from(*k == EntryKind::Directory)))
                .collect();
            let id = Self::id_of(2, &parts);
            self.dirs.insert(id, entries);
            id
        }
    }

    type Sets = (BTreeSet<ObjectId>, BTreeSet<ObjectId>, BTreeSet<ObjectId>);

    /// The earlier walk ([`reachable_typed`] over a graph), kept as the reference: every object
    /// reachable from `root`, the manifests and the chunks among them.
    fn reference(root: Option<ObjectId>, graph: &mut MemGraph) -> Sets {
        let (mut all, mut dirs, mut manifests) =
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        let Some(root) = root else {
            return (all, manifests, BTreeSet::new());
        };
        let mut stack = vec![root];
        all.insert(root);
        dirs.insert(root);
        while let Some(node) = stack.pop() {
            for (child, kind) in graph.dir_entries(&node).unwrap() {
                if !all.insert(child) {
                    continue;
                }
                match kind {
                    EntryKind::Directory => {
                        dirs.insert(child);
                        stack.push(child);
                    }
                    EntryKind::File => {
                        manifests.insert(child);
                        all.extend(graph.manifest_chunks(&child).unwrap());
                    }
                }
            }
        }
        let chunks = all
            .iter()
            .filter(|id| !dirs.contains(id) && !manifests.contains(id))
            .copied()
            .collect();
        (all, manifests, chunks)
    }

    /// Random trees over shared objects: few chunk IDs (repeated within and across manifests),
    /// few manifests (one file content in many places), empty and equal directories (one node
    /// referenced from many parents), and roots that reuse whole subtrees of others.
    fn random_graph(rng: &mut Rng) -> (MemGraph, Vec<ObjectId>) {
        let mut g = MemGraph::default();
        let chunks: Vec<ObjectId> = (0..6u8)
            .map(|i| ObjectId::from_bytes([i + 1; 32]))
            .collect();
        let mut manifests = Vec::new();
        for _ in 0..8 {
            let list: Vec<ObjectId> = (0..rng.below(4)).map(|_| *rng.pick(&chunks)).collect();
            manifests.push(g.manifest(list));
        }
        let mut dirs: Vec<ObjectId> = Vec::new();
        for _ in 0..30 {
            let mut entries = Vec::new();
            for _ in 0..rng.below(5) {
                if !dirs.is_empty() && rng.below(3) == 0 {
                    entries.push((*rng.pick(&dirs), EntryKind::Directory));
                } else {
                    entries.push((*rng.pick(&manifests), EntryKind::File));
                }
            }
            dirs.push(g.dir(entries));
        }
        (g, dirs)
    }

    /// Security review of the delta check, HIGH 2: moving the counted set from root to root
    /// gives exactly the set differences of the earlier walk, its manifest and chunk counts and
    /// the dropped ones among them, for random sequences of roots (also back and forth, to no
    /// root and to a subtree of the previous root).
    #[test]
    fn counted_transitions_equal_the_set_differences() {
        let mut rng = Rng(0xde17a);
        for case in 0..500 {
            let (mut g, dirs) = random_graph(&mut rng);
            let mut state = ReachState::new();
            let mut at: Option<ObjectId> = None;
            for step in 0..12 {
                let next = if rng.below(6) == 0 {
                    None
                } else {
                    Some(*rng.pick(&dirs))
                };
                let (before, before_manifests, before_chunks) = reference(at, &mut g);
                let (after, after_manifests, after_chunks) = reference(next, &mut g);
                let t = state.goto(next, &mut g).unwrap();
                let added: Vec<ObjectId> = after.difference(&before).copied().collect();
                let dropped: Vec<ObjectId> = before.difference(&after).copied().collect();
                let what = format!("case {case} step {step}");
                assert_eq!(t.added, added, "{what}");
                assert_eq!(t.dropped, dropped, "{what}");
                assert_eq!(
                    t.dropped_chunks,
                    before_chunks.difference(&after_chunks).count() as u64,
                    "{what}"
                );
                assert_eq!(
                    t.dropped_manifests,
                    before_manifests.difference(&after_manifests).count() as u64,
                    "{what}"
                );
                assert_eq!(state.len(), after.len(), "{what}");
                assert!(state.ids().copied().eq(after.iter().copied()), "{what}");
                assert_eq!(state.manifests(), after_manifests.len() as u64, "{what}");
                assert_eq!(state.chunks(), after_chunks.len() as u64, "{what}");
                at = next;
            }
        }
    }

    /// 200 commits over a tree of 20,000 files in 100 directories, each changing one file:
    /// the counted set reads the tree once and then only the changed nodes, and holds one set.
    /// The earlier check read both trees of every commit (about 8 million node reads here) and
    /// kept every set until the end of the pull.
    #[test]
    fn many_commits_over_a_large_tree_read_only_the_changes() {
        let (dirs_n, files_n) = (100usize, 200usize);
        let mut g = MemGraph::default();
        let mut content = 0u32;
        let mut new_manifest = |g: &mut MemGraph| {
            content += 1;
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&content.to_be_bytes());
            g.manifest(vec![ObjectId::from_bytes(bytes)])
        };
        let mut files: Vec<Vec<ObjectId>> = (0..dirs_n)
            .map(|_| (0..files_n).map(|_| new_manifest(&mut g)).collect())
            .collect();
        let build = |g: &mut MemGraph, files: &[Vec<ObjectId>]| {
            let subdirs: Vec<(ObjectId, EntryKind)> = files
                .iter()
                .map(|f| {
                    let entries = f.iter().map(|m| (*m, EntryKind::File)).collect();
                    (g.dir(entries), EntryKind::Directory)
                })
                .collect();
            g.dir(subdirs)
        };
        let first = build(&mut g, &files);
        let mut roots = vec![first];
        let mut rng = Rng(9);
        for _ in 0..200 {
            let (d, f) = (rng.below(dirs_n), rng.below(files_n));
            files[d][f] = new_manifest(&mut g);
            roots.push(build(&mut g, &files));
        }
        g.reads = 0;
        let mut state = ReachState::new();
        let mut largest = 0;
        let mut changed = 0usize;
        for root in &roots {
            let t = state.goto(Some(*root), &mut g).unwrap();
            changed += t.added.len() + t.dropped.len();
            largest = largest.max(state.len());
        }
        let tree = 1 + dirs_n + 2 * dirs_n * files_n;
        assert_eq!(state.len(), tree);
        // One read of the first tree, then six per commit: the new root, directory and
        // manifest, and the old ones when they go.
        assert!(
            g.reads <= (1 + dirs_n + dirs_n * files_n) as u64 + 6 * 200,
            "{} reads",
            g.reads
        );
        // The first tree once, then four objects in and four out per commit.
        assert_eq!(changed, tree + 200 * 8);
        assert!(largest <= tree + 4, "{largest} objects held");
    }
}
