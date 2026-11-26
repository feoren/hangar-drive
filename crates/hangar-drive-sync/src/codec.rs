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
                    let manifest = encode_manifest(v, crypto, store, &folder, entropy, &mut out)?;
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
        out,
    )
}

fn put_object(
    kind: ObjectType,
    plaintext: &[u8],
    crypto: &FolderCrypto,
    store: &dyn Store,
    folder: &FolderId,
    entropy: &mut dyn Entropy,
    out: &mut Encoded,
) -> Result<ObjectId, CodecError> {
    let digest = plaintext_digest(kind, plaintext);
    let id = match store.object_for(folder, &digest)? {
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
    let mut out = BTreeSet::new();
    let mut stack = vec![*root];
    out.insert(*root);
    while let Some(node_id) = stack.pop() {
        let (plain, _) =
            fetch_plaintext(&node_id, ObjectType::DirectoryNode, crypto, store, server)?;
        let node = DirectoryNode::decode(&plain)?;
        for entry in node.entries() {
            if !out.insert(entry.child) {
                continue;
            }
            match entry.kind {
                EntryKind::Directory => stack.push(entry.child),
                EntryKind::File => {
                    let (plain, _) = fetch_plaintext(
                        &entry.child,
                        ObjectType::FileManifest,
                        crypto,
                        store,
                        server,
                    )?;
                    out.extend(FileManifest::decode(&plain)?.chunks().iter().copied());
                }
            }
            if out.len() > MAX_REACHABLE_OBJECTS {
                return Err(CodecError::Limit);
            }
        }
    }
    Ok(out)
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
