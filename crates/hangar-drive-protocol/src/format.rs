//! Plaintext formats of directory nodes and file manifests (version 1). Both are encrypted as
//! objects by `hangar-drive-crypto`; this module only encodes and decodes them.
//!
//! Decoding is strict: every value has exactly one encoding, so re-encoding gives the same
//! bytes and the same object ID. Unknown versions, kinds and flag bits, unsorted or duplicate
//! entries, trailing bytes and anything above the limits of [`crate::object`] are refused.
//!
//! # Directory node
//!
//! ```text
//! node  = 0x01 || count (u32) || count x entry, sorted by comparison key (strictly increasing bytes)
//! entry = field(name, UTF-8 bytes from disk) || field(comparison key, NFC of name)
//!         || kind (u8: 1 file, 2 directory) || item id (16) || child object id (32)
//!         || size (u64) || mtime (i64, ms since the Unix epoch) || flags (u32)
//!         || conflict of (16, the original's item id; present only when flags bit 1 is set)
//! ```
//!
//! `flags` bit 0 is the execute bit (files only). Bit 1 is a wire bit of the directory entry
//! only: it says that a conflict-of item ID follows. A conflict copy carries the item ID of the
//! file it is the conflict of, so every device recognises the pair of original and copy
//! without parsing the localised copy name, which is only a label (decision of the main agent,
//! 2026-11-26). Encoding the presence in a flag bit keeps the format one byte string per
//! value and costs nothing for the common entry. The ID must differ from the entry's own.
//! A directory entry has size 0 and no execute bit. Item IDs are unique within a node.
//!
//! # File manifest
//!
//! ```text
//! manifest = 0x01 || size (u64) || mtime (i64 ms) || flags (u32) || count (u32) || count x chunk id (32)
//! ```
//!
//! `count` must be `ceil(size / CHUNK_SIZE)`: every chunk but the last holds exactly
//! [`CHUNK_SIZE`] bytes. The manifest's ID is a keyed hash over all of it, so chunk order,
//! count and the end of the file are authenticated through the tree.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::framing::{Reader, Writer};
use crate::ids::{ItemId, ObjectId};
use crate::name::{check_name, comparison_key, NameError};
use crate::object::{
    chunk_count, EntryFlags, EntryKind, CHUNK_SIZE, MAX_DIRECTORY_ENTRIES, MAX_FILE_SIZE,
    MAX_MANIFEST_CHUNKS, MAX_OBJECT_PLAINTEXT_LEN,
};

/// The format version of directory nodes and file manifests.
pub const FORMAT_VERSION: u8 = 1;

/// Wire flag bit of a directory entry: a conflict-of item ID follows the flags.
const WIRE_CONFLICT_OF: u32 = 1 << 1;
const WIRE_KNOWN: u32 = EntryFlags::EXECUTABLE | WIRE_CONFLICT_OF;

/// Why a directory node or file manifest was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FormatError {
    /// The input ends inside a value.
    #[error("the data is truncated")]
    Truncated,
    /// Bytes after the last value.
    #[error("trailing bytes after the data")]
    TrailingBytes,
    /// A format version this crate does not know.
    #[error("format version {0} is not supported")]
    Version(u8),
    /// More entries, chunks or bytes than the limits allow.
    #[error("the data exceeds the format's limits")]
    TooLarge,
    /// A name that is not UTF-8.
    #[error("a name is not valid UTF-8")]
    NameEncoding,
    /// A name no tree may hold.
    #[error(transparent)]
    Name(#[from] NameError),
    /// The stored comparison key is not the NFC of the name.
    #[error("a comparison key is not the NFC form of its name")]
    ComparisonKey,
    /// Entries out of order, or two entries with the same comparison key.
    #[error("the entries are not strictly sorted by comparison key")]
    Unsorted,
    /// Two entries with the same item ID.
    #[error("two entries share an item id")]
    DuplicateItem,
    /// An unknown entry kind.
    #[error("unknown entry kind {0}")]
    Kind(u8),
    /// Unknown flag bits.
    #[error("unknown flag bits {0:#x}")]
    Flags(u32),
    /// A directory entry with a size or an execute bit.
    #[error("a directory entry has a size or an execute bit")]
    DirectoryFields,
    /// An entry that names itself as the original of its conflict.
    #[error("an entry is a conflict copy of itself")]
    ConflictOfSelf,
    /// The chunk count does not match the file size.
    #[error("the chunk count does not match the file size")]
    ChunkCount,
    /// A file larger than the protocol allows.
    #[error("the file is too large")]
    FileTooLarge,
}

/// One entry of a directory node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// The name as the exact bytes from disk (UTF-8, possibly decomposed).
    pub name: String,
    /// The stable item ID the merge matches by.
    pub item: ItemId,
    /// File or directory.
    pub kind: EntryKind,
    /// The file manifest or directory node of the entry.
    pub child: ObjectId,
    /// File size in bytes; 0 for a directory.
    pub size: u64,
    /// Modification time, milliseconds since the Unix epoch.
    pub mtime_ms: i64,
    /// Flags; only files may be executable.
    pub flags: EntryFlags,
    /// For a conflict copy: the item ID of the file whose conflict it is.
    pub conflict_of: Option<ItemId>,
}

impl DirectoryEntry {
    /// The entry's comparison key (NFC of the name).
    pub fn comparison_key(&self) -> String {
        comparison_key(&self.name)
    }

    fn check(&self) -> Result<(), FormatError> {
        check_name(&self.name)?;
        match self.kind {
            EntryKind::Directory => {
                if self.size != 0 || self.flags.is_executable() {
                    return Err(FormatError::DirectoryFields);
                }
            }
            EntryKind::File => {
                if self.size > MAX_FILE_SIZE {
                    return Err(FormatError::FileTooLarge);
                }
            }
        }
        if self.conflict_of == Some(self.item) {
            return Err(FormatError::ConflictOfSelf);
        }
        Ok(())
    }

    fn wire_flags(&self) -> u32 {
        let conflict = if self.conflict_of.is_some() {
            WIRE_CONFLICT_OF
        } else {
            0
        };
        self.flags.bits() | conflict
    }
}

/// The entries of one directory, sorted by comparison key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirectoryNode {
    entries: Vec<DirectoryEntry>,
}

impl DirectoryNode {
    /// A node of these entries in any order: sorts them and checks every rule of the format.
    pub fn new(mut entries: Vec<DirectoryEntry>) -> Result<Self, FormatError> {
        entries.sort_by_cached_key(DirectoryEntry::comparison_key);
        let node = Self { entries };
        node.check()?;
        Ok(node)
    }

    /// The entries, sorted by comparison key.
    pub fn entries(&self) -> &[DirectoryEntry] {
        &self.entries
    }

    /// The entry with this comparison key.
    pub fn get(&self, comparison_key: &str) -> Option<&DirectoryEntry> {
        self.entries
            .binary_search_by(|entry| entry.comparison_key().as_str().cmp(comparison_key))
            .ok()
            .and_then(|at| self.entries.get(at))
    }

    fn check(&self) -> Result<(), FormatError> {
        if self.entries.len() > MAX_DIRECTORY_ENTRIES as usize {
            return Err(FormatError::TooLarge);
        }
        let mut items = BTreeSet::new();
        let mut previous: Option<String> = None;
        for entry in &self.entries {
            entry.check()?;
            let key = entry.comparison_key();
            if previous
                .as_ref()
                .is_some_and(|p| p.as_bytes() >= key.as_bytes())
            {
                return Err(FormatError::Unsorted);
            }
            if !items.insert(entry.item) {
                return Err(FormatError::DuplicateItem);
            }
            previous = Some(key);
        }
        Ok(())
    }

    /// The plaintext of the node (module docs).
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        self.check()?;
        let count = u32::try_from(self.entries.len()).map_err(|_| FormatError::TooLarge)?;
        let mut w = Writer::new();
        w.u8(FORMAT_VERSION).u32(count);
        for entry in &self.entries {
            w.field(entry.name.as_bytes())
                .field(entry.comparison_key().as_bytes())
                .u8(entry.kind.to_byte())
                .raw(entry.item.as_bytes())
                .raw(entry.child.as_bytes())
                .u64(entry.size)
                .i64(entry.mtime_ms)
                .u32(entry.wire_flags());
            if let Some(original) = entry.conflict_of {
                w.raw(original.as_bytes());
            }
            if w.len() > MAX_OBJECT_PLAINTEXT_LEN {
                return Err(FormatError::TooLarge);
            }
        }
        Ok(w.into_bytes())
    }

    /// Reads a node's plaintext, strictly (module docs).
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_OBJECT_PLAINTEXT_LEN {
            return Err(FormatError::TooLarge);
        }
        let mut r = Reader::new(bytes);
        let version = r.u8().ok_or(FormatError::Truncated)?;
        if version != FORMAT_VERSION {
            return Err(FormatError::Version(version));
        }
        let count = r.u32().ok_or(FormatError::Truncated)?;
        if count > MAX_DIRECTORY_ENTRIES {
            return Err(FormatError::TooLarge);
        }
        // The smallest entry has 79 bytes; a count the input cannot hold is refused before
        // anything is allocated for it.
        if (count as usize).saturating_mul(79) > r.remaining() {
            return Err(FormatError::Truncated);
        }
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            entries.push(decode_entry(&mut r)?);
        }
        r.finish().ok_or(FormatError::TrailingBytes)?;
        let node = Self { entries };
        node.check()?;
        Ok(node)
    }
}

fn decode_entry(r: &mut Reader<'_>) -> Result<DirectoryEntry, FormatError> {
    let name = r.field().ok_or(FormatError::Truncated)?;
    let name = std::str::from_utf8(name).map_err(|_| FormatError::NameEncoding)?;
    let key = r.field().ok_or(FormatError::Truncated)?;
    if key != comparison_key(name).as_bytes() {
        return Err(FormatError::ComparisonKey);
    }
    let kind_byte = r.u8().ok_or(FormatError::Truncated)?;
    let kind = EntryKind::from_byte(kind_byte).map_err(|_| FormatError::Kind(kind_byte))?;
    let item = ItemId::from_bytes(r.raw().ok_or(FormatError::Truncated)?);
    let child = ObjectId::from_bytes(r.raw().ok_or(FormatError::Truncated)?);
    let size = r.u64().ok_or(FormatError::Truncated)?;
    let mtime_ms = r.i64().ok_or(FormatError::Truncated)?;
    let wire = r.u32().ok_or(FormatError::Truncated)?;
    if wire & !WIRE_KNOWN != 0 {
        return Err(FormatError::Flags(wire & !WIRE_KNOWN));
    }
    let conflict_of = if wire & WIRE_CONFLICT_OF != 0 {
        Some(ItemId::from_bytes(r.raw().ok_or(FormatError::Truncated)?))
    } else {
        None
    };
    let flags = EntryFlags::from_bits(wire & EntryFlags::EXECUTABLE)
        .map_err(|unknown| FormatError::Flags(unknown.0))?;
    Ok(DirectoryEntry {
        name: name.to_owned(),
        item,
        kind,
        child,
        size,
        mtime_ms,
        flags,
        conflict_of,
    })
}

/// One file version: size, modification time, flags and the ordered chunk IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileManifest {
    size: u64,
    mtime_ms: i64,
    flags: EntryFlags,
    chunks: Vec<ObjectId>,
}

impl FileManifest {
    /// A manifest; the chunk count must match the size (module docs).
    pub fn new(
        size: u64,
        mtime_ms: i64,
        flags: EntryFlags,
        chunks: Vec<ObjectId>,
    ) -> Result<Self, FormatError> {
        let manifest = Self {
            size,
            mtime_ms,
            flags,
            chunks,
        };
        manifest.check()?;
        Ok(manifest)
    }

    fn check(&self) -> Result<(), FormatError> {
        if self.size > MAX_FILE_SIZE {
            return Err(FormatError::FileTooLarge);
        }
        if self.chunks.len() as u64 != chunk_count(self.size) {
            return Err(FormatError::ChunkCount);
        }
        Ok(())
    }

    /// File size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Modification time, milliseconds since the Unix epoch.
    pub fn mtime_ms(&self) -> i64 {
        self.mtime_ms
    }

    /// Flags.
    pub fn flags(&self) -> EntryFlags {
        self.flags
    }

    /// The chunk IDs in file order.
    pub fn chunks(&self) -> &[ObjectId] {
        &self.chunks
    }

    /// The plaintext length chunk `index` must have.
    pub fn chunk_len(&self, index: usize) -> Option<u64> {
        let index = u64::try_from(index).ok()?;
        let start = index.checked_mul(CHUNK_SIZE)?;
        if index >= self.chunks.len() as u64 {
            return None;
        }
        Some((self.size - start).min(CHUNK_SIZE))
    }

    /// The plaintext of the manifest (module docs).
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        self.check()?;
        let count = u32::try_from(self.chunks.len()).map_err(|_| FormatError::TooLarge)?;
        let mut w = Writer::with_capacity(25 + 32 * self.chunks.len());
        w.u8(FORMAT_VERSION)
            .u64(self.size)
            .i64(self.mtime_ms)
            .u32(self.flags.bits())
            .u32(count);
        for chunk in &self.chunks {
            w.raw(chunk.as_bytes());
        }
        Ok(w.into_bytes())
    }

    /// Reads a manifest's plaintext, strictly (module docs).
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().ok_or(FormatError::Truncated)?;
        if version != FORMAT_VERSION {
            return Err(FormatError::Version(version));
        }
        let size = r.u64().ok_or(FormatError::Truncated)?;
        let mtime_ms = r.i64().ok_or(FormatError::Truncated)?;
        let bits = r.u32().ok_or(FormatError::Truncated)?;
        let flags = EntryFlags::from_bits(bits).map_err(|unknown| FormatError::Flags(unknown.0))?;
        let count = r.u32().ok_or(FormatError::Truncated)?;
        if count > MAX_MANIFEST_CHUNKS {
            return Err(FormatError::TooLarge);
        }
        if (count as usize).saturating_mul(32) != r.remaining() {
            return Err(if (count as usize).saturating_mul(32) > r.remaining() {
                FormatError::Truncated
            } else {
                FormatError::TrailingBytes
            });
        }
        let mut chunks = Vec::with_capacity(count as usize);
        for _ in 0..count {
            chunks.push(ObjectId::from_bytes(r.raw().ok_or(FormatError::Truncated)?));
        }
        r.finish().ok_or(FormatError::TrailingBytes)?;
        Self::new(size, mtime_ms, flags, chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, item: u8) -> DirectoryEntry {
        DirectoryEntry {
            name: name.to_owned(),
            item: ItemId::from_bytes([item; 16]),
            kind: EntryKind::File,
            child: ObjectId::from_bytes([item; 32]),
            size: 5,
            mtime_ms: 1_700_000_000_000,
            flags: EntryFlags::NONE,
            conflict_of: None,
        }
    }

    fn dir(name: &str, item: u8) -> DirectoryEntry {
        DirectoryEntry {
            kind: EntryKind::Directory,
            size: 0,
            ..file(name, item)
        }
    }

    #[test]
    fn node_sorts_and_round_trips() {
        let node = DirectoryNode::new(vec![file("b", 2), dir("a", 1), file("C", 3)]).unwrap();
        let names: Vec<&str> = node.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["C", "a", "b"]);
        let bytes = node.encode().unwrap();
        assert_eq!(DirectoryNode::decode(&bytes).unwrap(), node);
        assert_eq!(
            node.get("a").map(|e| e.item),
            Some(ItemId::from_bytes([1; 16]))
        );
        assert!(node.get("z").is_none());
    }

    #[test]
    fn empty_node_is_five_bytes() {
        let node = DirectoryNode::new(vec![]).unwrap();
        assert_eq!(node.encode().unwrap(), vec![1, 0, 0, 0, 0]);
        assert_eq!(DirectoryNode::decode(&[1, 0, 0, 0, 0]).unwrap(), node);
    }

    #[test]
    fn node_keeps_decomposed_names_and_sorts_by_nfc() {
        let entry = file("cafe\u{301}", 1);
        let node = DirectoryNode::new(vec![entry.clone()]).unwrap();
        let bytes = node.encode().unwrap();
        let back = DirectoryNode::decode(&bytes).unwrap();
        assert_eq!(back.entries()[0].name, "cafe\u{301}");
        assert!(back.get("caf\u{e9}").is_some());
    }

    #[test]
    fn node_refuses_normalization_duplicates_but_keeps_case_pairs() {
        assert_eq!(
            DirectoryNode::new(vec![file("caf\u{e9}", 1), file("cafe\u{301}", 2)]),
            Err(FormatError::Unsorted)
        );
        assert!(DirectoryNode::new(vec![file("a", 1), file("A", 2)]).is_ok());
        assert_eq!(
            DirectoryNode::new(vec![file("a", 1), file("b", 1)]),
            Err(FormatError::DuplicateItem)
        );
    }

    #[test]
    fn conflict_of_round_trips_and_is_strict() {
        let mut copy = file("report (conflict laptop 2026-11-26).txt", 2);
        copy.conflict_of = Some(ItemId::from_bytes([1; 16]));
        copy.flags = EntryFlags::executable(true);
        let node = DirectoryNode::new(vec![file("report.txt", 1), copy.clone()]).unwrap();
        let bytes = node.encode().unwrap();
        let back = DirectoryNode::decode(&bytes).unwrap();
        assert_eq!(back, node);
        let decoded = back.entries().iter().find(|e| e.item == copy.item).unwrap();
        assert_eq!(decoded.conflict_of, Some(ItemId::from_bytes([1; 16])));
        assert!(decoded.flags.is_executable());
        // 16 more bytes than without the field.
        let plain = DirectoryNode::new(vec![file("report.txt", 1), {
            let mut c = copy.clone();
            c.conflict_of = None;
            c
        }])
        .unwrap();
        assert_eq!(bytes.len(), plain.encode().unwrap().len() + 16);

        let mut own = file("x", 3);
        own.conflict_of = Some(own.item);
        assert_eq!(
            DirectoryNode::new(vec![own]),
            Err(FormatError::ConflictOfSelf)
        );

        // The bit set without the 16 bytes: truncated.
        let single = DirectoryNode::new(vec![file("x", 3)]).unwrap();
        let mut bytes = single.encode().unwrap();
        let flags_at = bytes.len() - 4;
        bytes[flags_at + 3] |= 2;
        assert_eq!(DirectoryNode::decode(&bytes), Err(FormatError::Truncated));
        bytes.extend_from_slice(&[3; 16]);
        assert_eq!(
            DirectoryNode::decode(&bytes),
            Err(FormatError::ConflictOfSelf)
        );
    }

    #[test]
    fn directory_entries_have_no_size_or_execute_bit() {
        let mut d = dir("d", 1);
        d.size = 1;
        assert_eq!(
            DirectoryNode::new(vec![d]),
            Err(FormatError::DirectoryFields)
        );
        let mut d = dir("d", 1);
        d.flags = EntryFlags::executable(true);
        assert_eq!(
            DirectoryNode::new(vec![d]),
            Err(FormatError::DirectoryFields)
        );
    }

    fn one_entry_bytes() -> Vec<u8> {
        DirectoryNode::new(vec![file("x", 3)])
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn node_decoding_is_strict() {
        let bytes = one_entry_bytes();
        // Layout: version 1, count 4, name field 5, key field 5, then kind.
        let kind_at = 1 + 4 + 5 + 5;
        let mut wrong = bytes.clone();
        wrong[0] = 2;
        assert_eq!(DirectoryNode::decode(&wrong), Err(FormatError::Version(2)));
        let mut wrong = bytes.clone();
        wrong[kind_at] = 3;
        assert_eq!(DirectoryNode::decode(&wrong), Err(FormatError::Kind(3)));
        let mut wrong = bytes.clone();
        let flags_at = wrong.len() - 4;
        wrong[flags_at] = 0x80;
        assert_eq!(
            DirectoryNode::decode(&wrong),
            Err(FormatError::Flags(0x8000_0000))
        );
        let mut wrong = bytes.clone();
        wrong.push(0);
        assert_eq!(
            DirectoryNode::decode(&wrong),
            Err(FormatError::TrailingBytes)
        );
        for cut in 0..bytes.len() {
            assert!(DirectoryNode::decode(&bytes[..cut]).is_err(), "cut {cut}");
        }
        // A comparison key that is not the NFC of the name.
        let mut wrong = bytes.clone();
        wrong[1 + 4 + 5 + 4] = b'y';
        assert_eq!(
            DirectoryNode::decode(&wrong),
            Err(FormatError::ComparisonKey)
        );
        // A count larger than the input can hold.
        let mut wrong = bytes.clone();
        wrong[1..5].copy_from_slice(&MAX_DIRECTORY_ENTRIES.to_be_bytes());
        assert_eq!(DirectoryNode::decode(&wrong), Err(FormatError::Truncated));
        wrong[1..5].copy_from_slice(&(MAX_DIRECTORY_ENTRIES + 1).to_be_bytes());
        assert_eq!(DirectoryNode::decode(&wrong), Err(FormatError::TooLarge));
    }

    #[test]
    fn node_decoding_refuses_reordered_entries_and_bad_names() {
        let node = DirectoryNode::new(vec![file("a", 1), file("b", 2)]).unwrap();
        let bytes = node.encode().unwrap();
        let entry_len = (bytes.len() - 5) / 2;
        let mut swapped = bytes[..5].to_vec();
        swapped.extend_from_slice(&bytes[5 + entry_len..]);
        swapped.extend_from_slice(&bytes[5..5 + entry_len]);
        assert_eq!(DirectoryNode::decode(&swapped), Err(FormatError::Unsorted));

        let mut w = Writer::new();
        w.u8(1)
            .u32(1)
            .field(b"a/b")
            .field(b"a/b")
            .u8(1)
            .raw(&[1; 16])
            .raw(&[1; 32])
            .u64(0)
            .i64(0)
            .u32(0);
        assert_eq!(
            DirectoryNode::decode(&w.into_bytes()),
            Err(FormatError::Name(NameError::Slash))
        );
        let mut w = Writer::new();
        w.u8(1)
            .u32(1)
            .field(&[0xff])
            .field(&[0xff])
            .u8(1)
            .raw(&[1; 16])
            .raw(&[1; 32])
            .u64(0)
            .i64(0)
            .u32(0);
        assert_eq!(
            DirectoryNode::decode(&w.into_bytes()),
            Err(FormatError::NameEncoding)
        );
    }

    #[test]
    fn manifest_round_trips_and_checks_chunk_count() {
        let chunks = vec![ObjectId::from_bytes([1; 32]), ObjectId::from_bytes([2; 32])];
        let manifest =
            FileManifest::new(CHUNK_SIZE + 1, -5, EntryFlags::executable(true), chunks).unwrap();
        let bytes = manifest.encode().unwrap();
        assert_eq!(bytes.len(), 25 + 64);
        assert_eq!(FileManifest::decode(&bytes).unwrap(), manifest);
        assert_eq!(manifest.chunk_len(0), Some(CHUNK_SIZE));
        assert_eq!(manifest.chunk_len(1), Some(1));
        assert_eq!(manifest.chunk_len(2), None);

        let empty = FileManifest::new(0, 0, EntryFlags::NONE, vec![]).unwrap();
        assert_eq!(
            FileManifest::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );
        assert_eq!(
            FileManifest::new(1, 0, EntryFlags::NONE, vec![]),
            Err(FormatError::ChunkCount)
        );
        assert_eq!(
            FileManifest::new(0, 0, EntryFlags::NONE, vec![ObjectId::from_bytes([0; 32])]),
            Err(FormatError::ChunkCount)
        );
        assert_eq!(
            FileManifest::new(MAX_FILE_SIZE + 1, 0, EntryFlags::NONE, vec![]),
            Err(FormatError::FileTooLarge)
        );
    }

    #[test]
    fn manifest_decoding_is_strict() {
        let manifest =
            FileManifest::new(3, 0, EntryFlags::NONE, vec![ObjectId::from_bytes([9; 32])]).unwrap();
        let bytes = manifest.encode().unwrap();
        for cut in 0..bytes.len() {
            assert!(FileManifest::decode(&bytes[..cut]).is_err(), "cut {cut}");
        }
        let mut wrong = bytes.clone();
        wrong.push(0);
        assert_eq!(
            FileManifest::decode(&wrong),
            Err(FormatError::TrailingBytes)
        );
        let mut wrong = bytes.clone();
        wrong[0] = 0;
        assert_eq!(FileManifest::decode(&wrong), Err(FormatError::Version(0)));
        let mut wrong = bytes.clone();
        wrong[17..21].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(FileManifest::decode(&wrong), Err(FormatError::Flags(2)));
        let mut wrong = bytes.clone();
        wrong[21..25].copy_from_slice(&(MAX_MANIFEST_CHUNKS + 1).to_be_bytes());
        assert_eq!(FileManifest::decode(&wrong), Err(FormatError::TooLarge));
        let mut wrong = bytes;
        wrong[21..25].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(FileManifest::decode(&wrong), Err(FormatError::Truncated));
    }
}
