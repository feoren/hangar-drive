//! Object types, directory entry kinds and flags, and the size limits of objects.
//!
//! The server stores three types of encrypted objects. It sees the type in the object header
//! (the directory node headroom of the quota depends on it) but never the content.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Plaintext bytes of every chunk of a file but the last, which may be shorter.
pub const CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// Chunks one file manifest may list: 2^20 chunks of 4 MiB, 4 TiB per file.
pub const MAX_MANIFEST_CHUNKS: u32 = 1 << 20;

/// The largest file version 1 syncs.
pub const MAX_FILE_SIZE: u64 = CHUNK_SIZE * MAX_MANIFEST_CHUNKS as u64;

/// Entries one directory node may hold.
pub const MAX_DIRECTORY_ENTRIES: u32 = 1 << 18;

/// The largest plaintext of any object: a file manifest with [`MAX_MANIFEST_CHUNKS`] chunks
/// (header of 25 bytes plus 32 bytes per chunk). Chunks are at most [`CHUNK_SIZE`]; a directory
/// node must also fit this bound.
pub const MAX_OBJECT_PLAINTEXT_LEN: usize = 25 + 32 * MAX_MANIFEST_CHUNKS as usize;

/// The type of an encrypted object, part of its ID, its associated data and its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    /// Up to [`CHUNK_SIZE`] bytes of a file's content.
    Chunk,
    /// A file version: size, modification time, flags and the ordered chunk IDs.
    FileManifest,
    /// The entries of one directory.
    DirectoryNode,
}

/// A byte that is not an object type of version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown object type {0}")]
pub struct UnknownObjectType(pub u8);

impl ObjectType {
    /// The byte in IDs, associated data and headers.
    pub const fn to_byte(self) -> u8 {
        match self {
            ObjectType::Chunk => 1,
            ObjectType::FileManifest => 2,
            ObjectType::DirectoryNode => 3,
        }
    }

    /// The type of a header byte; every other value is refused.
    pub const fn from_byte(byte: u8) -> Result<Self, UnknownObjectType> {
        match byte {
            1 => Ok(ObjectType::Chunk),
            2 => Ok(ObjectType::FileManifest),
            3 => Ok(ObjectType::DirectoryNode),
            other => Err(UnknownObjectType(other)),
        }
    }

    /// The largest plaintext an object of this type may have.
    pub const fn max_plaintext_len(self) -> usize {
        match self {
            ObjectType::Chunk => CHUNK_SIZE as usize,
            ObjectType::FileManifest | ObjectType::DirectoryNode => MAX_OBJECT_PLAINTEXT_LEN,
        }
    }
}

/// What a directory node entry is (`kind`). A version 1 parser refuses every other value;
/// links can come later as a new kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A regular file; the child is a file manifest.
    File,
    /// A directory, also an empty one; the child is a directory node.
    Directory,
}

/// A byte that is not an entry kind of version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown entry kind {0}")]
pub struct UnknownEntryKind(pub u8);

impl EntryKind {
    /// The `kind` byte.
    pub const fn to_byte(self) -> u8 {
        match self {
            EntryKind::File => 1,
            EntryKind::Directory => 2,
        }
    }

    /// The kind of a `kind` byte; every other value is refused.
    pub const fn from_byte(byte: u8) -> Result<Self, UnknownEntryKind> {
        match byte {
            1 => Ok(EntryKind::File),
            2 => Ok(EntryKind::Directory),
            other => Err(UnknownEntryKind(other)),
        }
    }

    /// The type of the object the entry's child ID names.
    pub const fn child_type(self) -> ObjectType {
        match self {
            EntryKind::File => ObjectType::FileManifest,
            EntryKind::Directory => ObjectType::DirectoryNode,
        }
    }
}

/// The `flags` of a directory entry or file manifest. Version 1 knows one bit and refuses the
/// others, so a later flag cannot be dropped silently by an older device.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EntryFlags(u32);

/// Flag bits version 1 does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown flag bits {0:#x}")]
pub struct UnknownFlags(pub u32);

impl EntryFlags {
    /// Bit 0: the owner's execute bit (Linux and macOS read and write it; Windows keeps it).
    pub const EXECUTABLE: u32 = 1;
    const KNOWN: u32 = Self::EXECUTABLE;

    /// No flag set.
    pub const NONE: EntryFlags = EntryFlags(0);

    /// The flags of these bits, refusing unknown ones.
    pub const fn from_bits(bits: u32) -> Result<Self, UnknownFlags> {
        if bits & !Self::KNOWN != 0 {
            return Err(UnknownFlags(bits & !Self::KNOWN));
        }
        Ok(EntryFlags(bits))
    }

    /// The flags with only the execute bit as given.
    pub const fn executable(executable: bool) -> Self {
        EntryFlags(if executable { Self::EXECUTABLE } else { 0 })
    }

    /// Whether the execute bit is set.
    pub const fn is_executable(self) -> bool {
        self.0 & Self::EXECUTABLE != 0
    }

    /// The bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for EntryFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntryFlags({:#x})", self.0)
    }
}

/// Chunks a file of `size` bytes has: `ceil(size / CHUNK_SIZE)`, zero for an empty file.
pub const fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_types_round_trip_and_refuse_others() {
        for kind in [
            ObjectType::Chunk,
            ObjectType::FileManifest,
            ObjectType::DirectoryNode,
        ] {
            assert_eq!(ObjectType::from_byte(kind.to_byte()), Ok(kind));
        }
        assert_eq!(ObjectType::from_byte(0), Err(UnknownObjectType(0)));
        assert_eq!(ObjectType::from_byte(4), Err(UnknownObjectType(4)));
        assert_eq!(ObjectType::Chunk.to_byte(), 1);
        assert_eq!(ObjectType::FileManifest.to_byte(), 2);
        assert_eq!(ObjectType::DirectoryNode.to_byte(), 3);
    }

    #[test]
    fn entry_kinds_are_one_and_two_only() {
        assert_eq!(EntryKind::from_byte(1), Ok(EntryKind::File));
        assert_eq!(EntryKind::from_byte(2), Ok(EntryKind::Directory));
        for byte in [0u8, 3, 255] {
            assert_eq!(EntryKind::from_byte(byte), Err(UnknownEntryKind(byte)));
        }
        assert_eq!(EntryKind::File.child_type(), ObjectType::FileManifest);
        assert_eq!(EntryKind::Directory.child_type(), ObjectType::DirectoryNode);
    }

    #[test]
    fn flags_know_only_the_execute_bit() {
        assert!(EntryFlags::from_bits(1).unwrap().is_executable());
        assert!(!EntryFlags::from_bits(0).unwrap().is_executable());
        assert_eq!(EntryFlags::from_bits(2), Err(UnknownFlags(2)));
        assert_eq!(
            EntryFlags::from_bits(0x8000_0001),
            Err(UnknownFlags(0x8000_0000))
        );
        assert_eq!(EntryFlags::executable(true).bits(), 1);
    }

    #[test]
    fn chunk_counts_and_limits() {
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_SIZE), 1);
        assert_eq!(chunk_count(CHUNK_SIZE + 1), 2);
        assert_eq!(chunk_count(MAX_FILE_SIZE), u64::from(MAX_MANIFEST_CHUNKS));
        assert_eq!(MAX_FILE_SIZE, 4 << 40);
        assert_eq!(MAX_OBJECT_PLAINTEXT_LEN, 33_554_457);
        assert_eq!(ObjectType::Chunk.max_plaintext_len(), 4 << 20);
    }

    #[test]
    fn serializes_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&ObjectType::DirectoryNode).unwrap(),
            "\"directory_node\""
        );
        assert_eq!(serde_json::to_string(&EntryKind::File).unwrap(), "\"file\"");
    }
}
