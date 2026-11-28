//! The Windows side of [`super::LocalFs`]: every operation goes through directory handles
//! (security review L1), as on Unix ([`super::unix`]).
//!
//! The root is opened with `CreateFileW` and `FILE_FLAG_BACKUP_SEMANTICS |
//! FILE_FLAG_OPEN_REPARSE_POINT`, and every directory between it and the target with
//! `NtCreateFile` relative to the handle of the directory above it (`OBJECT_ATTRIBUTES.
//! RootDirectory`, the bare name as `ObjectName`) with `FILE_DIRECTORY_FILE |
//! FILE_OPEN_REPARSE_POINT`. A junction, a directory symbolic link or another reparse point on
//! the way is opened as itself and refused by its `FILE_ATTRIBUTE_REPARSE_POINT`, a file on the
//! way fails the open (`STATUS_NOT_A_DIRECTORY`); both are [`FsError::Changed`]. Where the index
//! knows a directory's file ID, the ID of the opened handle must match. The operation is then
//! relative to the handle of the directory that holds the target:
//!
//! - opening, creating and reading stats: `NtCreateFile` with the target's name relative to that
//!   handle, `FILE_OPEN_REPARSE_POINT` (a link in place of the target is the link itself, never
//!   what it points at) and `FILE_NON_DIRECTORY_FILE` or `FILE_DIRECTORY_FILE` where the kind is
//!   known;
//! - deleting: `SetFileInformationByHandle` with `FileDispositionInfoEx` and
//!   `FILE_DISPOSITION_FLAG_POSIX_SEMANTICS` on a handle of the target, `FileDispositionInfo`
//!   where the file system does not take the extended form (FAT, exFAT);
//! - renaming: `NtSetInformationFile` with `FileRenameInformation` on a handle of the source,
//!   `RootDirectory` set to the handle of the target's directory and the bare target name,
//!   `ReplaceIfExists` false where the caller expects "already exists";
//! - listing: `GetFileInformationByHandleEx` with `FileFullDirectoryInfo` on the directory handle.
//!
//! A path is never resolved twice: what was checked is the open handle, and a directory swapped
//! for a junction after the walk changes only what the path means; the operation still lands in
//! the directory that was checked, inside the root. Before, the directories were checked by path
//! and the operation resolved the path again.
//!
//! Names are passed to `NtCreateFile` as they are, below the Win32 path parser: no `\\?\` prefix,
//! no `MAX_PATH` limit for the path as a whole (each name has its own limit of 255 UTF-16 units),
//! and no mapping of reserved device names (`CON`, `NUL`), which [`super::name_problem`] refuses
//! before any of this anyway. A name with a path separator, a colon (an alternate data stream) or
//! a NUL, and `.` or `..`, is refused here as well, so no name can reach another directory or a
//! stream. Names are compared case-insensitively (`OBJ_CASE_INSENSITIVE`), as `CreateFileW` does.
//!
//! The file IDs and stats are read from the handles the same way as before (the 128-bit
//! `FileIdInfo` with the volume serial number, else the 64-bit file index; attributes, size and
//! write time from `GetFileInformationByHandle`), so the IDs in existing indexes stay valid (test
//! `handle_stats_match_std_metadata`).
//!
//! All unsafe code of the module is in the few calls of [`nt`] at the end, each with its
//! `SAFETY` note.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hangar_drive_protocol::name::RESERVED_ROOT_DIR;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
};
use windows_sys::Win32::Foundation::{STATUS_DELETE_PENDING, STATUS_NOT_A_DIRECTORY};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SYSTEM, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES,
    SYNCHRONIZE,
};

use super::{io_error, is_backup, millis, name_problem, RECOVERED_DIR, TEMP_DIR};
use crate::ports::{EntryType, FsError, ListEntry, Stat};
use crate::trash::QUARANTINE_DIR;

/// How deep the cleaning of the temporary directory and the quarantine descends. The engine
/// itself puts at most one level there; a deeper tree was made by someone else and is left
/// alone below this depth.
const CLEAN_DEPTH: u32 = 16;

/// The access of every directory handle on the way: list (also what makes the share mode count,
/// see [`Share::Pinned`]), traverse, read the attributes and the file ID.
const DIR_ACCESS: u32 = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

/// Attributes a replace carries over from the old file to the new one, as `ReplaceFileW` did
/// before (read-only is left out, so the engine can replace the file again).
const KEPT_ATTRIBUTES: u32 =
    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

/// The tag bit of reparse points that stand for another name (symbolic links, junctions); std's
/// `FileType::is_symlink` uses the same bit (`IsReparseTagNameSurrogate`).
const NAME_SURROGATE: u32 = 0x2000_0000;

/// What other openers may do while a directory handle is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Share {
    /// Read, write and delete: the directory can still be renamed or deleted by others, which
    /// changes nothing for the operation on the handle.
    All,
    /// Read and write, no delete: while the handle is open, nobody can rename, move or delete the
    /// directory (an open for `DELETE` fails with a sharing violation), so a path through it
    /// keeps its meaning. For the platform trash, which takes a path ([`pin`]).
    Pinned,
}

impl Share {
    fn mode(self) -> u32 {
        match self {
            Share::All => FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Share::Pinned => FILE_SHARE_READ | FILE_SHARE_WRITE,
        }
    }
}

/// The share mode of every file handle: as std's `OpenOptions`, so others keep their access.
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// An open directory (a handle that never went through a reparse point), shared by the places
/// in it.
#[derive(Debug, Clone)]
pub(super) struct Dir(Arc<OwnedHandle>);

impl Dir {
    /// The sync root. Its own path was canonicalized when the root was opened and lies outside
    /// the root; its last component is opened as itself and must be a plain directory.
    fn open_root(root: &Path, share: Share) -> Result<Dir, FsError> {
        let file = std::fs::OpenOptions::new()
            .access_mode(DIR_ACCESS)
            .share_mode(share.mode())
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(root)
            .map_err(|e| io_error(&e))?;
        let dir = Dir(Arc::new(OwnedHandle::from(file)));
        let info = nt::info(dir.handle()).map_err(|e| io_error(&e))?;
        if !info.plain_dir() {
            return Err(FsError::Changed);
        }
        Ok(dir)
    }

    fn handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }

    /// The directory `name` in this one, opened as itself. `Ok(None)` when it does not exist; a
    /// reparse point or a file in its place is [`FsError::Changed`].
    fn open_dir(&self, name: &OsStr, share: Share) -> Result<Option<(Dir, Info)>, FsError> {
        let open = nt::Open {
            access: DIR_ACCESS,
            share: share.mode(),
            disposition: FILE_OPEN,
            options: FILE_DIRECTORY_FILE,
            attributes: 0,
        };
        let handle = match nt::open(self.handle(), name, open) {
            Ok(h) => h,
            Err(e) if e.not_found() => return Ok(None),
            Err(e) if e.0 == STATUS_NOT_A_DIRECTORY => return Err(FsError::Changed),
            Err(e) => return Err(io_error(&e.into())),
        };
        let dir = Dir(Arc::new(handle));
        let info = nt::info(dir.handle()).map_err(|e| io_error(&e))?;
        if !info.plain_dir() {
            return Err(FsError::Changed);
        }
        Ok(Some((dir, info)))
    }

    /// The entry `name` in this directory, opened as itself with `open`.
    fn open_entry(&self, name: &OsStr, open: nt::Open) -> Result<OwnedHandle, nt::Status> {
        nt::open(self.handle(), name, open)
    }

    /// The stat of the entry `name` itself; `None` when it does not exist, and with `pending`
    /// also when it is about to be deleted (`STATUS_DELETE_PENDING`).
    fn stat_of(&self, name: &OsStr, pending: bool) -> io::Result<Option<Stat>> {
        let open = nt::Open {
            access: FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options: 0,
            attributes: 0,
        };
        match self.open_entry(name, open) {
            Ok(h) => nt::info(h.as_handle()).map(|info| Some(info.stat())),
            Err(e) if e.not_found() => Ok(None),
            Err(e) if pending && e.0 == STATUS_DELETE_PENDING => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The entries of this directory with their stats; an entry that disappears between the
    /// listing and its stat (or is about to be deleted) is left out.
    ///
    /// An entry whose own stat is refused (an ACL, a filter driver; security review L4) keeps
    /// its place with the stats of its directory record and no file ID, instead of failing the
    /// whole listing: a scan matches it by path (an unknown file ID counts as the same file), so
    /// it is neither lost nor taken for a delete. Its kind follows the record's attributes; a
    /// reparse point is [`EntryType::Reparse`] (the record has no reliable tag), never entered.
    fn entries(&self) -> Result<Vec<(OsString, Stat)>, FsError> {
        let records = nt::list(self.handle()).map_err(|e| io_error(&e))?;
        let mut out = Vec::new();
        for record in records {
            match self.stat_of(&record.name, true) {
                Ok(Some(stat)) => out.push((record.name, stat)),
                Ok(None) => {}
                Err(_) => {
                    let info = Info {
                        attributes: record.attributes,
                        tag: 0,
                        size: record.size,
                        write_time: record.write_time,
                        id: 0,
                        links: 0,
                    };
                    let mut stat = info.stat();
                    stat.file_id = None;
                    out.push((record.name, stat));
                }
            }
        }
        Ok(out)
    }

    /// Removes the entry `name` itself (a file, a link or a reparse point, never what it points
    /// at; a directory only when it is empty).
    fn remove_entry(&self, name: &OsStr, options: u32) -> io::Result<()> {
        let open = nt::Open {
            access: DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options,
            attributes: 0,
        };
        let handle = self.open_entry(name, open)?;
        nt::dispose(handle.as_handle())
    }
}

/// What the module needs from the stat of a handle.
#[derive(Debug, Clone, Copy)]
struct Info {
    attributes: u32,
    /// The reparse tag; 0 when the entry is no reparse point.
    tag: u32,
    size: u64,
    /// The last write time in 100 ns intervals since 1601 (a `FILETIME`).
    write_time: u64,
    id: u128,
    /// The number of names (hard links) of the file; 0 where the source does not tell.
    links: u32,
}

impl Info {
    fn reparse(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    fn plain_dir(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && !self.reparse()
    }

    /// The stat, with the kinds decided as std's `FileType` decides them (a name surrogate
    /// reparse point is a link, any other reparse point is [`EntryType::Reparse`]).
    fn stat(&self) -> Stat {
        let kind = if self.reparse() && self.tag & NAME_SURROGATE != 0 {
            EntryType::Symlink
        } else if self.reparse() {
            EntryType::Reparse
        } else if self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            EntryType::Directory
        } else if self.attributes & FILE_ATTRIBUTE_SYSTEM != 0 {
            EntryType::System
        } else {
            EntryType::File
        };
        let regular = matches!(kind, EntryType::File | EntryType::Directory);
        Stat {
            kind,
            size: if kind == EntryType::File {
                self.size
            } else {
                0
            },
            mtime_ms: millis(file_time(self.write_time)),
            file_id: regular.then_some(self.id),
            // The execute bit exists on Unix only.
            executable: false,
        }
    }
}

/// The point in time of a `FILETIME`, as std builds `SystemTime` from it.
fn file_time(intervals: u64) -> SystemTime {
    /// 100 ns intervals between 1601-01-01 and 1970-01-01.
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if intervals >= EPOCH_DIFF {
        let nanos = u128::from(intervals - EPOCH_DIFF) * 100;
        UNIX_EPOCH
            .checked_add(duration(nanos))
            .unwrap_or(UNIX_EPOCH)
    } else {
        let nanos = u128::from(EPOCH_DIFF - intervals) * 100;
        UNIX_EPOCH
            .checked_sub(duration(nanos))
            .unwrap_or(UNIX_EPOCH)
    }
}

fn duration(nanos: u128) -> Duration {
    let secs = u64::try_from(nanos / 1_000_000_000).unwrap_or(u64::MAX);
    // The remainder is below 10^9 and fits.
    let sub = u32::try_from(nanos % 1_000_000_000).unwrap_or(0);
    Duration::new(secs, sub)
}

/// An opened directory below the root and its path (for messages and the platform trash).
#[derive(Debug, Clone)]
pub(super) struct Folder {
    dir: Dir,
    full: PathBuf,
}

impl Folder {
    /// The place `name` in this directory.
    pub(super) fn child(&self, name: &OsStr) -> Spot {
        Spot {
            dir: self.dir.clone(),
            name: name.to_owned(),
            full: self.full.join(name),
        }
    }

    /// The stat of the directory itself.
    pub(super) fn stat(&self) -> Result<Option<Stat>, FsError> {
        nt::info(self.dir.handle())
            .map(|info| Some(info.stat()))
            .map_err(|e| io_error(&e))
    }

    /// The listing of the directory (L10 as on every platform: a name that fails the checks is
    /// [`EntryType::Other`]).
    pub(super) fn list(&self) -> Result<Vec<ListEntry>, FsError> {
        let mut out = Vec::new();
        for (os_name, mut stat) in self.dir.entries()? {
            let display = os_name.to_string_lossy().into_owned();
            let name = os_name.into_string().ok();
            if name.as_deref().is_some_and(|n| name_problem(n).is_some()) {
                stat.kind = EntryType::Other;
                stat.file_id = None;
            }
            out.push(ListEntry {
                name,
                display,
                stat,
            });
        }
        Ok(out)
    }
}

/// Where an entry is: the open directory that holds it and its name in there. Every operation
/// is relative to that handle (module docs).
#[derive(Debug, Clone)]
pub(super) struct Spot {
    dir: Dir,
    name: OsString,
    full: PathBuf,
}

impl Spot {
    /// The path, for messages and for the platform trash, which takes paths only.
    pub(super) fn full(&self) -> &Path {
        &self.full
    }

    /// The name of the entry.
    pub(super) fn name(&self) -> &OsStr {
        &self.name
    }

    /// The place `name` in the same directory.
    pub(super) fn sibling(&self, name: &str) -> Spot {
        Spot {
            dir: self.dir.clone(),
            name: OsString::from(name),
            full: self.full.with_file_name(name),
        }
    }

    /// The stat of the entry itself (a link or reparse point as such); `None` if it does not
    /// exist.
    pub(super) fn stat(&self) -> Result<Option<Stat>, FsError> {
        self.dir
            .stat_of(&self.name, false)
            .map_err(|e| io_error(&e))
    }

    /// Opens an existing file for reading and writing, never through a reparse point (the part
    /// file of a download in parts, which is checked through the same handle it lands with).
    pub(super) fn open_read_write(&self) -> io::Result<File> {
        self.open_file(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
    }

    /// The entry's NTFS `ChangeTime`, which every write and metadata change moves, also one
    /// that sets the modification time back; `None` if the entry does not exist.
    pub(super) fn change_stamp(&self) -> Result<Option<u64>, FsError> {
        let open = nt::Open {
            access: FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options: 0,
            attributes: 0,
        };
        match self.dir.open_entry(&self.name, open) {
            Ok(h) => nt::change_time(h.as_handle())
                .map(Some)
                .map_err(|e| io_error(&e)),
            Err(e) if e.not_found() => Ok(None),
            Err(e) => Err(io_error(&io::Error::from(e))),
        }
    }

    /// Opens an existing file with `access`, never through a reparse point: a link or a cloud
    /// placeholder in place of the file is opened as itself and refused (N6).
    fn open_file(&self, access: u32) -> io::Result<File> {
        let open = nt::Open {
            // The reparse check below reads the attributes, which FILE_GENERIC_WRITE lacks.
            access: access | FILE_READ_ATTRIBUTES,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options: FILE_NON_DIRECTORY_FILE,
            attributes: 0,
        };
        let handle = self.dir.open_entry(&self.name, open)?;
        if nt::info(handle.as_handle())?.reparse() {
            return Err(io::Error::other("the file is a reparse point"));
        }
        Ok(File::from(handle))
    }

    /// Opens an existing file for reading (as std's `read(true)`).
    pub(super) fn open_read(&self) -> io::Result<File> {
        self.open_file(FILE_GENERIC_READ)
    }

    /// Opens an existing file for writing its metadata (as std's `write(true)`, no create, no
    /// truncate).
    pub(super) fn open_write(&self) -> io::Result<File> {
        self.open_file(FILE_GENERIC_WRITE)
    }

    /// Creates a new file that must not exist yet, as std's `create_new(true)`.
    pub(super) fn create_new(&self) -> io::Result<File> {
        let open = nt::Open {
            access: FILE_GENERIC_WRITE,
            share: SHARE_ALL,
            disposition: FILE_CREATE,
            options: FILE_NON_DIRECTORY_FILE,
            attributes: FILE_ATTRIBUTE_NORMAL,
        };
        Ok(File::from(self.dir.open_entry(&self.name, open)?))
    }

    /// Creates the directory.
    pub(super) fn create_dir(&self) -> io::Result<()> {
        let open = nt::Open {
            access: FILE_LIST_DIRECTORY | SYNCHRONIZE,
            share: SHARE_ALL,
            disposition: FILE_CREATE,
            options: FILE_DIRECTORY_FILE,
            attributes: 0,
        };
        self.dir.open_entry(&self.name, open).map(drop)?;
        Ok(())
    }

    /// The file ID of the entry if it is a plain directory.
    pub(super) fn dir_id(&self) -> Option<u128> {
        match self.dir.open_dir(&self.name, Share::All) {
            Ok(Some((_, info))) => Some(info.id),
            _ => None,
        }
    }

    /// Removes the entry, a file or a link (never what a link points at).
    pub(super) fn remove_file(&self) -> io::Result<()> {
        self.dir.remove_entry(&self.name, FILE_NON_DIRECTORY_FILE)
    }

    /// Removes the entry if it is an empty plain directory; a reparse point or a file in its
    /// place is [`FsError::Changed`].
    pub(super) fn remove_dir(&self) -> Result<(), FsError> {
        let open = nt::Open {
            access: DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options: FILE_DIRECTORY_FILE,
            attributes: 0,
        };
        let handle = match self.dir.open_entry(&self.name, open) {
            Ok(h) => h,
            Err(e) if e.0 == STATUS_NOT_A_DIRECTORY => return Err(FsError::Changed),
            Err(e) => return Err(io_error(&e.into())),
        };
        if !nt::info(handle.as_handle())
            .map_err(|e| io_error(&e))?
            .plain_dir()
        {
            return Err(FsError::Changed);
        }
        super::with_lock_retry(|| nt::dispose(handle.as_handle()))
    }

    /// A rename that fails with "already exists" instead of replacing (L2).
    pub(super) fn rename_noreplace(&self, to: &Spot) -> io::Result<()> {
        self.rename_with(to, false, 0)
    }

    /// [`Spot::rename_noreplace`] for a file only: a directory or a directory link in place of
    /// the file is not moved.
    pub(super) fn rename_file_noreplace(&self, to: &Spot) -> io::Result<()> {
        self.rename_with(to, false, FILE_NON_DIRECTORY_FILE)
    }

    fn rename_with(&self, to: &Spot, replace: bool, options: u32) -> io::Result<()> {
        let open = nt::Open {
            access: DELETE | SYNCHRONIZE,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options,
            attributes: 0,
        };
        let handle = self.dir.open_entry(&self.name, open)?;
        nt::rename(handle.as_handle(), to.dir.handle(), &to.name, replace)
    }

    /// Gives this (new) file the creation time and the [`KEPT_ATTRIBUTES`] of `old`, as
    /// `ReplaceFileW` did for a replace. Best effort: a failure leaves the new file as it is.
    pub(super) fn inherit_from(&self, old: &Spot) {
        let read = nt::Open {
            access: FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            share: SHARE_ALL,
            disposition: FILE_OPEN,
            options: FILE_NON_DIRECTORY_FILE,
            attributes: 0,
        };
        let write = nt::Open {
            access: FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
            ..read
        };
        let (Ok(from), Ok(to)) = (
            old.dir.open_entry(&old.name, read),
            self.dir.open_entry(&self.name, write),
        ) else {
            return;
        };
        let _ = nt::inherit(from.as_handle(), to.as_handle(), KEPT_ATTRIBUTES);
    }
}

/// Directory handles held without `FILE_SHARE_DELETE` from the root down to the directory of
/// an entry ([`pin`]): while this lives, none of them can be renamed, moved or deleted.
#[derive(Debug)]
pub(super) struct Pin {
    _held: Vec<Dir>,
    spot: Spot,
}

impl Pin {
    /// The entry, relative to the pinned directory that holds it.
    pub(super) fn spot(&self) -> &Spot {
        &self.spot
    }
}

/// Opens `components` below `root` one directory at a time (module docs). The file ID of the
/// first `checked` components is compared with the index where it knows one; a mismatch, a
/// reparse point or a file on the way is [`FsError::Changed`]. `Ok(None)` when one of them does
/// not exist. With `held`, every handle on the way is kept there.
fn walk(
    root: &Path,
    components: &[String],
    checked: usize,
    expected: &BTreeMap<Vec<String>, u128>,
    share: Share,
    mut held: Option<&mut Vec<Dir>>,
) -> Result<Option<Dir>, FsError> {
    let mut dir = Dir::open_root(root, share)?;
    for (i, name) in components.iter().enumerate() {
        let Some((next, info)) = dir.open_dir(OsStr::new(name), share)? else {
            return Ok(None);
        };
        if i < checked {
            if let Some(want) = expected.get(&components[..=i]) {
                if info.id != *want {
                    return Err(FsError::Changed);
                }
            }
        }
        if let Some(held) = held.as_deref_mut() {
            held.push(dir);
        }
        dir = next;
    }
    Ok(Some(dir))
}

/// The place of `path` (not empty; every name already passed the name checks): the directory
/// that holds it, opened by [`walk`], and its name. `Ok(None)` when a directory on the way does
/// not exist.
pub(super) fn locate(
    root: &Path,
    full: PathBuf,
    path: &[String],
    expected: &BTreeMap<Vec<String>, u128>,
) -> Result<Option<Spot>, FsError> {
    let Some((name, parents)) = path.split_last() else {
        return Err(FsError::NotFound);
    };
    Ok(
        walk(root, parents, parents.len(), expected, Share::All, None)?.map(|dir| Spot {
            dir,
            name: OsString::from(name),
            full,
        }),
    )
}

/// The directory `path` itself, opened by [`walk`] (the root for an empty path). The index's
/// file IDs are compared for the directories above it, as for every other operation; the
/// directory itself only has to be a plain directory.
pub(super) fn open_folder(
    root: &Path,
    full: PathBuf,
    path: &[String],
    expected: &BTreeMap<Vec<String>, u128>,
) -> Result<Folder, FsError> {
    let checked = path.len().saturating_sub(1);
    match walk(root, path, checked, expected, Share::All, None)? {
        Some(dir) => Ok(Folder { dir, full }),
        None => Err(FsError::NotFound),
    }
}

/// The directories from the root down to the one that holds `spot` (found at `path`), walked
/// again with handles that do not share delete, so what the path of `spot` means in the file
/// system cannot change while the [`Pin`] lives; for the platform trash, which takes a path
/// (ADR 0001, amendment "Directory handles on Windows"). The shell resolves paths through its
/// own namespace as well, where a folder can be a junction the file system does not see; the
/// trash checks that resolution itself (`crate::trash`). The pinned directory must be the one `spot` was found in (same file
/// ID), else [`FsError::Changed`]. A directory that someone holds open for deleting at this
/// moment fails the open with a sharing violation ([`FsError::Locked`]).
pub(super) fn pin(
    root: &Path,
    path: &[String],
    expected: &BTreeMap<Vec<String>, u128>,
    spot: &Spot,
) -> Result<Pin, FsError> {
    let Some((name, parents)) = path.split_last() else {
        return Err(FsError::NotFound);
    };
    let mut held = Vec::new();
    let dir = walk(
        root,
        parents,
        parents.len(),
        expected,
        Share::Pinned,
        Some(&mut held),
    )?
    .ok_or(FsError::Changed)?;
    let id = |d: &Dir| nt::info(d.handle()).map(|i| i.id).map_err(|e| io_error(&e));
    if id(&dir)? != id(&spot.dir)? {
        return Err(FsError::Changed);
    }
    held.push(dir.clone());
    Ok(Pin {
        _held: held,
        spot: Spot {
            dir,
            name: OsString::from(name),
            full: spot.full.clone(),
        },
    })
}

/// `.hangar-drive/<parts>` below the root, each level created or opened in one step relative to
/// the one above (`FILE_OPEN_IF | FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT`, security review
/// N5): a junction or link at any level is opened as itself and refused, never followed.
pub(super) fn reserved_dir(root: &Path, parts: &[&str]) -> Result<Folder, FsError> {
    let refused = || FsError::CannotSync("the reserved directory is not a plain directory".into());
    let mut dir = Dir::open_root(root, Share::All)?;
    let mut full = root.to_path_buf();
    for part in std::iter::once(RESERVED_ROOT_DIR).chain(parts.iter().copied()) {
        let open = nt::Open {
            access: DIR_ACCESS,
            share: SHARE_ALL,
            disposition: FILE_OPEN_IF,
            options: FILE_DIRECTORY_FILE,
            attributes: 0,
        };
        let handle = match dir.open_entry(OsStr::new(part), open) {
            Ok(h) => h,
            Err(e) if e.0 == STATUS_NOT_A_DIRECTORY => return Err(refused()),
            Err(e) => return Err(io_error(&e.into())),
        };
        let next = Dir(Arc::new(handle));
        if !nt::info(next.handle())
            .map_err(|e| io_error(&e))?
            .plain_dir()
        {
            return Err(refused());
        }
        dir = next;
        full.push(part);
    }
    Ok(Folder { dir, full })
}

/// `.hangar-drive/<parts>` if every level exists and is a plain directory, opened without
/// creating anything.
fn existing_reserved(root: &Path, parts: &[&str]) -> Option<Dir> {
    let mut dir = Dir::open_root(root, Share::All).ok()?;
    for part in std::iter::once(RESERVED_ROOT_DIR).chain(parts.iter().copied()) {
        dir = dir.open_dir(OsStr::new(part), Share::All).ok()??.0;
    }
    Some(dir)
}

/// The file ID of an open file, as [`Spot::stat`] reports it.
pub(super) fn file_id_of(file: &File) -> Option<u128> {
    nt::info(file.as_handle()).ok().map(|info| info.id)
}

/// Whether an open file has no other name: a hard link made to it from elsewhere could change
/// it behind the check of its content.
pub(super) fn single_link(file: &File) -> bool {
    nt::info(file.as_handle()).is_ok_and(|info| info.links == 1)
}

/// Empties the reserved `tmp` directory (writes a crash left behind); backups of a replace
/// move into the quarantine instead (L3). Only plain directories are entered, each through its
/// handle, so a junction or link put at any level removes nothing outside.
pub(super) fn clean_temp(root: &Path) {
    let Some(temp) = existing_reserved(root, &[TEMP_DIR]) else {
        return;
    };
    let Ok(entries) = temp.entries() else {
        return;
    };
    let temp_path = root.join(RESERVED_ROOT_DIR).join(TEMP_DIR);
    let mut recovered: Option<Folder> = None;
    for (name, stat) in entries {
        // The old file of a replace a crash interrupted (security review L3): recovered into
        // the quarantine, never deleted. A backup that cannot move stays for the next start.
        if stat.kind == EntryType::File && is_backup(&name) {
            if recovered.is_none() {
                recovered = reserved_dir(root, &[QUARANTINE_DIR, RECOVERED_DIR]).ok();
            }
            if let Some(into) = &recovered {
                let from = Spot {
                    dir: temp.clone(),
                    full: temp_path.join(&name),
                    name: name.clone(),
                };
                let _ = from.rename_file_noreplace(&into.child(&name));
            }
            continue;
        }
        remove_tree(&temp, &name, &stat, CLEAN_DEPTH);
    }
}

/// Removes the entries of the quarantine whose time is past [`crate::trash::expired`], through
/// handles as [`clean_temp`] does.
pub(super) fn clean_quarantine(root: &Path, now: SystemTime) {
    let Some(quarantine) = existing_reserved(root, &[QUARANTINE_DIR]) else {
        return;
    };
    let Ok(entries) = quarantine.entries() else {
        return;
    };
    for (name, stat) in entries {
        // The entry's directory was made when the file moved in.
        if crate::trash::expired(super::system_time(stat.mtime_ms), now) {
            remove_tree(&quarantine, &name, &stat, CLEAN_DEPTH);
        }
    }
}

/// Removes everything in `dir`, down to `depth` levels. Errors leave the entry in place for the
/// next start.
fn empty(dir: &Dir, depth: u32) {
    let Ok(entries) = dir.entries() else {
        return;
    };
    for (name, stat) in entries {
        remove_tree(dir, &name, &stat, depth);
    }
}

/// Removes the entry `name` of `dir`: a plain directory with its content through its own handle
/// (down to `depth` levels), anything else as itself (a junction or link is removed, never
/// followed).
fn remove_tree(dir: &Dir, name: &OsStr, stat: &Stat, depth: u32) {
    if stat.kind == EntryType::Directory {
        if depth == 0 {
            return;
        }
        if let Ok(Some((child, _))) = dir.open_dir(name, Share::All) {
            empty(&child, depth - 1);
        }
        let _ = dir.remove_entry(name, FILE_DIRECTORY_FILE);
    } else {
        let _ = dir.remove_entry(name, 0);
    }
}

/// The calls into the system, each with its `SAFETY` note; everything above is safe code.
mod nt {
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileRenameInformation, NtCreateFile, NtSetInformationFile, FILE_OPEN_REPARSE_POINT,
        FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        RtlNtStatusToDosError, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER,
        ERROR_NOT_SUPPORTED, ERROR_NO_MORE_FILES, HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE,
        STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo, FileDispositionInfoEx,
        FileFullDirectoryInfo, FileFullDirectoryRestartInfo, FileIdInfo,
        GetFileInformationByHandle, GetFileInformationByHandleEx, SetFileInformationByHandle,
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
        FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use super::Info;

    /// A failed `NTSTATUS`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct Status(pub(super) NTSTATUS);

    impl Status {
        pub(super) fn not_found(self) -> bool {
            self.0 == STATUS_OBJECT_NAME_NOT_FOUND || self.0 == STATUS_OBJECT_PATH_NOT_FOUND
        }
    }

    impl From<Status> for io::Error {
        fn from(status: Status) -> io::Error {
            // SAFETY: a pure conversion of a status value, no pointers.
            let code = unsafe { RtlNtStatusToDosError(status.0) };
            io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX))
        }
    }

    /// The parameters of one `NtCreateFile`.
    #[derive(Debug, Clone, Copy)]
    pub(super) struct Open {
        pub(super) access: u32,
        pub(super) share: u32,
        pub(super) disposition: u32,
        pub(super) options: u32,
        pub(super) attributes: u32,
    }

    /// The UTF-16 form of a single name, refused when it could name anything but an entry of the
    /// directory itself: empty, `.`, `..`, a path separator, a colon (an alternate data stream
    /// or a device prefix) or a NUL, or longer than a `UNICODE_STRING` can carry.
    fn single_name(name: &OsStr) -> io::Result<Vec<u16>> {
        let wide: Vec<u16> = name.encode_wide().collect();
        let dot = u16::from(b'.');
        let refused = wide.is_empty()
            || wide == [dot]
            || wide == [dot, dot]
            || wide.iter().any(|&c| {
                c == 0 || c == u16::from(b'\\') || c == u16::from(b'/') || c == u16::from(b':')
            })
            || wide.len() > usize::from(u16::MAX / 2);
        if refused {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a single name",
            ));
        }
        Ok(wide)
    }

    /// `NtCreateFile` of `name` relative to the directory `dir`, never through a reparse point
    /// in `name` (`FILE_OPEN_REPARSE_POINT`), synchronous, case-insensitive.
    pub(super) fn open(
        dir: BorrowedHandle<'_>,
        name: &OsStr,
        open: Open,
    ) -> Result<OwnedHandle, Status> {
        // STATUS_OBJECT_NAME_INVALID for a name that is not a single name.
        let wide = single_name(name).map_err(|_| Status(0xC000_0033_u32 as i32))?;
        let bytes = u16::try_from(wide.len() * 2).map_err(|_| Status(0xC000_0033_u32 as i32))?;
        let object_name = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: wide.as_ptr().cast_mut(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: dir.as_raw_handle() as HANDLE,
            ObjectName: &object_name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut handle: HANDLE = std::ptr::null_mut();
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: every pointer refers to a local that lives across the call (`handle`,
        // `attributes` with `object_name`, whose buffer `wide` outlives the call, and
        // `status_block`); `dir` is an open handle borrowed for the call; the allocation size
        // and the extended attributes are null with length 0, as documented for "none".
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                open.access,
                &attributes,
                &mut status_block,
                std::ptr::null(),
                open.attributes,
                open.share,
                open.disposition,
                open.options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        if status < 0 {
            return Err(Status(status));
        }
        // SAFETY: the call succeeded, so `handle` is a new open handle that nothing else owns.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.cast()) })
    }

    /// The `ChangeTime` of an open entry, in 100 ns intervals since 1601.
    pub(super) fn change_time(handle: BorrowedHandle<'_>) -> io::Result<u64> {
        let basic: FILE_BASIC_INFO = query(handle, FileBasicInfo)?;
        Ok(basic.ChangeTime as u64)
    }

    /// `GetFileInformationByHandleEx` into a plain data structure `T`.
    fn query<T: Copy>(
        handle: BorrowedHandle<'_>,
        class: FILE_INFO_BY_HANDLE_CLASS,
    ) -> io::Result<T> {
        let mut out = std::mem::MaybeUninit::<T>::zeroed();
        // SAFETY: `out` is writable memory of exactly the size passed, for a structure of plain
        // integers that the call fills for `class`; `handle` is open for the call.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle() as HANDLE,
                class,
                out.as_mut_ptr().cast(),
                std::mem::size_of::<T>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call succeeded and wrote the structure; it was zeroed before anyway, and
        // every bit pattern is valid for its integer fields.
        Ok(unsafe { out.assume_init() })
    }

    /// `SetFileInformationByHandle` with the `len` bytes at `data`.
    ///
    /// # Safety
    /// `data` must point to `len` readable bytes that form a valid structure for `class`.
    unsafe fn set(
        handle: BorrowedHandle<'_>,
        class: FILE_INFO_BY_HANDLE_CLASS,
        data: *const std::ffi::c_void,
        len: usize,
    ) -> io::Result<()> {
        // `len` is passed on exactly as given: the system reads `len` bytes at `data`, and the
        // caller vouches for exactly those.
        let len = u32::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: the caller guarantees that `len` bytes at `data` are readable and form the
        // structure for `class`; `handle` is open for the call.
        let ok = unsafe {
            SetFileInformationByHandle(handle.as_raw_handle() as HANDLE, class, data, len)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Attributes, reparse tag, size, write time and file ID of an open handle. The ID is the
    /// 128-bit NTFS ID with the volume serial number where the volume has one (`FileIdInfo`),
    /// else the 64-bit file index, in the same form the index always stored.
    pub(super) fn info(handle: BorrowedHandle<'_>) -> io::Result<Info> {
        let mut basic = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        // SAFETY: `basic` is writable memory of the structure's size, which the call fills;
        // `handle` is open for the call.
        if unsafe {
            GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, basic.as_mut_ptr())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call succeeded and wrote the structure of plain integers (zeroed before).
        let basic = unsafe { basic.assume_init() };
        let id = match query::<FILE_ID_INFO>(handle, FileIdInfo) {
            Ok(info) => {
                u128::from(info.VolumeSerialNumber).rotate_left(64)
                    ^ u128::from_le_bytes(info.FileId.Identifier)
            }
            Err(_) => {
                (u128::from(basic.dwVolumeSerialNumber) << 64)
                    | (u128::from(basic.nFileIndexHigh) << 32)
                    | u128::from(basic.nFileIndexLow)
            }
        };
        let tag = if basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            query::<FILE_ATTRIBUTE_TAG_INFO>(handle, FileAttributeTagInfo)?.ReparseTag
        } else {
            0
        };
        let write = &basic.ftLastWriteTime;
        Ok(Info {
            attributes: basic.dwFileAttributes,
            tag,
            size: (u64::from(basic.nFileSizeHigh) << 32) | u64::from(basic.nFileSizeLow),
            write_time: (u64::from(write.dwHighDateTime) << 32) | u64::from(write.dwLowDateTime),
            id,
            links: basic.nNumberOfLinks,
        })
    }

    /// Marks the open entry for deletion: POSIX semantics where the file system has them (the
    /// name goes when the handle closes, even while others hold it open), the classic
    /// disposition elsewhere. A read-only file is refused, as `DeleteFileW` refuses it.
    pub(super) fn dispose(handle: BorrowedHandle<'_>) -> io::Result<()> {
        let ex = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // SAFETY: `ex` is a complete FILE_DISPOSITION_INFO_EX that lives across the call.
        let result = unsafe {
            set(
                handle,
                FileDispositionInfoEx,
                (&ex as *const FILE_DISPOSITION_INFO_EX).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO_EX>(),
            )
        };
        match result {
            Err(e) if unsupported(&e) => {
                let classic = FILE_DISPOSITION_INFO { DeleteFile: true };
                // SAFETY: `classic` is a complete FILE_DISPOSITION_INFO that lives across the
                // call.
                unsafe {
                    set(
                        handle,
                        FileDispositionInfo,
                        (&classic as *const FILE_DISPOSITION_INFO).cast(),
                        std::mem::size_of::<FILE_DISPOSITION_INFO>(),
                    )
                }
            }
            other => other,
        }
    }

    /// Whether a call failed because the file system or the system lacks the information class.
    fn unsupported(e: &io::Error) -> bool {
        e.raw_os_error().is_some_and(|code| {
            [
                ERROR_INVALID_PARAMETER,
                ERROR_NOT_SUPPORTED,
                ERROR_INVALID_FUNCTION,
            ]
            .iter()
            .any(|&c| i32::try_from(c) == Ok(code))
        })
    }

    /// Renames the open entry to `name` in the directory `to_dir`: `NtSetInformationFile` with
    /// `FileRenameInformation` and `RootDirectory`; with `replace` false an existing entry of
    /// that name is "already exists" (`STATUS_OBJECT_NAME_COLLISION`). `SetFileInformationByHandle`
    /// with `FileRenameInfo` refuses a `RootDirectory` with `ERROR_INVALID_PARAMETER` (measured on
    /// Windows 11), so the native call is used, whose documentation defines `RootDirectory` as
    /// the directory the new name is relative to.
    pub(super) fn rename(
        handle: BorrowedHandle<'_>,
        to_dir: BorrowedHandle<'_>,
        name: &OsStr,
        replace: bool,
    ) -> io::Result<()> {
        let wide = single_name(name)?;
        let name_offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
        let len = name_offset + wide.len() * 2;
        // u64 cells, so the structure (which holds a handle) is aligned, and never shorter than
        // the structure itself.
        let cells = len
            .max(std::mem::size_of::<FILE_RENAME_INFORMATION>())
            .div_ceil(8);
        let mut buf = vec![0u64; cells];
        let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let name_bytes = u32::try_from(wide.len() * 2)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // The call refuses a length below the structure's size (STATUS_INFO_LENGTH_MISMATCH).
        let len = len.max(std::mem::size_of::<FILE_RENAME_INFORMATION>());
        let len = u32::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `buf` is zeroed, aligned for FILE_RENAME_INFORMATION and at least `len` bytes
        // long, which covers the fixed part and the name; the fields are written in place, and
        // the name is copied to its offset, within the buffer.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = replace;
            (*info).RootDirectory = to_dir.as_raw_handle() as HANDLE;
            (*info).FileNameLength = name_bytes;
            std::ptr::copy_nonoverlapping(
                wide.as_ptr(),
                buf.as_mut_ptr().cast::<u8>().add(name_offset).cast::<u16>(),
                wide.len(),
            );
        }
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `buf` holds a complete FILE_RENAME_INFORMATION with its name in its first
        // `len` bytes and lives across the call, as does `status_block`; `handle` and `to_dir`
        // are open for the call.
        let status = unsafe {
            NtSetInformationFile(
                handle.as_raw_handle() as HANDLE,
                &mut status_block,
                buf.as_ptr().cast(),
                len,
                FileRenameInformation,
            )
        };
        if status < 0 {
            return Err(Status(status).into());
        }
        Ok(())
    }

    /// Copies the creation time and the attributes in `mask` of `from` to `to` (both open
    /// handles, `to` with `FILE_WRITE_ATTRIBUTES`); the other times of `to` stay as they are.
    pub(super) fn inherit(
        from: BorrowedHandle<'_>,
        to: BorrowedHandle<'_>,
        mask: u32,
    ) -> io::Result<()> {
        let old: FILE_BASIC_INFO = query(from, FileBasicInfo)?;
        let new: FILE_BASIC_INFO = query(to, FileBasicInfo)?;
        let mut attributes = (new.FileAttributes & !mask) | (old.FileAttributes & mask);
        if attributes == 0 {
            attributes = FILE_ATTRIBUTE_NORMAL;
        }
        let update = FILE_BASIC_INFO {
            CreationTime: old.CreationTime,
            // 0 leaves a time unchanged.
            LastAccessTime: 0,
            LastWriteTime: 0,
            ChangeTime: 0,
            FileAttributes: attributes,
        };
        // SAFETY: `update` is a complete FILE_BASIC_INFO that lives across the call.
        unsafe {
            set(
                to,
                FileBasicInfo,
                (&update as *const FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>(),
            )
        }
    }

    /// The records of the directory of `handle` (opened with `FILE_LIST_DIRECTORY`), without
    /// `.` and `..`, from the start of the directory.
    pub(super) fn list(handle: BorrowedHandle<'_>) -> io::Result<Vec<Record>> {
        // 64 KiB in u64 cells, so every entry (aligned to 8 bytes by the system) is aligned.
        let mut buf = vec![0u64; 8 * 1024];
        let bytes = buf.len() * 8;
        let mut class = FileFullDirectoryRestartInfo;
        let mut out = Vec::new();
        loop {
            // SAFETY: `buf` is writable memory of `bytes` bytes, as passed; `handle` is open for
            // the call.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    handle.as_raw_handle() as HANDLE,
                    class,
                    buf.as_mut_ptr().cast(),
                    bytes as u32,
                )
            };
            if ok == 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == i32::try_from(ERROR_NO_MORE_FILES).ok() {
                    return Ok(out);
                }
                return Err(e);
            }
            class = FileFullDirectoryInfo;
            // SAFETY: `buf` owns `bytes` initialized bytes (u64 cells viewed as bytes, which
            // have no alignment or validity requirement); the view ends before `buf` changes.
            let view = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), bytes) };
            parse_full_dir(view, &mut out);
        }
    }

    /// Offsets in a `FILE_FULL_DIR_INFO` record: `NextEntryOffset` (u32 at 0), `LastWriteTime`
    /// (i64 at 24), `EndOfFile` (i64 at 40), `FileAttributes` (u32 at 56), `FileNameLength` (u32
    /// at 60) and the name (at 68), as in `FILE_FULL_DIR_INFO` of the SDK (checked against
    /// windows-sys in the test `the_record_offsets_match_the_sdk`).
    pub(super) const NEXT_ENTRY: usize = 0;
    pub(super) const WRITE_TIME: usize = 24;
    pub(super) const END_OF_FILE: usize = 40;
    pub(super) const ATTRIBUTES: usize = 56;
    pub(super) const NAME_LENGTH: usize = 60;
    pub(super) const NAME: usize = 68;

    fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
        let bytes = buf.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn u64_at(buf: &[u8], at: usize) -> Option<u64> {
        let bytes = buf.get(at..at.checked_add(8)?)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    /// One entry of a directory listing as its record describes it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Record {
        pub(super) name: OsString,
        pub(super) attributes: u32,
        pub(super) size: u64,
        /// The last write time as a `FILETIME` value.
        pub(super) write_time: u64,
    }

    /// The records of a chain of `FILE_FULL_DIR_INFO` records in `buf`, without `.` and `..`.
    /// Safe code over a byte slice: a record whose fixed part or name would reach past the end,
    /// or a `NextEntryOffset` that does not lead past the fixed part of the record, ends the
    /// chain, so a malformed buffer can only shorten the listing, never read outside `buf`.
    pub(super) fn parse_full_dir(buf: &[u8], out: &mut Vec<Record>) {
        let mut offset = 0usize;
        loop {
            let (Some(next), Some(write_time), Some(size), Some(attributes), Some(name_len)) = (
                u32_at(buf, offset + NEXT_ENTRY),
                u64_at(buf, offset + WRITE_TIME),
                u64_at(buf, offset + END_OF_FILE),
                u32_at(buf, offset + ATTRIBUTES),
                u32_at(buf, offset + NAME_LENGTH),
            ) else {
                return;
            };
            let name_start = offset + NAME;
            let Some(name_end) = name_start.checked_add(name_len as usize / 2 * 2) else {
                return;
            };
            let Some(raw) = buf.get(name_start..name_end) else {
                return;
            };
            let name: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            let dot = u16::from(b'.');
            if name != [dot] && name != [dot, dot] {
                out.push(Record {
                    name: OsString::from_wide(&name),
                    attributes,
                    size,
                    write_time,
                });
            }
            let next = next as usize;
            if next == 0 || next < NAME {
                return;
            }
            offset += next;
        }
    }

    #[cfg(test)]
    pub(super) fn wide(name: &OsStr) -> Vec<u16> {
        name.encode_wide().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::MetadataExt;

    fn scratch(tag: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join(".tmp")
            .join(format!("sync-win-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(dir).unwrap()
    }

    fn junction(link: &Path, target: &Path) {
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(crate::trash::plain_path(link))
            .arg(crate::trash::plain_path(target))
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
    }

    /// The handle-relative stat gives the same kind, size, time and file ID as std's metadata
    /// and the handle opened by path did before, so the IDs the index stored stay valid.
    #[test]
    fn handle_stats_match_std_metadata() {
        let dir = scratch("ids");
        std::fs::write(dir.join("f.txt"), b"hello").unwrap();
        std::fs::create_dir(dir.join("d")).unwrap();
        std::fs::create_dir(dir.join("target")).unwrap();
        junction(&dir.join("j"), &dir.join("target"));
        let root = Dir::open_root(&dir, Share::All).unwrap();
        for name in ["f.txt", "d", "j"] {
            let stat = root.stat_of(OsStr::new(name), false).unwrap().unwrap();
            let meta = std::fs::symlink_metadata(dir.join(name)).unwrap();
            assert_eq!(stat.mtime_ms, millis(meta.modified().unwrap()), "{name}");
            let kind = if meta.file_type().is_symlink() {
                EntryType::Symlink
            } else if meta.is_dir() {
                EntryType::Directory
            } else {
                EntryType::File
            };
            assert_eq!(stat.kind, kind, "{name}");
            if kind == EntryType::File {
                assert_eq!(stat.size, meta.file_size(), "{name}");
            }
            // The ID as the code before this module read it: a handle opened by path with
            // FILE_FLAG_OPEN_REPARSE_POINT.
            let by_path = std::fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(dir.join(name))
                .unwrap();
            let want = nt::info(by_path.as_handle()).unwrap().id;
            if kind == EntryType::Symlink {
                assert_eq!(stat.file_id, None, "{name}");
            } else {
                assert_eq!(stat.file_id, Some(want), "{name}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_that_are_not_single_names_are_refused_by_the_open() {
        let dir = scratch("names");
        std::fs::write(dir.join("f.txt"), b"hello").unwrap();
        let root = Dir::open_root(&dir, Share::All).unwrap();
        for name in ["", ".", "..", "f.txt:stream", "a\\f.txt", "a/f.txt", "f\0"] {
            let result = root.stat_of(OsStr::new(name), false);
            assert!(result.is_err(), "{name:?}: {result:?}");
        }
        // A name with spaces and characters outside the BMP is a single name.
        let odd = "na me \u{1F600}.txt";
        std::fs::write(dir.join(odd), b"x").unwrap();
        assert!(root.stat_of(OsStr::new(odd), false).unwrap().is_some());
        assert_eq!(nt::wide(OsStr::new(odd)).len(), 12);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_record_offsets_match_the_sdk() {
        use windows_sys::Win32::Storage::FileSystem::FILE_FULL_DIR_INFO;
        assert_eq!(
            std::mem::offset_of!(FILE_FULL_DIR_INFO, NextEntryOffset),
            nt::NEXT_ENTRY
        );
        assert_eq!(
            std::mem::offset_of!(FILE_FULL_DIR_INFO, LastWriteTime),
            nt::WRITE_TIME
        );
        assert_eq!(
            std::mem::offset_of!(FILE_FULL_DIR_INFO, EndOfFile),
            nt::END_OF_FILE
        );
        assert_eq!(
            std::mem::offset_of!(FILE_FULL_DIR_INFO, FileAttributes),
            nt::ATTRIBUTES
        );
        assert_eq!(
            std::mem::offset_of!(FILE_FULL_DIR_INFO, FileNameLength),
            nt::NAME_LENGTH
        );
        assert_eq!(std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName), nt::NAME);
    }

    /// One record with `name` at `at` in `buf`, its `NextEntryOffset` set to `next`.
    fn record(buf: &mut Vec<u8>, at: usize, next: u32, name: &str, claimed_len: Option<u32>) {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let end = at + 68 + wide.len() * 2;
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[at..at + 4].copy_from_slice(&next.to_le_bytes());
        let len = claimed_len.unwrap_or(wide.len() as u32 * 2);
        buf[at + 60..at + 64].copy_from_slice(&len.to_le_bytes());
        for (i, unit) in wide.iter().enumerate() {
            buf[at + 68 + 2 * i..at + 70 + 2 * i].copy_from_slice(&unit.to_le_bytes());
        }
    }

    fn parsed(buf: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        nt::parse_full_dir(buf, &mut out);
        out.into_iter()
            .map(|r| r.name.to_string_lossy().into_owned())
            .collect()
    }

    /// Security review L2: the listing parser never reads past the buffer. The last record may
    /// sit at `bytes - 68` with an empty name; a record that would reach past the end, a name
    /// longer than the rest, or a `NextEntryOffset` inside the fixed part end the chain.
    #[test]
    fn the_listing_parser_stays_inside_the_buffer() {
        let mut buf = Vec::new();
        record(&mut buf, 0, 80, ".", None);
        record(&mut buf, 80, 88, "na me \u{1F600}", None);
        record(&mut buf, 168, 0, "last", None);
        assert_eq!(parsed(&buf), ["na me \u{1F600}", "last"]);

        // The last record exactly at the end: its fixed part fills the buffer, no name.
        let mut tight = Vec::new();
        record(&mut tight, 0, 72, "a", None);
        record(&mut tight, 72, 0, "", None);
        assert_eq!(tight.len(), 72 + 68);
        assert_eq!(parsed(&tight), ["a", ""]);
        // One byte less: the fixed part of the last record no longer fits.
        assert_eq!(parsed(&tight[..tight.len() - 1]), ["a"]);

        // A name length beyond the buffer, and a NextEntryOffset into the fixed part.
        let mut long = Vec::new();
        record(&mut long, 0, 0, "x", Some(4096));
        assert!(parsed(&long).is_empty());
        let mut looping = Vec::new();
        record(&mut looping, 0, 4, "y", None);
        looping.resize(200, 0);
        assert_eq!(parsed(&looping), ["y"]);
        // An empty buffer and one shorter than the fixed part.
        assert!(parsed(&[]).is_empty());
        assert!(parsed(&[0u8; 67]).is_empty());
    }

    #[test]
    fn times_before_the_epoch_convert_like_std() {
        assert_eq!(millis(file_time(116_444_736_000_000_000)), 0);
        assert_eq!(millis(file_time(116_444_736_000_000_000 + 12_345)), 1);
        assert_eq!(millis(file_time(116_444_736_000_000_000 - 50_000)), -5);
    }

    /// Runs `icacls` with `args` (an argv array) and asserts success.
    fn icacls(args: &[&OsStr]) {
        let out = std::process::Command::new("icacls")
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    /// Security review L4: an entry whose own stat is refused (here: an ACL that denies
    /// SYNCHRONIZE to everyone, which every open needs) no longer fails the whole listing; it is
    /// listed with the stats of its directory record and without a file ID, so the scan keeps it
    /// by its path instead of losing the directory.
    #[test]
    fn an_entry_without_a_stat_does_not_fail_the_listing() {
        let dir = scratch("nostat");
        std::fs::write(dir.join("open.txt"), b"hello").unwrap();
        std::fs::write(dir.join("closed.txt"), b"locked out").unwrap();
        let closed = crate::trash::plain_path(&dir.join("closed.txt"));
        icacls(&[
            closed.as_os_str(),
            OsStr::new("/deny"),
            OsStr::new("*S-1-1-0:(S)"),
        ]);
        let folder = open_folder(&dir, dir.clone(), &[], &BTreeMap::new()).unwrap();
        let listed = folder.list();
        icacls(&[closed.as_os_str(), OsStr::new("/reset")]);
        let listed = listed.unwrap();
        let find = |n: &str| {
            listed
                .iter()
                .find(|e| e.name.as_deref() == Some(n))
                .unwrap()
        };
        assert_eq!(find("open.txt").stat.kind, EntryType::File);
        assert!(find("open.txt").stat.file_id.is_some());
        let entry = find("closed.txt");
        assert_eq!(entry.stat.kind, EntryType::File);
        assert_eq!(entry.stat.size, 10);
        assert_eq!(entry.stat.file_id, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// While a [`Pin`] lives, the directories on the way cannot be renamed, so the path the
    /// platform trash gets keeps its meaning; afterwards they can.
    #[test]
    fn a_pinned_directory_cannot_be_renamed() {
        let dir = scratch("pin");
        std::fs::create_dir_all(dir.join("a").join("b")).unwrap();
        std::fs::write(dir.join("a").join("b").join("f"), b"inside").unwrap();
        let path: Vec<String> = ["a", "b", "f"].iter().map(|s| (*s).to_owned()).collect();
        let full = dir.join("a").join("b").join("f");
        let spot = locate(&dir, full, &path, &BTreeMap::new())
            .unwrap()
            .unwrap();
        let pinned = pin(&dir, &path, &BTreeMap::new(), &spot).unwrap();
        for name in ["a", "a\\b"] {
            let moved = std::fs::rename(dir.join(name), dir.join(format!("{name}.moved")));
            assert!(moved.is_err(), "{name} was renamed while pinned");
        }
        assert!(pinned.spot().stat().unwrap().is_some());
        // The file itself stays free to go, within its directory and out of it (the shell
        // recycles it by a rename into the recycle bin).
        std::fs::rename(dir.join("a\\b\\f"), dir.join("a\\b\\g")).unwrap();
        std::fs::rename(dir.join("a\\b\\g"), dir.join("g")).unwrap();
        drop(pinned);
        // NTFS refuses to rename a directory while a handle below it is open, so the handle of
        // the walk goes first.
        drop(spot);
        std::fs::rename(dir.join("a"), dir.join("a.moved")).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
