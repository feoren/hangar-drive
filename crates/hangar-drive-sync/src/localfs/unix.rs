//! The Unix side of [`super::LocalFs`]: every operation goes through directory handles
//! (security review L1).
//!
//! The root is opened with `O_DIRECTORY | O_NOFOLLOW`, and every directory between it and the
//! target with `openat` relative to the directory above it, with `O_DIRECTORY | O_NOFOLLOW |
//! O_CLOEXEC`. A symbolic link anywhere on the way fails that open (`ELOOP`, `ENOTDIR`), and
//! where the index knows a directory's file ID, the ID of the opened handle must match. The
//! operation itself (`openat`, `fstatat`/`statx`, `mkdirat`, `unlinkat`, `renameat2`/
//! `renameatx_np`, `linkat`) is then relative to the handle of the directory that holds the
//! target, with the target's own name, and never follows a link in that name either.
//!
//! A path is never resolved twice: what was checked is the open handle, and the handle stays
//! bound to the directory it was opened on. A program that swaps a directory for a link after
//! the walk changes only what the path means; the operation still lands in the directory that
//! was checked, inside the root. Before, the components were checked by path and the operation
//! resolved the path again, and a swap in between let a write, delete or rename land outside the
//! root.
//!
//! The calls come from `rustix` (module docs of the crate manifest), so this module has no
//! unsafe code.
//!
//! Stats are read here as well (`statx` on Linux, `fstatat` elsewhere), not through
//! `std::fs::Metadata`, which has no handle-relative form. The file ID keeps exactly the value
//! std's metadata gave before (device, inode and the birth time std reads the same way), so
//! the IDs the index stored stay valid.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hangar_drive_protocol::name::RESERVED_ROOT_DIR;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::{io_error, is_backup, millis, name_problem, RECOVERED_DIR, TEMP_DIR};
use crate::ports::{EntryType, FsError, ListEntry, Stat};
use crate::trash::QUARANTINE_DIR;

/// How deep the cleaning of the temporary directory descends. The engine itself only puts
/// files there; a deeper tree was made by someone else and is left alone.
const CLEAN_DEPTH: u32 = 16;

/// The flags of every directory on the way: read only, a directory, never a link, closed on
/// exec.
fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Whether an open with [`dir_flags`] failed because the name is not a plain directory: a
/// symbolic link (`ELOOP` on Linux and macOS, `EMLINK` on FreeBSD) or a file (`ENOTDIR`).
fn not_plain_dir(e: Errno) -> bool {
    e == Errno::LOOP || e == Errno::NOTDIR || e == Errno::MLINK
}

fn os(e: Errno) -> io::Error {
    io::Error::from(e)
}

fn fs_error(e: Errno) -> FsError {
    io_error(&os(e))
}

/// An open directory (a handle opened with [`dir_flags`]), shared by the places in it.
#[derive(Debug, Clone)]
pub(super) struct Dir(Arc<OwnedFd>);

impl Dir {
    /// The sync root. Its own path was canonicalized when the root was opened and lies outside
    /// the root; its last component is opened without following a link.
    fn open_root(root: &Path) -> Result<Dir, FsError> {
        match rustix::fs::open(root, dir_flags(), Mode::empty()) {
            Ok(fd) => Ok(Dir(Arc::new(fd))),
            Err(e) if not_plain_dir(e) => Err(FsError::Changed),
            Err(e) => Err(fs_error(e)),
        }
    }

    fn fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// The directory `name` in this one, never through a link.
    fn open_dir(&self, name: &OsStr) -> Result<Dir, Errno> {
        rustix::fs::openat(self.fd(), name, dir_flags(), Mode::empty()).map(|fd| Dir(Arc::new(fd)))
    }

    /// The stat of this directory itself.
    fn stat(&self) -> Result<Raw, Errno> {
        raw_fd(self.fd())
    }

    /// The file ID of this directory.
    fn id(&self) -> Result<u128, FsError> {
        self.stat().map(|raw| unix_id(&raw)).map_err(fs_error)
    }

    /// The entries of this directory with their stats, read without following links; an entry
    /// that disappears between the listing and its stat is left out.
    fn entries(&self) -> Result<Vec<(OsString, Raw)>, FsError> {
        // `read_from` opens "." relative to the handle, a new description with its own offset.
        let reader = rustix::fs::Dir::read_from(self.fd()).map_err(fs_error)?;
        let mut out = Vec::new();
        for entry in reader {
            let entry = entry.map_err(fs_error)?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == "." || name == ".." {
                continue;
            }
            match raw_at(self.fd(), name) {
                Ok(raw) => out.push((name.to_owned(), raw)),
                Err(e) if e == Errno::NOENT => {}
                Err(e) => return Err(fs_error(e)),
            }
        }
        Ok(out)
    }
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
        self.dir
            .stat()
            .map(|raw| Some(stat_of(&raw)))
            .map_err(fs_error)
    }

    /// The listing of the directory (L10 as on every platform: a name that fails the checks is
    /// [`EntryType::Other`]).
    pub(super) fn list(&self) -> Result<Vec<ListEntry>, FsError> {
        let mut out = Vec::new();
        for (os_name, raw) in self.dir.entries()? {
            let display = os_name.to_string_lossy().into_owned();
            let name = os_name.into_string().ok();
            let mut stat = stat_of(&raw);
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
        let full = match self.full.parent() {
            Some(parent) => parent.join(name),
            None => PathBuf::from(name),
        };
        Spot {
            dir: self.dir.clone(),
            name: OsString::from(name),
            full,
        }
    }

    /// Opens an existing regular file for reading and writing (the part file of a download in
    /// parts, which is checked through the same handle it lands with).
    pub(super) fn open_read_write(&self) -> io::Result<File> {
        let file = self.open(OFlags::RDWR | OFlags::NONBLOCK, Mode::empty())?;
        regular(file)
    }

    /// The entry's status change time (`ctime`), which every write and metadata change moves,
    /// also one that sets the modification time back; `None` if the entry does not exist.
    pub(super) fn change_stamp(&self) -> Result<Option<u64>, FsError> {
        match raw_at(self.dir.fd(), &self.name) {
            Ok(raw) => Ok(Some(
                (raw.ctime.0 as u64)
                    .wrapping_mul(1_000_000_000)
                    .wrapping_add(u64::from(raw.ctime.1)),
            )),
            Err(e) if e == Errno::NOENT => Ok(None),
            Err(e) => Err(fs_error(e)),
        }
    }

    /// The stat of the entry itself (a link is reported as a link); `None` if it does not exist.
    pub(super) fn stat(&self) -> Result<Option<Stat>, FsError> {
        match raw_at(self.dir.fd(), &self.name) {
            Ok(raw) => Ok(Some(stat_of(&raw))),
            Err(e) if e == Errno::NOENT => Ok(None),
            Err(e) => Err(fs_error(e)),
        }
    }

    fn open(&self, flags: OFlags, mode: Mode) -> io::Result<File> {
        rustix::fs::openat(
            self.dir.fd(),
            &self.name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )
        .map(File::from)
        .map_err(os)
    }

    /// Opens an existing regular file for reading. `O_NOFOLLOW` refuses a link in place of the
    /// file (N6), and `O_NONBLOCK` keeps a FIFO someone put there from blocking the open; the
    /// handle must then be a regular file.
    pub(super) fn open_read(&self) -> io::Result<File> {
        let file = self.open(OFlags::RDONLY | OFlags::NONBLOCK, Mode::empty())?;
        regular(file)
    }

    /// Opens an existing regular file for writing its metadata (no create, no truncate).
    pub(super) fn open_write(&self) -> io::Result<File> {
        let file = self.open(OFlags::WRONLY | OFlags::NONBLOCK, Mode::empty())?;
        regular(file)
    }

    /// Creates a new file that must not exist yet (`O_EXCL`), with the default mode before the
    /// umask, as `std::fs::OpenOptions` does.
    pub(super) fn create_new(&self) -> io::Result<File> {
        self.open(
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::from_bits_truncate(0o666),
        )
    }

    /// Creates the directory, with the default mode before the umask.
    pub(super) fn create_dir(&self) -> io::Result<()> {
        rustix::fs::mkdirat(self.dir.fd(), &self.name, Mode::from_bits_truncate(0o777)).map_err(os)
    }

    /// The file ID of the entry if it is a plain directory.
    pub(super) fn dir_id(&self) -> Option<u128> {
        match raw_at(self.dir.fd(), &self.name) {
            Ok(raw) if raw.kind == FileType::Directory => Some(unix_id(&raw)),
            _ => None,
        }
    }

    /// Removes the entry, a file or a link (never what a link points at).
    pub(super) fn remove_file(&self) -> io::Result<()> {
        rustix::fs::unlinkat(self.dir.fd(), &self.name, AtFlags::empty()).map_err(os)
    }

    /// Removes the entry if it is an empty plain directory; a link or a file in its place is
    /// [`FsError::Changed`].
    pub(super) fn remove_dir(&self) -> Result<(), FsError> {
        match rustix::fs::unlinkat(self.dir.fd(), &self.name, AtFlags::REMOVEDIR) {
            Ok(()) => Ok(()),
            Err(e) if e == Errno::NOTDIR => Err(FsError::Changed),
            Err(e) => Err(fs_error(e)),
        }
    }

    /// A rename that fails with "already exists" instead of replacing (L2): one
    /// `renameat2(RENAME_NOREPLACE)` or `renameatx_np(RENAME_EXCL)`. Where the file system does
    /// not offer it, a hard link (which never replaces) and an unlink move a file, and a
    /// directory falls back to a check before the rename.
    pub(super) fn rename_noreplace(&self, to: &Spot) -> io::Result<()> {
        if self.rename_flagged(to, Flag::NoReplace)? {
            return Ok(());
        }
        let source = raw_at(self.dir.fd(), &self.name).map_err(os)?;
        if source.kind == FileType::Directory {
            match raw_at(to.dir.fd(), &to.name) {
                Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists)),
                Err(e) if e == Errno::NOENT => {}
                Err(e) => return Err(os(e)),
            }
            return self.rename(to);
        }
        rustix::fs::linkat(
            self.dir.fd(),
            &self.name,
            to.dir.fd(),
            &to.name,
            AtFlags::empty(),
        )
        .map_err(os)?;
        self.remove_file()
    }

    /// Swaps the two names in one step (`RENAME_EXCHANGE`, `RENAME_SWAP`); `Ok(false)` where
    /// that is not offered.
    pub(super) fn exchange(&self, other: &Spot) -> io::Result<bool> {
        self.rename_flagged(other, Flag::Exchange)
    }

    /// A plain rename, which replaces a file at `to`.
    pub(super) fn rename(&self, to: &Spot) -> io::Result<()> {
        rustix::fs::renameat(self.dir.fd(), &self.name, to.dir.fd(), &to.name).map_err(os)
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    fn rename_flagged(&self, to: &Spot, flag: Flag) -> io::Result<bool> {
        use rustix::fs::RenameFlags;
        let flags = match flag {
            Flag::NoReplace => RenameFlags::NOREPLACE,
            Flag::Exchange => RenameFlags::EXCHANGE,
        };
        match rustix::fs::renameat_with(self.dir.fd(), &self.name, to.dir.fd(), &to.name, flags) {
            Ok(()) => Ok(true),
            Err(e) if unsupported(e) => Ok(false),
            Err(e) => Err(os(e)),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    fn rename_flagged(&self, _to: &Spot, _flag: Flag) -> io::Result<bool> {
        Ok(false)
    }
}

/// The two atomic rename variants.
#[derive(Debug, Clone, Copy)]
enum Flag {
    NoReplace,
    Exchange,
}

/// Whether a flagged rename failed because the kernel or the file system lacks it.
fn unsupported(e: Errno) -> bool {
    e == Errno::INVAL || e == Errno::NOSYS || e == Errno::NOTSUP || e == Errno::OPNOTSUPP
}

/// The file ID of an open file, as [`Spot::stat`] reports it.
pub(super) fn file_id_of(file: &File) -> Option<u128> {
    raw_fd(file.as_fd()).ok().map(|raw| unix_id(&raw))
}

/// Whether an open file has no other name: a hard link made to it from elsewhere could change
/// it behind the check of its content.
pub(super) fn single_link(file: &File) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    file.metadata().is_ok_and(|m| m.nlink() == 1)
}

/// The handle if it is a regular file.
fn regular(file: File) -> io::Result<File> {
    let raw = raw_fd(file.as_fd()).map_err(os)?;
    if raw.kind != FileType::RegularFile {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(file)
}

/// Opens `components` below `root` one directory at a time (module docs). The file ID of the
/// first `checked` components is compared with the index where it knows one; a mismatch, a link
/// or a file on the way is [`FsError::Changed`]. `Ok(None)` when one of them does not exist.
fn walk(
    root: &Path,
    components: &[String],
    checked: usize,
    expected: &BTreeMap<Vec<String>, u128>,
) -> Result<Option<Dir>, FsError> {
    let mut dir = Dir::open_root(root)?;
    for (i, name) in components.iter().enumerate() {
        let next = match dir.open_dir(OsStr::new(name)) {
            Ok(next) => next,
            Err(e) if e == Errno::NOENT => return Ok(None),
            Err(e) if not_plain_dir(e) => return Err(FsError::Changed),
            Err(e) => return Err(fs_error(e)),
        };
        if i < checked {
            if let Some(want) = expected.get(&components[..=i]) {
                if next.id()? != *want {
                    return Err(FsError::Changed);
                }
            }
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
        walk(root, parents, parents.len(), expected)?.map(|dir| Spot {
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
    match walk(root, path, checked, expected)? {
        Some(dir) => Ok(Folder { dir, full }),
        None => Err(FsError::NotFound),
    }
}

/// `.hangar-drive/<parts>` below the root, created one level at a time with `mkdirat` and opened
/// with `O_NOFOLLOW` (security review N5): a link at any level is refused, never followed.
pub(super) fn reserved_dir(root: &Path, parts: &[&str]) -> Result<Folder, FsError> {
    let mut dir = Dir::open_root(root)?;
    let mut full = root.to_path_buf();
    for part in std::iter::once(RESERVED_ROOT_DIR).chain(parts.iter().copied()) {
        let name = OsStr::new(part);
        match rustix::fs::mkdirat(dir.fd(), name, Mode::from_bits_truncate(0o777)) {
            Ok(()) => {}
            Err(e) if e == Errno::EXIST => {}
            Err(e) => return Err(fs_error(e)),
        }
        dir = match dir.open_dir(name) {
            Ok(next) => next,
            Err(e) if not_plain_dir(e) => {
                return Err(FsError::CannotSync(
                    "the reserved directory is not a plain directory".into(),
                ))
            }
            Err(e) => return Err(fs_error(e)),
        };
        full.push(part);
    }
    Ok(Folder { dir, full })
}

/// Empties the reserved `tmp` directory (writes a crash left behind); backups of a replace move
/// into the quarantine instead (L3). Only plain directories are entered, each through its
/// handle, so a link put at any level removes nothing outside.
pub(super) fn clean_temp(root: &Path) {
    let Ok(dir) = Dir::open_root(root) else {
        return;
    };
    let Ok(reserved) = dir.open_dir(OsStr::new(RESERVED_ROOT_DIR)) else {
        return;
    };
    let Ok(temp) = reserved.open_dir(OsStr::new(TEMP_DIR)) else {
        return;
    };
    let Ok(entries) = temp.entries() else {
        return;
    };
    let temp_path = root.join(RESERVED_ROOT_DIR).join(TEMP_DIR);
    let mut recovered: Option<Folder> = None;
    for (name, raw) in entries {
        // The old file of a replace a crash interrupted (security review L3): recovered into
        // the quarantine, never deleted. A backup that cannot move stays for the next start.
        if raw.kind == FileType::RegularFile && is_backup(&name) {
            if recovered.is_none() {
                recovered = reserved_dir(root, &[QUARANTINE_DIR, RECOVERED_DIR]).ok();
            }
            if let Some(into) = &recovered {
                let from = Spot {
                    dir: temp.clone(),
                    full: temp_path.join(&name),
                    name: name.clone(),
                };
                let _ = from.rename_noreplace(&into.child(&name));
            }
            continue;
        }
        remove_entry(&temp, &name, &raw, CLEAN_DEPTH);
    }
}

/// Removes the entries of the quarantine whose time is past [`crate::trash::expired`], through
/// handles as [`clean_temp`] does: a plain directory is emptied through its own handle and
/// removed, anything else (a link included) is unlinked itself, never followed.
pub(super) fn clean_quarantine(root: &Path, now: SystemTime) {
    let Ok(dir) = Dir::open_root(root) else {
        return;
    };
    let Ok(reserved) = dir.open_dir(OsStr::new(RESERVED_ROOT_DIR)) else {
        return;
    };
    let Ok(quarantine) = reserved.open_dir(OsStr::new(QUARANTINE_DIR)) else {
        return;
    };
    let Ok(entries) = quarantine.entries() else {
        return;
    };
    for (name, raw) in entries {
        // The entry's directory was made when the file moved in.
        if !crate::trash::expired(time(raw.mtime.0, raw.mtime.1), now) {
            continue;
        }
        if raw.kind == FileType::Directory {
            if let Ok(child) = quarantine.open_dir(&name) {
                empty(&child, CLEAN_DEPTH - 1);
            }
            let _ = rustix::fs::unlinkat(quarantine.fd(), &name, AtFlags::REMOVEDIR);
        } else {
            let _ = rustix::fs::unlinkat(quarantine.fd(), &name, AtFlags::empty());
        }
    }
}

/// Removes everything in `dir`; directories are removed through their own handles, down to
/// `depth` levels. Errors leave the entry in place for the next start.
fn empty(dir: &Dir, depth: u32) {
    let Ok(entries) = dir.entries() else {
        return;
    };
    for (name, raw) in entries {
        remove_entry(dir, &name, &raw, depth);
    }
}

/// Removes the entry `name` of `dir`: a plain directory with its content through its own handle
/// (down to `depth` levels), anything else (a link included) unlinked itself.
fn remove_entry(dir: &Dir, name: &OsStr, raw: &Raw, depth: u32) {
    if raw.kind == FileType::Directory {
        if depth == 0 {
            return;
        }
        if let Ok(child) = dir.open_dir(name) {
            empty(&child, depth - 1);
        }
        let _ = rustix::fs::unlinkat(dir.fd(), name, AtFlags::REMOVEDIR);
    } else {
        let _ = rustix::fs::unlinkat(dir.fd(), name, AtFlags::empty());
    }
}

/// What this module needs from a stat, read the same way std's metadata reads it.
#[derive(Debug, Clone, Copy)]
struct Raw {
    kind: FileType,
    mode: u32,
    size: u64,
    /// Seconds and nanoseconds of the modification time.
    mtime: (i64, u32),
    dev: u64,
    ino: u64,
    /// Seconds and nanoseconds of the birth time, where the file system reports one.
    birth: Option<(i64, u32)>,
    /// Seconds and nanoseconds of the status change time (`ctime`).
    ctime: (i64, u32),
}

/// The stat of `name` in `dir`, without following a link. On Linux through `statx` with
/// `STATX_BTIME`, exactly as std's metadata on glibc, with `fstatat` (no birth time) where the
/// kernel has no `statx`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn raw_at(dir: BorrowedFd<'_>, name: &OsStr) -> Result<Raw, Errno> {
    statx_or(dir, name, AtFlags::SYMLINK_NOFOLLOW, || {
        rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
    })
}

/// The stat of an open handle (Linux: `statx` with `AT_EMPTY_PATH`, else `fstat`).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn raw_fd(fd: BorrowedFd<'_>) -> Result<Raw, Errno> {
    statx_or(fd, OsStr::new(""), AtFlags::EMPTY_PATH, || {
        rustix::fs::fstat(fd)
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn statx_or(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    flags: AtFlags,
    fallback: impl FnOnce() -> Result<rustix::fs::Stat, Errno>,
) -> Result<Raw, Errno> {
    use rustix::fs::StatxFlags;
    match rustix::fs::statx(
        dir,
        name,
        flags,
        StatxFlags::BASIC_STATS | StatxFlags::BTIME,
    ) {
        Ok(s) => {
            let mode = u32::from(s.stx_mode);
            Ok(Raw {
                kind: FileType::from_raw_mode(mode),
                mode,
                size: s.stx_size,
                mtime: (s.stx_mtime.tv_sec, s.stx_mtime.tv_nsec),
                // std builds `st_dev` from the two halves with the same `makedev`.
                dev: rustix::fs::makedev(s.stx_dev_major, s.stx_dev_minor),
                ino: s.stx_ino,
                birth: (s.stx_mask & StatxFlags::BTIME.bits() != 0)
                    .then_some((s.stx_btime.tv_sec, s.stx_btime.tv_nsec)),
                ctime: (s.stx_ctime.tv_sec, s.stx_ctime.tv_nsec),
            })
        }
        // A kernel before 4.11 or a sandbox that blocks `statx`: std falls back the same way.
        Err(e) if e == Errno::NOSYS => fallback().map(from_stat),
        Err(e) => Err(e),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn raw_at(dir: BorrowedFd<'_>, name: &OsStr) -> Result<Raw, Errno> {
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map(from_stat)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn raw_fd(fd: BorrowedFd<'_>) -> Result<Raw, Errno> {
    rustix::fs::fstat(fd).map(from_stat)
}

/// A `struct stat`; the field types differ between targets, so the casts are those std's
/// `MetadataExt` makes (`st_dev as u64` included, which sign-extends macOS's `i32`).
#[allow(clippy::unnecessary_cast)]
fn from_stat(s: rustix::fs::Stat) -> Raw {
    let mode = s.st_mode as u32;
    #[cfg(target_vendor = "apple")]
    let birth = Some((s.st_birthtime as i64, s.st_birthtime_nsec as u32));
    #[cfg(not(target_vendor = "apple"))]
    let birth = None;
    Raw {
        kind: FileType::from_raw_mode(s.st_mode as _),
        mode,
        size: s.st_size as u64,
        mtime: (s.st_mtime as i64, s.st_mtime_nsec as u32),
        dev: s.st_dev as u64,
        ino: s.st_ino as u64,
        birth,
        ctime: (s.st_ctime as i64, s.st_ctime_nsec as u32),
    }
}

/// The point in time of seconds and nanoseconds since the epoch, as std builds `SystemTime`.
fn time(sec: i64, nsec: u32) -> SystemTime {
    let nanos = Duration::from_nanos(u64::from(nsec));
    let base = if sec >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(sec.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(sec.unsigned_abs()))
    };
    base.and_then(|t| t.checked_add(nanos))
        .unwrap_or(UNIX_EPOCH)
}

fn stat_of(raw: &Raw) -> Stat {
    let kind = if raw.kind == FileType::Symlink {
        EntryType::Symlink
    } else if raw.kind == FileType::Directory {
        EntryType::Directory
    } else if raw.kind == FileType::RegularFile {
        EntryType::File
    } else {
        EntryType::Other
    };
    let regular = matches!(kind, EntryType::File | EntryType::Directory);
    Stat {
        kind,
        size: if kind == EntryType::File { raw.size } else { 0 },
        mtime_ms: millis(time(raw.mtime.0, raw.mtime.1)),
        file_id: regular.then(|| unix_id(raw)),
        executable: kind == EntryType::File && raw.mode & 0o100 != 0,
    }
}

/// The file ID of a file or directory on Unix: device and inode, with the birth time mixed in
/// where the file system reports one (L1, L3).
///
/// Device and inode alone do not identify a file: Linux hands a freed inode number to the next
/// file created on the same file system at once (measured on ext4 below overlayfs:
/// `docs/wiki/raw/2026-11-26-unix-inode-reuse-measurement.md`), so a file another program
/// deleted and created again with the same size and mtime would pass the replace check. The
/// birth time is set once when the inode is made and never changes afterwards, not on a write, a
/// rename, a time or mode change or a new hard link, so a move still keeps its file ID and an
/// operation of the engine itself never looks like a replace.
///
/// The birth time is `stx_btime` from `statx` with `STATX_BTIME` on Linux (reported only when the
/// file system sets it in `stx_mask`) and `st_birthtime` on macOS, the same values
/// `std::fs::Metadata::created` reads, so the IDs did not change when this module moved from
/// std's metadata to handle-relative stats.
///
/// `st_ctime` is deliberately not the fallback: it changes with every rename, time change and
/// mode change (measured, same record), so a move would lose its file ID, a directory would get a
/// new ID with every entry added to it (failing the L1 check of every later operation in it), and
/// every `set_meta` would read as a replace by someone else. Where no birth time is reported
/// (ext4 with 128 byte inodes, 9p, NFSv3, many FUSE file systems), the ID stays device and inode,
/// the residual risk named in ADR 0001, section 7.
fn unix_id(raw: &Raw) -> u128 {
    let base = (u128::from(raw.dev) << 64) | u128::from(raw.ino);
    match birth_nanos(raw) {
        // The inode stays in the low half, so two files on one device never share an ID. A
        // reused inode differs in the high half, because `mix` is a bijection: different birth
        // times give different values. Mixing keeps device and time bits from cancelling out
        // between two devices.
        Some(birth) => base ^ (u128::from(mix(birth)) << 64),
        None => base,
    }
}

/// Nanoseconds since the Unix epoch of the birth time, `None` where the file system reports
/// none (or reports 0, as macOS does on a volume without birth times) and for a time before
/// the epoch.
fn birth_nanos(raw: &Raw) -> Option<u64> {
    let (sec, nsec) = raw.birth?;
    let sec = u128::try_from(sec).ok()?;
    u64::try_from(sec * 1_000_000_000 + u128::from(nsec))
        .ok()
        .filter(|nanos| *nanos != 0)
}

/// The SplitMix64 finalizer: a bijection on `u64` that spreads every input bit over the output.
fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn scratch(tag: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join(".tmp")
            .join(format!("sync-unix-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(dir).unwrap()
    }

    /// The handle-relative stat gives the same file ID, size, time and kind as std's metadata
    /// did, so the IDs the index stored stay valid.
    #[test]
    fn handle_stats_match_std_metadata() {
        let dir = scratch("ids");
        std::fs::write(dir.join("f.txt"), b"hello").unwrap();
        std::fs::create_dir(dir.join("d")).unwrap();
        std::os::unix::fs::symlink("f.txt", dir.join("link")).unwrap();
        let root = Dir::open_root(&dir).unwrap();
        for name in ["f.txt", "d", "link"] {
            let meta = std::fs::symlink_metadata(dir.join(name)).unwrap();
            let raw = raw_at(root.fd(), OsStr::new(name)).unwrap();
            assert_eq!(raw.dev, meta.dev(), "{name}");
            assert_eq!(raw.ino, meta.ino(), "{name}");
            assert_eq!(raw.mode, meta.mode(), "{name}");
            let std_birth = meta
                .created()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .and_then(|d| u64::try_from(d.as_nanos()).ok())
                .filter(|n| *n != 0);
            assert_eq!(birth_nanos(&raw), std_birth, "{name}");
            assert_eq!(
                millis(time(raw.mtime.0, raw.mtime.1)),
                millis(meta.modified().unwrap()),
                "{name}"
            );
        }
        let stat = stat_of(&raw_at(root.fd(), OsStr::new("f.txt")).unwrap());
        assert_eq!(stat.kind, EntryType::File);
        assert_eq!(stat.size, 5);
        assert_eq!(
            stat_of(&raw_at(root.fd(), OsStr::new("link")).unwrap()).kind,
            EntryType::Symlink
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn times_before_the_epoch_and_with_nanoseconds_convert_like_std() {
        assert_eq!(millis(time(0, 0)), 0);
        assert_eq!(millis(time(1_700_000_000, 123_456_789)), 1_700_000_000_123);
        assert_eq!(millis(time(-5, 0)), -5_000);
        assert_eq!(millis(time(-5, 500_000_000)), -4_500);
    }

    #[test]
    fn a_birth_time_of_zero_or_before_the_epoch_is_none() {
        let mut raw = Raw {
            kind: FileType::RegularFile,
            mode: 0o644,
            size: 0,
            mtime: (0, 0),
            dev: 1,
            ino: 2,
            birth: Some((0, 0)),
            ctime: (0, 0),
        };
        assert_eq!(birth_nanos(&raw), None);
        raw.birth = Some((-1, 0));
        assert_eq!(birth_nanos(&raw), None);
        raw.birth = Some((1, 5));
        assert_eq!(birth_nanos(&raw), Some(1_000_000_005));
        raw.birth = None;
        assert_eq!(unix_id(&raw), (1u128 << 64) | 2);
    }
}
