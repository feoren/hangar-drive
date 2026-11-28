//! The real sync root on disk (ADR 0001, section 7).
//!
//! - **Names before paths:** every name is checked with the protocol's `check_name` and, on
//!   Windows, `windows_problem` **before** a platform path is built from it, so a name such as
//!   `..\x`, `C:x` or `CON` from another device can never escape the root or reach a device; such
//!   a name is [`FsError::CannotSync`] ("cannot sync on this device"), never renamed silently.
//!   A listed entry whose name fails these checks is [`EntryType::Other`] and never synced
//!   (security review L10).
//! - **Directories on the way** (security review L1): before every operation each component
//!   between the root and the target is read without following links and must be a plain
//!   directory (no symbolic link, junction or other reparse point); where the index knows the
//!   directory's file ID ([`FileSystem::expect_directories`]), the ID on disk must be the same.
//!   Otherwise the operation fails with [`FsError::Changed`] and the next scan sees what
//!   happened.
//!   - **Unix** walks by handles ([`unix`]): every directory is opened with `openat` relative to
//!     the one above it with `O_DIRECTORY | O_NOFOLLOW`, and the operation is relative to the
//!     handle of the directory that holds the target (`openat`, `unlinkat`, `mkdirat`,
//!     `renameat2`, `renameatx_np`). What was checked is the handle the operation uses, so a
//!     directory swapped for a link after the check changes nothing outside the root.
//!   - **Windows** walks by handles as well ([`windows`]): every directory is opened with
//!     `NtCreateFile` relative to the handle of the one above it with `FILE_DIRECTORY_FILE |
//!     FILE_OPEN_REPARSE_POINT`, a junction or other reparse point on the way is refused by its
//!     attributes, and the operation is relative to the handle of the directory that holds the
//!     target (`NtCreateFile`, `NtSetInformationFile` with `FileRenameInformation`,
//!     `SetFileInformationByHandle` with `FileDispositionInfoEx`). For the recycle bin, which takes a path, the directories on the
//!     way are held open without `FILE_SHARE_DELETE`, so none of them can be swapped while the
//!     shell works ([`windows::pin`]).
//! - **Long paths:** on Windows the root is the verbatim (`\\?\`) form from `canonicalize`, so
//!   every path built on it works beyond `MAX_PATH` without the `LongPathsEnabled` registry value.
//! - **Atomic writes:** content goes to a temporary file with a random name in the reserved
//!   directory (same volume), is flushed, gets its modification time, and is then put in place
//!   (security review L2 to L4):
//!   - a new file is renamed onto a free name with a rename that never replaces
//!     (`MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`, `renameat2(RENAME_NOREPLACE)`,
//!     `renamex_np(RENAME_EXCL)`), no placeholder; a name that appeared meanwhile is
//!     [`FsError::Exists`];
//!   - a replace first checks size, modification time and file ID ([`Expect`]), then swaps in
//!     a way that keeps the old file (`RENAME_EXCHANGE` on Linux, `RENAME_SWAP` on macOS; on
//!     Windows two renames by handle that never replace: the old file into the reserved `tmp`
//!     directory, the new one onto the freed name). If the old file no longer matches (the person
//!     saved it between the check and the swap), it is kept next to the target as a conflict copy
//!     instead of being lost.
//!   - the reserved `tmp` directory is emptied when the root is opened, and an existing
//!     temporary name is never reported as the target's "already exists".
//! - **Incoming deletes** go to the system's recycle bin or the quarantine
//!   ([`crate::trash`], security review M2).
//! - **Locked files:** sharing and lock violations (Office, antivirus, the indexer) are retried a
//!   few times with a short backoff and then reported as [`FsError::Locked`]; the engine retries
//!   later with a longer backoff and never blocks the run.
//! - **Links and reparse points** are reported as such and never followed; files with the
//!   Windows system attribute are reported as [`EntryType::System`].
//! - **mtime tolerance:** 2 s on FAT and exFAT volumes, where write times have 2 s resolution
//!   (Windows: the volume's file system name; Linux: `statfs` `f_type` of vfat, msdos and
//!   exFAT), and 1 s on Linux for WSL's drvfs and other 9p mounts of Windows drives, which report
//!   whole second modification times (measured, `docs/wiki/pages/sources/
//!   unix-inode-reuse-measurement.md`). Other volumes and platforms have none.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hangar_drive_crypto::{Entropy, OsEntropy};
use hangar_drive_protocol::ids::ItemId;
use hangar_drive_protocol::name::check_name;

use crate::names::{conflict_copy_name, date_label, LabelWords};
use crate::ports::{EntryType, Expect, FileSystem, FsError, ListEntry, Stat};
use crate::trash::{Trashed, QUARANTINE_DIR};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
// The platform side: places bound to directory handles on both. Both offer the same `Spot` (an
// entry: its directory and its name), `Folder` (an opened directory) and free functions, so the
// logic of `LocalFs` below is written once.
#[cfg(unix)]
use self::unix as plat;
#[cfg(windows)]
use self::windows as plat;

/// Attempts for an operation on a locked file before [`FsError::Locked`].
const LOCK_ATTEMPTS: u32 = 4;
/// The first wait between attempts; it doubles.
const LOCK_BACKOFF: Duration = Duration::from_millis(40);
/// The temporary directory inside the reserved directory.
pub const TEMP_DIR: &str = "tmp";
/// The ending of the name under which a replace keeps the old file in [`TEMP_DIR`] until it is
/// settled (security review L3). The cleaning at start recovers such files into
/// [`RECOVERED_DIR`] instead of deleting them, so a crash in between loses no edit.
const BACKUP_SUFFIX: &str = ".bak";
/// The directory in the quarantine that takes the backups a crash left in [`TEMP_DIR`]; it
/// expires like every quarantine entry (30 days after the last file moved in).
const RECOVERED_DIR: &str = "recovered";

/// Whether `name` in [`TEMP_DIR`] is a backup of a replace ([`BACKUP_SUFFIX`]).
fn is_backup(name: &OsStr) -> bool {
    name.to_str().is_some_and(|n| n.ends_with(BACKUP_SUFFIX))
}
/// The device word in the name of a conflict copy this module keeps (a replace that found the
/// file changed at the last moment).
const LOCAL_DEVICE_LABEL: &str = "local";

/// A sync root on disk (module docs).
#[derive(Debug, Clone)]
pub struct LocalFs {
    root: PathBuf,
    tolerance_ms: i64,
    /// File IDs of directories below the root as the index knows them (L1). The map sits in an
    /// `Arc` of its own, so every operation takes a snapshot by cloning that `Arc` under the
    /// lock (O(1)) instead of copying the whole map; the rare writers copy on write
    /// ([`Arc::make_mut`]) or swap the `Arc` ([`FileSystem::expect_directories`]).
    dirs: Arc<Mutex<Arc<DirIds>>>,
}

/// File IDs of directories below the root, by path.
type DirIds = BTreeMap<Vec<String>, u128>;

fn io_error(e: &io::Error) -> FsError {
    #[cfg(windows)]
    {
        // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION.
        if matches!(e.raw_os_error(), Some(32) | Some(33)) {
            return FsError::Locked;
        }
        // ERROR_DIR_NOT_EMPTY.
        if e.raw_os_error() == Some(145) {
            return FsError::NotEmpty;
        }
        // ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS.
        if matches!(e.raw_os_error(), Some(80) | Some(183)) {
            return FsError::Exists;
        }
    }
    match e.kind() {
        io::ErrorKind::NotFound => FsError::NotFound,
        io::ErrorKind::AlreadyExists => FsError::Exists,
        io::ErrorKind::PermissionDenied => FsError::Denied,
        io::ErrorKind::DirectoryNotEmpty => FsError::NotEmpty,
        io::ErrorKind::StorageFull => FsError::DiskFull,
        _ => FsError::Io(e.to_string()),
    }
}

/// Runs `op` again while it fails with a lock or sharing violation.
fn with_lock_retry<T>(mut op: impl FnMut() -> io::Result<T>) -> Result<T, FsError> {
    let mut wait = LOCK_BACKOFF;
    let mut attempt = 1;
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let mapped = io_error(&e);
                if mapped != FsError::Locked || attempt >= LOCK_ATTEMPTS {
                    return Err(mapped);
                }
                std::thread::sleep(wait);
                wait *= 2;
                attempt += 1;
            }
        }
    }
}

fn millis(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

fn system_time(ms: i64) -> SystemTime {
    if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms.unsigned_abs())
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_millis(ms.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

/// Why a name cannot become a path on this platform, if it cannot.
pub fn name_problem(name: &str) -> Option<String> {
    if let Err(e) = check_name(name) {
        return Some(e.to_string());
    }
    #[cfg(windows)]
    {
        if let Some(problem) = hangar_drive_protocol::name::windows_problem(name) {
            return Some(problem.to_string());
        }
    }
    None
}

fn random_name(suffix: &str) -> Result<String, FsError> {
    let mut bytes = [0u8; 16];
    OsEntropy
        .fill(&mut bytes)
        .map_err(|_| FsError::Io("no randomness for a temporary name".into()))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{hex}{suffix}"))
}

impl LocalFs {
    /// The sync root at `root`, which must be an existing directory that is not a link or
    /// another reparse point. Opening empties the reserved `tmp` directory (writes a crash left
    /// behind) and removes quarantined files older than 30 days.
    pub fn new(root: &Path) -> Result<Self, FsError> {
        let meta = fs::symlink_metadata(root).map_err(|e| io_error(&e))?;
        if !meta.is_dir() || meta.file_type().is_symlink() || is_reparse(&meta) {
            return Err(FsError::CannotSync(
                "the sync root must be a plain directory".into(),
            ));
        }
        let root = fs::canonicalize(root).map_err(|e| io_error(&e))?;
        let tolerance_ms = volume_tolerance_ms(&root);
        let me = Self {
            root,
            tolerance_ms,
            dirs: Arc::new(Mutex::new(Arc::new(BTreeMap::new()))),
        };
        me.clean_reserved();
        Ok(me)
    }

    /// Empties `tmp` and removes expired quarantine entries; both walk by handles and enter
    /// only plain directories, so a link or junction at any level removes nothing outside.
    fn clean_reserved(&self) {
        plat::clean_temp(&self.root);
        plat::clean_quarantine(&self.root, SystemTime::now());
    }

    /// The root as an absolute (on Windows verbatim) path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The platform path of `path`, after every name passed the checks (module docs).
    pub fn full_path(&self, path: &[String]) -> Result<PathBuf, FsError> {
        let mut out = self.root.clone();
        for name in path {
            if let Some(problem) = name_problem(name) {
                return Err(FsError::CannotSync(problem));
            }
            out.push(name);
        }
        Ok(out)
    }

    /// The file IDs of the directories below the root as the index knows them (L1): a snapshot
    /// as of this call, as the copy of the map was before, so a change after the call does not
    /// alter the IDs one operation checks against.
    fn expected(&self) -> Arc<DirIds> {
        self.dirs.lock().map(|d| Arc::clone(&d)).unwrap_or_default()
    }

    /// The place of `path` after the name checks and the check of every directory on the way
    /// (module docs, L1). `None` on Unix when a directory on the way does not exist; on Windows
    /// a component that does not exist ends the check and the operation then fails on it.
    fn locate(&self, path: &[String]) -> Result<Option<plat::Spot>, FsError> {
        let full = self.full_path(path)?;
        let spot = plat::locate(&self.root, full, path, &self.expected())?;
        #[cfg(test)]
        race::after_check(path);
        Ok(spot)
    }

    /// [`LocalFs::locate`] for an operation that needs the directory on the way.
    fn spot(&self, path: &[String]) -> Result<plat::Spot, FsError> {
        self.locate(path)?.ok_or(FsError::NotFound)
    }

    /// The directory `path` itself (the root for an empty path), after the same checks; a link,
    /// a junction or a file in its place is [`FsError::Changed`].
    fn folder(&self, path: &[String]) -> Result<plat::Folder, FsError> {
        let full = self.full_path(path)?;
        let folder = plat::open_folder(&self.root, full, path, &self.expected())?;
        #[cfg(test)]
        race::after_check(path);
        Ok(folder)
    }

    /// The path below the root of an absolute path from a watcher event, with 8.3 short names
    /// resolved to long names first (ADR 0001, section 7). `None` for a path outside the root
    /// or a name that is not UTF-8.
    pub fn relative(&self, absolute: &Path) -> Option<Vec<String>> {
        let long = long_path(absolute);
        let long = strip_verbatim(&long);
        let root = strip_verbatim(&self.root);
        let rest = long.strip_prefix(&root).ok()?;
        rest.components()
            .map(|c| c.as_os_str().to_str().map(str::to_owned))
            .collect()
    }

    /// `.hangar-drive/<parts>` below the root, created one level at a time, with every level
    /// checked to be a plain directory (no symbolic link, junction or other reparse point,
    /// read without following it, security review N5). A link at any level, `.hangar-drive`
    /// itself included, would let a temporary write or a quarantined file land outside the
    /// root; `create_dir_all` alone follows it.
    fn reserved_dir(&self, parts: &[&str]) -> Result<plat::Folder, FsError> {
        plat::reserved_dir(&self.root, parts)
    }

    /// A new temporary file with a random name (L4). A name that exists is drawn again; it is
    /// never the target's "already exists".
    fn create_temp(&self, suffix: &str) -> Result<(plat::Spot, File), FsError> {
        let dir = self.reserved_dir(&[TEMP_DIR])?;
        for _ in 0..8 {
            let spot = dir.child(OsStr::new(&random_name(suffix)?));
            match spot.create_new() {
                Ok(file) => return Ok((spot, file)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(match io_error(&e) {
                        FsError::Exists => FsError::Io("the temporary name is taken".into()),
                        other => other,
                    })
                }
            }
        }
        Err(FsError::Io("no free temporary name".into()))
    }

    fn stat_matches(&self, s: &Stat, expect: Expect) -> bool {
        s.kind == EntryType::File
            && s.size == expect.size
            && (s.mtime_ms - expect.mtime_ms).abs() <= self.tolerance_ms
            && match (expect.file_id, s.file_id) {
                (Some(want), Some(have)) => want == have,
                _ => true,
            }
    }

    fn matches(&self, spot: &plat::Spot, expect: Expect) -> Result<bool, FsError> {
        Ok(spot.stat()?.is_some_and(|s| self.stat_matches(&s, expect)))
    }

    /// Puts a file that a replace pushed out, and that the person changed, next to the target
    /// as a conflict copy (L3).
    fn keep_as_conflict(&self, old: &plat::Spot, target: &plat::Spot) -> Result<(), FsError> {
        let name = target.name().to_str().ok_or(FsError::NotFound)?;
        let date = date_label(millis(SystemTime::now()), 0);
        let words = LabelWords::default();
        for n in 0..20u32 {
            let base = conflict_copy_name(name, &words, LOCAL_DEVICE_LABEL, &date, &|candidate| {
                matches!(target.sibling(candidate).stat(), Ok(Some(_)))
            });
            let candidate = if n == 0 {
                base
            } else {
                let (stem, ext) = crate::names::split_extension(&base);
                format!("{stem} {n}{ext}")
            };
            match old.rename_noreplace(&target.sibling(&candidate)) {
                Ok(()) => return Ok(()),
                Err(e) if io_error(&e) == FsError::Exists => continue,
                Err(e) => return Err(io_error(&e)),
            }
        }
        Err(FsError::Io("no free name for a conflict copy".into()))
    }

    /// Replaces `target` with `temp` and keeps the old file when it changed after the check
    /// (module docs, L3).
    fn replace_checked(
        &self,
        temp: &plat::Spot,
        target: &plat::Spot,
        expect: Expect,
    ) -> Result<(), FsError> {
        #[cfg(windows)]
        {
            // Windows has no swap of two names by handle (`ReplaceFileW` takes paths), so the
            // swap is two renames by handle, neither of which replaces: the old file moves into
            // `tmp`, then the new one takes the freed name. Nothing is lost in between; for that
            // moment the name is free.
            temp.inherit_from(target);
            let aside = self.reserved_dir(&[TEMP_DIR])?;
            let backup = self.move_aside(target, &aside)?;
            #[cfg(test)]
            race::after_check(&[race::REPLACE_SWAPPED.to_owned()]);
            if let Err(e) = with_lock_retry(|| temp.rename_noreplace(target)) {
                // Someone took the name in that moment: the old file goes back or, if that fails
                // too, next to it as a conflict copy, never left in `tmp` (emptied at start).
                if with_lock_retry(|| backup.rename_noreplace(target)).is_err() {
                    self.keep_as_conflict(&backup, target)?;
                }
                return Err(match e {
                    FsError::Exists => FsError::Changed,
                    other => other,
                });
            }
            self.settle_old(&backup, target, expect)
        }
        #[cfg(not(windows))]
        {
            // The new file first takes a backup name in `tmp`, so the name that holds the old
            // file after the exchange is one the cleaning at start recovers instead of deleting
            // (L3).
            let backup = temp.sibling(&random_name(BACKUP_SUFFIX)?);
            with_lock_retry(|| temp.rename_noreplace(&backup))?;
            let result = match with_lock_retry(|| backup.exchange(target)) {
                // `backup` now holds the old file.
                Ok(true) => {
                    #[cfg(test)]
                    race::after_check(&[race::REPLACE_SWAPPED.to_owned()]);
                    return self.settle_old(&backup, target, expect);
                }
                Ok(false) => with_lock_retry(|| backup.rename(target)),
                Err(e) => Err(e),
            };
            if result.is_err() {
                // Still the new content: nothing to keep.
                let _ = backup.remove_file();
            }
            result
        }
    }

    /// The old file after a swap: removed when it still was what the index expected, else
    /// kept as a conflict copy.
    fn settle_old(
        &self,
        old: &plat::Spot,
        target: &plat::Spot,
        expect: Expect,
    ) -> Result<(), FsError> {
        // The pushed-out file keeps its file ID through the swap (a rename exchange and the two
        // renames on Windows move names, not files), so the whole expectation applies.
        let unchanged = match old.stat()? {
            None => true,
            Some(s) => self.stat_matches(&s, expect),
        };
        if unchanged {
            let _ = old.remove_file();
            Ok(())
        } else {
            self.keep_as_conflict(old, target)
        }
    }

    /// Moves the file at `target` into `aside` under a new random name and returns its place
    /// there (the replace on Windows, [`LocalFs::replace_checked`]).
    #[cfg(windows)]
    fn move_aside(&self, target: &plat::Spot, aside: &plat::Folder) -> Result<plat::Spot, FsError> {
        for _ in 0..8 {
            let backup = aside.child(OsStr::new(&random_name(BACKUP_SUFFIX)?));
            match with_lock_retry(|| target.rename_file_noreplace(&backup)) {
                Ok(()) => return Ok(backup),
                Err(FsError::Exists) => continue,
                // The file went away after the check.
                Err(FsError::NotFound) => return Err(FsError::Changed),
                Err(e) => return Err(e),
            }
        }
        Err(FsError::Io("no free temporary name".into()))
    }

    fn move_dir_ids(&self, from: &[String], to: &[String]) {
        if let Ok(mut dirs) = self.dirs.lock() {
            let dirs = Arc::make_mut(&mut dirs);
            let moved: Vec<(Vec<String>, u128)> = dirs
                .iter()
                .filter(|(k, _)| k.starts_with(from))
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            for (k, v) in moved {
                dirs.remove(&k);
                let mut nk = to.to_vec();
                nk.extend_from_slice(&k[from.len()..]);
                dirs.insert(nk, v);
            }
        }
    }

    fn quarantine(&self, item: &ItemId, spot: &plat::Spot) -> Result<(), FsError> {
        let item = item.to_hex();
        let dir = self.reserved_dir(&[QUARANTINE_DIR, &item])?;
        let name = spot.name().to_owned();
        let mut target = dir.child(&name);
        for n in 1..100u32 {
            match with_lock_retry(|| spot.rename_noreplace(&target)) {
                Ok(()) => return Ok(()),
                Err(FsError::Exists) => {
                    let numbered = format!("{} ({n})", name.to_string_lossy());
                    target = dir.child(OsStr::new(&numbered));
                }
                Err(e) => return Err(e),
            }
        }
        Err(FsError::Io("no free name in the quarantine".into()))
    }
}

fn strip_verbatim(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

#[cfg(windows)]
fn is_reparse(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_meta: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_executable(file: &File, on: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = file.metadata()?.permissions();
    let mode = perms.mode();
    perms.set_mode(if on { mode | 0o100 } else { mode & !0o100 });
    file.set_permissions(perms)
}

#[cfg(not(unix))]
fn set_executable(_file: &File, _on: bool) -> io::Result<()> {
    Ok(())
}

/// The long form of a path whose components may be 8.3 short names (Windows); other platforms
/// return it unchanged. A path that does not exist (any more) is returned unchanged.
#[cfg(windows)]
pub fn long_path(path: &Path) -> PathBuf {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut buf = vec![0u16; 1024];
    for _ in 0..3 {
        let capacity = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `wide` is NUL-terminated and lives across the call; `buf` has room for
        // `capacity` UTF-16 units, and the function writes at most that many.
        let n = unsafe { GetLongPathNameW(wide.as_ptr(), buf.as_mut_ptr(), capacity) } as usize;
        if n == 0 {
            return path.to_path_buf();
        }
        if n < buf.len() {
            buf.truncate(n);
            return PathBuf::from(std::ffi::OsString::from_wide(&buf));
        }
        buf.resize(n + 1, 0);
    }
    path.to_path_buf()
}

/// The long form of a path (Windows only resolves 8.3 names).
#[cfg(not(windows))]
pub fn long_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// The mtime tolerance of the volume of `path` (module docs).
#[cfg(windows)]
fn volume_tolerance_ms(path: &Path) -> i64 {
    if volume_is_fat(path) {
        2_000
    } else {
        0
    }
}

/// The mtime tolerance of the volume of `path` from its `statfs` magic (module docs); none when
/// `statfs` fails.
#[cfg(target_os = "linux")]
fn volume_tolerance_ms(path: &Path) -> i64 {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return 0;
    };
    let mut info = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `c_path` is a NUL-terminated string that lives across the call, and `info` points
    // to writable memory of the size of `struct statfs`, which the call fills on success.
    if unsafe { libc::statfs(c_path.as_ptr(), info.as_mut_ptr()) } != 0 {
        return 0;
    }
    // SAFETY: `statfs` returned 0, so it wrote the whole struct; it was zeroed before anyway.
    let info = unsafe { info.assume_init() };
    // `f_type` is `__fsword_t`, 64 bits on x86_64 and 32 bits on some other targets.
    #[allow(clippy::unnecessary_cast)]
    let magic = info.f_type as i64;
    tolerance_for_magic(magic)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn volume_tolerance_ms(_path: &Path) -> i64 {
    0
}

/// `MSDOS_SUPER_MAGIC` (vfat and msdos), `linux/magic.h`.
pub const MSDOS_MAGIC: i64 = 0x4d44;
/// exFAT, `EXFAT_SUPER_MAGIC` of `linux/magic.h`.
pub const EXFAT_MAGIC: i64 = 0x2011_bab0;
/// `V9FS_MAGIC`: 9p, which WSL 2 uses for Windows drives (drvfs) under `/mnt`.
pub const V9FS_MAGIC: i64 = 0x0102_1997;

/// The mtime tolerance in milliseconds for a Linux file system magic (`statfs` `f_type`): 2 s
/// for FAT and exFAT, 1 s for 9p (WSL's drvfs, whole second times measured), none otherwise.
pub fn tolerance_for_magic(magic: i64) -> i64 {
    match magic {
        MSDOS_MAGIC | EXFAT_MAGIC => 2_000,
        V9FS_MAGIC => 1_000,
        _ => 0,
    }
}

/// Whether the volume of `path` is FAT or exFAT (2 s write time resolution).
#[cfg(windows)]
fn volume_is_fat(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut volume = vec![0u16; 1024];
    let len = u32::try_from(volume.len()).unwrap_or(u32::MAX);
    // SAFETY: `wide` is NUL-terminated; `volume` holds `len` units and receives a NUL-terminated
    // string of at most that length.
    if unsafe { GetVolumePathNameW(wide.as_ptr(), volume.as_mut_ptr(), len) } == 0 {
        return false;
    }
    let mut fs_name = [0u16; 64];
    // SAFETY: `volume` is NUL-terminated (written above); `fs_name` has room for 64 units as
    // passed; every other output pointer is null, which the API allows.
    let ok = unsafe {
        GetVolumeInformationW(
            volume.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            64,
        )
    };
    if ok == 0 {
        return false;
    }
    let end = fs_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fs_name.len());
    let name = String::from_utf16_lossy(&fs_name[..end]).to_ascii_uppercase();
    name.contains("FAT")
}

impl FileSystem for LocalFs {
    fn stat(&self, path: &[String]) -> Result<Option<Stat>, FsError> {
        if path.is_empty() {
            return self.folder(path)?.stat();
        }
        match self.locate(path)? {
            Some(spot) => spot.stat(),
            // A directory on the way does not exist, so neither does the entry.
            None => Ok(None),
        }
    }

    fn list(&self, path: &[String]) -> Result<Vec<ListEntry>, FsError> {
        self.folder(path)?.list()
    }

    fn read_at(&self, path: &[String], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let spot = self.spot(path)?;
        with_lock_retry(|| {
            let mut file = spot.open_read()?;
            file.seek(SeekFrom::Start(offset))?;
            let mut filled = 0;
            while filled < buf.len() {
                let n = file.read(&mut buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            Ok(filled)
        })
    }

    fn create_dir(&self, path: &[String]) -> Result<(), FsError> {
        let spot = self.spot(path)?;
        spot.create_dir().map_err(|e| io_error(&e))?;
        if let Some(id) = spot.dir_id() {
            if let Ok(mut dirs) = self.dirs.lock() {
                Arc::make_mut(&mut dirs).insert(path.to_vec(), id);
            }
        }
        Ok(())
    }

    fn write_atomic(
        &self,
        path: &[String],
        fill: &mut dyn FnMut(&mut dyn Write) -> Result<(), FsError>,
        mtime_ms: i64,
        executable: bool,
        replace: Option<Expect>,
    ) -> Result<Stat, FsError> {
        // A directory on the way that is gone: a replace no longer finds what it expects, a new
        // file has nowhere to go.
        let missing = if replace.is_some() {
            FsError::Changed
        } else {
            FsError::NotFound
        };
        let target = self.locate(path)?.ok_or(missing)?;
        let (temp, file) = self.create_temp(".part")?;
        let result = (|| {
            let mut writer = io::BufWriter::new(file);
            fill(&mut writer)?;
            let file = writer.into_inner().map_err(|e| io_error(e.error()))?;
            file.sync_all().map_err(|e| io_error(&e))?;
            file.set_modified(system_time(mtime_ms))
                .map_err(|e| io_error(&e))?;
            set_executable(&file, executable).map_err(|e| io_error(&e))?;
            drop(file);
            match replace {
                Some(expect) => {
                    if !self.matches(&target, expect)? {
                        return Err(FsError::Changed);
                    }
                    self.replace_checked(&temp, &target, expect)?;
                }
                // No placeholder: the rename itself claims the name or reports it taken
                // (security review N3, L2).
                None => with_lock_retry(|| temp.rename_noreplace(&target))?,
            }
            target.stat()?.ok_or(FsError::NotFound)
        })();
        if result.is_err() {
            let _ = temp.remove_file();
        }
        result
    }

    fn rename(&self, from: &[String], to: &[String]) -> Result<(), FsError> {
        let (source, target) = (self.spot(from)?, self.spot(to)?);
        if let Some(existing) = target.stat()? {
            // A case-only rename on a case-insensitive volume finds the item itself.
            let current = source.stat()?.ok_or(FsError::NotFound)?;
            if existing.file_id.is_none() || existing.file_id != current.file_id {
                return Err(FsError::Exists);
            }
            #[cfg(test)]
            race::after_check(&[race::SAME_FILE_RENAME.to_owned()]);
            // Windows: a rename without replace changes the case of the same entry (NTFS takes
            // it, test `a_rename_onto_the_same_file_never_replaces_another_one`), and a file put
            // under the target name after the check is "already exists" instead of being
            // replaced for good (security review L5). Linux and macOS keep the plain rename: on a
            // case-insensitive APFS volume `RENAME_EXCL` may refuse the case change of the same
            // entry (not measured), and two names of one inode make `rename` a no-op.
            #[cfg(windows)]
            with_lock_retry(|| source.rename_noreplace(&target))?;
            #[cfg(not(windows))]
            with_lock_retry(|| source.rename(&target))?;
        } else {
            with_lock_retry(|| source.rename_noreplace(&target))?;
        }
        self.move_dir_ids(from, to);
        Ok(())
    }

    fn remove_file(&self, path: &[String], expect: Expect) -> Result<(), FsError> {
        // A directory on the way that is gone: the file is not what the index expects.
        let spot = self.locate(path)?.ok_or(FsError::Changed)?;
        if !self.matches(&spot, expect)? {
            return Err(FsError::Changed);
        }
        with_lock_retry(|| spot.remove_file())
    }

    fn trash_file(
        &self,
        item: &ItemId,
        path: &[String],
        expect: Expect,
    ) -> Result<Trashed, FsError> {
        let spot = self.locate(path)?.ok_or(FsError::Changed)?;
        if !self.matches(&spot, expect)? {
            return Err(FsError::Changed);
        }
        // The platform trash takes a path. On Windows the directories on the way are walked
        // again and held without FILE_SHARE_DELETE until the shell is done, so the file
        // system meaning of the path stays the one checked here; the shell's own namespace
        // (folder shortcuts) is checked by `trash::to_recycle_bin`, which refuses an item the
        // shell resolves elsewhere (ADR 0001, amendment "Directory handles on Windows"). On
        // Linux and macOS a swap in that window is the open point named there. The quarantine
        // below goes through the handles.
        #[cfg(windows)]
        let pin = {
            let pin = plat::pin(&self.root, path, &self.expected(), &spot)?;
            if !self.matches(pin.spot(), expect)? {
                return Err(FsError::Changed);
            }
            pin
        };
        let recycled = crate::trash::to_recycle_bin(spot.full());
        #[cfg(windows)]
        drop(pin);
        match recycled {
            // The platform reported success, yet the checked file is still in place: it
            // recycled something else (a path it resolved elsewhere; security review of the
            // Windows handles, M1). The checked file goes to the quarantine, never reported as
            // recycled.
            Ok(()) if self.matches(&spot, expect).unwrap_or(false) => {
                self.quarantine(item, &spot)?;
                Ok(Trashed::Quarantine)
            }
            Ok(()) => Ok(Trashed::RecycleBin),
            Err(_) if matches!(spot.stat(), Ok(Some(_))) => {
                self.quarantine(item, &spot)?;
                Ok(Trashed::Quarantine)
            }
            // The platform reported a failure, yet the file is gone: it went somewhere the
            // platform decided (its own trash); nothing is left to quarantine.
            Err(_) => Ok(Trashed::RecycleBin),
        }
    }

    fn remove_dir(&self, path: &[String]) -> Result<(), FsError> {
        let spot = self.spot(path)?;
        spot.remove_dir()?;
        if let Ok(mut dirs) = self.dirs.lock() {
            Arc::make_mut(&mut dirs).retain(|k, _| !k.starts_with(path));
        }
        Ok(())
    }

    fn set_meta(
        &self,
        path: &[String],
        mtime_ms: i64,
        executable: bool,
        expect: Expect,
    ) -> Result<(), FsError> {
        let spot = self.locate(path)?.ok_or(FsError::Changed)?;
        if !self.matches(&spot, expect)? {
            return Err(FsError::Changed);
        }
        with_lock_retry(|| {
            let file = spot.open_write()?;
            file.set_modified(system_time(mtime_ms))?;
            set_executable(&file, executable)
        })
    }

    fn expect_directories(&self, ids: Vec<(Vec<String>, u128)>) {
        // Built outside the lock, then swapped in: snapshots taken before keep the old map.
        let ids: Arc<DirIds> = Arc::new(ids.into_iter().collect());
        if let Ok(mut dirs) = self.dirs.lock() {
            *dirs = ids;
        }
    }

    fn mtime_tolerance_ms(&self) -> i64 {
        self.tolerance_ms
    }

    fn free_bytes(&self) -> Option<u64> {
        crate::space::free_bytes(&self.root)
    }

    fn volume_bytes(&self) -> Option<u64> {
        crate::space::volume_bytes(&self.root)
    }

    fn exec_supported(&self) -> bool {
        cfg!(unix)
    }
    fn housekeeping(&self, now_ms: i64) {
        // Through handles, as when the root is opened.
        plat::clean_quarantine(&self.root, system_time(now_ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarse_file_systems_get_a_tolerance() {
        assert_eq!(tolerance_for_magic(0x4d44), 2_000, "vfat, msdos");
        assert_eq!(tolerance_for_magic(0x2011_bab0), 2_000, "exfat");
        assert_eq!(tolerance_for_magic(0x0102_1997), 1_000, "9p, WSL drvfs");
        assert_eq!(tolerance_for_magic(0xef53), 0, "ext4");
        assert_eq!(tolerance_for_magic(0x9123_683e), 0, "btrfs");
        assert_eq!(tolerance_for_magic(0x794c_7630), 0, "overlayfs");
    }

    #[test]
    fn names_are_checked_before_paths() {
        assert!(name_problem("ok.txt").is_none());
        assert!(name_problem("..").is_some());
        assert!(name_problem("a/b").is_some());
        #[cfg(windows)]
        {
            assert!(name_problem("..\\x").is_some());
            assert!(name_problem("C:x").is_some());
            assert!(name_problem("CON.txt").is_some());
            assert!(name_problem("trailing.").is_some());
        }
    }

    #[test]
    fn millis_round_trip() {
        for ms in [0i64, 1_700_000_000_123, -5_000] {
            assert_eq!(millis(system_time(ms)), ms);
        }
    }

    #[test]
    fn verbatim_prefix_is_stripped_for_comparison() {
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\C:\x\y")),
            PathBuf::from(r"C:\x\y")
        );
        assert_eq!(strip_verbatim(Path::new("/x/y")), PathBuf::from("/x/y"));
    }

    #[test]
    fn a_file_changed_at_the_last_moment_is_kept_as_a_conflict_copy() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join(".tmp")
            .join(format!("sync-settle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let local = LocalFs::new(&dir).unwrap();
        fs::write(local.root().join("plan.txt"), b"from the server").unwrap();
        // What a swap pushed out: the person saved it after the check (L3).
        let (old, mut file) = local.create_temp(".bak").unwrap();
        file.write_all(b"the edit of a moment ago").unwrap();
        drop(file);
        let expect = Expect {
            size: 3,
            mtime_ms: 0,
            file_id: None,
        };
        let target = local.spot(&["plan.txt".to_owned()]).unwrap();
        local.settle_old(&old, &target, expect).unwrap();
        assert!(!old.full().exists());
        let copies: Vec<String> = fs::read_dir(local.root())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("plan (conflict local "))
            .collect();
        assert_eq!(copies.len(), 1, "{copies:?}");
        assert_eq!(
            fs::read(local.root().join(&copies[0])).unwrap(),
            b"the edit of a moment ago"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    fn scratch_root(tag: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join(".tmp")
            .join(format!("sync-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The files in `.hangar-drive/trash/recovered` with their content.
    fn recovered(local: &LocalFs) -> Vec<Vec<u8>> {
        let dir = local
            .root()
            .join(hangar_drive_protocol::name::RESERVED_ROOT_DIR)
            .join(QUARANTINE_DIR)
            .join(RECOVERED_DIR);
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out: Vec<Vec<u8>> = entries
            .map(|e| fs::read(e.unwrap().path()).unwrap())
            .collect();
        out.sort();
        out
    }

    /// Security review L3: the old file a replace pushed out waits in `tmp` under a backup
    /// name until it is settled. Left there by a crash, it is recovered into the quarantine at
    /// the next start instead of being deleted; a half written download is still removed.
    #[test]
    fn a_backup_left_in_tmp_is_recovered_at_start() {
        let dir = scratch_root("recover");
        let local = LocalFs::new(&dir).unwrap();
        let temp = local
            .root()
            .join(hangar_drive_protocol::name::RESERVED_ROOT_DIR)
            .join(TEMP_DIR);
        fs::create_dir_all(&temp).unwrap();
        fs::write(
            temp.join(format!("00ff{BACKUP_SUFFIX}")),
            b"the person's edit",
        )
        .unwrap();
        fs::write(temp.join("11ee.part"), b"half a download").unwrap();
        let local = LocalFs::new(&dir).unwrap();
        assert_eq!(fs::read_dir(&temp).unwrap().count(), 0);
        assert_eq!(recovered(&local), [b"the person's edit".to_vec()]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The same for a crash right after the swap of a replace, before the old file was
    /// settled: the old content survives the next start.
    #[test]
    fn a_crash_after_the_swap_of_a_replace_loses_no_old_file() {
        let dir = scratch_root("crash");
        let local = LocalFs::new(&dir).unwrap();
        fs::write(local.root().join("plan.txt"), b"old").unwrap();
        let stat = local.stat(&["plan.txt".to_owned()]).unwrap().unwrap();
        let expect = Expect {
            size: stat.size,
            mtime_ms: stat.mtime_ms,
            file_id: stat.file_id,
        };
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _hook = race::arm(|path| {
                if path == [race::REPLACE_SWAPPED] {
                    panic!("simulated crash after the swap");
                }
            });
            let mut fill = |w: &mut dyn Write| w.write_all(b"new").map_err(|e| io_error(&e));
            let _ = local.write_atomic(&["plan.txt".to_owned()], &mut fill, 0, false, Some(expect));
        }));
        assert!(crashed.is_err(), "the hook ran");
        let local = LocalFs::new(&dir).unwrap();
        assert_eq!(recovered(&local), [b"old".to_vec()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn temporary_names_are_random() {
        let a = random_name(".part").unwrap();
        let b = random_name(".part").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32 + 5);
    }
}

/// A hook that runs right after the check of the directories on the way and before the
/// operation, so a test can swap a directory exactly in that window (security review L1). Per
/// thread, so tests that run in parallel do not see each other's hook.
#[cfg(test)]
mod race {
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut(&[String])>;

    /// The path the hook sees right after the swap of a replace, before the old file is
    /// settled (Windows: after the old file moved aside; Linux and macOS: after the exchange).
    pub(super) const REPLACE_SWAPPED: &str = ":replace-swapped";

    /// The path the hook sees between the file ID check of a rename onto the same file (a
    /// case-only rename) and the rename itself; no real name holds a colon.
    pub(super) const SAME_FILE_RENAME: &str = ":same-file-rename";

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// Removes the hook when dropped.
    pub(super) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            HOOK.with(|h| *h.borrow_mut() = None);
        }
    }

    /// Runs `hook` with the path of every following check on this thread until the guard drops.
    pub(super) fn arm(hook: impl FnMut(&[String]) + 'static) -> Armed {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        Armed
    }

    pub(super) fn after_check(path: &[String]) {
        // Taken out while it runs, so a hook that touches the file system cannot re-enter.
        let hook = HOOK.with(|h| h.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook(path);
            HOOK.with(|h| {
                let mut slot = h.borrow_mut();
                if slot.is_none() {
                    *slot = Some(hook);
                }
            });
        }
    }
}

/// The attack of security review L1: a program that may write in the sync root replaces a
/// directory with a link to a directory outside the root (a symbolic link on Unix, a junction or
/// a directory symbolic link on Windows), before the call or between the check of the
/// directories and the operation. Nothing outside the root may change.
#[cfg(test)]
mod link_swap_tests {
    use super::*;
    use hangar_drive_protocol::name::RESERVED_ROOT_DIR;

    /// The kinds of directory link an attacker can put in place of a directory.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Link {
        /// A symbolic link to a directory (Windows: needs developer mode or the privilege).
        Symlink,
        /// A junction (Windows only; any user may create one).
        #[cfg(windows)]
        Junction,
    }

    /// Makes `link` a link of `kind` to the directory `target`; `false` when this kind cannot be
    /// made here (a directory symbolic link on Windows without developer mode).
    fn make_link(kind: Link, target: &Path, link: &Path) -> bool {
        match kind {
            #[cfg(unix)]
            Link::Symlink => {
                std::os::unix::fs::symlink(target, link).unwrap();
                true
            }
            #[cfg(windows)]
            Link::Symlink => match std::os::windows::fs::symlink_dir(target, link) {
                Ok(()) => true,
                // ERROR_PRIVILEGE_NOT_HELD: no developer mode and no elevation.
                Err(e) if e.raw_os_error() == Some(1314) => false,
                Err(e) => panic!("symlink_dir: {e}"),
            },
            #[cfg(windows)]
            Link::Junction => {
                // `mklink` is a built-in of cmd; the arguments go as an argv array, and cmd gets
                // the plain form of the verbatim paths.
                let made = std::process::Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(crate::trash::plain_path(link))
                    .arg(crate::trash::plain_path(target))
                    .output()
                    .unwrap();
                assert!(made.status.success(), "{made:?}");
                true
            }
        }
    }

    /// The link kinds this machine can make; a kind that cannot be made is skipped with a note.
    fn kinds() -> Vec<Link> {
        #[cfg(unix)]
        let all = vec![Link::Symlink];
        #[cfg(windows)]
        let all = vec![Link::Junction, Link::Symlink];
        let probe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join(".tmp")
            .join(format!("sync-l1-probe-{:?}", std::thread::current().id()))
            .join(std::process::id().to_string());
        let _ = fs::remove_dir_all(&probe);
        fs::create_dir_all(probe.join("target")).unwrap();
        let probe = fs::canonicalize(probe).unwrap();
        let mut out = Vec::new();
        for (n, kind) in all.into_iter().enumerate() {
            if make_link(kind, &probe.join("target"), &probe.join(format!("link{n}"))) {
                out.push(kind);
            } else {
                eprintln!("skipped: {kind:?} links cannot be made here (no developer mode)");
            }
        }
        let _ = fs::remove_dir_all(&probe);
        out
    }

    /// A sync root with `a/f`, `a/sub/` and `b0` next to a directory `outside` with the same
    /// names, all below `tests/.tmp/`.
    struct Scene {
        base: PathBuf,
        root: PathBuf,
        outside: PathBuf,
        kind: Link,
        fs: LocalFs,
    }

    impl Scene {
        fn new(tag: &str, kind: Link) -> Scene {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("tests")
                .join(".tmp")
                .join(format!("sync-l1-{tag}-{kind:?}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).unwrap();
            let base = fs::canonicalize(base).unwrap();
            let (root, outside) = (base.join("root"), base.join("outside"));
            for dir in [&root, &outside] {
                fs::create_dir_all(dir.join("a").join("sub")).unwrap();
            }
            fs::write(root.join("a").join("f"), b"inside").unwrap();
            fs::write(root.join("b0"), b"b0").unwrap();
            // The outside twin of `a`: what a link in its place points at.
            fs::remove_dir(outside.join("a").join("sub")).unwrap();
            fs::remove_dir(outside.join("a")).unwrap();
            fs::create_dir(outside.join("sub")).unwrap();
            fs::write(outside.join("f"), b"outside").unwrap();
            let fs = LocalFs::new(&root).unwrap();
            Scene {
                base,
                root,
                outside,
                kind,
                fs,
            }
        }

        /// Replaces `a` with a link to `outside`; the real `a` lives on as `a.moved`.
        fn swap(root: &Path, outside: &Path, kind: Link) {
            fs::rename(root.join("a"), root.join("a.moved")).unwrap();
            assert!(make_link(kind, outside, &root.join("a")));
        }

        fn swap_now(&self) {
            Scene::swap(&self.root, &self.outside, self.kind);
        }

        /// Arms the race hook: `a` is swapped right after the check of `target`, once.
        fn swap_after_check_of(&self, target: &[&str]) -> race::Armed {
            let target: Vec<String> = target.iter().map(|s| (*s).to_owned()).collect();
            let (root, outside, kind) = (self.root.clone(), self.outside.clone(), self.kind);
            let mut done = false;
            race::arm(move |path| {
                if !done && path == target.as_slice() {
                    done = true;
                    Scene::swap(&root, &outside, kind);
                }
            })
        }

        /// Every entry below `outside` with its content (files) and modification time.
        fn outside_state(&self) -> Vec<(PathBuf, Option<Vec<u8>>, SystemTime)> {
            fn walk(dir: &Path, out: &mut Vec<(PathBuf, Option<Vec<u8>>, SystemTime)>) {
                let mut entries: Vec<_> = fs::read_dir(dir)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .collect();
                entries.sort();
                for path in entries {
                    let meta = fs::symlink_metadata(&path).unwrap();
                    let modified = meta.modified().unwrap();
                    if meta.is_dir() {
                        out.push((path.clone(), None, modified));
                        walk(&path, out);
                    } else {
                        out.push((path.clone(), Some(fs::read(&path).unwrap()), modified));
                    }
                }
            }
            let mut out = Vec::new();
            walk(&self.outside, &mut out);
            out
        }

        fn expect_f(&self) -> Expect {
            let stat = self.fs.stat(&p(&["a", "f"])).unwrap().unwrap();
            Expect {
                size: stat.size,
                mtime_ms: stat.mtime_ms,
                file_id: stat.file_id,
            }
        }

        fn moved(&self, name: &str) -> PathBuf {
            self.root.join("a.moved").join(name)
        }
    }

    impl Drop for Scene {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn p(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    fn write(
        fs: &LocalFs,
        path: &[&str],
        bytes: &[u8],
        replace: Option<Expect>,
    ) -> Result<Stat, FsError> {
        let mut fill = |w: &mut dyn Write| w.write_all(bytes).map_err(|e| io_error(&e));
        fs.write_atomic(&p(path), &mut fill, 1_700_000_000_000, false, replace)
    }

    fn item() -> ItemId {
        ItemId::from_bytes([7; 16])
    }

    #[test]
    fn a_directory_already_swapped_for_a_link_is_refused() {
        for kind in kinds() {
            let scene = Scene::new("before", kind);
            let expect = scene.expect_f();
            scene.swap_now();
            let before = scene.outside_state();
            let fs = &scene.fs;

            assert_eq!(write(fs, &["a", "new"], b"x", None), Err(FsError::Changed));
            assert_eq!(
                write(fs, &["a", "f"], b"x", Some(expect)),
                Err(FsError::Changed)
            );
            assert_eq!(
                fs.remove_file(&p(&["a", "f"]), expect),
                Err(FsError::Changed)
            );
            assert_eq!(
                fs.trash_file(&item(), &p(&["a", "f"]), expect),
                Err(FsError::Changed)
            );
            assert_eq!(
                fs.rename(&p(&["a", "f"]), &p(&["g"])),
                Err(FsError::Changed)
            );
            assert_eq!(
                fs.rename(&p(&["b0"]), &p(&["a", "g"])),
                Err(FsError::Changed)
            );
            assert_eq!(fs.create_dir(&p(&["a", "d"])), Err(FsError::Changed));
            assert_eq!(fs.remove_dir(&p(&["a", "sub"])), Err(FsError::Changed));
            assert_eq!(
                fs.set_meta(&p(&["a", "f"]), 0, true, expect),
                Err(FsError::Changed)
            );
            let mut buf = [0u8; 16];
            assert_eq!(
                fs.read_at(&p(&["a", "f"]), 0, &mut buf),
                Err(FsError::Changed)
            );
            assert_eq!(fs.stat(&p(&["a", "f"])), Err(FsError::Changed));
            assert_eq!(fs.list(&p(&["a"])), Err(FsError::Changed));

            assert_eq!(scene.outside_state(), before);
            assert!(scene.root.join("b0").exists());
        }
    }

    #[test]
    fn a_new_file_after_the_swap_lands_in_the_checked_directory() {
        for kind in kinds() {
            let scene = Scene::new("write-new", kind);
            let before = scene.outside_state();
            let _hook = scene.swap_after_check_of(&["a", "new"]);
            write(&scene.fs, &["a", "new"], b"fresh", None).unwrap();
            assert_eq!(scene.outside_state(), before);
            assert_eq!(fs::read(scene.moved("new")).unwrap(), b"fresh");
        }
    }

    #[test]
    fn a_replace_after_the_swap_lands_in_the_checked_directory() {
        for kind in kinds() {
            let scene = Scene::new("write-replace", kind);
            let expect = scene.expect_f();
            let before = scene.outside_state();
            let _hook = scene.swap_after_check_of(&["a", "f"]);
            write(&scene.fs, &["a", "f"], b"replaced", Some(expect)).unwrap();
            assert_eq!(scene.outside_state(), before);
            assert_eq!(fs::read(scene.moved("f")).unwrap(), b"replaced");
        }
    }

    #[test]
    fn a_delete_after_the_swap_removes_nothing_outside() {
        for kind in kinds() {
            let scene = Scene::new("remove", kind);
            let expect = scene.expect_f();
            let before = scene.outside_state();
            let _hook = scene.swap_after_check_of(&["a", "f"]);
            scene.fs.remove_file(&p(&["a", "f"]), expect).unwrap();
            assert_eq!(scene.outside_state(), before);
            assert!(!scene.moved("f").exists());
        }
    }

    #[test]
    fn a_directory_delete_after_the_swap_removes_nothing_outside() {
        for kind in kinds() {
            let scene = Scene::new("rmdir", kind);
            let before = scene.outside_state();
            let _hook = scene.swap_after_check_of(&["a", "sub"]);
            scene.fs.remove_dir(&p(&["a", "sub"])).unwrap();
            assert_eq!(scene.outside_state(), before);
            assert!(!scene.moved("sub").exists());
        }
    }

    #[test]
    fn a_rename_out_of_the_swapped_directory_takes_nothing_from_outside() {
        for kind in kinds() {
            let scene = Scene::new("rename-from", kind);
            let before = scene.outside_state();
            let _hook = scene.swap_after_check_of(&["g"]);
            scene.fs.rename(&p(&["a", "f"]), &p(&["g"])).unwrap();
            assert_eq!(scene.outside_state(), before);
            assert_eq!(fs::read(scene.root.join("g")).unwrap(), b"inside");
        }
    }

    #[test]
    fn a_rename_into_the_swapped_directory_puts_nothing_outside() {
        for kind in kinds() {
            let scene = Scene::new("rename-to", kind);
            let before = scene.outside_state();
            let _hook = scene.swap_after_check_of(&["a", "g"]);
            scene.fs.rename(&p(&["b0"]), &p(&["a", "g"])).unwrap();
            assert_eq!(scene.outside_state(), before);
            assert_eq!(fs::read(scene.moved("g")).unwrap(), b"b0");
        }
    }

    #[test]
    fn a_new_directory_after_the_swap_lands_in_the_checked_directory() {
        for kind in kinds() {
            let scene = Scene::new("mkdir", kind);
            let before = scene.outside_state();
            let _hook = scene.swap_after_check_of(&["a", "d"]);
            scene.fs.create_dir(&p(&["a", "d"])).unwrap();
            assert_eq!(scene.outside_state(), before);
            assert!(scene.moved("d").is_dir());
        }
    }

    #[test]
    fn metadata_after_the_swap_change_nothing_outside() {
        for kind in kinds() {
            let scene = Scene::new("meta", kind);
            let expect = scene.expect_f();
            let before = scene.outside_state();
            let _hook = scene.swap_after_check_of(&["a", "f"]);
            scene
                .fs
                .set_meta(&p(&["a", "f"]), 1_000_000_000_000, true, expect)
                .unwrap();
            assert_eq!(scene.outside_state(), before);
            assert_eq!(
                millis(fs::metadata(scene.moved("f")).unwrap().modified().unwrap()),
                1_000_000_000_000
            );
        }
    }

    #[test]
    fn a_read_after_the_swap_reads_the_checked_file() {
        for kind in kinds() {
            let scene = Scene::new("read", kind);
            let _hook = scene.swap_after_check_of(&["a", "f"]);
            let mut buf = [0u8; 16];
            let n = scene.fs.read_at(&p(&["a", "f"]), 0, &mut buf).unwrap();
            assert_eq!(&buf[..n], b"inside");
        }
    }

    #[test]
    fn a_listing_after_the_swap_lists_the_checked_directory() {
        for kind in kinds() {
            let scene = Scene::new("list", kind);
            let _hook = scene.swap_after_check_of(&["a"]);
            let listed = scene.fs.list(&p(&["a"])).unwrap();
            let mut names: Vec<String> = listed.iter().filter_map(|e| e.name.clone()).collect();
            names.sort();
            assert_eq!(names, ["f", "sub"]);
            // The outside twin has the same names; its `f` holds "outside", the checked one
            // "inside".
            let f = listed.iter().find(|e| e.name.as_deref() == Some("f"));
            assert_eq!(f.map(|e| e.stat.size), Some(6));
        }
    }

    /// Windows: the recycle bin takes a path, so after the check the directories are walked
    /// again and pinned; a swap in between is refused before the shell resolves the path. The
    /// outside twin of `f` has the same size and time and the expectation no file ID, so only
    /// the pin stops the shell from recycling the file outside the root.
    #[cfg(windows)]
    #[test]
    fn a_trash_after_the_swap_hands_the_shell_no_path_through_the_link() {
        for kind in kinds() {
            let scene = Scene::new("trash", kind);
            let inside = scene.root.join("a").join("f");
            fs::write(scene.outside.join("f"), b"inside").unwrap();
            let mtime = fs::metadata(&inside).unwrap().modified().unwrap();
            File::options()
                .write(true)
                .open(scene.outside.join("f"))
                .unwrap()
                .set_modified(mtime)
                .unwrap();
            let expect = Expect {
                file_id: None,
                ..scene.expect_f()
            };
            let before = scene.outside_state();
            let _hook = scene.swap_after_check_of(&["a", "f"]);
            assert_eq!(
                scene.fs.trash_file(&item(), &p(&["a", "f"]), expect),
                Err(FsError::Changed)
            );
            assert_eq!(scene.outside_state(), before);
            assert_eq!(fs::read(scene.moved("f")).unwrap(), b"inside");
        }
    }

    /// Security review L5: a rename onto a name that holds the same file (a case-only rename,
    /// or a second hard link) never replaces. Here the other name is swapped for another file
    /// between the file ID check and the rename; that file must survive.
    #[cfg(windows)]
    #[test]
    fn a_rename_onto_the_same_file_never_replaces_another_one() {
        let scene = Scene::new("same-file", Link::Junction);
        let root = scene.root.clone();
        fs::write(root.join("a.txt"), b"mine").unwrap();
        // A case-only rename works.
        scene.fs.rename(&p(&["a.txt"]), &p(&["A.txt"])).unwrap();
        let names: Vec<String> = fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"A.txt".to_owned()), "{names:?}");
        // A second link of the same file passes the ID check; then someone puts another file
        // in its place.
        fs::hard_link(root.join("A.txt"), root.join("b.txt")).unwrap();
        let other = root.clone();
        let _hook = race::arm(move |path| {
            if path == [race::SAME_FILE_RENAME] {
                fs::remove_file(other.join("b.txt")).unwrap();
                fs::write(other.join("b.txt"), b"theirs").unwrap();
            }
        });
        assert_eq!(
            scene.fs.rename(&p(&["A.txt"]), &p(&["b.txt"])),
            Err(FsError::Exists)
        );
        assert_eq!(fs::read(root.join("b.txt")).unwrap(), b"theirs");
        assert_eq!(fs::read(root.join("A.txt")).unwrap(), b"mine");
    }

    /// `CLSID_FolderShortcut`: a folder the Explorer shell follows through its `target.lnk`.
    #[cfg(windows)]
    const FOLDER_SHORTCUT: &str = "{0AFACED1-E828-11D1-9187-B532F1E9575D}";

    /// Makes `dir\target.lnk` a shell link to `target` (WScript.Shell through PowerShell, the
    /// paths passed in the environment, the command as an argv array).
    #[cfg(windows)]
    fn shell_link(dir: &Path, target: &Path) {
        let made = std::process::Command::new("powershell")
            .env("HD_LNK", crate::trash::plain_path(&dir.join("target.lnk")))
            .env("HD_TARGET", crate::trash::plain_path(target))
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:HD_LNK); \
                 $s.TargetPath = $env:HD_TARGET; $s.Save()",
            ])
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
    }

    /// Security review of the Windows handles, M1, first form: a folder named `x.{CLSID}` with a
    /// `target.lnk` is a folder shortcut for the shell, so the shell resolves a path through it
    /// to the link's target outside the root. Such a name cannot sync on Windows, so the engine
    /// never hands that path to the shell; nothing outside changes. The shell's resolution is
    /// read without deleting anything.
    #[cfg(windows)]
    #[test]
    fn a_shell_junction_name_never_reaches_the_shell() {
        let scene = Scene::new("shell-name", Link::Junction);
        let name = format!("a.{FOLDER_SHORTCUT}");
        let junction = scene.root.join(&name);
        fs::create_dir(&junction).unwrap();
        fs::write(junction.join("f"), b"inside").unwrap();
        shell_link(&junction, &scene.outside);
        let resolved = crate::trash::resolved_by_shell(&junction.join("f")).unwrap();
        assert!(
            resolved.to_string_lossy().eq_ignore_ascii_case(
                &crate::trash::plain_path(&scene.outside.join("f")).to_string_lossy()
            ),
            "the shell resolves {resolved:?}"
        );
        let before = scene.outside_state();
        let expect = Expect {
            size: 6,
            mtime_ms: 0,
            file_id: None,
        };
        assert!(matches!(
            scene
                .fs
                .trash_file(&item(), &[name.clone(), "f".to_owned()], expect),
            Err(FsError::CannotSync(_))
        ));
        assert_eq!(scene.outside_state(), before);
        assert_eq!(fs::read(junction.join("f")).unwrap(), b"inside");
    }

    /// M1, second form: a plain folder name, made a folder shortcut by a `desktop.ini` that names
    /// the CLSID and the read-only attribute. The handles see a plain directory, the shell a
    /// junction to `outside`. The check of the shell's resolution refuses the recycle bin, and
    /// the checked file goes to the quarantine; nothing outside changes.
    #[cfg(windows)]
    #[test]
    fn the_recycle_bin_refuses_a_path_the_shell_resolves_elsewhere() {
        let scene = Scene::new("shell-ini", Link::Junction);
        let a = scene.root.join("a");
        fs::write(
            a.join("desktop.ini"),
            format!("[.ShellClassInfo]\r\nCLSID2={FOLDER_SHORTCUT}\r\nFlags=2\r\n"),
        )
        .unwrap();
        shell_link(&a, &scene.outside);
        let mut perms = fs::metadata(&a).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&a, perms.clone()).unwrap();
        let resolved = crate::trash::resolved_by_shell(&a.join("f")).unwrap();
        let outside_f = crate::trash::plain_path(&scene.outside.join("f"));
        let redirected = resolved
            .to_string_lossy()
            .eq_ignore_ascii_case(&outside_f.to_string_lossy());
        assert!(
            redirected,
            "the shell resolves {resolved:?}, the attack needs {outside_f:?}"
        );
        let expect = scene.expect_f();
        let before = scene.outside_state();
        let trashed = scene.fs.trash_file(&item(), &p(&["a", "f"]), expect);
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(&a, perms).unwrap();
        assert_eq!(trashed, Ok(Trashed::Quarantine));
        assert_eq!(scene.outside_state(), before);
        assert!(!a.join("f").exists());
        let kept = scene
            .root
            .join(RESERVED_ROOT_DIR)
            .join(QUARANTINE_DIR)
            .join(item().to_hex())
            .join("f");
        assert_eq!(fs::read(kept).unwrap(), b"inside");
    }

    #[test]
    fn a_directory_replaced_by_another_directory_is_refused() {
        for kind in kinds() {
            let scene = Scene::new("other-dir", kind);
            let id = scene.fs.stat(&p(&["a"])).unwrap().unwrap().file_id.unwrap();
            scene.fs.expect_directories(vec![(p(&["a"]), id)]);
            fs::rename(scene.root.join("a"), scene.root.join("a.moved")).unwrap();
            fs::create_dir(scene.root.join("a")).unwrap();
            fs::write(scene.root.join("a").join("f"), b"inside").unwrap();
            assert_eq!(
                write(&scene.fs, &["a", "x"], b"x", None),
                Err(FsError::Changed)
            );
            assert_eq!(scene.fs.stat(&p(&["a", "f"])), Err(FsError::Changed));
        }
    }

    #[test]
    fn a_link_at_the_reserved_directory_is_never_followed() {
        for kind in kinds() {
            let scene = Scene::new("reserved", kind);
            // The outside directory with a `tmp` of its own, which the cleaning must not empty.
            fs::create_dir(scene.outside.join(TEMP_DIR)).unwrap();
            fs::write(scene.outside.join(TEMP_DIR).join("keep"), b"keep").unwrap();
            let before = scene.outside_state();
            let reserved = scene.root.join(RESERVED_ROOT_DIR);
            let _ = fs::remove_dir_all(&reserved);
            assert!(make_link(kind, &scene.outside, &reserved));
            assert!(matches!(
                write(&scene.fs, &["new"], b"x", None),
                Err(FsError::CannotSync(_))
            ));
            // Opening the root again cleans `tmp` only through plain directories.
            let _ = LocalFs::new(&scene.root).unwrap();
            assert_eq!(scene.outside_state(), before);
        }
    }
}
