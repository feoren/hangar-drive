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
//!   happened. On Windows the IDs come from a handle opened with
//!   `FILE_FLAG_OPEN_REPARSE_POINT`, so a junction put in place of a directory reports itself
//!   instead of its target. Unix opens the last component with `O_NOFOLLOW`; between the check
//!   of a directory and the operation a swap is still possible there (a walk with `openat` on
//!   directory handles would close it, open point).
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
//!     one step that keeps the old file (`ReplaceFileW` with a backup on Windows,
//!     `RENAME_EXCHANGE` on Linux, `RENAME_SWAP` on macOS). If the old file no longer matches
//!     (the person saved it between the check and the swap), it is kept next to the target as a
//!     conflict copy instead of being lost.
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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hangar_drive_crypto::{Entropy, OsEntropy};
use hangar_drive_protocol::ids::ItemId;
use hangar_drive_protocol::name::{check_name, RESERVED_ROOT_DIR};

use crate::names::{conflict_copy_name, date_label, LabelWords};
use crate::ports::{EntryType, Expect, FileSystem, FsError, ListEntry, Stat};
use crate::trash::{Trashed, QUARANTINE_DIR};

/// Attempts for an operation on a locked file before [`FsError::Locked`].
const LOCK_ATTEMPTS: u32 = 4;
/// The first wait between attempts; it doubles.
const LOCK_BACKOFF: Duration = Duration::from_millis(40);
/// The temporary directory inside the reserved directory.
pub const TEMP_DIR: &str = "tmp";
/// The device word in the name of a conflict copy this module keeps (a replace that found the
/// file changed at the last moment).
const LOCAL_DEVICE_LABEL: &str = "local";

/// A sync root on disk (module docs).
#[derive(Debug, Clone)]
pub struct LocalFs {
    root: PathBuf,
    tolerance_ms: i64,
    /// File IDs of directories below the root as the index knows them (L1).
    dirs: Arc<Mutex<BTreeMap<Vec<String>, u128>>>,
}

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
            dirs: Arc::new(Mutex::new(BTreeMap::new())),
        };
        me.clean_reserved();
        Ok(me)
    }

    fn reserved(&self) -> PathBuf {
        self.root.join(RESERVED_ROOT_DIR)
    }

    fn clean_reserved(&self) {
        let reserved = self.reserved();
        // Only a plain reserved directory is touched.
        let plain = |p: &Path| {
            fs::symlink_metadata(p)
                .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink() && !is_reparse(&m))
        };
        if !plain(&reserved) {
            return;
        }
        let temp = reserved.join(TEMP_DIR);
        if plain(&temp) {
            if let Ok(entries) = fs::read_dir(&temp) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    match fs::symlink_metadata(&path) {
                        Ok(m) if m.is_dir() && !m.file_type().is_symlink() && !is_reparse(&m) => {
                            let _ = fs::remove_dir_all(&path);
                        }
                        Ok(_) => {
                            let _ = fs::remove_file(&path);
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        let quarantine = reserved.join(QUARANTINE_DIR);
        if plain(&quarantine) {
            crate::trash::clean_quarantine(&quarantine, SystemTime::now());
        }
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

    /// [`LocalFs::full_path`] after the check of every directory on the way (module docs, L1).
    /// A component that does not exist ends the check: the operation then fails on it.
    fn checked_path(&self, path: &[String]) -> Result<PathBuf, FsError> {
        let full = self.full_path(path)?;
        let expected = self.dirs.lock().map(|d| d.clone()).unwrap_or_default();
        let mut current = self.root.clone();
        let check = |at: &Path, rel: Option<&[String]>| -> Result<bool, FsError> {
            match dir_info(at) {
                Ok(Some(id)) => {
                    if let Some(want) = rel.and_then(|r| expected.get(r)) {
                        if *want != id {
                            return Err(FsError::Changed);
                        }
                    }
                    Ok(true)
                }
                Ok(None) => Err(FsError::Changed),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(io_error(&e)),
            }
        };
        if !check(&current, None)? {
            return Err(FsError::NotFound);
        }
        let parents = path.len().saturating_sub(1);
        for i in 0..parents {
            current.push(&path[i]);
            if !check(&current, Some(&path[..=i]))? {
                break;
            }
        }
        Ok(full)
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

    fn temp_dir(&self) -> Result<PathBuf, FsError> {
        self.reserved_dir(&[TEMP_DIR])
    }

    /// `.hangar-drive/<parts>` below the root, created one level at a time, with every level
    /// checked to be a plain directory (no symbolic link, junction or other reparse point,
    /// read without following it, security review N5). A link at any level, `.hangar-drive`
    /// itself included, would let a temporary write or a quarantined file land outside the
    /// root; `create_dir_all` alone follows it.
    fn reserved_dir(&self, parts: &[&str]) -> Result<PathBuf, FsError> {
        let mut dir = self.root.clone();
        for part in std::iter::once(RESERVED_ROOT_DIR).chain(parts.iter().copied()) {
            dir.push(part);
            match fs::create_dir(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io_error(&e)),
            }
            match dir_info(&dir) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(FsError::CannotSync(
                        "the reserved directory is not a plain directory".into(),
                    ))
                }
                Err(e) => return Err(io_error(&e)),
            }
        }
        Ok(dir)
    }

    /// A new temporary file with a random name (L4). A name that exists is drawn again; it is
    /// never the target's "already exists".
    fn create_temp(&self, suffix: &str) -> Result<(PathBuf, File), FsError> {
        let dir = self.temp_dir()?;
        for _ in 0..8 {
            let path = dir.join(random_name(suffix)?);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
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

    fn stat_path(&self, full: &Path) -> Result<Option<Stat>, FsError> {
        let meta = match fs::symlink_metadata(full) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(&e)),
        };
        Ok(Some(stat_of(full, &meta)))
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

    fn matches(&self, full: &Path, expect: Expect) -> Result<bool, FsError> {
        Ok(self
            .stat_path(full)?
            .is_some_and(|s| self.stat_matches(&s, expect)))
    }

    /// Puts a file that a replace pushed out, and that the person changed, next to the target
    /// as a conflict copy (L3).
    fn keep_as_conflict(&self, old: &Path, full: &Path) -> Result<(), FsError> {
        let parent = full.parent().ok_or(FsError::NotFound)?;
        let name = full
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(FsError::NotFound)?;
        let date = date_label(millis(SystemTime::now()), 0);
        let words = LabelWords::default();
        for n in 0..20u32 {
            let base = conflict_copy_name(name, &words, LOCAL_DEVICE_LABEL, &date, &|candidate| {
                parent.join(candidate).exists()
            });
            let candidate = if n == 0 {
                base
            } else {
                let (stem, ext) = crate::names::split_extension(&base);
                format!("{stem} {n}{ext}")
            };
            match sys::rename_noreplace(old, &parent.join(&candidate)) {
                Ok(()) => return Ok(()),
                Err(e) if io_error(&e) == FsError::Exists => continue,
                Err(e) => return Err(io_error(&e)),
            }
        }
        Err(FsError::Io("no free name for a conflict copy".into()))
    }

    /// Replaces `full` with `temp` and keeps the old file when it changed after the check
    /// (module docs, L3).
    fn replace_checked(&self, temp: &Path, full: &Path, expect: Expect) -> Result<(), FsError> {
        #[cfg(windows)]
        {
            let (backup, file) = self.create_temp(".bak")?;
            drop(file);
            let replaced = with_lock_retry(|| sys::replace_file(full, temp, &backup));
            if let Err(e) = replaced {
                let _ = fs::remove_file(&backup);
                return Err(e);
            }
            self.settle_old(&backup, full, expect)
        }
        #[cfg(not(windows))]
        {
            match with_lock_retry(|| sys::exchange(temp, full))? {
                // `temp` now holds the old file.
                true => self.settle_old(temp, full, expect),
                false => with_lock_retry(|| fs::rename(temp, full)),
            }
        }
    }

    /// The old file after a swap: removed when it still was what the index expected, else
    /// kept as a conflict copy.
    fn settle_old(&self, old: &Path, full: &Path, expect: Expect) -> Result<(), FsError> {
        // The pushed-out file keeps its file ID through the swap (measured for `ReplaceFileW`,
        // `docs/wiki/raw/2026-11-26-recycle-bin-measurement.md`; a rename exchange moves names,
        // not files), so the whole expectation applies.
        let unchanged = match self.stat_path(old)? {
            None => true,
            Some(s) => self.stat_matches(&s, expect),
        };
        if unchanged {
            let _ = fs::remove_file(old);
            Ok(())
        } else {
            self.keep_as_conflict(old, full)
        }
    }

    fn move_dir_ids(&self, from: &[String], to: &[String]) {
        if let Ok(mut dirs) = self.dirs.lock() {
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

    fn quarantine(&self, item: &ItemId, full: &Path) -> Result<(), FsError> {
        let item = item.to_hex();
        let dir = self.reserved_dir(&[QUARANTINE_DIR, &item])?;
        let name = full.file_name().ok_or(FsError::NotFound)?;
        let mut target = dir.join(name);
        for n in 1..100u32 {
            match with_lock_retry(|| sys::rename_noreplace(full, &target)) {
                Ok(()) => return Ok(()),
                Err(FsError::Exists) => {
                    target = dir.join(format!("{} ({n})", name.to_string_lossy()));
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

#[cfg(windows)]
fn is_system(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x4 != 0
}

#[cfg(not(windows))]
fn is_system(_meta: &fs::Metadata) -> bool {
    false
}

/// The file ID of a plain directory at `path`, `Ok(None)` if it is something else (a link, a
/// junction, a file), read without following links (L1).
fn dir_info(path: &Path) -> io::Result<Option<u128>> {
    #[cfg(windows)]
    {
        let (attributes, id) = sys::handle_info(path)?;
        let directory = attributes & 0x10 != 0;
        let reparse = attributes & 0x400 != 0;
        Ok((directory && !reparse).then_some(id))
    }
    #[cfg(unix)]
    {
        let meta = fs::symlink_metadata(path)?;
        Ok((meta.is_dir() && !meta.file_type().is_symlink()).then(|| unix_id(&meta)))
    }
    #[cfg(not(any(windows, unix)))]
    {
        let meta = fs::symlink_metadata(path)?;
        Ok((meta.is_dir() && !meta.file_type().is_symlink()).then_some(0))
    }
}

#[cfg(unix)]
fn file_id(_full: &Path, meta: &fs::Metadata) -> Option<u128> {
    Some(unix_id(meta))
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
/// [`fs::Metadata::created`] is `stx_btime` from the `statx` call std already makes on Linux with
/// glibc (std asks for `STATX_BTIME` and reports it only when the file system sets it in
/// `stx_mask`) and `st_birthtime` on macOS, so the birth time costs no extra system call and no
/// unsafe code here.
///
/// `st_ctime` is deliberately not the fallback: it changes with every rename, time change and
/// mode change (measured, same record), so a move would lose its file ID, a directory would get a
/// new ID with every entry added to it (failing the L1 check of every later operation in it), and
/// every `set_meta` would read as a replace by someone else. Where no birth time is reported
/// (ext4 with 128 byte inodes, 9p, NFSv3, many FUSE file systems, musl builds whose std does not
/// call `statx`), the ID stays device and inode, the residual risk named in ADR 0001, section 7.
#[cfg(unix)]
fn unix_id(meta: &fs::Metadata) -> u128 {
    use std::os::unix::fs::MetadataExt;
    let base = (u128::from(meta.dev()) << 64) | u128::from(meta.ino());
    match birth_nanos(meta) {
        // The inode stays in the low half, so two files on one device never share an ID. A
        // reused inode differs in the high half, because `mix` is a bijection: different birth
        // times give different values. Mixing keeps device and time bits from cancelling out
        // between two devices.
        Some(birth) => base ^ (u128::from(mix(birth)) << 64),
        None => base,
    }
}

/// Nanoseconds since the Unix epoch of the birth time, `None` where the file system reports
/// none (std returns an error, macOS reports 0 on a volume without birth times).
#[cfg(unix)]
fn birth_nanos(meta: &fs::Metadata) -> Option<u64> {
    let since = meta.created().ok()?.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(since.as_nanos())
        .ok()
        .filter(|nanos| *nanos != 0)
}

/// The SplitMix64 finalizer: a bijection on `u64` that spreads every input bit over the output.
#[cfg(unix)]
fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[cfg(windows)]
fn file_id(full: &Path, _meta: &fs::Metadata) -> Option<u128> {
    sys::handle_info(full).ok().map(|(_, id)| id)
}

#[cfg(not(any(windows, unix)))]
fn file_id(_full: &Path, _meta: &fs::Metadata) -> Option<u128> {
    None
}

#[cfg(unix)]
fn executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o100 != 0
}

#[cfg(not(unix))]
fn executable(_meta: &fs::Metadata) -> bool {
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

/// Opens an existing file for reading without following a link in its last component.
///
/// On Windows `FILE_FLAG_OPEN_REPARSE_POINT` opens a symbolic link, junction or cloud
/// placeholder that someone put in place of the file as itself, never what it points at, and
/// the open is refused when the handle is a reparse point (security review N6), as `O_NOFOLLOW`
/// does on Unix. The check is on the opened handle, so it holds for exactly the file that is
/// read. The components above the last one are checked by `checked_path` before the open; a
/// program that may write in the sync root can still swap one of them between that check and
/// the open (ADR 0001, section 7, "Residual risk").
fn open_read(full: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(full)?;
    if is_reparse(&file.metadata()?) {
        return Err(io::Error::other("the file is a reparse point"));
    }
    Ok(file)
}

fn stat_of(full: &Path, meta: &fs::Metadata) -> Stat {
    let file_type = meta.file_type();
    let kind = if file_type.is_symlink() {
        EntryType::Symlink
    } else if is_reparse(meta) {
        EntryType::Reparse
    } else if file_type.is_dir() {
        EntryType::Directory
    } else if file_type.is_file() {
        if is_system(meta) {
            EntryType::System
        } else {
            EntryType::File
        }
    } else {
        EntryType::Other
    };
    let regular = matches!(kind, EntryType::File | EntryType::Directory);
    Stat {
        kind,
        size: if kind == EntryType::File {
            meta.len()
        } else {
            0
        },
        mtime_ms: meta.modified().map(millis).unwrap_or(0),
        file_id: if regular { file_id(full, meta) } else { None },
        executable: kind == EntryType::File && executable(meta),
    }
}

/// Platform calls: the file ID from a handle that does not follow reparse points, the rename
/// that never replaces, and the swap of a replace.
#[cfg(windows)]
mod sys {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx, MoveFileExW,
        ReplaceFileW, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_IGNORE_ACL_ERRORS, REPLACEFILE_IGNORE_MERGE_ERRORS,
    };

    /// `FILE_READ_ATTRIBUTES`.
    const READ_ATTRIBUTES: u32 = 0x80;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    /// Attributes and file ID of `path` itself, a reparse point included (not its target).
    /// The ID is the 128-bit NTFS ID with the volume serial number where the volume has one
    /// (`FileIdInfo`), else the 64-bit file index, in the same form the index always stored.
    pub(super) fn handle_info(path: &Path) -> io::Result<(u32, u128)> {
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let handle = file.as_raw_handle() as HANDLE;
        // SAFETY: `handle` is a valid open handle for the length of `file`; both structures
        // are plain data written by the calls, with their sizes passed.
        unsafe {
            let mut basic: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
            if GetFileInformationByHandle(handle, &mut basic) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut info: FILE_ID_INFO = std::mem::zeroed();
            let ok = GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            );
            let id = if ok != 0 {
                u128::from(info.VolumeSerialNumber).rotate_left(64)
                    ^ u128::from_le_bytes(info.FileId.Identifier)
            } else {
                (u128::from(basic.dwVolumeSerialNumber) << 64)
                    | (u128::from(basic.nFileIndexHigh) << 32)
                    | u128::from(basic.nFileIndexLow)
            };
            Ok((basic.dwFileAttributes, id))
        }
    }

    /// A rename that fails with "already exists" instead of replacing (L2).
    pub(super) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        let (from, to) = (wide(from), wide(to));
        // SAFETY: both paths are NUL-terminated and live across the call. Without
        // MOVEFILE_REPLACE_EXISTING the call fails if `to` exists.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `ReplaceFileW`: `replacement` takes the place of `replaced`, whose old file becomes
    /// `backup` (L3).
    pub(super) fn replace_file(
        replaced: &Path,
        replacement: &Path,
        backup: &Path,
    ) -> io::Result<()> {
        let (a, b, c) = (wide(replaced), wide(replacement), wide(backup));
        // SAFETY: all three paths are NUL-terminated and live across the call; the two reserved
        // pointers are null as documented.
        let ok = unsafe {
            ReplaceFileW(
                a.as_ptr(),
                b.as_ptr(),
                c.as_ptr(),
                REPLACEFILE_IGNORE_MERGE_ERRORS | REPLACEFILE_IGNORE_ACL_ERRORS,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(unix)]
mod sys {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    fn c(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in a path"))
    }

    /// One of the two atomic rename variants; `Ok(false)` when the file system or the kernel
    /// does not offer it.
    fn rename_with(from: &Path, to: &Path, exchange: bool) -> io::Result<bool> {
        let (from, to) = (c(from)?, c(to)?);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: both paths are NUL-terminated and live across the call; AT_FDCWD makes them
        // relative to the working directory, and they are absolute anyway.
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                if exchange {
                    libc::RENAME_EXCHANGE
                } else {
                    libc::RENAME_NOREPLACE
                },
            )
        };
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        // SAFETY: both paths are NUL-terminated and live across the call.
        let result = unsafe {
            libc::renamex_np(
                from.as_ptr(),
                to.as_ptr(),
                if exchange {
                    libc::RENAME_SWAP
                } else {
                    libc::RENAME_EXCL
                },
            )
        };
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        )))]
        let result: libc::c_int = {
            let _ = (&from, &to, exchange);
            return Ok(false);
        };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::ENOTSUP) => Ok(false),
            _ => Err(error),
        }
    }

    /// A rename that fails with "already exists" instead of replacing (L2). Where the atomic
    /// variant is missing, a hard link (which never replaces) and an unlink move a file; a
    /// directory falls back to a check before the rename.
    pub(super) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        if rename_with(from, to, false)? {
            return Ok(());
        }
        let meta = std::fs::symlink_metadata(from)?;
        if meta.is_dir() {
            if std::fs::symlink_metadata(to).is_ok() {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            return std::fs::rename(from, to);
        }
        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }

    /// Swaps two names in one step; `Ok(false)` where that is not offered.
    pub(super) fn exchange(a: &Path, b: &Path) -> io::Result<bool> {
        rename_with(a, b, true)
    }
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
        let full = self.checked_path(path)?;
        self.stat_path(&full)
    }

    fn list(&self, path: &[String]) -> Result<Vec<ListEntry>, FsError> {
        let full = self.checked_path(path)?;
        if !path.is_empty() && dir_info(&full).map_err(|e| io_error(&e))?.is_none() {
            // The directory itself is a link or a junction now.
            return Err(FsError::Changed);
        }
        let reader = fs::read_dir(&full).map_err(|e| io_error(&e))?;
        let mut out = Vec::new();
        for entry in reader {
            let entry = entry.map_err(|e| io_error(&e))?;
            let os_name = entry.file_name();
            let display = os_name.to_string_lossy().into_owned();
            let name = os_name.into_string().ok();
            let entry_path = entry.path();
            let meta = match fs::symlink_metadata(&entry_path) {
                Ok(m) => m,
                // Gone between the listing and the stat: the next scan sees it.
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io_error(&e)),
            };
            let mut stat = stat_of(&entry_path, &meta);
            // A name this device could not have created (only possible through other tools),
            // or one the platform rules refuse, is listed but never synced (L10).
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

    fn read_at(&self, path: &[String], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let full = self.checked_path(path)?;
        with_lock_retry(|| {
            let mut file = open_read(&full)?;
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
        let full = self.checked_path(path)?;
        fs::create_dir(&full).map_err(|e| io_error(&e))?;
        if let Ok(Some(id)) = dir_info(&full) {
            if let Ok(mut dirs) = self.dirs.lock() {
                dirs.insert(path.to_vec(), id);
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
        let full = self.checked_path(path)?;
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
                    if !self.matches(&full, expect)? {
                        return Err(FsError::Changed);
                    }
                    self.replace_checked(&temp, &full, expect)?;
                }
                // No placeholder: the rename itself claims the name or reports it taken
                // (security review N3, L2).
                None => with_lock_retry(|| sys::rename_noreplace(&temp, &full))?,
            }
            self.stat_path(&full)?.ok_or(FsError::NotFound)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn rename(&self, from: &[String], to: &[String]) -> Result<(), FsError> {
        let (from_full, to_full) = (self.checked_path(from)?, self.checked_path(to)?);
        if let Some(existing) = self.stat_path(&to_full)? {
            // A case-only rename on a case-insensitive volume finds the item itself; a plain
            // rename is the only way to change the case of a name there.
            let source = self.stat_path(&from_full)?.ok_or(FsError::NotFound)?;
            if existing.file_id.is_none() || existing.file_id != source.file_id {
                return Err(FsError::Exists);
            }
            with_lock_retry(|| fs::rename(&from_full, &to_full))?;
        } else {
            with_lock_retry(|| sys::rename_noreplace(&from_full, &to_full))?;
        }
        self.move_dir_ids(from, to);
        Ok(())
    }

    fn remove_file(&self, path: &[String], expect: Expect) -> Result<(), FsError> {
        let full = self.checked_path(path)?;
        if !self.matches(&full, expect)? {
            return Err(FsError::Changed);
        }
        with_lock_retry(|| fs::remove_file(&full))
    }

    fn trash_file(
        &self,
        item: &ItemId,
        path: &[String],
        expect: Expect,
    ) -> Result<Trashed, FsError> {
        let full = self.checked_path(path)?;
        if !self.matches(&full, expect)? {
            return Err(FsError::Changed);
        }
        match crate::trash::to_recycle_bin(&full) {
            Ok(()) => Ok(Trashed::RecycleBin),
            Err(_) if full.exists() => {
                self.quarantine(item, &full)?;
                Ok(Trashed::Quarantine)
            }
            // The platform reported a failure, yet the file is gone: it went somewhere the
            // platform decided (its own trash); nothing is left to quarantine.
            Err(_) => Ok(Trashed::RecycleBin),
        }
    }

    fn remove_dir(&self, path: &[String]) -> Result<(), FsError> {
        let full = self.checked_path(path)?;
        if dir_info(&full).map_err(|e| io_error(&e))?.is_none() {
            return Err(FsError::Changed);
        }
        with_lock_retry(|| fs::remove_dir(&full))?;
        if let Ok(mut dirs) = self.dirs.lock() {
            dirs.retain(|k, _| !k.starts_with(path));
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
        let full = self.checked_path(path)?;
        if !self.matches(&full, expect)? {
            return Err(FsError::Changed);
        }
        with_lock_retry(|| {
            let mut options = OpenOptions::new();
            options.write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let file = options.open(&full)?;
            file.set_modified(system_time(mtime_ms))?;
            set_executable(&file, executable)
        })
    }

    fn expect_directories(&self, ids: Vec<(Vec<String>, u128)>) {
        if let Ok(mut dirs) = self.dirs.lock() {
            *dirs = ids.into_iter().collect();
        }
    }

    fn mtime_tolerance_ms(&self) -> i64 {
        self.tolerance_ms
    }

    fn exec_supported(&self) -> bool {
        cfg!(unix)
    }
    fn housekeeping(&self, now_ms: i64) {
        let quarantine = self.reserved().join(QUARANTINE_DIR);
        // Only a plain directory is touched, as when the root is opened.
        let plain = fs::symlink_metadata(&quarantine)
            .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink() && !is_reparse(&m));
        if plain {
            crate::trash::clean_quarantine(&quarantine, system_time(now_ms));
        }
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
        local
            .settle_old(&old, &local.root().join("plan.txt"), expect)
            .unwrap();
        assert!(!old.exists());
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

    #[test]
    fn temporary_names_are_random() {
        let a = random_name(".part").unwrap();
        let b = random_name(".part").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32 + 5);
    }
}
