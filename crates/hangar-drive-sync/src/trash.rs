//! The system's recycle bin for files that other devices deleted (security review M2;
//! [ux-concept, 8.1]: "files deleted locally because another device deleted them go to the
//! recycle bin, not into nothing"). Deletions this device sends are unchanged; they only ever
//! touch the server.
//!
//! | Platform | How |
//! | --- | --- |
//! | Windows | `IFileOperation::DeleteItem` with `FOFX_RECYCLEONDELETE` and `FOF_ALLOWUNDO`, no UI. A progress sink refuses the delete in `PreDeleteItem` when the shell would not recycle (`TSF_DELETE_RECYCLE_IF_POSSIBLE` missing, a drive without a recycle bin), and `PostDeleteItem` confirms the recycled item, so a file is never deleted for good by this path. |
//! | macOS | `NSFileManager trashItemAtURL:resultingItemURL:error:`. |
//! | Linux | The XDG trash (freedesktop.org Trash specification 1.0): `$XDG_DATA_HOME/Trash` for the home's file system, else `$topdir/.Trash-$uid` of the file's mount, with an `info/*.trashinfo` written exclusively before the file moves to `files/`. |
//!
//! When there is no recycle bin or the move fails, the file goes into the quarantine
//! [`QUARANTINE_DIR`] of the sync root, `.hangar-drive/trash/<item ID>/<name>`, on the same
//! volume, so the move is a rename. The reserved directory is never scanned
//! (`hangar_drive_protocol::name::is_ignored`), and [`clean_quarantine`] removes entries older
//! than [`QUARANTINE_DAYS`] when the sync root is opened.
//!
//! Paths: `std` hands Windows the verbatim form (`\\?\C:\...`) of the root. The shell's parser
//! does not take every verbatim path (measured, `docs/wiki/raw/2026-11-26-recycle-bin-measurement.md`),
//! so the shell gets the plain form; a path the plain form cannot carry (longer than `MAX_PATH`)
//! fails there and goes to the quarantine.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The quarantine directory inside the reserved directory of the sync root.
pub const QUARANTINE_DIR: &str = "trash";
/// Days a file stays in the quarantine.
pub const QUARANTINE_DAYS: u64 = 30;

/// Where a deleted file went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trashed {
    /// The system's recycle bin.
    RecycleBin,
    /// The quarantine of the sync root.
    Quarantine,
}

/// Why the recycle bin did not take a file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrashError {
    /// This volume has no recycle bin (or the shell would delete instead).
    #[error("no recycle bin for this file")]
    NoRecycleBin,
    /// The platform refused, with its message.
    #[error("the recycle bin refused: {0}")]
    Failed(String),
}

/// The plain form of a verbatim Windows path for APIs that do not parse `\\?\`; other paths
/// unchanged.
pub fn plain_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

/// Moves `path` (a file) to the system's recycle bin (module docs).
pub fn to_recycle_bin(path: &Path) -> Result<(), TrashError> {
    platform::to_recycle_bin(path)
}

/// Removes quarantine entries older than [`QUARANTINE_DAYS`] below `quarantine`. Errors are
/// ignored: an entry that cannot be removed now is tried again at the next opening.
pub fn clean_quarantine(quarantine: &Path, now: SystemTime) {
    let Ok(entries) = std::fs::read_dir(quarantine) else {
        return;
    };
    let max_age = Duration::from_secs(QUARANTINE_DAYS * 24 * 60 * 60);
    for entry in entries.flatten() {
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        // The entry's directory was made when the file moved in.
        let Ok(made) = meta.modified() else {
            continue;
        };
        if now.duration_since(made).is_ok_and(|age| age > max_age) {
            if meta.is_dir() && !meta.file_type().is_symlink() {
                let _ = std::fs::remove_dir_all(entry.path());
            } else {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::cell::Cell;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::rc::Rc;

    use windows::core::{implement, Ref, Result as WinResult, HRESULT, PCWSTR};
    use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    };
    use windows::Win32::UI::Shell::{
        FileOperation, IFileOperation, IFileOperationProgressSink, IFileOperationProgressSink_Impl,
        IShellItem, SHCreateItemFromParsingName, COPYENGINE_E_USER_CANCELLED, FOFX_EARLYFAILURE,
        FOFX_RECYCLEONDELETE, FOF_ALLOWUNDO, FOF_NO_UI, TSF_DELETE_RECYCLE_IF_POSSIBLE,
    };

    use super::{plain_path, TrashError};

    #[derive(Default)]
    struct Outcome {
        /// The shell would not recycle and the delete was refused.
        refused: Cell<bool>,
        /// The item was recycled (a new item in the recycle bin was reported).
        recycled: Cell<bool>,
    }

    #[implement(IFileOperationProgressSink)]
    struct Sink(Rc<Outcome>);

    #[allow(non_snake_case)]
    impl IFileOperationProgressSink_Impl for Sink_Impl {
        fn StartOperations(&self) -> WinResult<()> {
            Ok(())
        }
        fn FinishOperations(&self, _hrresult: HRESULT) -> WinResult<()> {
            Ok(())
        }
        fn PreRenameItem(
            &self,
            _dwflags: u32,
            _psiitem: Ref<IShellItem>,
            _psznewname: &PCWSTR,
        ) -> WinResult<()> {
            Ok(())
        }
        fn PostRenameItem(
            &self,
            _dwflags: u32,
            _psiitem: Ref<IShellItem>,
            _psznewname: &PCWSTR,
            _hrrename: HRESULT,
            _psinewlycreated: Ref<IShellItem>,
        ) -> WinResult<()> {
            Ok(())
        }
        fn PreMoveItem(
            &self,
            _dwflags: u32,
            _psiitem: Ref<IShellItem>,
            _psidestinationfolder: Ref<IShellItem>,
            _psznewname: &PCWSTR,
        ) -> WinResult<()> {
            Ok(())
        }
        fn PostMoveItem(
            &self,
            _dwflags: u32,
            _psiitem: Ref<IShellItem>,
            _psidestinationfolder: Ref<IShellItem>,
            _psznewname: &PCWSTR,
            _hrmove: HRESULT,
            _psinewlycreated: Ref<IShellItem>,
        ) -> WinResult<()> {
            Ok(())
        }
        fn PreCopyItem(
            &self,
            _dwflags: u32,
            _psiitem: Ref<IShellItem>,
            _psidestinationfolder: Ref<IShellItem>,
            _psznewname: &PCWSTR,
        ) -> WinResult<()> {
            Ok(())
        }
        fn PostCopyItem(
            &self,
            _dwflags: u32,
            _psiitem: Ref<IShellItem>,
            _psidestinationfolder: Ref<IShellItem>,
            _psznewname: &PCWSTR,
            _hrcopy: HRESULT,
            _psinewlycreated: Ref<IShellItem>,
        ) -> WinResult<()> {
            Ok(())
        }
        fn PreDeleteItem(&self, dwflags: u32, _psiitem: Ref<IShellItem>) -> WinResult<()> {
            // Without this flag the shell would delete the file for good (no recycle bin on
            // the drive, or the file too large for it): refuse, the caller quarantines.
            if dwflags & (TSF_DELETE_RECYCLE_IF_POSSIBLE.0 as u32) == 0 {
                self.0.refused.set(true);
                return Err(COPYENGINE_E_USER_CANCELLED.into());
            }
            Ok(())
        }
        fn PostDeleteItem(
            &self,
            _dwflags: u32,
            _psiitem: Ref<IShellItem>,
            hrdelete: HRESULT,
            psinewlycreated: Ref<IShellItem>,
        ) -> WinResult<()> {
            if hrdelete.is_ok() && psinewlycreated.is_some() {
                self.0.recycled.set(true);
            }
            Ok(())
        }
        fn PreNewItem(
            &self,
            _dwflags: u32,
            _psidestinationfolder: Ref<IShellItem>,
            _psznewname: &PCWSTR,
        ) -> WinResult<()> {
            Ok(())
        }
        fn PostNewItem(
            &self,
            _dwflags: u32,
            _psidestinationfolder: Ref<IShellItem>,
            _psznewname: &PCWSTR,
            _psztemplatename: &PCWSTR,
            _dwfileattributes: u32,
            _hrnew: HRESULT,
            _psinewitem: Ref<IShellItem>,
        ) -> WinResult<()> {
            Ok(())
        }
        fn UpdateProgress(&self, _iworktotal: u32, _iworksofar: u32) -> WinResult<()> {
            Ok(())
        }
        fn ResetTimer(&self) -> WinResult<()> {
            Ok(())
        }
        fn PauseTimer(&self) -> WinResult<()> {
            Ok(())
        }
        fn ResumeTimer(&self) -> WinResult<()> {
            Ok(())
        }
    }

    /// COM for the calling thread for the length of one operation.
    struct Com(bool);

    impl Com {
        fn enter() -> Result<Self, TrashError> {
            // SAFETY: CoInitializeEx has no pointer arguments besides the reserved null; it is
            // balanced by CoUninitialize in Drop when it succeeded (S_OK or S_FALSE).
            let hr =
                unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
            if hr.is_ok() {
                Ok(Com(true))
            } else if hr == RPC_E_CHANGED_MODE {
                // COM is already initialised on this thread in another mode; use it as it is.
                Ok(Com(false))
            } else {
                Err(TrashError::Failed(format!("COM: {hr:?}")))
            }
        }
    }

    impl Drop for Com {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: balances the successful CoInitializeEx of `enter` on this thread.
                unsafe { CoUninitialize() };
            }
        }
    }

    pub(super) fn to_recycle_bin(path: &Path) -> Result<(), TrashError> {
        let _com = Com::enter()?;
        let plain = plain_path(path);
        let wide: Vec<u16> = plain.as_os_str().encode_wide().chain(Some(0)).collect();
        let outcome = Rc::new(Outcome::default());
        let sink: IFileOperationProgressSink = Sink(Rc::clone(&outcome)).into();
        let failed = |e: windows::core::Error| TrashError::Failed(e.message());
        // SAFETY: every call gets valid COM interfaces created here and a NUL-terminated path
        // that lives until the operation finished; the interfaces are released on drop, before
        // `_com` ends COM on this thread.
        unsafe {
            let op: IFileOperation =
                CoCreateInstance(&FileOperation, None, CLSCTX_INPROC_SERVER).map_err(failed)?;
            op.SetOperationFlags(
                FOF_NO_UI | FOF_ALLOWUNDO | FOFX_RECYCLEONDELETE | FOFX_EARLYFAILURE,
            )
            .map_err(failed)?;
            let item: IShellItem =
                SHCreateItemFromParsingName(PCWSTR(wide.as_ptr()), None).map_err(failed)?;
            op.DeleteItem(&item, &sink).map_err(failed)?;
            let performed = op.PerformOperations();
            if outcome.refused.get() {
                return Err(TrashError::NoRecycleBin);
            }
            performed.map_err(failed)?;
            if op.GetAnyOperationsAborted().map_err(failed)?.as_bool() {
                return Err(TrashError::Failed("the operation was aborted".into()));
            }
        }
        if outcome.recycled.get() {
            Ok(())
        } else {
            Err(TrashError::Failed(
                "the shell reported no recycled item".into(),
            ))
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::path::Path;

    use objc2_foundation::{NSFileManager, NSString, NSURL};

    use super::TrashError;

    pub(super) fn to_recycle_bin(path: &Path) -> Result<(), TrashError> {
        let text = path
            .to_str()
            .ok_or_else(|| TrashError::Failed("the path is not UTF-8".into()))?;
        let url = NSURL::fileURLWithPath(&NSString::from_str(text));
        let manager = NSFileManager::defaultManager();
        manager
            .trashItemAtURL_resultingItemURL_error(&url, None)
            .map_err(|e| TrashError::Failed(e.localizedDescription().to_string()))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use super::TrashError;

    fn home_trash() -> Option<PathBuf> {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| dirs::home_dir().map(|h| h.join(".local").join("share")))?;
        Some(data.join("Trash"))
    }

    /// The top directory of the mount that holds `path`: the last ancestor on its device.
    fn top_dir(path: &Path, dev: u64) -> Option<PathBuf> {
        let mut top = path.parent()?.to_path_buf();
        while let Some(parent) = top.parent() {
            match fs::symlink_metadata(parent) {
                Ok(m) if m.dev() == dev => top = parent.to_path_buf(),
                _ => break,
            }
        }
        Some(top)
    }

    fn trash_dir_for(path: &Path) -> Result<PathBuf, TrashError> {
        let meta = fs::symlink_metadata(path).map_err(|e| TrashError::Failed(e.to_string()))?;
        if let Some(home) = home_trash() {
            let home_dev = dirs::home_dir()
                .and_then(|h| fs::metadata(h).ok())
                .map(|m| m.dev());
            if home_dev == Some(meta.dev()) {
                return Ok(home);
            }
        }
        // SAFETY: getuid has no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        let top = top_dir(path, meta.dev()).ok_or(TrashError::NoRecycleBin)?;
        // $topdir/.Trash/$uid only when .Trash is a real directory with the sticky bit.
        let shared = top.join(".Trash");
        if let Ok(m) = fs::symlink_metadata(&shared) {
            if m.is_dir() && !m.file_type().is_symlink() && m.permissions().mode() & 0o1000 != 0 {
                return Ok(shared.join(uid.to_string()));
            }
        }
        Ok(top.join(format!(".Trash-{uid}")))
    }

    fn encode(path: &Path) -> String {
        use std::os::unix::ffi::OsStrExt;
        let mut out = String::new();
        for &b in path.as_os_str().as_bytes() {
            if b.is_ascii_alphanumeric() || b"/-_.~".contains(&b) {
                out.push(char::from(b));
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    fn now_local() -> String {
        // The specification asks for local time without a zone; this crate has no time zone
        // database, so the UTC time is written (the date of a restore list may be off by the
        // zone offset).
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let rest = secs % 86_400;
        let date = crate::names::date_label(i64::try_from(secs).unwrap_or(0) * 1000, 0);
        format!(
            "{date}T{:02}:{:02}:{:02}",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60
        )
    }

    pub(super) fn to_recycle_bin(path: &Path) -> Result<(), TrashError> {
        let failed = |e: std::io::Error| TrashError::Failed(e.to_string());
        let trash = trash_dir_for(path)?;
        let files = trash.join("files");
        let info = trash.join("info");
        for dir in [&files, &info] {
            fs::create_dir_all(dir).map_err(failed)?;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        let name = path
            .file_name()
            .ok_or_else(|| TrashError::Failed("no file name".into()))?
            .to_string_lossy()
            .into_owned();
        for n in 0..1000u32 {
            let candidate = if n == 0 {
                name.clone()
            } else {
                format!("{name}.{n}")
            };
            let info_path = info.join(format!("{candidate}.trashinfo"));
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&info_path)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(failed(e)),
            };
            let text = format!(
                "[Trash Info]\nPath={}\nDeletionDate={}\n",
                encode(path),
                now_local()
            );
            if let Err(e) = file
                .write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
            {
                let _ = fs::remove_file(&info_path);
                return Err(failed(e));
            }
            let target = files.join(&candidate);
            if fs::symlink_metadata(&target).is_ok() {
                let _ = fs::remove_file(&info_path);
                continue;
            }
            return match fs::rename(path, &target) {
                Ok(()) => Ok(()),
                Err(e) => {
                    let _ = fs::remove_file(&info_path);
                    Err(failed(e))
                }
            };
        }
        Err(TrashError::Failed("no free name in the trash".into()))
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    use std::path::Path;

    use super::TrashError;

    pub(super) fn to_recycle_bin(_path: &Path) -> Result<(), TrashError> {
        Err(TrashError::NoRecycleBin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_paths_become_plain() {
        assert_eq!(
            plain_path(Path::new(r"\\?\C:\a\b")),
            PathBuf::from(r"C:\a\b")
        );
        assert_eq!(
            plain_path(Path::new(r"\\?\UNC\srv\share\x")),
            PathBuf::from(r"\\srv\share\x")
        );
        assert_eq!(plain_path(Path::new("/x/y")), PathBuf::from("/x/y"));
    }
}
