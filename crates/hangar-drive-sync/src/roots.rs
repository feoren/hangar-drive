//! Which folders may become sync roots (security review M4).
//!
//! A new root, and a root the person points a missing folder to (`relocate_folder`), is
//! checked on its canonical form:
//!
//! - **Canonical:** `canonicalize` must succeed (the folder exists and every link on the way is
//!   resolved); a failure is refused, never skipped.
//! - **Comparison key:** the Windows verbatim prefix (`\\?\`, `\\?\UNC\`) is removed and, on
//!   Windows, the path is compared without regard to case, because NTFS and the Windows path
//!   rules treat `C:\Docs` and `c:\docs` as one folder. Other platforms compare exactly; a
//!   case-insensitive APFS volume may still let two spellings name one folder, which
//!   `canonicalize` does not fold (residual risk, ADR 0001, section 7).
//! - **No nesting:** the new root is refused if it lies inside an existing root or holds one,
//!   in both directions, and if it holds the app's own index.
//! - **No drive roots, no system folders:** a drive or volume root (`C:\`, `/`, a UNC share),
//!   the Windows, program and program data folders, the user's application data, the home
//!   folder itself, and the usual Unix and macOS system folders.
//! - **No other cloud's folder:** two sync clients on one folder fight over every change. The
//!   roots this module can see are refused in both directions: OneDrive from the environment
//!   variables its client sets for the session (`OneDrive`, `OneDriveConsumer`,
//!   `OneDriveCommercial`) and from `HKCU\Software\Microsoft\OneDrive\Accounts\<account>`
//!   value `UserFolder` (the registry also lists accounts whose variables are not set in this
//!   process, for example a business account added later), Dropbox from its `info.json`,
//!   iCloud Drive on Windows (`%USERPROFILE%\iCloudDrive`), and on macOS everything below
//!   `~/Library/CloudStorage` (every File Provider client: OneDrive, Google Drive, Dropbox,
//!   Box) and `~/Library/Mobile Documents` (iCloud). Other clients are not recognised.

use std::path::{Path, PathBuf};

/// Why a folder cannot become a sync root.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootError {
    /// The folder does not exist or its path cannot be resolved.
    #[error("the folder cannot be resolved: {0}")]
    Unresolved(String),
    /// It lies inside another sync root, or holds one.
    #[error("the folder overlaps another synced folder")]
    Overlaps,
    /// It holds the app's own index.
    #[error("the folder holds the app's own index")]
    HoldsIndex,
    /// A drive or volume root.
    #[error("a whole drive cannot be synced")]
    DriveRoot,
    /// A system folder, the home folder or application data.
    #[error("a system folder cannot be synced")]
    System,
    /// Another sync client's folder.
    #[error("the folder belongs to {0}")]
    OtherCloud(&'static str),
}

/// The comparison key of a canonical path (module docs).
pub fn key(path: &Path) -> String {
    let text = path.to_string_lossy();
    let text = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        text.into_owned()
    };
    let sep = std::path::MAIN_SEPARATOR;
    let mut text = text.trim_end_matches(sep).to_owned();
    if text.is_empty() || text.ends_with(':') {
        // "/" or "C:" keep their separator, so every key of a root ends without one.
        text.push(sep);
    }
    if cfg!(windows) {
        text = text.replace('/', "\\").to_lowercase();
    }
    text
}

/// Whether `inner` is `outer` or lies below it (keys of [`key`]).
pub fn within(inner: &str, outer: &str) -> bool {
    let sep = std::path::MAIN_SEPARATOR;
    if inner == outer {
        return true;
    }
    let outer = if outer.ends_with(sep) {
        outer.to_owned()
    } else {
        format!("{outer}{sep}")
    };
    inner.starts_with(&outer)
}

/// Whether two keys overlap in either direction.
pub fn overlap(a: &str, b: &str) -> bool {
    within(a, b) || within(b, a)
}

fn is_drive_root(key: &str) -> bool {
    let sep = std::path::MAIN_SEPARATOR;
    if key.ends_with(sep) {
        // "/" and "c:\".
        return true;
    }
    if cfg!(windows) {
        // A UNC share root: "\\server\share".
        if let Some(rest) = key.strip_prefix(r"\\") {
            return rest.split('\\').filter(|s| !s.is_empty()).count() <= 2;
        }
    }
    false
}

/// What the platform forbids: (folder, whether folders below it are forbidden as well).
fn system_folders() -> Vec<(PathBuf, bool)> {
    let mut out = Vec::new();
    let mut add = |path: Option<PathBuf>, below: bool| {
        if let Some(p) = path {
            if !p.as_os_str().is_empty() {
                out.push((p, below));
            }
        }
    };
    let env = |name: &str| std::env::var_os(name).map(PathBuf::from);
    if cfg!(windows) {
        for name in [
            "SystemRoot",
            "windir",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramW6432",
            "ProgramData",
            "APPDATA",
            "LOCALAPPDATA",
        ] {
            add(env(name), true);
        }
        add(env("USERPROFILE"), false);
    } else {
        for dir in [
            "/bin",
            "/boot",
            "/dev",
            "/etc",
            "/lib",
            "/lib64",
            "/opt",
            "/proc",
            "/root",
            "/run",
            "/sbin",
            "/srv",
            "/sys",
            "/usr",
            "/var",
            "/System",
            "/Library",
            "/Applications",
            "/private",
            "/Volumes",
            "/home",
            "/Users",
        ] {
            // `/home` and `/Users` themselves, not the homes below them.
            let below = !matches!(dir, "/Volumes" | "/home" | "/Users");
            add(Some(PathBuf::from(dir)), below);
        }
        add(dirs::home_dir(), false);
        add(dirs::home_dir().map(|h| h.join("Library")), true);
    }
    out
}

/// The roots of other sync clients this module recognises (module docs).
pub fn other_clouds() -> Vec<(&'static str, PathBuf)> {
    let mut out = Vec::new();
    for name in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
        if let Some(p) = std::env::var_os(name) {
            out.push(("OneDrive", PathBuf::from(p)));
        }
    }
    for p in onedrive_registry_folders() {
        out.push(("OneDrive", p));
    }
    for p in dropbox_folders() {
        out.push(("Dropbox", p));
    }
    if cfg!(windows) {
        if let Some(home) = std::env::var_os("USERPROFILE") {
            out.push(("iCloud Drive", PathBuf::from(home).join("iCloudDrive")));
        }
    }
    if cfg!(target_os = "macos") {
        if let Some(home) = dirs::home_dir() {
            out.push((
                "a cloud storage app",
                home.join("Library").join("CloudStorage"),
            ));
            out.push((
                "iCloud Drive",
                home.join("Library").join("Mobile Documents"),
            ));
        }
    }
    out
}

/// `path` of Dropbox's `info.json` files (personal and business accounts).
fn dropbox_folders() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(d) = dirs::config_dir() {
        files.push(d.join("Dropbox").join("info.json"));
    }
    if let Some(d) = dirs::data_local_dir() {
        files.push(d.join("Dropbox").join("info.json"));
    }
    if let Some(h) = dirs::home_dir() {
        files.push(h.join(".dropbox").join("info.json"));
    }
    let mut out = Vec::new();
    for file in files {
        // A small file the Dropbox client writes; anything larger is not read.
        let Ok(meta) = std::fs::metadata(&file) else {
            continue;
        };
        if meta.len() > 64 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if let Some(accounts) = value.as_object() {
            for account in accounts.values() {
                if let Some(path) = account.get("path").and_then(|p| p.as_str()) {
                    out.push(PathBuf::from(path));
                }
            }
        }
    }
    out
}

#[cfg(windows)]
fn onedrive_registry_folders() -> Vec<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ};

    let wide = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(Some(0))
            .collect()
    };
    let value = wide("UserFolder");
    let mut out = Vec::new();
    let accounts =
        std::iter::once("Personal".to_owned()).chain((1..=9).map(|n| format!("Business{n}")));
    for account in accounts {
        let subkey = wide(&format!(r"Software\Microsoft\OneDrive\Accounts\{account}"));
        let mut buf = vec![0u16; 1024];
        let mut bytes = u32::try_from(buf.len() * 2).unwrap_or(u32::MAX);
        // SAFETY: `subkey` and `value` are NUL-terminated and live across the call; `buf` holds
        // `bytes` bytes, and the function writes at most that many and updates `bytes`. The
        // type pointer is null, which the API allows.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status != 0 {
            continue;
        }
        let units = (bytes as usize / 2).min(buf.len());
        let text: &[u16] = &buf[..units];
        let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
        if end > 0 {
            out.push(PathBuf::from(OsString::from_wide(&text[..end])));
        }
    }
    out
}

#[cfg(not(windows))]
fn onedrive_registry_folders() -> Vec<PathBuf> {
    Vec::new()
}

/// The canonical form of a folder, refused if it cannot be resolved.
pub fn canonical(path: &Path) -> Result<PathBuf, RootError> {
    std::fs::canonicalize(path).map_err(|e| RootError::Unresolved(e.kind().to_string()))
}

/// Checks the comparison key of a resolved candidate against the existing roots, the index
/// directory, the forbidden folders and other clouds' roots (module docs). Pure apart from
/// the lists it is given, so the rules are tested on any platform.
pub fn check_key(
    candidate: &str,
    existing: &[String],
    index_dir: Option<&str>,
    system: &[(String, bool)],
    clouds: &[(&'static str, String)],
) -> Result<(), RootError> {
    if is_drive_root(candidate) {
        return Err(RootError::DriveRoot);
    }
    if existing.iter().any(|e| overlap(candidate, e)) {
        return Err(RootError::Overlaps);
    }
    if index_dir.is_some_and(|i| within(i, candidate)) {
        return Err(RootError::HoldsIndex);
    }
    for (dir, below) in system {
        // The folder itself, anything below it where that is forbidden too, and any folder
        // that holds it.
        if candidate == dir || (*below && within(candidate, dir)) || within(dir, candidate) {
            return Err(RootError::System);
        }
    }
    for (name, root) in clouds {
        if overlap(candidate, root) {
            return Err(RootError::OtherCloud(name));
        }
    }
    Ok(())
}

/// Checks `candidate` as a new sync root next to `existing` (module docs) and returns its
/// canonical form. The existing roots are resolved too; one that cannot be resolved (a drive
/// that is not attached) is compared by its stored form.
pub fn check_root(candidate: &Path, existing: &[PathBuf]) -> Result<PathBuf, RootError> {
    let resolved = canonical(candidate)?;
    if !resolved.is_dir() {
        return Err(RootError::Unresolved("not a directory".into()));
    }
    let existing: Vec<String> = existing
        .iter()
        .map(|p| key(&std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())))
        .collect();
    let index = crate::index::default_index_path()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .map(|d| key(&std::fs::canonicalize(&d).unwrap_or(d)));
    let clouds: Vec<(&'static str, String)> = other_clouds()
        .into_iter()
        .map(|(name, p)| (name, key(&std::fs::canonicalize(&p).unwrap_or(p))))
        .collect();
    let system: Vec<(String, bool)> = system_folders()
        .into_iter()
        .map(|(p, below)| (key(&std::fs::canonicalize(&p).unwrap_or(p)), below))
        .collect();
    check_key(
        &key(&resolved),
        &existing,
        index.as_deref(),
        &system,
        &clouds,
    )?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> String {
        key(Path::new(s))
    }

    #[cfg(windows)]
    #[test]
    fn windows_keys_drop_the_verbatim_prefix_and_case() {
        assert_eq!(k(r"\\?\C:\Users\X\Docs"), k(r"c:\users\x\docs"));
        assert_eq!(k(r"\\?\C:\"), r"c:\");
        assert_eq!(k(r"\\?\UNC\srv\share\x"), r"\\srv\share\x");
        assert_eq!(k(r"C:\Docs\"), k(r"c:\DOCS"));
        assert!(within(&k(r"C:\Docs\Sub"), &k(r"c:\docs")));
        assert!(!within(&k(r"C:\Docs2"), &k(r"C:\Docs")));
        assert!(is_drive_root(&k(r"\\?\D:\")));
        assert!(is_drive_root(&k(r"\\srv\share")));
        assert!(!is_drive_root(&k(r"\\srv\share\dir")));
    }

    #[cfg(windows)]
    #[test]
    fn the_rules_on_windows_paths() {
        let system = vec![(k(r"C:\Windows"), true), (k(r"C:\Users\X"), false)];
        let clouds = vec![("OneDrive", k(r"C:\Users\X\OneDrive"))];
        let existing = vec![k(r"C:\Users\X\Docs")];
        let check = |c: &str| {
            check_key(
                &k(c),
                &existing,
                Some(&k(r"C:\Users\X\AppData\Roaming\hd")),
                &system,
                &clouds,
            )
        };
        assert_eq!(check(r"\\?\C:\Users\X\Music"), Ok(()));
        // Both directions of nesting, any case.
        assert_eq!(check(r"c:\users\x\docs\inner"), Err(RootError::Overlaps));
        assert_eq!(check(r"\\?\C:\USERS\X\DOCS"), Err(RootError::Overlaps));
        assert_eq!(check(r"C:\Users\X\Documents"), Ok(()));
        assert_eq!(check(r"C:\"), Err(RootError::DriveRoot));
        assert_eq!(check(r"C:\Windows\Temp"), Err(RootError::System));
        // The home holds the existing root as well; without it, the system rule answers.
        assert_eq!(check(r"C:\Users\X"), Err(RootError::Overlaps));
        let alone = |c: &str| check_key(&k(c), &[], None, &system, &clouds);
        assert_eq!(
            alone(r"C:\Users\X"),
            Err(RootError::System),
            "the home itself"
        );
        assert_eq!(alone(r"C:\Users"), Err(RootError::System), "above the home");
        assert_eq!(
            check(r"C:\Users\X\OneDrive\Pictures"),
            Err(RootError::OtherCloud("OneDrive"))
        );
        let holds_index = check_key(&k(r"C:\Data"), &[], Some(&k(r"C:\Data\hd")), &[], &[]);
        assert_eq!(holds_index, Err(RootError::HoldsIndex));
    }

    #[cfg(not(windows))]
    #[test]
    fn the_rules_on_unix_paths() {
        let system = vec![(k("/etc"), true), (k("/home/x"), false)];
        let clouds = vec![("Dropbox", k("/home/x/Dropbox"))];
        // Outside the home folder, so the home folder itself is refused as a system folder and
        // not first as one that holds an existing root.
        let existing = vec![k("/srv/Docs")];
        let check = |c: &str| check_key(&k(c), &existing, None, &system, &clouds);
        assert_eq!(check("/home/x/Music"), Ok(()));
        assert_eq!(check("/srv/Docs/inner"), Err(RootError::Overlaps));
        assert_eq!(check("/srv"), Err(RootError::Overlaps));
        assert_eq!(check("/home/x"), Err(RootError::System));
        assert_eq!(check("/"), Err(RootError::DriveRoot));
        assert_eq!(check("/etc/x"), Err(RootError::System));
        assert_eq!(
            check("/home/x/Dropbox"),
            Err(RootError::OtherCloud("Dropbox"))
        );
    }

    #[test]
    fn unresolvable_folders_are_refused() {
        let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join(".tmp")
            .join("no-such-folder-for-roots");
        assert!(matches!(
            check_root(&missing, &[]),
            Err(RootError::Unresolved(_))
        ));
    }

    #[test]
    fn a_real_folder_inside_another_root_is_refused_in_both_directions() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join(".tmp")
            .join("roots-nesting");
        let inner = base.join("Outer").join("Inner");
        std::fs::create_dir_all(&inner).unwrap();
        let outer = base.join("Outer");
        assert!(check_root(&outer, &[]).is_ok());
        assert_eq!(
            check_root(&inner, std::slice::from_ref(&outer)),
            Err(RootError::Overlaps)
        );
        assert_eq!(
            check_root(&outer, std::slice::from_ref(&inner)),
            Err(RootError::Overlaps)
        );
        #[cfg(windows)]
        {
            // Another spelling of the same folder.
            let upper = PathBuf::from(outer.to_string_lossy().to_uppercase());
            assert_eq!(
                check_root(&upper, std::slice::from_ref(&outer)),
                Err(RootError::Overlaps)
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
