//! What the shell asks the operating system: the computer's name, free disk space, the local
//! time zone and language, the taskbar's theme, whether a place lies in another sync client's
//! folder, and showing a folder or file in the file manager. Programs are always started with an
//! argument list, never through a shell; on Windows the file manager is driven through the shell
//! API, never through `explorer.exe` and its own command line parser (security review L5).

use std::path::{Path, PathBuf};
use std::process::Command;

/// The computer's name as a device name: trimmed, at most 64 characters, the `.local` of a
/// macOS host name dropped; `Computer` when there is none.
pub fn device_name() -> String {
    clean_device_name(&raw_host_name().unwrap_or_default())
}

pub fn clean_device_name(raw: &str) -> String {
    let name = raw.trim();
    let name = name.strip_suffix(".local").unwrap_or(name);
    let name: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
    let name = name.trim();
    if name.is_empty() {
        "Computer".to_owned()
    } else {
        name.to_owned()
    }
}

#[cfg(windows)]
fn raw_host_name() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

#[cfg(unix)]
fn raw_host_name() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for its full length, which is passed; the result is
    // NUL-terminated or truncated, and only the bytes up to the first NUL are read.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

#[cfg(not(any(windows, unix)))]
fn raw_host_name() -> Option<String> {
    None
}

/// The default place of the first folder: `Hangar Drive` in the home folder (ux-concept 4.2).
pub fn default_folder() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join("Hangar Drive"))
}

/// Free bytes for this user on the volume of `path`.
#[cfg(windows)]
pub fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut free = 0u64;
    // SAFETY: `wide` is NUL-terminated; `free` is a valid out pointer; the other two may be
    // null as the API documents.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(free)
}

#[cfg(unix)]
pub fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero `statvfs` is a valid value of the plain C struct, and it is fully
    // written by a successful call.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is NUL-terminated and `stat` a valid out pointer.
    if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    Some((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

#[cfg(not(any(windows, unix)))]
pub fn free_bytes(_path: &Path) -> Option<u64> {
    None
}

/// The local time zone's offset from UTC in minutes, now.
#[cfg(windows)]
pub fn tz_offset_minutes() -> i32 {
    use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    // SAFETY: an all-zero TIME_ZONE_INFORMATION is valid; the call fills it.
    let mut info: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out pointer.
    let id = unsafe { GetTimeZoneInformation(&mut info) };
    // 2 is TIME_ZONE_ID_DAYLIGHT; the bias is "UTC = local + bias", so the offset is -bias.
    let extra = if id == 2 {
        info.DaylightBias
    } else {
        info.StandardBias
    };
    -(info.Bias + extra)
}

#[cfg(unix)]
pub fn tz_offset_minutes() -> i32 {
    // SAFETY: `time` with a null pointer only returns the time; `localtime_r` writes `tm`,
    // an all-zero `tm` being a valid value of the plain C struct.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return 0;
        }
        i32::try_from(tm.tm_gmtoff / 60).unwrap_or(0)
    }
}

#[cfg(not(any(windows, unix)))]
pub fn tz_offset_minutes() -> i32 {
    0
}

/// "Until tomorrow" (ux-concept 6.2): 06:00 local time on the next day, in UTC milliseconds.
pub fn next_morning(now_ms: i64, tz_offset_minutes: i32) -> i64 {
    const DAY: i64 = 86_400_000;
    let offset = i64::from(tz_offset_minutes) * 60_000;
    let local = now_ms + offset;
    let midnight = local.div_euclid(DAY) * DAY;
    midnight + DAY + 6 * 3_600_000 - offset
}

/// The user's language as a two-letter code, if the system tells.
#[cfg(windows)]
pub fn os_language() -> Option<String> {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    let mut buf = [0u16; 85];
    // SAFETY: `buf` holds 85 units (LOCALE_NAME_MAX_LENGTH), as passed.
    let len = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), 85) };
    let len = usize::try_from(len).ok().filter(|l| *l > 1)?;
    Some(String::from_utf16_lossy(&buf[..len - 1]))
}

#[cfg(not(windows))]
pub fn os_language() -> Option<String> {
    // macOS GUI apps do not always get LANG; then the window's language decides the rest and
    // the backend texts fall back to English [UNVERIFIED for every macOS setup].
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|v| !v.is_empty() && v != "C" && v != "POSIX")
}

/// Whether the taskbar is dark (Windows: `SystemUsesLightTheme` is 0). Elsewhere a dark panel
/// is assumed, the default of GNOME and KDE.
#[cfg(windows)]
pub fn taskbar_is_dark() -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
    let value = wide("SystemUsesLightTheme");
    let mut data = 0u32;
    let mut size = 4u32;
    // SAFETY: both names are NUL-terminated; `data` holds the four bytes `size` names.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    // Without the value (Windows 10 before 1903) the taskbar is dark.
    rc != 0 || data == 0
}

#[cfg(not(windows))]
pub fn taskbar_is_dark() -> bool {
    true
}

/// `path` without the `\\?\` prefix `canonicalize` puts on Windows paths, which the shell API
/// does not read; other paths unchanged.
pub fn plain(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

/// Opens a folder in the file manager, or shows a file selected in its folder. `path` is a
/// canonical path the caller checked to lie inside a synced folder.
#[cfg(windows)]
pub fn reveal(path: &Path, select: bool) -> std::io::Result<()> {
    if !select && !path.is_dir() {
        // "open" of a file would run it.
        return Err(std::io::Error::other("not a folder"));
    }
    let path = plain(path);
    // COM wants its own single-threaded apartment; a short-lived thread keeps it off the
    // command threads.
    std::thread::Builder::new()
        .name("hangar-drive-reveal".into())
        .spawn(move || shell_reveal(&path, select))?
        .join()
        .map_err(|_| std::io::Error::other("the file manager thread failed"))?
}

#[cfg(windows)]
fn shell_reveal(path: &Path, select: bool) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED,
    };
    use windows_sys::Win32::UI::Shell::{
        ILCreateFromPathW, ILFree, SHOpenFolderAndSelectItems, ShellExecuteW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: called once on this thread with no reserved pointer; a successful call (S_OK or
    // S_FALSE, both >= 0) is balanced by `CoUninitialize` below on the same thread.
    let init = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
    let result = if select {
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call.
        let pidl = unsafe { ILCreateFromPathW(wide.as_ptr()) };
        if pidl.is_null() {
            Err(std::io::Error::other("the shell does not know the path"))
        } else {
            // SAFETY: `pidl` is the valid item ID list just created; with no child items the
            // call opens its folder with the item selected. The list is freed once, after use.
            let hr = unsafe { SHOpenFolderAndSelectItems(pidl, 0, std::ptr::null(), 0) };
            // SAFETY: `pidl` came from `ILCreateFromPathW` and is not used after this.
            unsafe { ILFree(pidl) };
            if hr < 0 {
                Err(std::io::Error::other(format!(
                    "the shell refused (0x{hr:08x})"
                )))
            } else {
                Ok(())
            }
        }
    } else {
        let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
        // SAFETY: both strings are NUL-terminated and outlive the call; no window, parameters
        // or directory are passed (null is allowed for each). `path` is a folder (checked by
        // the caller), so "open" shows it and runs nothing.
        let instance = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW reports success as a value greater than 32.
        if instance as isize > 32 {
            Ok(())
        } else {
            Err(std::io::Error::other("the shell did not open the folder"))
        }
    };
    if init >= 0 {
        // SAFETY: balances the successful `CoInitializeEx` above on this thread.
        unsafe { CoUninitialize() };
    }
    result
}

/// Opens a folder in the file manager, or shows a file selected in its folder.
#[cfg(not(windows))]
pub fn reveal(path: &Path, select: bool) -> std::io::Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        if select {
            c.arg("-R");
        }
        c.arg(path);
        c
    } else {
        // xdg-open cannot select a file; it opens the folder that holds it.
        let target = if select {
            path.parent().unwrap_or(path)
        } else {
            path
        };
        let mut c = Command::new("xdg-open");
        c.arg(target);
        c
    };
    command.spawn().map(drop)
}

/// The roots of other sync clients and cloud folders: [`hangar_drive_sync::roots::other_clouds`]
/// (OneDrive from `OneDrive`, `OneDriveConsumer`, `OneDriveCommercial` and the registry, Dropbox
/// from its `info.json`, iCloud Drive, `~/Library/CloudStorage`, `~/Library/Mobile Documents`)
/// plus the default places of Dropbox and Google Drive. A recovery file must not be saved below
/// one (security review M2): it would travel to a provider next to nothing it protects.
pub fn cloud_roots() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = hangar_drive_sync::roots::other_clouds()
        .into_iter()
        .map(|(_, path)| path)
        .collect();
    if let Some(home) = dirs::home_dir() {
        // Dropbox's default, Google Drive for desktop's mirror folder and the older Backup and
        // Sync folder [UNVERIFIED for every client version].
        for name in ["Dropbox", "Google Drive", "My Drive", "GoogleDrive"] {
            out.push(home.join(name));
        }
    }
    out
}

/// Whether the folder `dir` lies in one of `roots` (both compared in canonical form), or on a
/// volume of Google Drive for desktop, which mounts the account as a drive of its own.
pub fn in_cloud_folder(dir: &Path, roots: &[PathBuf]) -> bool {
    use hangar_drive_sync::roots::{key, within};
    let Ok(dir) = std::fs::canonicalize(dir) else {
        return false;
    };
    let target = key(&dir);
    let below = roots.iter().any(|root| {
        std::fs::canonicalize(root)
            .map(|root| within(&target, &key(&root)))
            .unwrap_or(false)
    });
    below || volume_label(&dir).is_some_and(|label| label.eq_ignore_ascii_case("Google Drive"))
}

/// The label of the volume that holds `path`.
#[cfg(windows)]
fn volume_label(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};
    let wide: Vec<u16> = plain(path)
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut root = [0u16; 1024];
    // SAFETY: `wide` is NUL-terminated; `root` is writable for the length passed.
    let ok = unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) };
    if ok == 0 {
        return None;
    }
    let mut label = [0u16; 261];
    // SAFETY: `root` holds the NUL-terminated volume root just written; `label` is writable
    // for the length passed; the other out pointers may be null as the API documents.
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            label.as_mut_ptr(),
            label.len() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return None;
    }
    let end = label.iter().position(|c| *c == 0).unwrap_or(label.len());
    Some(String::from_utf16_lossy(&label[..end]))
}

#[cfg(not(windows))]
fn volume_label(_path: &Path) -> Option<String> {
    None
}

/// The system's storage settings (ux-concept 8.5); nothing where the system has none to open.
pub fn open_storage_settings() -> std::io::Result<()> {
    if cfg!(windows) {
        Command::new("explorer.exe")
            .arg("ms-settings:storagesense")
            .spawn()
            .map(drop)
    } else if cfg!(target_os = "macos") {
        Command::new("open")
            .arg("x-apple.systempreferences:com.apple.settings.Storage")
            .spawn()
            .map(drop)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Security review M2: a place below `OneDrive` (here a test folder the variable points to)
    // is a cloud folder, a place beside it is not.
    #[test]
    fn a_place_below_onedrive_is_a_cloud_folder() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(".tmp")
            .join("cloud");
        let _ = std::fs::remove_dir_all(&base);
        let cloud = base.join("OneDrive");
        let inside = cloud.join("Documents");
        let beside = base.join("Local");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&beside).unwrap();
        std::env::set_var("OneDrive", &cloud);
        let roots = cloud_roots();
        assert!(roots.contains(&cloud));
        assert!(in_cloud_folder(&inside, &roots));
        assert!(in_cloud_folder(&cloud, &roots));
        assert!(!in_cloud_folder(&beside, &roots));
        assert!(!in_cloud_folder(&base.join("missing"), &roots));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn verbatim_prefixes_are_dropped_for_the_shell() {
        assert_eq!(
            plain(Path::new(r"\\?\C:\Users\a b\x.txt")),
            PathBuf::from(r"C:\Users\a b\x.txt")
        );
        assert_eq!(
            plain(Path::new(r"\\?\UNC\server\share\x")),
            PathBuf::from(r"\\server\share\x")
        );
        assert_eq!(plain(Path::new("/home/a")), PathBuf::from("/home/a"));
    }

    #[test]
    fn host_names_become_device_names() {
        assert_eq!(clean_device_name("  Sams-MacBook.local "), "Sams-MacBook");
        assert_eq!(clean_device_name(""), "Computer");
        assert_eq!(clean_device_name("\u{7}"), "Computer");
        assert_eq!(clean_device_name(&"x".repeat(100)).len(), 64);
        assert!(!device_name().is_empty());
    }

    #[test]
    fn tomorrow_means_six_in_the_morning_local_time() {
        // 2026-11-26 16:30 UTC.
        let now = 1_795_710_600_000;
        // UTC: 2026-11-27 06:00 UTC.
        assert_eq!(next_morning(now, 0), 1_795_759_200_000);
        // UTC+1: 06:00 local is 05:00 UTC.
        assert_eq!(next_morning(now, 60), 1_795_759_200_000 - 3_600_000);
        // UTC-10, where it is still the 26th at 06:30 local: the 27th, 06:00 local.
        assert_eq!(next_morning(now, -600), 1_795_759_200_000 + 36_000_000);
        assert!(next_morning(now, tz_offset_minutes()) > now);
    }

    #[test]
    fn free_space_and_language_answer_on_this_system() {
        let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        assert!(free_bytes(&here).is_some_and(|b| b > 0));
        let _ = os_language();
        let _ = taskbar_is_dark();
        assert!(default_folder().is_some_and(|p| p.ends_with("Hangar Drive")));
    }
}
