//! Free disk space of a sync root's volume, for the check before a download writes anything
//! ([`crate::ports::FileSystem::free_bytes`]).

use std::path::Path;

/// Free bytes for this user on the volume of `path`, `None` when the platform cannot tell.
#[cfg(windows)]
pub fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut free = 0u64;
    // SAFETY: `wide` is NUL-terminated and outlives the call; `free` is a valid out pointer;
    // the other two may be null as the API documents.
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

/// Free bytes for this user on the volume of `path`, `None` when the platform cannot tell.
#[cfg(unix)]
pub fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero `statvfs` is a valid value of the plain C struct, and a successful
    // call writes it fully.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is NUL-terminated and `stat` is a valid out pointer.
    if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    // The field types differ between platforms (u32 on some, u64 on others).
    #[allow(clippy::unnecessary_cast)]
    Some((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

/// Free bytes for this user on the volume of `path`, `None` when the platform cannot tell.
#[cfg(not(any(windows, unix)))]
pub fn free_bytes(_path: &Path) -> Option<u64> {
    None
}

/// The size of the volume of `path` (as this user sees it), `None` when the platform cannot
/// tell.
#[cfg(windows)]
pub fn volume_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut total = 0u64;
    // SAFETY: `wide` is NUL-terminated and outlives the call; `total` is a valid out pointer;
    // the other two may be null as the API documents.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            &mut total,
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(total)
}

/// The size of the volume of `path`, `None` when the platform cannot tell.
#[cfg(unix)]
pub fn volume_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero `statvfs` is a valid value of the plain C struct, and a successful
    // call writes it fully.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is NUL-terminated and `stat` is a valid out pointer.
    if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    // The field types differ between platforms (u32 on some, u64 on others).
    #[allow(clippy::unnecessary_cast)]
    Some((stat.f_blocks as u64).saturating_mul(stat.f_frsize as u64))
}

/// The size of the volume of `path`, `None` when the platform cannot tell.
#[cfg(not(any(windows, unix)))]
pub fn volume_bytes(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_volume_of_the_crate_has_free_space() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(free_bytes(here).is_some_and(|b| b > 0));
        let volume = volume_bytes(here).unwrap();
        assert!(free_bytes(here).is_some_and(|free| free <= volume));
    }
}
