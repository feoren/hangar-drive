//! Free disk space for the disk reserve (ADR 0001, section 5): below it every upload is refused.
//! Behind a trait so tests can simulate a full disk.

use std::path::{Path, PathBuf};

pub trait DiskSpace: Send + Sync {
    /// Bytes available to the server, `None` if the platform cannot tell.
    fn available(&self) -> Option<u64>;
}

/// The file system of the data folder.
#[derive(Debug, Clone)]
pub struct FsDiskSpace {
    path: PathBuf,
}

impl FsDiskSpace {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl DiskSpace for FsDiskSpace {
    fn available(&self) -> Option<u64> {
        available_bytes(&self.path)
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn available_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call, and `stat`
    // points to writable memory of the right size; statvfs initializes it when it returns 0.
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    // SAFETY: statvfs returned 0, so it initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    // The field types differ by platform (u32 on macOS, u64 on Linux); both widen to u64.
    #[allow(clippy::unnecessary_cast)]
    let (blocks, size) = (stat.f_bavail as u64, stat.f_frsize as u64);
    blocks.checked_mul(size)
}

#[cfg(not(unix))]
fn available_bytes(_path: &Path) -> Option<u64> {
    None
}

/// A fixed answer (tests).
#[derive(Debug)]
pub struct FixedDiskSpace(pub std::sync::atomic::AtomicU64);

impl FixedDiskSpace {
    pub fn new(bytes: u64) -> Self {
        Self(std::sync::atomic::AtomicU64::new(bytes))
    }

    pub fn set(&self, bytes: u64) {
        self.0.store(bytes, std::sync::atomic::Ordering::SeqCst);
    }
}

impl DiskSpace for FixedDiskSpace {
    fn available(&self) -> Option<u64> {
        Some(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_space_on_unix_and_fixed_values() {
        let real = FsDiskSpace::new(Path::new(env!("CARGO_MANIFEST_DIR")));
        if cfg!(unix) {
            assert!(real.available().is_some_and(|b| b > 0));
        } else {
            assert_eq!(real.available(), None);
        }
        let fixed = FixedDiskSpace::new(5);
        fixed.set(7);
        assert_eq!(fixed.available(), Some(7));
    }
}
