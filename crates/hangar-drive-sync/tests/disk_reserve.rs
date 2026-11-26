//! The free space a download leaves (LOW 4 of the follow-up review): 5 % of the volume,
//! between 256 MiB and 10 GiB, and no write at all while the free space is unknown.
//!
//! The policy is checked as the executor applies it, file by file against the free space read
//! right before each file (`folder::room_for`), without writing the files themselves: twenty
//! files of 1 GiB that name one chunk each would need 20 GiB of memory in `MemFs`.

use hangar_drive_sync::folder::{disk_reserve, room_for};

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

/// Writes `files` files of `size` bytes as long as [`room_for`] lets them; returns the free
/// space left.
fn download(mut free: u64, volume: Option<u64>, files: usize, size: u64) -> u64 {
    for _ in 0..files {
        if !room_for(size, Some(free), volume) {
            break;
        }
        free -= size;
    }
    free
}

#[test]
fn twenty_files_of_one_gib_leave_five_percent_of_the_volume() {
    // A 100 GiB volume with 10 GiB free, and twenty files of 1 GiB from one chunk each: before,
    // the downloads stopped at 1 GiB free, 1 % of the volume.
    let volume = 100 * GIB;
    let left = download(10 * GIB, Some(volume), 20, GIB);
    assert!(left * 100 >= volume * 5, "{left} bytes free");
    assert_eq!(left, 5 * GIB);
}

#[test]
fn the_reserve_is_five_percent_between_its_bounds() {
    assert_eq!(disk_reserve(None), 256 * MIB);
    assert_eq!(disk_reserve(Some(GIB)), 256 * MIB);
    assert_eq!(disk_reserve(Some(100 * GIB)), 5 * GIB);
    assert_eq!(disk_reserve(Some(4096 * GIB)), 10 * GIB);
    // Unknown free space is no room, whatever the file.
    assert!(!room_for(1, None, Some(100 * GIB)));
    assert!(room_for(GIB, Some(6 * GIB), Some(100 * GIB)));
    assert!(!room_for(GIB, Some(6 * GIB - 1), Some(100 * GIB)));
}
