//! Folder key rings: a decoded ring re-encodes to the same bytes.
#![no_main]

#[path = "common/mod.rs"]
mod common;

use hangar_drive_crypto::folder_keys::FolderKeyRing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(ring) = FolderKeyRing::decode(data, &common::FOLDER) {
        assert_eq!(ring.encode().as_slice(), data);
    }
});
