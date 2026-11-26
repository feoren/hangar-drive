//! Object blobs: the header reader and the open never panic, and no forged blob opens.
#![no_main]

#[path = "common/mod.rs"]
mod common;

use hangar_drive_crypto::folder_keys::FolderKeyRing;
use hangar_drive_crypto::object::{object_header, ObjectKeys};
use hangar_drive_crypto::OsEntropy;
use hangar_drive_protocol::ids::{Generation, ObjectId};
use hangar_drive_protocol::object::ObjectType;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = object_header(data);
    let ring = FolderKeyRing::new(common::FOLDER, 1, &mut OsEntropy).expect("a ring");
    let keys = ObjectKeys::from_ring(&common::ACCOUNT, &ring, Generation(1)).expect("keys");
    let id = ObjectId::from_bytes([0; 32]);
    for kind in [
        ObjectType::Chunk,
        ObjectType::FileManifest,
        ObjectType::DirectoryNode,
    ] {
        assert!(keys.open(&id, kind, data).is_err());
    }
});
