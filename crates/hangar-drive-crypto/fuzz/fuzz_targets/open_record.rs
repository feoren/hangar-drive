//! Sealed records: the header reader and the full open never panic, and nothing opens that the
//! fixture's device did not seal (it seals nothing here, so nothing may open).
#![no_main]

#[path = "common/mod.rs"]
mod common;

use hangar_drive_crypto::record::{record_header, RecordCipher};
use hangar_drive_protocol::api::{RecordKey, RecordKind};
use hangar_drive_protocol::ids::Epoch;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = record_header(data);
    let fixture = common::fixture();
    let cipher =
        RecordCipher::for_epoch(&fixture.state, &fixture.secret, Epoch(1)).expect("epoch 1");
    for key in [
        RecordKey::new(RecordKind::FolderKeys, Some(common::FOLDER)),
        RecordKey::new(RecordKind::Folders, None),
        RecordKey::new(RecordKind::DeviceNames, None),
    ]
    .into_iter()
    .flatten()
    {
        let version = record_header(data).map_or(1, |h| h.version);
        assert!(cipher.open(&fixture.state, &key, version, data).is_err());
    }
});
