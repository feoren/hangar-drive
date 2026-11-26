//! Device log entries: a decoded entry re-encodes to the same bytes, and the verifier never
//! panics on any input.
#![no_main]

#[path = "common/mod.rs"]
mod common;

use hangar_drive_crypto::devicelog::LogEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entry) = LogEntry::decode(data) {
        assert_eq!(entry.encode(), data);
    }
    let fixture = common::fixture();
    let _ = fixture.state.clone().apply(data);
    let _ = fixture.state.admit_batch([data], &common::DEVICE);
});
