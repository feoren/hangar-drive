//! Wrapped epoch secrets: unwrapping never panics, and no forged wrap passes the commitment.
#![no_main]

#[path = "common/mod.rs"]
mod common;

use hangar_drive_crypto::epoch::unwrap;
use hangar_drive_protocol::ids::Epoch;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let fixture = common::fixture();
    let record = fixture.state.current_epoch().expect("epoch 1");
    let result = unwrap(
        &fixture.identity,
        &common::ACCOUNT,
        Epoch(1),
        &common::DEVICE,
        data,
        &record.commitment,
    );
    if let Ok(secret) = result {
        // Only a wrap of the real secret can pass the commitment.
        assert_eq!(secret, fixture.secret);
    }
});
