//! Sealed pairing names (security review, info): opening never panics, and nothing opens with
//! the fixture's secret that it did not seal (it seals nothing here, so nothing may open).
#![no_main]

#[path = "common/mod.rs"]
mod common;

use std::sync::OnceLock;

use hangar_drive_crypto::pairing::PairingSecret;
use libfuzzer_sys::fuzz_target;

fn secret() -> &'static PairingSecret {
    static SECRET: OnceLock<PairingSecret> = OnceLock::new();
    SECRET.get_or_init(|| {
        PairingSecret::generate(&mut hangar_drive_crypto::OsEntropy).expect("os randomness")
    })
}

fuzz_target!(|data: &[u8]| {
    assert!(secret()
        .open_name(&common::ACCOUNT, &common::DEVICE, data)
        .is_err());
});
