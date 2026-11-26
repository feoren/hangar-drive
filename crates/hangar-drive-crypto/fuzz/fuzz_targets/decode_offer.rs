//! Pairing offers: a decoded offer re-encodes to the same bytes, carries only an allowed server
//! URL, and its checks against a log never panic.
#![no_main]

#[path = "common/mod.rs"]
mod common;

use hangar_drive_crypto::pairing::{parse_server_url, PairingOffer};
use hangar_drive_protocol::ids::ServerId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(offer) = PairingOffer::decode(data) {
        assert_eq!(
            offer.encode().expect("a decoded offer encodes").as_slice(),
            data
        );
        assert!(parse_server_url(offer.content.server_url.as_str()).is_ok());
        let fixture = common::fixture();
        let _ = offer.server_address(&fixture.state, &ServerId::from_bytes([4; 16]));
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(url) = parse_server_url(text) {
            assert!(url.username().is_empty() && url.password().is_none());
        }
    }
});
