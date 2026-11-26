//! Typed recovery and pairing codes: parsing never panics, and a parsed code reveals a code
//! that parses to the same secret.
#![no_main]

use hangar_drive_crypto::pairing::PairingSecret;
use hangar_drive_crypto::recovery::RecoveryCode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(code) = RecoveryCode::parse(text) {
        let again = RecoveryCode::parse(&code.reveal()).expect("a revealed code parses");
        assert_eq!(again.reveal().as_str(), code.reveal().as_str());
    }
    if let Ok(secret) = PairingSecret::parse(text) {
        assert_eq!(
            PairingSecret::parse(&secret.reveal()).expect("parses"),
            secret
        );
    }
});
