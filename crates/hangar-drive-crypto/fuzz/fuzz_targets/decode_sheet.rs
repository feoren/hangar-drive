//! Recovery sheets (security review, info): the decoder of the sheet's public part never
//! panics, and a decoded sheet re-encodes to the same bytes with an allowed server URL.
#![no_main]

use hangar_drive_crypto::pairing::parse_server_url;
use hangar_drive_crypto::recovery::RecoverySheet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sheet) = RecoverySheet::decode(data) {
        assert_eq!(sheet.encode().as_slice(), data);
        assert!(parse_server_url(sheet.server_url.as_str()).is_ok());
    }
});
