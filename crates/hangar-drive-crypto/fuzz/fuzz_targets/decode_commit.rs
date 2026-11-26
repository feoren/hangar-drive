//! Commits: a decoded commit keeps its exact wire bytes, and the signer checks never panic.
#![no_main]

#[path = "common/mod.rs"]
mod common;

use hangar_drive_crypto::commit::SignedCommit;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(commit) = SignedCommit::decode(data) {
        assert_eq!(commit.wire, data);
        let fixture = common::fixture();
        let _ = commit.verify_signer(&fixture.state, &common::FOLDER);
        let _ = commit.verify_for_server(&fixture.state, &common::FOLDER);
    }
});
