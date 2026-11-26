//! The folder delta check: any delta, any order, any bytes. It never panics, and an error leaves
//! the view as it was (fail closed: the method takes `&self`, so this checks that a result
//! never claims a frontier its own commits do not end in).
#![no_main]

#[path = "common/mod.rs"]
mod common;

use hangar_drive_crypto::commit::FolderView;
use hangar_drive_protocol::api::{CommitRole, DeltaCommit};
use hangar_drive_protocol::ids::{Blob, Generation};
use libfuzzer_sys::fuzz_target;

/// Splits the input into delta items: `len (u16) || sequence (u8) || role (u8) || commit`.
fn delta(mut data: &[u8]) -> Vec<DeltaCommit> {
    let mut out = Vec::new();
    while data.len() >= 4 && out.len() < 64 {
        let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
        let sequence = u64::from(data[2]);
        let role = if data[3] & 1 == 0 {
            CommitRole::Head
        } else {
            CommitRole::Side
        };
        let rest = &data[4..];
        let take = len.min(rest.len());
        out.push(DeltaCommit {
            sequence,
            role,
            commit: Blob(rest[..take].to_vec()),
            server_ms: None,
        });
        data = &rest[take..];
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let fixture = common::fixture();
    let view = FolderView::new(common::ACCOUNT, common::FOLDER);
    let delta = delta(data);
    for generation in [Generation(1), Generation(u32::MAX)] {
        if let Ok(outcome) = view.verify_delta(&fixture.state, generation, &delta) {
            assert_eq!(
                outcome.view.frontier().map(|e| e.commit),
                outcome.heads.last().map(|h| h.id)
            );
        }
        // The fixture's log has no removal, so no delta is refused by the removed signer rule
        // and no takeover permit exists (security review N2, H1): the check before a barrier is
        // unreachable here, which is the point.
        if let Ok(hangar_drive_crypto::commit::DeltaCheck::RemovedSigner(refusal)) =
            view.check_delta(&fixture.state, generation, &delta)
        {
            assert!(hangar_drive_crypto::epoch::BarrierPermit::takeover(
                &fixture.state,
                &common::DEVICE,
                &refusal
            )
            .is_none());
        }
        let _ = view.reanchor_base(&fixture.state, generation, &delta);
    }
});
