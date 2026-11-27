//! The folder delta check on commits that are validly signed (security review, info): the bytes
//! choose the fields of each commit (signer, parents, height, counter, log head, generation,
//! flags, sequence and role), and the target signs it with a key of the fixture, so the checks
//! behind the signature are reached: `step`, the removed signer rule and the re-anchor walk.
//! The fixture's log removes one of its two devices, so heads of a removed signer occur. Every
//! call must return without a panic, and an accepted delta ends at its own last head.
#![no_main]

#[path = "common/mod.rs"]
mod common;

use std::collections::BTreeSet;
use std::sync::OnceLock;

use hangar_drive_crypto::commit::{Commit, DeltaCheck, DeltaDigest, FolderView, SignedCommit};
use hangar_drive_crypto::devicelog::{AccountState, EntryKind, LogDevice};
use hangar_drive_crypto::epoch::remove_devices;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_crypto::OsEntropy;
use hangar_drive_protocol::api::{CommitRole, DeltaCommit};
use hangar_drive_protocol::ids::{Blob, DeviceId, Generation, LogHead, ObjectId};
use libfuzzer_sys::fuzz_target;

const REMOVED: DeviceId = DeviceId::from_bytes([2; 16]);
/// Bytes that describe one commit.
const ITEM_LEN: usize = 9;
/// Commits one input builds at most.
const MAX_ITEMS: usize = 24;

struct World {
    state: AccountState,
    removed: DeviceIdentity,
}

/// The common fixture's device, plus a second device that the first one removed again, with
/// the rotation after it: log entries 1 to 5.
fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let fixture = common::fixture();
        let removed = DeviceIdentity::generate(&mut OsEntropy).expect("os randomness");
        let mut state = fixture.state.clone();
        let add = state
            .next_entry(
                &fixture.identity,
                common::DEVICE,
                0,
                EntryKind::AddDevice(LogDevice::of(&removed, &common::ACCOUNT, REMOVED, false)),
            )
            .expect("add");
        state.apply(&add).expect("apply");
        let removal = remove_devices(
            &state,
            &fixture.identity,
            common::DEVICE,
            0,
            &[REMOVED],
            &mut OsEntropy,
        )
        .expect("remove");
        World {
            state: removal.state,
            removed,
        }
    })
}

/// Builds and signs the commits the input describes. Per commit, 9 bytes:
/// `flags || first parent || second parent || height || counter || log head || generation
/// || root || sequence`. Flags bit 0 picks the removed device as signer, bit 1 the side role,
/// bit 2 the re-anchor mark, bit 3 the side bit, bit 4 a full delta digest, bit 5 no parent, bit
/// 6 a second parent. A parent byte names an earlier commit of the input (modulo their count),
/// the log head byte an index of the fixture's log.
fn built_delta(data: &[u8], world: &World) -> Vec<DeltaCommit> {
    let fixture = common::fixture();
    let mut built: Vec<SignedCommit> = Vec::new();
    let mut delta = Vec::new();
    for item in data.chunks_exact(ITEM_LEN).take(MAX_ITEMS) {
        let flags = item[0];
        let pick = |byte: u8| -> Option<&SignedCommit> {
            (!built.is_empty()).then(|| &built[usize::from(byte) % built.len()])
        };
        let mut parents = Vec::new();
        if flags & 0x20 == 0 {
            if let Some(first) = pick(item[1]) {
                parents.push(first.id);
            }
            if flags & 0x40 != 0 {
                if let Some(second) = pick(item[2]) {
                    parents.push(second.id);
                }
            }
        }
        let index = 1 + u64::from(item[5]) % world.state.len();
        let Some(hash) = world.state.hash_at(index).copied() else {
            continue;
        };
        let removed = flags & 1 != 0;
        let delta_digest = if flags & 0x10 != 0 {
            DeltaDigest::full(&BTreeSet::new())
        } else {
            DeltaDigest::diff(&BTreeSet::new(), &BTreeSet::new())
        };
        let commit = Commit {
            account: common::ACCOUNT,
            folder: common::FOLDER,
            height: u64::from(item[3]),
            parents,
            root: ObjectId::from_bytes([item[7]; 32]),
            generation: Generation(u32::from(item[6] % 4)),
            device: if removed { REMOVED } else { common::DEVICE },
            log_head: LogHead { index, hash },
            counter: u64::from(item[4]),
            reanchor: flags & 0x04 != 0,
            side: flags & 0x08 != 0,
            delta: delta_digest,
        };
        let identity = if removed {
            &world.removed
        } else {
            &fixture.identity
        };
        // A commit of an invalid shape is not signed; the decoder tests cover such bytes.
        let Ok(signed) = commit.sign(identity) else {
            continue;
        };
        delta.push(DeltaCommit {
            sequence: u64::from(item[8]),
            role: if flags & 0x02 != 0 {
                CommitRole::Side
            } else {
                CommitRole::Head
            },
            commit: Blob(signed.wire.clone()),
            server_ms: None,
        });
        built.push(signed);
    }
    delta
}

fuzz_target!(|data: &[u8]| {
    let world = world();
    let delta = built_delta(data, world);
    let empty = FolderView::new(common::ACCOUNT, common::FOLDER);
    // A view that already verified a prefix of the delta, so re-anchors have a chain to reach.
    let split = delta.len() / 2;
    let views = match empty.verify_delta(&world.state, Generation(3), &delta[..split]) {
        Ok(outcome) => vec![empty.clone(), outcome.view],
        Err(_) => vec![empty],
    };
    for view in &views {
        for generation in [Generation(1), Generation(3)] {
            if let Ok(outcome) = view.verify_delta(&world.state, generation, &delta) {
                assert_eq!(
                    outcome.view.frontier().map(|e| e.commit),
                    outcome.heads.last().map(|h| h.id)
                );
            }
            if let Ok(DeltaCheck::Accepted(outcome)) =
                view.check_delta(&world.state, generation, &delta)
            {
                assert_eq!(
                    outcome.view.frontier().map(|e| e.commit),
                    outcome.heads.last().map(|h| h.id)
                );
            }
            if let Ok(base) = view.reanchor_base(&world.state, generation, &delta[split..]) {
                assert_eq!(
                    Some(base.head.commit),
                    base.segment
                        .last()
                        .map(|c| c.id)
                        .or(base.base.map(|b| b.commit))
                );
            }
        }
    }
});
