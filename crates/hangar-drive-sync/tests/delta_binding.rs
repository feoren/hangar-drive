//! Reference deltas bound to the tree (ADR 0001, amendment "reference deltas bound to the
//! tree"; security review 2026-11-26, finding HIGH): every device recomputes a pulled head's
//! delta from the trees and refuses a head whose signed delta does not fit, removing the device
//! that wrote it lets the folder go on behind a barrier with a full delta, and an honest device
//! repairs a broken server view with a full delta, uploading again what the collection deleted.

use std::collections::BTreeSet;

use hangar_drive_crypto::commit::{
    ChainEntry, ChainError, Commit, CommitContent, CommitError, DeltaDigest, SignedCommit,
};
use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::api::{CommitRequest, CommitUpload, ReferenceDelta};
use hangar_drive_protocol::ids::{
    AccountId, Blob, DeviceId, FolderId, InviteToken, ItemId, ObjectId,
};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::codec;
use hangar_drive_sync::error::SyncError;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom,
};
use hangar_drive_sync::ports::{ChunkList, Clock, ServerApi, Store};
use hangar_drive_sync::removal::{remove_devices, JobCtx};
use hangar_drive_sync::tree::{ContentKey, FileVersion, Node, NodeKind, ROOT};

const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
const FOLDER: FolderId = FolderId::from_bytes([0xf1; 16]);

struct Dev {
    id: DeviceId,
    fs: MemFs,
    store: MemStore,
    keys: MemKeychain,
    server: MemServer,
    rng: SeededRandom,
    account: Account,
    folder: FolderSync,
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

/// Three devices of one account on one folder: A created it, B and C joined.
fn world() -> (Vec<Dev>, ManualClock, FolderSettings) {
    let shared = MemServer::new_shared();
    let ids: Vec<DeviceId> = (1..=3).map(|i| DeviceId::from_bytes([i; 16])).collect();
    let mut server0 = MemServer::connect(&shared, ids[0]);
    let (mut store0, mut keys0, mut rng0) = (
        MemStore::new(),
        MemKeychain::default(),
        SeededRandom::new(1),
    );
    let mut a = Account::create(
        &mut server0,
        &mut keys0,
        &mut store0,
        &mut rng0,
        0,
        InviteToken::from_bytes([9; 16]),
        ACCOUNT,
        ids[0],
        "A",
        None,
    )
    .unwrap();
    a.create_folder(&mut server0, &mut store0, FOLDER, "Docs", &mut rng0)
        .unwrap();
    let mut joined = Vec::new();
    for (n, id) in ids.iter().enumerate().skip(1) {
        let mut rng = SeededRandom::new(n as u64 + 10);
        let identity = DeviceIdentity::generate(&mut DynEntropy(&mut rng)).unwrap();
        a.add_device(
            &mut server0,
            &mut store0,
            LogDevice::of(&identity, &ACCOUNT, *id, false),
            &format!("D{n}"),
            0,
            &mut rng0,
        )
        .unwrap();
        joined.push((identity, *id, rng));
    }
    a.refresh(&mut server0, &mut keys0, &mut store0).unwrap();
    let folder = FolderSync::new(&a, FOLDER, "Docs");
    let fs = MemFs::new(true);
    folder.write_marker(&fs).unwrap();
    let mut devs = vec![Dev {
        id: ids[0],
        fs,
        store: store0,
        keys: keys0,
        server: server0,
        rng: rng0,
        account: a,
        folder,
    }];
    for (n, (identity, id, rng)) in joined.into_iter().enumerate() {
        let mut server = MemServer::connect(&shared, id);
        let (mut store, mut keys) = (MemStore::new(), MemKeychain::default());
        let account = Account::join(
            &mut server,
            &mut keys,
            &mut store,
            identity,
            ACCOUNT,
            id,
            &format!("D{}", n + 1),
            &[],
        )
        .unwrap();
        let folder = FolderSync::new(&account, FOLDER, "Docs");
        let fs = MemFs::new(true);
        folder.write_marker(&fs).unwrap();
        devs.push(Dev {
            id,
            fs,
            store,
            keys,
            server,
            rng,
            account,
            folder,
        });
    }
    (
        devs,
        ManualClock::at(1_795_651_200_000),
        FolderSettings::default(),
    )
}

fn round(
    d: &mut Dev,
    clock: &ManualClock,
    settings: &FolderSettings,
) -> Result<RoundReport, SyncError> {
    d.account
        .refresh(&mut d.server, &mut d.keys, &mut d.store)?;
    let mut cx = Ctx {
        account: &mut d.account,
        server: &mut d.server,
        keychain: &mut d.keys,
        fs: &d.fs,
        store: &mut d.store,
        clock,
        entropy: &mut d.rng,
        settings,
    };
    d.folder.request_full_scan();
    d.folder.round(&mut cx)
}

/// Every object reachable from `root`, read with `d`'s keys.
fn reachable(d: &mut Dev, root: &ObjectId) -> BTreeSet<ObjectId> {
    let reader = d.account.folder_reader(&FOLDER).unwrap();
    codec::reachable(root, &reader, &mut d.store, &mut d.server).unwrap()
}

/// The root of the server's current head.
fn server_root(d: &Dev) -> ObjectId {
    let wire = d.server.state().head_commit(&FOLDER).unwrap();
    hangar_drive_crypto::commit::SignedCommit::decode(&wire)
        .unwrap()
        .commit
        .root
}

/// A compromised device `d` signs a head on its frontier that keeps the tree but drops every
/// object of it except the root, with the digest of that lie (attack 1 of the finding). The
/// server cannot see the tree, so it takes the head.
fn forge_drop_all_but_root(d: &mut Dev) {
    let frontier = *d.folder.view().frontier().unwrap();
    let root = d.folder.meta().remote_root.unwrap();
    let dropped: Vec<ObjectId> = reachable(d, &root)
        .into_iter()
        .filter(|id| *id != root)
        .collect();
    assert!(!dropped.is_empty());
    let content = CommitContent {
        root,
        generation: frontier.generation,
        device: d.id,
        log_head: d.account.log_head().unwrap(),
        counter: d.account.next_counter(&mut d.store).unwrap(),
        delta: DeltaDigest::of(false, &[], &dropped).unwrap(),
    };
    let signed = d
        .account
        .sign(Commit::on(ACCOUNT, FOLDER, &frontier, content))
        .unwrap();
    let request = CommitRequest {
        expected_head: Some(frontier.commit),
        head: CommitUpload {
            commit: Blob(signed.wire),
            delta: ReferenceDelta {
                added: Vec::new(),
                dropped,
            },
        },
        side: None,
    };
    d.server.commit(&FOLDER, &request).unwrap();
}

#[test]
fn a_head_whose_delta_does_not_fit_its_tree_is_refused_until_its_device_is_removed() {
    let (mut devs, clock, settings) = world();
    devs[0].fs.user_write(&p(&["a.txt"]), b"alpha");
    devs[0].fs.user_write(&p(&["b.txt"]), b"beta");
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    let honest_root = server_root(&devs[1]);
    let tree = reachable(&mut devs[1], &honest_root);
    assert_eq!(devs[1].server.state().live_set(&FOLDER), tree);
    // C is compromised: its head keeps the tree, so no device would see a change, but the
    // server's live set loses every file and the collection would delete them.
    forge_drop_all_but_root(&mut devs[2]);
    let broken = devs[1].server.state().live_set(&FOLDER);
    assert_eq!(broken, [honest_root].into_iter().collect());
    // B recomputes the delta from the trees and refuses the head like a bad signature.
    let frontier_before = devs[1].folder.view().frontier().copied();
    let refused = round(&mut devs[1], &clock, &settings);
    assert!(
        matches!(
            refused,
            Err(SyncError::Chain(ChainError::Commit(
                CommitError::DeltaMismatch
            )))
        ),
        "{refused:?}"
    );
    assert_eq!(devs[1].folder.view().frontier().copied(), frontier_before);
    // It keeps refusing, and it publishes nothing on top of the head.
    devs[1].fs.user_write(&p(&["early.txt"]), b"early");
    assert!(round(&mut devs[1], &clock, &settings).is_err());
    assert!(devs[1].fs.user_delete(&p(&["early.txt"])));
    // The person removes C on A: the barrier carries a full delta, which resets the server's
    // live set to the tree.
    let target = devs[2].id;
    {
        let d = &mut devs[0];
        let mut jx = JobCtx {
            account: &mut d.account,
            server: &mut d.server,
            keychain: &mut d.keys,
            store: &mut d.store,
            clock: &clock,
            entropy: &mut d.rng,
            settings: &settings,
        };
        let outcome = remove_devices(&mut jx, &mut [(&mut d.folder, &d.fs)], &[target]).unwrap();
        assert_eq!(outcome.barriers, 1);
        assert_eq!(outcome.removed_heads.len(), 1);
    }
    assert_eq!(devs[1].server.state().live_set(&FOLDER), tree);
    // B takes the barrier in (C's mismatching head is now one of a removed device behind it),
    // publishes its change, and the server's live set matches the tree again.
    devs[1].fs.user_write(&p(&["c.txt"]), b"gamma");
    let report = round(&mut devs[1], &clock, &settings).unwrap();
    assert!(report.published, "{report:?}");
    assert!(!devs[1].folder.meta().full_next);
    let root = server_root(&devs[1]);
    let now = reachable(&mut devs[1], &root);
    assert_eq!(devs[1].server.state().live_set(&FOLDER), now);
    round(&mut devs[0], &clock, &settings).unwrap();
    assert_eq!(devs[0].fs.read_all(&p(&["c.txt"])).unwrap(), b"gamma");
    assert_eq!(devs[0].fs.read_all(&p(&["a.txt"])).unwrap(), b"alpha");
}

#[test]
fn an_honest_device_heals_a_broken_server_view_and_commits_again() {
    let (mut devs, clock, settings) = world();
    devs[0].fs.user_write(&p(&["a.txt"]), b"alpha");
    devs[0].fs.user_write(&p(&["b.txt"]), b"beta");
    round(&mut devs[0], &clock, &settings).unwrap();
    round(&mut devs[1], &clock, &settings).unwrap();
    let old_root = server_root(&devs[0]);
    let old_tree = reachable(&mut devs[0], &old_root);
    // The state after attacks 1 and 2 of the finding: the server holds the folder as empty
    // and its collection deleted every object of the tree. Before the fix every later honest
    // commit was refused for good, and so was the re-anchor.
    devs[0].server.state().set_live(&FOLDER, BTreeSet::new());
    devs[0].server.state().delete_objects(&FOLDER, &old_tree);
    // A changes a file. Its diff names the old root as dropped, which the broken view does not
    // hold: the server answers `delta_mismatch`, and A sends the same tree again with a full
    // delta, uploading every object the collection deleted.
    devs[0].fs.user_write(&p(&["c.txt"]), b"gamma");
    let report = round(&mut devs[0], &clock, &settings).unwrap();
    assert!(report.published, "{report:?}");
    assert!(!devs[0].folder.meta().full_next);
    let root = server_root(&devs[0]);
    let tree = reachable(&mut devs[0], &root);
    assert_eq!(devs[0].server.state().live_set(&FOLDER), tree);
    let missing = devs[0]
        .server
        .missing_objects(&FOLDER, &tree.iter().copied().collect::<Vec<_>>())
        .unwrap();
    assert!(
        missing.is_empty(),
        "every object of the tree is back: {missing:?}"
    );
    // The full head verifies on B, which takes it in.
    round(&mut devs[1], &clock, &settings).unwrap();
    assert_eq!(devs[1].fs.read_all(&p(&["c.txt"])).unwrap(), b"gamma");
    assert_eq!(devs[1].fs.read_all(&p(&["a.txt"])).unwrap(), b"alpha");
    // And plain diffs fit the repaired view again.
    devs[1].fs.user_write(&p(&["a.txt"]), b"alpha 2");
    let report = round(&mut devs[1], &clock, &settings).unwrap();
    assert!(report.published);
    let root = server_root(&devs[1]);
    let tree = reachable(&mut devs[1], &root);
    assert_eq!(devs[1].server.state().live_set(&FOLDER), tree);
    let wire = devs[1].server.state().head_commit(&FOLDER).unwrap();
    let head = hangar_drive_crypto::commit::SignedCommit::decode(&wire).unwrap();
    assert!(!head.commit.delta.full, "a normal commit is a diff again");
}

/// Signs `content` on `parent` as `d` and sends it with `delta`; returns the commit and its
/// sequence.
fn send_forged(
    d: &mut Dev,
    parent: &ChainEntry,
    root: ObjectId,
    added: Vec<ObjectId>,
    dropped: Vec<ObjectId>,
) -> (SignedCommit, u64) {
    let content = CommitContent {
        root,
        generation: parent.generation,
        device: d.id,
        log_head: d.account.log_head().unwrap(),
        counter: d.account.next_counter(&mut d.store).unwrap(),
        delta: DeltaDigest::of(false, &added, &dropped).unwrap(),
    };
    let signed = d
        .account
        .sign(Commit::on(ACCOUNT, FOLDER, parent, content))
        .unwrap();
    let request = CommitRequest {
        expected_head: Some(parent.commit),
        head: CommitUpload {
            commit: Blob(signed.wire.clone()),
            delta: ReferenceDelta { added, dropped },
        },
        side: None,
    };
    let response = d.server.commit(&FOLDER, &request).unwrap();
    (signed, response.sequence)
}

/// HIGH 1 of the follow-up review: compromised `d` commits X1, whose root names a manifest it
/// never uploads (so no device can read the tree, added = {R1}), and right after X2, which goes
/// back to the tree T0 and drops every object of T0 but its root (dropped = R(T0) \ {R0}).
/// Returns R(T0).
fn forge_behind_an_unreadable_tree(d: &mut Dev) -> BTreeSet<ObjectId> {
    let frontier = *d.folder.view().frontier().unwrap();
    let r0 = d.folder.meta().remote_root.unwrap();
    let t0 = reachable(d, &r0);
    let mut tree = d.folder.remote().clone();
    let ghost = ObjectId::from_bytes([0x6d; 32]);
    let content = ContentKey::of_chunks(&[ghost]);
    d.store
        .put_chunk_list(
            &FOLDER,
            &content,
            &ChunkList {
                generation: Some(frontier.generation.0),
                chunks: vec![ghost],
            },
        )
        .unwrap();
    tree.insert(
        ItemId::from_bytes([0x6e; 16]),
        Node {
            parent: ROOT,
            name: "hidden.txt".into(),
            kind: NodeKind::File(FileVersion {
                size: 4,
                mtime_ms: 0,
                executable: false,
                content,
            }),
            conflict_of: None,
        },
    );
    let crypto = d
        .account
        .folder_crypto(&FOLDER, Some(frontier.generation))
        .unwrap();
    let encoded = codec::encode(&tree, &crypto, &d.store, &mut d.rng).unwrap();
    let r1 = encoded.root;
    d.server
        .put_object(&FOLDER, &r1, &encoded.sealed[&r1])
        .unwrap();
    let (x1, seq1) = send_forged(d, &frontier, r1, vec![r1], vec![r0]);
    let x1_entry = ChainEntry {
        commit: x1.id,
        height: x1.commit.height,
        sequence: seq1,
        generation: x1.commit.generation,
        log_index: x1.commit.log_head.index,
    };
    let mut dropped: Vec<ObjectId> = t0.iter().filter(|id| **id != r0).copied().collect();
    dropped.push(r1);
    dropped.sort();
    send_forged(d, &x1_entry, r0, vec![r0], dropped);
    t0
}

#[test]
fn a_forged_delta_behind_a_tree_nobody_can_read_is_refused() {
    let (mut devs, clock, settings) = world();
    devs[0].fs.user_write(&p(&["a.txt"]), b"alpha");
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    // The server stamps its calls with the current time: the forged commits are young.
    devs[0].server.state().server_time_ms = u64::try_from(clock.now_ms()).ok();
    forge_behind_an_unreadable_tree(&mut devs[2]);
    let r0 = server_root(&devs[1]);
    assert_eq!(
        devs[1].server.state().live_set(&FOLDER),
        [r0].into_iter().collect(),
        "the server took both forged heads"
    );
    // B cannot read X1's tree, and X1 is younger than any retention: a mismatch, not a
    // commit it may skip.
    let frontier_before = devs[1].folder.view().frontier().copied();
    let refused = round(&mut devs[1], &clock, &settings);
    assert!(
        matches!(
            refused,
            Err(SyncError::Chain(ChainError::Commit(
                CommitError::DeltaMismatch
            )))
        ),
        "{refused:?}"
    );
    assert_eq!(devs[1].folder.view().frontier().copied(), frontier_before);
}

#[test]
fn an_unreadable_old_tree_is_skipped_and_repaired_at_once() {
    let (mut devs, clock, settings) = world();
    devs[0].fs.user_write(&p(&["a.txt"]), b"alpha");
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    // Without a server time (as for commits whose time expired) B may take X1's tree as one
    // the collection already took; it then repairs the live set at once, with no local change.
    let t0 = forge_behind_an_unreadable_tree(&mut devs[2]);
    let report = round(&mut devs[1], &clock, &settings).unwrap();
    assert!(report.published, "the repair commit went out: {report:?}");
    assert!(!devs[1].folder.meta().full_next);
    let root = server_root(&devs[1]);
    let now = reachable(&mut devs[1], &root);
    assert_eq!(now.len(), t0.len());
    assert_eq!(devs[1].server.state().live_set(&FOLDER), now);
    let wire = devs[1].server.state().head_commit(&FOLDER).unwrap();
    assert!(SignedCommit::decode(&wire).unwrap().commit.delta.full);
    assert_eq!(devs[1].fs.read_all(&p(&["a.txt"])).unwrap(), b"alpha");
}
