//! Follow-up check N-4: the limits of a folder (`codec::MAX_TREE_ITEMS`, `MAX_TREE_DEPTH`) hold
//! for the local scan and for the tree to publish, not only for a server's tree. A folder on
//! the disk beyond them stops with its own reason ("too large for a folder") and publishes
//! nothing; it goes on once it is within them again. Tested with small limits.

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::error::SyncError;
use hangar_drive_sync::folder::{
    Ctx, FolderSettings, FolderState, FolderSync, RoundReport, StopReason,
};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom,
};

const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
const FOLDER: FolderId = FolderId::from_bytes([0xf0; 16]);

struct Dev {
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

fn world() -> (Vec<Dev>, ManualClock, FolderSettings) {
    let shared = MemServer::new_shared();
    let ids: Vec<DeviceId> = (1..=2).map(|i| DeviceId::from_bytes([i; 16])).collect();
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
    let mut devs = Vec::new();
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
    devs.push(Dev {
        fs,
        store: store0,
        keys: keys0,
        server: server0,
        rng: rng0,
        account: a,
        folder,
    });
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
    d.folder.request_full_scan();
    round_as_is(d, clock, settings)
}

/// A round without asking for a full scan first: what the watcher noted, or nothing.
fn round_as_is(
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
    d.folder.round(&mut cx)
}

fn small(items: usize, depth: usize) -> FolderSettings {
    FolderSettings {
        max_tree_items: items,
        max_tree_depth: depth,
        ..FolderSettings::default()
    }
}

fn too_large(d: &Dev) -> bool {
    d.folder.state() == FolderState::Stopped(StopReason::LocalTooLarge)
}

fn head(d: &Dev) -> Option<hangar_drive_protocol::ids::CommitId> {
    d.server.state().head(&FOLDER)
}

#[test]
fn a_folder_with_too_many_items_stops_and_publishes_nothing() {
    let (mut devs, clock, _) = world();
    let settings = small(5, 8);
    let d = &mut devs[0];
    round(d, &clock, &settings).unwrap();
    let before = head(d);
    for n in 0..6 {
        d.fs.user_write(&p(&[&format!("f{n}.txt")]), b"x");
    }
    let report = round(d, &clock, &settings).unwrap();
    assert!(!report.published);
    assert!(too_large(d));
    assert_eq!(head(d), before, "nothing was published");
    // Stopped: a round without a change in the folder does not walk it again.
    let report = round_as_is(d, &clock, &settings).unwrap();
    assert!(!report.published && too_large(d));
    // Back within the limits: the change starts a full scan, and the folder goes on.
    assert!(d.fs.user_delete(&p(&["f5.txt"])));
    d.folder.note_changes([p(&["f5.txt"])]);
    clock.advance(60_000);
    let report = round_as_is(d, &clock, &settings).unwrap();
    assert!(report.published, "{report:?}");
    assert_eq!(d.folder.state(), FolderState::Active);
    assert_eq!(d.folder.remote().count_files(), 5);
}

#[test]
fn a_folder_deeper_than_the_limit_stops_and_publishes_nothing() {
    let (mut devs, clock, _) = world();
    let settings = small(100, 3);
    let d = &mut devs[0];
    round(d, &clock, &settings).unwrap();
    let before = head(d);
    assert!(d.fs.user_mkdir(&p(&["a"])));
    assert!(d.fs.user_mkdir(&p(&["a", "b"])));
    assert!(d.fs.user_mkdir(&p(&["a", "b", "c"])));
    d.fs.user_write(&p(&["a", "b", "c", "deep.txt"]), b"x");
    round(d, &clock, &settings).unwrap();
    assert!(too_large(d));
    assert_eq!(head(d), before);
    // Three levels are within the limit.
    assert!(d.fs.user_delete(&p(&["a", "b", "c", "deep.txt"])));
    let report = round(d, &clock, &settings).unwrap();
    assert!(report.published, "{report:?}");
    assert_eq!(d.folder.state(), FolderState::Active);
}

/// The disk and the server are each within the limit, but the merged tree is not: it is
/// never published either.
#[test]
fn a_merged_tree_beyond_the_limit_is_not_published() {
    let (mut devs, clock, _) = world();
    let settings = small(5, 8);
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    for n in 0..3 {
        devs[1].fs.user_write(&p(&[&format!("b{n}.txt")]), b"b");
    }
    assert!(round(&mut devs[1], &clock, &settings).unwrap().published);
    let before = head(&devs[1]);
    for n in 0..3 {
        devs[0].fs.user_write(&p(&[&format!("a{n}.txt")]), b"a");
    }
    let report = round(&mut devs[0], &clock, &settings).unwrap();
    assert!(!report.published);
    assert!(too_large(&devs[0]));
    assert_eq!(head(&devs[0]), before);
}
