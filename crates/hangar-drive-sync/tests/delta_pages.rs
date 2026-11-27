//! The folder delta page by page (ADR 0001, amendment "delta pages in the engine"): a device
//! without a frontier takes in a delta of any length in pages, a pull cut off midway goes on
//! from its stored state, a changed device log begins again, and the stored state stays small.
//! Small pages and a small bound stand for the real ones; the full size runs as an ignored
//! test.

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, Blob, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::error::SyncError;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom,
};
use hangar_drive_sync::ports::Store;

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

/// A writes `n` commits, one file each round.
fn commits(d: &mut Dev, clock: &ManualClock, settings: &FolderSettings, n: usize) {
    for i in 0..n {
        d.fs.user_write(
            &p(&[&format!("f{}.txt", i % 50)]),
            format!("{i}").as_bytes(),
        );
        assert!(round(d, clock, settings).unwrap().published);
    }
}

fn pending(d: &Dev) -> Option<Vec<u8>> {
    d.store
        .account_value(&format!("pull/{}", FOLDER.to_hex()))
        .unwrap()
}

/// Pages a whole pull from the start reads: four calls per page.
fn full_pages(d: &Dev) -> u64 {
    d.server.state().folder_sequence(&FOLDER).div_ceil(4)
}

#[test]
fn a_device_without_a_frontier_takes_a_long_delta_in_pages() {
    let (mut devs, clock, settings) = world();
    commits(&mut devs[0], &clock, &settings, 120);
    let b = &mut devs[1];
    b.server.state().page_size = 4;
    // Beyond the bound of a pull: refused, and nothing is taken in.
    let small = FolderSettings {
        max_pull_commits: 60,
        ..FolderSettings::default()
    };
    assert!(round(b, &clock, &small).is_err());
    assert!(b.folder.view().frontier().is_none());
    assert!(pending(b).is_none(), "a refusal keeps no state");
    // Within it: every page, and the folder is the server's.
    let before = b.server.state().delta_pages;
    round(b, &clock, &settings).unwrap();
    let pages = b.server.state().delta_pages - before;
    assert!(pages >= full_pages(b), "{pages} pages");
    assert_eq!(
        b.folder.view().frontier().map(|f| f.commit),
        b.server.state().head(&FOLDER)
    );
    assert_eq!(b.fs.read_all(&p(&["f19.txt"])).unwrap(), b"119");
    assert!(pending(b).is_none());
    assert_eq!(
        b.folder.meta().timeline.len(),
        devs[0].folder.meta().timeline.len()
    );
}

#[test]
fn a_pull_cut_off_midway_goes_on_from_its_stored_state() {
    let (mut devs, clock, settings) = world();
    commits(&mut devs[0], &clock, &settings, 80);
    let b = &mut devs[1];
    b.server.state().page_size = 4;
    b.server.state().delta_pages_left = Some(10);
    let report = round(b, &clock, &settings).unwrap();
    assert!(report.offline);
    assert!(b.folder.view().frontier().is_none(), "nothing taken in yet");
    let stored = pending(b).expect("the state after ten pages");
    // The stored state holds per head its chain entry and nothing of the raw commits: well
    // below the commits of ten pages (about 40 heads of 60 bytes, plus the last page's
    // sequences and the last head).
    assert!(stored.len() < 12_000, "{} bytes", stored.len());
    b.server.state().delta_pages_left = None;
    let before = b.server.state().delta_pages;
    round(b, &clock, &settings).unwrap();
    let pages = b.server.state().delta_pages - before;
    assert!(
        pages <= full_pages(b) - 10 + 1,
        "{pages} pages after the cut"
    );
    assert_eq!(
        b.folder.view().frontier().map(|f| f.commit),
        b.server.state().head(&FOLDER)
    );
    assert_eq!(b.fs.read_all(&p(&["f29.txt"])).unwrap(), b"79");
    assert!(pending(b).is_none());
    // The timeline holds every commit once.
    let mut seen: Vec<_> = b.folder.meta().timeline.iter().map(|t| t.commit).collect();
    let n = seen.len();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), n);
    assert_eq!(n, devs[0].folder.meta().timeline.len());
}

/// A device added between the cut and the next round: the stored check goes on with the longer
/// log instead of beginning again (amendment "recovery in one piece, adds per day, delta check on
/// a growing log", M5). A's commits after the add name the newer log head, so the stored check
/// stops at the first of them and the rest is checked as the next delta in the same round.
#[test]
fn a_growing_log_goes_on_with_the_pull() {
    let (mut devs, clock, settings) = world();
    commits(&mut devs[0], &clock, &settings, 40);
    {
        let b = &mut devs[1];
        b.server.state().page_size = 4;
        b.server.state().delta_pages_left = Some(5);
        assert!(round(b, &clock, &settings).unwrap().offline);
        assert!(pending(b).is_some());
        b.server.state().delta_pages_left = None;
    }
    {
        let a = &mut devs[0];
        let mut rng = SeededRandom::new(77);
        let identity = DeviceIdentity::generate(&mut DynEntropy(&mut rng)).unwrap();
        a.account
            .add_device(
                &mut a.server,
                &mut a.store,
                LogDevice::of(&identity, &ACCOUNT, DeviceId::from_bytes([9; 16]), false),
                "D9",
                0,
                &mut a.rng,
            )
            .unwrap();
    }
    commits(&mut devs[0], &clock, &settings, 8);
    let b = &mut devs[1];
    let before = b.server.state().delta_pages;
    round(b, &clock, &settings).unwrap();
    let pages = b.server.state().delta_pages - before;
    // The remaining pages, the page of the cut once more and the last page's end.
    assert!(pages + 5 <= full_pages(b) + 2, "went on: {pages} pages");
    assert_eq!(
        b.folder.view().frontier().map(|f| f.commit),
        b.server.state().head(&FOLDER)
    );
    assert_eq!(
        b.folder.meta().timeline.len(),
        devs[0].folder.meta().timeline.len()
    );
}

/// A stored check whose pinned log head is not in this device's log (`ChainError::LogChanged`
/// when it is decoded) begins again from the frontier.
#[test]
fn a_stored_pull_without_its_pinned_log_head_begins_again() {
    let (mut devs, clock, settings) = world();
    commits(&mut devs[0], &clock, &settings, 40);
    let b = &mut devs[1];
    b.server.state().page_size = 4;
    b.server.state().delta_pages_left = Some(5);
    assert!(round(b, &clock, &settings).unwrap().offline);
    b.server.state().delta_pages_left = None;
    // Another hash at the pinned log head's index: format, account, folder, generation, mode,
    // the head's tag and index come before it (47 bytes).
    let key = format!("pull/{}", FOLDER.to_hex());
    let mut stored: serde_json::Value = serde_json::from_slice(&pending(b).unwrap()).unwrap();
    let mut verifier: Blob = serde_json::from_value(stored["verifier"].clone()).unwrap();
    verifier.0[47] ^= 0xff;
    stored["verifier"] = serde_json::to_value(&verifier).unwrap();
    b.store
        .put_account_value(&key, &serde_json::to_vec(&stored).unwrap())
        .unwrap();
    let before = b.server.state().delta_pages;
    round(b, &clock, &settings).unwrap();
    let pages = b.server.state().delta_pages - before;
    assert!(pages >= full_pages(b), "began again: {pages} pages");
    assert_eq!(
        b.folder.view().frontier().map(|f| f.commit),
        b.server.state().head(&FOLDER)
    );
    assert!(pending(b).is_none());
}

/// A refusal on a later page drops the stored state and takes nothing in: the server shows an
/// older state of the folder while B goes on with a pull it began before.
#[test]
fn a_rewound_server_after_a_cut_off_pull_stops_the_folder_and_keeps_nothing() {
    let (mut devs, clock, settings) = world();
    commits(&mut devs[0], &clock, &settings, 10);
    round(&mut devs[1], &clock, &settings).unwrap();
    let synced = devs[1].folder.view().frontier().copied();
    let old = devs[0].server.state().folder_sequence(&FOLDER);
    commits(&mut devs[0], &clock, &settings, 30);
    let b = &mut devs[1];
    b.server.state().page_size = 4;
    b.server.state().delta_pages_left = Some(3);
    assert!(round(b, &clock, &settings).unwrap().offline);
    assert!(pending(b).is_some());
    b.server.state().delta_pages_left = None;
    b.server.state().rewind_folder(&FOLDER, old - 2);
    round(b, &clock, &settings).unwrap();
    assert_eq!(
        b.folder.state(),
        hangar_drive_sync::folder::FolderState::Stopped(
            hangar_drive_sync::folder::StopReason::OlderState
        )
    );
    assert_eq!(b.folder.view().frontier().copied(), synced);
    assert!(pending(b).is_none());
}

/// The full size: more commits than the former bound of a delta read as a whole (200,000).
/// About 200,000 rounds of a device; run with `--ignored`.
#[test]
#[ignore]
fn a_device_joins_a_folder_with_more_commits_than_the_former_bound() {
    let (mut devs, clock, settings) = world();
    let n = hangar_drive_sync::paging::MAX_DELTA_TOTAL + 1;
    commits(&mut devs[0], &clock, &settings, n);
    let b = &mut devs[1];
    round(b, &clock, &settings).unwrap();
    assert_eq!(
        b.folder.view().frontier().map(|f| f.commit),
        b.server.state().head(&FOLDER)
    );
}
