//! The caches of the local index shrink (security review, MEDIUM 3): after many versions the
//! cleanup keeps what the trees and the recent history need, and syncing, downloading and a
//! restore of an old version still work afterwards.

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport, HISTORY_CACHE_MS};
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

macro_rules! cx {
    ($d:expr, $clock:expr, $settings:expr) => {
        Ctx {
            account: &mut $d.account,
            server: &mut $d.server,
            keychain: &mut $d.keys,
            fs: &$d.fs,
            store: &mut $d.store,
            clock: $clock,
            entropy: &mut $d.rng,
            settings: $settings,
        }
    };
}

fn round(d: &mut Dev, clock: &ManualClock, settings: &FolderSettings) -> RoundReport {
    d.folder.request_full_scan();
    d.account
        .refresh(&mut d.server, &mut d.keys, &mut d.store)
        .unwrap();
    let mut cx = cx!(d, clock, settings);
    d.folder.round(&mut cx).unwrap()
}

#[test]
fn the_cache_shrinks_and_syncing_and_restoring_go_on() {
    let (mut devs, clock, settings) = world();
    for d in devs.iter_mut() {
        round(d, &clock, &settings);
    }
    let a = 0;
    for n in 0..20 {
        devs[a].fs.user_mkdir(&p(&[&format!("d{n}")]));
        devs[a].fs.user_write(
            &p(&[&format!("d{n}"), "f.txt"]),
            format!("first {n}").as_bytes(),
        );
    }
    assert!(round(&mut devs[a], &clock, &settings).published);
    // B downloads the first versions, then A rewrites every file 30 times.
    round(&mut devs[1], &clock, &settings);
    let first = devs[1].folder.meta().timeline.last().unwrap().commit;
    for v in 0..30 {
        for n in 0..20 {
            devs[a].fs.user_write(
                &p(&[&format!("d{n}"), "f.txt"]),
                format!("version {v} of {n}").as_bytes(),
            );
        }
        round(&mut devs[a], &clock, &settings);
        round(&mut devs[1], &clock, &settings);
        clock.advance(60_000);
    }
    let b = &mut devs[1];
    let before = b.store.cache_rows();
    // The history is older than the window now: only the trees' rows stay.
    clock.advance(HISTORY_CACHE_MS);
    let gone = {
        let mut cx = cx!(b, &clock, &settings);
        b.folder.prune_cache(&mut cx).unwrap()
    };
    let after = b.store.cache_rows();
    assert!(
        gone > 0 && after.0 < before.0 / 4,
        "{before:?} -> {after:?}"
    );
    assert!(after.2 < before.2 / 4, "{before:?} -> {after:?}");
    // A new version still comes down to B.
    devs[a]
        .fs
        .user_write(&p(&["d3", "f.txt"]), b"after the cleanup");
    assert!(round(&mut devs[a], &clock, &settings).published);
    round(&mut devs[1], &clock, &settings);
    assert_eq!(
        devs[1].fs.read_all(&p(&["d3", "f.txt"])).unwrap(),
        b"after the cleanup"
    );
    // B publishes on its own, and a restore of the first version fetches it again.
    devs[1].fs.user_write(&p(&["new.txt"]), b"from b");
    assert!(round(&mut devs[1], &clock, &settings).published);
    let b = &mut devs[1];
    {
        let mut cx = cx!(b, &clock, &settings);
        b.folder.restore_folder(&mut cx, &first).unwrap();
    }
    round(b, &clock, &settings);
    assert_eq!(b.fs.read_all(&p(&["d3", "f.txt"])).unwrap(), b"first 3");
}
