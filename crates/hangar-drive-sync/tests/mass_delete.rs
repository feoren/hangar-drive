//! The mass delete guard for this device's own deletes (security review, LOW 1): an approval
//! lets exactly the held deletes go, a question that is open holds every further delete, and
//! the threshold counts the deletes of a sliding window, not of one round.

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport};
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

fn round(d: &mut Dev, clock: &ManualClock, settings: &FolderSettings) -> RoundReport {
    d.folder.request_full_scan();
    d.account
        .refresh(&mut d.server, &mut d.keys, &mut d.store)
        .unwrap();
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
    d.folder.round(&mut cx).unwrap()
}

fn name(i: usize) -> Vec<String> {
    p(&[&format!("f{i:03}.txt")])
}

/// A device with `n` synced files; returns it with the clock and settings.
fn synced_files(n: usize) -> (Dev, ManualClock, FolderSettings) {
    let (mut devs, clock, settings) = world();
    let mut d = devs.remove(0);
    round(&mut d, &clock, &settings);
    for i in 0..n {
        d.fs.user_write(&name(i), format!("{i}").as_bytes());
    }
    assert!(round(&mut d, &clock, &settings).published);
    assert_eq!(d.folder.remote().count_files(), n);
    (d, clock, settings)
}

/// Deletes files `range` on the disk and runs rounds until the delete delay is over.
fn delete(
    d: &mut Dev,
    clock: &ManualClock,
    settings: &FolderSettings,
    range: std::ops::Range<usize>,
) {
    for i in range {
        assert!(d.fs.user_delete(&name(i)));
    }
    round(d, clock, settings);
    clock.advance(settings.delete_delay_ms + 1_000);
    round(d, clock, settings);
}

#[test]
fn an_approval_lets_only_the_held_deletes_go() {
    let (mut d, clock, settings) = synced_files(300);
    delete(&mut d, &clock, &settings, 0..120);
    assert_eq!(d.folder.meta().held.len(), 120);
    assert_eq!(d.folder.remote().count_files(), 300, "held, not propagated");
    // The person lets them go, and before the next round deletes 150 more.
    d.folder.resolve_held(false, &mut d.store).unwrap();
    for i in 120..270 {
        assert!(d.fs.user_delete(&name(i)));
    }
    clock.advance(settings.delete_delay_ms + 1_000);
    round(&mut d, &clock, &settings);
    clock.advance(settings.delete_delay_ms + 1_000);
    round(&mut d, &clock, &settings);
    // The 120 went; the 150 were never approved and wait for their own question.
    assert_eq!(d.folder.remote().count_files(), 180);
    assert_eq!(d.folder.meta().held.len(), 150);
    assert!(d.folder.meta().approved.is_empty());
}

#[test]
fn an_open_question_holds_every_further_delete() {
    let (mut d, clock, settings) = synced_files(130);
    delete(&mut d, &clock, &settings, 0..110);
    assert_eq!(d.folder.meta().held.len(), 110);
    // One more file while the question is open: held as well, not propagated on its own.
    delete(&mut d, &clock, &settings, 120..121);
    assert_eq!(d.folder.meta().held.len(), 111);
    assert_eq!(d.folder.remote().count_files(), 130);
}

#[test]
fn a_slow_delete_is_held_once_the_window_reaches_the_threshold() {
    let (mut d, clock, settings) = synced_files(200);
    // 50 files every 15 seconds: the first 50 go, the next ones reach 100 in the window.
    delete(&mut d, &clock, &settings, 0..50);
    assert!(d.folder.meta().held.is_empty());
    assert_eq!(
        d.folder
            .meta()
            .recent_deletes
            .iter()
            .map(|r| r.1)
            .sum::<u64>(),
        50
    );
    assert_eq!(d.folder.remote().count_files(), 150);
    delete(&mut d, &clock, &settings, 50..100);
    assert_eq!(d.folder.meta().held.len(), 50);
    assert_eq!(d.folder.remote().count_files(), 150);
    // After the window, a delete of the same size goes through again.
    d.folder.resolve_held(true, &mut d.store).unwrap();
    round(&mut d, &clock, &settings);
    assert!(d.folder.meta().held.is_empty());
    clock.advance(hangar_drive_sync::folder::DELETE_WINDOW_MS);
    delete(&mut d, &clock, &settings, 100..150);
    assert!(d.folder.meta().held.is_empty());
    assert_eq!(d.folder.remote().count_files(), 100);
}

// Security review M3: the same flank as the incoming guard. 60 deletes, and 60 more past the
// 10 minute window, stayed below the threshold one by one; over the day they are 120 of 400.
#[test]
fn deletes_paced_past_the_window_add_up_over_the_day() {
    let (mut d, clock, settings) = synced_files(400);
    // A day later the files are no longer new.
    clock.advance(hangar_drive_sync::folder::LONG_DELETE_WINDOW_MS);
    round(&mut d, &clock, &settings);
    delete(&mut d, &clock, &settings, 0..60);
    assert!(d.folder.meta().held.is_empty());
    assert_eq!(d.folder.remote().count_files(), 340);
    clock.advance(hangar_drive_sync::folder::DELETE_WINDOW_MS + 60_000);
    delete(&mut d, &clock, &settings, 60..120);
    assert_eq!(d.folder.meta().held.len(), 60);
    assert_eq!(d.folder.remote().count_files(), 340);
    // The decision starts the day again.
    d.folder.resolve_held(false, &mut d.store).unwrap();
    round(&mut d, &clock, &settings);
    assert_eq!(d.folder.remote().count_files(), 280);
    clock.advance(hangar_drive_sync::folder::DELETE_WINDOW_MS + 60_000);
    delete(&mut d, &clock, &settings, 120..180);
    assert!(d.folder.meta().held.is_empty());
}

// Creating a project and deleting most of it again is ordinary work: files that only just
// arrived do not count in the long window.
#[test]
fn deleting_files_made_today_does_not_add_up() {
    let (mut d, clock, settings) = synced_files(100);
    clock.advance(hangar_drive_sync::folder::LONG_DELETE_WINDOW_MS);
    round(&mut d, &clock, &settings);
    for i in 100..400 {
        d.fs.user_write(&name(i), b"new");
    }
    round(&mut d, &clock, &settings);
    for batch in [100..190, 190..280] {
        delete(&mut d, &clock, &settings, batch);
        assert!(d.folder.meta().held.is_empty());
        clock.advance(hangar_drive_sync::folder::DELETE_WINDOW_MS + 60_000);
    }
    assert_eq!(d.folder.remote().count_files(), 220);
}
