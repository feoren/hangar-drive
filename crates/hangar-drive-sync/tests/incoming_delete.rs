//! The guard for deletes another device made (ADR 0001, amendment "incoming mass deletes"): a
//! single compromised device, or a slip on another device, must not empty the working copy of
//! every device within seconds. Device A deletes, device B holds the deletes until the person
//! decides, and only exactly what B showed goes when the person lets it.

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport, DELETE_WINDOW_MS};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom,
};

const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
const FOLDER: FolderId = FolderId::from_bytes([0xf1; 16]);
const A: DeviceId = DeviceId::from_bytes([1; 16]);
const B: DeviceId = DeviceId::from_bytes([2; 16]);

struct Dev {
    fs: MemFs,
    store: MemStore,
    keys: MemKeychain,
    server: MemServer,
    rng: SeededRandom,
    account: Account,
    folder: FolderSync,
    settings: FolderSettings,
}

struct World {
    a: Dev,
    b: Dev,
    clock: ManualClock,
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

/// Files live in directories of 100, so no directory gets huge.
fn name(i: usize) -> Vec<String> {
    p(&[&format!("d{:02}", i / 100), &format!("f{i:04}.txt")])
}

fn world() -> World {
    let shared = MemServer::new_shared();
    let mut server_a = MemServer::connect(&shared, A);
    let (mut store_a, mut keys_a, mut rng_a) = (
        MemStore::new(),
        MemKeychain::default(),
        SeededRandom::new(1),
    );
    let mut account_a = Account::create(
        &mut server_a,
        &mut keys_a,
        &mut store_a,
        &mut rng_a,
        0,
        InviteToken::from_bytes([9; 16]),
        ACCOUNT,
        A,
        "Laptop",
        None,
    )
    .unwrap();
    account_a
        .create_folder(&mut server_a, &mut store_a, FOLDER, "Docs", &mut rng_a)
        .unwrap();
    let mut rng_b = SeededRandom::new(11);
    let identity = DeviceIdentity::generate(&mut DynEntropy(&mut rng_b)).unwrap();
    account_a
        .add_device(
            &mut server_a,
            &mut store_a,
            LogDevice::of(&identity, &ACCOUNT, B, false),
            "Desktop",
            0,
            &mut rng_a,
        )
        .unwrap();
    account_a
        .refresh(&mut server_a, &mut keys_a, &mut store_a)
        .unwrap();
    let mut server_b = MemServer::connect(&shared, B);
    let (mut store_b, mut keys_b) = (MemStore::new(), MemKeychain::default());
    let account_b = Account::join(
        &mut server_b,
        &mut keys_b,
        &mut store_b,
        identity,
        ACCOUNT,
        B,
        "Desktop",
        &[],
    )
    .unwrap();
    let dev = |fs: MemFs,
               store: MemStore,
               keys: MemKeychain,
               server: MemServer,
               rng: SeededRandom,
               account: Account,
               settings: FolderSettings| {
        let folder = FolderSync::new(&account, FOLDER, "Docs");
        folder.write_marker(&fs).unwrap();
        Dev {
            fs,
            store,
            keys,
            server,
            rng,
            account,
            folder,
            settings,
        }
    };
    // A plays the device that deletes: its own guard is out of the way, as on a compromised
    // device.
    let a_settings = FolderSettings {
        mass_delete_threshold: usize::MAX,
        ..FolderSettings::default()
    };
    World {
        a: dev(
            MemFs::new(true),
            store_a,
            keys_a,
            server_a,
            rng_a,
            account_a,
            a_settings,
        ),
        b: dev(
            MemFs::new(true),
            store_b,
            keys_b,
            server_b,
            rng_b,
            account_b,
            FolderSettings::default(),
        ),
        clock: ManualClock::at(1_795_651_200_000),
    }
}

fn round(d: &mut Dev, clock: &ManualClock) -> RoundReport {
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
        settings: &d.settings,
    };
    d.folder.round(&mut cx).unwrap()
}

/// Runs `f` on B's folder with a context.
fn on_b<T>(w: &mut World, f: impl FnOnce(&mut FolderSync, &mut Ctx<'_>) -> T) -> T {
    let d = &mut w.b;
    d.account
        .refresh(&mut d.server, &mut d.keys, &mut d.store)
        .unwrap();
    let mut cx = Ctx {
        account: &mut d.account,
        server: &mut d.server,
        keychain: &mut d.keys,
        fs: &d.fs,
        store: &mut d.store,
        clock: &w.clock,
        entropy: &mut d.rng,
        settings: &d.settings,
    };
    f(&mut d.folder, &mut cx)
}

/// Both devices hold `n` synced files.
fn synced(n: usize) -> World {
    let mut w = world();
    round(&mut w.a, &w.clock);
    for i in 0..n {
        if i % 100 == 0 {
            assert!(w.a.fs.user_mkdir(&name(i)[..1]));
        }
        assert!(w.a.fs.user_write(&name(i), format!("{i}").as_bytes()));
    }
    assert!(round(&mut w.a, &w.clock).published);
    round(&mut w.b, &w.clock);
    assert_eq!(w.b.folder.local().count_files(), n);
    w
}

/// A deletes files `range` (its delete delay included), and B takes one round.
fn a_deletes(w: &mut World, range: std::ops::Range<usize>) -> RoundReport {
    for i in range {
        assert!(w.a.fs.user_delete(&name(i)), "{i}");
    }
    round(&mut w.a, &w.clock);
    w.clock.advance(w.a.settings.delete_delay_ms + 1_000);
    round(&mut w.a, &w.clock);
    round(&mut w.b, &w.clock)
}

fn on_b_disk(w: &World, i: usize) -> bool {
    w.b.fs.read_all(&name(i)).is_some()
}

fn held(w: &World) -> usize {
    w.b.folder.incoming_held_files()
}

#[test]
fn a_folder_of_fewer_than_100_files_never_asks() {
    let mut w = synced(99);
    a_deletes(&mut w, 0..99);
    assert_eq!(held(&w), 0);
    assert_eq!(w.b.folder.local().count_files(), 0);
    assert!(!on_b_disk(&w, 0));
}

#[test]
fn deleting_all_of_100_files_is_held_on_the_other_device() {
    let mut w = synced(100);
    let report = a_deletes(&mut w, 0..100);
    assert_eq!(held(&w), 100);
    assert!((0..100).all(|i| on_b_disk(&w, i)), "the files stay on B");
    assert_eq!(w.b.folder.synced().count_files(), 100, "and in B's base");
    assert_eq!(w.a.folder.remote().count_files(), 0, "A's delete went out");
    assert!(!report.in_sync);
    // A held delete is no activity entry.
    assert!(report.changes.is_empty(), "{:?}", report.changes);
    // The writer is known from the verified timeline.
    assert_eq!(
        w.b.folder
            .meta()
            .incoming_devices
            .iter()
            .collect::<Vec<_>>(),
        vec![&A]
    );
}

#[test]
fn the_share_counts_from_a_quarter_of_the_folder() {
    let mut w = synced(401);
    a_deletes(&mut w, 0..100);
    assert_eq!(held(&w), 0, "100 of 401 is less than a quarter");
    assert_eq!(w.b.folder.local().count_files(), 301);

    let mut w = synced(400);
    a_deletes(&mut w, 0..100);
    assert_eq!(held(&w), 100, "100 of 400 is a quarter");
}

#[test]
fn from_1000_deletes_the_share_does_not_matter() {
    let mut w = synced(4001);
    a_deletes(&mut w, 0..999);
    assert_eq!(held(&w), 0, "999 of 4001");
    assert_eq!(w.b.folder.local().count_files(), 3002);
    // One more within the window: 1000 of the 4001 files, less than a quarter, but 1000.
    a_deletes(&mut w, 999..1000);
    assert_eq!(held(&w), 1);
    assert!(on_b_disk(&w, 999));
}

#[test]
fn honest_tidying_up_does_not_ask() {
    let mut w = synced(300);
    let report = a_deletes(&mut w, 0..20);
    assert_eq!(held(&w), 0);
    assert_eq!(w.b.folder.local().count_files(), 280);
    assert!(report.in_sync);
}

#[test]
fn moves_and_directories_are_not_counted() {
    let mut w = synced(200);
    // 200 files move into one new directory; their old directories go.
    w.a.fs.user_mkdir(&p(&["all"]));
    for i in 0..200 {
        let to = p(&["all", &format!("f{i:04}.txt")]);
        assert!(w.a.fs.user_rename(&name(i), &to));
    }
    round(&mut w.a, &w.clock);
    w.clock.advance(w.a.settings.delete_delay_ms + 1_000);
    round(&mut w.a, &w.clock);
    round(&mut w.b, &w.clock);
    assert_eq!(held(&w), 0);
    assert!(w.b.fs.read_all(&p(&["all", "f0150.txt"])).is_some());
    assert_eq!(w.b.folder.local().count_files(), 200);
}

#[test]
fn the_window_adds_up_deletes_of_several_commits() {
    let mut w = synced(400);
    // 60 files go, then 60 more: alone each is below the threshold, together they are 120 of
    // the 400 files the folder held.
    a_deletes(&mut w, 0..60);
    assert_eq!(held(&w), 0);
    assert_eq!(w.b.folder.local().count_files(), 340);
    a_deletes(&mut w, 60..120);
    assert_eq!(held(&w), 60);
    assert!((60..120).all(|i| on_b_disk(&w, i)));
    // Every further delete is held while the question is open.
    a_deletes(&mut w, 120..121);
    assert_eq!(held(&w), 61);
    // After the window, a delete of the same size goes through again.
    let revision = w.b.folder.meta().incoming_revision;
    w.b.folder
        .approve_incoming(revision, &mut w.b.store)
        .unwrap();
    round(&mut w.b, &w.clock);
    assert_eq!(held(&w), 0);
    w.clock.advance(DELETE_WINDOW_MS);
    a_deletes(&mut w, 121..181);
    assert_eq!(held(&w), 0);
    assert_eq!(w.b.folder.local().count_files(), 219);
}

#[test]
fn an_approval_lets_only_the_shown_deletes_go() {
    let mut w = synced(400);
    a_deletes(&mut w, 0..120);
    assert_eq!(held(&w), 120);
    let shown = w.b.folder.meta().incoming_revision;
    // 10 more arrive after the person saw the question: the old answer no longer fits.
    a_deletes(&mut w, 120..130);
    assert_eq!(held(&w), 130);
    assert!(w.b.folder.approve_incoming(shown, &mut w.b.store).is_err());
    assert_eq!(held(&w), 130, "nothing approved");
    let now = w.b.folder.meta().incoming_revision;
    assert_eq!(
        w.b.folder.approve_incoming(now, &mut w.b.store).unwrap(),
        130
    );
    // Before B's next round, A deletes 120 more: they were never shown and ask on their own.
    for i in 130..250 {
        assert!(w.a.fs.user_delete(&name(i)));
    }
    round(&mut w.a, &w.clock);
    w.clock.advance(w.a.settings.delete_delay_ms + 1_000);
    round(&mut w.a, &w.clock);
    round(&mut w.b, &w.clock);
    assert!(
        (0..130).all(|i| !on_b_disk(&w, i)),
        "the approved ones went"
    );
    assert_eq!(held(&w), 120);
    assert!((130..250).all(|i| on_b_disk(&w, i)));
    assert!(w.b.folder.meta().incoming_approved.is_empty());
}

#[test]
fn restore_brings_the_files_back_on_the_deleting_device() {
    let mut w = synced(150);
    a_deletes(&mut w, 0..120);
    assert_eq!(held(&w), 120);
    let back = on_b(&mut w, |f, cx| f.restore_incoming(cx)).unwrap();
    assert_eq!(back, 120);
    assert_eq!(held(&w), 0);
    round(&mut w.b, &w.clock);
    round(&mut w.a, &w.clock);
    assert_eq!(w.a.folder.local().count_files(), 150);
    assert_eq!(w.a.fs.read_all(&name(7)), Some(b"7".to_vec()));
    assert_eq!(w.b.folder.local().count_files(), 150);
    assert!(round(&mut w.b, &w.clock).in_sync);
}

#[test]
fn a_local_change_to_a_held_file_wins_over_the_delete() {
    let mut w = synced(150);
    a_deletes(&mut w, 0..120);
    assert_eq!(held(&w), 120);
    assert!(w.b.fs.user_write(&name(5), b"changed on B"));
    let report = round(&mut w.b, &w.clock);
    assert!(report.published);
    assert_eq!(held(&w), 119);
    round(&mut w.a, &w.clock);
    assert_eq!(w.a.fs.read_all(&name(5)), Some(b"changed on B".to_vec()));
}

#[test]
fn the_question_survives_a_restart() {
    let mut w = synced(150);
    a_deletes(&mut w, 0..120);
    let before = w.b.folder.meta().incoming_held.clone();
    let revision = w.b.folder.meta().incoming_revision;
    w.b.folder = FolderSync::load(&w.b.account, FOLDER, &w.b.store)
        .unwrap()
        .unwrap();
    assert_eq!(w.b.folder.meta().incoming_held, before);
    assert_eq!(w.b.folder.meta().incoming_revision, revision);
    assert_eq!(
        w.b.folder
            .meta()
            .incoming_devices
            .iter()
            .collect::<Vec<_>>(),
        vec![&A]
    );
    round(&mut w.b, &w.clock);
    assert_eq!(held(&w), 120);
    assert!((0..120).all(|i| on_b_disk(&w, i)));
}

#[test]
fn a_restore_of_this_device_deletes_without_asking() {
    let mut w = synced(150);
    // The person resets the folder on B to a tree without most files: their own decision.
    let mut tree = w.b.folder.remote().clone();
    for i in 0..120 {
        let id = tree.lookup(&name(i)).unwrap();
        tree.remove(&id);
    }
    on_b(&mut w, |f, cx| f.publish_tree(cx, tree)).unwrap();
    round(&mut w.b, &w.clock);
    assert_eq!(held(&w), 0);
    assert_eq!(w.b.folder.local().count_files(), 30);
    // Device A did not decide it: it asks.
    round(&mut w.a, &w.clock);
    assert_eq!(w.a.folder.incoming_held_files(), 120);
}

// -- Security review M3: the threshold cannot be diluted or paced ---------------------------------

/// A writes `n` more files after `from` (new on both devices), and B takes them in.
fn a_adds(w: &mut World, from: usize, n: usize) {
    for i in from..from + n {
        if i % 100 == 0 {
            assert!(w.a.fs.user_mkdir(&name(i)[..1]));
        }
        assert!(w.a.fs.user_write(&name(i), b""));
    }
    assert!(round(&mut w.a, &w.clock).published);
    round(&mut w.b, &w.clock);
}

#[test]
fn files_added_just_before_do_not_dilute_the_share() {
    let mut w = synced(200);
    // 1000 empty files first, then the 200 real ones go in one commit: 200 of 1200 is less
    // than a quarter, but the folder held only 200 files a moment ago.
    a_adds(&mut w, 200, 1000);
    assert_eq!(w.b.folder.local().count_files(), 1200);
    a_deletes(&mut w, 0..200);
    assert_eq!(held(&w), 200);
    assert!((0..200).all(|i| on_b_disk(&w, i)));
}

#[test]
fn deletes_paced_below_the_short_window_add_up_over_the_day() {
    let mut w = synced(400);
    a_deletes(&mut w, 0..60);
    assert_eq!(held(&w), 0);
    // Past the 10 minute window: alone 60 would pass, together they are 120 of 400.
    w.clock.advance(DELETE_WINDOW_MS + 60_000);
    a_deletes(&mut w, 60..120);
    assert_eq!(held(&w), 60);
    // 99 every 10 minutes do not slip through either: the second batch asks.
    let mut w = synced(500);
    a_deletes(&mut w, 0..99);
    assert_eq!(held(&w), 0);
    w.clock.advance(DELETE_WINDOW_MS + 1_000);
    a_deletes(&mut w, 99..198);
    assert_eq!(held(&w), 99);
    assert_eq!(w.b.folder.local().count_files(), 401);
}

#[test]
fn deleting_part_of_a_new_project_does_not_ask() {
    let mut w = synced(50);
    // A project of 300 files arrives, and 200 of them go again the same day.
    a_adds(&mut w, 100, 300);
    a_deletes(&mut w, 100..300);
    assert_eq!(held(&w), 0);
    assert_eq!(w.b.folder.local().count_files(), 150);
}

#[test]
fn a_little_cleanup_every_day_does_not_ask() {
    let mut w = synced(300);
    for day in 0..5 {
        a_deletes(&mut w, day * 20..day * 20 + 20);
        assert_eq!(held(&w), 0, "day {day}");
        w.clock
            .advance(hangar_drive_sync::folder::LONG_DELETE_WINDOW_MS);
    }
    assert_eq!(w.b.folder.local().count_files(), 200);
}

#[test]
fn deleting_and_writing_again_under_the_same_names_is_held() {
    let mut w = synced(150);
    // A deletes 120 files and, after its delete delay, writes new empty files with the same
    // names: on B the old ones are kept until the person decides.
    for i in 0..120 {
        assert!(w.a.fs.user_delete(&name(i)));
    }
    round(&mut w.a, &w.clock);
    w.clock.advance(w.a.settings.delete_delay_ms + 1_000);
    round(&mut w.a, &w.clock);
    for i in 0..120 {
        assert!(w.a.fs.user_write(&name(i), b""));
    }
    round(&mut w.a, &w.clock);
    round(&mut w.b, &w.clock);
    round(&mut w.b, &w.clock);
    assert_eq!(held(&w), 120);
    assert_eq!(
        w.b.fs.read_all(&name(7)),
        Some(b"7".to_vec()),
        "the old one stays"
    );
    // Letting them go brings the new files.
    let revision = w.b.folder.meta().incoming_revision;
    w.b.folder
        .approve_incoming(revision, &mut w.b.store)
        .unwrap();
    round(&mut w.b, &w.clock);
    round(&mut w.b, &w.clock);
    assert_eq!(w.b.fs.read_all(&name(7)), Some(Vec::new()));
    assert!(
        w.b.folder.meta().cannot_sync.is_empty(),
        "{:?}",
        w.b.folder.meta().cannot_sync
    );
    assert_eq!(w.b.folder.local().count_files(), 150);
}

#[test]
fn the_long_window_survives_a_restart() {
    let mut w = synced(400);
    a_deletes(&mut w, 0..60);
    w.b.folder = FolderSync::load(&w.b.account, FOLDER, &w.b.store)
        .unwrap()
        .unwrap();
    w.clock.advance(DELETE_WINDOW_MS + 60_000);
    a_deletes(&mut w, 60..120);
    assert_eq!(held(&w), 60);
}
