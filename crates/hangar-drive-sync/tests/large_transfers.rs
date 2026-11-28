//! Large files and many small ones without a frozen engine: downloads go in parallel through
//! worker threads within a byte window, a large file arrives in parts across rounds and goes
//! on where it stopped (atomic at the end, no chunk fetched twice), and a large file is hashed
//! in parts across rounds without reading it again from the start.

use std::time::{Duration, Instant};

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_protocol::object::CHUNK_SIZE;
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport};
use hangar_drive_sync::interrupt::Interrupt;
use hangar_drive_sync::memory::{
    MemFs, MemKeychain, MemServer, MemStore, SeededRandom, ServerState, SharedClock,
};
use hangar_drive_sync::ports::Clock;

const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
const FOLDER: FolderId = FolderId::from_bytes([0xf0; 16]);
const START_MS: i64 = 1_795_651_200_000;

struct Dev {
    store: MemStore,
    keychain: MemKeychain,
    server: MemServer,
    account: Account,
    rng: SeededRandom,
    sync: FolderSync,
    fs: MemFs,
}

/// One account with one folder on two devices.
fn setup(clock: &SharedClock) -> (std::rc::Rc<std::cell::RefCell<ServerState>>, Dev, Dev) {
    let server = MemServer::new_shared();
    let now = clock.now_ms() as u64;
    let id0 = DeviceId::from_bytes([1; 16]);
    let id1 = DeviceId::from_bytes([2; 16]);
    let mut s0 = MemServer::connect(&server, id0);
    let mut k0 = MemKeychain::default();
    let mut st0 = MemStore::new();
    let mut r0 = SeededRandom::new(7);
    let mut account = Account::create(
        &mut s0,
        &mut k0,
        &mut st0,
        &mut r0,
        now,
        InviteToken::from_bytes([9; 16]),
        ACCOUNT,
        id0,
        "Dev0",
        None,
    )
    .unwrap();
    account
        .create_folder(&mut s0, &mut st0, FOLDER, "Docs", &mut r0)
        .unwrap();
    let mut r1 = SeededRandom::new(8);
    let identity = DeviceIdentity::generate(&mut DynEntropy(&mut r1)).unwrap();
    let device = LogDevice::of(&identity, &ACCOUNT, id1, false);
    account
        .add_device(&mut s0, &mut st0, device, "Dev1", now, &mut r0)
        .unwrap();
    let mut s1 = MemServer::connect(&server, id1);
    let mut k1 = MemKeychain::default();
    let mut st1 = MemStore::new();
    let mut a1 = Account::join(
        &mut s1,
        &mut k1,
        &mut st1,
        identity,
        ACCOUNT,
        id1,
        "Dev1",
        &[],
    )
    .unwrap();
    account.refresh(&mut s0, &mut k0, &mut st0).unwrap();
    a1.refresh(&mut s1, &mut k1, &mut st1).unwrap();
    let dev = |account: Account, server, keychain, store, rng| {
        let sync = FolderSync::new(&account, FOLDER, "Docs");
        let fs = MemFs::new(true);
        sync.write_marker(&fs).unwrap();
        Dev {
            store,
            keychain,
            server,
            account,
            rng,
            sync,
            fs,
        }
    };
    (
        std::rc::Rc::clone(&server),
        dev(account, s0, k0, st0, r0),
        dev(a1, s1, k1, st1, r1),
    )
}

fn round(d: &mut Dev, clock: &SharedClock, settings: &FolderSettings) -> RoundReport {
    let events = d.fs.take_events();
    d.sync.note_changes(events);
    d.account
        .refresh(&mut d.server, &mut d.keychain, &mut d.store)
        .unwrap();
    let mut cx = Ctx {
        account: &mut d.account,
        server: &mut d.server,
        keychain: &mut d.keychain,
        fs: &d.fs,
        store: &mut d.store,
        clock,
        entropy: &mut d.rng,
        settings,
    };
    d.sync.round(&mut cx).unwrap()
}

fn files(fs: &MemFs) -> Vec<(String, Vec<u8>)> {
    fs.snapshot()
        .into_iter()
        .filter(|(k, _)| !k[0].starts_with('.'))
        .filter_map(|(k, v)| v.map(|v| (k.join("/"), v)))
        .collect()
}

/// A round that runs to its end.
fn whole() -> FolderSettings {
    FolderSettings {
        hash_threads: 1,
        ..FolderSettings::default()
    }
}

/// A file of `chunks` full chunks whose chunks all differ.
fn large(chunks: usize, tag: u8) -> Vec<u8> {
    let chunk = CHUNK_SIZE as usize;
    let mut data = vec![tag; chunks * chunk];
    for i in 0..chunks {
        data[i * chunk] = i as u8;
    }
    data
}

/// Wall time of the round that brings 60 small files to the second device, one download at a
/// time and through the lane's workers, with 20 ms per download. Printed for the record; the
/// assertion asks for a clear gain only, so a slow machine does not make it flaky.
#[test]
fn many_small_files_download_in_parallel() {
    let measure = |parallel: bool| {
        let clock = SharedClock::at(START_MS);
        let (server, mut d0, mut d1) = setup(&clock);
        for i in 0..60 {
            assert!(d0.fs.user_write(
                &[format!("small-{i:03}.txt")],
                format!("small {i}").as_bytes()
            ));
        }
        round(&mut d0, &clock, &whole());
        assert!(d0.sync.in_sync());
        let downloads = if parallel {
            let downloads = server.borrow_mut().enable_parallel_downloads();
            downloads.lock().delay = Duration::from_millis(20);
            Some(downloads)
        } else {
            server.borrow_mut().get_cost = Some(clock.cost(0, Duration::from_millis(20)));
            None
        };
        let started = Instant::now();
        round(&mut d1, &clock, &whole());
        let took = started.elapsed();
        assert_eq!(files(&d0.fs), files(&d1.fs), "every file arrived");
        if let Some(downloads) = downloads {
            let d = downloads.lock();
            assert!(
                d.max_in_flight > 1,
                "downloads overlapped: {}",
                d.max_in_flight
            );
            assert!(
                d.max_in_flight <= hangar_drive_sync::download::DOWNLOAD_WORKERS,
                "at most the cap at once: {}",
                d.max_in_flight
            );
            assert_eq!(
                d.fetched.values().max(),
                Some(&1),
                "a chunk was fetched twice"
            );
        }
        took
    };
    let serial = measure(false);
    let parallel = measure(true);
    eprintln!(
        "60 small files at 20 ms per download: one at a time {serial:?}, parallel {parallel:?}"
    );
    assert!(
        parallel * 2 < serial,
        "parallel {parallel:?} against serial {serial:?}"
    );
}

/// A large file arrives in parts: each round with a budget writes some chunks into the part
/// file and stops, the next goes on from there, no chunk is fetched twice, the file appears
/// only whole, and the part file is gone afterwards.
#[test]
fn a_large_download_goes_on_where_it_stopped() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, mut d1) = setup(&clock);
    let data = large(6, 3);
    assert!(d0.fs.user_write(&["video.bin".to_owned()], &data));
    round(&mut d0, &clock, &whole());
    assert!(d0.sync.in_sync());
    // Each chunk costs 400 ms of the budget of 1 s.
    server.borrow_mut().get_cost = Some(clock.cost(400, Duration::ZERO));
    let settings = FolderSettings {
        work_budget_ms: Some(1_000),
        ..whole()
    };
    let mut parts = Vec::new();
    for _ in 0..20 {
        let report = round(&mut d1, &clock, &settings);
        clock.advance(1_000);
        let in_place = d1.fs.read_all(&["video.bin".to_owned()]);
        if !report.more && in_place.is_some() {
            break;
        }
        assert!(in_place.is_none(), "the file appeared before it was whole");
        parts.push(d1.fs.partial_files());
    }
    assert!(
        parts.len() >= 2,
        "the download took several rounds: {parts:?}"
    );
    let grown: Vec<u64> = parts
        .iter()
        .map(|p| p.first().map_or(0, |(_, len)| *len))
        .collect();
    assert!(
        grown.windows(2).all(|w| w[1] >= w[0]) && grown.first() < grown.last(),
        "the part file grew from round to round: {grown:?}"
    );
    assert_eq!(files(&d0.fs), files(&d1.fs));
    assert!(d1.fs.partial_files().is_empty(), "the part file stayed");
    let s = server.borrow();
    assert_eq!(
        s.object_gets.values().max(),
        Some(&1),
        "a chunk was fetched twice"
    );
}

/// A command that waits stops a large download after the chunk under way, not after the file.
#[test]
fn a_waiting_command_stops_a_large_download_between_chunks() {
    let clock = SharedClock::at(START_MS);
    let (_server, mut d0, mut d1) = setup(&clock);
    let data = large(5, 4);
    assert!(d0.fs.user_write(&["big.bin".to_owned()], &data));
    round(&mut d0, &clock, &whole());
    let interrupt = Interrupt::default();
    let settings = FolderSettings {
        work_budget_ms: Some(60_000),
        interrupt: interrupt.clone(),
        ..whole()
    };
    let waiting = interrupt.raise();
    let report = round(&mut d1, &clock, &settings);
    assert!(report.more, "the stopped download asks for the next round");
    assert_eq!(
        d1.fs.partial_files().first().map(|(_, len)| *len),
        Some(CHUNK_SIZE),
        "one chunk per round while a command waits"
    );
    assert!(d1.fs.read_all(&["big.bin".to_owned()]).is_none());
    drop(waiting);
    let report = round(&mut d1, &clock, &settings);
    assert!(!report.more);
    assert_eq!(files(&d0.fs), files(&d1.fs));
}

/// A large file is hashed in parts while commands wait: each round goes on from the chunks
/// hashed so far, the file is read once for hashing, and a file that changed in between is
/// hashed from its start.
#[test]
fn a_large_hash_goes_on_where_it_stopped() {
    let clock = SharedClock::at(START_MS);
    let (_server, mut d0, mut d1) = setup(&clock);
    let data = large(5, 5);
    assert!(d0.fs.user_write(&["disk.img".to_owned()], &data));
    let interrupt = Interrupt::default();
    let settings = FolderSettings {
        work_budget_ms: Some(60_000),
        interrupt: interrupt.clone(),
        ..whole()
    };
    let waiting = interrupt.raise();
    let mut rounds = 0;
    while d0.sync.deferred().0 > 0 || rounds == 0 {
        round(&mut d0, &clock, &settings);
        rounds += 1;
        assert!(rounds <= 8, "the hash did not go on from where it stopped");
    }
    assert_eq!(rounds, 5, "one chunk per round while a command waits");
    // Hashing read the file once; the upload of the round that finished it reads a chunk more
    // at most before it yields.
    let read = d0.fs.bytes_read();
    assert!(
        read <= data.len() as u64 + 2 * CHUNK_SIZE,
        "read {read} bytes for a file of {}",
        data.len()
    );
    drop(waiting);
    for _ in 0..10 {
        if !round(&mut d0, &clock, &settings).more && d0.sync.in_sync() {
            break;
        }
    }
    round(&mut d1, &clock, &whole());
    assert_eq!(files(&d0.fs), files(&d1.fs));

    // A change in the middle starts the hash over, so the new content is what goes up.
    let waiting = interrupt.raise();
    let changed = large(5, 6);
    assert!(d0.fs.user_write(&["disk.img".to_owned()], &changed));
    round(&mut d0, &clock, &settings);
    clock.advance(5_000);
    let newer = large(5, 7);
    assert!(d0.fs.user_write(&["disk.img".to_owned()], &newer));
    drop(waiting);
    for _ in 0..10 {
        if !round(&mut d0, &clock, &settings).more && d0.sync.in_sync() {
            break;
        }
    }
    round(&mut d1, &clock, &whole());
    assert_eq!(
        d1.fs.read_all(&["disk.img".to_owned()]),
        Some(newer),
        "the newest content arrived"
    );
}

/// Once a waiting command stopped the wait for one file, the rest of the run starts no other
/// download: many files still to come must not each wait a slice.
#[test]
fn a_stopped_download_run_ends_at_once() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, mut d1) = setup(&clock);
    for i in 0..60 {
        assert!(d0.fs.user_write(
            &[format!("small-{i:03}.txt")],
            format!("small {i}").as_bytes()
        ));
    }
    round(&mut d0, &clock, &whole());
    let downloads = server.borrow_mut().enable_parallel_downloads();
    downloads.lock().delay = Duration::from_millis(400);
    let interrupt = Interrupt::default();
    let settings = FolderSettings {
        work_budget_ms: Some(60_000),
        interrupt: interrupt.clone(),
        ..whole()
    };
    let waiting = interrupt.raise();
    let started = Instant::now();
    let report = round(&mut d1, &clock, &settings);
    let took = started.elapsed();
    assert!(report.more);
    assert!(
        took < Duration::from_millis(1_000),
        "the stopped run took {took:?}"
    );
    drop(waiting);
    for _ in 0..20 {
        if !round(&mut d1, &clock, &settings).more {
            break;
        }
    }
    assert_eq!(files(&d0.fs), files(&d1.fs));
}

/// The first round of a large download while a command waits: one chunk in the part file.
fn start_in_parts(
    clock: &SharedClock,
    d0: &mut Dev,
    d1: &mut Dev,
    data: &[u8],
) -> (FolderSettings, String) {
    assert!(d0.fs.user_write(&["big.bin".to_owned()], data));
    round(d0, clock, &whole());
    let interrupt = Interrupt::default();
    let settings = FolderSettings {
        work_budget_ms: Some(60_000),
        interrupt: interrupt.clone(),
        ..whole()
    };
    let waiting = interrupt.raise();
    round(d1, clock, &settings);
    drop(waiting);
    let parts = d1.fs.partial_files();
    assert_eq!(parts.len(), 1, "one part file: {parts:?}");
    (settings, parts[0].0.clone())
}

/// Rounds until the file is in place; its content then must be what the other device holds.
fn finish(clock: &SharedClock, d: &mut Dev, settings: &FolderSettings) -> Vec<u8> {
    for _ in 0..20 {
        round(d, clock, settings);
        clock.advance(60_000);
        if let Some(data) = d.fs.read_all(&["big.bin".to_owned()]) {
            return data;
        }
    }
    panic!("the file never landed");
}

/// Security review M1: bytes of the part file changed between two rounds at the same length
/// (another program, a disk error) never land; the download starts over and the right content
/// arrives.
#[test]
fn a_part_file_changed_between_rounds_never_lands() {
    let clock = SharedClock::at(START_MS);
    let (_server, mut d0, mut d1) = setup(&clock);
    let data = large(4, 8);
    let (settings, name) = start_in_parts(&clock, &mut d0, &mut d1, &data);
    d1.fs.tamper_partial(&name);
    let landed = finish(&clock, &mut d1, &settings);
    assert!(landed == data, "the changed part file landed");
    assert!(d1.fs.partial_files().is_empty());
}

/// Security review M1: a finish that failed (the target was locked) keeps the whole content in
/// the part file; one cut short meanwhile is checked again and never lands.
#[test]
fn a_part_file_cut_after_a_failed_finish_never_lands() {
    let clock = SharedClock::at(START_MS);
    let (_server, mut d0, mut d1) = setup(&clock);
    let data = large(4, 9);
    let target = vec!["big.bin".to_owned()];
    d1.fs.set_locked(&target, true);
    let (settings, name) = start_in_parts(&clock, &mut d0, &mut d1, &data);
    // The rest of the chunks go in; the finish fails on the lock.
    round(&mut d1, &clock, &settings);
    assert_eq!(
        d1.fs.partial_files().first().map(|(_, len)| *len),
        Some(data.len() as u64),
        "the whole content is in the part file"
    );
    assert!(d1.fs.read_all(&target).is_none());
    d1.fs.truncate_partial(&name, 1000);
    d1.fs.set_locked(&target, false);
    clock.advance(60_000);
    let landed = finish(&clock, &mut d1, &settings);
    assert!(landed == data, "the cut part file landed");
}

/// Security review N1: the part file of a file the other device deleted meanwhile goes with the
/// next round, and a folder that is let go leaves none behind.
#[test]
fn part_files_go_once_nothing_needs_them() {
    let clock = SharedClock::at(START_MS);
    let (_server, mut d0, mut d1) = setup(&clock);
    let data = large(3, 10);
    let (settings, _) = start_in_parts(&clock, &mut d0, &mut d1, &data);
    assert!(d0.fs.user_delete(&["big.bin".to_owned()]));
    for _ in 0..5 {
        round(&mut d0, &clock, &whole());
        clock.advance(20_000);
    }
    round(&mut d1, &clock, &settings);
    assert!(d1.fs.partial_files().is_empty(), "the part file stayed");
    assert_eq!(d1.sync.partial_download_count(), 0);

    let (_, _) = start_in_parts(&clock, &mut d0, &mut d1, &large(3, 11));
    d1.sync.discard_partials(&d1.fs);
    assert!(
        d1.fs.partial_files().is_empty(),
        "a let-go folder kept its part file"
    );
}
