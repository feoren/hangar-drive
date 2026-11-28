//! Parallel object uploads (ADR 0001, amendment "upload throughput of the server", section
//! "Parallel uploads on the device"): several objects go up at once, never more than the cap,
//! also with two folders in one pass; the result equals one upload at a time; a failing upload,
//! a busy slot, an expired session and a cut at the work budget all leave a state the next
//! round goes on from.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport};
use hangar_drive_sync::memory::{
    MemFs, MemKeychain, MemServer, MemStore, MemUploads, SeededRandom, ServerState, SharedClock,
};
use hangar_drive_sync::ports::Clock;
use hangar_drive_sync::upload::UPLOAD_WORKERS;

const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
const DOCS: FolderId = FolderId::from_bytes([0xf0; 16]);
const PHOTOS: FolderId = FolderId::from_bytes([0xf1; 16]);
const START_MS: i64 = 1_795_651_200_000;

struct Dev {
    store: MemStore,
    keychain: MemKeychain,
    server: MemServer,
    account: Account,
    rng: SeededRandom,
    /// One synced folder per entry of `FOLDERS`, with its disk.
    folders: Vec<(FolderSync, MemFs)>,
}

const FOLDERS: [FolderId; 2] = [DOCS, PHOTOS];

/// One account with the two folders on two devices; the first device uploads, the second one
/// checks what arrived.
fn setup(clock: &SharedClock) -> (Rc<RefCell<ServerState>>, Dev, Dev) {
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
    for (folder, name) in FOLDERS.iter().zip(["Docs", "Photos"]) {
        account
            .create_folder(&mut s0, &mut st0, *folder, name, &mut r0)
            .unwrap();
    }
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
    let folders = |a: &Account| -> Vec<(FolderSync, MemFs)> {
        FOLDERS
            .iter()
            .zip(["Docs", "Photos"])
            .map(|(folder, name)| {
                let f = FolderSync::new(a, *folder, name);
                let fs = MemFs::new(true);
                f.write_marker(&fs).unwrap();
                (f, fs)
            })
            .collect()
    };
    let f0 = folders(&account);
    let f1 = folders(&a1);
    (
        Rc::clone(&server),
        Dev {
            store: st0,
            keychain: k0,
            server: s0,
            account,
            rng: r0,
            folders: f0,
        },
        Dev {
            store: st1,
            keychain: k1,
            server: s1,
            account: a1,
            rng: r1,
            folders: f1,
        },
    )
}

/// One round of folder `index`.
fn try_round(
    d: &mut Dev,
    index: usize,
    clock: &SharedClock,
    settings: &FolderSettings,
) -> Result<RoundReport, hangar_drive_sync::error::SyncError> {
    let (folder, fs) = &mut d.folders[index];
    let events = fs.take_events();
    folder.note_changes(events);
    d.account
        .refresh(&mut d.server, &mut d.keychain, &mut d.store)
        .unwrap();
    let mut cx = Ctx {
        account: &mut d.account,
        server: &mut d.server,
        keychain: &mut d.keychain,
        fs: &*fs,
        store: &mut d.store,
        clock,
        entropy: &mut d.rng,
        settings,
    };
    folder.round(&mut cx)
}

fn round(d: &mut Dev, index: usize, clock: &SharedClock, settings: &FolderSettings) -> RoundReport {
    try_round(d, index, clock, settings).unwrap()
}

fn files(fs: &MemFs) -> Vec<(String, Vec<u8>)> {
    fs.snapshot()
        .into_iter()
        .filter(|(k, _)| !k[0].starts_with('.'))
        .filter_map(|(k, v)| v.map(|v| (k.join("/"), v)))
        .collect()
}

/// `count` small files of distinct content, in two directories, plus one file of three chunks.
fn write_files(fs: &MemFs, count: usize, tag: &str) {
    fs.user_mkdir(&["sub".to_owned()]);
    for i in 0..count {
        let mut path = Vec::new();
        if i % 2 == 0 {
            path.push("sub".to_owned());
        }
        path.push(format!("{tag}-{i:03}.txt"));
        assert!(fs.user_write(&path, format!("{tag} {i}").repeat(20).as_bytes()));
    }
    let chunk = hangar_drive_protocol::object::CHUNK_SIZE as usize;
    let mut large = vec![7u8; 2 * chunk + 10];
    large[chunk] = 8;
    large[2 * chunk] = 9;
    assert!(fs.user_write(&[format!("{tag}-large.bin")], &large));
}

/// A round that runs to its end, with `workers` uploads at once.
fn whole(workers: usize) -> FolderSettings {
    FolderSettings {
        hash_threads: 1,
        upload_workers: workers,
        ..FolderSettings::default()
    }
}

/// Parallel uploads where each one takes `delay` of real time.
fn parallel(server: &Rc<RefCell<ServerState>>, delay: Duration) -> Arc<MemUploads> {
    let uploads = server.borrow_mut().enable_parallel_uploads();
    uploads.lock().delay = delay;
    uploads
}

/// Syncs every folder of the second device and checks it holds what the first one holds.
fn check_arrived(clock: &SharedClock, d0: &Dev, d1: &mut Dev) {
    for index in 0..d1.folders.len() {
        round(d1, index, clock, &whole(1));
        assert_eq!(
            files(&d0.folders[index].1),
            files(&d1.folders[index].1),
            "folder {index} arrived whole"
        );
    }
}

#[test]
fn uploads_overlap_and_never_exceed_the_cap() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, mut d1) = setup(&clock);
    let uploads = parallel(&server, Duration::from_millis(5));
    write_files(&d0.folders[0].1, 40, "doc");
    let report = round(&mut d0, 0, &clock, &whole(UPLOAD_WORKERS));
    assert!(!report.more);
    assert!(d0.folders[0].0.in_sync());
    let most = uploads.lock().max_in_flight;
    assert!(most > 1, "uploads overlapped: {most}");
    assert!(most <= UPLOAD_WORKERS, "at most the cap at once: {most}");
    assert_eq!(server.borrow().folder_sequence(&DOCS), 1);
    assert_eq!(
        server.borrow().object_puts.values().max(),
        Some(&1),
        "an object went up twice"
    );
    check_arrived(&clock, &d0, &mut d1);
}

#[test]
fn a_setting_above_the_servers_slots_is_capped() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, _d1) = setup(&clock);
    let uploads = parallel(&server, Duration::from_millis(5));
    write_files(&d0.folders[0].1, 60, "doc");
    round(&mut d0, 0, &clock, &whole(64));
    let most = uploads.lock().max_in_flight;
    assert!(
        most <= hangar_drive_sync::upload::MAX_UPLOAD_WORKERS,
        "capped at the server's slots: {most}"
    );
}

// Two runs draw their account and folder keys anew, so object IDs differ between runs; what
// must be equal is everything the keys do not decide.
#[test]
fn the_result_equals_one_upload_at_a_time() {
    let run = |workers: usize| {
        let clock = SharedClock::at(START_MS);
        let (server, mut d0, mut d1) = setup(&clock);
        if workers > 1 {
            parallel(&server, Duration::from_millis(1));
        }
        write_files(&d0.folders[0].1, 30, "doc");
        round(&mut d0, 0, &clock, &whole(workers));
        assert!(d0.folders[0].0.in_sync());
        check_arrived(&clock, &d0, &mut d1);
        let s = server.borrow();
        let live = s.live_set(&DOCS);
        let held = live
            .iter()
            .filter(|id| s.object_puts.contains_key(id))
            .count();
        (
            live.len(),
            held,
            s.object_puts.len(),
            s.object_puts.values().max().copied(),
            s.folder_sequence(&DOCS),
            files(&d1.folders[0].1),
        )
    };
    let serial = run(1);
    let parallel = run(UPLOAD_WORKERS);
    assert_eq!(serial.0, parallel.0, "as many live objects");
    assert_eq!(parallel.0, parallel.1, "every live object was uploaded");
    assert_eq!(serial.2, parallel.2, "as many objects uploaded");
    assert_eq!(parallel.3, Some(1), "each once");
    assert_eq!(serial.4, parallel.4, "as many commits");
    assert_eq!(serial.5, parallel.5, "the same files arrive");
}

#[test]
fn two_folders_in_one_pass_stay_within_the_cap() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, mut d1) = setup(&clock);
    let uploads = parallel(&server, Duration::from_millis(5));
    write_files(&d0.folders[0].1, 30, "doc");
    write_files(&d0.folders[1].1, 30, "photo");
    // One pass of the engine: every folder with its share of the budget, one after the other.
    let settings = FolderSettings {
        work_budget_ms: Some(1_000),
        ..whole(UPLOAD_WORKERS)
    };
    server.borrow_mut().put_cost = Some(clock.cost(10, Duration::ZERO));
    let mut passes = 0;
    loop {
        let mut more = false;
        for index in 0..2 {
            more |= round(&mut d0, index, &clock, &settings).more;
        }
        clock.advance(1_000);
        passes += 1;
        if !more && d0.folders.iter().all(|(f, _)| f.in_sync()) {
            break;
        }
        assert!(passes < 100, "the uploads did not finish");
    }
    let most = uploads.lock().max_in_flight;
    assert!(most > 1, "uploads overlapped: {most}");
    assert!(
        most <= UPLOAD_WORKERS,
        "at most the cap across folders: {most}"
    );
    assert_eq!(server.borrow().object_puts.values().max(), Some(&1));
    check_arrived(&clock, &d0, &mut d1);
}

#[test]
fn a_failing_upload_midway_leaves_a_state_the_next_round_goes_on_from() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, mut d1) = setup(&clock);
    let uploads = parallel(&server, Duration::from_millis(2));
    uploads.lock().fail_after = Some(10);
    write_files(&d0.folders[0].1, 40, "doc");
    // A transient failure: the round reports the server as unreachable and tries again later.
    let report = round(&mut d0, 0, &clock, &whole(UPLOAD_WORKERS));
    assert!(report.offline, "the failed upload is reported");
    assert!(!d0.folders[0].0.in_sync());
    assert_eq!(
        server.borrow().folder_sequence(&DOCS),
        0,
        "nothing is committed half"
    );
    let accepted = uploads.lock().accepted;
    assert_eq!(
        accepted, 10,
        "uploads in flight finished, none dispatched after the error"
    );
    assert_eq!(server.borrow().object_puts.len() as u64, accepted);
    uploads.lock().fail_after = None;
    clock.advance(1_000);
    let report = round(&mut d0, 0, &clock, &whole(UPLOAD_WORKERS));
    assert!(!report.more);
    assert!(d0.folders[0].0.in_sync());
    assert_eq!(
        server.borrow().object_puts.values().max(),
        Some(&1),
        "what went up before the error is not sent again"
    );
    check_arrived(&clock, &d0, &mut d1);
}

#[test]
fn a_budget_cut_with_parallel_workers_goes_on_where_it_stopped() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, mut d1) = setup(&clock);
    parallel(&server, Duration::from_millis(1));
    server.borrow_mut().put_cost = Some(clock.cost(100, Duration::ZERO));
    write_files(&d0.folders[0].1, 40, "doc");
    let settings = FolderSettings {
        work_budget_ms: Some(1_000),
        stage_bytes: 8 * 1_000,
        stage_interval_ms: 0,
        ..whole(UPLOAD_WORKERS)
    };
    let mut rounds = 0;
    let mut cut = 0;
    loop {
        let report = round(&mut d0, 0, &clock, &settings);
        clock.advance(1_000);
        rounds += 1;
        if report.more {
            cut += 1;
        }
        if !report.more && d0.folders[0].0.in_sync() {
            break;
        }
        assert!(rounds < 200, "the upload did not finish");
    }
    assert!(cut >= 2, "the budget cut the upload: {cut} cuts");
    let s = server.borrow();
    assert!(s.folder_sequence(&DOCS) >= 2, "intermediate commits");
    assert_eq!(
        s.object_puts.values().max(),
        Some(&1),
        "an object went up twice"
    );
    drop(s);
    check_arrived(&clock, &d0, &mut d1);
}

#[test]
fn a_busy_slot_narrows_the_upload_instead_of_failing_it() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, mut d1) = setup(&clock);
    let uploads = parallel(&server, Duration::from_millis(2));
    uploads.lock().rate_limited = 2;
    write_files(&d0.folders[0].1, 20, "doc");
    let report = round(&mut d0, 0, &clock, &whole(UPLOAD_WORKERS));
    assert!(!report.more);
    assert!(d0.folders[0].0.in_sync());
    assert_eq!(uploads.lock().refused, 2);
    assert_eq!(server.borrow().object_puts.values().max(), Some(&1));
    check_arrived(&clock, &d0, &mut d1);
}

#[test]
fn a_busy_slot_at_one_upload_at_a_time_is_an_error() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, _d1) = setup(&clock);
    let uploads = parallel(&server, Duration::ZERO);
    // More refusals than the upload can narrow: it ends at one at a time and reports it.
    uploads.lock().rate_limited = 100;
    write_files(&d0.folders[0].1, 20, "doc");
    let report = round(&mut d0, 0, &clock, &whole(UPLOAD_WORKERS));
    assert!(
        report.offline,
        "the refusal is reported like an unreachable server"
    );
    assert!(!d0.folders[0].0.in_sync());
    assert_eq!(server.borrow().folder_sequence(&DOCS), 0);
    assert!(uploads.lock().refused <= UPLOAD_WORKERS as u64 * 2);
    uploads.lock().rate_limited = 0;
    clock.advance(1_000);
    assert!(!round(&mut d0, 0, &clock, &whole(UPLOAD_WORKERS)).more);
    assert!(d0.folders[0].0.in_sync());
}

#[test]
fn an_expired_session_under_a_worker_is_renewed_on_the_round_thread() {
    let clock = SharedClock::at(START_MS);
    let (server, mut d0, mut d1) = setup(&clock);
    let uploads = parallel(&server, Duration::from_millis(2));
    uploads.lock().unauthorized = 3;
    write_files(&d0.folders[0].1, 20, "doc");
    let report = round(&mut d0, 0, &clock, &whole(UPLOAD_WORKERS));
    assert!(!report.more);
    assert!(d0.folders[0].0.in_sync());
    assert_eq!(uploads.lock().unauthorized, 0);
    assert_eq!(server.borrow().object_puts.values().max(), Some(&1));
    check_arrived(&clock, &d0, &mut d1);
}

/// Wall time of one round that uploads many small files with 5 ms per upload, one at a time and with
/// the default number of workers. Printed for the record (`--nocapture`); the assertion only
/// asks for a clear gain, so a slow test machine does not make it flaky.
#[test]
fn parallel_uploads_take_less_wall_time() {
    let measure = |workers: usize| {
        let clock = SharedClock::at(START_MS);
        let (server, mut d0, _d1) = setup(&clock);
        parallel(&server, Duration::ZERO);
        // Real time per upload on both paths: the cost is paid by the inline upload and by
        // the workers alike.
        server.borrow_mut().put_cost = Some(clock.cost(0, Duration::from_millis(5)));
        write_files(&d0.folders[0].1, 60, "doc");
        let start = Instant::now();
        round(&mut d0, 0, &clock, &whole(workers));
        let took = start.elapsed();
        let objects = server.borrow().put_log.len();
        (took, objects)
    };
    let (serial, objects) = measure(1);
    let (parallel, _) = measure(UPLOAD_WORKERS);
    eprintln!(
        "{objects} objects at 5 ms each: one at a time {serial:?}, {UPLOAD_WORKERS} workers {parallel:?}"
    );
    assert!(
        parallel * 3 < serial * 2,
        "parallel {parallel:?} against serial {serial:?}"
    );
}

/// The engine's passes: every folder of the account in one pass, each with its share of the
/// budget, through the engine's own folder settings.
mod engine_pass {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Duration;

    use hangar_drive_protocol::ids::*;
    use hangar_drive_sync::api::{ApiResult, FolderStatus};
    use hangar_drive_sync::engine::{EngineCore, EnginePorts, EngineSettings};
    use hangar_drive_sync::memory::{
        MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedClock, SharedKeychain,
    };
    use hangar_drive_sync::ports::{FileSystem, ServerApi};
    use hangar_drive_sync::upload::UPLOAD_WORKERS;

    type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

    #[test]
    fn two_folders_of_one_engine_upload_in_parallel_within_the_cap() {
        let shared: Rc<RefCell<ServerState>> = MemServer::new_shared();
        let disks: Disks = Rc::default();
        let clock = SharedClock::at(super::START_MS);
        let ports = {
            let server = Rc::clone(&shared);
            let disks = Rc::clone(&disks);
            EnginePorts {
                store: Box::new(MemStore::new()),
                keychain: Box::new(SharedKeychain::default()),
                clock: Box::new(clock.clone()),
                entropy: Box::new(SeededRandom::new(1)),
                fs: Box::new(move |path: &Path| {
                    let fs = disks
                        .borrow_mut()
                        .entry(path.to_path_buf())
                        .or_insert_with(|| Arc::new(MemFs::new(true)))
                        .clone();
                    let events =
                        Box::new(fs.clone()) as Box<dyn hangar_drive_sync::watch::ChangeSource>;
                    Ok((Box::new(fs) as Box<dyn FileSystem>, Some(events)))
                }),
                server: Box::new(move |config, identity| {
                    let device = identity.map_or(DeviceId::from_bytes([0; 16]), |i| i.device);
                    Ok(
                        Box::new(MemServer::connect_pinned(&server, device, config.pin))
                            as Box<dyn ServerApi>,
                    )
                }),
                roots: Box::new(|path: &Path, _existing: &[PathBuf]| Ok(path.to_path_buf())),
            }
        };
        let mut core = EngineCore::open(ports, EngineSettings::default()).unwrap();
        let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
        let ApiResult::Ok(code) = core.begin_account(&link, "Laptop").unwrap() else {
            panic!("begin");
        };
        let group = code.groups[code.check_group as usize - 1].clone();
        assert!(core.confirm_recovery_group(&group).unwrap());
        let uploads = shared.borrow_mut().enable_parallel_uploads();
        uploads.lock().delay = Duration::from_millis(2);
        shared.borrow_mut().put_cost = Some(clock.cost(20, Duration::ZERO));
        let mut ids = Vec::new();
        for (path, name) in [("mem:/a/Docs", "Docs"), ("mem:/a/Photos", "Photos")] {
            let folder = core.add_folder(path, name).unwrap();
            ids.push(FolderId::from_hex(&folder).unwrap());
            let fs = disks.borrow()[&PathBuf::from(path)].clone();
            for i in 0..40 {
                assert!(fs.user_write(
                    &[format!("{name}-{i:03}.txt")],
                    format!("{name} {i}").as_bytes()
                ));
            }
        }
        let mut passes = 0;
        loop {
            clock.advance(1_000);
            core.tick();
            passes += 1;
            let snapshot = core.snapshot();
            if !core.has_more_work()
                && snapshot.folders.len() == 2
                && snapshot
                    .folders
                    .iter()
                    .all(|f| f.status == FolderStatus::UpToDate)
            {
                break;
            }
            assert!(passes < 300, "the folders did not get up to date");
        }
        let most = uploads.lock().max_in_flight;
        assert!(most > 1, "uploads overlapped: {most}");
        assert!(
            most <= UPLOAD_WORKERS,
            "at most the cap across both folders: {most}"
        );
        let s = shared.borrow();
        assert_eq!(
            s.object_puts.values().max(),
            Some(&1),
            "an object went up twice"
        );
        for folder in &ids {
            assert!(s.folder_sequence(folder) >= 1);
            // The server took every upload in (`settle_uploads`) and holds the head's objects.
            assert!(s.object_count(folder) >= s.live_set(folder).len());
        }
    }
}
