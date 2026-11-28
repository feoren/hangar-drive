//! The engine stays responsive during long work: a round stops at its work budget at a clean
//! point (between hash batches, between object uploads before the commit, between downloaded
//! files), the loop answers commands and sends progress snapshots in between, and the next
//! round carries on. Nothing is uploaded twice and no half commit is made, also when the app
//! ends in the middle of an upload and starts again.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hangar_drive_protocol::ids::*;
use hangar_drive_sync::api::{ApiResult, BackendEvent, FolderStatus, Snapshot};
use hangar_drive_sync::engine::{Engine, EngineCore, EnginePorts, EngineSettings};
use hangar_drive_sync::memory::{
    MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedClock, SharedKeychain,
};
use hangar_drive_sync::ports::{Clock, FileSystem, ServerApi};

type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

const START_MS: i64 = 1_795_651_200_000;
/// The longest a command may wait while every upload hangs for a second on the server.
const COMMAND_BOUND: Duration = Duration::from_millis(500);

struct World {
    shared: Rc<RefCell<ServerState>>,
    disks: Disks,
    clock: SharedClock,
}

impl World {
    fn new(clock: SharedClock) -> Self {
        Self {
            shared: MemServer::new_shared(),
            disks: Rc::default(),
            clock,
        }
    }

    /// An installation with its own keychain and local index; the same two make the same
    /// installation after a restart of the app.
    fn device(&self, seed: u64, keychain: &SharedKeychain, store: &MemStore) -> EngineCore {
        let server = Rc::clone(&self.shared);
        let disks = Rc::clone(&self.disks);
        let ports = EnginePorts {
            store: Box::new(store.clone()),
            keychain: Box::new(keychain.clone()),
            clock: Box::new(self.clock.clone()),
            entropy: Box::new(SeededRandom::new(seed)),
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
        };
        EngineCore::open(ports, EngineSettings::default()).unwrap()
    }

    fn disk(&self, path: &str) -> Arc<MemFs> {
        self.disks.borrow()[&PathBuf::from(path)].clone()
    }

    /// The folder's objects on the server: how often each was uploaded, how many the server
    /// holds, and how many the head's tree references.
    fn objects(&self, folder: &FolderId) -> (u64, usize, usize) {
        let s = self.shared.borrow();
        let most = s.object_puts.values().copied().max().unwrap_or(0);
        (most, s.object_count(folder), s.live_set(folder).len())
    }
}

/// A new account with its code confirmed and one folder with `files` small files of distinct
/// content; returns the folder ID.
fn account_with_files(world: &World, core: &mut EngineCore, files: usize) -> FolderId {
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = core.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(core.confirm_recovery_group(&group).unwrap());
    let folder = core.add_folder("mem:/a/Docs", "Docs").unwrap();
    let fs = world.disk("mem:/a/Docs");
    fs.user_mkdir(&["sub".to_owned()]);
    for i in 0..files {
        let dir = if i.is_multiple_of(2) { "sub" } else { "" };
        let mut path: Vec<String> = Vec::new();
        if !dir.is_empty() {
            path.push(dir.to_owned());
        }
        path.push(format!("file-{i:04}.txt"));
        assert!(fs.user_write(&path, format!("content of file {i}").as_bytes()));
    }
    FolderId::from_hex(&folder).unwrap()
}

fn folder_status(snapshot: &Snapshot) -> FolderStatus {
    snapshot.folders[0].status
}

thread_local! {
    /// The engine thread's server, so a command can report its counters to the test thread.
    static SERVER: RefCell<Option<Rc<RefCell<ServerState>>>> = const { RefCell::new(None) };
}

#[test]
fn the_engine_answers_and_reports_progress_during_a_large_upload() {
    const FILES: usize = 150;
    let (handle, events) = Engine::spawn(
        || {
            let world = World::new(SharedClock::at(START_MS));
            let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
            account_with_files(&world, &mut core, FILES);
            // Every upload takes 100 ms of engine time (the budget sees ten per second) and
            // 15 ms of real time: the whole upload of some 300 objects takes several seconds.
            world.shared.borrow_mut().put_cost =
                Some(world.clock.cost(100, Duration::from_millis(15)));
            SERVER.with(|s| *s.borrow_mut() = Some(Rc::clone(&world.shared)));
            Ok(core)
        },
        // The app's pause between passes: with work left the loop must not wait for it.
        Duration::from_secs(5),
    )
    .unwrap();

    // The first event is the stored state, before any scan or upload.
    let first = events.recv_timeout(Duration::from_secs(5)).unwrap();
    let BackendEvent::Snapshot { snapshot } = first else {
        panic!("the first event is a snapshot");
    };
    assert_eq!(snapshot.folders.len(), 1);

    // Progress snapshots arrive while the upload runs: uploading, with bytes left going down.
    let mut seen_left: Vec<u64> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while seen_left.len() < 3 {
        assert!(Instant::now() < deadline, "no progress snapshots");
        let Ok(BackendEvent::Snapshot { snapshot }) = events.recv_timeout(Duration::from_secs(10))
        else {
            continue;
        };
        if let FolderStatus::Uploading { count } = folder_status(&snapshot) {
            assert_eq!(count, FILES as u64);
            assert!(snapshot.sync.pending_files >= FILES as u64);
            if snapshot.sync.bytes_left > 0 {
                seen_left.push(snapshot.sync.bytes_left);
            }
        }
    }
    assert!(
        seen_left.windows(2).all(|w| w[1] <= w[0]) && seen_left.last() < seen_left.first(),
        "bytes left go down: {seen_left:?}"
    );

    // Commands are answered within a slice, not after the whole upload.
    for _ in 0..5 {
        let asked = Instant::now();
        let snapshot = handle.call(|core| core.snapshot()).unwrap();
        let waited = asked.elapsed();
        assert!(
            waited < Duration::from_millis(1500),
            "a command waited {waited:?} during the upload"
        );
        if snapshot.folders[0].status == FolderStatus::UpToDate {
            break;
        }
    }

    // The upload ends without the loop's five second pause between slices.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        assert!(Instant::now() < deadline, "the upload did not finish");
        let snapshot = handle.call(|core| core.snapshot()).unwrap();
        if snapshot.folders[0].status == FolderStatus::UpToDate {
            assert_eq!(snapshot.sync.pending_files, 0);
            assert_eq!(snapshot.sync.bytes_left, 0);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Every object went up exactly once, and the server holds exactly the committed tree.
    let (most, uploaded, calls) = handle
        .call(|_| {
            SERVER.with(|s| {
                let s = s.borrow();
                let s = s.as_ref().unwrap().borrow();
                let most = s.object_puts.values().copied().max().unwrap_or(0);
                (most, s.object_puts.len(), s.calls)
            })
        })
        .unwrap();
    assert_eq!(most, 1, "an object was uploaded twice");
    assert!(uploaded >= 2 * FILES, "chunks and manifests: {uploaded}");
    assert!(calls > 0);
}

#[test]
fn an_upload_cut_off_by_the_end_of_the_app_resumes_after_a_restart() {
    const FILES: usize = 60;
    let world = World::new(SharedClock::at(START_MS));
    let keys = SharedKeychain::default();
    let store = MemStore::new();
    let mut core = world.device(1, &keys, &store);
    let folder = account_with_files(&world, &mut core, FILES);
    world.shared.borrow_mut().put_cost = Some(world.clock.cost(100, Duration::ZERO));

    // One pass: the scan, then uploads until the budget is spent. No commit yet.
    core.tick();
    assert!(core.has_more_work());
    let (most, stored, _) = world.objects(&folder);
    assert_eq!(most, 1);
    assert!(
        stored > 0 && stored < 2 * FILES,
        "part of the upload: {stored}"
    );
    assert_eq!(world.shared.borrow().head(&folder), None, "no commit yet");
    let snapshot = core.snapshot();
    assert_eq!(
        folder_status(&snapshot),
        FolderStatus::Uploading {
            count: FILES as u64
        }
    );
    assert!(snapshot.sync.bytes_left > 0);
    assert_eq!(snapshot.sync.last_sync, None);

    // The app ends here and starts again with the same index and keychain.
    drop(core);
    let mut core = world.device(1, &keys, &store);
    let mut passes = 0;
    loop {
        world.clock.advance(1_000);
        core.tick();
        passes += 1;
        if !core.has_more_work() && core.snapshot().folders[0].status == FolderStatus::UpToDate {
            break;
        }
        assert!(passes < 100, "the upload did not finish");
    }
    assert!(passes > 1, "the rest took more than one budget");
    let (most, stored, live) = world.objects(&folder);
    assert_eq!(most, 1, "an object was uploaded twice");
    assert_eq!(stored, live, "the server holds exactly the committed tree");
    assert!(world.shared.borrow().head(&folder).is_some());
    let snapshot = core.snapshot();
    assert_eq!(snapshot.sync.pending_files, 0);
    assert_eq!(snapshot.sync.bytes_left, 0);
    assert!(snapshot.sync.last_sync.is_some());
    let total: u64 = (0..FILES)
        .map(|i| format!("content of file {i}").len() as u64)
        .sum();
    assert_eq!(snapshot.folders[0].bytes, Some(total));
}

#[test]
fn a_large_first_scan_hashes_in_slices_and_commits_every_file() {
    const FILES: usize = 100;
    let world = World::new(SharedClock::at(START_MS));
    let keys = SharedKeychain::default();
    let store = MemStore::new();
    let mut core = world.device(1, &keys, &store);
    let folder = account_with_files(&world, &mut core, FILES);
    // Every read takes 20 ms; hashing a small file reads twice (the data, then the end), and
    // sealing it for the upload once more: all of them take several budgets.
    world
        .disk("mem:/a/Docs")
        .set_read_cost(Some(world.clock.cost(20, Duration::ZERO)));
    assert_eq!(
        core.snapshot().folders[0].file_count,
        None,
        "before the scan"
    );

    let started = world.clock.now_ms();
    core.tick();
    let took = world.clock.now_ms() - started;
    assert!(core.has_more_work(), "the scan stopped at its budget");
    // The file count does not jump: files waiting for their hash count already.
    let early = core.snapshot();
    assert_eq!(early.folders[0].file_count, Some(FILES as u64));
    // A pass cut at its budget is no full sync (security review of the budget, L1).
    assert_eq!(early.sync.last_sync, None);
    // One hash batch (32 files, 1.3 s here) plus a quarter budget of uploads at most.
    assert!(took < 2_000, "one pass took {took} ms of work");
    let first = core.snapshot();
    let FolderStatus::Uploading { count } = folder_status(&first) else {
        panic!(
            "the folder shows that it uploads: {:?}",
            folder_status(&first)
        );
    };
    // Files left unhashed at the budget count as still to upload, so a large first scan never
    // reads as up to date while it works (seen live on 2026-11-28: every folder said "up to
    // date" during a 7 GB first upload).
    assert_eq!(count, FILES as u64, "every new file counts as pending");
    let total: u64 = (0..FILES)
        .map(|i| format!("content of file {i}").len() as u64)
        .sum();
    assert_eq!(first.sync.pending_files, FILES as u64);
    // Sealed objects are padded, so what is left to send is at least the waiting plaintext.
    assert!(
        first.sync.bytes_left >= total / 2,
        "the bytes left cover the waiting files: {}",
        first.sync.bytes_left
    );

    let mut passes = 1;
    while core.has_more_work() {
        core.tick();
        passes += 1;
        assert!(passes < 100, "the scan did not finish");
    }
    // A pass without a budget cut confirms the end state.
    world.clock.advance(20_000);
    core.tick();
    let snapshot = core.snapshot();
    assert_eq!(folder_status(&snapshot), FolderStatus::UpToDate);
    assert_eq!(snapshot.sync.pending_files, 0);
    assert_eq!(snapshot.folders[0].bytes, Some(total));
    assert_eq!(snapshot.folders[0].file_count, Some(FILES as u64));
    assert!(snapshot.sync.last_sync.is_some());
    let (most, _, _) = world.objects(&folder);
    assert_eq!(most, 1, "an object was uploaded twice");
}

#[test]
fn a_large_download_writes_files_in_slices() {
    const FILES: usize = 60;
    let world = World::new(SharedClock::at(START_MS));
    let keys = SharedKeychain::default();
    let store = MemStore::new();
    let mut core = world.device(1, &keys, &store);
    let folder = account_with_files(&world, &mut core, FILES);
    let hex = folder.to_hex();
    core.tick();
    core.tick();
    assert_eq!(folder_status(&core.snapshot()), FolderStatus::UpToDate);

    // The folder is synced again at an empty place: every file comes from the server, and
    // every object fetched takes 100 ms.
    core.stop_folder(&hex).unwrap();
    core.add_account_folder(&hex, "mem:/a/Copy").unwrap();
    world.shared.borrow_mut().get_cost = Some(world.clock.cost(100, Duration::ZERO));
    core.tick();
    assert!(core.has_more_work(), "the download stopped at its budget");
    let copy = world.disk("mem:/a/Copy");
    let name = |i: usize| -> Vec<String> {
        let mut path = Vec::new();
        if i.is_multiple_of(2) {
            path.push("sub".to_owned());
        }
        path.push(format!("file-{i:04}.txt"));
        path
    };
    let written = (0..FILES)
        .filter(|i| copy.read_all(&name(*i)).is_some())
        .count();
    assert!(
        written > 0 && written < FILES,
        "part of the files: {written}"
    );
    let snapshot = core.snapshot();
    let FolderStatus::Downloading { count } = folder_status(&snapshot) else {
        panic!("downloading: {:?}", folder_status(&snapshot));
    };
    assert_eq!(count, (FILES - written) as u64);
    assert!(snapshot.sync.bytes_left > 0);

    let mut passes = 1;
    while core.has_more_work() {
        core.tick();
        passes += 1;
        assert!(passes < 100, "the download did not finish");
    }
    for i in 0..FILES {
        assert_eq!(
            copy.read_all(&name(i)).unwrap(),
            format!("content of file {i}").as_bytes()
        );
    }
    let snapshot = core.snapshot();
    assert_eq!(folder_status(&snapshot), FolderStatus::UpToDate);
    assert_eq!(snapshot.sync.bytes_left, 0);
    let most = world
        .shared
        .borrow()
        .object_gets
        .values()
        .copied()
        .max()
        .unwrap_or(0);
    assert_eq!(most, 1, "an object was downloaded twice");
}

#[test]
fn the_file_count_serializes_and_follows_the_disk() {
    let world = World::new(SharedClock::at(START_MS));
    let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
    account_with_files(&world, &mut core, 3);
    let json = serde_json::to_value(core.snapshot()).unwrap();
    assert!(
        json["folders"][0]["fileCount"].is_null(),
        "null before the scan"
    );
    core.tick();
    let json = serde_json::to_value(core.snapshot()).unwrap();
    // Files only: the directory `sub` and the folder's own marker do not count.
    assert_eq!(json["folders"][0]["fileCount"], 3);
    world
        .disk("mem:/a/Docs")
        .user_write(&["new.txt".to_owned()], b"one more");
    world.clock.advance(20_000);
    core.tick();
    assert_eq!(core.snapshot().folders[0].file_count, Some(4));
}

#[test]
fn a_snapshot_of_an_unchanged_folder_walks_no_tree() {
    const FILES: usize = 2_000;
    let world = World::new(SharedClock::at(START_MS));
    let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
    account_with_files(&world, &mut core, FILES);
    core.set_work_budget(None);
    core.tick();
    core.tick();
    let first = core.snapshot();
    assert_eq!(folder_status(&first), FolderStatus::UpToDate);
    let before = EngineCore::folder_sums_computed();
    for _ in 0..50 {
        assert_eq!(core.snapshot(), first);
    }
    assert_eq!(
        EngineCore::folder_sums_computed(),
        before,
        "an unchanged folder was summed again"
    );
    // A change on disk shows in the next snapshot after its pass.
    world
        .disk("mem:/a/Docs")
        .user_write(&["late.txt".to_owned()], b"late");
    world.clock.advance(20_000);
    core.tick();
    let after = core.snapshot();
    assert_eq!(after.folders[0].file_count, Some(FILES as u64 + 1));
    assert!(EngineCore::folder_sums_computed() > before);
}

#[test]
fn a_command_shows_in_a_snapshot_before_the_next_pass() {
    let (handle, events) = Engine::spawn(
        || {
            let world = World::new(SharedClock::at(START_MS));
            let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
            account_with_files(&world, &mut core, 60);
            core.pause(hangar_drive_sync::api::PauseDuration::Manual, None)
                .unwrap();
            // Once resumed, a pass uploads for a whole second of real time.
            world.shared.borrow_mut().put_cost =
                Some(world.clock.cost(100, Duration::from_millis(100)));
            SERVER.with(|s| *s.borrow_mut() = Some(Rc::clone(&world.shared)));
            Ok(core)
        },
        Duration::from_secs(5),
    )
    .unwrap();
    let Ok(BackendEvent::Snapshot { snapshot }) = events.recv_timeout(Duration::from_secs(5))
    else {
        panic!("the first event is a snapshot");
    };
    assert!(snapshot.sync.pause.is_some());
    while events.try_recv().is_ok() {}
    let asked = Instant::now();
    handle.call(|core| core.resume()).unwrap().unwrap();
    loop {
        let Ok(BackendEvent::Snapshot { snapshot }) = events.recv_timeout(Duration::from_secs(5))
        else {
            panic!("no snapshot after the command");
        };
        if snapshot.sync.pause.is_none() {
            break;
        }
    }
    let waited = asked.elapsed();
    assert!(
        waited < Duration::from_millis(600),
        "the resumed state showed after {waited:?}, behind a pass"
    );
}

#[test]
fn a_server_that_keeps_nothing_does_not_drive_the_loop_without_a_pause() {
    const FILES: usize = 60;
    let world = World::new(SharedClock::at(START_MS));
    let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
    account_with_files(&world, &mut core, FILES);
    {
        let mut s = world.shared.borrow_mut();
        s.put_cost = Some(world.clock.cost(100, Duration::ZERO));
        s.forget_puts = true;
    }
    core.tick();
    assert!(core.has_more_work(), "the first cut asks for the next pass");
    world.clock.advance(1_000);
    core.tick();
    assert!(
        !core.has_more_work(),
        "an upload that made no progress waits for the loop's pause"
    );
    // A server that keeps what it gets again is finished as usual.
    world.shared.borrow_mut().forget_puts = false;
    for _ in 0..100 {
        world.clock.advance(20_000);
        core.tick();
        if core.snapshot().folders[0].status == FolderStatus::UpToDate {
            return;
        }
    }
    panic!("the upload did not finish");
}

/// Rounds of one folder on two devices without the engine, as the security review's probes
/// ran them (security review of the budget, H1 and L1).
mod rounds {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    use hangar_drive_crypto::devicelog::LogDevice;
    use hangar_drive_crypto::identity::DeviceIdentity;
    use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
    use hangar_drive_sync::account::Account;
    use hangar_drive_sync::chunker::DynEntropy;
    use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport};
    use hangar_drive_sync::memory::{
        MemFs, MemKeychain, MemServer, MemStore, SeededRandom, ServerState, SharedClock,
    };
    use hangar_drive_sync::ports::Clock;

    const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
    const FOLDER: FolderId = FolderId::from_bytes([0xf0; 16]);

    struct Dev {
        fs: MemFs,
        store: MemStore,
        keychain: MemKeychain,
        server: MemServer,
        account: Account,
        folder: FolderSync,
        rng: SeededRandom,
    }

    fn p(s: &str) -> Vec<String> {
        s.split('/').map(str::to_owned).collect()
    }

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
        let f0 = FolderSync::new(&account, FOLDER, "Docs");
        let f1 = FolderSync::new(&a1, FOLDER, "Docs");
        let fs0 = MemFs::new(true);
        let fs1 = MemFs::new(true);
        f0.write_marker(&fs0).unwrap();
        f1.write_marker(&fs1).unwrap();
        (
            Rc::clone(&server),
            Dev {
                fs: fs0,
                store: st0,
                keychain: k0,
                server: s0,
                account,
                folder: f0,
                rng: r0,
            },
            Dev {
                fs: fs1,
                store: st1,
                keychain: k1,
                server: s1,
                account: a1,
                folder: f1,
                rng: r1,
            },
        )
    }

    fn round(d: &mut Dev, clock: &SharedClock, budget: Option<i64>) -> RoundReport {
        let settings = FolderSettings {
            hash_threads: 1,
            work_budget_ms: budget,
            ..FolderSettings::default()
        };
        let events = d.fs.take_events();
        d.folder.note_changes(events);
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
            settings: &settings,
        };
        d.folder.round(&mut cx).unwrap()
    }

    /// The files below the root with their contents, without the reserved directory.
    fn files(fs: &MemFs) -> Vec<(String, Vec<u8>)> {
        fs.snapshot()
            .into_iter()
            .filter(|(k, _)| !k[0].starts_with('.'))
            .filter_map(|(k, v)| v.map(|v| (k.join("/"), v)))
            .collect()
    }

    fn same_files(d0: &mut Dev, d1: &mut Dev) {
        for i in 0..40 {
            let name = p(&format!("f{i:02}.txt"));
            d0.fs.user_write(&name, format!("same {i}").as_bytes());
            d1.fs.user_write(&name, format!("same {i}").as_bytes());
        }
    }

    /// Device 1 joins a folder it already holds the same 40 files of, with the budget on and
    /// slow reads, so most of its files wait for their hash while the server's arrive.
    fn join(budget: Option<i64>) -> (SharedClock, Dev, Dev) {
        let clock = SharedClock::at(1_795_651_200_000);
        let (_server, mut d0, mut d1) = setup(&clock);
        same_files(&mut d0, &mut d1);
        for _ in 0..3 {
            round(&mut d0, &clock, None);
            clock.advance(20_000);
        }
        d1.fs.set_read_cost(Some(clock.cost(50, Duration::ZERO)));
        for _ in 0..10 {
            round(&mut d1, &clock, budget);
            clock.advance(20_000);
            round(&mut d0, &clock, None);
            clock.advance(20_000);
        }
        d1.fs.set_read_cost(None);
        (clock, d0, d1)
    }

    fn assert_joined(d0: &Dev, d1: &Dev) {
        assert!(
            d1.folder.cannot_sync().is_empty(),
            "files marked cannot sync: {:?}",
            d1.folder.cannot_sync()
        );
        let (f0, f1) = (files(&d0.fs), files(&d1.fs));
        assert_eq!(f1.len(), 40, "no conflict copies on device 1: {f1:?}");
        assert_eq!(f0, f1);
    }

    #[test]
    fn a_join_with_the_budget_leaves_no_file_unsynced() {
        let (_clock, d0, d1) = join(Some(1000));
        assert_joined(&d0, &d1);
        assert!(d1.folder.in_sync());
    }

    #[test]
    fn a_join_without_the_budget_leaves_no_file_unsynced() {
        let (_clock, d0, d1) = join(None);
        assert_joined(&d0, &d1);
    }

    #[test]
    fn edits_after_a_join_with_the_budget_reach_both_devices() {
        let (clock, mut d0, mut d1) = join(Some(1000));
        // The last files in hash order are the ones that waited longest.
        d1.fs.user_write(&p("f38.txt"), b"edited on dev1");
        d0.fs.user_write(&p("f39.txt"), b"edited on dev0");
        for _ in 0..5 {
            round(&mut d1, &clock, None);
            clock.advance(20_000);
            round(&mut d0, &clock, None);
            clock.advance(20_000);
        }
        assert_eq!(d0.fs.read_all(&p("f38.txt")).unwrap(), b"edited on dev1");
        assert_eq!(d1.fs.read_all(&p("f39.txt")).unwrap(), b"edited on dev0");
        assert_joined(&d0, &d1);
    }

    #[test]
    fn a_new_file_waiting_for_its_hash_meets_a_remote_file_of_its_name() {
        let clock = SharedClock::at(1_795_651_200_000);
        let (_server, mut d0, mut d1) = setup(&clock);
        // The hashed part has nothing to upload: its contents are on the server already.
        d0.fs.user_mkdir(&p("copy"));
        for i in 0..32 {
            d0.fs.user_write(
                &p(&format!("copy/n{i:02}.txt")),
                format!("dev1 {i}").as_bytes(),
            );
        }
        for _ in 0..2 {
            round(&mut d0, &clock, None);
            clock.advance(20_000);
            round(&mut d1, &clock, None);
            clock.advance(20_000);
        }
        for i in 0..40 {
            d1.fs
                .user_write(&p(&format!("n{i:02}.txt")), format!("dev1 {i}").as_bytes());
        }
        d0.fs.user_write(&p("n39.txt"), b"dev0 39");
        round(&mut d0, &clock, None);
        clock.advance(20_000);
        d1.fs.set_read_cost(Some(clock.cost(50, Duration::ZERO)));
        for _ in 0..10 {
            round(&mut d1, &clock, Some(1000));
            clock.advance(20_000);
        }
        assert!(
            d1.folder.cannot_sync().is_empty(),
            "files marked cannot sync: {:?}",
            d1.folder.cannot_sync()
        );
        // Both versions of n39 are kept, one of them as the conflict copy.
        let contents: Vec<Vec<u8>> = files(&d1.fs).into_iter().map(|(_, v)| v).collect();
        assert!(contents.contains(&b"dev0 39".to_vec()));
        assert!(contents.contains(&b"dev1 39".to_vec()));
    }

    #[test]
    fn a_round_with_files_waiting_for_their_hash_is_not_in_sync() {
        let clock = SharedClock::at(1_795_651_200_000);
        let (_server, mut d0, mut d1) = setup(&clock);
        // Every content device 1 will hash is on the server already, so its upload seals no
        // chunk and its commit goes through within the budget, while files still wait.
        d0.fs.user_mkdir(&p("copy"));
        for i in 0..40 {
            d0.fs.user_write(
                &p(&format!("copy/x{i:02}.txt")),
                format!("x {i}").as_bytes(),
            );
        }
        for _ in 0..2 {
            round(&mut d0, &clock, None);
            clock.advance(20_000);
            round(&mut d1, &clock, None);
            clock.advance(20_000);
        }
        for i in 0..40 {
            d1.fs
                .user_write(&p(&format!("x{i:02}.txt")), format!("x {i}").as_bytes());
        }
        d1.fs.set_read_cost(Some(clock.cost(50, Duration::ZERO)));
        let report = round(&mut d1, &clock, Some(1000));
        assert!(report.more);
        assert!(report.published, "the hashed part went out");
        assert!(!report.in_sync, "in sync while files wait for their hash");
    }
}

/// A server that takes a second per object (measured on a slow server, 2026-11-28): the
/// engine takes a command within half a second while every upload worker waits for it, a
/// pause stops new uploads at once while those in flight finish, and after the resume the
/// upload ends with every object sent once. The bound ([`COMMAND_BOUND`]) is about ten times
/// what a desktop measured (some 50 ms) and half of one upload, so a slow CI runner passes
/// while a command that waits for an upload still fails.
#[test]
fn a_command_is_taken_at_once_while_uploads_hang_on_a_slow_server() {
    const FILES: usize = 40;
    let (uploads_tx, uploads_rx) = std::sync::mpsc::channel();
    let (handle, events) = Engine::spawn(
        move || {
            let world = World::new(SharedClock::at(START_MS));
            let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
            account_with_files(&world, &mut core, FILES);
            let uploads = world.shared.borrow_mut().enable_parallel_uploads();
            uploads.lock().delay = Duration::from_millis(1_000);
            let _ = uploads_tx.send(uploads);
            SERVER.with(|s| *s.borrow_mut() = Some(Rc::clone(&world.shared)));
            Ok(core)
        },
        Duration::from_secs(5),
    )
    .unwrap();
    let uploads = uploads_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // Drained in the background, as the app's event thread does.
    std::thread::spawn(move || for _ in events {});

    let deadline = Instant::now() + Duration::from_secs(30);
    while uploads.lock().accepted < 2 {
        assert!(Instant::now() < deadline, "the upload did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    let asked = Instant::now();
    handle
        .call(|core| core.pause(hangar_drive_sync::api::PauseDuration::Manual, None))
        .unwrap()
        .unwrap();
    let waited = asked.elapsed();
    eprintln!("the pause was taken after {waited:?} with every upload worker waiting");
    assert!(
        waited < COMMAND_BOUND,
        "the pause waited {waited:?} for uploads in flight"
    );
    let asked = Instant::now();
    let snapshot = handle.call(|core| core.snapshot()).unwrap();
    assert!(snapshot.sync.pause.is_some(), "the pause shows");
    assert!(asked.elapsed() < COMMAND_BOUND);

    // What was in flight finishes; nothing new goes up while paused, and no upload worker
    // waits idle meanwhile.
    std::thread::sleep(Duration::from_millis(1_500));
    let settled = uploads.lock().accepted;
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(
        uploads.lock().accepted,
        settled,
        "uploads went on while paused"
    );
    let open = handle.call(|core| core.open_transfer_lanes()).unwrap();
    assert_eq!(open, 0, "a paused folder keeps upload workers");

    handle.call(|core| core.resume()).unwrap().unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        assert!(Instant::now() < deadline, "the upload did not finish");
        let asked = Instant::now();
        let snapshot = handle.call(|core| core.snapshot()).unwrap();
        let waited = asked.elapsed();
        assert!(
            waited < COMMAND_BOUND,
            "a command waited {waited:?} during the upload"
        );
        if snapshot.folders[0].status == FolderStatus::UpToDate {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let most = handle
        .call(|_| {
            SERVER.with(|s| {
                let s = s.borrow();
                let s = s.as_ref().unwrap().borrow();
                s.object_puts.values().copied().max().unwrap_or(0)
            })
        })
        .unwrap();
    assert_eq!(most, 1, "an object was uploaded twice");
}

/// Passes that only carry on a long upload read the account feed once per
/// `CONTINUATION_REFRESH_MS`, not once per slice: each read is a round trip on the engine
/// thread. A pass after a command still reads it at once.
#[test]
fn passes_that_carry_on_an_upload_read_the_feed_only_now_and_then() {
    const FILES: usize = 60;
    let world = World::new(SharedClock::at(START_MS));
    let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
    account_with_files(&world, &mut core, FILES);
    world.shared.borrow_mut().put_cost = Some(world.clock.cost(100, Duration::ZERO));
    core.tick();
    assert!(core.has_more_work());
    let feed = |world: &World| world.shared.borrow().feed_calls;
    let before = feed(&world);
    // Four slices of a second each: within the interval, no feed read.
    for _ in 0..4 {
        core.note_continuation();
        core.tick();
        assert!(core.has_more_work(), "the upload is still under way");
    }
    assert_eq!(feed(&world), before, "a continuation read the feed");
    // A pass that is no continuation (a command ran) reads it.
    core.tick();
    assert_eq!(feed(&world), before + 1);
    // Past the interval a continuation reads it again.
    world
        .clock
        .advance(hangar_drive_sync::engine::CONTINUATION_REFRESH_MS);
    core.note_continuation();
    core.tick();
    assert_eq!(feed(&world), before + 2);
    // The upload still finishes with every object sent once.
    for _ in 0..200 {
        core.note_continuation();
        core.tick();
        if !core.has_more_work() && folder_status(&core.snapshot()) == FolderStatus::UpToDate {
            let (most, _, _) =
                world.objects(&FolderId::from_hex(&core.snapshot().folders[0].id).unwrap());
            assert_eq!(most, 1, "an object was uploaded twice");
            return;
        }
    }
    panic!("the upload did not finish");
}

/// A pass yields to a waiting command before it starts a folder's round (scan, hashing,
/// downloads, uploads), and the next pass carries on; without a command it works as before.
#[test]
fn a_pass_yields_to_a_waiting_command_before_a_round() {
    const FILES: usize = 30;
    let world = World::new(SharedClock::at(START_MS));
    let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
    let folder = account_with_files(&world, &mut core, FILES);
    let waiting = core.interrupt().raise();
    core.tick();
    assert!(core.has_more_work(), "the yielded work is still due");
    assert_eq!(world.objects(&folder).1, 0, "nothing was uploaded");
    assert_eq!(world.shared.borrow().head(&folder), None);
    drop(waiting);
    for _ in 0..20 {
        core.tick();
        if !core.has_more_work() && folder_status(&core.snapshot()) == FolderStatus::UpToDate {
            assert!(world.shared.borrow().head(&folder).is_some());
            return;
        }
        world.clock.advance(1_000);
    }
    panic!("the folder did not get up to date");
}

/// Live progress: while the rounds of a long upload work, snapshots with fewer bytes left
/// arrive several times per second, not only once per pass, but no more than the throttle lets
/// through.
#[test]
fn progress_arrives_several_times_per_second_within_a_round() {
    const FILES: usize = 80;
    let (handle, events) = Engine::spawn(
        || {
            let world = World::new(SharedClock::at(START_MS));
            let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
            account_with_files(&world, &mut core, FILES);
            // Each upload takes 120 ms of real time and 50 ms of the budget: a pass of a second
            // takes about 20 uploads, some 600 ms with four workers.
            let uploads = world.shared.borrow_mut().enable_parallel_uploads();
            uploads.lock().delay = Duration::from_millis(120);
            world.shared.borrow_mut().put_cost = Some(world.clock.cost(50, Duration::ZERO));
            Ok(core)
        },
        Duration::from_secs(5),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    // Wait for the upload to start.
    loop {
        assert!(Instant::now() < deadline, "the upload did not start");
        if let Ok(BackendEvent::Snapshot { snapshot }) = events.recv_timeout(Duration::from_secs(5))
        {
            if matches!(folder_status(&snapshot), FolderStatus::Uploading { .. }) {
                break;
            }
        }
    }
    let window = Duration::from_secs(2);
    let started = Instant::now();
    let mut left = Vec::new();
    while started.elapsed() < window {
        if let Ok(BackendEvent::Snapshot { snapshot }) =
            events.recv_timeout(Duration::from_millis(100))
        {
            left.push(snapshot.sync.bytes_left);
        }
    }
    eprintln!("{} snapshots in {window:?}: {left:?}", left.len());
    assert!(left.len() >= 6, "too few progress snapshots: {left:?}");
    assert!(
        left.len() <= 20,
        "more snapshots than the throttle allows: {left:?}"
    );
    assert!(
        left.windows(2).all(|w| w[1] <= w[0]) && left.last() < left.first(),
        "bytes left go down: {left:?}"
    );
    drop(handle);
}
