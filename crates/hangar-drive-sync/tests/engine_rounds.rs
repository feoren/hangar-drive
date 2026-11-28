//! What a round costs when it has little to do (second performance review): a round cut at its
//! budget goes on uploading without asking the server about every object again (A), a large
//! upload commits the files complete so far as it goes (C), an idle folder is skipped and pulls
//! only when the change feed names a new head (F), a change on disk wakes the engine before its
//! pause ends (N), and chunks go up in the order of their files (H).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hangar_drive_protocol::ids::*;
use hangar_drive_sync::api::{ApiResult, BackendEvent, FolderStatus, StopReasonApi};
use hangar_drive_sync::engine::{Engine, EngineCore, EnginePorts, EngineSettings};
use hangar_drive_sync::memory::{
    MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedClock, SharedKeychain,
};
use hangar_drive_sync::ports::{FileSystem, ServerApi};

type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

const START_MS: i64 = 1_795_651_200_000;
const DOCS: &str = "mem:/a/Docs";

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
}

/// A new account with one folder of `files` small files of distinct content.
fn account_with_files(world: &World, core: &mut EngineCore, files: usize) -> FolderId {
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = core.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(core.confirm_recovery_group(&group).unwrap());
    let folder = core.add_folder(DOCS, "Docs").unwrap();
    let fs = world.disk(DOCS);
    for i in 0..files {
        assert!(fs.user_write(
            &[format!("file-{i:04}.txt")],
            format!("content of file {i}").as_bytes()
        ));
    }
    FolderId::from_hex(&folder).unwrap()
}

fn sync_up(world: &World, core: &mut EngineCore) {
    for _ in 0..200 {
        world.clock.advance(1_000);
        core.tick();
        if !core.has_more_work() && core.snapshot().folders[0].status == FolderStatus::UpToDate {
            return;
        }
    }
    panic!("the folder did not get up to date");
}

// A: a round cut at its budget goes on with its queue: the server is asked about each object
// about once (the first ask, the check of what the last round sent, the ask before the commit),
// not in every round, and no round pulls the folder's commits for nothing.
#[test]
fn a_cut_upload_goes_on_without_asking_about_every_object_again() {
    const FILES: usize = 60;
    let world = World::new(SharedClock::at(START_MS));
    let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
    account_with_files(&world, &mut core, FILES);
    world.shared.borrow_mut().put_cost = Some(world.clock.cost(100, Duration::ZERO));
    let pages_before = world.shared.borrow().delta_pages;
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
    let s = world.shared.borrow();
    let objects = s.object_puts.len() as u64;
    assert!(passes > 5, "the upload took several passes: {passes}");
    assert_eq!(
        s.object_puts.values().max(),
        Some(&1),
        "an object went up twice"
    );
    assert!(
        s.missing_ids <= 3 * objects + 10,
        "asked about {} IDs for {objects} objects in {passes} passes",
        s.missing_ids
    );
    assert!(
        s.delta_pages - pages_before <= 2,
        "{} delta pulls during the upload",
        s.delta_pages - pages_before
    );
}

// F: an idle folder costs the change feed only: no pull, no scan, no save.
#[test]
fn an_idle_folder_costs_only_the_feed() {
    let world = World::new(SharedClock::at(START_MS));
    let store = MemStore::new();
    let mut core = world.device(1, &SharedKeychain::default(), &store);
    account_with_files(&world, &mut core, 20);
    sync_up(&world, &mut core);
    world.clock.advance(5_000);
    core.tick();
    let (calls, pages, saves) = {
        let s = world.shared.borrow();
        (s.calls, s.delta_pages, store.saves())
    };
    for _ in 0..20 {
        world.clock.advance(5_000);
        core.tick();
    }
    let s = world.shared.borrow();
    assert_eq!(s.delta_pages, pages, "an idle folder pulled");
    assert_eq!(store.saves(), saves, "an idle folder was saved");
    assert!(
        s.calls - calls <= 20,
        "{} server calls in 20 idle passes",
        s.calls - calls
    );
    drop(s);
    assert_eq!(core.snapshot().folders[0].status, FolderStatus::UpToDate);
    assert!(core.snapshot().sync.last_sync.is_some());
}

fn older_state(core: &EngineCore) -> bool {
    core.snapshot().folders[0].status
        == FolderStatus::Stopped {
            reason: StopReasonApi::OlderState,
        }
}

/// A folder with two commits, synced and idle.
fn two_commits() -> (World, EngineCore, FolderId) {
    let world = World::new(SharedClock::at(START_MS));
    let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
    let folder = account_with_files(&world, &mut core, 5);
    sync_up(&world, &mut core);
    world
        .disk(DOCS)
        .user_write(&["late.txt".to_owned()], b"late");
    sync_up(&world, &mut core);
    assert_eq!(world.shared.borrow().folder_sequence(&folder), 2);
    (world, core, folder)
}

// F: a head the change feed reports is pulled in the next pass (here an older state, which the
// pull notices and stops the folder for).
#[test]
fn a_head_the_feed_reports_is_pulled_in_the_next_pass() {
    let (world, mut core, folder) = two_commits();
    world.shared.borrow_mut().rewind_folder(&folder, 1);
    world.clock.advance(5_000);
    core.tick();
    assert!(older_state(&core), "the reported head was not pulled");
}

// F: a head the feed never reports is still pulled within the hour.
#[test]
fn a_head_the_feed_missed_is_pulled_within_the_hour() {
    let (world, mut core, folder) = two_commits();
    {
        let mut s = world.shared.borrow_mut();
        let first: Vec<_> = s
            .folder_commits(&folder)
            .into_iter()
            .filter(|c| c.sequence <= 1)
            .collect();
        s.set_folder_commits(&folder, first);
    }
    for _ in 0..5 {
        world.clock.advance(5_000);
        core.tick();
    }
    assert!(!older_state(&core), "pulled without a feed entry");
    world
        .clock
        .advance(hangar_drive_sync::engine::FULL_SCAN_INTERVAL_MS);
    core.tick();
    assert!(older_state(&core), "the hourly pull did not run");
}

thread_local! {
    static SERVER: RefCell<Option<Rc<RefCell<ServerState>>>> = const { RefCell::new(None) };
}

// N: a file written while the loop waits for its pause is synced well before the pause ends.
#[test]
fn a_change_on_disk_wakes_the_engine_before_its_pause() {
    let disk = Arc::new(MemFs::new(true));
    let engine_disk = Arc::clone(&disk);
    let clock = SharedClock::at(START_MS);
    let engine_clock = clock.clone();
    let (handle, events) = Engine::spawn(
        move || {
            let world = World::new(engine_clock);
            world
                .disks
                .borrow_mut()
                .insert(PathBuf::from(DOCS), engine_disk);
            let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
            account_with_files(&world, &mut core, 3);
            SERVER.with(|s| *s.borrow_mut() = Some(Rc::clone(&world.shared)));
            Ok(core)
        },
        // Far longer than the test waits.
        Duration::from_secs(120),
    )
    .unwrap();
    let up_to_date = |deadline: Duration, files: u64| {
        let until = Instant::now() + deadline;
        while Instant::now() < until {
            if let Ok(BackendEvent::Snapshot { snapshot }) =
                events.recv_timeout(Duration::from_millis(100))
            {
                let f = &snapshot.folders[0];
                if f.status == FolderStatus::UpToDate && f.file_count == Some(files) {
                    return true;
                }
            }
        }
        false
    };
    // A command runs a pass: the first upload.
    handle.call(|_| ()).unwrap();
    assert!(up_to_date(Duration::from_secs(20), 3), "the first upload");
    // Time passes as it would between edits (the manual clock does not move by itself), so the
    // publish interval after the first upload is over.
    clock.advance(hangar_drive_sync::folder::PUBLISH_INTERVAL_MS);
    let written = Instant::now();
    assert!(disk.user_write(&["new.txt".to_owned()], b"new"));
    assert!(
        up_to_date(Duration::from_secs(10), 4),
        "the new file was not synced before the loop's pause"
    );
    let took = written.elapsed();
    assert!(took >= Duration::from_millis(300), "debounced: {took:?}");
    let heads = handle
        .call(|_| {
            SERVER.with(|s| {
                let s = s.borrow();
                let s = s.as_ref().unwrap().borrow();
                s.object_puts.len()
            })
        })
        .unwrap();
    assert!(heads > 0);
}

// Security review of the client changes, MEDIUM 1: a file rewritten every half second (a log,
// a database) makes at most one commit per publish interval, while the first change after a
// quiet spell goes out in its own pass.
#[test]
fn a_file_rewritten_all_the_time_makes_few_commits() {
    let world = World::new(SharedClock::at(START_MS));
    let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
    let folder = account_with_files(&world, &mut core, 3);
    sync_up(&world, &mut core);
    world.clock.advance(60_000);
    core.tick();
    let sequence = |world: &World| world.shared.borrow().folder_sequence(&folder);
    let before = sequence(&world);
    let disk = world.disk(DOCS);
    let log = vec!["app.log".to_owned()];
    assert!(disk.user_write(&log, b"line 0"));
    core.tick();
    assert_eq!(
        sequence(&world),
        before + 1,
        "the first change waits for nothing"
    );
    for i in 1..60 {
        assert!(disk.user_write(&log, format!("line {i}").as_bytes()));
        world.clock.advance(500);
        core.tick();
    }
    let made = sequence(&world) - before;
    // A burst of three, then one per five seconds.
    assert!(made <= 9, "{made} commits in 30 s of changes");
    // The last version goes out once its time has come.
    world
        .clock
        .advance(hangar_drive_sync::folder::PUBLISH_INTERVAL_MS);
    core.tick();
    core.tick();
    assert_eq!(core.snapshot().folders[0].status, FolderStatus::UpToDate);
    assert_eq!(world.disk(DOCS).read_all(&log).unwrap(), b"line 59");
}

// MEDIUM 1: the commits of all folders of the device stay within its budget per minute, well
// below the server's limit of 30.
#[test]
fn the_folders_of_a_device_share_one_commit_budget() {
    let world = World::new(SharedClock::at(START_MS));
    let mut core = world.device(1, &SharedKeychain::default(), &MemStore::new());
    let first = account_with_files(&world, &mut core, 1);
    let mut folders = vec![(first, DOCS.to_owned())];
    for name in ["B", "C", "D"] {
        let path = format!("mem:/a/{name}");
        let id = core.add_folder(&path, name).unwrap();
        folders.push((FolderId::from_hex(&id).unwrap(), path));
    }
    for _ in 0..5 {
        world.clock.advance(1_000);
        core.tick();
    }
    world.clock.advance(120_000);
    core.tick();
    let total = |world: &World| -> u64 {
        let s = world.shared.borrow();
        folders.iter().map(|(id, _)| s.folder_sequence(id)).sum()
    };
    let before = total(&world);
    let log = vec!["app.log".to_owned()];
    for i in 0..60 {
        for (_, path) in &folders {
            assert!(world
                .disk(path)
                .user_write(&log, format!("line {i}").as_bytes()));
        }
        world.clock.advance(1_000);
        core.tick();
    }
    let made = total(&world) - before;
    assert!(
        (10..=u64::from(hangar_drive_sync::engine::DEVICE_COMMITS_PER_MINUTE)).contains(&made),
        "{made} commits of four folders in one minute"
    );
}

/// Rounds of one folder on two devices without the engine.
mod rounds {
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::rc::Rc;
    use std::time::Duration;

    use hangar_drive_crypto::devicelog::LogDevice;
    use hangar_drive_crypto::identity::DeviceIdentity;
    use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken, ObjectId};
    use hangar_drive_sync::account::Account;
    use hangar_drive_sync::chunker::DynEntropy;
    use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync, RoundReport};
    use hangar_drive_sync::memory::{
        MemFs, MemKeychain, MemServer, MemStore, SeededRandom, ServerState, SharedClock,
    };
    use hangar_drive_sync::ports::{Clock, Store};

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

    fn round(d: &mut Dev, clock: &SharedClock, settings: &FolderSettings) -> RoundReport {
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
            settings,
        };
        d.folder.round(&mut cx).unwrap()
    }

    fn files(fs: &MemFs) -> Vec<(String, Vec<u8>)> {
        fs.snapshot()
            .into_iter()
            .filter(|(k, _)| !k[0].starts_with('.'))
            .filter_map(|(k, v)| v.map(|v| (k.join("/"), v)))
            .collect()
    }

    /// Settings of a budgeted round whose upload commits every eight small files.
    fn staged() -> FolderSettings {
        FolderSettings {
            hash_threads: 1,
            work_budget_ms: Some(1_000),
            stage_bytes: 8 * 1_000,
            stage_interval_ms: 0,
            ..FolderSettings::default()
        }
    }

    fn whole() -> FolderSettings {
        FolderSettings {
            hash_threads: 1,
            ..FolderSettings::default()
        }
    }

    const FILES: usize = 40;

    fn write_files(fs: &MemFs) {
        for i in 0..FILES {
            let body = format!("{i:04}").repeat(250);
            fs.user_write(&[format!("f{i:02}.txt")], body.as_bytes());
        }
    }

    // C: a large first upload commits the files complete so far as it goes, so the other
    // device sees a part of them long before the end; every stage is a whole tree, and every
    // object goes up once.
    #[test]
    fn a_large_upload_commits_as_it_goes_and_the_other_device_sees_a_part() {
        let clock = SharedClock::at(1_795_651_200_000);
        let (server, mut d0, mut d1) = setup(&clock);
        write_files(&d0.fs);
        server.borrow_mut().put_cost = Some(clock.cost(100, Duration::ZERO));
        let mut partial = BTreeSet::new();
        let mut rounds = 0;
        loop {
            let report = round(&mut d0, &clock, &staged());
            clock.advance(1_000);
            round(&mut d1, &clock, &whole());
            let seen = files(&d1.fs).len();
            if seen > 0 && seen < FILES {
                partial.insert(seen);
            }
            rounds += 1;
            if !report.more && d0.folder.in_sync() {
                break;
            }
            assert!(rounds < 200, "the upload did not finish");
        }
        round(&mut d1, &clock, &whole());
        let commits = server.borrow().folder_sequence(&FOLDER);
        assert!(commits >= 3, "intermediate commits: {commits}");
        assert!(
            partial.len() >= 2,
            "the other device saw the upload grow: {partial:?}"
        );
        assert_eq!(files(&d0.fs), files(&d1.fs));
        assert_eq!(files(&d1.fs).len(), FILES);
        assert_eq!(server.borrow().object_puts.values().max(), Some(&1));
    }

    // C: an app that ends after an intermediate commit goes on from the stored state: no
    // conflict copy of a file the commit already holds, nothing uploaded twice.
    #[test]
    fn a_restart_after_an_intermediate_commit_goes_on() {
        let clock = SharedClock::at(1_795_651_200_000);
        let (server, mut d0, mut d1) = setup(&clock);
        write_files(&d0.fs);
        server.borrow_mut().put_cost = Some(clock.cost(100, Duration::ZERO));
        let mut rounds = 0;
        while server.borrow().folder_sequence(&FOLDER) == 0 {
            let report = round(&mut d0, &clock, &staged());
            assert!(
                report.more,
                "the upload is not finished at its first commit"
            );
            clock.advance(1_000);
            rounds += 1;
            assert!(rounds < 50, "no intermediate commit");
        }
        // The app ends and starts again with the same index.
        d0.folder = FolderSync::load(&d0.account, FOLDER, &d0.store)
            .unwrap()
            .unwrap();
        loop {
            let report = round(&mut d0, &clock, &staged());
            clock.advance(1_000);
            rounds += 1;
            if !report.more && d0.folder.in_sync() {
                break;
            }
            assert!(rounds < 200, "the upload did not finish");
        }
        round(&mut d1, &clock, &whole());
        assert_eq!(files(&d0.fs).len(), FILES, "no conflict copies");
        assert_eq!(files(&d0.fs), files(&d1.fs));
        assert_eq!(server.borrow().object_puts.values().max(), Some(&1));
    }

    // H: chunks go up in the order of their files' paths and, within a file, of their index,
    // so the disk is read from front to back, not in the random order of the object IDs.
    #[test]
    fn chunks_go_up_in_path_and_chunk_order() {
        let clock = SharedClock::at(1_795_651_200_000);
        let (server, mut d0, _d1) = setup(&clock);
        let chunk = hangar_drive_protocol::object::CHUNK_SIZE as usize;
        d0.fs.user_mkdir(&["m".to_owned()]);
        for name in [
            "z.txt", "b.txt", "m/k.txt", "a.txt", "q.txt", "c.txt", "m/a.txt",
        ] {
            let path: Vec<String> = name.split('/').map(str::to_owned).collect();
            d0.fs.user_write(&path, format!("small {name}").as_bytes());
        }
        let mut large = vec![1u8; chunk + 100];
        large[chunk] = 2;
        d0.fs.user_write(&["k.bin".to_owned()], &large);
        round(&mut d0, &clock, &whole());
        let tree = d0.folder.local().clone();
        let mut expected: Vec<(Vec<String>, usize, ObjectId)> = Vec::new();
        for (id, node) in tree.iter() {
            let Some(v) = node.kind.file() else {
                continue;
            };
            let list = d0.store.chunk_list(&FOLDER, &v.content).unwrap().unwrap();
            for (index, c) in list.chunks.iter().enumerate() {
                expected.push((tree.path(id).unwrap(), index, *c));
            }
        }
        expected.sort();
        let want: Vec<ObjectId> = expected.iter().map(|(_, _, c)| *c).collect();
        let chunks: BTreeSet<ObjectId> = want.iter().copied().collect();
        let sent: Vec<ObjectId> = server
            .borrow()
            .put_log
            .iter()
            .filter(|id| chunks.contains(id))
            .copied()
            .collect();
        assert_eq!(want.len(), 9);
        assert_eq!(sent, want);
    }

    // Security review of the client changes, LOW 3: files that wait for their hash are hashed
    // first, so a folder that keeps changing in front of them (in path order) cannot starve
    // them.
    #[test]
    fn files_waiting_for_their_hash_are_not_starved_by_constant_changes() {
        let clock = SharedClock::at(1_795_651_200_000);
        let (_server, mut d0, _d1) = setup(&clock);
        for i in 0..60 {
            d0.fs
                .user_write(&[format!("f{i:03}.txt")], format!("waiting {i}").as_bytes());
        }
        d0.fs.set_read_cost(Some(clock.cost(50, Duration::ZERO)));
        let settings = FolderSettings {
            hash_threads: 1,
            work_budget_ms: Some(1_000),
            ..FolderSettings::default()
        };
        let waiting_in_tree = |d: &Dev| {
            d.folder
                .local()
                .iter()
                .filter(|(_, n)| n.name.starts_with('f'))
                .count()
        };
        for round_no in 0..30 {
            // Forty files in front of the waiting ones change before every round.
            for i in 0..40 {
                d0.fs.user_write(
                    &[format!("a{i:03}.txt")],
                    format!("churn {round_no} {i}").as_bytes(),
                );
            }
            round(&mut d0, &clock, &settings);
            clock.advance(1_000);
        }
        assert_eq!(
            waiting_in_tree(&d0),
            60,
            "files waiting for their hash starved"
        );
    }
}
