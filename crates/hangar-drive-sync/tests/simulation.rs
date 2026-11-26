//! Seeded simulation of the sync engine, after Dropbox Nucleus' CanopyCheck and Trinity
//! (ADR 0001, section 3).
//!
//! Several devices share one in-memory server. A seed drives random file operations of the
//! people on every device, sync rounds, server outages, lost commit replies, device restarts
//! (state reloaded from the local index and the keychain) and the clock. After the random
//! phase the world quiesces: the server comes back and every device syncs until nothing
//! changes. Invariants:
//!
//! - **no panics** (the test would fail);
//! - **termination:** the quiet phase converges within a bounded number of rounds;
//! - **convergence:** every device's disk, remote, synced and local tree agree, and agree with
//!   the server's head;
//! - **no data loss:** every content a person wrote and did not overwrite or delete on that
//!   same device is on every disk at the end; nothing appears that nobody wrote.
//!
//! `cargo test` runs a fixed set of seeds. More seeds: `HANGAR_DRIVE_SIM_SEEDS=5000 cargo test
//! --release --test simulation`; one seed: `HANGAR_DRIVE_SIM_SEED=1234`.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderState, FolderSync};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom, ServerState,
};
use hangar_drive_sync::ports::{Clock, ServerApi};

const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
const FOLDER: FolderId = FolderId::from_bytes([0xf0; 16]);

struct Device {
    name: String,
    id: DeviceId,
    fs: MemFs,
    store: MemStore,
    keychain: MemKeychain,
    server: MemServer,
    account: Option<Account>,
    folder: Option<FolderSync>,
    rng: SeededRandom,
}

struct World {
    seed: u64,
    rng: SeededRandom,
    clock: ManualClock,
    server: Rc<RefCell<ServerState>>,
    devices: Vec<Device>,
    settings: FolderSettings,
    required: BTreeSet<Vec<u8>>,
    written: BTreeSet<Vec<u8>>,
    counter: u64,
    log: Vec<String>,
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

const NAMES: [&str; 9] = [
    "a.txt",
    "b.txt",
    "A.TXT",
    "notes.md",
    "\u{e9}.txt",
    "e\u{301}.txt",
    "dir1",
    "Dir1",
    "sub",
];

impl World {
    fn new(seed: u64, devices: usize) -> World {
        let mut rng = SeededRandom::new(seed);
        let clock = ManualClock::at(1_795_651_200_000);
        let server = MemServer::new_shared();
        let settings = FolderSettings {
            hash_threads: 1,
            ..FolderSettings::default()
        };
        let mut list = Vec::new();
        for i in 0..devices {
            let id = DeviceId::from_bytes([i as u8 + 1; 16]);
            list.push(Device {
                name: format!("Dev{i}"),
                id,
                // Even devices behave like Windows and macOS, odd ones like Linux.
                fs: MemFs::new(i % 2 == 0),
                store: MemStore::new(),
                keychain: MemKeychain::default(),
                server: MemServer::connect(&server, id),
                account: None,
                folder: None,
                rng: SeededRandom::new(rng.next_u64()),
            });
        }
        let mut world = World {
            seed,
            rng,
            clock,
            server,
            devices: list,
            settings,
            required: BTreeSet::new(),
            written: BTreeSet::new(),
            counter: 0,
            log: Vec::new(),
        };
        world.setup();
        world
    }

    fn setup(&mut self) {
        let now = self.clock.now_ms() as u64;
        let first = &mut self.devices[0];
        let mut account = Account::create(
            &mut first.server,
            &mut first.keychain,
            &mut first.store,
            &mut first.rng,
            now,
            InviteToken::from_bytes([9; 16]),
            ACCOUNT,
            first.id,
            &first.name,
            None,
        )
        .expect("create account");
        account
            .create_folder(
                &mut first.server,
                &mut first.store,
                FOLDER,
                "Docs",
                &mut first.rng,
            )
            .expect("create folder");
        let mut identities = Vec::new();
        for i in 1..self.devices.len() {
            let identity =
                DeviceIdentity::generate(&mut DynEntropy(&mut self.devices[i].rng)).expect("id");
            let device = LogDevice::of(&identity, &ACCOUNT, self.devices[i].id, false);
            let name = self.devices[i].name.clone();
            let first = &mut self.devices[0];
            account
                .add_device(
                    &mut first.server,
                    &mut first.store,
                    device,
                    &name,
                    now,
                    &mut first.rng,
                )
                .expect("add device");
            identities.push(identity);
        }
        self.devices[0].account = Some(account);
        for (i, identity) in identities.into_iter().enumerate() {
            let d = &mut self.devices[i + 1];
            let account = Account::join(
                &mut d.server,
                &mut d.keychain,
                &mut d.store,
                identity,
                ACCOUNT,
                d.id,
                &d.name.clone(),
                None,
            )
            .expect("join");
            d.account = Some(account);
        }
        for d in &mut self.devices {
            let account = d.account.as_mut().expect("account");
            account
                .refresh(&mut d.server, &mut d.keychain, &mut d.store)
                .expect("refresh");
            let folder = FolderSync::new(account, FOLDER, "Docs");
            folder.write_marker(&d.fs).expect("marker");
            d.folder = Some(folder);
        }
    }

    fn note(&mut self, line: String) {
        self.log.push(line);
    }

    fn dump(&self) -> String {
        let mut out = format!(
            "server head {:?} seq {}
",
            self.server.borrow().head(&FOLDER),
            self.server.borrow().folder_sequence(&FOLDER)
        );
        for (i, d) in self.devices.iter().enumerate() {
            let f = d.folder.as_ref().expect("folder");
            let paths = |t: &hangar_drive_sync::tree::Tree| {
                let mut v: Vec<String> = t
                    .iter()
                    .map(|(id, n)| {
                        format!(
                            "{}{} {:?}",
                            t.path_string(id).unwrap_or_default(),
                            if n.is_dir() { "/" } else { "" },
                            &id.to_hex()[..4]
                        )
                    })
                    .collect();
                v.sort();
                v
            };
            out.push_str(&format!(
                "dev{i}: frontier {:?} in_sync {} state {:?}
 disk {:?}
 remote {:?}
 synced {:?}
 local {:?}
 cannot {:?} held {:?}
",
                f.view().frontier(),
                f.in_sync(),
                f.state(),
                d.fs.snapshot().keys().collect::<Vec<_>>(),
                paths(f.remote()),
                paths(f.synced()),
                paths(f.local()),
                f.meta().cannot_sync,
                f.meta().held,
            ));
        }
        out
    }

    fn fail(&self, what: &str) -> ! {
        eprintln!("{}", self.dump());
        let keep = if std::env::var("HANGAR_DRIVE_SIM_FULL_LOG").is_ok() {
            usize::MAX
        } else {
            40
        };
        let tail: Vec<&String> = self.log.iter().rev().take(keep).collect();
        panic!(
            "seed {}: {what}\nlast steps (newest first):\n{}",
            self.seed,
            tail.iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    fn content(&mut self, device: usize) -> Vec<u8> {
        self.counter += 1;
        let c = format!("content {} from {device} seed {}", self.counter, self.seed).into_bytes();
        self.written.insert(c.clone());
        c
    }

    /// Contents below `path` on a device's disk.
    fn contents_below(fs: &MemFs, path: &[String]) -> Vec<Vec<u8>> {
        let key = |p: &[String]| -> Vec<String> {
            p.iter()
                .map(|n| hangar_drive_protocol::name::case_key(n))
                .collect()
        };
        let target = key(path);
        fs.snapshot()
            .into_iter()
            .filter(|(k, _)| key(k).starts_with(&target))
            .filter_map(|(_, v)| v)
            .collect()
    }

    fn random_path(&mut self, device: usize) -> Option<Vec<String>> {
        let snap = self.devices[device].fs.snapshot();
        if snap.is_empty() {
            return None;
        }
        let i = self.rng.below(snap.len() as u64) as usize;
        snap.keys().nth(i).cloned()
    }

    fn random_dir(&mut self, device: usize) -> Vec<String> {
        let dirs: Vec<Vec<String>> = self.devices[device]
            .fs
            .snapshot()
            .into_iter()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k)
            .filter(|k| k.len() < 3)
            .collect();
        if dirs.is_empty() || self.rng.chance(40) {
            return Vec::new();
        }
        let i = self.rng.below(dirs.len() as u64) as usize;
        dirs[i].clone()
    }

    fn random_name(&mut self) -> String {
        NAMES[self.rng.below(NAMES.len() as u64) as usize].to_owned()
    }

    fn user_op(&mut self, device: usize) {
        let choice = self.rng.below(100);
        match choice {
            0..=34 => {
                // Write a new or existing file.
                let mut path = self.random_dir(device);
                path.push(self.random_name());
                let fs = &self.devices[device].fs;
                let old = fs.read_all(&path);
                let data = self.content(device);
                if self.devices[device].fs.user_write(&path, &data) {
                    if let Some(old) = old {
                        self.required.remove(&old);
                    }
                    self.required.insert(data);
                    let n = self.counter;
                    self.note(format!("dev{device} write {path:?} c{n}"));
                }
            }
            35..=54 => {
                // Edit an existing file.
                if let Some(path) = self.random_path(device) {
                    if let Some(old) = self.devices[device].fs.read_all(&path) {
                        let data = self.content(device);
                        if self.devices[device].fs.user_write(&path, &data) {
                            self.required.remove(&old);
                            self.required.insert(data);
                            let n = self.counter;
                            self.note(format!("dev{device} edit {path:?} c{n}"));
                        }
                    }
                }
            }
            55..=69 => {
                if let Some(from) = self.random_path(device) {
                    let mut to = self.random_dir(device);
                    to.push(self.random_name());
                    if self.devices[device].fs.user_rename(&from, &to) {
                        self.note(format!("dev{device} move {from:?} -> {to:?}"));
                    }
                }
            }
            70..=84 => {
                if let Some(path) = self.random_path(device) {
                    let gone = Self::contents_below(&self.devices[device].fs, &path);
                    if self.devices[device].fs.user_delete(&path) {
                        for c in gone {
                            self.required.remove(&c);
                        }
                        self.note(format!("dev{device} delete {path:?}"));
                    }
                }
            }
            _ => {
                let mut path = self.random_dir(device);
                path.push(self.random_name());
                if self.devices[device].fs.user_mkdir(&path) {
                    self.note(format!("dev{device} mkdir {path:?}"));
                }
            }
        }
    }

    fn sync(&mut self, device: usize) {
        let settings = self.settings.clone();
        let clock = self.clock.clone();
        let d = &mut self.devices[device];
        let (Some(account), Some(folder)) = (d.account.as_mut(), d.folder.as_mut()) else {
            return;
        };
        // The watcher: usually every change, sometimes an overflow that forces a full scan,
        // and now and then the hourly full scan.
        let events = d.fs.take_events();
        match d.rng.below(100) {
            0..=4 => folder.request_full_scan(),
            _ => folder.note_changes(events),
        }
        match account.refresh(&mut d.server, &mut d.keychain, &mut d.store) {
            Ok(_) => {}
            Err(e) if e.is_offline() => return,
            Err(e) => {
                let msg = format!("dev{device} refresh failed: {e}");
                self.fail(&msg);
            }
        }
        let mut cx = Ctx {
            account,
            server: &mut d.server,
            keychain: &mut d.keychain,
            fs: &d.fs,
            store: &mut d.store,
            clock: &clock,
            entropy: &mut d.rng,
            settings: &settings,
        };
        match folder.round(&mut cx) {
            Ok(r) => {
                let line = format!(
                    "dev{device} round: pulled {} published {} applied {} failed {:?} offline {} copies {}",
                    r.pulled,
                    r.published,
                    r.applied,
                    r.failed,
                    r.offline,
                    r.copies.len()
                );
                self.note(line);
                if std::env::var("HANGAR_DRIVE_SIM_TRACE").is_ok() {
                    let dump = self.dump();
                    self.note(dump);
                }
            }
            Err(e) => {
                let msg = format!("dev{device} round failed: {e:?}");
                self.fail(&msg);
            }
        }
        if let Some(f) = self.devices[device].folder.as_ref() {
            if f.state() != FolderState::Active {
                let msg = format!("dev{device} folder stopped: {:?}", f.state());
                self.fail(&msg);
            }
        }
    }

    fn restart(&mut self, device: usize) {
        let d = &mut self.devices[device];
        d.account = None;
        d.folder = None;
        let account = Account::load(&d.store, &d.keychain)
            .expect("load account")
            .expect("account stored");
        let folder = FolderSync::load(&account, FOLDER, &d.store)
            .expect("load folder")
            .unwrap_or_else(|| FolderSync::new(&account, FOLDER, "Docs"));
        d.account = Some(account);
        d.folder = Some(folder);
        self.note(format!("dev{device} restart"));
    }

    fn random_phase(&mut self, steps: usize) {
        for _ in 0..steps {
            let device = self.rng.below(self.devices.len() as u64) as usize;
            match self.rng.below(100) {
                0..=44 => self.user_op(device),
                45..=84 => self.sync(device),
                85..=89 => {
                    let mut s = self.server.borrow_mut();
                    s.online = !s.online;
                    let online = s.online;
                    drop(s);
                    self.note(format!("server online {online}"));
                }
                90..=92 => {
                    self.server.borrow_mut().lose_next_commit_reply = true;
                    self.note("server loses next commit reply".into());
                }
                93..=95 => self.restart(device),
                96 => {
                    let size = 1 + self.rng.below(3) as usize;
                    self.server.borrow_mut().page_size = size;
                }
                _ => {
                    let ms = self.rng.below(30_000) as i64;
                    self.clock.advance(ms);
                }
            }
        }
    }

    fn quiesce(&mut self) -> usize {
        {
            let mut s = self.server.borrow_mut();
            s.online = true;
            s.lose_next_commit_reply = false;
        }
        let n = self.devices.len();
        for round in 0..40 {
            self.clock.advance(20_000);
            for device in 0..n {
                self.sync(device);
            }
            if self.converged() {
                return round;
            }
        }
        self.fail("no convergence after 40 quiet rounds")
    }

    fn converged(&self) -> bool {
        let first = self.devices[0].fs.snapshot();
        let head_root = self.devices[0]
            .folder
            .as_ref()
            .and_then(|f| f.meta().remote_root);
        self.devices.iter().all(|d| {
            let f = d.folder.as_ref().expect("folder");
            f.in_sync() && d.fs.snapshot() == first && f.meta().remote_root == head_root
        })
    }

    fn check(&self) {
        let snap = self.devices[0].fs.snapshot();
        let contents: BTreeSet<Vec<u8>> = snap.values().flatten().cloned().collect();
        for c in &self.required {
            if !contents.contains(c) {
                self.fail(&format!(
                    "data loss: {:?} is on no disk",
                    String::from_utf8_lossy(c)
                ));
            }
        }
        for c in &contents {
            if !self.written.contains(c) {
                self.fail(&format!("unknown content {:?}", String::from_utf8_lossy(c)));
            }
        }
        // The server holds the same tree.
        let head = self.server.borrow().head(&FOLDER);
        let frontier = self.devices[0]
            .folder
            .as_ref()
            .and_then(|f| f.view().frontier().map(|e| e.commit));
        if head != frontier {
            self.fail("the server head is not the devices' frontier");
        }
    }
}

fn run(seed: u64) {
    let mut rng = SeededRandom::new(seed ^ 0x5eed);
    let devices = 2 + rng.below(2) as usize;
    let steps = 40 + rng.below(80) as usize;
    let mut world = World::new(seed, devices);
    world.random_phase(steps);
    world.quiesce();
    world.check();
    // A second burst after convergence, with restarts, must converge again.
    world.random_phase(steps / 2);
    world.quiesce();
    world.check();
}

fn seeds() -> Vec<u64> {
    if let Ok(one) = std::env::var("HANGAR_DRIVE_SIM_SEED") {
        if let Ok(seed) = one.parse() {
            return vec![seed];
        }
    }
    let count = std::env::var("HANGAR_DRIVE_SIM_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24u64);
    (1..=count).collect()
}

#[test]
fn seeded_simulation_converges_without_data_loss() {
    for seed in seeds() {
        run(seed);
    }
}

#[test]
fn two_devices_edit_the_same_file_and_both_versions_survive() {
    let mut w = World::new(1000, 2);
    assert!(w.devices[0].fs.user_write(&p(&["plan.txt"]), b"base"));
    w.written.insert(b"base".to_vec());
    w.sync(0);
    w.sync(1);
    assert_eq!(
        w.devices[1].fs.read_all(&p(&["plan.txt"])).unwrap(),
        b"base"
    );
    w.devices[0].fs.user_write(&p(&["plan.txt"]), b"from zero");
    w.devices[1].fs.user_write(&p(&["plan.txt"]), b"from one");
    w.written.insert(b"from zero".to_vec());
    w.written.insert(b"from one".to_vec());
    w.required.insert(b"from zero".to_vec());
    w.required.insert(b"from one".to_vec());
    w.sync(0);
    w.sync(1);
    w.quiesce();
    w.check();
    let snap = w.devices[0].fs.snapshot();
    // The version that reached the server first keeps the name.
    assert_eq!(
        snap.get(&p(&["plan.txt"])).unwrap().as_deref(),
        Some(&b"from zero"[..])
    );
    assert!(snap
        .keys()
        .any(|k| k[0] == "plan (conflict Dev1 2026-11-26).txt"));
}

#[test]
fn a_deleted_root_marker_stops_the_folder_instead_of_deleting() {
    let mut w = World::new(1001, 2);
    w.devices[0].fs.user_write(&p(&["keep.txt"]), b"k");
    w.sync(0);
    w.sync(1);
    // The person deletes the reserved directory (and so the marker) on device 1, then all files.
    w.devices[1].fs.user_delete(&p(&[".hangar-drive"]));
    w.devices[1].fs.user_delete(&p(&["keep.txt"]));
    let d = &mut w.devices[1];
    let settings = w.settings.clone();
    let clock = w.clock.clone();
    let mut cx = Ctx {
        account: d.account.as_mut().unwrap(),
        server: &mut d.server,
        keychain: &mut d.keychain,
        fs: &d.fs,
        store: &mut d.store,
        clock: &clock,
        entropy: &mut d.rng,
        settings: &settings,
    };
    d.folder.as_mut().unwrap().round(&mut cx).unwrap();
    assert!(matches!(
        d.folder.as_ref().unwrap().state(),
        FolderState::Stopped(_)
    ));
    // Nothing was deleted on the server.
    w.sync(0);
    assert_eq!(w.devices[0].fs.read_all(&p(&["keep.txt"])).unwrap(), b"k");
}

#[test]
fn many_deletes_are_held_until_the_person_decides() {
    let mut w = World::new(1002, 2);
    for i in 0..120 {
        w.devices[0]
            .fs
            .user_write(&p(&[&format!("f{i}.txt")]), format!("{i}").as_bytes());
    }
    w.sync(0);
    w.sync(1);
    for i in 0..120 {
        w.devices[1].fs.user_delete(&p(&[&format!("f{i}.txt")]));
    }
    w.sync(1);
    w.clock.advance(60_000);
    w.sync(1);
    w.sync(0);
    assert!(
        w.devices[0].fs.read_all(&p(&["f5.txt"])).is_some(),
        "held, not propagated"
    );
    let d = &mut w.devices[1];
    let held = d.folder.as_ref().unwrap().meta().held.len();
    assert_eq!(held, 120);
    // "Restore": the files come back on device 1.
    d.folder
        .as_mut()
        .unwrap()
        .resolve_held(true, &mut d.store)
        .unwrap();
    w.sync(1);
    assert!(w.devices[1].fs.read_all(&p(&["f5.txt"])).is_some());
}

#[test]
fn the_server_rewound_to_an_older_state_is_detected_and_reanchored() {
    let mut w = World::new(1003, 2);
    w.devices[0].fs.user_write(&p(&["x.txt"]), b"one");
    w.sync(0);
    let old = w.server.borrow().folder_sequence(&FOLDER);
    w.devices[0].fs.user_write(&p(&["y.txt"]), b"two");
    w.sync(0);
    w.sync(1);
    // The operator restores an old backup of the server.
    w.server.borrow_mut().rewind_folder(&FOLDER, old);
    let d = &mut w.devices[1];
    let settings = w.settings.clone();
    let clock = w.clock.clone();
    {
        let mut cx = Ctx {
            account: d.account.as_mut().unwrap(),
            server: &mut d.server,
            keychain: &mut d.keychain,
            fs: &d.fs,
            store: &mut d.store,
            clock: &clock,
            entropy: &mut d.rng,
            settings: &settings,
        };
        d.folder.as_mut().unwrap().round(&mut cx).unwrap();
        assert!(matches!(
            d.folder.as_ref().unwrap().state(),
            FolderState::Stopped(hangar_drive_sync::folder::StopReason::OlderState)
        ));
        // The person confirms the re-anchor.
        d.folder.as_mut().unwrap().reanchor(&mut cx).unwrap();
    }
    w.sync(1);
    assert_eq!(w.devices[1].fs.read_all(&p(&["y.txt"])).unwrap(), b"two");
    // The re-anchor commit carries y.txt again; device 0 sees an older state too and
    // re-anchors after its own confirmation.
    let d0 = &mut w.devices[0];
    let mut cx = Ctx {
        account: d0.account.as_mut().unwrap(),
        server: &mut d0.server,
        keychain: &mut d0.keychain,
        fs: &d0.fs,
        store: &mut d0.store,
        clock: &clock,
        entropy: &mut d0.rng,
        settings: &settings,
    };
    d0.folder.as_mut().unwrap().round(&mut cx).unwrap();
    if matches!(d0.folder.as_ref().unwrap().state(), FolderState::Stopped(_)) {
        d0.folder.as_mut().unwrap().reanchor(&mut cx).unwrap();
    }
    w.quiesce();
    assert_eq!(w.devices[0].fs.read_all(&p(&["y.txt"])).unwrap(), b"two");
    assert_eq!(w.devices[1].fs.read_all(&p(&["x.txt"])).unwrap(), b"one");
}

#[test]
fn restore_of_an_old_version_is_a_commit() {
    let mut w = World::new(1004, 2);
    w.devices[0].fs.user_write(&p(&["r.txt"]), b"v1");
    w.sync(0);
    let first = w.devices[0]
        .folder
        .as_ref()
        .unwrap()
        .view()
        .frontier()
        .unwrap()
        .commit;
    w.devices[0].fs.user_write(&p(&["r.txt"]), b"v2");
    w.sync(0);
    w.sync(1);
    assert_eq!(w.devices[1].fs.read_all(&p(&["r.txt"])).unwrap(), b"v2");
    let d = &mut w.devices[0];
    let settings = w.settings.clone();
    let clock = w.clock.clone();
    {
        let mut cx = Ctx {
            account: d.account.as_mut().unwrap(),
            server: &mut d.server,
            keychain: &mut d.keychain,
            fs: &d.fs,
            store: &mut d.store,
            clock: &clock,
            entropy: &mut d.rng,
            settings: &settings,
        };
        d.folder
            .as_mut()
            .unwrap()
            .restore_folder(&mut cx, &first)
            .unwrap();
    }
    w.quiesce();
    assert_eq!(w.devices[1].fs.read_all(&p(&["r.txt"])).unwrap(), b"v1");
    assert_eq!(w.devices[0].fs.read_all(&p(&["r.txt"])).unwrap(), b"v1");
}

#[test]
fn a_join_of_a_non_empty_folder_deletes_nothing() {
    let mut w = World::new(1005, 2);
    w.devices[0].fs.user_write(&p(&["same.txt"]), b"same");
    w.devices[0].fs.user_write(&p(&["differs.txt"]), b"server");
    w.sync(0);
    // Device 1 already holds files at its place before its first round.
    w.devices[1].fs.user_write(&p(&["same.txt"]), b"same");
    w.devices[1].fs.user_write(&p(&["differs.txt"]), b"local");
    w.devices[1].fs.user_write(&p(&["only-local.txt"]), b"mine");
    for c in [&b"same"[..], b"server", b"local", b"mine"] {
        w.written.insert(c.to_vec());
        w.required.insert(c.to_vec());
    }
    w.quiesce();
    w.check();
    let snap = w.devices[0].fs.snapshot();
    assert_eq!(snap.len(), 4, "{snap:?}");
}

#[test]
fn locked_files_are_retried_and_do_not_block_others() {
    let mut w = World::new(1006, 2);
    w.devices[0].fs.user_write(&p(&["locked.txt"]), b"one");
    w.devices[0].fs.user_write(&p(&["free.txt"]), b"two");
    w.sync(0);
    w.sync(1);
    w.devices[0].fs.user_write(&p(&["locked.txt"]), b"three");
    w.devices[0].fs.user_write(&p(&["free.txt"]), b"four");
    w.sync(0);
    w.devices[1].fs.set_locked(&p(&["locked.txt"]), true);
    w.sync(1);
    assert_eq!(
        w.devices[1].fs.read_all(&p(&["free.txt"])).unwrap(),
        b"four"
    );
    w.devices[1].fs.set_locked(&p(&["locked.txt"]), false);
    w.clock.advance(120_000);
    w.sync(1);
    w.sync(1);
    assert_eq!(
        w.devices[1].fs.read_all(&p(&["locked.txt"])).unwrap(),
        b"three"
    );
}

#[test]
fn a_lost_commit_reply_does_not_duplicate_or_lose_the_change() {
    let mut w = World::new(1007, 2);
    w.server.borrow_mut().lose_next_commit_reply = true;
    w.devices[0].fs.user_write(&p(&["once.txt"]), b"x");
    w.written.insert(b"x".to_vec());
    w.required.insert(b"x".to_vec());
    w.sync(0);
    w.sync(0);
    w.quiesce();
    w.check();
    assert_eq!(w.devices[1].fs.snapshot().len(), 1);
}

#[test]
fn the_server_rejects_nothing_a_device_sends() {
    // Every commit of the engine passes the server's checks from the crypto crate.
    let mut w = World::new(1008, 3);
    w.random_phase(60);
    w.quiesce();
    w.check();
    assert!(w.server.borrow().account_state().is_some());
    let feed = w.devices[0].server.clone().feed(0).unwrap();
    assert!(!feed.entries.is_empty());
}

#[test]
fn incoming_entries_with_ignored_names_are_never_written() {
    use hangar_drive_protocol::ids::ItemId;
    use hangar_drive_sync::tree::{Node, NodeKind, ROOT};
    let mut w = World::new(1010, 2);
    w.devices[0].fs.user_write(&p(&["r.txt"]), b"content");
    w.sync(0);
    w.sync(1);
    let marker_before = w.devices[1]
        .fs
        .read_all(&hangar_drive_sync::folder::marker_path())
        .unwrap();
    // Another device (or a server replaying a crafted commit) presents a tree with the
    // reserved directory at the root and an ignored file name (security review L5).
    let d = &mut w.devices[0];
    let mut tree = d.folder.as_ref().unwrap().remote().clone();
    let file = tree
        .iter()
        .find(|(_, n)| n.name == "r.txt")
        .map(|(_, n)| n.clone())
        .unwrap();
    let NodeKind::File(version) = file.kind else {
        panic!("a file");
    };
    let reserved = ItemId::from_bytes([0x71; 16]);
    tree.insert(
        reserved,
        Node {
            parent: ROOT,
            name: ".hangar-drive".into(),
            kind: NodeKind::Directory,
            conflict_of: None,
        },
    );
    tree.insert(
        ItemId::from_bytes([0x72; 16]),
        Node {
            parent: reserved,
            name: "marker".into(),
            kind: NodeKind::File(version),
            conflict_of: None,
        },
    );
    tree.insert(
        ItemId::from_bytes([0x73; 16]),
        Node {
            parent: ROOT,
            name: "desktop.ini".into(),
            kind: NodeKind::File(version),
            conflict_of: None,
        },
    );
    let settings = w.settings.clone();
    let clock = w.clock.clone();
    {
        let mut cx = Ctx {
            account: d.account.as_mut().unwrap(),
            server: &mut d.server,
            keychain: &mut d.keychain,
            fs: &d.fs,
            store: &mut d.store,
            clock: &clock,
            entropy: &mut d.rng,
            settings: &settings,
        };
        d.folder
            .as_mut()
            .unwrap()
            .publish_tree(&mut cx, tree)
            .unwrap();
    }
    w.sync(1);
    w.sync(1);
    let b = &w.devices[1];
    assert_eq!(
        b.fs.read_all(&hangar_drive_sync::folder::marker_path())
            .unwrap(),
        marker_before,
        "the root marker is untouched"
    );
    assert!(b.fs.read_all(&p(&["desktop.ini"])).is_none());
    let cannot = &b.folder.as_ref().unwrap().meta().cannot_sync;
    assert!(cannot.contains_key(&reserved));
    assert!(cannot.contains_key(&ItemId::from_bytes([0x73; 16])));
    assert_eq!(b.fs.read_all(&p(&["r.txt"])).unwrap(), b"content");
}

#[test]
fn a_publish_too_large_for_one_commit_goes_out_as_whole_intermediate_trees() {
    let mut w = World::new(1011, 2);
    // A small limit per commit stands in for MAX_REFERENCE_DELTA_IDS (open point B).
    w.settings.max_delta_ids = 12;
    w.devices[0].fs.user_write(&p(&["base.txt"]), b"base");
    w.written.insert(b"base".to_vec());
    w.sync(0);
    w.sync(1);
    let before = w.server.borrow().folder_sequence(&FOLDER);
    for i in 0..20 {
        let name = format!("f{i:02}.txt");
        let data = format!("content {i}").into_bytes();
        assert!(w.devices[0].fs.user_mkdir(&p(&["new"])) || i > 0);
        assert!(w.devices[0].fs.user_write(&p(&["new", &name]), &data));
        w.written.insert(data.clone());
        w.required.insert(data);
    }
    w.sync(0);
    let after = w.server.borrow().folder_sequence(&FOLDER);
    assert!(after - before > 1, "several commits: {before} to {after}");
    // Every head on the way is a whole tree: it decodes, holds no item without its parents
    // and only files whose content is on the server, and the files only grow.
    let d = &mut w.devices[1];
    let settings = w.settings.clone();
    let clock = w.clock.clone();
    let mut cx = Ctx {
        account: d.account.as_mut().unwrap(),
        server: &mut d.server,
        keychain: &mut d.keychain,
        fs: &d.fs,
        store: &mut d.store,
        clock: &clock,
        entropy: &mut d.rng,
        settings: &settings,
    };
    let folder = d.folder.as_mut().unwrap();
    folder.round(&mut cx).unwrap();
    let heads: Vec<_> = folder
        .meta()
        .timeline
        .iter()
        .filter(|t| !t.side && t.sequence > before)
        .map(|t| t.commit)
        .collect();
    assert!(heads.len() > 1);
    let mut files = 0;
    for head in heads {
        let tree = folder.tree_at(&mut cx, &head).unwrap();
        tree.check().unwrap();
        let count = tree.count_files();
        assert!(count >= files, "a stage never drops a file");
        files = count;
    }
    assert_eq!(files, 21);
    w.quiesce();
    w.check();
}

#[test]
fn intermediate_trees_count_the_directories_they_change_above_new_files() {
    // New files in many directories the server already has: every directory node above each
    // of them changes as well, so a stage must count those nodes against the commit limit, not
    // only the new directories.
    let mut w = World::new(1012, 2);
    w.settings.max_delta_ids = 12;
    for i in 0..8 {
        let top = format!("a{i}");
        assert!(w.devices[0].fs.user_mkdir(&p(&[&top])));
        assert!(w.devices[0].fs.user_mkdir(&p(&[&top, "x"])));
        assert!(w.devices[0].fs.user_mkdir(&p(&[&top, "x", "y"])));
        let data = format!("base {i}").into_bytes();
        assert!(w.devices[0]
            .fs
            .user_write(&p(&[&top, "x", "y", "base.txt"]), &data));
        w.written.insert(data.clone());
        w.required.insert(data);
        // Each directory chain in its own commit, so the setup itself fits the limit.
        w.sync(0);
    }
    w.sync(1);
    for i in 0..8 {
        let top = format!("a{i}");
        let data = format!("new {i}").into_bytes();
        assert!(w.devices[0]
            .fs
            .user_write(&p(&[&top, "x", "y", "new.txt"]), &data));
        w.written.insert(data.clone());
        w.required.insert(data);
    }
    w.sync(0);
    w.quiesce();
    w.check();
    // Changed files count as well: new content in every existing file at once.
    w.required.clear();
    for i in 0..8 {
        let top = format!("a{i}");
        for name in ["base.txt", "new.txt"] {
            let data = format!("changed {i} {name}").into_bytes();
            assert!(w.devices[0]
                .fs
                .user_write(&p(&[&top, "x", "y", name]), &data));
            w.written.insert(data.clone());
            w.required.insert(data);
        }
    }
    w.sync(0);
    w.quiesce();
    w.check();
}
