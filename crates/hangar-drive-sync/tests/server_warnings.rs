//! What the server tells every device and what a download may cost this device:
//!
//! - ADR 0001, section 5: an anomaly pin after a burst by one device shows as "suspect device"
//!   on the other devices too, naming the device from the verified history; "That was me" hides
//!   it on one device only, and a pin that lapsed under the pin cap is marked.
//! - The quota, account budget and disk reserve notices reach the window once each.
//! - Security review M2 of the download path: without free space a file is not fetched and not
//!   written, the window shows "disk full", and a chunk the manifest repeats is fetched once.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::CHUNK_SIZE;
use hangar_drive_sync::api::{ApiResult, BackendEvent, PairResult, ServerNotice, Warning};
use hangar_drive_sync::engine::{EngineCore, EnginePorts, EngineSettings};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom, ServerState,
};
use hangar_drive_sync::ports::FileSystem;

type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn core(
    shared: &Rc<RefCell<ServerState>>,
    disks: &Disks,
    clock: &ManualClock,
    seed: u64,
) -> EngineCore {
    let server = Rc::clone(shared);
    let disks = Rc::clone(disks);
    let ports = EnginePorts {
        store: Box::new(MemStore::new()),
        keychain: Box::new(MemKeychain::default()),
        clock: Box::new(clock.clone()),
        entropy: Box::new(SeededRandom::new(seed)),
        fs: Box::new(move |path: &Path| {
            let fs = disks
                .borrow_mut()
                .entry(path.to_path_buf())
                .or_insert_with(|| Arc::new(MemFs::new(true)))
                .clone();
            let events = Box::new(fs.clone()) as Box<dyn hangar_drive_sync::watch::ChangeSource>;
            Ok((Box::new(fs) as Box<dyn FileSystem>, Some(events)))
        }),
        server: Box::new(move |config, identity| {
            let device = identity.map_or(DeviceId::from_bytes([0; 16]), |i| i.device);
            Ok(Box::new(MemServer::connect_pinned(&server, device, config.pin)) as Box<_>)
        }),
        roots: Box::new(|path: &Path, _: &[PathBuf]| Ok(path.to_path_buf())),
    };
    EngineCore::open(ports, EngineSettings::default()).unwrap()
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn disk(disks: &Disks, path: &str) -> Arc<MemFs> {
    disks
        .borrow_mut()
        .entry(PathBuf::from(path))
        .or_insert_with(|| Arc::new(MemFs::new(true)))
        .clone()
}

fn settle(a: &mut EngineCore, b: &mut EngineCore, clock: &ManualClock) {
    for _ in 0..4 {
        clock.advance(20_000);
        a.tick();
        b.tick();
    }
}

/// Two devices of one account, "Laptop" (A) with the folder "Docs" holding `files`, and
/// "Desktop" (B) joined to it. Returns the folder ID.
fn two_devices(
    a: &mut EngineCore,
    b: &mut EngineCore,
    disks: &Disks,
    clock: &ManualClock,
    files: &[(&str, &[u8])],
) -> String {
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.confirm_recovery_group(&group).unwrap());
    let folder = a.add_folder("mem:/a/Docs", "Docs").unwrap();
    for (name, data) in files {
        disk(disks, "mem:/a/Docs").user_write(&p(&[name]), data);
    }
    a.tick();
    a.tick();
    let offer = a.create_pairing_offer().unwrap();
    let ApiResult::Ok(_) = b.start_pairing(&offer.link, "Desktop").unwrap() else {
        panic!("start pairing");
    };
    let request = a
        .tick()
        .into_iter()
        .find_map(|e| match e {
            BackendEvent::PairRequest { request } => Some(request),
            _ => None,
        })
        .expect("pair request");
    a.answer_pair_request(&request.offer_id, true).unwrap();
    assert!(b.tick().iter().any(|e| matches!(
        e,
        BackendEvent::PairResult {
            result: PairResult::Joined { .. }
        }
    )));
    b.add_account_folder(&folder, "mem:/b/Docs").unwrap();
    settle(a, b, clock);
    folder
}

fn suspects(engine: &EngineCore) -> Vec<Warning> {
    engine
        .snapshot()
        .warnings
        .into_iter()
        .filter(|w| matches!(w, Warning::Suspect { .. }))
        .collect()
}

#[test]
fn a_burst_by_one_device_warns_every_device() {
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&shared, &disks, &clock, 1);
    let mut b = core(&shared, &disks, &clock, 2);
    let names = ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt", "f.txt"];
    let files: Vec<(&str, &[u8])> = names.iter().map(|n| (*n, b"plain".as_slice())).collect();
    let folder = two_devices(&mut a, &mut b, &disks, &clock, &files);
    let folder_id = FolderId::from_hex(&folder).unwrap();
    let before = shared.borrow().head(&folder_id).expect("head");
    assert!(suspects(&b).is_empty());

    // A burst on A: every file replaced, as malware that encrypts them would.
    for name in names {
        disk(&disks, "mem:/a/Docs").user_write(&p(&[name]), b"scrambled!");
    }
    settle(&mut a, &mut b, &clock);
    assert_eq!(
        disk(&disks, "mem:/b/Docs")
            .read_all(&p(&["a.txt"]))
            .unwrap(),
        b"scrambled!"
    );
    // The server pins the last commit before the burst and tells every device.
    let now = 1_795_651_200_000u64 + 200_000;
    shared.borrow_mut().push_notice(Notice::AnomalyPin {
        folder: folder_id,
        commit: before,
        until_ms: now + 90 * DAY_MS,
    });
    b.tick();
    a.tick();
    let shown = suspects(&b);
    assert_eq!(shown.len(), 1, "{shown:?}");
    let Warning::Suspect {
        id,
        device_name,
        device_id,
        folder_name,
        folder_id: warned_folder,
        entry_id,
        days,
        lapsed,
        ..
    } = shown[0].clone()
    else {
        unreachable!()
    };
    assert_eq!(device_name, "Laptop");
    assert!(!device_id.is_empty());
    assert_eq!(folder_name, "Docs");
    assert_eq!(warned_folder, folder);
    assert_eq!(entry_id, before.to_hex());
    assert_eq!(days, 30);
    assert!(!lapsed);
    // The entry is the one the timeline offers for the restore.
    assert!(b
        .get_timeline(&folder, 50)
        .unwrap()
        .entries
        .iter()
        .any(|e| e.id == entry_id));
    // A, the device that did it, is told as well.
    assert_eq!(suspects(&a).len(), 1);

    // "That was me" on B hides it there only (no shared dismissal).
    b.dismiss_warning(&id).unwrap();
    assert!(suspects(&b).is_empty());
    assert_eq!(suspects(&a).len(), 1);

    // The pin cap lets the pin go: the notice comes again, ending now.
    shared.borrow_mut().push_notice(Notice::AnomalyPin {
        folder: folder_id,
        commit: before,
        until_ms: now,
    });
    a.tick();
    b.tick();
    assert!(matches!(
        suspects(&a).as_slice(),
        [Warning::Suspect { lapsed: true, .. }]
    ));
    assert!(suspects(&b).is_empty());
}

#[test]
fn quota_budget_and_disk_notices_reach_the_window_once() {
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&shared, &disks, &clock, 3);
    let mut b = core(&shared, &disks, &clock, 4);
    two_devices(&mut a, &mut b, &disks, &clock, &[("a.txt", b"x")]);
    for _ in 0..2 {
        let mut s = shared.borrow_mut();
        s.push_notice(Notice::QuotaWarning {
            live_bytes: 95,
            quota_bytes: 100,
        });
        s.push_notice(Notice::AccountBudget);
        s.push_notice(Notice::DiskReserve);
        drop(s);
        b.tick();
    }
    let snap = b.snapshot();
    assert_eq!(
        snap.notices,
        vec![
            ServerNotice::Quota,
            ServerNotice::BudgetAccount,
            ServerNotice::ServerDisk
        ]
    );
    let storage = snap.storage.expect("storage");
    assert_eq!((storage.used, storage.quota), (95, 100));
    let json = serde_json::to_value(&snap.notices).unwrap();
    assert_eq!(
        json,
        serde_json::json!([
            { "kind": "quota" },
            { "kind": "budgetAccount" },
            { "kind": "serverDisk" }
        ])
    );
}

#[test]
fn a_download_waits_for_space_and_fetches_a_repeated_chunk_once() {
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&shared, &disks, &clock, 5);
    let mut b = core(&shared, &disks, &clock, 6);
    // Three identical chunks: the manifest names one chunk ID three times.
    let big = vec![7u8; 3 * CHUNK_SIZE as usize];
    // B's disk has room for the small file and the reserve of 256 MiB, not for the big one.
    disk(&disks, "mem:/b/Docs").set_free_bytes(Some(260 * 1024 * 1024));
    two_devices(
        &mut a,
        &mut b,
        &disks,
        &clock,
        &[("big.bin", &big), ("small.txt", b"s")],
    );
    let b_disk = disk(&disks, "mem:/b/Docs");
    assert!(b_disk.read_all(&p(&["big.bin"])).is_none());
    let needed = b
        .snapshot()
        .warnings
        .iter()
        .find_map(|w| match w {
            Warning::DiskFull { needed, .. } => Some(*needed),
            _ => None,
        })
        .expect("disk full warning");
    assert_eq!(needed, big.len() as u64);
    let fetched_before = shared.borrow().object_gets.clone();

    // Space again: after the wait the file comes, its chunk fetched once.
    b_disk.set_free_bytes(Some(64 * 1024 * 1024 * 1024));
    // The wait doubles from one minute; four minutes cover the second one.
    for _ in 0..3 {
        settle(&mut a, &mut b, &clock);
    }
    assert_eq!(b_disk.read_all(&p(&["big.bin"])).unwrap(), big);
    assert!(!b
        .snapshot()
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::DiskFull { .. })));
    let fetched_after = shared.borrow().object_gets.clone();
    let mut chunk_fetches = 0;
    for (id, count) in &fetched_after {
        let new = count - fetched_before.get(id).copied().unwrap_or(0);
        assert!(new <= 1, "object {id} fetched {new} times");
        chunk_fetches += new;
    }
    assert!(chunk_fetches >= 1);
}
