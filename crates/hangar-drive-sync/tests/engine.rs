//! The engine as the app uses it: setting up an account with the recovery code check, adding a
//! folder, pairing a second device through an offer, the second device joining the folder, the
//! snapshot and the events, conflicts and "keep both", the timeline and a restore, and the
//! engine thread.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use hangar_drive_protocol::ids::{base64url, DeviceId};
use hangar_drive_sync::api::{ApiResult, BackendEvent, FolderStatus, PairResult, SetupState};
use hangar_drive_sync::engine::{Engine, EngineCore, EnginePorts, EngineSettings};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom, ServerState,
};
use hangar_drive_sync::ports::FileSystem;

type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

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
        server: Box::new(move |_config, identity| {
            let device = identity.map_or(DeviceId::from_bytes([0; 16]), |i| i.device);
            Ok(Box::new(MemServer::connect(&server, device)) as Box<_>)
        }),
        // In-memory roots: the nesting rule on the path names, as the real check does on the
        // canonical forms.
        roots: Box::new(|path: &Path, existing: &[PathBuf]| {
            let key = path.to_string_lossy().to_lowercase();
            if existing.iter().any(|e| {
                let e = e.to_string_lossy().to_lowercase();
                hangar_drive_sync::roots::overlap(&key, &e)
            }) {
                return Err(hangar_drive_sync::roots::RootError::Overlaps);
            }
            Ok(path.to_path_buf())
        }),
    };
    EngineCore::open(ports, EngineSettings::default()).unwrap()
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn disk(disks: &Disks, path: &str) -> Arc<MemFs> {
    disks.borrow()[&PathBuf::from(path)].clone()
}

fn settle(a: &mut EngineCore, b: &mut EngineCore, clock: &ManualClock) -> Vec<BackendEvent> {
    let mut events = Vec::new();
    for _ in 0..4 {
        clock.advance(20_000);
        events.extend(a.tick());
        events.extend(b.tick());
    }
    events
}

#[test]
fn setup_pairing_and_sync_through_the_engine() {
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&shared, &disks, &clock, 1);
    let mut b = core(&shared, &disks, &clock, 2);
    assert_eq!(a.snapshot().setup, SetupState::Needed);

    // Account: invite, recovery code, the typed check group.
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    assert!(matches!(a.check_invite(&link), ApiResult::Ok(ref h) if h == "localhost:8080"));
    assert!(matches!(a.check_invite("nonsense"), ApiResult::Err(_)));
    let ApiResult::Ok(code) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    assert_eq!(code.groups.len(), 8);
    assert!((2..=8).contains(&code.check_group));
    assert!(!a.confirm_recovery_group("WRONG").unwrap());
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a
        .confirm_recovery_group(&group.to_ascii_lowercase())
        .unwrap());
    assert_eq!(a.snapshot().setup, SetupState::Done);

    // A folder with a file.
    let folder = a.add_folder("mem:/a/Docs", "Docs").unwrap();
    disk(&disks, "mem:/a/Docs").user_write(&p(&["plan.txt"]), b"v1");
    a.tick();
    a.tick();
    let snap = a.snapshot();
    assert_eq!(snap.folders.len(), 1);
    assert_eq!(snap.folders[0].status, FolderStatus::UpToDate);

    // Pairing: A offers, B answers, A asks the person, B joins.
    let offer = a.create_pairing_offer().unwrap();
    assert_eq!(offer.code.len(), 8);
    let ApiResult::Ok(safety_b) = b.start_pairing(&offer.link, "Desktop").unwrap() else {
        panic!("start pairing");
    };
    let events = a.tick();
    let request = events
        .iter()
        .find_map(|e| match e {
            BackendEvent::PairRequest { request } => Some(request.clone()),
            _ => None,
        })
        .expect("pair request");
    assert_eq!(request.device_name, "Desktop");
    // Both devices show the same safety number of the new device.
    assert_eq!(request.safety, safety_b);
    a.answer_pair_request(&request.offer_id, true).unwrap();
    let events = b.tick();
    assert!(events.iter().any(|e| matches!(
        e,
        BackendEvent::PairResult {
            result: PairResult::Joined
        }
    )));
    assert_eq!(a.list_devices().unwrap().devices.len(), 2);

    // B sees the account folder and joins it.
    let snap = b.snapshot();
    assert_eq!(snap.remote_folders.len(), 1);
    b.add_account_folder(&folder, "mem:/b/Docs").unwrap();
    settle(&mut a, &mut b, &clock);
    assert_eq!(
        disk(&disks, "mem:/b/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v1"
    );

    // A conflict: both edit, the server order decides, "keep both" drops the link.
    disk(&disks, "mem:/a/Docs").user_write(&p(&["plan.txt"]), b"from a");
    disk(&disks, "mem:/b/Docs").user_write(&p(&["plan.txt"]), b"from b!");
    a.tick();
    b.tick();
    settle(&mut a, &mut b, &clock);
    let groups = b.list_conflicts();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].versions.len(), 2);
    b.keep_both_conflict(&groups[0].id).unwrap();
    settle(&mut a, &mut b, &clock);
    assert!(a.list_conflicts().is_empty());
    assert!(b.list_conflicts().is_empty());

    // The timeline and a restore of the whole folder to the first version.
    let timeline = a.get_timeline(&folder, 20).unwrap();
    assert!(timeline.entries.len() >= 3);
    let first = timeline.entries.last().unwrap().id.clone();
    let tree = a.get_tree_at(&folder, &first).unwrap();
    assert!(tree.nodes.iter().any(|n| n.name == "plan.txt"));
    a.reset_folder(&folder, &first).unwrap();
    settle(&mut a, &mut b, &clock);
    assert_eq!(
        disk(&disks, "mem:/a/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v1"
    );
    assert_eq!(
        disk(&disks, "mem:/b/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v1"
    );

    // The snapshot serializes to the window's JSON shape.
    let json = serde_json::to_value(a.snapshot()).unwrap();
    assert_eq!(json["setup"], "done");
    assert_eq!(json["sync"]["connection"]["kind"], "online");
    assert!(json["folders"][0]["notSyncedCount"].is_number());
}

#[test]
fn the_engine_thread_answers_commands_and_sends_snapshots() {
    let (handle, events) = Engine::spawn(
        || {
            let shared = MemServer::new_shared();
            let disks: Disks = Rc::default();
            let clock = ManualClock::at(0);
            Ok(core(&shared, &disks, &clock, 7))
        },
        Duration::from_millis(10),
    )
    .unwrap();
    let setup = handle.call(|core| core.snapshot().setup).unwrap();
    assert_eq!(setup, SetupState::Needed);
    let event = events.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(event, BackendEvent::Snapshot { .. }));
}

#[test]
fn recovery_with_the_sheet_replaces_every_lost_device() {
    use hangar_drive_sync::api::RecoverError;
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&shared, &disks, &clock, 11);
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    // The sheet names server, server ID and account; its link never carries the code.
    let sheet = code.sheet.clone();
    assert_eq!(sheet.server_url, "http://localhost:8080/");
    assert_eq!(sheet.server_id.len(), 32);
    assert!(sheet.link.starts_with("hangar-drive://recover#"));
    let text = code.groups.join("-");
    assert!(!sheet.link.contains(&text) && !sheet.link.contains(&code.groups[0]));
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.confirm_recovery_group(&group).unwrap());
    let folder = a.add_folder("mem:/a/Docs", "Docs").unwrap();
    disk(&disks, "mem:/a/Docs").user_write(&p(&["plan.txt"]), b"kept");
    a.tick();
    a.tick();
    let lost = a.list_devices().unwrap().devices[0].id.clone();

    // A is lost. A new installation types the code from the sheet.
    let mut c = core(&shared, &disks, &clock, 12);
    let typo = format!("{}X", &text[..text.len() - 1]);
    assert_eq!(
        c.recover_account(&sheet.link, &typo, "Neu").unwrap(),
        ApiResult::Err(RecoverError::Typo)
    );
    assert_eq!(
        c.recover_account(&sheet.link, &text, "Neu").unwrap(),
        ApiResult::Ok(())
    );
    let old = c.recovery_devices().unwrap();
    assert_eq!(old.len(), 1);
    assert_eq!(old[0].id, lost);
    let renewed = c
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap();
    assert_eq!(renewed.groups.len(), 8);
    assert_ne!(renewed.groups, code.groups);
    assert_eq!(renewed.sheet.account_id, sheet.account_id);
    // Only the new device is left; the old code is used up.
    let devices = c.list_devices().unwrap().devices;
    assert_eq!(devices.len(), 1);
    assert!(devices[0].is_this);
    let mut d = core(&shared, &disks, &clock, 13);
    assert_eq!(
        d.recover_account(&sheet.link, &text, "Noch eins").unwrap(),
        ApiResult::Err(RecoverError::Used)
    );
    // The new code works, and the files come back.
    let snap = c.snapshot();
    assert_eq!(snap.remote_folders.len(), 1);
    c.add_account_folder(&folder, "mem:/c/Docs").unwrap();
    for _ in 0..3 {
        clock.advance(20_000);
        c.tick();
    }
    assert_eq!(
        disk(&disks, "mem:/c/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"kept"
    );
    assert_eq!(
        c.snapshot().warnings.len(),
        0,
        "no stop for the lost device's heads"
    );
    // A, if it ever comes back, learns that it was removed.
    clock.advance(20_000);
    a.tick();
    assert!(a
        .snapshot()
        .warnings
        .iter()
        .any(|w| matches!(w, hangar_drive_sync::api::Warning::Removed { .. })));
    let mut e = core(&shared, &disks, &clock, 14);
    assert_eq!(
        e.recover_account(&renewed.sheet.link, &renewed.groups.join(""), "Später")
            .unwrap(),
        ApiResult::Ok(())
    );
}
