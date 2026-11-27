//! The engine commands behind the window's last buttons: disconnecting this device after "these
//! are not my devices" (N2), undo, a folder deleted everywhere brought back, a restore that waits
//! for the upload budget, "download again" for a missing folder, the pin rotation with the server
//! number or an offer (ADR 0001, section 6), and files another device deleted brought back.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use hangar_drive_crypto::identity::server_key_number;
use hangar_drive_protocol::api::ErrorCode;
use hangar_drive_protocol::ids::{base64url, DeviceId, ServerId};
use hangar_drive_sync::api::{
    ActivityEntry, ApiResult, BackendEvent, DeviceNameError, FixServerError, FolderStatus,
    NumberRows, PairResult, RestoreOutcome, SetupState, StopReasonApi, Warning,
};
use hangar_drive_sync::engine::{
    EngineCore, EnginePorts, EngineSettings, RESTORE_RETRY_MS, SERVER_NUMBER_COMMAND,
};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedKeychain,
};
use hangar_drive_sync::ports::FileSystem;

type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

struct World {
    shared: Rc<RefCell<ServerState>>,
    disks: Disks,
    clock: ManualClock,
}

impl World {
    fn new() -> Self {
        Self {
            shared: MemServer::new_shared(),
            disks: Rc::default(),
            clock: ManualClock::at(1_795_651_200_000),
        }
    }

    /// A device on this server; connections are pinned like the real client's.
    fn device(&self, seed: u64, keychain: SharedKeychain) -> EngineCore {
        let server = Rc::clone(&self.shared);
        let disks = Rc::clone(&self.disks);
        let ports = EnginePorts {
            store: Box::new(MemStore::new()),
            keychain: Box::new(keychain),
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
                Ok(Box::new(MemServer::connect_pinned(&server, device, config.pin)) as Box<_>)
            }),
            roots: Box::new(|path: &Path, _existing: &[PathBuf]| Ok(path.to_path_buf())),
        };
        EngineCore::open(ports, EngineSettings::default()).unwrap()
    }

    fn disk(&self, path: &str) -> Arc<MemFs> {
        self.disks.borrow()[&PathBuf::from(path)].clone()
    }

    fn settle(&self, devices: &mut [&mut EngineCore]) -> Vec<BackendEvent> {
        let mut events = Vec::new();
        for _ in 0..4 {
            self.clock.advance(20_000);
            for d in devices.iter_mut() {
                events.extend(d.tick());
            }
        }
        events
    }
}

/// The server ID of the in-memory server and the key it presents at first.
const SERVER: [u8; 16] = [0x5e; 16];
const FIRST_KEY: [u8; 32] = [7; 32];
const NEW_KEY: [u8; 32] = [8; 32];

/// A new account on `a`, through an invite that pins `FIRST_KEY` when `pinned`.
fn set_up(a: &mut EngineCore, pinned: bool) {
    let link = if pinned {
        format!(
            "https://drive.example/join#{}.{}.{}",
            base64url(&[9; 16]),
            "5e".repeat(16),
            base64url(&FIRST_KEY)
        )
    } else {
        format!("http://localhost:8080/join#{}", base64url(&[9; 16]))
    };
    let ApiResult::Ok(code) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.confirm_recovery_group(&group).unwrap());
}

/// Pairs `b` into the account of `a`; returns the devices `b` was shown (N2).
fn pair(world: &World, a: &mut EngineCore, b: &mut EngineCore) -> Vec<String> {
    let offer = a.create_pairing_offer().unwrap();
    assert!(matches!(
        b.start_pairing(&offer.link, "Desktop").unwrap(),
        ApiResult::Ok(_)
    ));
    let request = a
        .tick()
        .into_iter()
        .find_map(|e| match e {
            BackendEvent::PairRequest { request } => Some(request),
            _ => None,
        })
        .expect("pair request");
    a.answer_pair_request(&request.offer_id, true).unwrap();
    world.clock.advance(1_000);
    b.tick()
        .into_iter()
        .find_map(|e| match e {
            BackendEvent::PairResult {
                result: PairResult::Joined { devices },
            } => Some(devices.into_iter().map(|d| d.name).collect()),
            _ => None,
        })
        .expect("joined")
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

/// A with an account and a folder "Docs" holding `plan.txt`, B paired and syncing it too.
fn two_devices(world: &World) -> (EngineCore, EngineCore, String) {
    let mut a = world.device(1, SharedKeychain::default());
    let mut b = world.device(2, SharedKeychain::default());
    set_up(&mut a, false);
    let folder = a.add_folder("mem:/a/Docs", "Docs").unwrap();
    world
        .disk("mem:/a/Docs")
        .user_write(&p(&["plan.txt"]), b"v1");
    a.tick();
    pair(world, &mut a, &mut b);
    b.add_account_folder(&folder, "mem:/b/Docs").unwrap();
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(
        world
            .disk("mem:/b/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v1"
    );
    (a, b, folder)
}

// N2: "No, these are not my devices" right after the join disconnects for real: no secret of
// the stranger's account stays, nothing is synced, and the device no longer reaches the server.
// It stays in that account's log until a device there removes it.
#[test]
fn disconnecting_after_the_join_forgets_the_strangers_account() {
    let world = World::new();
    let mut stranger = world.device(11, SharedKeychain::default());
    set_up(&mut stranger, false);
    let keys = SharedKeychain::default();
    let mut me = world.device(12, keys.clone());
    let shown = pair(&world, &mut stranger, &mut me);
    assert_eq!(shown.len(), 2);
    assert!(keys.keys().contains(&"device-identity".to_owned()));
    assert!(keys.keys().iter().any(|k| k.starts_with("epoch-")));
    assert_eq!(me.snapshot().setup, SetupState::Done);

    me.disconnect_this_device().unwrap();

    assert_eq!(keys.keys(), Vec::<String>::new(), "no secret is left");
    let snap = me.snapshot();
    assert_eq!(snap.setup, SetupState::Needed);
    assert!(snap.folders.is_empty() && snap.remote_folders.is_empty());
    assert!(snap.warnings.is_empty(), "{:?}", snap.warnings);
    assert!(me.list_devices().is_err());
    let calls = world.shared.borrow().calls;
    world.clock.advance(120_000);
    me.tick();
    assert_eq!(
        world.shared.borrow().calls,
        calls,
        "nothing reaches the server"
    );
    // The other account still lists the device: only a device there can remove it.
    stranger.tick();
    assert_eq!(stranger.list_devices().unwrap().devices.len(), 2);
}

// UX 9.2: a restored file comes with "Undo", which is a new commit with the version before.
#[test]
fn a_restore_and_a_folder_reset_can_be_undone() {
    let world = World::new();
    let (mut a, mut b, folder) = two_devices(&world);
    world
        .disk("mem:/a/Docs")
        .user_write(&p(&["plan.txt"]), b"v2");
    world.disk("mem:/a/Docs").user_write(&p(&["new.txt"]), b"n");
    world.settle(&mut [&mut a, &mut b]);
    let timeline = a.get_timeline(&folder, 20).unwrap();
    let first = timeline.entries.last().unwrap().id.clone();

    let RestoreOutcome::Done {
        undo_token: Some(token),
        ..
    } = a.restore_file(&folder, &first, "plan.txt").unwrap()
    else {
        panic!("restore");
    };
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(
        world
            .disk("mem:/b/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v1"
    );
    let entries = a.get_timeline(&folder, 50).unwrap().entries.len();
    a.undo(&token).unwrap();
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(
        world
            .disk("mem:/b/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v2"
    );
    assert!(
        a.get_timeline(&folder, 50).unwrap().entries.len() > entries,
        "the undo is a new commit"
    );
    // A token is used once.
    assert!(a.undo(&token).is_err());

    // The whole folder back to the first state, and undone again.
    let RestoreOutcome::Done {
        undo_token: Some(token),
        ..
    } = a.reset_folder(&folder, &first).unwrap()
    else {
        panic!("reset");
    };
    world.settle(&mut [&mut a, &mut b]);
    assert!(world
        .disk("mem:/b/Docs")
        .read_all(&p(&["new.txt"]))
        .is_none());
    a.undo(&token).unwrap();
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(
        world
            .disk("mem:/b/Docs")
            .read_all(&p(&["new.txt"]))
            .unwrap(),
        b"n"
    );
    assert_eq!(
        world
            .disk("mem:/b/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v2"
    );
}

// UX 7: "Keep this" offers "Undo"; the undo brings back the original's content and the copy,
// so the two versions are a conflict again.
#[test]
fn keep_this_can_be_undone() {
    let world = World::new();
    let (mut a, mut b, _folder) = two_devices(&world);
    world
        .disk("mem:/a/Docs")
        .user_write(&p(&["plan.txt"]), b"from a");
    world
        .disk("mem:/b/Docs")
        .user_write(&p(&["plan.txt"]), b"from b!");
    a.tick();
    b.tick();
    world.settle(&mut [&mut a, &mut b]);
    let groups = b.list_conflicts();
    assert_eq!(groups.len(), 1, "{groups:?}");
    let original = groups[0].versions.iter().find(|v| v.original).unwrap();
    let copy = groups[0].versions.iter().find(|v| !v.original).unwrap();
    let original_content = world
        .disk("mem:/b/Docs")
        .read_all(&p(&["plan.txt"]))
        .unwrap();
    let copy_content = world
        .disk("mem:/b/Docs")
        .read_all(&p(&[copy.name.as_str()]))
        .unwrap();
    assert_ne!(original.id, copy.id);

    let token = b.keep_conflict_version(&groups[0].id, &copy.id).unwrap();
    assert!(!token.is_empty());
    world.settle(&mut [&mut a, &mut b]);
    assert!(a.list_conflicts().is_empty() && b.list_conflicts().is_empty());
    assert_eq!(
        world
            .disk("mem:/a/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        copy_content
    );

    b.undo(&token).unwrap();
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(
        world
            .disk("mem:/a/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        original_content
    );
    assert_eq!(
        world
            .disk("mem:/a/Docs")
            .read_all(&p(&[copy.name.as_str()]))
            .unwrap(),
        copy_content
    );
    assert_eq!(a.list_conflicts().len(), 1);
}

// UX 6 and ADR 0001, section 3: a folder deleted everywhere is listed under "Gelöschte Ordner"
// on every device and can be brought back within the window; a device that synced it carries
// on.
#[test]
fn a_folder_deleted_everywhere_comes_back() {
    let world = World::new();
    let (mut a, mut b, folder) = two_devices(&world);
    a.delete_folder_everywhere(&folder).unwrap();
    world.settle(&mut [&mut a, &mut b]);
    for device in [&a, &b] {
        let snap = device.snapshot();
        assert_eq!(snap.deleted_folders.len(), 1, "{:?}", snap.deleted_folders);
        assert_eq!(snap.deleted_folders[0].name, "Docs");
        assert_eq!(snap.deleted_folders[0].days_left, 30);
        assert!(snap.remote_folders.is_empty());
    }
    // B still syncs it; the server refuses its commits while the folder is retired.
    world
        .disk("mem:/b/Docs")
        .user_write(&p(&["back.txt"]), b"b");
    world.settle(&mut [&mut a, &mut b]);
    assert_ne!(b.snapshot().folders[0].status, FolderStatus::UpToDate);

    // B brings it back; A sees it as an account folder again, B syncs on with its change.
    b.restore_deleted_folder(&folder).unwrap();
    world.settle(&mut [&mut a, &mut b]);
    let snap = a.snapshot();
    assert!(snap.deleted_folders.is_empty());
    assert_eq!(snap.remote_folders.len(), 1);
    assert_eq!(snap.remote_folders[0].name, "Docs");
    assert!(b.snapshot().deleted_folders.is_empty());
    assert_eq!(b.snapshot().folders[0].status, FolderStatus::UpToDate);
    a.add_account_folder(&folder, "mem:/a2/Docs").unwrap();
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(
        world
            .disk("mem:/a2/Docs")
            .read_all(&p(&["back.txt"]))
            .unwrap(),
        b"b"
    );

    // After the window the entry is gone.
    a.delete_folder_everywhere(&folder).unwrap();
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(a.snapshot().deleted_folders.len(), 1);
    world.clock.advance(31 * 24 * 60 * 60 * 1000);
    a.tick();
    assert!(a.snapshot().deleted_folders.is_empty());
    assert!(a.restore_deleted_folder(&folder).is_err());
}

// UX 9.1: a restore the upload budget holds back waits as a job, runs by itself later, and can
// be cancelled.
#[test]
fn a_restore_waits_for_the_budget_and_can_be_cancelled() {
    let world = World::new();
    let (mut a, mut b, folder) = two_devices(&world);
    world
        .disk("mem:/a/Docs")
        .user_write(&p(&["plan.txt"]), b"v2");
    world.settle(&mut [&mut a, &mut b]);
    let first = a
        .get_timeline(&folder, 20)
        .unwrap()
        .entries
        .last()
        .unwrap()
        .id
        .clone();

    world.shared.borrow_mut().refuse_commits = Some(ErrorCode::BudgetExceeded);
    let RestoreOutcome::WaitBudget { job_id } =
        a.restore_file(&folder, &first, "plan.txt").unwrap()
    else {
        panic!("wait");
    };
    assert!(!job_id.is_empty());
    // Still held back: it waits on.
    world.clock.advance(RESTORE_RETRY_MS);
    a.tick();
    world.shared.borrow_mut().refuse_commits = None;
    world.clock.advance(RESTORE_RETRY_MS);
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(
        world
            .disk("mem:/b/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v1",
        "the waiting restore ran by itself"
    );

    // A cancelled job never runs.
    world
        .disk("mem:/a/Docs")
        .user_write(&p(&["plan.txt"]), b"v3");
    world.settle(&mut [&mut a, &mut b]);
    world.shared.borrow_mut().refuse_commits = Some(ErrorCode::BudgetExceeded);
    let RestoreOutcome::WaitBudget { job_id } =
        a.restore_file(&folder, &first, "plan.txt").unwrap()
    else {
        panic!("wait");
    };
    a.cancel_restore(&job_id).unwrap();
    a.cancel_restore(&job_id).unwrap();
    world.shared.borrow_mut().refuse_commits = None;
    world.clock.advance(2 * RESTORE_RETRY_MS);
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(
        world
            .disk("mem:/b/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v3"
    );
}

// UX 8.2: a folder whose place went missing is downloaded again into its old place; nothing
// was deleted anywhere.
#[test]
fn a_missing_folder_is_downloaded_again() {
    let world = World::new();
    let (mut a, mut b, folder) = two_devices(&world);
    // B's folder is gone with everything in it, the marker too.
    let disk = world.disk("mem:/b/Docs");
    assert!(disk.user_delete(&p(&["plan.txt"])));
    assert!(disk.user_delete(&hangar_drive_sync::folder::marker_path()));
    world.settle(&mut [&mut a, &mut b]);
    assert!(b
        .snapshot()
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::MissingFolder { .. })));
    assert_eq!(
        b.snapshot().folders[0].status,
        FolderStatus::Stopped {
            reason: StopReasonApi::Missing
        }
    );
    assert_eq!(
        world
            .disk("mem:/a/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v1",
        "nothing is deleted elsewhere"
    );
    // Only a missing folder is downloaded again.
    assert!(a.redownload_folder(&folder).is_err());

    b.redownload_folder(&folder).unwrap();
    world.settle(&mut [&mut a, &mut b]);
    assert_eq!(
        world
            .disk("mem:/b/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"v1"
    );
    let snap = b.snapshot();
    assert!(snap.warnings.is_empty(), "{:?}", snap.warnings);
    assert_eq!(snap.folders[0].status, FolderStatus::UpToDate);
    // The history stays.
    assert!(!b.get_timeline(&folder, 20).unwrap().entries.is_empty());
}

// ADR 0001, section 6, "Pin rotation": the server number of the key the server now presents,
// confirmed against the server CLI, becomes the pin; no other key is ever taken.
#[test]
fn the_server_number_confirmed_becomes_the_pin() {
    let world = World::new();
    let mut a = world.device(21, SharedKeychain::default());
    set_up(&mut a, true);
    a.add_folder("mem:/a/Docs", "Docs").unwrap();
    a.tick();
    assert!(
        a.confirm_server_number(&NEW_KEY).is_err(),
        "no number was shown"
    );
    world.shared.borrow_mut().presented_pin = Some(NEW_KEY);
    world.clock.advance(20_000);
    a.tick();
    assert!(a
        .snapshot()
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::ServerIdentity { .. })));

    let shown = a.server_number().unwrap();
    assert_eq!(shown.command, SERVER_NUMBER_COMMAND);
    assert_eq!(
        shown.number,
        NumberRows::of(&server_key_number(&ServerId::from_bytes(SERVER), &NEW_KEY))
    );
    // Security review N7: only the key whose number was shown, never another one.
    assert!(a.confirm_server_number(&[0x42; 32]).is_err());
    a.confirm_server_number(&shown.pin).unwrap();
    world.clock.advance(20_000);
    a.tick();
    assert!(
        !a.snapshot()
            .warnings
            .iter()
            .any(|w| matches!(w, Warning::ServerIdentity { .. })),
        "{:?}",
        a.snapshot().warnings
    );
    // Taken once: a second confirmation needs a number shown again.
    assert!(a.confirm_server_number(&shown.pin).is_err());
    // A server that presents no other key has no number to compare.
    assert!(a.server_number().is_err());
}

// ADR 0001, section 6: an offer of a device that still connects brings the new server
// identity; only an offer of this account, fresh and signed by a device of its log, is taken.
#[test]
fn an_offer_of_a_trusted_device_brings_the_new_server_key() {
    let world = World::new();
    let mut a = world.device(31, SharedKeychain::default());
    let mut b = world.device(32, SharedKeychain::default());
    set_up(&mut a, true);
    pair(&world, &mut a, &mut b);
    world.shared.borrow_mut().presented_pin = Some(NEW_KEY);
    world.settle(&mut [&mut a, &mut b]);
    for device in [&a, &b] {
        assert!(device
            .snapshot()
            .warnings
            .iter()
            .any(|w| matches!(w, Warning::ServerIdentity { .. })));
    }
    // A compares the number; then it connects and offers the new key to B.
    let shown = a.server_number().unwrap();
    a.confirm_server_number(&shown.pin).unwrap();
    a.tick();
    let offer = a.create_pairing_offer().unwrap();

    assert_eq!(
        b.fix_server_with_offer("nonsense").unwrap(),
        ApiResult::Err(FixServerError::NotALink)
    );
    // An offer of another account (on another server) is refused.
    let other_world = World::new();
    let mut c = other_world.device(33, SharedKeychain::default());
    set_up(&mut c, false);
    let foreign = c.create_pairing_offer().unwrap();
    assert_eq!(
        b.fix_server_with_offer(&foreign.link).unwrap(),
        ApiResult::Err(FixServerError::OtherAccount)
    );

    assert_eq!(
        b.fix_server_with_offer(&offer.link).unwrap(),
        ApiResult::Ok(())
    );
    world.settle(&mut [&mut a, &mut b]);
    assert!(
        !b.snapshot()
            .warnings
            .iter()
            .any(|w| matches!(w, Warning::ServerIdentity { .. })),
        "{:?}",
        b.snapshot().warnings
    );
    // B did not pair again: the account still has two devices.
    assert_eq!(b.list_devices().unwrap().devices.len(), 2);

    // An expired offer is refused.
    let late = a.create_pairing_offer().unwrap();
    world
        .clock
        .advance(i64::try_from(hangar_drive_crypto::pairing::OFFER_LIFETIME_MS).unwrap() + 1_000);
    assert_eq!(
        b.fix_server_with_offer(&late.link).unwrap(),
        ApiResult::Err(FixServerError::Expired)
    );
}

// UX 8.1: files another device deleted are one activity entry with "Wiederherstellen", which
// brings them back on every device.
#[test]
fn files_another_device_deleted_come_back_from_the_activity() {
    let world = World::new();
    let (mut a, mut b, _folder) = two_devices(&world);
    world
        .disk("mem:/a/Docs")
        .user_write(&p(&["notes.txt"]), b"n");
    world.settle(&mut [&mut a, &mut b]);
    assert!(world.disk("mem:/a/Docs").user_delete(&p(&["plan.txt"])));
    assert!(world.disk("mem:/a/Docs").user_delete(&p(&["notes.txt"])));
    // Past the delete delay of the planner.
    for _ in 0..6 {
        world.clock.advance(60_000);
        a.tick();
        b.tick();
    }
    assert!(world
        .disk("mem:/b/Docs")
        .read_all(&p(&["plan.txt"]))
        .is_none());
    let entry = b
        .snapshot()
        .activity
        .into_iter()
        .find_map(|e| match e {
            ActivityEntry::RemoteDeleted {
                id, count, device, ..
            } => Some((id, count, device)),
            _ => None,
        })
        .expect("a remote delete entry");
    assert_eq!(entry.1, 2);
    assert_eq!(entry.2, "Laptop");
    // A's own deletes are not offered back to A as another device's.
    assert!(!a
        .snapshot()
        .activity
        .iter()
        .any(|e| matches!(e, ActivityEntry::RemoteDeleted { .. })));

    assert_eq!(b.restore_remote_deleted(&entry.0).unwrap(), 2);
    world.settle(&mut [&mut a, &mut b]);
    for disk in ["mem:/a/Docs", "mem:/b/Docs"] {
        assert_eq!(world.disk(disk).read_all(&p(&["plan.txt"])).unwrap(), b"v1");
        assert_eq!(world.disk(disk).read_all(&p(&["notes.txt"])).unwrap(), b"n");
    }
    // A second time brings nothing: both are back already.
    assert_eq!(b.restore_remote_deleted(&entry.0).unwrap(), 0);
    assert!(b.restore_remote_deleted("a-unknown").is_err());
}

// Follow-up check N-3: a warning is hidden only while the engine shows it; an ID the window
// makes up is refused and hides nothing that appears later. Only "suspect device" is on the
// allowlist, so a shown "folder missing" is refused as well and stays.
#[test]
fn only_a_shown_warning_can_be_hidden() {
    let world = World::new();
    let (mut a, mut b, folder) = two_devices(&world);
    let id = format!("missing-{folder}");
    assert!(b.dismiss_warning(&id).is_err(), "not shown yet");
    assert!(b.dismiss_warning("made-up").is_err());
    let disk = world.disk("mem:/b/Docs");
    assert!(disk.user_delete(&hangar_drive_sync::folder::marker_path()));
    world.settle(&mut [&mut a, &mut b]);
    let shown = |b: &EngineCore| {
        b.snapshot()
            .warnings
            .iter()
            .any(|w| matches!(w, Warning::MissingFolder { .. }))
    };
    assert!(shown(&b), "the early attempt hid nothing");
    assert!(b.dismiss_warning(&id).is_err(), "not on the allowlist");
    assert!(shown(&b), "the refused attempt hid nothing");
}

// Skeleton check of device names: a new device whose name looks like one of the account's is
// named in the request, so the window and the native question can say so.
#[test]
fn a_pairing_request_names_a_device_that_looks_the_same() {
    let world = World::new();
    let mut a = world.device(1, SharedKeychain::default());
    let mut b = world.device(2, SharedKeychain::default());
    set_up(&mut a, false);
    let offer = a.create_pairing_offer().unwrap();
    // Cyrillic small a in "Laptop", the name of the device that invites.
    assert!(matches!(
        b.start_pairing(&offer.link, "L\u{0430}ptop").unwrap(),
        ApiResult::Ok(_)
    ));
    let request = a
        .tick()
        .into_iter()
        .find_map(|e| match e {
            BackendEvent::PairRequest { request } => Some(request),
            _ => None,
        })
        .expect("pair request");
    assert_eq!(request.similar_to.as_deref(), Some("Laptop"));
    assert_eq!(
        a.pair_request(&request.offer_id)
            .unwrap()
            .similar_to
            .as_deref(),
        Some("Laptop")
    );
    // A name that does not look like any is not flagged.
    assert_eq!(a.similar_device_name("Desktop", None), None);
}

// A rename to a name that looks like another device's needs the confirmation the app gets in
// the native question; the device's own name in another case is no look-alike of itself.
#[test]
fn a_rename_to_a_look_alike_needs_the_confirmation() {
    let world = World::new();
    let (mut a, _b, _folder) = two_devices(&world);
    let devices = a.list_devices().unwrap().devices;
    let me = devices.iter().find(|d| d.is_this).unwrap().id.clone();
    let other = devices.iter().find(|d| !d.is_this).unwrap().id.clone();
    assert_eq!(
        a.rename_device(&other, "LAPT0P", false).unwrap(),
        ApiResult::Err(DeviceNameError::LooksLike)
    );
    let names = |a: &EngineCore| {
        a.list_devices()
            .unwrap()
            .devices
            .into_iter()
            .map(|d| d.name)
            .collect::<Vec<_>>()
    };
    assert!(!names(&a).contains(&"LAPT0P".to_owned()));
    assert_eq!(
        a.rename_device(&other, "LAPT0P", true).unwrap(),
        ApiResult::Ok(())
    );
    assert!(names(&a).contains(&"LAPT0P".to_owned()));
    assert_eq!(
        a.rename_device(&me, "Mein Rechner", false).unwrap(),
        ApiResult::Ok(())
    );
    assert_eq!(
        a.rename_device(&me, "MEIN RECHNER", false).unwrap(),
        ApiResult::Ok(())
    );
}

// Follow-up check N-1: the engine counts the files a folder reset makes disappear before the
// native question.
#[test]
fn a_reset_preview_counts_the_files_that_disappear() {
    let world = World::new();
    let (mut a, mut b, folder) = two_devices(&world);
    let first = a
        .get_timeline(&folder, 20)
        .unwrap()
        .entries
        .last()
        .unwrap()
        .id
        .clone();
    world.disk("mem:/a/Docs").user_write(&p(&["new.txt"]), b"n");
    world
        .disk("mem:/a/Docs")
        .user_write(&p(&["more.txt"]), b"m");
    world
        .disk("mem:/a/Docs")
        .user_write(&p(&["plan.txt"]), b"v2");
    world.settle(&mut [&mut a, &mut b]);
    let preview = a.reset_folder_preview(&folder, &first).unwrap();
    assert_eq!(preview.folder_name, "Docs");
    assert_eq!(preview.vanishing, 2, "plan.txt changes but stays");
    // Nothing changed by the preview.
    assert_eq!(
        world
            .disk("mem:/b/Docs")
            .read_all(&p(&["new.txt"]))
            .unwrap(),
        b"n"
    );
}

/// A and B with 150 files in "Docs"; A deletes 120 of them (approving its own question), and
/// B holds the deletes (ADR 0001, amendment "incoming mass deletes").
fn incoming_held(world: &World) -> (EngineCore, EngineCore, String) {
    let (mut a, mut b, folder) = two_devices(world);
    let disk_a = world.disk("mem:/a/Docs");
    for i in 0..150 {
        assert!(disk_a.user_write(&p(&[&format!("f{i:03}.txt")]), b"x"));
    }
    world.settle(&mut [&mut a, &mut b]);
    // A day later the files are no longer new on B: deleting them is no ordinary cleanup of
    // what just arrived (security review M3).
    world
        .clock
        .advance(hangar_drive_sync::folder::LONG_DELETE_WINDOW_MS);
    world.settle(&mut [&mut a, &mut b]);
    for i in 0..120 {
        assert!(disk_a.user_delete(&p(&[&format!("f{i:03}.txt")])));
    }
    world.settle(&mut [&mut a, &mut b]);
    a.resolve_mass_delete(&folder, false).unwrap();
    world.settle(&mut [&mut a, &mut b]);
    (a, b, folder)
}

type Incoming = (String, Option<String>, u64, Vec<String>, Option<i64>);

fn incoming_warning(core: &EngineCore) -> Option<Incoming> {
    core.snapshot().warnings.into_iter().find_map(|w| match w {
        Warning::IncomingDelete {
            id,
            device,
            count,
            sample,
            device_added,
            ..
        } => Some((id, device, count, sample, device_added)),
        _ => None,
    })
}

#[test]
fn many_deletes_of_another_device_wait_for_the_person() {
    let world = World::new();
    let (mut a, mut b, folder) = incoming_held(&world);
    let (id, device, count, sample, added) = incoming_warning(&b).expect("the question on B");
    assert_eq!(id, format!("incomingDelete-{folder}"));
    assert_eq!(device.as_deref(), Some("Laptop"));
    // The day the verified log added the device, as the device list shows it (L5).
    let listed = b
        .list_devices()
        .unwrap()
        .devices
        .into_iter()
        .find(|d| d.name == "Laptop")
        .map(|d| d.added);
    assert!(added.is_some());
    assert_eq!(added, listed);
    assert_eq!(count, 120);
    assert_eq!(sample.len(), 3);
    assert!(incoming_warning(&a).is_none(), "A deleted, A is not asked");
    let list = b.list_incoming_delete(&folder).unwrap();
    assert_eq!(list.len(), 120);
    assert!(list.contains(&"f000.txt".to_owned()));
    let disk_b = world.disk("mem:/b/Docs");
    assert!(disk_b.read_all(&p(&["f000.txt"])).is_some(), "still on B");
    // An answer to an older state is refused; the current one lets them go.
    let revision = b.incoming_delete_revision(&folder).unwrap();
    assert!(b
        .resolve_incoming_delete(&folder, false, revision + 1)
        .is_err());
    assert_eq!(
        b.resolve_incoming_delete(&folder, false, revision).unwrap(),
        120
    );
    world.settle(&mut [&mut a, &mut b]);
    assert!(disk_b.read_all(&p(&["f000.txt"])).is_none());
    assert!(disk_b.read_all(&p(&["f149.txt"])).is_some());
    assert!(incoming_warning(&b).is_none());
}

#[test]
fn held_deletes_of_another_device_come_back_on_every_device() {
    let world = World::new();
    let (mut a, mut b, folder) = incoming_held(&world);
    assert!(incoming_warning(&b).is_some());
    assert_eq!(b.resolve_incoming_delete(&folder, true, 0).unwrap(), 120);
    world.settle(&mut [&mut a, &mut b]);
    for disk in ["mem:/a/Docs", "mem:/b/Docs"] {
        assert!(
            world.disk(disk).read_all(&p(&["f000.txt"])).is_some(),
            "{disk}"
        );
        assert!(
            world.disk(disk).read_all(&p(&["f119.txt"])).is_some(),
            "{disk}"
        );
    }
    assert!(incoming_warning(&b).is_none());
    assert!(incoming_warning(&a).is_none());
}
