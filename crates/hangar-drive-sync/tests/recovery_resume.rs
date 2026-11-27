//! Account recovery past its one append (security review "recovery", H1, M1 and L1): once the
//! batch that adds the new device and removes the old ones is sent, no failure may lose the new
//! device's key, since it may be the only key the account has left. A lost answer, the end of the
//! app before the join, a record under an older epoch and a record nobody can open all end with
//! the new device in the account and the account usable; an append that did not go through
//! leaves the code valid. A device added while the person chooses is offered too, and an account
//! left without a recovery device says so.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_sync::api::{
    ApiResult, BackendEvent, PairResult, RecoverError, RecoveryCodeView, SetupState,
};
use hangar_drive_sync::engine::{EngineCore, EnginePorts, EngineSettings};
use hangar_drive_sync::error::SyncError;
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedKeychain,
};
use hangar_drive_sync::ports::{FileSystem, NetError, ServerApi};

type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

/// The keychain entry of a pending recovery's device key.
const PENDING_KEY: &str = "recovery-identity";

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

    /// An installation with its own keychain and local index; the same two make the same
    /// installation after a restart of the app.
    fn device(&self, seed: u64, keychain: &SharedKeychain, store: &MemStore) -> EngineCore {
        self.device_with(seed, keychain, store, None)
    }

    /// [`World::device`] whose server connections end the log one entry early while `hide` is
    /// set (see [`Hiding`]).
    fn device_with(
        &self,
        seed: u64,
        keychain: &SharedKeychain,
        store: &MemStore,
        hide: Option<Rc<Cell<bool>>>,
    ) -> EngineCore {
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
                let inner = Box::new(MemServer::connect_pinned(&server, device, config.pin))
                    as Box<dyn ServerApi>;
                Ok(match &hide {
                    Some(hide) => Box::new(Hiding {
                        inner,
                        hide: Rc::clone(hide),
                    }) as Box<dyn ServerApi>,
                    None => inner,
                })
            }),
            roots: Box::new(|path: &Path, _existing: &[PathBuf]| Ok(path.to_path_buf())),
        };
        EngineCore::open(ports, EngineSettings::default()).unwrap()
    }

    /// A fresh installation.
    fn fresh(&self, seed: u64) -> (EngineCore, SharedKeychain, MemStore) {
        let keys = SharedKeychain::default();
        let store = MemStore::new();
        (self.device(seed, &keys, &store), keys, store)
    }

    fn disk(&self, path: &str) -> Arc<MemFs> {
        self.disks.borrow()[&PathBuf::from(path)].clone()
    }

    fn rounds(&self, device: &mut EngineCore, n: usize) {
        for _ in 0..n {
            self.clock.advance(20_000);
            device.tick();
        }
    }
}

/// A server whose log ends one entry early while `hide` is set; the first append clears it.
/// It stands for a race (a device added right between the recovery's last read and its append)
/// or for a server that lets such an add in right then.
struct Hiding {
    inner: Box<dyn ServerApi>,
    hide: Rc<Cell<bool>>,
}

macro_rules! forward {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {
        $(fn $name(&mut self, $($arg: $ty),*) -> Result<$out, NetError> {
            self.inner.$name($($arg),*)
        })*
    };
}

impl ServerApi for Hiding {
    fn log(&mut self, after: u64) -> Result<LogPage, NetError> {
        let mut page = self.inner.log(after)?;
        if self.hide.get() && page.length > 0 {
            let shown = page.length - 1;
            page.length = shown;
            let keep = shown.saturating_sub(page.first_index.saturating_sub(1));
            page.entries.truncate(usize::try_from(keep).unwrap_or(0));
        }
        Ok(page)
    }
    fn append_log(&mut self, request: &LogAppendRequest) -> Result<LogAppendResponse, NetError> {
        self.hide.set(false);
        self.inner.append_log(request)
    }
    forward! {
        create_account(r: &CreateAccountRequest) -> CreateAccountResponse;
        challenge(a: &AccountId, d: &DeviceId) -> ChallengeResponse;
        proof(a: &AccountId, d: &DeviceId, c: &Challenge, s: &Signature) -> SessionResponse;
        epoch_key(e: Epoch) -> WrappedKeyResponse;
        record(k: &RecordKey) -> Option<RecordResponse>;
        put_record(k: &RecordKey, p: &RecordPut) -> ();
        feed(a: u64) -> FeedPage;
        reserve_pairing(i: &PairingId) -> PairingReservation;
        post_pairing(i: &PairingId, r: &PairingRequest) -> ();
        get_pairing(i: &PairingId) -> Option<PairingRequest>;
        close_pairing(i: &PairingId) -> ();
        missing_objects(f: &FolderId, i: &[ObjectId]) -> Vec<ObjectId>;
        put_object(f: &FolderId, i: &ObjectId, b: &[u8]) -> UploadResponse;
        get_object(f: &FolderId, i: &ObjectId) -> Vec<u8>;
        commit(f: &FolderId, r: &CommitRequest) -> CommitResponse;
        commits(f: &FolderId, a: u64) -> DeltaPage;
        retire(f: &FolderId) -> ();
        bring_back(f: &FolderId) -> ();
    }
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

/// A with an account and a folder "Docs" holding `plan.txt`; returns the code, the folder and
/// A's device ID.
fn lost_laptop(world: &World) -> (EngineCore, RecoveryCodeView, String, String) {
    let (mut a, _, _) = world.fresh(1);
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.confirm_recovery_group(&group).unwrap());
    let folder = a.add_folder("mem:/a/Docs", "Docs").unwrap();
    world
        .disk("mem:/a/Docs")
        .user_write(&p(&["plan.txt"]), b"kept");
    a.tick();
    a.tick();
    let id = a.list_devices().unwrap().devices[0].id.clone();
    (a, code, folder, id)
}

/// Pairs `b` into the account of `a`; returns `b`'s device ID.
fn pair(world: &World, a: &mut EngineCore, b: &mut EngineCore) -> String {
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
    assert!(b.tick().into_iter().any(|e| matches!(
        e,
        BackendEvent::PairResult {
            result: PairResult::Joined { .. }
        }
    )));
    b.list_devices()
        .unwrap()
        .devices
        .into_iter()
        .find(|d| d.is_this)
        .expect("this device")
        .id
}

/// The recovered device is the account's only device, the old code is used up, and the folder's
/// files come back.
fn usable(world: &World, c: &mut EngineCore, code: &RecoveryCodeView, folder: &str) {
    assert_eq!(c.snapshot().setup, SetupState::Done);
    let devices = c.list_devices().unwrap().devices;
    assert_eq!(devices.len(), 1, "{devices:?}");
    assert!(devices[0].is_this);
    let (mut late, _, _) = world.fresh(99);
    assert_eq!(
        late.recover_account(&code.sheet.link, &code.groups.join(""), "Late")
            .unwrap(),
        ApiResult::Err(RecoverError::Used)
    );
    c.add_account_folder(folder, "mem:/c/Docs").unwrap();
    world.rounds(c, 3);
    assert_eq!(
        world
            .disk("mem:/c/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"kept"
    );
}

fn has_warning(core: &EngineCore, kind: &str) -> bool {
    core.snapshot().warnings.iter().any(|w| {
        serde_json::to_value(w)
            .ok()
            .is_some_and(|v| v["kind"] == kind && v["id"] == kind)
    })
}

// H1: the server takes the batch, and its answer is lost. The new device's own verified log shows
// the batch, so it joins at once instead of throwing its key away.
#[test]
fn a_lost_answer_after_the_append_still_joins() {
    let world = World::new();
    let (_a, code, folder, lost) = lost_laptop(&world);
    let (mut c, keys, _) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    world.shared.borrow_mut().lose_next_append_reply = true;
    let renewed = c
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap();
    assert_ne!(renewed.groups, code.groups);
    assert!(!keys.keys().contains(&PENDING_KEY.to_owned()));
    usable(&world, &mut c, &code, &folder);
    assert!(!has_warning(&c, "noRecoveryCode"));
}

// H1 and L1: the app ends right after the append, before the join. The next start finds the
// pending recovery, the new device joins and writes the barriers, and the window is told that no
// recovery code works until a new one is confirmed.
#[test]
fn a_recovery_cut_off_before_the_join_finishes_after_a_restart() {
    let world = World::new();
    let (_a, code, folder, lost) = lost_laptop(&world);
    let (mut c, keys, store) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    world.shared.borrow_mut().offline_after_next_append = true;
    assert!(matches!(
        c.finish_recovery_cleanup(std::slice::from_ref(&lost)),
        Err(e) if e.is_offline()
    ));
    assert_eq!(c.snapshot().setup, SetupState::Needed);
    assert!(has_warning(&c, "recoveryPending"));
    assert!(
        keys.keys().contains(&PENDING_KEY.to_owned()),
        "the key stays"
    );
    drop(c);

    world.shared.borrow_mut().online = true;
    let mut c = world.device(13, &keys, &store);
    assert!(has_warning(&c, "recoveryPending"));
    c.tick();
    assert_eq!(c.snapshot().setup, SetupState::Done);
    assert!(!has_warning(&c, "recoveryPending"));
    assert!(!keys.keys().contains(&PENDING_KEY.to_owned()));
    assert!(has_warning(&c, "noRecoveryCode"));
    assert!(
        c.dismiss_warning("noRecoveryCode").is_err(),
        "it cannot be hidden"
    );
    // The window offers a new code; confirming it ends the warning.
    let fresh = c.renew_recovery_code().unwrap();
    let group = fresh.groups[fresh.check_group as usize - 1].clone();
    assert!(c.confirm_recovery_group(&group).unwrap());
    assert!(!has_warning(&c, "noRecoveryCode"));
    usable(&world, &mut c, &code, &folder);
    let mut later = world.fresh(14).0;
    assert_eq!(
        later
            .recover_account(&fresh.sheet.link, &fresh.groups.join(""), "Später")
            .unwrap(),
        ApiResult::Ok(())
    );
}

// H1: after the restart the server is still out of reach, and the person types the code again
// once it is back: the earlier attempt's device joins, without a second append.
#[test]
fn typing_the_code_again_finishes_a_pending_recovery() {
    let world = World::new();
    let (_a, code, folder, lost) = lost_laptop(&world);
    let (mut c, keys, store) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    world.shared.borrow_mut().offline_after_next_append = true;
    assert!(c
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .is_err());
    drop(c);
    let mut c = world.device(13, &keys, &store);
    c.tick();
    assert_eq!(c.snapshot().setup, SetupState::Needed, "still offline");
    world.shared.borrow_mut().online = true;
    let log_length = world.shared.borrow().account_state().unwrap().len();
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    assert_eq!(c.snapshot().setup, SetupState::Done);
    c.finish_recovery_cleanup(&[]).unwrap();
    // Barriers and the new recovery device; never a second recovery batch.
    assert!(world.shared.borrow().account_state().unwrap().len() > log_length);
    assert!(!has_warning(&c, "noRecoveryCode"));
    usable(&world, &mut c, &code, &folder);
}

// H1: the append is lost on its way and the server never took it. The recovery device's log still
// lists the recovery device, so nothing happened: the key and the marker go, and the same code
// works for the next try.
#[test]
fn an_append_that_did_not_go_through_starts_over_with_the_same_code() {
    let world = World::new();
    let (_a, code, folder, lost) = lost_laptop(&world);
    let (mut c, keys, _) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    let log_length = world.shared.borrow().account_state().unwrap().len();
    world.shared.borrow_mut().drop_next_append = true;
    assert!(c
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .is_err());
    assert_eq!(
        world.shared.borrow().account_state().unwrap().len(),
        log_length
    );
    assert_eq!(c.snapshot().setup, SetupState::Needed);
    assert!(!has_warning(&c, "recoveryPending"));
    assert_eq!(keys.keys(), Vec::<String>::new(), "no key is left");
    // Another installation could start with the same code; this one simply tries again.
    let (mut other, _, _) = world.fresh(15);
    assert_eq!(
        other
            .recover_account(&code.sheet.link, &code.groups.join("-"), "Other")
            .unwrap(),
        ApiResult::Ok(())
    );
    c.finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap();
    usable(&world, &mut c, &code, &folder);
}

fn device_names_key() -> RecordKey {
    RecordKey {
        kind: RecordKind::DeviceNames,
        folder: None,
    }
}

// H1: the account's device names are under an epoch older than the one the recovery device can
// open (here a server shows the record as it was before the last rotation). The new device has
// only the secrets of the current epoch and the one after the batch, so the record counts as
// missing, and as the only device left it writes the names anew.
#[test]
fn a_record_under_an_older_epoch_does_not_stop_the_join() {
    let world = World::new();
    let (mut a, _, folder, lost) = lost_laptop(&world);
    let (version, sealed) = world
        .shared
        .borrow()
        .stored_record(&device_names_key())
        .unwrap();
    // A renewed code removes the old recovery device: a rotation, and every record moves on.
    let code = a.renew_recovery_code().unwrap();
    let group = code.groups[code.check_group as usize - 1].clone();
    world.clock.advance(1_000);
    assert!(a.confirm_recovery_group(&group).unwrap());
    assert!(
        world
            .shared
            .borrow()
            .stored_record(&device_names_key())
            .unwrap()
            .0
            > version
    );
    world
        .shared
        .borrow_mut()
        .set_stored_record(device_names_key(), version, sealed);

    let (mut c, _, _) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    c.finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap();
    let devices = c.list_devices().unwrap().devices;
    assert_eq!(devices[0].name, "Neu");
    usable(&world, &mut c, &code, &folder);
}

// H1: a device of the account (H) leaves a record that is signed but opens for nobody (the
// in-memory server, like the real one, does not open records; a damaged record stands for one H
// sealed with a key no device has). The recovery removes A and H; the new device takes the record
// as missing and writes it anew instead of stopping.
#[test]
fn an_unreadable_record_of_another_device_does_not_stop_the_join() {
    let world = World::new();
    let (mut a, code, folder, lost) = lost_laptop(&world);
    let (mut h, _, _) = world.fresh(2);
    let hostile = pair(&world, &mut a, &mut h);
    assert_eq!(
        h.rename_device(&hostile, "Hostile", true).unwrap(),
        ApiResult::Ok(())
    );
    let (version, mut sealed) = world
        .shared
        .borrow()
        .stored_record(&device_names_key())
        .unwrap();
    if let Some(last) = sealed.last_mut() {
        *last ^= 0xff;
    }
    world
        .shared
        .borrow_mut()
        .set_stored_record(device_names_key(), version, sealed);

    let (mut c, _, _) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    let offered: Vec<String> = c
        .recovery_devices()
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(offered.len(), 2);
    c.finish_recovery_cleanup(&[lost, hostile]).unwrap();
    assert_eq!(c.list_devices().unwrap().devices[0].name, "Neu");
    usable(&world, &mut c, &code, &folder);
}

// M1: a device added to the account between the list and the append would survive the recovery
// unseen. The append is refused without writing anything, and the list offers the new device.
#[test]
fn a_device_added_while_the_person_chooses_is_offered_too() {
    let world = World::new();
    let (mut a, code, folder, lost) = lost_laptop(&world);
    let (mut c, _, _) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    assert_eq!(c.recovery_devices().unwrap().len(), 1);
    let (mut b, _, _) = world.fresh(3);
    let added = pair(&world, &mut a, &mut b);
    let log_length = world.shared.borrow().account_state().unwrap().len();
    assert_eq!(
        c.finish_recovery_cleanup(std::slice::from_ref(&lost)),
        Err(SyncError::RecoveryListChanged)
    );
    assert_eq!(
        world.shared.borrow().account_state().unwrap().len(),
        log_length,
        "nothing was written"
    );
    let offered: Vec<String> = c
        .recovery_devices()
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert!(
        offered.contains(&added) && offered.contains(&lost),
        "{offered:?}"
    );
    c.finish_recovery_cleanup(&[lost, added]).unwrap();
    usable(&world, &mut c, &code, &folder);
}

// H1: the record H leaves unreadable is the folder list. Nothing else would ever write it, and
// every later refresh of the new device would stop at it, so the new device, the only one left,
// writes an empty folder list in its place: the account stays usable, and a new folder syncs.
#[test]
fn an_unreadable_folder_list_becomes_an_empty_one() {
    let world = World::new();
    let (mut a, code, _, lost) = lost_laptop(&world);
    let (mut h, _, _) = world.fresh(2);
    let hostile = pair(&world, &mut a, &mut h);
    let folders = RecordKey {
        kind: RecordKind::Folders,
        folder: None,
    };
    let (version, mut sealed) = world.shared.borrow().stored_record(&folders).unwrap();
    if let Some(last) = sealed.last_mut() {
        *last ^= 0xff;
    }
    world
        .shared
        .borrow_mut()
        .set_stored_record(folders, version, sealed);

    let (mut c, keys, store) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    c.finish_recovery_cleanup(&[lost, hostile]).unwrap();
    assert!(world.shared.borrow().stored_record(&folders).unwrap().0 > version);
    // Also after a restart, which keeps nothing of the join but what it stored.
    drop(c);
    let mut c = world.device(13, &keys, &store);
    world.rounds(&mut c, 2);
    assert!(c.snapshot().remote_folders.is_empty());
    c.add_folder("mem:/c/New", "New").unwrap();
    world
        .disk("mem:/c/New")
        .user_write(&p(&["new.txt"]), b"new");
    world.rounds(&mut c, 2);
    assert_eq!(c.snapshot().folders.len(), 1);
    assert_eq!(
        c.snapshot().folders[0].status,
        hangar_drive_sync::api::FolderStatus::UpToDate
    );
}

// H1: the app ended in the middle of the join, after it stored the new identity under the device
// identity's entry and before it stored the account. The next try removes exactly that copy and
// joins, instead of refusing as a device that already belongs to an account.
#[test]
fn a_join_cut_off_midway_is_tried_again() {
    use hangar_drive_sync::ports::Keychain;
    let world = World::new();
    let (_a, code, folder, lost) = lost_laptop(&world);
    let (mut c, keys, store) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    world.shared.borrow_mut().offline_after_next_append = true;
    assert!(c
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .is_err());
    drop(c);
    let mut half = keys.clone();
    // The pending entry is a format byte, the marker's digest and the identity.
    let entry = half.load(PENDING_KEY).unwrap().unwrap();
    half.store("device-identity", &entry[33..]).unwrap();

    world.shared.borrow_mut().online = true;
    let mut c = world.device(13, &keys, &store);
    c.tick();
    assert_eq!(c.snapshot().setup, SetupState::Done);
    usable(&world, &mut c, &code, &folder);
}

// The app tells "code used" from other failures by its own error variant: another installation
// used the code between the list and the append. Nothing is written and nothing stays pending.
#[test]
fn a_code_used_in_between_is_its_own_error() {
    let world = World::new();
    let (_a, code, _, lost) = lost_laptop(&world);
    let (mut c, keys, _) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    let (mut other, _, _) = world.fresh(16);
    assert_eq!(
        other
            .recover_account(&code.sheet.link, &code.groups.join("-"), "Other")
            .unwrap(),
        ApiResult::Ok(())
    );
    other
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap();
    let error = c
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap_err();
    assert_eq!(error, SyncError::RecoveryCodeUsed);
    assert_eq!(
        serde_json::to_value(error.code()).unwrap(),
        "recoveryCodeUsed"
    );
    assert_eq!(keys.keys(), Vec::<String>::new());
    assert!(!has_warning(&c, "recoveryPending"));
}

// Follow-up review M1: the recovery's reads miss a device added right before its append, so the
// append, built on the shorter log, is refused. The log the recovery device reads then is
// longer than the one the person chose from: the person is told that the devices changed and
// sees the new device, instead of a retry with the old choice that leaves it in the account.
#[test]
fn a_device_added_between_read_and_append_is_offered_before_the_retry() {
    let world = World::new();
    let (mut a, code, folder, lost) = lost_laptop(&world);
    let (mut b, _, _) = world.fresh(3);
    let added = pair(&world, &mut a, &mut b);

    let hide = Rc::new(Cell::new(true));
    let keys = SharedKeychain::default();
    let mut c = world.device_with(12, &keys, &MemStore::new(), Some(Rc::clone(&hide)));
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    let offered: Vec<String> = c
        .recovery_devices()
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(offered, vec![lost.clone()], "B is hidden at first");

    assert_eq!(
        c.finish_recovery_cleanup(std::slice::from_ref(&lost)),
        Err(SyncError::RecoveryListChanged)
    );
    assert_eq!(keys.keys(), Vec::<String>::new(), "nothing is pending");
    let offered: Vec<String> = c
        .recovery_devices()
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert!(
        offered.contains(&added) && offered.contains(&lost),
        "{offered:?}"
    );
    c.finish_recovery_cleanup(&[lost, added]).unwrap();
    usable(&world, &mut c, &code, &folder);
}

fn folders_unreadable(core: &EngineCore) -> Option<serde_json::Value> {
    core.snapshot().warnings.iter().find_map(|w| {
        let v = serde_json::to_value(w).ok()?;
        (v["kind"] == "foldersUnreadable").then_some(v)
    })
}

// Follow-up review LOW 2: the server damages a folder's key ring during the join. The folder
// stays in the account's list, the window names it, and once the server shows the intact ring
// again the new device opens it and the folder can be synced.
#[test]
fn a_ring_the_server_damages_during_the_join_comes_back() {
    let world = World::new();
    let (_a, code, folder, lost) = lost_laptop(&world);
    let key = RecordKey {
        kind: RecordKind::FolderKeys,
        folder: Some(FolderId::from_hex(&folder).unwrap()),
    };
    let (version, original) = world.shared.borrow().stored_record(&key).unwrap();
    let mut damaged = original.clone();
    if let Some(last) = damaged.last_mut() {
        *last ^= 0xff;
    }
    world
        .shared
        .borrow_mut()
        .set_stored_record(key, version, damaged);

    let (mut c, keys, store) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    c.finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap();
    world.rounds(&mut c, 2);
    let warning = folders_unreadable(&c).expect("the folder is named");
    assert_eq!(warning["id"], "foldersUnreadable");
    assert_eq!(warning["folders"], serde_json::json!(["Docs"]));
    assert_eq!(warning["folderList"], false);
    assert!(c.dismiss_warning("foldersUnreadable").is_err());
    // Kept over a restart.
    drop(c);
    let mut c = world.device(13, &keys, &store);
    world.rounds(&mut c, 1);
    assert!(folders_unreadable(&c).is_some());

    // The server is honest again: the intact ring is back.
    world
        .shared
        .borrow_mut()
        .set_stored_record(key, version, original);
    world.rounds(&mut c, 2);
    assert!(
        folders_unreadable(&c).is_none(),
        "{:?}",
        c.snapshot().warnings
    );
    assert_eq!(c.snapshot().remote_folders.len(), 1);
    usable(&world, &mut c, &code, &folder);
    assert!(
        c.snapshot().warnings.is_empty(),
        "{:?}",
        c.snapshot().warnings
    );
}

// Follow-up review LOW 3: the marker in the local index steers server, account and removals; a
// changed marker is refused instead of being acted on, and the key stays.
#[test]
fn a_changed_marker_is_refused() {
    use hangar_drive_sync::ports::Store;
    let world = World::new();
    let (_a, code, _, lost) = lost_laptop(&world);
    let (mut c, keys, store) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    world.shared.borrow_mut().offline_after_next_append = true;
    assert!(c
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .is_err());
    drop(c);
    let mut index = store.clone();
    let marker = index.account_value("recovery-pending").unwrap().unwrap();
    let text = String::from_utf8(marker).unwrap();
    let changed = text.replace("\"name\":\"Neu\"", "\"name\":\"Evil\"");
    assert_ne!(changed, text);
    index
        .put_account_value("recovery-pending", changed.as_bytes())
        .unwrap();

    world.shared.borrow_mut().online = true;
    let mut c = world.device(13, &keys, &store);
    c.tick();
    assert_eq!(c.snapshot().setup, SetupState::Needed);
    assert!(has_warning(&c, "recoveryPending"));
    assert!(
        keys.keys().contains(&PENDING_KEY.to_owned()),
        "the key stays"
    );
    assert!(matches!(
        c.finish_recovery_cleanup(&[]),
        Err(SyncError::Corrupt(_)) | Err(SyncError::Invalid(_))
    ));
}

// Follow-up review LOW 7: "reset this device" while a recovery is pending would destroy what may
// be the account's only key. It is refused with its own error; only the explicit forced reset
// removes it.
#[test]
fn a_reset_during_a_pending_recovery_needs_the_forced_reset() {
    let world = World::new();
    let (_a, code, _, lost) = lost_laptop(&world);
    let (mut c, keys, _) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    world.shared.borrow_mut().offline_after_next_append = true;
    assert!(c
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .is_err());
    let error = c.reset_device().unwrap_err();
    assert_eq!(error, SyncError::RecoveryPending);
    assert_eq!(
        serde_json::to_value(error.code()).unwrap(),
        "recoveryPending"
    );
    assert!(keys.keys().contains(&PENDING_KEY.to_owned()));
    c.reset_device_discarding_recovery().unwrap();
    assert_eq!(keys.keys(), Vec::<String>::new());
    assert!(!has_warning(&c, "recoveryPending"));
}

// Follow-up review LOW 5: with another regular device left, the new device does not write the
// device names alone when it could not read them (that would drop every other name); the device
// that is left re-seals them under the new epoch, and the new device's name follows.
#[test]
fn unreadable_names_wait_for_the_device_that_is_left() {
    let world = World::new();
    let (mut a, code, _, lost) = lost_laptop(&world);
    let (mut b, _, _) = world.fresh(3);
    let kept = pair(&world, &mut a, &mut b);
    let (version, mut sealed) = world
        .shared
        .borrow()
        .stored_record(&device_names_key())
        .unwrap();
    if let Some(last) = sealed.last_mut() {
        *last ^= 0xff;
    }
    world
        .shared
        .borrow_mut()
        .set_stored_record(device_names_key(), version, sealed.clone());

    let (mut c, _, _) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    c.finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap();
    assert_eq!(
        world
            .shared
            .borrow()
            .stored_record(&device_names_key())
            .unwrap(),
        (version, sealed),
        "the new device wrote no names of its own"
    );
    // B is left; it re-seals, and C's name follows.
    for _ in 0..4 {
        world.clock.advance(20_000);
        b.tick();
        c.tick();
    }
    let devices = c.list_devices().unwrap().devices;
    assert_eq!(devices.len(), 2, "{devices:?}");
    assert!(devices.iter().any(|d| d.id == kept && d.name == "Desktop"));
    assert!(
        devices.iter().any(|d| d.is_this && d.name == "Neu"),
        "{devices:?}"
    );
}

// Follow-up review LOW 4: a marker that outlives the finished join (its removal failed) does not
// make the device lenient again. The server shows the folder list as it was under an older epoch;
// a device past its join leaves it alone instead of putting it aside as "unreadable since the
// recovery" (which would also show the folder list warning).
#[test]
fn a_marker_left_after_the_join_brings_no_leniency_back() {
    use hangar_drive_sync::ports::{Keychain, Store};
    let world = World::new();
    let (mut a, _, _, lost) = lost_laptop(&world);
    let list = RecordKey {
        kind: RecordKind::Folders,
        folder: None,
    };
    let (old_version, old) = world.shared.borrow().stored_record(&list).unwrap();
    // A renewed code: a rotation, and the list moves to the next epoch.
    let code = a.renew_recovery_code().unwrap();
    let group = code.groups[code.check_group as usize - 1].clone();
    world.clock.advance(1_000);
    assert!(a.confirm_recovery_group(&group).unwrap());

    let (mut c, keys, store) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    world.shared.borrow_mut().offline_after_next_append = true;
    assert!(c
        .finish_recovery_cleanup(std::slice::from_ref(&lost))
        .is_err());
    drop(c);
    let marker = store.account_value("recovery-pending").unwrap().unwrap();
    let entry = keys.load(PENDING_KEY).unwrap().unwrap();
    world.shared.borrow_mut().online = true;
    let mut c = world.device(13, &keys, &store);
    c.tick();
    assert_eq!(c.snapshot().setup, SetupState::Done);
    assert!(folders_unreadable(&c).is_none());
    drop(c);

    world
        .shared
        .borrow_mut()
        .set_stored_record(list, old_version, old);
    let (mut index, mut keychain) = (store.clone(), keys.clone());
    index
        .put_account_value("recovery-pending", &marker)
        .unwrap();
    keychain.store(PENDING_KEY, &entry).unwrap();

    let mut c = world.device(14, &keys, &store);
    world.rounds(&mut c, 2);
    assert!(
        folders_unreadable(&c).is_none(),
        "{:?}",
        c.snapshot().warnings
    );
    assert_eq!(c.snapshot().remote_folders.len(), 1);
}

// Follow-up: the app ends after a ring that was unreadable since the join opened and before its
// folder got the barriers of the recovery's removals (here the barrier commit fails, then the
// engine is made anew). The due barriers are stored with the account, so the next start writes
// them and the folder does not stop at the removed device's heads.
#[test]
fn barriers_for_a_ring_that_came_back_survive_a_restart() {
    let world = World::new();
    let (_a, code, folder, lost) = lost_laptop(&world);
    let key = RecordKey {
        kind: RecordKind::FolderKeys,
        folder: Some(FolderId::from_hex(&folder).unwrap()),
    };
    let (version, original) = world.shared.borrow().stored_record(&key).unwrap();
    let mut damaged = original.clone();
    if let Some(last) = damaged.last_mut() {
        *last ^= 0xff;
    }
    world
        .shared
        .borrow_mut()
        .set_stored_record(key, version, damaged);
    let (mut c, keys, store) = world.fresh(12);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
    c.finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap();
    world.rounds(&mut c, 1);
    assert!(folders_unreadable(&c).is_some());

    // The ring is back, but the barrier cannot be written before the app ends.
    world
        .shared
        .borrow_mut()
        .set_stored_record(key, version, original);
    world.shared.borrow_mut().refuse_commits = Some(ErrorCode::Internal);
    world.rounds(&mut c, 1);
    assert!(folders_unreadable(&c).is_none());
    drop(c);
    world.shared.borrow_mut().refuse_commits = None;

    let mut c = world.device(13, &keys, &store);
    world.rounds(&mut c, 1);
    usable(&world, &mut c, &code, &folder);
    assert!(
        c.snapshot().warnings.is_empty(),
        "{:?}",
        c.snapshot().warnings
    );
}
