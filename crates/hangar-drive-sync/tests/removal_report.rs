//! Security review H2: "this device was removed" from the server. Only the answer to the
//! device's own proof counts (`NetError::DeviceRemoved`, which the HTTP client gives only for
//! the proof route). Without device log entries that show the removal from the device's own
//! head (here: the bare code), the engine stops syncing, shows a warning and forgets the
//! account only after the person confirms, however long the server keeps saying it. The same
//! code on any other call never makes it forget. The verified removal is `removal_proof.rs`.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_sync::api::{ApiResult, SetupState, Warning};
use hangar_drive_sync::engine::{EngineCore, EnginePorts, EngineSettings, REMOVAL_PROBE_MS};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedKeychain,
};
use hangar_drive_sync::ports::{FileSystem, NetError, ServerApi};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    /// The bare code as the answer of the feed call (with a token, not a proof).
    FeedCode,
    /// The proof's answer, as the HTTP client reports it.
    Proof,
}

/// The in-memory server with a switch for what the feed answers, and a count of feed calls.
struct Saying {
    inner: MemServer,
    mode: Rc<Cell<Mode>>,
    feeds: Rc<Cell<u32>>,
}

macro_rules! pass {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {
        $(fn $name(&mut self, $($arg: $ty),*) -> Result<$out, NetError> {
            self.inner.$name($($arg),*)
        })*
    };
}

impl ServerApi for Saying {
    fn feed(&mut self, after: u64) -> Result<FeedPage, NetError> {
        self.feeds.set(self.feeds.get() + 1);
        match self.mode.get() {
            Mode::Normal => self.inner.feed(after),
            Mode::FeedCode => Err(NetError::Server(ErrorBody::new(ErrorCode::DeviceRemoved))),
            Mode::Proof => Err(NetError::DeviceRemoved(None)),
        }
    }
    pass! {
        create_account(request: &CreateAccountRequest) -> CreateAccountResponse;
        challenge(account: &AccountId, device: &DeviceId) -> ChallengeResponse;
        proof(account: &AccountId, device: &DeviceId, challenge: &Challenge, signature: &Signature) -> SessionResponse;
        log(after: u64) -> LogPage;
        append_log(request: &LogAppendRequest) -> LogAppendResponse;
        epoch_key(epoch: Epoch) -> WrappedKeyResponse;
        record(key: &RecordKey) -> Option<RecordResponse>;
        put_record(key: &RecordKey, put: &RecordPut) -> ();
        reserve_pairing(id: &PairingId) -> PairingReservation;
        post_pairing(id: &PairingId, request: &PairingRequest) -> ();
        get_pairing(id: &PairingId) -> Option<PairingRequest>;
        close_pairing(id: &PairingId) -> ();
        missing_objects(folder: &FolderId, ids: &[ObjectId]) -> Vec<ObjectId>;
        put_object(folder: &FolderId, id: &ObjectId, blob: &[u8]) -> UploadResponse;
        get_object(folder: &FolderId, id: &ObjectId) -> Vec<u8>;
        commit(folder: &FolderId, request: &CommitRequest) -> CommitResponse;
        commits(folder: &FolderId, after: u64) -> DeltaPage;
        retire(folder: &FolderId) -> ();
        bring_back(folder: &FolderId) -> ();
    }
    fn seen_pin(&self) -> Option<[u8; 32]> {
        self.inner.seen_pin()
    }
}

struct Device {
    core: EngineCore,
    keys: SharedKeychain,
    mode: Rc<Cell<Mode>>,
    feeds: Rc<Cell<u32>>,
    clock: ManualClock,
}

fn device() -> Device {
    let shared: Rc<RefCell<ServerState>> = MemServer::new_shared();
    let disks: Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>> = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let keys = SharedKeychain::default();
    let mode = Rc::new(Cell::new(Mode::Normal));
    let feeds = Rc::new(Cell::new(0));
    let (m, f) = (Rc::clone(&mode), Rc::clone(&feeds));
    let ports = EnginePorts {
        store: Box::new(MemStore::new()),
        keychain: Box::new(keys.clone()),
        clock: Box::new(clock.clone()),
        entropy: Box::new(SeededRandom::new(7)),
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
            Ok(Box::new(Saying {
                inner: MemServer::connect_pinned(&shared, device, config.pin),
                mode: Rc::clone(&m),
                feeds: Rc::clone(&f),
            }) as Box<_>)
        }),
        roots: Box::new(|path: &Path, _: &[PathBuf]| Ok(path.to_path_buf())),
    };
    let mut core = EngineCore::open(ports, EngineSettings::default()).unwrap();
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = core.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin_account")
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(core.confirm_recovery_group(&group).unwrap());
    core.add_folder("mem:/Docs", "Docs").unwrap();
    core.tick();
    Device {
        core,
        keys,
        mode,
        feeds,
        clock,
    }
}

fn reported(d: &Device) -> bool {
    d.core
        .snapshot()
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::RemovalReported { .. }))
}

fn removed(d: &Device) -> bool {
    d.core
        .snapshot()
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::Removed { .. }))
}

#[test]
fn device_removed_on_the_feed_does_not_forget() {
    let mut d = device();
    let keys = d.keys.keys();
    d.mode.set(Mode::FeedCode);
    for _ in 0..5 {
        d.clock.advance(REMOVAL_PROBE_MS);
        d.core.tick();
    }
    assert_eq!(d.core.snapshot().setup, SetupState::Done);
    assert_eq!(d.keys.keys(), keys);
    assert!(!removed(&d) && !reported(&d));
}

#[test]
fn a_reported_removal_stops_sync_until_the_person_confirms() {
    let mut d = device();
    let keys = d.keys.keys();
    // Nothing to confirm while the server reported nothing.
    assert!(d.core.confirm_device_removed().is_err());
    d.mode.set(Mode::Proof);
    d.core.tick();
    assert!(reported(&d));
    assert_eq!(d.core.snapshot().setup, SetupState::Done);
    assert_eq!(d.keys.keys(), keys, "nothing is forgotten yet");
    // Sync stays stopped: no call to the server before the next probe is due.
    let calls = d.feeds.get();
    for _ in 0..5 {
        d.clock.advance(60_000);
        d.core.tick();
    }
    assert_eq!(d.feeds.get(), calls);
    d.core.confirm_device_removed().unwrap();
    assert_eq!(d.core.snapshot().setup, SetupState::Needed);
    assert!(d.keys.keys().is_empty(), "{:?}", d.keys.keys());
    assert!(removed(&d));
}

/// The automatic forgetting after three answers over a day is gone: a server that only says
/// "removed", for a week of fresh proofs, still forgets nothing without the person.
#[test]
fn a_bare_removal_answer_never_forgets_by_itself() {
    let mut d = device();
    let keys = d.keys.keys();
    d.mode.set(Mode::Proof);
    for _ in 0..(7 * 24) {
        d.core.tick();
        d.clock.advance(REMOVAL_PROBE_MS);
    }
    d.core.tick();
    assert_eq!(d.core.snapshot().setup, SetupState::Done);
    assert_eq!(d.keys.keys(), keys);
    assert!(reported(&d) && !removed(&d));
}

/// The warning cannot be hidden, only confirmed (follow-up check N-3).
#[test]
fn the_removal_report_cannot_be_dismissed() {
    let mut d = device();
    d.mode.set(Mode::Proof);
    d.core.tick();
    assert!(reported(&d));
    assert!(d.core.dismiss_warning("removalReported").is_err());
    assert!(reported(&d));
}

#[test]
fn a_server_that_accepts_the_device_again_ends_the_report() {
    let mut d = device();
    d.mode.set(Mode::Proof);
    d.core.tick();
    assert!(reported(&d));
    d.mode.set(Mode::Normal);
    d.clock.advance(REMOVAL_PROBE_MS);
    d.core.tick();
    assert!(!reported(&d));
    assert_eq!(d.core.snapshot().setup, SetupState::Done);
    assert!(d.core.confirm_device_removed().is_err());
}

/// A clock set back after a report (a dead CMOS battery, a manual change) must not stop the
/// probes until it has caught up again: the device would stay stopped, possibly for months,
/// although the server accepts it again.
#[test]
fn a_clock_set_back_does_not_stop_the_probes() {
    let mut d = device();
    d.mode.set(Mode::Proof);
    d.core.tick();
    assert!(reported(&d));
    d.clock.advance(-30 * 24 * REMOVAL_PROBE_MS);
    let calls = d.feeds.get();
    d.core.tick();
    assert_eq!(
        d.feeds.get(),
        calls + 1,
        "the probe ran after the clock went back"
    );
    assert!(reported(&d));
    d.mode.set(Mode::Normal);
    d.clock.advance(REMOVAL_PROBE_MS);
    d.core.tick();
    assert!(!reported(&d));
    assert_eq!(d.core.snapshot().setup, SetupState::Done);
}
