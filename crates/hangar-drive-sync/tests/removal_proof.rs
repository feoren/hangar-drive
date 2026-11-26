//! Security review H2, verifiable removal: the server answers a removed device's own proof
//! with `device_removed` and the device log from the head the device named up to its removal.
//! The device checks those entries from its own verified head with the device log verifier.
//! A valid removal of itself makes it forget the account at once (L1); a forged entry, no entry
//! or a chain that does not start at its own head never does: it waits for the person.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_sync::api::{ApiResult, BackendEvent, PairResult, SetupState, Warning};
use hangar_drive_sync::engine::{EngineCore, EnginePorts, EngineSettings, REMOVAL_PROBE_MS};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedKeychain,
};
use hangar_drive_sync::ports::{FileSystem, NetError, ServerApi};

/// What a server makes of the log it sends with "removed".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tamper {
    /// As it is.
    Honest,
    /// No log at all.
    Missing,
    /// The log without the removal entry.
    WithoutRemoval,
    /// The removal's signature broken.
    Forged,
    /// The log said to start one entry before the device's own head.
    BeforeHead,
    /// The log said to start one entry after the device's own head (a gap).
    AfterHead,
}

/// The in-memory server, with the log of a "removed" answer changed by `tamper`.
struct Lying {
    inner: MemServer,
    tamper: Rc<Cell<Tamper>>,
}

impl Lying {
    fn changed<T>(&self, result: Result<T, NetError>) -> Result<T, NetError> {
        result.map_err(|e| match e {
            NetError::DeviceRemoved(log) => {
                NetError::DeviceRemoved(tampered(self.tamper.get(), log))
            }
            other => other,
        })
    }
}

fn tampered(tamper: Tamper, log: Option<LogPage>) -> Option<LogPage> {
    let mut log = log?;
    match tamper {
        Tamper::Honest => {}
        Tamper::Missing => return None,
        Tamper::WithoutRemoval => {
            log.entries.pop();
        }
        Tamper::Forged => {
            let last = log.entries.last_mut()?;
            let at = last.0.len() - 1;
            last.0[at] ^= 1;
        }
        Tamper::BeforeHead => log.first_index -= 1,
        Tamper::AfterHead => log.first_index += 1,
    }
    Some(log)
}

macro_rules! pass {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {
        $(fn $name(&mut self, $($arg: $ty),*) -> Result<$out, NetError> {
            let result = self.inner.$name($($arg),*);
            self.changed(result)
        })*
    };
}

impl ServerApi for Lying {
    pass! {
        create_account(request: &CreateAccountRequest) -> CreateAccountResponse;
        challenge(account: &AccountId, device: &DeviceId) -> ChallengeResponse;
        proof(account: &AccountId, device: &DeviceId, challenge: &Challenge, signature: &Signature) -> SessionResponse;
        log(after: u64) -> LogPage;
        append_log(request: &LogAppendRequest) -> LogAppendResponse;
        epoch_key(epoch: Epoch) -> WrappedKeyResponse;
        record(key: &RecordKey) -> Option<RecordResponse>;
        put_record(key: &RecordKey, put: &RecordPut) -> ();
        feed(after: u64) -> FeedPage;
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
    fn set_known_log_length(&mut self, length: u64) {
        self.inner.set_known_log_length(length);
    }
}

struct World {
    shared: Rc<RefCell<ServerState>>,
    disks: Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>,
    clock: ManualClock,
    tamper: Rc<Cell<Tamper>>,
}

impl World {
    fn new() -> Self {
        Self {
            shared: MemServer::new_shared(),
            disks: Rc::default(),
            clock: ManualClock::at(1_795_651_200_000),
            tamper: Rc::new(Cell::new(Tamper::Honest)),
        }
    }

    fn device(&self, seed: u64, keychain: SharedKeychain) -> EngineCore {
        let server = Rc::clone(&self.shared);
        let disks = Rc::clone(&self.disks);
        let tamper = Rc::clone(&self.tamper);
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
                Ok(Box::new(Lying {
                    inner: MemServer::connect_pinned(&server, device, config.pin),
                    tamper: Rc::clone(&tamper),
                }) as Box<_>)
            }),
            roots: Box::new(|path: &Path, _: &[PathBuf]| Ok(path.to_path_buf())),
        };
        EngineCore::open(ports, EngineSettings::default()).unwrap()
    }
}

/// A with an account and a folder, B paired into it; B then removes A. Returns A and its
/// keychain, with the server answering A's calls as the real server answers a removed device.
fn removed_device(world: &World) -> (EngineCore, SharedKeychain) {
    let keys = SharedKeychain::default();
    let mut a = world.device(1, keys.clone());
    let mut b = world.device(2, SharedKeychain::default());
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.confirm_recovery_group(&group).unwrap());
    a.add_folder("mem:/a/Docs", "Docs").unwrap();
    a.tick();
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
    world.clock.advance(20_000);
    a.tick();
    b.tick();
    let a_id = b
        .list_devices()
        .unwrap()
        .devices
        .into_iter()
        .find(|d| !d.is_this)
        .unwrap()
        .id;
    b.remove_device(&a_id).unwrap();
    world.shared.borrow_mut().refuse_removed = true;
    (a, keys)
}

fn warnings(d: &EngineCore) -> Vec<Warning> {
    d.snapshot().warnings
}

#[test]
fn a_real_removal_entry_forgets_at_once() {
    let world = World::new();
    let (mut a, keys) = removed_device(&world);
    assert!(!keys.keys().is_empty());
    world.clock.advance(20_000);
    a.tick();
    assert_eq!(a.snapshot().setup, SetupState::Needed);
    assert!(keys.keys().is_empty(), "{:?}", keys.keys());
    assert!(
        warnings(&a)
            .iter()
            .any(|w| matches!(w, Warning::Removed { by, .. } if by == "Desktop")),
        "{:?}",
        warnings(&a)
    );
}

#[test]
fn a_forged_or_missing_removal_never_forgets() {
    for tamper in [Tamper::Missing, Tamper::WithoutRemoval, Tamper::Forged] {
        let world = World::new();
        let (mut a, keys) = removed_device(&world);
        let before = keys.keys();
        world.tamper.set(tamper);
        for _ in 0..(3 * 24) {
            world.clock.advance(REMOVAL_PROBE_MS);
            a.tick();
        }
        assert_eq!(a.snapshot().setup, SetupState::Done, "{tamper:?}");
        assert_eq!(keys.keys(), before, "{tamper:?}");
        assert!(
            warnings(&a)
                .iter()
                .any(|w| matches!(w, Warning::RemovalReported { .. })),
            "{tamper:?}: {:?}",
            warnings(&a)
        );
        // The person still decides; the real removal then comes through when it is shown.
        world.tamper.set(Tamper::Honest);
        world.clock.advance(REMOVAL_PROBE_MS);
        a.tick();
        assert_eq!(a.snapshot().setup, SetupState::Needed, "{tamper:?}");
    }
}

#[test]
fn a_chain_that_does_not_start_at_the_own_head_never_forgets() {
    for tamper in [Tamper::BeforeHead, Tamper::AfterHead] {
        let world = World::new();
        let (mut a, keys) = removed_device(&world);
        let before = keys.keys();
        world.tamper.set(tamper);
        for _ in 0..3 {
            world.clock.advance(REMOVAL_PROBE_MS);
            a.tick();
        }
        assert_eq!(a.snapshot().setup, SetupState::Done, "{tamper:?}");
        assert_eq!(keys.keys(), before, "{tamper:?}");
        assert!(warnings(&a)
            .iter()
            .any(|w| matches!(w, Warning::RemovalReported { .. })));
    }
}
