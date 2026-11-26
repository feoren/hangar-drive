//! Security review M2: a forged pairing offer must not change anything of this device before
//! its signature is checked, and a feed sequence a server pushed far ahead (up to `u64::MAX`)
//! must not freeze the device: a sequence below the cursor is an older state, read again in
//! full from cursor 0.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_crypto::pairing::{PairingOffer, PairingSecret};
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_sync::api::{ApiResult, BackendEvent, FixServerError, PairResult, ServerNotice};
use hangar_drive_sync::engine::{EngineCore, EnginePorts, EngineSettings};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedKeychain,
};
use hangar_drive_sync::ports::{FileSystem, NetError, ServerApi};

/// The in-memory server; `max_once` makes the next feed answer claim `u64::MAX`, `calls`
/// counts every call that is not a log read.
struct Watched {
    inner: MemServer,
    max_once: Rc<Cell<bool>>,
    calls: Rc<Cell<u32>>,
}

macro_rules! pass {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {
        $(fn $name(&mut self, $($arg: $ty),*) -> Result<$out, NetError> {
            self.calls.set(self.calls.get() + 1);
            self.inner.$name($($arg),*)
        })*
    };
}

impl ServerApi for Watched {
    fn feed(&mut self, after: u64) -> Result<FeedPage, NetError> {
        self.calls.set(self.calls.get() + 1);
        let mut page = self.inner.feed(after)?;
        if self.max_once.replace(false) {
            page.sequence = u64::MAX;
        }
        Ok(page)
    }
    fn log(&mut self, after: u64) -> Result<LogPage, NetError> {
        self.inner.log(after)
    }
    pass! {
        create_account(request: &CreateAccountRequest) -> CreateAccountResponse;
        challenge(account: &AccountId, device: &DeviceId) -> ChallengeResponse;
        proof(account: &AccountId, device: &DeviceId, challenge: &Challenge, signature: &Signature) -> SessionResponse;
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

struct World {
    honest: Rc<RefCell<ServerState>>,
    attacker: Rc<RefCell<ServerState>>,
    max_once: Rc<Cell<bool>>,
    attacker_calls: Rc<Cell<u32>>,
    disks: Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>,
    clock: ManualClock,
}

impl World {
    fn new() -> Self {
        Self {
            honest: MemServer::new_shared(),
            attacker: MemServer::new_shared(),
            max_once: Rc::default(),
            attacker_calls: Rc::default(),
            disks: Rc::default(),
            clock: ManualClock::at(1_795_651_200_000),
        }
    }

    /// A device; `watched` puts the `max_once` switch on its connections to the honest server.
    fn device(&self, seed: u64, watched: bool) -> EngineCore {
        let (honest, attacker) = (Rc::clone(&self.honest), Rc::clone(&self.attacker));
        let (max_once, calls) = (Rc::clone(&self.max_once), Rc::clone(&self.attacker_calls));
        let disks = Rc::clone(&self.disks);
        let ports = EnginePorts {
            store: Box::new(MemStore::new()),
            keychain: Box::new(SharedKeychain::default()),
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
                if config.url.to_string().contains(":9090") {
                    return Ok(Box::new(Watched {
                        inner: MemServer::connect_pinned(&attacker, device, config.pin),
                        max_once: Rc::new(Cell::new(true)),
                        calls: Rc::clone(&calls),
                    }) as Box<_>);
                }
                Ok(Box::new(Watched {
                    inner: MemServer::connect_pinned(&honest, device, config.pin),
                    max_once: if watched {
                        Rc::clone(&max_once)
                    } else {
                        Rc::default()
                    },
                    calls: Rc::default(),
                }) as Box<_>)
            }),
            roots: Box::new(|path: &Path, _: &[PathBuf]| Ok(path.to_path_buf())),
        };
        EngineCore::open(ports, EngineSettings::default()).unwrap()
    }
}

fn set_up(engine: &mut EngineCore) {
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = engine.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin_account")
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(engine.confirm_recovery_group(&group).unwrap());
}

fn pair(world: &World, a: &mut EngineCore, b: &mut EngineCore) {
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
}

#[test]
fn a_forged_offer_touches_nothing_before_its_signature_is_checked() {
    let world = World::new();
    let mut a = world.device(1, false);
    set_up(&mut a);
    a.add_folder("mem:/a/Docs", "Docs").unwrap();
    a.tick();
    // A real offer of A as the template, then forged: the attacker's server, a head ahead of
    // A's log, an inviter A does not know, signed with the attacker's own key.
    let genuine = a.create_pairing_offer().unwrap();
    let bytes = hangar_drive_sync::links::parse_pairing_link(&genuine.link).unwrap();
    let mut content = PairingOffer::decode(&bytes).unwrap().content;
    content.server_url =
        hangar_drive_crypto::pairing::parse_server_url("http://localhost:9090/").unwrap();
    content.head.index += 5;
    content.head.hash = LogHash::from_bytes([0x66; 32]);
    content.inviter = DeviceId::from_bytes([0x77; 16]);
    content.secret = PairingSecret::generate(&mut hangar_drive_crypto::entropy::OsEntropy).unwrap();
    let forger = DeviceIdentity::generate(&mut hangar_drive_crypto::entropy::OsEntropy).unwrap();
    let forged = content.sign(&forger).unwrap();
    let link = hangar_drive_sync::links::pairing_link(&forged.encode().unwrap());

    assert_eq!(
        a.fix_server_with_offer(&link).unwrap(),
        ApiResult::Err(FixServerError::OtherAccount)
    );
    // Only the log was read from the offered server: no feed, no record, no sign-in.
    assert_eq!(world.attacker_calls.get(), 0);
    // A keeps syncing with its own server.
    world.clock.advance(20_000);
    a.tick();
    assert!(a
        .snapshot()
        .warnings
        .iter()
        .all(|w| !matches!(w, hangar_drive_sync::api::Warning::ServerIdentity { .. })));
}

#[test]
fn a_feed_sequence_pushed_to_the_maximum_does_not_freeze_the_device() {
    let world = World::new();
    let mut a = world.device(1, true);
    let mut b = world.device(2, false);
    set_up(&mut a);
    pair(&world, &mut a, &mut b);
    world.clock.advance(20_000);
    a.tick();
    // One answer claims the largest sequence.
    world.max_once.set(true);
    world.clock.advance(20_000);
    a.tick();
    // B adds a folder; A must still learn of it.
    b.add_folder("mem:/b/Photos", "Photos").unwrap();
    for _ in 0..3 {
        world.clock.advance(20_000);
        b.tick();
        a.tick();
    }
    let snapshot = a.snapshot();
    assert!(
        snapshot.remote_folders.iter().any(|f| f.name == "Photos"),
        "{:?}",
        snapshot.remote_folders
    );
    assert!(snapshot
        .notices
        .iter()
        .any(|n| matches!(n, ServerNotice::OlderAccountState)));
}

/// Security review, info: `inspectLink` names a punycode host for a pairing offer and a
/// recovery sheet as it does for an invite, so the window can warn of a look-alike name.
#[test]
fn inspect_link_names_a_punycode_host_of_an_offer_and_a_sheet() {
    use hangar_drive_sync::api::InspectedLink;
    let world = World::new();
    let mut a = world.device(1, false);
    set_up(&mut a);
    let genuine = a.create_pairing_offer().unwrap();
    let bytes = hangar_drive_sync::links::parse_pairing_link(&genuine.link).unwrap();
    let mut content = PairingOffer::decode(&bytes).unwrap().content;
    content.server_url =
        hangar_drive_crypto::pairing::parse_server_url("https://xn--drve-xqa.example/").unwrap();
    let signer = DeviceIdentity::generate(&mut hangar_drive_crypto::entropy::OsEntropy).unwrap();
    let offer = content.sign(&signer).unwrap();
    let link = hangar_drive_sync::links::pairing_link(&offer.encode().unwrap());
    let b = world.device(2, false);
    assert!(matches!(
        b.inspect_link(&link),
        ApiResult::Ok(InspectedLink::Pair { punycode: true, .. })
    ));
    let sheet = hangar_drive_sync::links::recovery_link(&hangar_drive_sync::links::RecoverySheet {
        server_url: hangar_drive_crypto::pairing::parse_server_url("https://xn--drve-xqa.example/")
            .unwrap(),
        server: ServerId::from_bytes([1; 16]),
        account: AccountId::from_bytes([2; 16]),
        genesis: LogHash::from_bytes([3; 32]),
        pin: None,
    });
    assert!(matches!(
        b.inspect_link(&sheet),
        ApiResult::Ok(InspectedLink::Recover { punycode: true, .. })
    ));
}
