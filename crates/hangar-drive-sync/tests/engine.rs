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

use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_sync::api::{ApiResult, BackendEvent, FolderStatus, PairResult, SetupState};
use hangar_drive_sync::engine::{Engine, EngineCore, EnginePorts, EngineSettings};
use hangar_drive_sync::memory::SharedKeychain;
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom, ServerState,
};
use hangar_drive_sync::ports::{FileSystem, NetError, ServerApi};

type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

fn core(
    shared: &Rc<RefCell<ServerState>>,
    disks: &Disks,
    clock: &ManualClock,
    seed: u64,
) -> EngineCore {
    core_with(
        shared,
        disks,
        clock,
        seed,
        Box::new(MemKeychain::default()),
        false,
    )
}

/// [`core`] with a keychain the test keeps a handle to; `lie_head` makes the server answer
/// every log append with a head it made up (security review I1).
fn core_with(
    shared: &Rc<RefCell<ServerState>>,
    disks: &Disks,
    clock: &ManualClock,
    seed: u64,
    keychain: Box<dyn hangar_drive_sync::ports::Keychain>,
    lie_head: bool,
) -> EngineCore {
    let server = Rc::clone(shared);
    let disks = Rc::clone(disks);
    let ports = EnginePorts {
        store: Box::new(MemStore::new()),
        keychain,
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
        // Pinned like the real client: a server presenting another key fails every call.
        server: Box::new(move |config, identity| {
            let device = identity.map_or(DeviceId::from_bytes([0; 16]), |i| i.device);
            let server = MemServer::connect_pinned(&server, device, config.pin);
            if lie_head {
                return Ok(Box::new(LyingHead(server)) as Box<_>);
            }
            Ok(Box::new(server) as Box<_>)
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

/// A server that answers every log append with a head it made up.
struct LyingHead(MemServer);

macro_rules! pass {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {
        $(fn $name(&mut self, $($arg: $ty),*) -> Result<$out, NetError> {
            self.0.$name($($arg),*)
        })*
    };
}

impl ServerApi for LyingHead {
    fn append_log(&mut self, request: &LogAppendRequest) -> Result<LogAppendResponse, NetError> {
        let mut response = self.0.append_log(request)?;
        response.head.hash = LogHash::from_bytes([0x66; 32]);
        Ok(response)
    }
    pass! {
        create_account(request: &CreateAccountRequest) -> CreateAccountResponse;
        challenge(account: &AccountId, device: &DeviceId) -> ChallengeResponse;
        proof(account: &AccountId, device: &DeviceId, challenge: &Challenge, signature: &Signature) -> SessionResponse;
        log(after: u64) -> LogPage;
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
        self.0.seen_pin()
    }
}

/// A new account on `a` with its code confirmed; returns the code view.
fn set_up(a: &mut EngineCore) -> hangar_drive_sync::api::RecoveryCodeView {
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.confirm_recovery_group(&group).unwrap());
    code
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
    assert!(matches!(
        a.check_invite(&link),
        ApiResult::Ok(ref c) if c.host == "localhost:8080" && !c.pinned && !c.punycode
    ));
    // N3: a pin and a punycode host are reported, so the window can warn.
    let pinned = format!(
        "https://xn--drve-6qa.example/join#{}.{}.{}",
        base64url(&[9; 16]),
        "5e".repeat(16),
        base64url(&[7; 32])
    );
    assert!(matches!(
        a.check_invite(&pinned),
        ApiResult::Ok(ref c) if c.pinned && c.punycode && c.host == "xn--drve-6qa.example"
    ));
    // Name errors are their own codes.
    assert_eq!(
        a.begin_account(&link, " Laptop").unwrap(),
        ApiResult::Err(hangar_drive_sync::api::BeginError::EdgeWhitespace)
    );
    assert_eq!(
        a.begin_account(&link, "   ").unwrap(),
        ApiResult::Err(hangar_drive_sync::api::BeginError::Blank)
    );
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
    // N2: before B sends anything it shows host and account of the link.
    let ApiResult::Ok(hangar_drive_sync::api::InspectedLink::Pair {
        host,
        account,
        pinned,
        punycode,
    }) = b.inspect_link(&offer.link)
    else {
        panic!("inspect");
    };
    assert_eq!(host, "localhost:8080");
    assert_eq!(account, offer.account);
    assert!(!pinned && !punycode);
    assert!(matches!(
        b.inspect_link("hangar-drive://pair#AQID"),
        ApiResult::Err(hangar_drive_sync::api::LinkProblem::Damaged)
    ));
    assert!(matches!(
        b.inspect_link("nonsense"),
        ApiResult::Err(hangar_drive_sync::api::LinkProblem::NotALink)
    ));
    assert!(matches!(
        b.inspect_link(&link),
        ApiResult::Ok(hangar_drive_sync::api::InspectedLink::Invite { .. })
    ));
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
    // N2: the joined device sees the account's devices to confirm them.
    let joined = events
        .iter()
        .find_map(|e| match e {
            BackendEvent::PairResult {
                result: PairResult::Joined { devices },
            } => Some(devices.clone()),
            _ => None,
        })
        .expect("joined");
    assert_eq!(joined.len(), 2);
    assert!(joined.iter().any(|d| d.is_this && d.name == "Desktop"));
    assert!(joined.iter().any(|d| !d.is_this && d.name == "Laptop"));
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

/// N1: the sheet's genesis anchor binds the recovery to the account's own log.
#[test]
fn a_sheet_with_another_genesis_is_refused() {
    use hangar_drive_protocol::ids::{AccountId, LogHash, ServerId};
    use hangar_drive_sync::api::RecoverError;
    use hangar_drive_sync::links::{parse_recovery_link, recovery_link};
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&shared, &disks, &clock, 21);
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.confirm_recovery_group(&group).unwrap());
    // The sheet names entry 1 of the log the server now holds.
    let sheet = parse_recovery_link(&code.sheet.link).unwrap();
    let log = shared.borrow().account_state().unwrap().hash_at(1).copied();
    assert_eq!(Some(sheet.genesis), log);
    assert_eq!(code.sheet.genesis_anchor, sheet.genesis.to_hex());
    assert!(matches!(
        a.inspect_link(&code.sheet.link),
        ApiResult::Ok(hangar_drive_sync::api::InspectedLink::Recover { ref account, .. })
            if *account == code.sheet.account_id
    ));
    let mut probe = core(&shared, &disks, &clock, 23);
    assert_eq!(
        probe
            .recover_account(&code.sheet.link, "x", " Neu")
            .unwrap(),
        ApiResult::Err(RecoverError::EdgeWhitespace)
    );
    assert_eq!(
        sheet.account,
        AccountId::from_hex(&code.sheet.account_id).unwrap()
    );
    assert_eq!(
        sheet.server,
        ServerId::from_hex(&code.sheet.server_id).unwrap()
    );
    // Another anchor with the sheet's tag: the code does not vouch for it, and nothing is sent.
    let mut forged = sheet.clone();
    forged.genesis = LogHash::from_bytes([0x42; 32]);
    let mut c = core(&shared, &disks, &clock, 22);
    let text = code.groups.join("-");
    let calls = shared.borrow().calls;
    assert_eq!(
        c.recover_account(&recovery_link(&forged), &text, "Neu")
            .unwrap(),
        ApiResult::Err(RecoverError::WrongSheet)
    );
    assert_eq!(shared.borrow().calls, calls);
    // Another anchor that the code does vouch for: the server's log does not start there (N1).
    let typed = hangar_drive_crypto::recovery::RecoveryCode::parse(&text).unwrap();
    forged.anchor_tag = typed.anchor_tag(&forged.account, &forged.genesis).unwrap();
    assert_eq!(
        c.recover_account(&recovery_link(&forged), &text, "Neu")
            .unwrap(),
        ApiResult::Err(RecoverError::Unknown)
    );
    // With the real sheet it works.
    assert_eq!(
        c.recover_account(&code.sheet.link, &text, "Neu").unwrap(),
        ApiResult::Ok(())
    );
}

/// Security review "recovery link as phishing": whoever knows the account's log (the server's
/// operator, a copy of its database) builds an account of their own with the same account ID and
/// their own entry 1, lists the code's recovery device in it (public keys and proof of
/// possession copied from the real log), wraps an epoch secret they hold to its KEM key and sends
/// a recovery link to their server. The sheet's anchor tag, which only the code makes, stops it
/// before anything is sent; without it the real code would pass every other check there.
#[test]
fn a_forged_account_that_lists_the_recovery_device_cannot_take_the_code() {
    use hangar_drive_crypto::devicelog::{EntryKind as LogKind, LogEntry};
    use hangar_drive_crypto::recovery::{RecoveryCode, RecoverySheet};
    use hangar_drive_sync::account::{Account, Genesis};
    use hangar_drive_sync::api::RecoverError;
    use hangar_drive_sync::links::{parse_recovery_link, recovery_link};
    use hangar_drive_sync::recovery::{add_device_with_code, RecoveryError};

    let real = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&real, &disks, &clock, 31);
    let code = set_up(&mut a);
    let text = code.groups.join("-");
    let real_sheet = parse_recovery_link(&code.sheet.link).unwrap();

    // What the attacker reads from the real log: entry 1 with the recovery device and its proof.
    let page = MemServer::connect(&real, DeviceId::from_bytes([0; 16]))
        .log(0)
        .unwrap();
    let LogKind::Create { devices } = LogEntry::decode(page.entries[0].as_bytes()).unwrap().kind
    else {
        panic!("entry 1 creates the account");
    };
    let recovery_device = devices.into_iter().find(|d| d.recovery).unwrap();

    // The attacker's account on their own server: the same account ID, their own entry 1 and
    // device, an epoch secret they hold, and the recovery device added with that secret wrapped
    // to its KEM key.
    let evil = MemServer::new_shared();
    let mut entropy = SeededRandom::new(666);
    let mut keychain = MemKeychain::default();
    let mut store = MemStore::new();
    let attacker = DeviceId::from_bytes([0xe1; 16]);
    let genesis = Genesis::new(&mut entropy, 1, real_sheet.account, attacker, None).unwrap();
    let evil_genesis = genesis.hash().unwrap();
    assert_ne!(evil_genesis, real_sheet.genesis);
    let mut server = MemServer::connect(&evil, attacker);
    let mut account = Account::create_from(
        &mut server,
        &mut keychain,
        &mut store,
        InviteToken::from_bytes([9; 16]),
        &genesis,
        "Attacker",
    )
    .unwrap();
    account
        .finish_setup(&mut server, &mut keychain, &mut store, &mut entropy, 2)
        .unwrap();
    account
        .add_recovery_device(&mut server, &mut store, recovery_device, 3, &mut entropy)
        .unwrap();
    let listed = evil
        .borrow()
        .account_state()
        .unwrap()
        .device(&recovery_device.id)
        .cloned();
    assert!(listed.is_some_and(|d| d.recovery && d.is_current()));

    // The phishing link: the attacker's genesis, everything else as on the real sheet. The tag
    // can only be the real sheet's one (or a guess); it does not cover this genesis.
    let phishing = RecoverySheet {
        genesis: evil_genesis,
        ..real_sheet.clone()
    };
    let mut victim = core(&evil, &disks, &clock, 32);
    let calls = evil.borrow().calls;
    let log_length = evil.borrow().account_state().unwrap().len();
    assert_eq!(
        victim
            .recover_account(&recovery_link(&phishing), &text, "Neu")
            .unwrap(),
        ApiResult::Err(RecoverError::WrongSheet)
    );
    // Refused before the recovery device signed in anywhere: the attacker's server saw nothing.
    assert_eq!(evil.borrow().calls, calls);
    assert_eq!(evil.borrow().account_state().unwrap().len(), log_length);
    assert!(victim.list_devices().is_err(), "no account on the victim");
    // The engine's recovery step refuses it on its own as well.
    let typed = RecoveryCode::parse(&text).unwrap();
    let mut session = MemServer::connect(&evil, typed.device_id().unwrap());
    let joiner = hangar_drive_crypto::identity::DeviceIdentity::generate(
        &mut hangar_drive_crypto::entropy::OsEntropy,
    )
    .unwrap();
    let joiner = hangar_drive_crypto::devicelog::LogDevice::of(
        &joiner,
        &real_sheet.account,
        DeviceId::from_bytes([0xe2; 16]),
        false,
    );
    assert_eq!(
        add_device_with_code(
            &mut session,
            &phishing,
            &typed,
            joiner,
            4,
            &mut hangar_drive_crypto::entropy::OsEntropy,
        ),
        Err(RecoveryError::WrongSheet)
    );
    assert_eq!(evil.borrow().calls, calls);

    // Only the code holder can make the tag for the attacker's genesis. Made here, it shows that
    // the tag is what stops the attack: every other check passes on the attacker's server, and
    // the new device would join an account whose epoch secret the attacker holds.
    let vouched = RecoverySheet::new(
        phishing.server_url.clone(),
        phishing.server,
        phishing.account,
        evil_genesis,
        phishing.pin,
        &typed,
    )
    .unwrap();
    let mut fooled = core(&evil, &disks, &clock, 33);
    assert_eq!(
        fooled
            .recover_account(&recovery_link(&vouched), &text, "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );

    // The real sheet with the same code works on the real server.
    let mut c = core(&real, &disks, &clock, 34);
    assert_eq!(
        c.recover_account(&code.sheet.link, &text, "Neu").unwrap(),
        ApiResult::Ok(())
    );
}

/// ux-concept 10.3: a renewed code replaces the old one only after the group check.
#[test]
fn a_renewed_code_replaces_the_old_one_after_the_group_check() {
    use hangar_drive_sync::api::RecoverError;
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&shared, &disks, &clock, 31);
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(old) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin");
    };
    let group = old.groups[old.check_group as usize - 1].clone();
    assert!(a.confirm_recovery_group(&group).unwrap());
    let created = a.list_devices().unwrap().recovery_created;

    // Shown, then abandoned: the old code still works.
    let abandoned = a.renew_recovery_code().unwrap();
    assert_ne!(abandoned.groups, old.groups);
    // The sheet names the same account, server and anchor; its link differs only in the anchor
    // tag, which each code makes for itself.
    assert_eq!(
        (
            &abandoned.sheet.server_url,
            &abandoned.sheet.server_id,
            &abandoned.sheet.account_id,
            &abandoned.sheet.genesis_anchor
        ),
        (
            &old.sheet.server_url,
            &old.sheet.server_id,
            &old.sheet.account_id,
            &old.sheet.genesis_anchor
        ),
        "the sheet's public part stays"
    );
    assert_ne!(abandoned.sheet.link, old.sheet.link);
    assert!(!a.confirm_recovery_group("0000").unwrap());

    let renewed = a.renew_recovery_code().unwrap();
    let group = renewed.groups[renewed.check_group as usize - 1].clone();
    clock.advance(1_000);
    assert!(a.confirm_recovery_group(&group).unwrap());
    assert!(a.list_devices().unwrap().recovery_created > created);
    let mut c = core(&shared, &disks, &clock, 32);
    assert_eq!(
        c.recover_account(&old.sheet.link, &old.groups.join(""), "Neu")
            .unwrap(),
        ApiResult::Err(RecoverError::Used)
    );
    assert_eq!(
        c.recover_account(&abandoned.sheet.link, &abandoned.groups.join(""), "Neu")
            .unwrap(),
        ApiResult::Err(RecoverError::Unknown)
    );
    // The new code with the old sheet's link: the link was not made for it.
    assert_eq!(
        c.recover_account(&old.sheet.link, &renewed.groups.join(""), "Neu")
            .unwrap(),
        ApiResult::Err(RecoverError::WrongSheet)
    );
    assert_eq!(
        c.recover_account(&renewed.sheet.link, &renewed.groups.join(""), "Neu")
            .unwrap(),
        ApiResult::Ok(())
    );
}

// Security review L1: a device that learns it was removed forgets its secrets and its account at
// once and keeps the warning (with the remover's name when it could still read it), and the files
// stay.
#[test]
fn a_removed_device_forgets_its_secrets() {
    use hangar_drive_sync::api::Warning;
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let keys = SharedKeychain::default();
    let mut a = core_with(&shared, &disks, &clock, 31, Box::new(keys.clone()), false);
    let code = set_up(&mut a);
    a.add_folder("mem:/a/Docs", "Docs").unwrap();
    disk(&disks, "mem:/a/Docs").user_write(&p(&["plan.txt"]), b"mine");
    a.tick();
    assert!(keys.keys().contains(&"device-identity".to_owned()));
    assert!(keys.keys().iter().any(|k| k.starts_with("epoch-")));
    let lost = a.list_devices().unwrap().devices[0].id.clone();
    // Another installation recovers the account and removes A.
    let mut c = core(&shared, &disks, &clock, 32);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Rescue")
            .unwrap(),
        ApiResult::Ok(())
    );
    c.finish_recovery_cleanup(std::slice::from_ref(&lost))
        .unwrap();
    clock.advance(20_000);
    a.tick();
    assert_eq!(keys.keys(), Vec::<String>::new(), "no secret is left");
    let snap = a.snapshot();
    assert_eq!(snap.setup, SetupState::Needed);
    assert!(snap.folders.is_empty());
    assert!(
        snap.warnings
            .iter()
            .any(|w| matches!(w, Warning::Removed { by, .. } if by.is_empty() || by == "Rescue")),
        "{:?}",
        snap.warnings
    );
    assert_eq!(
        disk(&disks, "mem:/a/Docs")
            .read_all(&p(&["plan.txt"]))
            .unwrap(),
        b"mine",
        "the files stay"
    );
    // A reset clears the warning too; a restart finds no account and no warning left over.
    a.reset_device().unwrap();
    assert!(a.snapshot().warnings.is_empty());
    assert_eq!(a.snapshot().setup, SetupState::Needed);
}

// Security review L1: "start over" forgets every secret and the account.
#[test]
fn a_reset_forgets_every_secret() {
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let keys = SharedKeychain::default();
    let mut a = core_with(&shared, &disks, &clock, 33, Box::new(keys.clone()), false);
    set_up(&mut a);
    a.add_folder("mem:/a/Docs", "Docs").unwrap();
    a.tick();
    assert!(!keys.keys().is_empty());
    a.reset_device().unwrap();
    assert_eq!(keys.keys(), Vec::<String>::new());
    let snap = a.snapshot();
    assert_eq!(snap.setup, SetupState::Needed);
    assert!(snap.folders.is_empty() && snap.warnings.is_empty());
}

// Security review L1: a join that fails after the identity was stored leaves nothing behind.
#[test]
fn an_aborted_join_leaves_no_secret() {
    use hangar_drive_crypto::identity::DeviceIdentity;
    use hangar_drive_sync::account::Account;
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&shared, &disks, &clock, 34);
    let code = set_up(&mut a);
    let account = AccountId::from_hex(&code.sheet.account_id).unwrap();
    // A device the log does not list: the join reads the log and refuses.
    let device = DeviceId::from_bytes([0x77; 16]);
    let identity = DeviceIdentity::generate(&mut SeededRandom::new(35)).unwrap();
    let mut server = MemServer::connect(&shared, device);
    let mut keychain = MemKeychain::default();
    let mut store = MemStore::new();
    let joined = Account::join(
        &mut server,
        &mut keychain,
        &mut store,
        identity,
        account,
        device,
        "Stranger",
        &[],
    );
    assert!(joined.is_err());
    assert_eq!(keychain.keys(), Vec::<String>::new());
    assert!(Account::load(&store, &keychain).unwrap().is_none());
}

// Security review I1: the recovery computes the head after its append itself and refuses a
// server that reports another one, before the new device joins at it.
#[test]
fn a_recovery_refuses_a_head_the_server_made_up() {
    use hangar_drive_sync::api::RecoverError;
    let shared = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = core(&shared, &disks, &clock, 36);
    let code = set_up(&mut a);
    let keys = SharedKeychain::default();
    let mut c = core_with(&shared, &disks, &clock, 37, Box::new(keys.clone()), true);
    assert_eq!(
        c.recover_account(&code.sheet.link, &code.groups.join("-"), "Neu")
            .unwrap(),
        ApiResult::Err(RecoverError::Unknown)
    );
    assert_eq!(c.snapshot().setup, SetupState::Needed);
    assert_eq!(keys.keys(), Vec::<String>::new());
}
