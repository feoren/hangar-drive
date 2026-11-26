//! Security review H1: a set-up device whose window calls `startPairing` with an offer of
//! another account must neither join that account nor lose its own identity and secrets.
//! Taken over from the review's proof of concept, with the attack's outcome asserted.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use hangar_drive_protocol::ids::*;
use hangar_drive_sync::api::{ApiResult, BackendEvent};
use hangar_drive_sync::engine::{EngineCore, EnginePorts, EngineSettings};
use hangar_drive_sync::error::SyncError;
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedKeychain,
};
use hangar_drive_sync::ports::{FileSystem, Keychain};

type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

fn core(
    victim: &Rc<RefCell<ServerState>>,
    attacker: &Rc<RefCell<ServerState>>,
    disks: &Disks,
    clock: &ManualClock,
    seed: u64,
    keychain: SharedKeychain,
) -> EngineCore {
    let (victim, attacker, disks) = (Rc::clone(victim), Rc::clone(attacker), Rc::clone(disks));
    let ports = EnginePorts {
        store: Box::new(MemStore::new()),
        keychain: Box::new(keychain),
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
        // The attacker's account lives on another server (port 9090).
        server: Box::new(move |config, identity| {
            let device = identity.map_or(DeviceId::from_bytes([0; 16]), |i| i.device);
            let target = if config.url.to_string().contains(":9090") {
                &attacker
            } else {
                &victim
            };
            Ok(Box::new(MemServer::connect_pinned(target, device, config.pin)) as Box<_>)
        }),
        roots: Box::new(|path: &Path, _: &[PathBuf]| Ok(path.to_path_buf())),
    };
    EngineCore::open(ports, EngineSettings::default()).unwrap()
}

fn set_up(engine: &mut EngineCore, invite: u8, port: u16, name: &str) {
    let link = format!("http://localhost:{port}/join#{}", base64url(&[invite; 16]));
    let ApiResult::Ok(code) = engine.begin_account(&link, name).unwrap() else {
        panic!("begin_account")
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(engine.confirm_recovery_group(&group).unwrap());
}

#[test]
fn a_set_up_device_does_not_pair_into_another_account() {
    let victim_server = MemServer::new_shared();
    let attacker_server = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let keys = SharedKeychain::default();
    let mut v = core(
        &victim_server,
        &attacker_server,
        &disks,
        &clock,
        41,
        keys.clone(),
    );
    set_up(&mut v, 9, 8080, "Victim");
    v.add_folder("mem:/v/Docs", "Docs").unwrap();
    v.tick();
    let account_before = format!("{:?}", v.snapshot().account);
    let keys_before = keys.keys();
    let identity_before = keys.load("device-identity").unwrap().unwrap();

    let mut x = core(
        &victim_server,
        &attacker_server,
        &disks,
        &clock,
        42,
        SharedKeychain::default(),
    );
    set_up(&mut x, 8, 9090, "Attacker");
    x.add_folder("mem:/x/Documents", "Documents").unwrap();
    x.tick();
    let offer = x.create_pairing_offer().unwrap();

    // The compromised window of the victim: refused, nothing is sent.
    let started = v.start_pairing(&offer.link, "exfil-0123456789");
    assert!(
        matches!(started, Err(SyncError::Invalid(_))),
        "{:?}",
        started.map(|r| matches!(r, ApiResult::Ok(_)))
    );
    let events = x.tick();
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, BackendEvent::PairRequest { .. })),
        "the attacker got a pairing request"
    );
    for _ in 0..3 {
        clock.advance(6_000);
        v.tick();
        x.tick();
    }
    // The victim still is itself, in its own account, with its own secrets.
    let snap = v.snapshot();
    assert_eq!(format!("{:?}", snap.account), account_before);
    assert_eq!(keys.keys(), keys_before);
    assert_eq!(
        *keys.load("device-identity").unwrap().unwrap(),
        *identity_before
    );
    assert!(snap.remote_folders.iter().all(|f| f.name != "Documents"));
}

/// The second line of defence: `Account::join` itself refuses over a stored identity and
/// touches nothing, also when the join would fail.
#[test]
fn a_join_over_a_stored_identity_touches_nothing() {
    use hangar_drive_crypto::identity::DeviceIdentity;
    use hangar_drive_sync::account::Account;

    let server = MemServer::new_shared();
    let mut keys = SharedKeychain::default();
    keys.store("device-identity", b"the victim's identity")
        .unwrap();
    keys.store("epoch-1", &[7; 32]).unwrap();
    let before = keys.keys();
    let mut store = MemStore::new();
    let mut api = MemServer::connect_pinned(&server, DeviceId::from_bytes([3; 16]), None);
    let identity = DeviceIdentity::generate(&mut hangar_drive_crypto::entropy::OsEntropy).unwrap();
    let joined = Account::join(
        &mut api,
        &mut keys,
        &mut store,
        identity,
        AccountId::from_bytes([1; 16]),
        DeviceId::from_bytes([3; 16]),
        "Laptop",
        &[],
    );
    assert!(matches!(joined, Err(SyncError::AlreadySetUp)));
    assert_eq!(keys.keys(), before);
    assert_eq!(
        &**keys.load("device-identity").unwrap().unwrap(),
        b"the victim's identity"
    );
    assert_eq!(&**keys.load("epoch-1").unwrap().unwrap(), &[7; 32]);
}
