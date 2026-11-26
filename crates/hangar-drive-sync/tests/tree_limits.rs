//! Security review M3: a tree is a server's input. Decoding stops at `MAX_TREE_DEPTH` levels and
//! `MAX_TREE_ITEMS` items, `Tree::check` is linear, a folder whose head is beyond the limits
//! stops with its own reason, and "Undo a device" brings it back without decoding that head.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hangar_drive_crypto::folder_keys::FolderKeyRing;
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_sync::api::{ApiResult, FolderStatus, RestoreOutcome, StopReasonApi, Warning};
use hangar_drive_sync::codec::{self, CodecError, FolderCrypto, MAX_TREE_DEPTH};
use hangar_drive_sync::engine::{EngineCore, EnginePorts, EngineSettings};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemServer, MemStore, SeededRandom, ServerState, SharedKeychain,
};
use hangar_drive_sync::ports::{FileSystem, NetError, ServerApi};
use hangar_drive_sync::tree::{Node, Tree, ROOT};

fn item(n: u64) -> ItemId {
    let mut b = [0u8; 16];
    b[0] = 1;
    b[8..].copy_from_slice(&n.to_be_bytes());
    ItemId::from_bytes(b)
}

/// A chain of `depth` directories, each inside the one before.
fn chain(depth: u64) -> Tree {
    let mut tree = Tree::new();
    let mut parent = ROOT;
    for i in 0..depth {
        tree.insert(item(i), Node::dir(parent, "d"));
        parent = item(i);
    }
    tree
}

/// Serves sealed objects from a map and counts the fetches; every other call fails.
struct Objects {
    blobs: BTreeMap<ObjectId, Vec<u8>>,
    fetched: usize,
}

macro_rules! refuse {
    ($($name:ident($($ty:ty),*) -> $out:ty;)*) => {
        $(fn $name(&mut self, $(_: $ty),*) -> Result<$out, NetError> {
            Err(NetError::Unreachable)
        })*
    };
}

impl ServerApi for Objects {
    fn get_object(&mut self, _folder: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError> {
        self.fetched += 1;
        self.blobs.get(id).cloned().ok_or(NetError::Unreachable)
    }
    refuse! {
        create_account(&CreateAccountRequest) -> CreateAccountResponse;
        challenge(&AccountId, &DeviceId) -> ChallengeResponse;
        proof(&AccountId, &DeviceId, &Challenge, &Signature) -> SessionResponse;
        log(u64) -> LogPage;
        append_log(&LogAppendRequest) -> LogAppendResponse;
        epoch_key(Epoch) -> WrappedKeyResponse;
        record(&RecordKey) -> Option<RecordResponse>;
        put_record(&RecordKey, &RecordPut) -> ();
        feed(u64) -> FeedPage;
        reserve_pairing(&PairingId) -> PairingReservation;
        post_pairing(&PairingId, &PairingRequest) -> ();
        get_pairing(&PairingId) -> Option<PairingRequest>;
        close_pairing(&PairingId) -> ();
        missing_objects(&FolderId, &[ObjectId]) -> Vec<ObjectId>;
        put_object(&FolderId, &ObjectId, &[u8]) -> UploadResponse;
        commit(&FolderId, &CommitRequest) -> CommitResponse;
        commits(&FolderId, u64) -> DeltaPage;
        retire(&FolderId) -> ();
        bring_back(&FolderId) -> ();
    }
}

/// The measurement of the review: a chain of 40,000 directories is refused at once, after at
/// most `MAX_TREE_DEPTH` directory nodes, instead of being fetched in full and checked in
/// O(n x depth).
#[test]
fn a_tree_40000_levels_deep_is_refused_quickly() {
    let account = AccountId::from_bytes([1; 16]);
    let folder = FolderId::from_bytes([2; 16]);
    let ring = FolderKeyRing::new(folder, 1, &mut hangar_drive_crypto::entropy::OsEntropy).unwrap();
    let crypto = FolderCrypto::new(&account, &ring, Generation(1)).unwrap();
    let deep = chain(40_000);
    let started = Instant::now();
    let encoded =
        codec::encode(&deep, &crypto, &MemStore::new(), &mut SeededRandom::new(3)).unwrap();
    println!("encode 40,000 levels: {:?}", started.elapsed());

    let mut server = Objects {
        blobs: encoded.sealed,
        fetched: 0,
    };
    let started = Instant::now();
    let decoded = codec::decode(&encoded.root, &crypto, &mut MemStore::new(), &mut server);
    let took = started.elapsed();
    println!(
        "decode 40,000 levels: {:?} after {} objects",
        took, server.fetched
    );
    assert_eq!(decoded.unwrap_err(), CodecError::Limit);
    assert!(server.fetched <= MAX_TREE_DEPTH + 1, "{}", server.fetched);
    assert!(took < Duration::from_secs(5), "{took:?}");

    // The limit itself still decodes.
    let ok = chain(MAX_TREE_DEPTH as u64);
    let encoded = codec::encode(&ok, &crypto, &MemStore::new(), &mut SeededRandom::new(4)).unwrap();
    let mut server = Objects {
        blobs: encoded.sealed,
        fetched: 0,
    };
    let tree = codec::decode(&encoded.root, &crypto, &mut MemStore::new(), &mut server).unwrap();
    assert_eq!(tree.len(), MAX_TREE_DEPTH);
}

/// `Tree::check` walks once from the root: 40,000 levels in well under a second (it was about
/// 10^9 steps before).
#[test]
fn checking_a_deep_tree_is_linear() {
    let deep = chain(40_000);
    let started = Instant::now();
    deep.check().unwrap();
    let took = started.elapsed();
    println!("check 40,000 levels: {took:?}");
    assert!(took < Duration::from_secs(2), "{took:?}");
    // Cycles are still found.
    let mut cyclic = chain(3);
    cyclic.insert(item(0), Node::dir(item(2), "d"));
    assert!(cyclic.check().is_err());
}

// -- The folder stops, and "Undo a device" brings it back ------------------------------------

type Disks = Rc<RefCell<BTreeMap<PathBuf, Arc<MemFs>>>>;

fn device(
    server: &Rc<RefCell<ServerState>>,
    disks: &Disks,
    clock: &ManualClock,
    seed: u64,
) -> EngineCore {
    let (server, disks) = (Rc::clone(server), Rc::clone(disks));
    let ports = EnginePorts {
        store: Box::new(MemStore::new()),
        keychain: Box::new(SharedKeychain::default()),
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

#[test]
fn a_head_beyond_the_limits_stops_the_folder_and_undo_a_device_brings_it_back() {
    let server = MemServer::new_shared();
    let disks: Disks = Rc::default();
    let clock = ManualClock::at(1_795_651_200_000);
    let mut a = device(&server, &disks, &clock, 1);
    let mut b = device(&server, &disks, &clock, 2);
    let link = format!("http://localhost:8080/join#{}", base64url(&[9; 16]));
    let ApiResult::Ok(code) = a.begin_account(&link, "Laptop").unwrap() else {
        panic!("begin_account")
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.confirm_recovery_group(&group).unwrap());
    let folder = a.add_folder("mem:/a/Docs", "Docs").unwrap();
    disks.borrow()[&PathBuf::from("mem:/a/Docs")].user_write(&p(&["plan.txt"]), b"v1");
    a.tick();
    // B joins and syncs the folder.
    let offer = a.create_pairing_offer().unwrap();
    assert!(matches!(
        b.start_pairing(&offer.link, "Desktop").unwrap(),
        ApiResult::Ok(_)
    ));
    let request = a
        .tick()
        .into_iter()
        .find_map(|e| match e {
            hangar_drive_sync::api::BackendEvent::PairRequest { request } => Some(request),
            _ => None,
        })
        .expect("pair request");
    a.answer_pair_request(&request.offer_id, true).unwrap();
    clock.advance(1_000);
    b.tick();
    b.add_account_folder(&folder, "mem:/b/Docs").unwrap();
    for _ in 0..3 {
        clock.advance(20_000);
        b.tick();
        a.tick();
    }
    // B (compromised) commits a tree deeper than any folder. An honest device refuses to
    // publish it (follow-up check N-4, `local_limits.rs`), so B ignores its own limits here.
    b.set_tree_limits(usize::MAX, usize::MAX);
    let fs_b = Arc::clone(&disks.borrow()[&PathBuf::from("mem:/b/Docs")]);
    let mut path = Vec::new();
    for _ in 0..(MAX_TREE_DEPTH + 8) {
        path.push("d".to_owned());
        assert!(fs_b.user_mkdir(&path));
    }
    clock.advance(20_000);
    b.tick();
    clock.advance(20_000);
    a.tick();
    let snapshot = a.snapshot();
    assert!(
        snapshot.folders.iter().any(|f| f.status
            == FolderStatus::Stopped {
                reason: StopReasonApi::TreeLimit
            }),
        "{:?}",
        snapshot.folders
    );
    assert!(snapshot
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::TreeLimit { .. })));
    // Nothing of it reached A's disk.
    assert!(disks.borrow()[&PathBuf::from("mem:/a/Docs")]
        .read_all(&p(&["d"]))
        .is_none());

    // "Undo a device": the last head before B's.
    let b_id = a
        .list_devices()
        .unwrap()
        .devices
        .into_iter()
        .find(|d| d.name == "Desktop")
        .unwrap()
        .id;
    let entry = a
        .find_before_device(&folder, &b_id, 0)
        .unwrap()
        .expect("a head before B's");
    let outcome = a.reset_folder(&folder, &entry).unwrap();
    assert!(
        matches!(outcome, RestoreOutcome::Done { .. }),
        "{outcome:?}"
    );
    clock.advance(20_000);
    a.tick();
    let snapshot = a.snapshot();
    assert!(
        snapshot
            .folders
            .iter()
            .all(|f| !matches!(f.status, FolderStatus::Stopped { .. })),
        "{:?}",
        snapshot.folders
    );
    assert_eq!(
        disks.borrow()[&PathBuf::from("mem:/a/Docs")].read_all(&p(&["plan.txt"])),
        Some(b"v1".to_vec())
    );
}
