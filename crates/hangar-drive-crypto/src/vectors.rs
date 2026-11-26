//! The fixed test vectors of `testdata/vectors.json`: this crate's output for fixed inputs must
//! equal the file, and `test_vectors.py` recomputes the same file independently with the
//! Python standard library. A format change shows in both; regenerate the file with
//! `py -3 crates/hangar-drive-crypto/test_vectors.py --write` only after a deliberate change.

use std::collections::BTreeMap;

use hangar_drive_protocol::format::{DirectoryEntry, DirectoryNode, FileManifest};
use hangar_drive_protocol::ids::{
    AccountId, Challenge, DeviceId, Epoch, FolderId, Generation, ItemId, LogHead, ObjectId,
    ServerId,
};
use hangar_drive_protocol::name::{
    case_key, check_display_name, comparison_key, fold_key, is_format_character, upper_key,
    DisplayNameError,
};
use hangar_drive_protocol::object::{EntryFlags, EntryKind, ObjectType};
use zeroize::Zeroizing;

use crate::commit::{ChainEntry, Commit, CommitContent, SignedCommit};
use crate::device_names::{seal_device_names, DeviceName, DeviceNameList};
use crate::devicelog::{AccountState, EntryKind as LogKind, LogDevice};
use crate::entropy::FixedEntropy;
use crate::epoch::{wrap, AccountSecret};
use crate::folder_keys::{seal_folder_list, seal_ring, FolderEntry, FolderKeyRing, FolderList};
use crate::identity::{folder_safety_number, safety_number, server_key_number, DeviceIdentity};
use crate::object::{padme, ObjectKeys};
use crate::pairing::{parse_server_url, OfferContent, PairingSecret};
use crate::record::RecordCipher;
use crate::recovery::{RecoveryCode, RecoverySheet};

fn counting(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

fn array<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&counting(start, N));
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const ISSUED_AT: u64 = 1_700_000_000_000;
const MTIME: i64 = 1_700_000_000_000;
const G1: Generation = Generation(1);

/// Names whose case keys differ between the three keys of the name policy.
const CASE_NAMES: [&str; 6] = [
    "CAF\u{c9}",
    "Ma\u{17f}\u{17f}e \u{df}",
    "\u{39f}\u{394}\u{39f}\u{3a3} \u{3c2}",
    "\u{b5}\u{3d0} \u{fb01}",
    "f\u{131}le \u{130}",
    "\u{1c6}\u{1c4}\u{1c5}",
];

/// Display names across every rule of [`check_display_name`], checked with a bound of 16
/// bytes.
const DISPLAY_NAMES: [&str; 24] = [
    "Laptop",
    "",
    "seventeen bytes!!",
    "a\u{7f}b",
    "a\u{202e}b",
    " ",
    "\u{3000}\u{a0}",
    "\u{3164}",
    "\u{115f}\u{1160} \u{ffa0}",
    " Laptop",
    "Laptop\u{2003}",
    "My Laptop",
    "\u{d55c}\u{3164}",
    "\u{3164}a",
    // Security review N12: blank characters, and fillers at the edge.
    "\u{2800}",
    "\u{34f}",
    "\u{fe0f}\u{e0100}",
    "\u{e000}",
    "a\u{2800}",
    "\u{34f}a",
    "Anna \u{2764}\u{fe0f}",
    "a \u{fe0f}",
    // Default ignorable code points, a reserved one alone and one at the edge.
    "\u{2065}",
    "\u{180b}a",
];

/// The verdict of [`check_display_name`] on each of [`DISPLAY_NAMES`].
fn display_verdicts() -> String {
    DISPLAY_NAMES
        .iter()
        .map(|name| match check_display_name(name, 16) {
            Ok(()) => "ok",
            Err(DisplayNameError::Empty) => "empty",
            Err(DisplayNameError::TooLong) => "too-long",
            Err(DisplayNameError::Control) => "control",
            Err(DisplayNameError::Format) => "format",
            Err(DisplayNameError::Blank) => "blank",
            Err(DisplayNameError::EdgeWhitespace) => "edge-whitespace",
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The code point ranges [`is_format_character`] refuses, merged, as `low-high` in hex.
fn format_ranges() -> String {
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for c in (0..=0x10ffffu32).filter_map(char::from_u32) {
        if !is_format_character(c) {
            continue;
        }
        let c = u32::from(c);
        match ranges.last_mut() {
            Some((_, high)) if *high + 1 == c => *high = c,
            _ => ranges.push((c, c)),
        }
    }
    ranges
        .iter()
        .map(|(low, high)| format!("{low:x}-{high:x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn compute() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut put = |name: &str, value: String| {
        out.insert(name.to_owned(), value);
    };
    let account = AccountId::from_bytes(array(0x10));
    let device = DeviceId::from_bytes(array(0x20));
    let folder = FolderId::from_bytes(array(0x30));
    let server = ServerId::from_bytes(array(0x40));
    let identity = DeviceIdentity::from_seeds(&array(0x50)).unwrap();
    let keys = identity.public_keys();
    put("identity.sign_public", hex(keys.sign.as_bytes()));
    put("identity.kem_public", hex(keys.kem.as_bytes()));
    put(
        "identity.safety_number",
        safety_number(&account, &device, &keys).to_string(),
    );
    put(
        "identity.proof",
        hex(identity.prove(&account, &device, false).as_bytes()),
    );

    // Device log: create and rotate epoch 1.
    let mut state = AccountState::new(account);
    let create = state
        .next_entry(
            &identity,
            device,
            ISSUED_AT,
            LogKind::Create {
                devices: vec![LogDevice::of(&identity, &account, device, false)],
            },
        )
        .unwrap();
    let create_head = state.apply(&create).unwrap();
    put("log.create_entry", hex(&create));
    put("log.create_hash", hex(create_head.hash.as_bytes()));
    let secret = AccountSecret::from_bytes(Zeroizing::new(array(0x60)));
    let commitment = secret.commitment(&account, Epoch(1));
    put("epoch.commitment", hex(&commitment.0));
    let rotate = state
        .next_entry(
            &identity,
            device,
            ISSUED_AT + 1,
            LogKind::Rotate {
                epoch: Epoch(1),
                commitment,
            },
        )
        .unwrap();
    let head = state.apply(&rotate).unwrap();
    put("log.rotate_entry", hex(&rotate));
    put("log.rotate_hash", hex(head.hash.as_bytes()));
    put(
        "log.safety_number",
        state.safety_number().unwrap().to_string(),
    );
    let wrapped = wrap(
        &secret,
        &account,
        Epoch(1),
        &device,
        &keys.kem,
        &mut FixedEntropy::counting(0x80, 32),
    )
    .unwrap();
    put("epoch.wrapped_key", hex(&wrapped));

    // The log goes on in a copy: a second device is added (3) and removed again (4).
    let device2 = DeviceId::from_bytes(array(0x29));
    let identity2 = DeviceIdentity::from_seeds(&array(0x91)).unwrap();
    let mut later = state.clone();
    let add = later
        .next_entry(
            &identity,
            device,
            ISSUED_AT + 2,
            LogKind::AddDevice(LogDevice::of(&identity2, &account, device2, false)),
        )
        .unwrap();
    let add_head = later.apply(&add).unwrap();
    put("log.add_entry", hex(&add));
    put("log.add_hash", hex(add_head.hash.as_bytes()));
    let remove = later
        .next_entry(
            &identity,
            device,
            ISSUED_AT + 3,
            LogKind::RemoveDevice(device2),
        )
        .unwrap();
    let remove_head = later.apply(&remove).unwrap();
    put("log.remove_entry", hex(&remove));
    put("log.remove_hash", hex(remove_head.hash.as_bytes()));

    // Objects.
    let ring =
        FolderKeyRing::new(folder, head.index, &mut FixedEntropy::counting(0xa0, 32)).unwrap();
    let object_keys = ObjectKeys::from_ring(&account, &ring, G1).unwrap();
    let chunk = b"hello, drive";
    let sealed = object_keys
        .seal(
            ObjectType::Chunk,
            chunk,
            &mut FixedEntropy::counting(0xb0, 24),
        )
        .unwrap();
    put("object.chunk_id", hex(sealed.id.as_bytes()));
    put("object.chunk_blob", hex(&sealed.blob));
    assert_eq!(
        object_keys
            .open(&sealed.id, ObjectType::Chunk, &sealed.blob)
            .unwrap()
            .as_slice(),
        chunk
    );
    let manifest = FileManifest::new(
        chunk.len() as u64,
        MTIME,
        EntryFlags::executable(true),
        vec![sealed.id],
    )
    .unwrap()
    .encode()
    .unwrap();
    put("format.file_manifest", hex(&manifest));
    let manifest_id = object_keys
        .object_id(ObjectType::FileManifest, &manifest)
        .unwrap();
    put("object.manifest_id", hex(manifest_id.as_bytes()));
    let empty = DirectoryNode::new(vec![]).unwrap().encode().unwrap();
    let empty_id = object_keys
        .object_id(ObjectType::DirectoryNode, &empty)
        .unwrap();
    put("object.empty_node_id", hex(empty_id.as_bytes()));
    let original = ItemId::from_bytes(array(0x01));
    let file = |name: &str, item: ItemId, flags, conflict_of| DirectoryEntry {
        name: name.to_owned(),
        item,
        kind: EntryKind::File,
        child: manifest_id,
        size: chunk.len() as u64,
        mtime_ms: MTIME,
        flags,
        conflict_of,
    };
    let node = DirectoryNode::new(vec![
        file(
            "cafe\u{301}.txt",
            original,
            EntryFlags::executable(true),
            None,
        ),
        file(
            "cafe\u{301} (conflict laptop 2026-11-26).txt",
            ItemId::from_bytes(array(0x02)),
            EntryFlags::NONE,
            Some(original),
        ),
        DirectoryEntry {
            name: "Docs".into(),
            item: ItemId::from_bytes(array(0x03)),
            kind: EntryKind::Directory,
            child: empty_id,
            size: 0,
            mtime_ms: MTIME,
            flags: EntryFlags::NONE,
            conflict_of: None,
        },
    ])
    .unwrap()
    .encode()
    .unwrap();
    put("format.directory_node", hex(&node));
    let root: ObjectId = object_keys
        .object_id(ObjectType::DirectoryNode, &node)
        .unwrap();
    put("object.root_id", hex(root.as_bytes()));

    // Commits: the first commit, a re-anchor commit on it, a side commit on it and the merge of
    // the re-anchor commit (as the server head) with the side commit.
    let content = |counter| CommitContent {
        root,
        generation: G1,
        device,
        log_head: head,
        counter,
    };
    let first = Commit::first(account, folder, content(1))
        .sign(&identity)
        .unwrap();
    put("commit.first_id", hex(first.id.as_bytes()));
    put("commit.first_wire", hex(&first.wire));
    let base = ChainEntry {
        commit: first.id,
        height: 1,
        sequence: 1,
        generation: G1,
        log_index: 2,
    };
    let reanchor = Commit::reanchor(account, folder, &base, content(2))
        .sign(&identity)
        .unwrap();
    put("commit.reanchor_id", hex(reanchor.id.as_bytes()));
    put("commit.reanchor_wire", hex(&reanchor.wire));
    let side = Commit::side(account, folder, &base, content(3))
        .sign(&identity)
        .unwrap();
    put("commit.side_id", hex(side.id.as_bytes()));
    put("commit.side_wire", hex(&side.wire));
    let server_head = ChainEntry {
        commit: reanchor.id,
        height: 2,
        sequence: 2,
        generation: G1,
        log_index: 2,
    };
    let merge = Commit::merge(account, folder, &server_head, &side, content(4))
        .sign(&identity)
        .unwrap();
    put("commit.merge_id", hex(merge.id.as_bytes()));
    put("commit.merge_wire", hex(&merge.wire));
    put(
        "identity.folder_safety_number",
        folder_safety_number(&account, &folder, &first.id, 1).to_string(),
    );

    // Records: the folder key ring, the folder list and the device names, each sealed as
    // version 1 under epoch 1.
    put("record.ring_plaintext", hex(&ring.encode()));
    let cipher = RecordCipher::for_epoch(&state, &secret, Epoch(1)).unwrap();
    let record = seal_ring(
        &cipher,
        &ring,
        1,
        &identity,
        &device,
        &head,
        &mut FixedEntropy::counting(0xc0, 24),
    )
    .unwrap();
    put("record.ring_sealed", hex(&record));
    let list = FolderList::new(vec![FolderEntry {
        folder,
        name: "Photos".into(),
    }])
    .unwrap();
    put("record.folder_list", hex(&list.encode().unwrap()));
    let many = FolderList::new(vec![
        FolderEntry {
            folder: FolderId::from_bytes(array(0x33)),
            name: "Caf\u{e9} \u{1f600}".into(),
        },
        FolderEntry {
            folder,
            name: "Photos".into(),
        },
        FolderEntry {
            folder: FolderId::from_bytes(array(0x31)),
            name: "Arbeit".into(),
        },
    ])
    .unwrap();
    put("record.folder_list_many", hex(&many.encode().unwrap()));
    let folders_sealed = seal_folder_list(
        &cipher,
        &many,
        1,
        &identity,
        &device,
        &head,
        &mut FixedEntropy::counting(0xc8, 24),
    )
    .unwrap();
    put("record.folders_sealed", hex(&folders_sealed));
    let names = DeviceNameList::new(vec![
        DeviceName {
            device: device2,
            name: "Laptop".into(),
        },
        DeviceName {
            device,
            name: "Desktop".into(),
        },
    ])
    .unwrap();
    put("record.device_names", hex(&names.encode().unwrap()));
    let names_sealed = seal_device_names(
        &cipher,
        &names,
        1,
        &identity,
        &device,
        &head,
        &mut FixedEntropy::counting(0xd8, 24),
    )
    .unwrap();
    put("record.device_names_sealed", hex(&names_sealed));

    // Recovery.
    let code = RecoveryCode::generate(&mut FixedEntropy::counting(0xd0, 16)).unwrap();
    put("recovery.code", code.reveal().to_string());
    let recovery = code.identity().unwrap().public_keys();
    put("recovery.sign_public", hex(recovery.sign.as_bytes()));
    put("recovery.kem_public", hex(recovery.kem.as_bytes()));
    put("recovery.device_id", code.device_id().unwrap().to_hex());
    // The recovery sheet (version 2): anchored at the create entry, with and without a pin.
    let sheet = RecoverySheet {
        server_url: parse_server_url("https://drive.example").unwrap(),
        server,
        account,
        genesis: create_head.hash,
        pin: Some(array(0xf0)),
    };
    put("recovery.sheet", hex(&sheet.encode()));
    let plain = RecoverySheet { pin: None, ..sheet };
    put("recovery.sheet_unpinned", hex(&plain.encode()));

    // Pairing.
    let pairing = PairingSecret::generate(&mut FixedEntropy::counting(0xe0, 16)).unwrap();
    put("pairing.code", pairing.reveal().to_string());
    put("pairing.id", pairing.pairing_id().unwrap().to_hex());
    let request = pairing
        .request(
            &identity,
            &account,
            device,
            "Laptop",
            &mut FixedEntropy::counting(0xe8, 24),
        )
        .unwrap();
    put("pairing.sealed_name", hex(request.sealed_name.as_bytes()));
    put("pairing.tag", hex(request.tag.as_bytes()));
    let offer = OfferContent {
        server_url: parse_server_url("https://drive.example").unwrap(),
        spki_pin: Some(array(0xf0)),
        server,
        account,
        inviter: device,
        head: LogHead {
            index: head.index,
            hash: head.hash,
        },
        secret: pairing,
        expires_at_ms: ISSUED_AT + 600_000,
    }
    .sign(&identity)
    .unwrap();
    put("pairing.offer", hex(&offer.encode().unwrap()));

    // Session and server key number.
    let challenge = Challenge::from_bytes(array(0x70));
    put(
        "session.proof",
        hex(identity
            .prove_session(
                &server,
                "https://drive.example/",
                &account,
                &device,
                &challenge,
            )
            .as_bytes()),
    );
    put(
        "identity.server_key_number",
        server_key_number(&server, &array(0xf0)).to_string(),
    );

    // Name policy and padding.
    put(
        "name.comparison_key",
        hex(comparison_key("cafe\u{301}").as_bytes()),
    );
    put("name.case_key", hex(case_key("CAF\u{c9}").as_bytes()));
    let keys_of = |f: fn(&str) -> String| {
        CASE_NAMES
            .iter()
            .map(|n| hex(f(n).as_bytes()))
            .collect::<Vec<_>>()
            .join(" ")
    };
    put("name.case_keys", keys_of(case_key));
    put("name.fold_keys", keys_of(fold_key));
    put("name.upper_keys", keys_of(upper_key));
    put("name.format_ranges", format_ranges());
    put("name.display_names", display_verdicts());
    let lengths = [8u64, 9, 15, 17, 100, 1000, 1025, 65544, 4_194_312];
    put(
        "padme",
        lengths
            .iter()
            .map(|n| format!("{n}:{}", padme(*n)))
            .collect::<Vec<_>>()
            .join(" "),
    );
    out
}

#[test]
fn every_vector_matches_the_file() {
    let file: BTreeMap<String, String> =
        serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let computed = compute();
    for (name, value) in &computed {
        assert_eq!(file.get(name), Some(value), "vector {name}");
    }
    assert_eq!(
        file.keys().collect::<Vec<_>>(),
        computed.keys().collect::<Vec<_>>(),
        "the same vectors on both sides"
    );
}

#[test]
fn the_vectors_open_and_verify() {
    // The stored records, commits, log and offer are not only equal bytes but valid ones.
    let file: BTreeMap<String, String> =
        serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let unhex = |name: &str| -> Vec<u8> {
        let text = &file[name];
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    };
    let account = AccountId::from_bytes(array(0x10));
    let folder = FolderId::from_bytes(array(0x30));
    let server = ServerId::from_bytes(array(0x40));
    let state = AccountState::from_entries(
        account,
        [unhex("log.create_entry"), unhex("log.rotate_entry")]
            .iter()
            .map(Vec::as_slice),
    )
    .unwrap();
    let first = SignedCommit::decode(&unhex("commit.first_wire")).unwrap();
    first.verify_signer(&state, &folder).unwrap();
    let reanchor = SignedCommit::decode(&unhex("commit.reanchor_wire")).unwrap();
    assert!(reanchor.commit.reanchor);
    let side = SignedCommit::decode(&unhex("commit.side_wire")).unwrap();
    assert!(side.commit.side);
    side.verify_signer(&state, &folder).unwrap();
    let merge = SignedCommit::decode(&unhex("commit.merge_wire")).unwrap();
    assert_eq!(merge.commit.parents, vec![reanchor.id, side.id]);
    merge.verify_signer(&state, &folder).unwrap();
    let secret = AccountSecret::from_bytes(Zeroizing::new(array(0x60)));
    let cipher = RecordCipher::for_epoch(&state, &secret, Epoch(1)).unwrap();
    let ring =
        crate::folder_keys::open_ring(&cipher, &state, &folder, 1, &unhex("record.ring_sealed"))
            .unwrap();
    assert_eq!(ring.ring.newest_generation(), G1);
    assert_eq!(ring.ring.newest_created_at(), 2);
    let (list, _) =
        crate::folder_keys::open_folder_list(&cipher, &state, 1, &unhex("record.folders_sealed"))
            .unwrap();
    assert_eq!(list.folders().len(), 3);
    let (names, _) = crate::device_names::open_device_names(
        &cipher,
        &state,
        1,
        &unhex("record.device_names_sealed"),
    )
    .unwrap();
    assert_eq!(names.names().len(), 2);
    assert!(DirectoryNode::decode(&unhex("format.directory_node")).is_ok());
    assert!(FileManifest::decode(&unhex("format.file_manifest")).is_ok());
    let offer = crate::pairing::PairingOffer::decode(&unhex("pairing.offer")).unwrap();
    assert!(offer.server_address(&state, &server).is_ok());
    // The log goes on with the added and the removed device.
    let mut later = state.clone();
    later.apply(&unhex("log.add_entry")).unwrap();
    later.apply(&unhex("log.remove_entry")).unwrap();
    assert!(later.rotation_due());
    assert_eq!(later.last_removal_index(), 4);
}
