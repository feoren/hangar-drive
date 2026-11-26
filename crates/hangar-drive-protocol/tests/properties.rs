//! Property tests of the protocol crate's formats (ADR 0001, Amendment, robustness): for every
//! format `decode(encode(x)) == x`, and a decoder accepts only bytes that `encode` produces,
//! checked on random values and on random mutations of valid encodings.

use hangar_drive_protocol::format::{DirectoryEntry, DirectoryNode, FileManifest};
use hangar_drive_protocol::framing::{Reader, Writer};
use hangar_drive_protocol::ids::{Blob, CommitId, DeviceId, ItemId, ObjectId, PublicKey};
use hangar_drive_protocol::name::{collision, comparison_key, CaseKeys, Collision};
use hangar_drive_protocol::object::{chunk_count, EntryFlags, EntryKind, CHUNK_SIZE};
use proptest::prelude::*;

/// One change to a byte string: flip a bit, insert or delete a byte, or cut the end.
#[derive(Debug, Clone)]
enum Mutation {
    Flip(usize, u8),
    Insert(usize, u8),
    Delete(usize),
    Truncate(usize),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), 0u8..8).prop_map(|(at, bit)| Mutation::Flip(at, bit)),
        (any::<usize>(), any::<u8>()).prop_map(|(at, b)| Mutation::Insert(at, b)),
        any::<usize>().prop_map(Mutation::Delete),
        any::<usize>().prop_map(Mutation::Truncate),
    ]
}

fn mutate(bytes: &[u8], mutations: &[Mutation]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for m in mutations {
        let len = out.len();
        match *m {
            Mutation::Flip(at, bit) if len > 0 => out[at % len] ^= 1 << bit,
            Mutation::Insert(at, byte) => out.insert(at % (len + 1), byte),
            Mutation::Delete(at) if len > 0 => {
                out.remove(at % len);
            }
            Mutation::Truncate(at) => out.truncate(at % (len + 1)),
            _ => {}
        }
    }
    out
}

/// Names from a small alphabet with composed and decomposed letters, case pairs and
/// characters that Windows forbids, so collisions and sort order are exercised.
fn name() -> impl Strategy<Value = String> {
    let parts = prop::sample::select(vec![
        "a",
        "A",
        "b",
        "\u{e9}",
        "e\u{301}",
        "\u{df}",
        "\u{17f}",
        "s",
        ".",
        " ",
        ":",
        "\\",
        "\u{3c3}",
        "\u{3c2}",
        "\u{1f600}",
        "~",
        "x",
    ]);
    prop::collection::vec(parts, 1..6)
        .prop_map(|parts| parts.concat())
        .prop_filter("not a dot name", |n| n != "." && n != "..")
}

fn entry() -> impl Strategy<Value = DirectoryEntry> {
    (
        name(),
        any::<[u8; 16]>(),
        any::<bool>(),
        any::<[u8; 32]>(),
        0u64..10_000_000,
        any::<i64>(),
        any::<bool>(),
        prop::option::of(any::<[u8; 16]>()),
    )
        .prop_map(|(name, item, dir, child, size, mtime_ms, exec, conflict)| {
            let kind = if dir {
                EntryKind::Directory
            } else {
                EntryKind::File
            };
            DirectoryEntry {
                name,
                item: ItemId::from_bytes(item),
                kind,
                child: ObjectId::from_bytes(child),
                size: if dir { 0 } else { size },
                mtime_ms,
                flags: EntryFlags::executable(exec && !dir),
                conflict_of: conflict.filter(|c| *c != item).map(ItemId::from_bytes),
            }
        })
}

fn node() -> impl Strategy<Value = DirectoryNode> {
    prop::collection::vec(entry(), 0..8).prop_filter_map("unique keys and items", |entries| {
        DirectoryNode::new(entries).ok()
    })
}

fn manifest() -> impl Strategy<Value = FileManifest> {
    (
        0u64..=3 * CHUNK_SIZE + 7,
        any::<i64>(),
        any::<bool>(),
        any::<[u8; 32]>(),
    )
        .prop_map(|(size, mtime, exec, seed)| {
            let chunks = (0..chunk_count(size))
                .map(|i| {
                    let mut id = seed;
                    id[0] ^= i as u8;
                    ObjectId::from_bytes(id)
                })
                .collect();
            FileManifest::new(size, mtime, EntryFlags::executable(exec), chunks)
                .expect("a consistent manifest")
        })
}

proptest! {
    #[test]
    fn directory_nodes_round_trip(node in node()) {
        let bytes = node.encode().unwrap();
        prop_assert_eq!(DirectoryNode::decode(&bytes).unwrap(), node);
    }

    #[test]
    fn directory_node_decoding_accepts_only_encodings(
        node in node(),
        mutations in prop::collection::vec(mutation(), 1..4),
    ) {
        let bytes = mutate(&node.encode().unwrap(), &mutations);
        if let Ok(decoded) = DirectoryNode::decode(&bytes) {
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn directory_node_decoding_of_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(decoded) = DirectoryNode::decode(&bytes) {
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn file_manifests_round_trip(manifest in manifest()) {
        let bytes = manifest.encode().unwrap();
        prop_assert_eq!(FileManifest::decode(&bytes).unwrap(), manifest);
    }

    #[test]
    fn file_manifest_decoding_accepts_only_encodings(
        manifest in manifest(),
        mutations in prop::collection::vec(mutation(), 1..4),
    ) {
        let bytes = mutate(&manifest.encode().unwrap(), &mutations);
        if let Ok(decoded) = FileManifest::decode(&bytes) {
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn ids_have_one_text_form(bytes in any::<[u8; 32]>(), text in "[0-9a-fA-F]{0,66}") {
        let id = CommitId::from_bytes(bytes);
        prop_assert_eq!(CommitId::from_hex(&id.to_hex()).unwrap(), id);
        if let Ok(parsed) = CommitId::from_hex(&text) {
            prop_assert_eq!(parsed.to_hex(), text);
        }
        let device = DeviceId::from_bytes([bytes[0]; 16]);
        prop_assert_eq!(device.to_hex().parse::<DeviceId>().unwrap(), device);
    }

    #[test]
    fn base64_values_have_one_text_form(bytes in any::<[u8; 32]>(), text in "[A-Za-z0-9_=+/-]{0,46}") {
        let key = PublicKey::from_bytes(bytes);
        prop_assert_eq!(PublicKey::from_base64url(&key.to_base64url()).unwrap(), key);
        if let Ok(parsed) = PublicKey::from_base64url(&text) {
            prop_assert_eq!(parsed.to_base64url(), text);
        }
    }

    #[test]
    fn blobs_round_trip_through_json(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
        let blob = Blob(bytes);
        let json = serde_json::to_string(&blob).unwrap();
        prop_assert_eq!(serde_json::from_str::<Blob>(&json).unwrap(), blob);
    }

    #[test]
    fn framing_round_trips(parts in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..40), 0..6)) {
        let mut w = Writer::new();
        for part in &parts {
            w.field(part);
        }
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        for part in &parts {
            prop_assert_eq!(r.field(), Some(part.as_slice()));
        }
        prop_assert_eq!(r.finish(), Some(()));
    }

    #[test]
    fn case_collisions_are_symmetric_and_keyed_by_nfc(a in name(), b in name()) {
        prop_assert_eq!(collision(&a, &b), collision(&b, &a));
        if a != b && comparison_key(&a) == comparison_key(&b) {
            prop_assert_eq!(collision(&a, &b), Some(Collision::Normalization));
        }
        let same_keys = CaseKeys::of(&a).collides(&CaseKeys::of(&b));
        if a != b && comparison_key(&a) != comparison_key(&b) {
            prop_assert_eq!(collision(&a, &b) == Some(Collision::Case), same_keys);
        }
        // Lower and upper case of one name always collide (no false negatives).
        let upper = a.to_uppercase();
        if upper != a && comparison_key(&upper) != comparison_key(&a) {
            prop_assert_eq!(collision(&a, &upper), Some(Collision::Case));
        }
    }
}
