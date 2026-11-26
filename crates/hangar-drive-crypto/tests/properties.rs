//! Property tests of every format of the crypto crate (ADR 0001, Amendment, robustness): for
//! every format `decode(encode(x)) == x`, and a decoder accepts only bytes that `encode`
//! produces, checked on random values and on random mutations of valid encodings. For the
//! authenticated formats (records, objects, wrapped keys) "only images of encode" means that
//! nothing but the exact sealed bytes opens.
//!
//! Not covered by the second property: typed codes ([`RecoveryCode::parse`],
//! [`PairingSecret::parse`]), which accept lower case, spaces, hyphens and the look-alikes
//! `O`, `I`, `L` by design; for them only the round trip is a property.

use std::sync::OnceLock;

use hangar_drive_crypto::commit::{ChainEntry, Commit, CommitContent, SignedCommit};
use hangar_drive_crypto::device_names::{DeviceName, DeviceNameList};
use hangar_drive_crypto::devicelog::{AccountState, EntryKind, LogDevice, LogEntry};
use hangar_drive_crypto::epoch::{rotate, unwrap, wrap, AccountSecret, EpochCommitment};
use hangar_drive_crypto::folder_keys::{FolderEntry, FolderKeyRing, FolderList};
use hangar_drive_crypto::identity::{DeviceIdentity, DevicePublicKeys};
use hangar_drive_crypto::object::ObjectKeys;
use hangar_drive_crypto::pairing::{parse_server_url, OfferContent, PairingOffer, PairingSecret};
use hangar_drive_crypto::record::{record_header, RecordCipher};
use hangar_drive_crypto::recovery::RecoveryCode;
use hangar_drive_crypto::{Entropy, EntropyError, OsEntropy};
use hangar_drive_protocol::api::{RecordKey, RecordKind};
use hangar_drive_protocol::ids::{
    AccountId, CommitId, DeviceId, Epoch, FolderId, Generation, LogHash, LogHead, ObjectId,
    PublicKey, ServerId, Signature,
};
use hangar_drive_protocol::object::ObjectType;
use proptest::prelude::*;

const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
const FOLDER: FolderId = FolderId::from_bytes([3; 16]);

const DEVICE: DeviceId = DeviceId::from_bytes([1; 16]);

fn identity() -> &'static DeviceIdentity {
    static IDENTITY: OnceLock<DeviceIdentity> = OnceLock::new();
    IDENTITY.get_or_init(|| DeviceIdentity::generate(&mut OsEntropy).expect("os randomness"))
}

/// An account of [`identity`] as [`DEVICE`] with epoch 1, and that epoch's secret.
fn account() -> &'static (AccountState, AccountSecret) {
    static ACCOUNT_STATE: OnceLock<(AccountState, AccountSecret)> = OnceLock::new();
    ACCOUNT_STATE.get_or_init(|| {
        let mut state = AccountState::new(ACCOUNT);
        let create = state
            .next_entry(
                identity(),
                DEVICE,
                0,
                EntryKind::Create {
                    devices: vec![LogDevice::of(identity(), &ACCOUNT, DEVICE, false)],
                },
            )
            .expect("create");
        state.apply(&create).expect("apply");
        let rotation = rotate(&state, identity(), DEVICE, 0, &mut OsEntropy).expect("rotate");
        state.apply(&rotation.entry).expect("apply");
        (state, rotation.secret)
    })
}

/// Entropy from fixed bytes, repeated, so a generated value is reproducible.
struct Seeded(Vec<u8>, usize);

impl Entropy for Seeded {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for byte in dest {
            *byte = self.0[self.1 % self.0.len()].wrapping_add((self.1 / self.0.len()) as u8);
            self.1 += 1;
        }
        Ok(())
    }
}

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

fn mutations() -> impl Strategy<Value = Vec<Mutation>> {
    prop::collection::vec(mutation(), 1..4)
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

fn log_device() -> impl Strategy<Value = LogDevice> {
    (
        any::<[u8; 16]>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<bool>(),
        any::<[u8; 64]>(),
    )
        .prop_map(|(id, sign, kem, recovery, proof)| LogDevice {
            id: DeviceId::from_bytes(id),
            keys: DevicePublicKeys {
                sign: PublicKey::from_bytes(sign),
                kem: PublicKey::from_bytes(kem),
            },
            recovery,
            proof: Signature::from_bytes(proof),
        })
}

fn entry_kind() -> impl Strategy<Value = EntryKind> {
    prop_oneof![
        prop::collection::vec(log_device(), 1..=8)
            .prop_map(|devices| EntryKind::Create { devices }),
        log_device().prop_map(EntryKind::AddDevice),
        any::<[u8; 16]>().prop_map(|d| EntryKind::RemoveDevice(DeviceId::from_bytes(d))),
        (any::<u32>(), any::<[u8; 32]>()).prop_map(|(e, c)| EntryKind::Rotate {
            epoch: Epoch(e),
            commitment: EpochCommitment(c),
        }),
    ]
}

fn log_entry() -> impl Strategy<Value = LogEntry> {
    (
        any::<[u8; 16]>(),
        any::<u64>(),
        prop::option::of(any::<[u8; 32]>()),
        any::<u64>(),
        any::<[u8; 16]>(),
        entry_kind(),
        any::<[u8; 64]>(),
    )
        .prop_map(
            |(account, index, prev, issued_at_ms, issuer, kind, sig)| LogEntry {
                account: AccountId::from_bytes(account),
                index,
                prev: prev.map(LogHash::from_bytes),
                issued_at_ms,
                issuer: DeviceId::from_bytes(issuer),
                kind,
                signature: Signature::from_bytes(sig),
            },
        )
}

fn content() -> impl Strategy<Value = CommitContent> {
    (
        any::<[u8; 32]>(),
        1u32..10,
        any::<[u8; 16]>(),
        1u64..1000,
        any::<[u8; 32]>(),
        1u64..u64::MAX,
    )
        .prop_map(
            |(root, generation, device, index, hash, counter)| CommitContent {
                root: ObjectId::from_bytes(root),
                generation: Generation(generation),
                device: DeviceId::from_bytes(device),
                log_head: LogHead {
                    index,
                    hash: LogHash::from_bytes(hash),
                },
                counter,
            },
        )
}

fn base() -> impl Strategy<Value = ChainEntry> {
    (any::<[u8; 32]>(), 1u64..1000).prop_map(|(id, height)| ChainEntry {
        commit: CommitId::from_bytes(id),
        height,
        sequence: height,
        generation: Generation(1),
        log_index: 1,
    })
}

fn commit() -> impl Strategy<Value = Commit> {
    (0u8..5, base(), base(), content()).prop_map(|(shape, a, b, content)| match shape {
        0 => Commit::first(ACCOUNT, FOLDER, content),
        1 => Commit::on(ACCOUNT, FOLDER, &a, content),
        2 => Commit::side(ACCOUNT, FOLDER, &a, content),
        3 => Commit::reanchor(ACCOUNT, FOLDER, &a, content),
        _ => {
            let side = Commit::side(ACCOUNT, FOLDER, &b, content)
                .sign(identity())
                .expect("a valid side commit");
            Commit::merge(ACCOUNT, FOLDER, &a, &side, content)
        }
    })
}

fn ring() -> impl Strategy<Value = FolderKeyRing> {
    (
        prop::collection::vec(0u64..5, 0..6),
        1u64..100,
        prop::collection::vec(any::<u8>(), 1..32),
    )
        .prop_map(|(steps, start, seed)| {
            let mut entropy = Seeded(seed, 0);
            let mut ring = FolderKeyRing::new(FOLDER, start, &mut entropy).expect("a ring");
            let mut at = start;
            for step in steps {
                at += step;
                ring.add_generation(at, &mut entropy).expect("a generation");
            }
            ring
        })
}

/// A valid display name: spaces only inside, since a padded name is refused.
fn display_name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9\u{e9}\u{df}\u{1f600}-]([A-Za-z0-9 \u{e9}\u{df}\u{1f600}-]{0,18}[A-Za-z0-9\u{e9}\u{df}\u{1f600}-])?"
}

fn folder_list() -> impl Strategy<Value = FolderList> {
    prop::collection::btree_map(any::<[u8; 16]>(), display_name(), 0..6).prop_map(|map| {
        FolderList::new(
            map.into_iter()
                .map(|(id, name)| FolderEntry {
                    folder: FolderId::from_bytes(id),
                    name,
                })
                .collect(),
        )
        .expect("a valid list")
    })
}

fn device_names() -> impl Strategy<Value = DeviceNameList> {
    prop::collection::btree_map(any::<[u8; 16]>(), display_name(), 0..6).prop_map(|map| {
        DeviceNameList::new(
            map.into_iter()
                .map(|(id, name)| DeviceName {
                    device: DeviceId::from_bytes(id),
                    name,
                })
                .collect(),
        )
        .expect("a valid list")
    })
}

fn offer() -> impl Strategy<Value = PairingOffer> {
    (
        prop::sample::select(vec![
            "https://drive.example/",
            "https://drive.example:8443/base",
            "http://localhost:8080/",
            "http://[::1]/",
            "https://xn--caf-dma.example/a/b",
        ]),
        prop::option::of(any::<[u8; 32]>()),
        any::<[u8; 16]>(),
        1u64..u64::MAX,
        any::<[u8; 32]>(),
        any::<[u8; 16]>(),
        any::<u64>(),
    )
        .prop_map(|(url, pin, server, index, hash, secret, expires)| {
            OfferContent {
                server_url: parse_server_url(url).expect("an allowed url"),
                spki_pin: pin,
                server: ServerId::from_bytes(server),
                account: ACCOUNT,
                inviter: DEVICE,
                head: LogHead {
                    index,
                    hash: LogHash::from_bytes(hash),
                },
                secret: PairingSecret::generate(&mut Seeded(secret.to_vec(), 0)).expect("a secret"),
                expires_at_ms: expires,
            }
            .sign(identity())
            .expect("a signed offer")
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn log_entries_round_trip(entry in log_entry()) {
        let bytes = entry.encode();
        prop_assert_eq!(LogEntry::decode(&bytes).unwrap(), entry);
    }

    #[test]
    fn log_entry_decoding_accepts_only_encodings(entry in log_entry(), m in mutations()) {
        let bytes = mutate(&entry.encode(), &m);
        if let Ok(decoded) = LogEntry::decode(&bytes) {
            prop_assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn commits_round_trip(commit in commit()) {
        let signed = commit.sign(identity()).unwrap();
        prop_assert_eq!(SignedCommit::decode(&signed.wire).unwrap(), signed);
    }

    #[test]
    fn commit_decoding_accepts_only_encodings(commit in commit(), m in mutations()) {
        let signed = commit.sign(identity()).unwrap();
        let bytes = mutate(&signed.wire, &m);
        if let Ok(decoded) = SignedCommit::decode(&bytes) {
            prop_assert_eq!(decoded.wire, bytes);
        }
    }

    #[test]
    fn rings_round_trip(ring in ring()) {
        let bytes = ring.encode();
        let back = FolderKeyRing::decode(&bytes, &FOLDER).unwrap();
        prop_assert!(back.extends(&ring) && ring.extends(&back));
        prop_assert_eq!(back.encode().to_vec(), bytes.to_vec());
    }

    #[test]
    fn ring_decoding_accepts_only_encodings(ring in ring(), m in mutations()) {
        let bytes = mutate(&ring.encode(), &m);
        if let Ok(decoded) = FolderKeyRing::decode(&bytes, &FOLDER) {
            prop_assert_eq!(decoded.encode().to_vec(), bytes);
        }
    }

    #[test]
    fn folder_lists_round_trip_and_decode_strictly(list in folder_list(), m in mutations()) {
        let bytes = list.encode().unwrap();
        prop_assert_eq!(FolderList::decode(&bytes).unwrap(), list);
        let bytes = mutate(&bytes, &m);
        if let Ok(decoded) = FolderList::decode(&bytes) {
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn device_names_round_trip_and_decode_strictly(list in device_names(), m in mutations()) {
        let bytes = list.encode().unwrap();
        prop_assert_eq!(DeviceNameList::decode(&bytes).unwrap(), list);
        let bytes = mutate(&bytes, &m);
        if let Ok(decoded) = DeviceNameList::decode(&bytes) {
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn offers_round_trip_and_decode_strictly(offer in offer(), m in mutations()) {
        let bytes = offer.encode().unwrap();
        prop_assert_eq!(&PairingOffer::decode(&bytes).unwrap(), &offer);
        let bytes = mutate(&bytes, &m);
        if let Ok(decoded) = PairingOffer::decode(&bytes) {
            prop_assert_eq!(decoded.encode().unwrap().to_vec(), bytes);
        }
    }

    #[test]
    fn objects_open_only_as_sealed(
        plaintext in prop::collection::vec(any::<u8>(), 0..300),
        seed in prop::collection::vec(any::<u8>(), 1..32),
        m in mutations(),
    ) {
        let ring = FolderKeyRing::new(FOLDER, 1, &mut Seeded(seed.clone(), 0)).unwrap();
        let keys = ObjectKeys::from_ring(&ACCOUNT, &ring, Generation(1)).unwrap();
        let sealed = keys.seal(ObjectType::Chunk, &plaintext, &mut Seeded(seed, 7)).unwrap();
        prop_assert_eq!(
            keys.open(&sealed.id, ObjectType::Chunk, &sealed.blob).unwrap().to_vec(),
            plaintext
        );
        let bytes = mutate(&sealed.blob, &m);
        if keys.open(&sealed.id, ObjectType::Chunk, &bytes).is_ok() {
            prop_assert_eq!(bytes, sealed.blob);
        }
    }

    #[test]
    fn wrapped_keys_open_only_as_sealed(seed in any::<[u8; 32]>(), m in mutations()) {
        let me = DeviceId::from_bytes([1; 16]);
        let secret = AccountSecret::generate(&mut Seeded(seed.to_vec(), 0)).unwrap();
        let commitment = secret.commitment(&ACCOUNT, Epoch(1));
        let kem = identity().public_keys().kem;
        let data = wrap(&secret, &ACCOUNT, Epoch(1), &me, &kem, &mut OsEntropy).unwrap();
        prop_assert_eq!(
            unwrap(identity(), &ACCOUNT, Epoch(1), &me, &data, &commitment).unwrap(),
            secret.clone()
        );
        let bytes = mutate(&data, &m);
        if unwrap(identity(), &ACCOUNT, Epoch(1), &me, &bytes, &commitment).is_ok() {
            prop_assert_eq!(bytes, data);
        }
    }

    #[test]
    fn records_open_only_as_sealed(
        plaintext in prop::collection::vec(any::<u8>(), 0..300),
        version in 1u64..1000,
        m in mutations(),
    ) {
        let (state, secret) = account();
        let cipher = RecordCipher::for_epoch(state, secret, Epoch(1)).unwrap();
        let key = RecordKey::new(RecordKind::FolderKeys, Some(FOLDER)).unwrap();
        let head = state.head().unwrap();
        let data = cipher
            .seal(&key, version, identity(), &DEVICE, &head, &plaintext, &mut OsEntropy)
            .unwrap();
        let opened = cipher.open(state, &key, version, &data).unwrap();
        prop_assert_eq!(opened.plaintext.to_vec(), plaintext);
        prop_assert_eq!(record_header(&data).unwrap().version, version);
        let bytes = mutate(&data, &m);
        if cipher.open(state, &key, version, &bytes).is_ok() {
            prop_assert_eq!(bytes, data);
        }
    }

    #[test]
    fn typed_codes_round_trip(seed in any::<[u8; 16]>()) {
        let code = RecoveryCode::generate(&mut Seeded(seed.to_vec(), 0)).unwrap();
        let again = RecoveryCode::parse(&code.reveal()).unwrap();
        let (a, b) = (again.reveal(), code.reveal());
        prop_assert_eq!(a.as_str(), b.as_str());
        let secret = PairingSecret::generate(&mut Seeded(seed.to_vec(), 0)).unwrap();
        prop_assert_eq!(PairingSecret::parse(&secret.reveal()).unwrap(), secret);
    }
}
