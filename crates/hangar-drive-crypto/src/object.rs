//! Encrypted objects: chunks, file manifests and directory nodes (ADR 0001, section 4;
//! threat model, section 8.4).
//!
//! ```text
//! K_obj  = HKDF-SHA256(ikm = FK_f,g, info = field("hangar-drive/v1/object-key") || field(f) || field(g, u32))
//! K_id   = HKDF-SHA256(ikm = FK_f,g, info = field("hangar-drive/v1/object-id")  || field(f) || field(g, u32))
//! id     = HMAC-SHA-256(K_id, field(type, u8) || field(plaintext))
//! padded = length (u64) || plaintext || zeros, to padme(8 + len(plaintext)) bytes
//! aad    = field("hangar-drive/v1/object") || field(0x01) || field(account) || field(f)
//!          || field(g, u32) || field(type, u8) || field(id)
//! blob   = 0x01 || g (u32) || type (u8) || nonce (24) || XChaCha20-Poly1305(K_obj, nonce, padded, aad)
//! ```
//!
//! - **No convergent encryption:** IDs are keyed per folder and generation, so the server can
//!   neither test a guessed file nor see equal content across folders.
//! - **Padmé** (Nikitin et al., PETS 2019) hides exact sizes with at most 12% overhead.
//! - **Key commitment:** Poly1305 AEADs do not commit to their key. [`ObjectKeys::open`]
//!   recomputes the keyed ID from the plaintext and refuses a mismatch, which binds a ciphertext
//!   to exactly one plaintext under one key.
//! - **Strict padding:** the padded length must be exactly `padme(8 + len)` and every padding
//!   byte zero, so one plaintext has one padded form.
//! - The server stores a blob under `(account, f, id)` and reads only the clear header
//!   ([`object_header`]): generation and type, for the directory node headroom of the quota.

use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hangar_drive_protocol::ids::{AccountId, FolderId, Generation, ObjectId};
use hangar_drive_protocol::object::ObjectType;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::encoding::{constant_time_eq, hkdf, hmac, mac_field, mac_finish, Reader, Writer};
use crate::entropy::{Entropy, EntropyError};
use crate::folder_keys::FolderKeyRing;

const LABEL_OBJECT_KEY: &[u8] = b"hangar-drive/v1/object-key";
const LABEL_OBJECT_ID: &[u8] = b"hangar-drive/v1/object-id";
const LABEL_OBJECT: &[u8] = b"hangar-drive/v1/object";
const OBJECT_VERSION: u8 = 1;
/// Bytes of the random nonce one seal draws from its entropy source (XChaCha20-Poly1305).
pub const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// Bytes of the clear header: version, generation, type, nonce.
pub const OBJECT_HEADER_LEN: usize = 1 + 4 + 1 + NONCE_LEN;

/// The Padmé length of `len` bytes: `len` rounded up so that only the top
/// `floor(log2(floor(log2 len))) + 1` bits of the length can be non-zero. `None` when the
/// rounded length does not fit in a `u64` (lengths close to `u64::MAX`, security review info).
pub fn padme(len: u64) -> Option<u64> {
    if len < 2 {
        return Some(len);
    }
    let e = 63 - u64::from(len.leading_zeros());
    let s = 64 - u64::from(e.leading_zeros());
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    Some(len.checked_add(mask)? & !mask)
}

/// The blob length of an object with a plaintext of `len` bytes.
pub fn blob_len(len: usize) -> Option<usize> {
    let padded = usize::try_from(padme(u64::try_from(len).ok()?.checked_add(8)?)?).ok()?;
    OBJECT_HEADER_LEN.checked_add(padded)?.checked_add(TAG_LEN)
}

/// Server side: whether a blob of `len` bytes can be an object of `kind` as far as its length
/// tells: a padded part that is exactly a Padmé length holding at least the length prefix, and
/// no more than the largest plaintext of the type pads to. Says nothing about the content, which
/// the server cannot open.
pub fn blob_len_fits(kind: ObjectType, len: usize) -> bool {
    let Some(padded) = len.checked_sub(OBJECT_HEADER_LEN + TAG_LEN) else {
        return false;
    };
    let Ok(padded) = u64::try_from(padded) else {
        return false;
    };
    padded >= 8
        && padme(padded) == Some(padded)
        && blob_len(kind.max_plaintext_len()).is_some_and(|max| len <= max)
}

/// Why an object was not sealed or did not open.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ObjectError {
    /// Not a blob of this format.
    #[error("the object is malformed")]
    Malformed,
    /// A blob format version this crate does not know.
    #[error("object format version {0} is not supported")]
    Version(u8),
    /// Another key generation than these keys'.
    #[error("the object uses generation {got}, these keys are generation {expected}")]
    Generation {
        /// The keys' generation.
        expected: u32,
        /// The object's generation.
        got: u32,
    },
    /// Another object type than the referencing entry expects, or an unknown one.
    #[error("the object has another type than expected")]
    Type,
    /// The plaintext is above its type's limit.
    #[error("the object is too large for its type")]
    TooLarge,
    /// The AEAD refused: another key, account, folder, generation, type or ID, or changed.
    #[error("the object does not decrypt")]
    Decrypt,
    /// The padding is not the canonical Padmé padding with zeros.
    #[error("the object's padding is invalid")]
    Padding,
    /// The plaintext's keyed ID is not the referenced ID.
    #[error("the object's content does not match its id")]
    IdMismatch,
    /// The ring has no key of the object's generation.
    #[error("the folder key ring has no generation {0}")]
    UnknownGeneration(u32),
    /// Key derivation or the cipher failed (not expected).
    #[error("object key setup failed")]
    Key,
    /// No randomness for the nonce.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
}

/// The clear header of a blob: generation and type. Read without any check.
pub fn object_header(blob: &[u8]) -> Option<(Generation, ObjectType)> {
    let mut r = Reader::new(blob);
    if r.u8()? != OBJECT_VERSION {
        return None;
    }
    let generation = Generation(r.u32()?);
    let kind = ObjectType::from_byte(r.u8()?).ok()?;
    (blob.len() >= OBJECT_HEADER_LEN + TAG_LEN + 8).then_some((generation, kind))
}

/// A sealed object: its ID and the blob to upload.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedObject {
    /// The keyed ID.
    pub id: ObjectId,
    /// The blob.
    pub blob: Vec<u8>,
}

impl fmt::Debug for SealedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedObject({:?}, {} bytes)", self.id, self.blob.len())
    }
}

/// `K_obj` and `K_id` of one folder and generation. Wiped on drop, never printed.
pub struct ObjectKeys {
    account: AccountId,
    folder: FolderId,
    generation: Generation,
    k_obj: Zeroizing<[u8; 32]>,
    k_id: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for ObjectKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectKeys")
            .field("folder", &self.folder)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl ObjectKeys {
    /// The keys of `generation` of `folder` from its ring.
    pub fn from_ring(
        account: &AccountId,
        ring: &FolderKeyRing,
        generation: Generation,
    ) -> Result<Self, ObjectError> {
        let key = ring
            .get(generation)
            .ok_or(ObjectError::UnknownGeneration(generation.0))?;
        let derive = |label: &[u8]| {
            let mut info = Writer::new();
            info.field(label)
                .field(ring.folder().as_bytes())
                .field_u32(generation.0);
            hkdf::<32>(key.bytes(), &info.into_bytes()).ok_or(ObjectError::Key)
        };
        Ok(Self {
            account: *account,
            folder: *ring.folder(),
            generation,
            k_obj: derive(LABEL_OBJECT_KEY)?,
            k_id: derive(LABEL_OBJECT_ID)?,
        })
    }

    /// The generation.
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// The keyed ID of a plaintext of type `kind`.
    pub fn object_id(&self, kind: ObjectType, plaintext: &[u8]) -> Result<ObjectId, ObjectError> {
        let mut mac = hmac(self.k_id.as_ref()).ok_or(ObjectError::Key)?;
        mac_field(&mut mac, &[kind.to_byte()]);
        mac_field(&mut mac, plaintext);
        Ok(ObjectId::from_bytes(mac_finish(mac)))
    }

    fn aad(&self, kind: ObjectType, id: &ObjectId) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(LABEL_OBJECT)
            .field_u8(OBJECT_VERSION)
            .field(self.account.as_bytes())
            .field(self.folder.as_bytes())
            .field_u32(self.generation.0)
            .field_u8(kind.to_byte())
            .field(id.as_bytes());
        w.into_bytes()
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, ObjectError> {
        XChaCha20Poly1305::new_from_slice(self.k_obj.as_ref()).map_err(|_| ObjectError::Key)
    }

    /// Seals a plaintext of type `kind`.
    pub fn seal(
        &self,
        kind: ObjectType,
        plaintext: &[u8],
        entropy: &mut impl Entropy,
    ) -> Result<SealedObject, ObjectError> {
        if plaintext.len() > kind.max_plaintext_len() {
            return Err(ObjectError::TooLarge);
        }
        let id = self.object_id(kind, plaintext)?;
        let len = u64::try_from(plaintext.len()).map_err(|_| ObjectError::TooLarge)?;
        let padded_len = len
            .checked_add(8)
            .and_then(padme)
            .and_then(|padded| usize::try_from(padded).ok())
            .ok_or(ObjectError::TooLarge)?;
        let mut padded = Zeroizing::new(Vec::with_capacity(padded_len));
        padded.extend_from_slice(&len.to_be_bytes());
        padded.extend_from_slice(plaintext);
        padded.resize(padded_len, 0);
        let mut nonce = [0u8; NONCE_LEN];
        entropy.fill(&mut nonce)?;
        let ciphertext = self
            .cipher()?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &padded,
                    aad: &self.aad(kind, &id),
                },
            )
            .map_err(|_| ObjectError::Key)?;
        let mut w = Writer::with_capacity(OBJECT_HEADER_LEN + ciphertext.len());
        w.u8(OBJECT_VERSION)
            .u32(self.generation.0)
            .u8(kind.to_byte())
            .raw(&nonce)
            .raw(&ciphertext);
        Ok(SealedObject {
            id,
            blob: w.into_bytes(),
        })
    }

    /// Opens the blob a tree references as `expected` of type `kind`: decrypts, checks the
    /// padding, recomputes the ID and refuses a mismatch.
    pub fn open(
        &self,
        expected: &ObjectId,
        kind: ObjectType,
        blob: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ObjectError> {
        let mut r = Reader::new(blob);
        let version = r.u8().ok_or(ObjectError::Malformed)?;
        if version != OBJECT_VERSION {
            return Err(ObjectError::Version(version));
        }
        let generation = r.u32().ok_or(ObjectError::Malformed)?;
        if generation != self.generation.0 {
            return Err(ObjectError::Generation {
                expected: self.generation.0,
                got: generation,
            });
        }
        let type_byte = r.u8().ok_or(ObjectError::Malformed)?;
        if ObjectType::from_byte(type_byte) != Ok(kind) {
            return Err(ObjectError::Type);
        }
        let nonce: [u8; NONCE_LEN] = r.raw().ok_or(ObjectError::Malformed)?;
        let ciphertext = r.raw_slice(r.remaining()).ok_or(ObjectError::Malformed)?;
        let padded_len = ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .filter(|len| *len >= 8)
            .ok_or(ObjectError::Malformed)?;
        let max = blob_len(kind.max_plaintext_len()).ok_or(ObjectError::TooLarge)?;
        if blob.len() > max {
            return Err(ObjectError::TooLarge);
        }
        let padded = Zeroizing::new(
            self.cipher()?
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &self.aad(kind, expected),
                    },
                )
                .map_err(|_| ObjectError::Decrypt)?,
        );
        let (len, rest) = padded.split_at(8);
        let len = u64::from_be_bytes(len.try_into().map_err(|_| ObjectError::Padding)?);
        let len_usize = usize::try_from(len).map_err(|_| ObjectError::Padding)?;
        if len_usize > rest.len()
            || len_usize > kind.max_plaintext_len()
            || u64::try_from(padded_len).ok() != len.checked_add(8).and_then(padme)
        {
            return Err(ObjectError::Padding);
        }
        let (plaintext, padding) = rest.split_at(len_usize);
        if padding.iter().any(|&b| b != 0) {
            return Err(ObjectError::Padding);
        }
        let id = self.object_id(kind, plaintext)?;
        if !constant_time_eq(id.as_bytes(), expected.as_bytes()) {
            return Err(ObjectError::IdMismatch);
        }
        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::{FixedEntropy, OsEntropy};
    use hangar_drive_protocol::object::CHUNK_SIZE;

    const ACCOUNT: AccountId = AccountId::from_bytes([1; 16]);
    const FOLDER: FolderId = FolderId::from_bytes([3; 16]);

    #[test]
    fn blob_lengths_the_server_accepts() {
        for len in [0usize, 1, 7, 100, 4096, 65_537] {
            let blob = blob_len(len).unwrap();
            assert!(blob_len_fits(ObjectType::DirectoryNode, blob), "{len}");
            assert!(blob_len_fits(ObjectType::Chunk, blob), "{len}");
        }
        let chunk_max = blob_len(CHUNK_SIZE as usize).unwrap();
        assert!(blob_len_fits(ObjectType::Chunk, chunk_max));
        // One Padmé step above a full chunk is a longer blob than a chunk may have (a few bytes
        // more pad to the same length as a full chunk).
        assert_eq!(blob_len(CHUNK_SIZE as usize + 1), Some(chunk_max));
        let over = blob_len(CHUNK_SIZE as usize + 128 * 1024).unwrap();
        assert!(over > chunk_max);
        assert!(!blob_len_fits(ObjectType::Chunk, over));
        assert!(blob_len_fits(ObjectType::FileManifest, over));
        // Not a Padmé length, and too short for the length prefix.
        assert!(!blob_len_fits(ObjectType::Chunk, chunk_max - 1));
        assert!(!blob_len_fits(
            ObjectType::Chunk,
            OBJECT_HEADER_LEN + TAG_LEN + 7
        ));
        assert!(!blob_len_fits(ObjectType::Chunk, 3));
        let manifest_max = blob_len(ObjectType::FileManifest.max_plaintext_len()).unwrap();
        assert!(blob_len_fits(ObjectType::FileManifest, manifest_max));
        assert!(!blob_len_fits(
            ObjectType::FileManifest,
            manifest_max + (1 << 20)
        ));
    }

    fn ring() -> FolderKeyRing {
        let mut ring = FolderKeyRing::new(FOLDER, 1, &mut OsEntropy).unwrap();
        ring.add_generation(2, &mut OsEntropy).unwrap();
        ring
    }

    #[test]
    fn padme_matches_the_paper() {
        // Values from the definition (Nikitin et al., algorithm 1).
        for (len, padded) in [
            (0u64, 0u64),
            (1, 1),
            (8, 8),
            (9, 10),
            (15, 16),
            (17, 18),
            (100, 104),
            (1000, 1024),
            (1025, 1088),
            (4_194_312, 4_325_376),
        ] {
            assert_eq!(padme(len), Some(padded), "padme({len})");
        }
        // Never shorter, at most 12% longer.
        for len in (8..100_000u64).step_by(97) {
            let p = padme(len).unwrap();
            assert!(p >= len && p * 100 <= len * 112 + 100, "{len} -> {p}");
        }
        assert_eq!(blob_len(0), Some(30 + 8 + 16));
    }

    // Security review, info: lengths close to `u64::MAX` round up past it. They give `None`
    // instead of a wrapped length or an overflow panic.
    #[test]
    fn padme_does_not_overflow_near_the_top() {
        assert_eq!(padme(u64::MAX), None);
        assert_eq!(padme(u64::MAX - 1), None);
        // Above 2^63 a length rounds up to a multiple of 2^57: the highest one fits, a length
        // above it would round past the top.
        assert_eq!(padme(1 << 63), Some(1 << 63));
        assert_eq!(padme((1 << 63) + 1), Some((1 << 63) + (1 << 57)));
        let highest = u64::MAX - ((1 << 57) - 1);
        assert_eq!(padme(highest), Some(highest));
        assert_eq!(padme(highest + 1), None);
        // The top bits only: 2^63 + 2^62 is a Padmé length.
        assert_eq!(padme((1 << 63) | (1 << 62)), Some((1 << 63) | (1 << 62)));
        assert_eq!(blob_len(usize::MAX), None);
        assert!(!blob_len_fits(ObjectType::Chunk, usize::MAX));
    }

    #[test]
    fn seal_open_round_trip_per_type() {
        let ring = ring();
        let keys = ObjectKeys::from_ring(&ACCOUNT, &ring, Generation(2)).unwrap();
        for kind in [
            ObjectType::Chunk,
            ObjectType::FileManifest,
            ObjectType::DirectoryNode,
        ] {
            for plaintext in [&b""[..], b"x", b"hello, drive"] {
                let sealed = keys.seal(kind, plaintext, &mut OsEntropy).unwrap();
                assert_eq!(Some(sealed.blob.len()), blob_len(plaintext.len()));
                assert_eq!(object_header(&sealed.blob), Some((Generation(2), kind)));
                let opened = keys.open(&sealed.id, kind, &sealed.blob).unwrap();
                assert_eq!(opened.as_slice(), plaintext);
            }
        }
    }

    #[test]
    fn ids_are_keyed_per_folder_generation_and_type() {
        let ring = ring();
        let g1 = ObjectKeys::from_ring(&ACCOUNT, &ring, Generation(1)).unwrap();
        let g2 = ObjectKeys::from_ring(&ACCOUNT, &ring, Generation(2)).unwrap();
        let a = g1.object_id(ObjectType::Chunk, b"same").unwrap();
        assert_eq!(
            a,
            g1.object_id(ObjectType::Chunk, b"same").unwrap(),
            "dedup"
        );
        assert_ne!(a, g2.object_id(ObjectType::Chunk, b"same").unwrap());
        assert_ne!(a, g1.object_id(ObjectType::FileManifest, b"same").unwrap());
        let other = ring.clone();
        let mut other_folder = FolderKeyRing::decode(
            &{
                let mut bytes = other.encode().to_vec();
                bytes[1..17].copy_from_slice(&[4; 16]);
                bytes
            },
            &FolderId::from_bytes([4; 16]),
        )
        .unwrap();
        let moved = ObjectKeys::from_ring(&ACCOUNT, &other_folder, Generation(1)).unwrap();
        assert_ne!(a, moved.object_id(ObjectType::Chunk, b"same").unwrap());
        other_folder.add_generation(2, &mut OsEntropy).unwrap();
        assert!(ObjectKeys::from_ring(&ACCOUNT, &ring, Generation(3)).is_err());
        assert!(!format!("{g1:?}").contains("k_obj"));
    }

    #[test]
    fn opening_refuses_wrong_context() {
        let ring = ring();
        let keys = ObjectKeys::from_ring(&ACCOUNT, &ring, Generation(2)).unwrap();
        let sealed = keys
            .seal(ObjectType::Chunk, b"content", &mut OsEntropy)
            .unwrap();
        // Another expected ID (the server answers with another object).
        let other = keys
            .seal(ObjectType::Chunk, b"other", &mut OsEntropy)
            .unwrap();
        assert_eq!(
            keys.open(&other.id, ObjectType::Chunk, &sealed.blob),
            Err(ObjectError::Decrypt)
        );
        // Another expected type.
        assert_eq!(
            keys.open(&sealed.id, ObjectType::FileManifest, &sealed.blob),
            Err(ObjectError::Type)
        );
        // Another generation's keys.
        let g1 = ObjectKeys::from_ring(&ACCOUNT, &ring, Generation(1)).unwrap();
        assert_eq!(
            g1.open(&sealed.id, ObjectType::Chunk, &sealed.blob),
            Err(ObjectError::Generation {
                expected: 1,
                got: 2
            })
        );
        // Another account: the AAD binds it.
        let elsewhere =
            ObjectKeys::from_ring(&AccountId::from_bytes([9; 16]), &ring, Generation(2)).unwrap();
        assert_eq!(
            elsewhere.open(&sealed.id, ObjectType::Chunk, &sealed.blob),
            Err(ObjectError::Decrypt)
        );
        // The header's type rewritten: the AAD binds the type too.
        let mut retyped = sealed.blob.clone();
        retyped[5] = ObjectType::FileManifest.to_byte();
        assert_eq!(
            keys.open(&sealed.id, ObjectType::FileManifest, &retyped),
            Err(ObjectError::Decrypt)
        );
        // Version, flipped byte, truncation.
        let mut v2 = sealed.blob.clone();
        v2[0] = 2;
        assert_eq!(
            keys.open(&sealed.id, ObjectType::Chunk, &v2),
            Err(ObjectError::Version(2))
        );
        let mut flipped = sealed.blob.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            keys.open(&sealed.id, ObjectType::Chunk, &flipped),
            Err(ObjectError::Decrypt)
        );
        for cut in [0, 5, 6, OBJECT_HEADER_LEN, sealed.blob.len() - 1] {
            assert!(keys
                .open(&sealed.id, ObjectType::Chunk, &sealed.blob[..cut])
                .is_err());
        }
    }

    /// Seals arbitrary padded bytes as if a malicious writer with the key did.
    fn seal_padded(keys: &ObjectKeys, kind: ObjectType, id: &ObjectId, padded: &[u8]) -> Vec<u8> {
        let nonce = [7u8; NONCE_LEN];
        let ciphertext = keys
            .cipher()
            .unwrap()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: padded,
                    aad: &keys.aad(kind, id),
                },
            )
            .unwrap();
        let mut w = Writer::new();
        w.u8(1)
            .u32(keys.generation.0)
            .u8(kind.to_byte())
            .raw(&nonce)
            .raw(&ciphertext);
        w.into_bytes()
    }

    #[test]
    fn key_commitment_and_strict_padding() {
        let ring = ring();
        let keys = ObjectKeys::from_ring(&ACCOUNT, &ring, Generation(2)).unwrap();
        let id = keys.object_id(ObjectType::Chunk, b"abc").unwrap();
        let mut good = 3u64.to_be_bytes().to_vec();
        good.extend_from_slice(b"abc");
        good.resize(usize::try_from(padme(11).unwrap()).unwrap(), 0);
        let blob = seal_padded(&keys, ObjectType::Chunk, &id, &good);
        assert_eq!(
            keys.open(&id, ObjectType::Chunk, &blob).unwrap().as_slice(),
            b"abc"
        );

        // A valid ciphertext under the referenced ID whose plaintext has another ID: refused.
        let mut other = 3u64.to_be_bytes().to_vec();
        other.extend_from_slice(b"abd");
        other.resize(good.len(), 0);
        let blob = seal_padded(&keys, ObjectType::Chunk, &id, &other);
        assert_eq!(
            keys.open(&id, ObjectType::Chunk, &blob),
            Err(ObjectError::IdMismatch)
        );
        // Non-zero padding.
        let mut dirty = good.clone();
        let last = dirty.len() - 1;
        dirty[last] = 1;
        let blob = seal_padded(&keys, ObjectType::Chunk, &id, &dirty);
        assert_eq!(
            keys.open(&id, ObjectType::Chunk, &blob),
            Err(ObjectError::Padding)
        );
        // Longer than the Padmé length.
        let mut long = good.clone();
        long.extend_from_slice(&[0; 8]);
        let blob = seal_padded(&keys, ObjectType::Chunk, &id, &long);
        assert_eq!(
            keys.open(&id, ObjectType::Chunk, &blob),
            Err(ObjectError::Padding)
        );
        // A length beyond the data.
        let mut lying = good;
        lying[..8].copy_from_slice(&100u64.to_be_bytes());
        let blob = seal_padded(&keys, ObjectType::Chunk, &id, &lying);
        assert_eq!(
            keys.open(&id, ObjectType::Chunk, &blob),
            Err(ObjectError::Padding)
        );
    }

    #[test]
    fn size_limits() {
        let ring = ring();
        let keys = ObjectKeys::from_ring(&ACCOUNT, &ring, Generation(1)).unwrap();
        let big = vec![0u8; usize::try_from(CHUNK_SIZE).unwrap() + 1];
        assert_eq!(
            keys.seal(ObjectType::Chunk, &big, &mut OsEntropy),
            Err(ObjectError::TooLarge)
        );
        let full = &big[..big.len() - 1];
        let sealed = keys.seal(ObjectType::Chunk, full, &mut OsEntropy).unwrap();
        assert_eq!(
            keys.open(&sealed.id, ObjectType::Chunk, &sealed.blob)
                .unwrap()
                .len(),
            full.len()
        );
        assert!(keys
            .seal(ObjectType::Chunk, b"x", &mut FixedEntropy::counting(0, 3))
            .is_err());
    }
}
