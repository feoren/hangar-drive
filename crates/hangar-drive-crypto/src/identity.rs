//! A device's long-term keys: Ed25519 to sign log entries, commits, records and proofs, X25519
//! to receive wrapped epoch secrets (HPKE). The private halves leave this crate only as the
//! versioned, zeroizing byte string of [`DeviceIdentity::export`], meant for the OS keychain.
//!
//! Drive identities are separate from Hangar's: every label starts with `hangar-drive/v1/` and
//! the secret format has its own prefix, so no key or signature of one product is valid in the
//! other. Built after the sister project's `hangar-team-crypto` (`src/identity.rs`, MIT, same
//! owner); the X25519 key checks are taken from there unchanged.
//!
//! # Secret format (version 1, 67 bytes)
//!
//! ```text
//! "DR" || 0x01 || Ed25519 seed (32 bytes) || X25519 private key (32 bytes)
//! ```
//!
//! # Proof of possession
//!
//! ```text
//! proof = Ed25519 signature of the device over
//!         field("hangar-drive/v1/device-proof") || field(account) || field(device)
//!         || field(sign public key) || field(kem public key) || field(recovery: 0 or 1)
//! ```
//!
//! The proof shows that whoever lists the keys holds the signing key, and binds both keys to
//! one device of one account. It cannot show possession of the X25519 key (X25519 does not
//! sign); a wrong one only keeps that device from receiving keys.
//!
//! # Safety numbers
//!
//! ```text
//! device: d = SHA-256( field("hangar-drive/v1/safety-number") || field(account) || field(device)
//!                      || field(sign public key) || field(kem public key) )
//! log:    d = SHA-256( field("hangar-drive/v1/log-safety-number") || field(account)
//!                      || field(head index, u64) || field(head hash) )
//! folder: d = SHA-256( field("hangar-drive/v1/folder-safety-number") || field(account)
//!                      || field(folder) || field(head commit id) || field(height, u64) )
//! group i (0..6) = (d[5i .. 5i+5] as a 40-bit big endian number) mod 100000
//! ```
//!
//! printed as six groups of five digits (about 99.7 bits), Hangar's format.
//!
//! # X25519 key validation
//!
//! A key is accepted only as a canonical u-coordinate (below `2^255 - 19`, bit 255 clear) that
//! is not of small order (the five canonical values libsodium refuses), so a device never wraps
//! a secret to a key whose shared secret is fixed.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hangar_drive_protocol::ids::{
    AccountId, CommitId, DeviceId, FolderId, LogHead, PublicKey, ServerId, Signature,
};
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, Serializable};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{framed, sha256_framed};
use crate::entropy::{Entropy, EntropyError};

pub(crate) type KemPrivateKey = <X25519HkdfSha256 as Kem>::PrivateKey;
pub(crate) type KemPublicKey = <X25519HkdfSha256 as Kem>::PublicKey;

const SECRET_MAGIC: &[u8; 2] = b"DR";
const SECRET_VERSION: u8 = 1;
/// Bytes of an exported device secret.
pub const DEVICE_SECRET_LEN: usize = 2 + 1 + 32 + 32;

const LABEL_SAFETY_NUMBER: &[u8] = b"hangar-drive/v1/safety-number";
const LABEL_LOG_SAFETY_NUMBER: &[u8] = b"hangar-drive/v1/log-safety-number";
const LABEL_FOLDER_SAFETY_NUMBER: &[u8] = b"hangar-drive/v1/folder-safety-number";
const LABEL_DEVICE_PROOF: &[u8] = b"hangar-drive/v1/device-proof";
const LABEL_SERVER_KEY_NUMBER: &[u8] = b"hangar-drive/v1/server-key-number";

/// Why key material was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdentityError {
    /// Not a device secret of this crate (wrong length or prefix).
    #[error("not a Hangar Drive device secret")]
    Format,
    /// A device secret of a format version this crate does not know.
    #[error("device secret format version {0} is not supported")]
    Version(u8),
    /// The key library refused the key material (not expected for 32-byte keys).
    #[error("the key material was refused")]
    Key,
    /// No randomness for a new identity.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
}

/// A device's public keys, as the device log vouches for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevicePublicKeys {
    /// Ed25519.
    pub sign: PublicKey,
    /// X25519.
    pub kem: PublicKey,
}

/// A device's private keys. Wiped on drop; `Debug` shows only the public keys.
pub struct DeviceIdentity {
    sign: SigningKey,
    kem: KemPrivateKey,
    public: DevicePublicKeys,
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// A new device: 64 random bytes become the Ed25519 seed and the X25519 private key.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, IdentityError> {
        let mut seeds = Zeroizing::new([0u8; 64]);
        entropy.fill(seeds.as_mut())?;
        Self::from_seeds(&seeds)
    }

    /// The identity of 64 bytes of key material: Ed25519 seed, then X25519 private key.
    pub(crate) fn from_seeds(seeds: &[u8; 64]) -> Result<Self, IdentityError> {
        let mut sign_seed = Zeroizing::new([0u8; 32]);
        sign_seed.copy_from_slice(&seeds[..32]);
        let sign = SigningKey::from_bytes(&sign_seed);
        // X25519 clamps any 32 bytes into a valid private key; only a wrong length fails.
        let kem = KemPrivateKey::from_bytes(&seeds[32..]).map_err(|_| IdentityError::Key)?;
        let mut kem_public = X25519HkdfSha256::sk_to_pk(&kem).to_bytes();
        let kem_bytes = PublicKey::from_slice(kem_public.as_slice()).ok_or(IdentityError::Key)?;
        kem_public.as_mut_slice().zeroize();
        let public = DevicePublicKeys {
            sign: PublicKey::from_bytes(sign.verifying_key().to_bytes()),
            kem: kem_bytes,
        };
        Ok(Self { sign, kem, public })
    }

    /// The public keys to put into the device log.
    pub fn public_keys(&self) -> DevicePublicKeys {
        self.public
    }

    /// The private keys for the OS keychain, in the versioned format of this module.
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(DEVICE_SECRET_LEN));
        out.extend_from_slice(SECRET_MAGIC);
        out.push(SECRET_VERSION);
        out.extend_from_slice(self.sign.as_bytes());
        let mut kem = self.kem.to_bytes();
        out.extend_from_slice(kem.as_slice());
        kem.as_mut_slice().zeroize();
        out
    }

    /// Reads what [`DeviceIdentity::export`] wrote.
    pub fn import(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() < 3 || &bytes[..2] != SECRET_MAGIC {
            return Err(IdentityError::Format);
        }
        if bytes[2] != SECRET_VERSION {
            return Err(IdentityError::Version(bytes[2]));
        }
        if bytes.len() != DEVICE_SECRET_LEN {
            return Err(IdentityError::Format);
        }
        let mut seeds = Zeroizing::new([0u8; 64]);
        seeds.copy_from_slice(&bytes[3..]);
        Self::from_seeds(&seeds)
    }

    /// The proof of possession of this device as `device` of `account` (module docs).
    /// `recovery` marks the offline device derived from a recovery code.
    pub fn prove(&self, account: &AccountId, device: &DeviceId, recovery: bool) -> Signature {
        Signature::from_bytes(self.sign(&proof_message(account, device, &self.public, recovery)))
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.sign.sign(message).to_bytes()
    }

    pub(crate) fn kem_private(&self) -> &KemPrivateKey {
        &self.kem
    }
}

/// Whether `key` is an Ed25519 public key a device may hold: a valid point, not of small order.
pub fn is_valid_sign_key(key: &PublicKey) -> bool {
    VerifyingKey::from_bytes(key.as_bytes()).is_ok_and(|key| !key.is_weak())
}

/// The canonical X25519 u-coordinates of small order (RFC 7748 section 6.1 asks to refuse an
/// all-zero shared secret; these are the inputs that give one, the list libsodium refuses).
/// Little endian. Encodings at or above `p` are refused as non-canonical before this list.
const LOW_ORDER_KEM_KEYS: [[u8; 32]; 5] = [
    // 0 (order 4)
    [0; 32],
    // 1 (order 1)
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // order 8
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // order 8
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1 (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Whether the little endian number `u` is below `p = 2^255 - 19` (with bit 255 clear).
fn is_canonical_field_element(u: &[u8; 32]) -> bool {
    if u[31] & 0x80 != 0 {
        return false;
    }
    let top_is_max = u[31] == 0x7f && u[1..31].iter().all(|&b| b == 0xff);
    !(top_is_max && u[0] >= 0xed)
}

/// Whether `key` is an X25519 public key a device may hold: canonical and not of small order.
pub fn is_valid_kem_key(key: &PublicKey) -> bool {
    let u = key.as_bytes();
    is_canonical_field_element(u) && !LOW_ORDER_KEM_KEYS.iter().any(|low| low == u)
}

fn proof_message(
    account: &AccountId,
    device: &DeviceId,
    keys: &DevicePublicKeys,
    recovery: bool,
) -> Vec<u8> {
    framed(&[
        LABEL_DEVICE_PROOF,
        account.as_bytes(),
        device.as_bytes(),
        keys.sign.as_bytes(),
        keys.kem.as_bytes(),
        &[u8::from(recovery)],
    ])
}

/// Checks a proof of possession made with [`DeviceIdentity::prove`].
pub fn verify_proof(
    account: &AccountId,
    device: &DeviceId,
    keys: &DevicePublicKeys,
    recovery: bool,
    proof: &Signature,
) -> bool {
    verify(
        &keys.sign,
        &proof_message(account, device, keys, recovery),
        proof.as_bytes(),
    )
}

/// Strict Ed25519 verification (RFC 8032 with canonical encodings, no small-order keys).
pub(crate) fn verify(key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(key.as_bytes()) else {
        return false;
    };
    if key.is_weak() {
        return false;
    }
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .is_ok()
}

/// 30 decimal digits in six groups for comparing keys or states out of band (module docs).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SafetyNumber([u32; 6]);

impl SafetyNumber {
    fn from_digest(digest: &[u8; 32]) -> Self {
        let mut groups = [0u32; 6];
        for (i, group) in groups.iter_mut().enumerate() {
            let mut wide = [0u8; 8];
            wide[3..].copy_from_slice(&digest[5 * i..5 * i + 5]);
            // Below 100000, so the conversion cannot fail.
            *group = u32::try_from(u64::from_be_bytes(wide) % 100_000).unwrap_or(0);
        }
        Self(groups)
    }

    /// The six groups of five digits.
    pub fn groups(&self) -> [u32; 6] {
        self.0
    }
}

impl fmt::Display for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, group) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{group:05}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafetyNumber({self})")
    }
}

/// The safety number of one device: compared before a new device is approved.
pub fn safety_number(
    account: &AccountId,
    device: &DeviceId,
    keys: &DevicePublicKeys,
) -> SafetyNumber {
    SafetyNumber::from_digest(&sha256_framed(&[
        LABEL_SAFETY_NUMBER,
        account.as_bytes(),
        device.as_bytes(),
        keys.sign.as_bytes(),
        keys.kem.as_bytes(),
    ]))
}

/// The safety number of the account's device log at `head`: equal on two devices exactly when
/// both verified the same log up to the same entry.
pub fn log_safety_number(account: &AccountId, head: &LogHead) -> SafetyNumber {
    SafetyNumber::from_digest(&sha256_framed(&[
        LABEL_LOG_SAFETY_NUMBER,
        account.as_bytes(),
        &head.index.to_be_bytes(),
        head.hash.as_bytes(),
    ]))
}

/// The folder safety number over a device's frontier: two devices that show the same number
/// see the same head of the folder, so a fork or freeze shows when they differ.
pub fn folder_safety_number(
    account: &AccountId,
    folder: &FolderId,
    head: &CommitId,
    height: u64,
) -> SafetyNumber {
    SafetyNumber::from_digest(&sha256_framed(&[
        LABEL_FOLDER_SAFETY_NUMBER,
        account.as_bytes(),
        folder.as_bytes(),
        head.as_bytes(),
        &height.to_be_bytes(),
    ]))
}

/// SHA-256 of a server certificate's DER `SubjectPublicKeyInfo`: the pin a pairing offer
/// carries for a self-signed server.
pub fn spki_pin(spki_der: &[u8]) -> [u8; 32] {
    crate::encoding::sha256(spki_der)
}

/// The server key number (ADR 0001, section 6, pin rotation): the digits a person compares
/// with the server CLI's output before a device takes a new server key. Binding the server ID
/// means a number from another server never matches. `pin` is [`spki_pin`] of the key.
pub fn server_key_number(server: &ServerId, pin: &[u8; 32]) -> SafetyNumber {
    SafetyNumber::from_digest(&sha256_framed(&[
        LABEL_SERVER_KEY_NUMBER,
        server.as_bytes(),
        pin,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::{FixedEntropy, OsEntropy};
    use hangar_drive_protocol::ids::LogHash;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn ed25519_matches_rfc_8032_test_1() {
        let mut seeds = [0u8; 64];
        seeds[..32].copy_from_slice(&hex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let identity = DeviceIdentity::from_seeds(&seeds).expect("keys");
        assert_eq!(
            identity.public_keys().sign.as_bytes().to_vec(),
            hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        assert_eq!(
            identity.sign(b"").to_vec(),
            hex(concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ))
        );
    }

    #[test]
    fn x25519_matches_rfc_7748_section_6_1() {
        let mut seeds = [0u8; 64];
        seeds[32..].copy_from_slice(&hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let identity = DeviceIdentity::from_seeds(&seeds).expect("keys");
        assert_eq!(
            identity.public_keys().kem.as_bytes().to_vec(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
    }

    #[test]
    fn export_import_round_trip_and_refusals() {
        let identity = DeviceIdentity::generate(&mut OsEntropy).expect("rng");
        let secret = identity.export();
        assert_eq!(secret.len(), DEVICE_SECRET_LEN);
        assert_eq!(&secret[..3], b"DR\x01");
        let back = DeviceIdentity::import(&secret).expect("import");
        assert_eq!(back.public_keys(), identity.public_keys());
        assert_eq!(
            DeviceIdentity::import(b"HD").unwrap_err(),
            IdentityError::Format
        );
        let mut hangar = secret.to_vec();
        hangar[..2].copy_from_slice(b"HD");
        assert_eq!(
            DeviceIdentity::import(&hangar).unwrap_err(),
            IdentityError::Format
        );
        let mut v2 = secret.to_vec();
        v2[2] = 2;
        assert_eq!(
            DeviceIdentity::import(&v2).unwrap_err(),
            IdentityError::Version(2)
        );
        assert_eq!(
            DeviceIdentity::import(&secret[..66]).unwrap_err(),
            IdentityError::Format
        );
        assert!(!format!("{identity:?}").contains(&format!("{:?}", &secret[3..10])));
        assert!(DeviceIdentity::generate(&mut FixedEntropy::counting(0, 10)).is_err());
    }

    #[test]
    fn proof_binds_account_device_keys_and_recovery() {
        let identity = DeviceIdentity::generate(&mut OsEntropy).expect("rng");
        let keys = identity.public_keys();
        let account = AccountId::from_bytes([1; 16]);
        let device = DeviceId::from_bytes([2; 16]);
        let proof = identity.prove(&account, &device, false);
        assert!(verify_proof(&account, &device, &keys, false, &proof));
        assert!(!verify_proof(&account, &device, &keys, true, &proof));
        assert!(!verify_proof(
            &AccountId::from_bytes([9; 16]),
            &device,
            &keys,
            false,
            &proof
        ));
        assert!(!verify_proof(
            &account,
            &DeviceId::from_bytes([9; 16]),
            &keys,
            false,
            &proof
        ));
        let other = DeviceIdentity::generate(&mut OsEntropy)
            .expect("rng")
            .public_keys();
        let swapped = DevicePublicKeys {
            sign: keys.sign,
            kem: other.kem,
        };
        assert!(!verify_proof(&account, &device, &swapped, false, &proof));
    }

    #[test]
    fn key_validation() {
        let identity = DeviceIdentity::generate(&mut OsEntropy).expect("rng");
        assert!(is_valid_sign_key(&identity.public_keys().sign));
        assert!(is_valid_kem_key(&identity.public_keys().kem));
        for low in LOW_ORDER_KEM_KEYS {
            assert!(!is_valid_kem_key(&PublicKey::from_bytes(low)));
        }
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert!(!is_valid_kem_key(&PublicKey::from_bytes(p)));
        p[0] = 0xeb;
        assert!(is_valid_kem_key(&PublicKey::from_bytes(p)));
        let mut high = [9u8; 32];
        high[31] |= 0x80;
        assert!(!is_valid_kem_key(&PublicKey::from_bytes(high)));
        // The identity point is of small order.
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        assert!(!is_valid_sign_key(&PublicKey::from_bytes(identity_point)));
    }

    #[test]
    fn safety_numbers_format_and_differ() {
        let account = AccountId::from_bytes([1; 16]);
        let keys = DeviceIdentity::generate(&mut OsEntropy)
            .expect("rng")
            .public_keys();
        let a = safety_number(&account, &DeviceId::from_bytes([2; 16]), &keys);
        let b = safety_number(&account, &DeviceId::from_bytes([3; 16]), &keys);
        assert_ne!(a, b);
        let text = a.to_string();
        assert_eq!(text.len(), 35);
        assert_eq!(text.split(' ').count(), 6);
        assert!(a.groups().iter().all(|g| *g < 100_000));
        let head = LogHead {
            index: 1,
            hash: LogHash::from_bytes([0; 32]),
        };
        let next = LogHead { index: 2, ..head };
        assert_ne!(
            log_safety_number(&account, &head),
            log_safety_number(&account, &next)
        );
        let folder = FolderId::from_bytes([4; 16]);
        let commit = CommitId::from_bytes([5; 32]);
        assert_ne!(
            folder_safety_number(&account, &folder, &commit, 1),
            folder_safety_number(&account, &folder, &commit, 2)
        );
        assert!(format!("{a:?}").starts_with("SafetyNumber("));
    }

    #[test]
    fn server_key_number_binds_server_and_key() {
        let pin = spki_pin(b"spki");
        let server = ServerId::from_bytes([1; 16]);
        let number = server_key_number(&server, &pin);
        assert_eq!(number, server_key_number(&server, &spki_pin(b"spki")));
        assert_ne!(
            number,
            server_key_number(&ServerId::from_bytes([2; 16]), &pin)
        );
        assert_ne!(number, server_key_number(&server, &spki_pin(b"other")));
        assert_eq!(number.to_string().split(' ').count(), 6);
    }
}
