//! The printable recovery code: 128 random bits that deterministically derive an offline
//! recovery device. No escrow, and no password recovery: a chosen password would let the server
//! attack the wrapped keys offline, while the code is machine drawn and needs no password
//! hashing.
//!
//! Built after the sister project's `hangar-team-crypto` (`src/recovery.rs`, MIT, same owner),
//! with Drive's labels.
//!
//! # Code (version 1)
//!
//! ```text
//! payload  = 0x01 || entropy (16 bytes) || checksum (3 bytes)
//! checksum = SHA-256( field("hangar-drive/v1/recovery-code") || field(0x01) || field(entropy) )[0..3]
//! code     = Crockford base32 of payload (20 bytes, 32 characters), 8 groups of 4 joined by "-"
//! ```
//!
//! Crockford's alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`) has no `I`, `L`, `O` or `U`; reading
//! accepts lower case, ignores spaces and hyphens, and reads `O` as `0`, `I` and `L` as `1`. The
//! checksum catches typos (a wrong code passes with probability 2^-24).
//!
//! # Identity
//!
//! ```text
//! okm = HKDF-SHA256(salt none, ikm = entropy, info = field("hangar-drive/v1/recovery-identity"), 64 bytes)
//! Ed25519 seed = okm[0..32], X25519 private key = okm[32..64]
//! ```
//!
//! The recovery device sits in the device log with `recovery: true` and receives every epoch
//! wrap. Its only log entry is adding the new installation as a regular device
//! ([`crate::devicelog`]); it signs no commits and no records.

use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::encoding::{constant_time_eq, framed, hkdf, sha256_framed};
use crate::entropy::{Entropy, EntropyError};
use crate::identity::{DeviceIdentity, IdentityError};

const LABEL_CODE: &[u8] = b"hangar-drive/v1/recovery-code";
const LABEL_IDENTITY: &[u8] = b"hangar-drive/v1/recovery-identity";
const CODE_VERSION: u8 = 1;
pub(crate) const ENTROPY_LEN: usize = 16;
const PAYLOAD_LEN: usize = 1 + ENTROPY_LEN + 3;
const CHARS: usize = PAYLOAD_LEN * 8 / 5;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Why a typed code was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CodeError {
    /// Characters outside the alphabet or the wrong number of them.
    #[error("the code has the wrong length or characters")]
    Format,
    /// A code of a version this crate does not know.
    #[error("code version {0} is not supported")]
    Version(u8),
    /// The checksum does not match: a typo.
    #[error("the code contains a typo")]
    Checksum,
}

fn checksum(label: &[u8], version: u8, entropy: &[u8; ENTROPY_LEN]) -> [u8; 3] {
    let digest = sha256_framed(&[label, &[version], entropy]);
    [digest[0], digest[1], digest[2]]
}

fn symbol_value(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    let value = ALPHABET.iter().position(|&a| char::from(a) == c)?;
    u8::try_from(value).ok()
}

/// `version || entropy || checksum` in Crockford base32, 8 groups of 4. Shared with the pairing
/// code, which differs only in its checksum label.
pub(crate) fn encode_code(
    label: &[u8],
    version: u8,
    entropy: &[u8; ENTROPY_LEN],
) -> Zeroizing<String> {
    let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
    payload[0] = version;
    payload[1..1 + ENTROPY_LEN].copy_from_slice(entropy);
    payload[1 + ENTROPY_LEN..].copy_from_slice(&checksum(label, version, entropy));
    let mut out = Zeroizing::new(String::with_capacity(CHARS + CHARS / 4));
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut written = 0usize;
    for &byte in payload.iter() {
        acc = (acc << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((acc >> bits) & 0x1f).unwrap_or(0);
            if written > 0 && written.is_multiple_of(4) {
                out.push('-');
            }
            out.push(char::from(ALPHABET[index]));
            written += 1;
        }
        acc &= (1 << bits) - 1;
    }
    out
}

/// Reads a typed code of `version` (case, spaces, hyphens and look-alike letters forgiven).
pub(crate) fn decode_code(
    text: &str,
    label: &[u8],
    version: u8,
) -> Result<Zeroizing<[u8; ENTROPY_LEN]>, CodeError> {
    let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut at = 0usize;
    let mut symbols = 0usize;
    for c in text.chars().filter(|c| !matches!(c, ' ' | '-')) {
        let value = symbol_value(c).ok_or(CodeError::Format)?;
        symbols += 1;
        if symbols > CHARS {
            return Err(CodeError::Format);
        }
        acc = (acc << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            payload[at] = u8::try_from((acc >> bits) & 0xff).unwrap_or(0);
            at += 1;
        }
        acc &= (1 << bits) - 1;
    }
    if symbols != CHARS {
        return Err(CodeError::Format);
    }
    if payload[0] != version {
        return Err(CodeError::Version(payload[0]));
    }
    let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
    entropy.copy_from_slice(&payload[1..1 + ENTROPY_LEN]);
    if !constant_time_eq(
        &checksum(label, version, &entropy),
        &payload[1 + ENTROPY_LEN..],
    ) {
        return Err(CodeError::Checksum);
    }
    Ok(entropy)
}

/// A recovery code. Wiped on drop; `Debug` hides it, and it has no `Display` so it is not
/// printed by accident: [`RecoveryCode::reveal`] gives the text to show once.
#[derive(Clone)]
pub struct RecoveryCode(Zeroizing<[u8; ENTROPY_LEN]>);

impl PartialEq for RecoveryCode {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_ref(), other.0.as_ref())
    }
}

impl Eq for RecoveryCode {}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(..)")
    }
}

impl RecoveryCode {
    /// A new random code.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, EntropyError> {
        let mut bytes = Zeroizing::new([0u8; ENTROPY_LEN]);
        entropy.fill(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// The code as text to show once: 8 groups of 4 characters.
    pub fn reveal(&self) -> Zeroizing<String> {
        encode_code(LABEL_CODE, CODE_VERSION, &self.0)
    }

    /// Reads a typed code.
    pub fn parse(text: &str) -> Result<Self, CodeError> {
        decode_code(text, LABEL_CODE, CODE_VERSION).map(Self)
    }

    /// The offline recovery device this code stands for.
    pub fn identity(&self) -> Result<DeviceIdentity, IdentityError> {
        let okm =
            hkdf::<64>(self.0.as_ref(), &framed(&[LABEL_IDENTITY])).ok_or(IdentityError::Key)?;
        DeviceIdentity::from_seeds(&okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::{FixedEntropy, OsEntropy};

    #[test]
    fn code_round_trips_and_derives_the_same_identity() {
        let code = RecoveryCode::generate(&mut OsEntropy).unwrap();
        let text = code.reveal();
        assert_eq!(text.len(), 32 + 7);
        assert_eq!(text.split('-').count(), 8);
        let parsed = RecoveryCode::parse(&text).unwrap();
        assert_eq!(parsed, code);
        assert_eq!(
            parsed.identity().unwrap().public_keys(),
            code.identity().unwrap().public_keys()
        );
        let other = RecoveryCode::generate(&mut OsEntropy).unwrap();
        assert_ne!(
            other.identity().unwrap().public_keys(),
            code.identity().unwrap().public_keys()
        );
    }

    #[test]
    fn parsing_forgives_case_spaces_and_look_alikes() {
        let code = RecoveryCode::generate(&mut FixedEntropy::counting(0, 16)).unwrap();
        let text = code.reveal().replace('-', " ").to_lowercase();
        assert_eq!(RecoveryCode::parse(&text).unwrap(), code);
        let look_alike = code.reveal().replace('0', "O").replace('1', "l");
        assert_eq!(RecoveryCode::parse(&look_alike).unwrap(), code);
    }

    #[test]
    fn typos_and_bad_codes_are_typed() {
        let code = RecoveryCode::generate(&mut FixedEntropy::counting(0, 16)).unwrap();
        let text = code.reveal().to_string();
        let mut chars: Vec<char> = text.chars().collect();
        chars[10] = if chars[10] == '2' { '3' } else { '2' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(RecoveryCode::parse(&typo), Err(CodeError::Checksum));
        assert_eq!(RecoveryCode::parse(&text[..20]), Err(CodeError::Format));
        assert_eq!(
            RecoveryCode::parse(&format!("{text}0")),
            Err(CodeError::Format)
        );
        assert_eq!(
            RecoveryCode::parse(&text.replacen(&text[..1], "U", 1)),
            Err(CodeError::Format)
        );
        assert!(matches!(
            RecoveryCode::parse(&format!("2{}", &text[1..])),
            Err(CodeError::Version(_))
        ));
    }

    #[test]
    fn debug_hides_the_code() {
        let code = RecoveryCode::generate(&mut OsEntropy).unwrap();
        assert_eq!(format!("{code:?}"), "RecoveryCode(..)");
    }
}
