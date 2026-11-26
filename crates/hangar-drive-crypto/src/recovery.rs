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
//! device ID = HKDF-SHA256(salt none, ikm = entropy, info = field("hangar-drive/v1/recovery-device-id"), 16 bytes)
//! ```
//!
//! The device ID is derived as well, so the recovery sheet needs only the server, the account
//! and the code: the recovering installation signs in as exactly the recovery device that the
//! account's log lists (open point A of the sync engine review).
//!
//! The recovery device sits in the device log with `recovery: true` and receives every epoch
//! wrap. Its only log entry is adding the new installation as a regular device
//! ([`crate::devicelog`]); it signs no commits and no records.
//!
//! # Sheet (version 3)
//!
//! The public part of the printed recovery sheet, also carried by the link
//! `hangar-drive://recover#<base64url of sheet>`; it never holds the code:
//!
//! ```text
//! sheet = 0x03 || account ID (16) || server ID (16) || genesis (32) || anchor tag (16)
//!         || pin flag (0x00 or 0x01) || SPKI pin (32, only with flag 0x01) || server URL (UTF-8)
//! anchor tag = HKDF-SHA256(salt none, ikm = entropy,
//!                          info = field("hangar-drive/v1/recovery-anchor") || field(account ID)
//!                                 || field(genesis), 16 bytes)
//! ```
//!
//! `genesis` is the hash of the account's first device log entry
//! ([`crate::devicelog::entry_hash`] at index 1). The recovering installation refuses every log
//! that does not start with it, so a server cannot hand it another account's log or a log it
//! made up, and the new device joins exactly the account the sheet was printed for (sync engine
//! review N1, N6).
//!
//! The anchor tag binds the account and its genesis anchor to the code. A sheet arrives as a
//! link, and a link can come from anyone: whoever knows the account's log (the server's
//! operator, a copy of its database) could otherwise build an account of their own with the same
//! account ID and their own genesis entry, list the code's recovery device in it (its public
//! keys and proof of possession are public in the real log), wrap an epoch secret they know to
//! its KEM key and send a link to their server. Without the tag the real code passes every check
//! there and the new device joins an account whose secret the sender knows. The tag is a PRF of
//! the code's entropy over exactly the account and the genesis anchor, so nobody without the
//! code can make one for another genesis; the recovering installation checks it
//! ([`RecoverySheet::is_for`]) right after the code is typed, before it connects anywhere
//! (security review "recovery link as phishing"). The genesis anchor cannot enter the recovery
//! device's key derivation instead: entry 1 lists the first recovery device, so its hash
//! depends on that device's keys. The pin is the SHA-256 of the server's SubjectPublicKeyInfo for a self-signed
//! server, so the recovery's first connection is pinned as the pairing's is (ADR 0001,
//! section 6). The URL is stored in the WHATWG serialization; another spelling is refused, so
//! one sheet has one byte form. Versions 1 (without genesis and pin) and 2 (without the anchor
//! tag) were never shipped and are refused.

use std::fmt;

use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::encoding::{constant_time_eq, framed, hkdf, sha256_framed};
use crate::entropy::{Entropy, EntropyError};
use crate::identity::{DeviceIdentity, IdentityError};
use crate::pairing::parse_server_url;
use hangar_drive_protocol::ids::{AccountId, DeviceId, LogHash, ServerId};

const LABEL_CODE: &[u8] = b"hangar-drive/v1/recovery-code";
const LABEL_IDENTITY: &[u8] = b"hangar-drive/v1/recovery-identity";
const LABEL_DEVICE_ID: &[u8] = b"hangar-drive/v1/recovery-device-id";
const LABEL_ANCHOR: &[u8] = b"hangar-drive/v1/recovery-anchor";
/// The length of a sheet's anchor tag (module docs, "Sheet").
pub const ANCHOR_TAG_LEN: usize = 16;
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

    /// The device ID of the offline recovery device this code stands for (module docs).
    pub fn device_id(&self) -> Result<DeviceId, IdentityError> {
        let okm =
            hkdf::<16>(self.0.as_ref(), &framed(&[LABEL_DEVICE_ID])).ok_or(IdentityError::Key)?;
        Ok(DeviceId::from_bytes(*okm))
    }

    /// The offline recovery device this code stands for.
    pub fn identity(&self) -> Result<DeviceIdentity, IdentityError> {
        let okm =
            hkdf::<64>(self.0.as_ref(), &framed(&[LABEL_IDENTITY])).ok_or(IdentityError::Key)?;
        DeviceIdentity::from_seeds(&okm)
    }

    /// The anchor tag of the sheet for `account` with the genesis anchor `genesis` (module
    /// docs, "Sheet"): only who holds the code can make it.
    pub fn anchor_tag(
        &self,
        account: &AccountId,
        genesis: &LogHash,
    ) -> Result<[u8; ANCHOR_TAG_LEN], IdentityError> {
        let okm = hkdf::<ANCHOR_TAG_LEN>(
            self.0.as_ref(),
            &framed(&[LABEL_ANCHOR, account.as_bytes(), genesis.as_bytes()]),
        )
        .ok_or(IdentityError::Key)?;
        Ok(*okm)
    }
}

/// The format version of [`RecoverySheet`].
pub const SHEET_VERSION: u8 = 3;
const SHEET_FIXED_LEN: usize = 1 + 16 + 16 + 32 + ANCHOR_TAG_LEN + 1;
const FLAG_AT: usize = SHEET_FIXED_LEN - 1;

/// Why sheet bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SheetError {
    /// Too short, a bad pin flag, or a URL that is not UTF-8 or not in its one spelling.
    #[error("the recovery sheet is damaged")]
    Malformed,
    /// A version this crate does not read.
    #[error("recovery sheet version {0} is not supported")]
    Version(u8),
    /// The server address is not allowed (`https`, or `http` to the local host only).
    #[error("the server address is not allowed")]
    Insecure,
}

/// The public part of a recovery sheet (module docs, "Sheet").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySheet {
    /// The server's base URL.
    pub server_url: Url,
    /// The server ID.
    pub server: ServerId,
    /// The account ID.
    pub account: AccountId,
    /// The hash of the account's first device log entry.
    pub genesis: LogHash,
    /// The SPKI pin of a self-signed server.
    pub pin: Option<[u8; 32]>,
    /// The code's tag over `account` and `genesis` ([`RecoveryCode::anchor_tag`]).
    pub anchor_tag: [u8; ANCHOR_TAG_LEN],
}

impl RecoverySheet {
    /// The sheet of `code` for `account`, whose first log entry has the hash `genesis`.
    pub fn new(
        server_url: Url,
        server: ServerId,
        account: AccountId,
        genesis: LogHash,
        pin: Option<[u8; 32]>,
        code: &RecoveryCode,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            anchor_tag: code.anchor_tag(&account, &genesis)?,
            server_url,
            server,
            account,
            genesis,
            pin,
        })
    }

    /// Whether this sheet was made for `code`: its anchor tag is the code's tag over the
    /// sheet's account and genesis anchor. A sheet that fails names an account the code was not
    /// made for, whatever that account's log lists (module docs, "Sheet").
    pub fn is_for(&self, code: &RecoveryCode) -> bool {
        code.anchor_tag(&self.account, &self.genesis)
            .is_ok_and(|tag| constant_time_eq(&tag, &self.anchor_tag))
    }

    /// The sheet bytes (module docs).
    pub fn encode(&self) -> Vec<u8> {
        let url = self.server_url.as_str().as_bytes();
        let mut out = Vec::with_capacity(SHEET_FIXED_LEN + 32 + url.len());
        out.push(SHEET_VERSION);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(self.server.as_bytes());
        out.extend_from_slice(self.genesis.as_bytes());
        out.extend_from_slice(&self.anchor_tag);
        match &self.pin {
            Some(pin) => {
                out.push(1);
                out.extend_from_slice(pin);
            }
            None => out.push(0),
        }
        out.extend_from_slice(url);
        out
    }

    /// Reads sheet bytes strictly (module docs).
    pub fn decode(bytes: &[u8]) -> Result<Self, SheetError> {
        let version = *bytes.first().ok_or(SheetError::Malformed)?;
        if version != SHEET_VERSION {
            return Err(SheetError::Version(version));
        }
        if bytes.len() < SHEET_FIXED_LEN + 1 {
            return Err(SheetError::Malformed);
        }
        let account = AccountId::from_slice(&bytes[1..17]).ok_or(SheetError::Malformed)?;
        let server = ServerId::from_slice(&bytes[17..33]).ok_or(SheetError::Malformed)?;
        let genesis = LogHash::from_slice(&bytes[33..65]).ok_or(SheetError::Malformed)?;
        let anchor_tag = <[u8; ANCHOR_TAG_LEN]>::try_from(&bytes[65..FLAG_AT])
            .map_err(|_| SheetError::Malformed)?;
        let (pin, rest) = match bytes[FLAG_AT] {
            0 => (None, &bytes[SHEET_FIXED_LEN..]),
            1 => {
                let pin = bytes
                    .get(SHEET_FIXED_LEN..SHEET_FIXED_LEN + 32)
                    .and_then(|p| <[u8; 32]>::try_from(p).ok())
                    .ok_or(SheetError::Malformed)?;
                (Some(pin), &bytes[SHEET_FIXED_LEN + 32..])
            }
            _ => return Err(SheetError::Malformed),
        };
        let text = std::str::from_utf8(rest).map_err(|_| SheetError::Malformed)?;
        if text.is_empty() {
            return Err(SheetError::Malformed);
        }
        let server_url = parse_server_url(text).map_err(|_| SheetError::Insecure)?;
        if server_url.as_str() != text {
            return Err(SheetError::Malformed);
        }
        Ok(Self {
            server_url,
            server,
            account,
            genesis,
            pin,
            anchor_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::{FixedEntropy, OsEntropy};

    fn sheet(pin: Option<[u8; 32]>) -> RecoverySheet {
        RecoverySheet {
            server_url: parse_server_url("https://drive.example/").unwrap(),
            server: ServerId::from_bytes([0x40; 16]),
            account: AccountId::from_bytes([0x10; 16]),
            genesis: LogHash::from_bytes([0x77; 32]),
            pin,
            anchor_tag: [0x5a; ANCHOR_TAG_LEN],
        }
    }

    #[test]
    fn sheets_round_trip_with_and_without_a_pin() {
        for pin in [None, Some([0xf0; 32])] {
            let s = sheet(pin);
            let bytes = s.encode();
            assert_eq!(bytes[0], SHEET_VERSION);
            assert_eq!(RecoverySheet::decode(&bytes).unwrap(), s);
        }
    }

    #[test]
    fn sheets_are_read_strictly() {
        let bytes = sheet(Some([1; 32])).encode();
        // Version 1 had no genesis anchor, version 2 no anchor tag; both are refused.
        for version in [1, 2] {
            let mut old = bytes.clone();
            old[0] = version;
            assert_eq!(
                RecoverySheet::decode(&old),
                Err(SheetError::Version(version))
            );
        }
        assert_eq!(RecoverySheet::decode(&[]), Err(SheetError::Malformed));
        assert_eq!(
            RecoverySheet::decode(&bytes[..SHEET_FIXED_LEN]),
            Err(SheetError::Malformed)
        );
        let mut flag = bytes.clone();
        flag[FLAG_AT] = 2;
        assert_eq!(RecoverySheet::decode(&flag), Err(SheetError::Malformed));
        // A pin flag without the pin.
        let mut short = sheet(None).encode()[..SHEET_FIXED_LEN].to_vec();
        short[FLAG_AT] = 1;
        short.extend_from_slice(&[1; 10]);
        assert_eq!(RecoverySheet::decode(&short), Err(SheetError::Malformed));
        let mut insecure = sheet(None).encode()[..SHEET_FIXED_LEN].to_vec();
        insecure.extend_from_slice(b"http://drive.example/");
        assert_eq!(RecoverySheet::decode(&insecure), Err(SheetError::Insecure));
        let mut spelled = sheet(None).encode()[..SHEET_FIXED_LEN].to_vec();
        spelled.extend_from_slice(b"https://DRIVE.example");
        assert_eq!(RecoverySheet::decode(&spelled), Err(SheetError::Malformed));
    }

    // The phishing link of the security review: a sheet that names another genesis (or another
    // account) than the code was made for fails, and its tag cannot be carried over.
    #[test]
    fn a_sheet_is_only_for_the_code_it_was_made_with() {
        let code = RecoveryCode::generate(&mut FixedEntropy::counting(0xd0, 16)).unwrap();
        let other = RecoveryCode::generate(&mut FixedEntropy::counting(0x30, 16)).unwrap();
        let base = sheet(None);
        let real = RecoverySheet::new(
            base.server_url.clone(),
            base.server,
            base.account,
            base.genesis,
            None,
            &code,
        )
        .unwrap();
        assert!(real.is_for(&code));
        assert!(!real.is_for(&other));
        assert!(RecoverySheet::decode(&real.encode()).unwrap().is_for(&code));
        // Another genesis with the real tag, as a forger would send it.
        let forged = RecoverySheet {
            genesis: LogHash::from_bytes([0x78; 32]),
            ..real.clone()
        };
        assert!(!forged.is_for(&code));
        let moved = RecoverySheet {
            account: AccountId::from_bytes([0x11; 16]),
            ..real.clone()
        };
        assert!(!moved.is_for(&code));
        // Server address, server ID and pin are not bound: a server may move.
        let elsewhere = RecoverySheet {
            server_url: parse_server_url("https://other.example/").unwrap(),
            server: ServerId::from_bytes([0x41; 16]),
            pin: Some([2; 32]),
            ..real
        };
        assert!(elsewhere.is_for(&code));
    }

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
