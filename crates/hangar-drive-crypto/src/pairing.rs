//! Pairing a new device: the signed offer an existing device shows as a QR code, the request
//! tag the server cannot forge, and the new device's check of the log it then receives (ADR
//! 0001, sections 4 and 6; threat model, section 2.2).
//!
//! # Offer (version 1)
//!
//! ```text
//! offer = 0x01 || field(server URL, UTF-8) || field(SPKI pin, 32 bytes or empty) || field(server id)
//!         || field(account) || field(inviting device) || field(log head index, u64)
//!         || field(log head hash) || field(pairing secret P, 16 bytes) || field(expires at, u64 ms)
//! wire  = offer || Ed25519 signature of the inviting device over field("hangar-drive/v1/pairing-offer") || offer
//! ```
//!
//! The offer is the new device's trust anchor: the log head comes out of band, so a server
//! cannot show the new device an invented log ([`check_joined`]). It is single use and expires
//! after 10 minutes (the server enforces single use, the app the expiry).
//!
//! **Typed pairing is not supported** (security review, info). [`PairingSecret::reveal`] and
//! [`PairingSecret::parse`] turn P into a 32-character code (Crockford base32 with a checksum,
//! like the recovery code), but that code carries P alone: no account ID and no log head hash.
//! A new device that only typed it has no trust anchor, so the server could show it an invented
//! log with devices of the server's own, and [`check_joined`] needs the offer's head. The app
//! therefore pairs only through the scanned offer; a typed form must carry account ID and head
//! hash (or the person must compare the log safety number before anything is trusted) before
//! it can be offered. Short codes are never used as P without a PAKE: the server sees the tag
//! and could brute force a short code offline.
//!
//! **Signature:** the inviting device signs the offer. A device of the same account that scans
//! an offer takes the server URL and the SPKI pin from it (pin rotation, ADR 0001, section 6)
//! only if the signature verifies with the inviter's key in its own verified log and the inviter
//! is a current, regular device there ([`PairingOffer::server_address`]). Without the signature
//! anyone who can show a QR code to the person could point the device at another server. The
//! new device checks the same signature once it has the log ([`check_joined`]).
//!
//! # Request tag and sealed name
//!
//! ```text
//! P_mac  = HKDF-SHA256(ikm = P, info = field("hangar-drive/v1/pairing-mac"), 32 bytes)
//! P_id   = HKDF-SHA256(ikm = P, info = field("hangar-drive/v1/pairing-id"), 16 bytes)
//! P_name = HKDF-SHA256(ikm = P, info = field("hangar-drive/v1/pairing-name-key"), 32 bytes)
//! sealed name = nonce (24 random bytes) || XChaCha20-Poly1305(P_name, nonce, padded,
//!               aad = field("hangar-drive/v1/pairing-name") || field(account) || field(new device id))
//! padded = length (u64) || name (UTF-8) || zeros, to padme(8 + len(name)) bytes
//! tag    = HMAC-SHA-256(P_mac, field("hangar-drive/v1/pairing-request") || field(account)
//!                       || field(new device id) || field(sign key) || field(kem key)
//!                       || field(proof) || field(sealed name))
//! ```
//!
//! The server routes the request by `P_id` and learns neither P nor anything that lets it forge
//! the tag or read the name: device names are sealed records everywhere else (ADR 0001, section
//! 4), and a request waits on the server until it is answered. The name is padded with Padmé
//! (security review N13), so its length shows only to its Padmé length; the key's HKDF info and
//! the AEAD's associated data carry labels of their own (`pairing-name-key`, `pairing-name`), so
//! no byte string serves two purposes (security review, info). Only who holds P (the inviting
//! device, and the new device that read the offer) can open the name. The key seals one request
//! of one offer, so a random nonce is ample. The inviting device checks the tag in constant
//! time, then opens the name, then checks the proof of possession, then asks the person `Add
//! device <name>?` with the new device's safety number. The name passes
//! [`hangar_drive_protocol::name::check_display_name`] on both sides.
//!
//! # Server URL
//!
//! Parsed by the WHATWG URL Standard parser (`url`, the parser reqwest uses), so the host
//! checked is the host the app connects to ([`parse_server_url`]). Allowed are `https` with any
//! host, and `http` only to `localhost`, `127.0.0.1` or `[::1]` (ADR 0001, section 6). A URL with
//! a user name or password is refused, which closes forms such as
//! `http://localhost:80@evil.example/`, and so is a URL with a query or a fragment, since the
//! app joins API paths onto it. Only the parsed [`Url`] is passed on; in an offer the URL
//! must be in the parser's own serialization, so it has one spelling.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hangar_drive_protocol::api::{PairingRequest, MAX_DEVICE_NAME_LEN, SEALED_NAME_OVERHEAD};
use hangar_drive_protocol::ids::{
    AccountId, Blob, DeviceId, LogHash, LogHead, PairingId, ServerId, Signature,
};
use hangar_drive_protocol::name::check_display_name;
use thiserror::Error;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::devicelog::AccountState;
use crate::encoding::{
    constant_time_eq, framed, hkdf, hmac, mac_field, mac_finish, Reader, Writer,
};
use crate::entropy::{Entropy, EntropyError};
use crate::identity::{
    is_valid_kem_key, is_valid_sign_key, verify, verify_proof, DeviceIdentity, DevicePublicKeys,
};
use crate::object::padme;
use crate::recovery::{decode_code, encode_code, CodeError, ENTROPY_LEN};

const LABEL_CODE: &[u8] = b"hangar-drive/v1/pairing-code";
const LABEL_MAC: &[u8] = b"hangar-drive/v1/pairing-mac";
const LABEL_ID: &[u8] = b"hangar-drive/v1/pairing-id";
const LABEL_REQUEST: &[u8] = b"hangar-drive/v1/pairing-request";
const LABEL_OFFER: &[u8] = b"hangar-drive/v1/pairing-offer";
const LABEL_NAME: &[u8] = b"hangar-drive/v1/pairing-name";
const LABEL_NAME_KEY: &[u8] = b"hangar-drive/v1/pairing-name-key";
/// Bytes of the random nonce in front of a sealed name.
const NAME_NONCE_LEN: usize = 24;
const CODE_VERSION: u8 = 1;
const OFFER_VERSION: u8 = 1;
const SIGNATURE_LEN: usize = 64;
/// How long an offer is valid.
pub const OFFER_LIFETIME_MS: u64 = 10 * 60 * 1000;
/// The longest server URL an offer carries.
pub const MAX_URL_LEN: usize = 2048;

/// Why a pairing step failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PairingError {
    /// Not an offer of this format.
    #[error("the pairing offer is malformed")]
    Malformed,
    /// A format version this crate does not know.
    #[error("pairing offer version {0} is not supported")]
    Version(u8),
    /// A server URL the client may not use.
    #[error("the server address must use https (plain http only for localhost)")]
    Url,
    /// The offer's time is over.
    #[error("the pairing offer has expired")]
    Expired,
    /// The tag does not verify: not made with this offer's secret.
    #[error("the pairing request was not made with this offer")]
    Tag,
    /// The proof of possession does not verify, or the keys are not valid.
    #[error("the new device's keys are not valid")]
    Keys,
    /// The name is empty, too long or has control or formatting characters.
    #[error("the device name is not valid")]
    Name,
    /// The log does not extend the offer's head, or does not list this device with its keys.
    #[error("the account log does not extend the pairing offer or does not list this device")]
    NotJoined,
    /// The offer belongs to another account or server.
    #[error("the pairing offer belongs to another account or server")]
    OtherAccount,
    /// The offer names a log head this device has not verified yet: fetch the log first.
    #[error("the pairing offer names log entry {index}, which this device has not verified yet")]
    AheadOfLog {
        /// The offer's head index.
        index: u64,
    },
    /// The offer is not signed by a current, regular device of the verified log.
    #[error("the pairing offer is not signed by a device of this account")]
    Signature,
    /// A typed pairing code was not accepted.
    #[error(transparent)]
    Code(#[from] CodeError),
    /// Key derivation failed (not expected).
    #[error("key derivation failed")]
    Key,
    /// No randomness.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
}

/// The 128-bit pairing secret P. Wiped on drop, never printed.
#[derive(Clone)]
pub struct PairingSecret(Zeroizing<[u8; ENTROPY_LEN]>);

impl fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingSecret(..)")
    }
}

impl PartialEq for PairingSecret {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_ref(), other.0.as_ref())
    }
}

impl Eq for PairingSecret {}

impl PairingSecret {
    /// A new random secret.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, EntropyError> {
        let mut bytes = Zeroizing::new([0u8; ENTROPY_LEN]);
        entropy.fill(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// The secret as a code of 8 groups of 4 characters. Not a pairing method on its own: the
    /// code carries no trust anchor (module docs, "Typed pairing is not supported").
    pub fn reveal(&self) -> Zeroizing<String> {
        encode_code(LABEL_CODE, CODE_VERSION, &self.0)
    }

    /// Reads a code made by [`PairingSecret::reveal`]. A device that has only this has no
    /// trust anchor (module docs).
    pub fn parse(text: &str) -> Result<Self, PairingError> {
        Ok(Self(decode_code(text, LABEL_CODE, CODE_VERSION)?))
    }

    /// Where the server routes the request.
    pub fn pairing_id(&self) -> Result<PairingId, PairingError> {
        let id = hkdf::<16>(self.0.as_ref(), &framed(&[LABEL_ID])).ok_or(PairingError::Key)?;
        Ok(PairingId::from_bytes(*id))
    }

    fn name_cipher(&self) -> Result<XChaCha20Poly1305, PairingError> {
        let key =
            hkdf::<32>(self.0.as_ref(), &framed(&[LABEL_NAME_KEY])).ok_or(PairingError::Key)?;
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| PairingError::Key)
    }

    /// The new device's name sealed for whoever holds this secret (module docs).
    fn seal_name(
        &self,
        account: &AccountId,
        device: &DeviceId,
        name: &str,
        entropy: &mut impl Entropy,
    ) -> Result<Vec<u8>, PairingError> {
        let mut nonce = [0u8; NAME_NONCE_LEN];
        entropy.fill(&mut nonce)?;
        let aad = framed(&[LABEL_NAME, account.as_bytes(), device.as_bytes()]);
        let len = u64::try_from(name.len()).map_err(|_| PairingError::Name)?;
        let padded_len = len
            .checked_add(8)
            .and_then(padme)
            .and_then(|padded| usize::try_from(padded).ok())
            .ok_or(PairingError::Name)?;
        let mut padded = Zeroizing::new(Vec::with_capacity(padded_len));
        padded.extend_from_slice(&len.to_be_bytes());
        padded.extend_from_slice(name.as_bytes());
        padded.resize(padded_len, 0);
        let ciphertext = self
            .name_cipher()?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &padded,
                    aad: &aad,
                },
            )
            .map_err(|_| PairingError::Key)?;
        let mut sealed = Vec::with_capacity(padded_len + SEALED_NAME_OVERHEAD);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Opens a sealed name: [`PairingError::Name`] if it does not open with this secret for
    /// this account and device, its padding is not exactly the Padmé length with zeros, or it
    /// is not a valid name. Public for the fuzz target; the inviting device calls it through
    /// [`PairingSecret::verify_request`] after the tag.
    pub fn open_name(
        &self,
        account: &AccountId,
        device: &DeviceId,
        sealed: &[u8],
    ) -> Result<String, PairingError> {
        if sealed.len() <= SEALED_NAME_OVERHEAD {
            return Err(PairingError::Name);
        }
        let (nonce, ciphertext) = sealed.split_at(NAME_NONCE_LEN);
        let nonce: [u8; NAME_NONCE_LEN] = nonce.try_into().map_err(|_| PairingError::Name)?;
        let aad = framed(&[LABEL_NAME, account.as_bytes(), device.as_bytes()]);
        let plain = self
            .name_cipher()?
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| PairingError::Name)?;
        let plain = Zeroizing::new(plain);
        if plain.len() < 8 {
            return Err(PairingError::Name);
        }
        let (len, rest) = plain.split_at(8);
        let len = u64::from_be_bytes(len.try_into().map_err(|_| PairingError::Name)?);
        let len_usize = usize::try_from(len).map_err(|_| PairingError::Name)?;
        if len_usize > rest.len()
            || len_usize > MAX_DEVICE_NAME_LEN
            || u64::try_from(plain.len()).ok() != len.checked_add(8).and_then(padme)
        {
            return Err(PairingError::Name);
        }
        let (name, padding) = rest.split_at(len_usize);
        if padding.iter().any(|&b| b != 0) {
            return Err(PairingError::Name);
        }
        let name = String::from_utf8(name.to_vec()).map_err(|_| PairingError::Name)?;
        check_name(&name)?;
        Ok(name)
    }

    fn tag(
        &self,
        account: &AccountId,
        device: &DeviceId,
        keys: &DevicePublicKeys,
        proof: &Signature,
        sealed_name: &[u8],
    ) -> Result<[u8; 32], PairingError> {
        let key = hkdf::<32>(self.0.as_ref(), &framed(&[LABEL_MAC])).ok_or(PairingError::Key)?;
        let mut mac = hmac(key.as_ref()).ok_or(PairingError::Key)?;
        for part in [
            LABEL_REQUEST,
            account.as_bytes(),
            device.as_bytes(),
            keys.sign.as_bytes(),
            keys.kem.as_bytes(),
            proof.as_bytes(),
            sealed_name,
        ] {
            mac_field(&mut mac, part);
        }
        Ok(mac_finish(mac))
    }

    /// The new device's request: its keys, its proof of possession, its sealed name and the
    /// tag. `entropy` gives the name's nonce.
    pub fn request(
        &self,
        identity: &DeviceIdentity,
        account: &AccountId,
        device: DeviceId,
        name: &str,
        entropy: &mut impl Entropy,
    ) -> Result<PairingRequest, PairingError> {
        check_name(name)?;
        let keys = identity.public_keys();
        let proof = identity.prove(account, &device, false);
        let sealed_name = self.seal_name(account, &device, name, entropy)?;
        let tag = self.tag(account, &device, &keys, &proof, &sealed_name)?;
        Ok(PairingRequest {
            device,
            sign: keys.sign,
            kem: keys.kem,
            proof,
            sealed_name: Blob(sealed_name),
            tag: Blob(tag.to_vec()),
        })
    }

    /// The inviting device's check of a request: tag (constant time), name, keys and proof of
    /// possession. On success the app shows the opened name and the safety number of the
    /// returned keys and asks the person before it adds the device to the log.
    pub fn verify_request(
        &self,
        account: &AccountId,
        request: &PairingRequest,
    ) -> Result<VerifiedRequest, PairingError> {
        let keys = DevicePublicKeys {
            sign: request.sign,
            kem: request.kem,
        };
        let expected = self.tag(
            account,
            &request.device,
            &keys,
            &request.proof,
            request.sealed_name.as_bytes(),
        )?;
        if !constant_time_eq(&expected, request.tag.as_bytes()) {
            return Err(PairingError::Tag);
        }
        let name = self.open_name(account, &request.device, request.sealed_name.as_bytes())?;
        if !is_valid_sign_key(&keys.sign)
            || !is_valid_kem_key(&keys.kem)
            || !verify_proof(account, &request.device, &keys, false, &request.proof)
        {
            return Err(PairingError::Keys);
        }
        Ok(VerifiedRequest { keys, name })
    }
}

/// A pairing request the inviting device checked ([`PairingSecret::verify_request`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRequest {
    /// The new device's keys.
    pub keys: DevicePublicKeys,
    /// Its name, opened and checked.
    pub name: String,
}

fn check_name(name: &str) -> Result<(), PairingError> {
    check_display_name(name, MAX_DEVICE_NAME_LEN).map_err(|_| PairingError::Name)
}

/// Parses a server URL the client may use (module docs): `https`, or `http` only to the local
/// machine, without user name or password. The app connects only to the returned [`Url`].
pub fn parse_server_url(text: &str) -> Result<Url, PairingError> {
    // The parser drops tabs, newlines and surrounding spaces silently; refuse them instead, so
    // the URL the person sees is the URL that is used.
    if text.len() > MAX_URL_LEN || text.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(PairingError::Url);
    }
    let url = Url::parse(text).map_err(|_| PairingError::Url)?;
    // The parser also reads `https:///host`, `https:host` and `https:\\host` as `https://host/`;
    // only the plain `scheme://host` form is accepted, so the text shows its host.
    let scheme_len = url.scheme().len();
    let plain_authority = text
        .get(..scheme_len)
        .is_some_and(|s| s.eq_ignore_ascii_case(url.scheme()))
        && text
            .get(scheme_len..)
            .and_then(|rest| rest.strip_prefix("://"))
            .is_some_and(|rest| !rest.starts_with(['/', '\\']));
    // A base URL carries no query or fragment: the app joins API paths onto it, and a signed
    // offer should not carry text the connection never uses.
    if !plain_authority
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PairingError::Url);
    }
    let allowed = match url.scheme() {
        "https" => url.host().is_some(),
        "http" => match url.host() {
            Some(Host::Domain(domain)) => domain == "localhost",
            Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
            Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
            None => false,
        },
        _ => false,
    };
    if !allowed || url.as_str().len() > MAX_URL_LEN {
        return Err(PairingError::Url);
    }
    Ok(url)
}

/// Whether the client may talk to `url` ([`parse_server_url`]).
pub fn is_allowed_server_url(url: &str) -> bool {
    parse_server_url(url).is_ok()
}

/// What an offer says (module docs), before the inviting device signs it. Holds the pairing
/// secret: wiped on drop through it, never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct OfferContent {
    /// The server's address, parsed ([`parse_server_url`]).
    pub server_url: Url,
    /// SHA-256 of the server's SPKI for a self-signed server; `None` with a public CA.
    pub spki_pin: Option<[u8; 32]>,
    /// The server's ID, which the new device pins.
    pub server: ServerId,
    /// The account.
    pub account: AccountId,
    /// The device that shows the offer and signs it.
    pub inviter: DeviceId,
    /// The account log head, the new device's trust anchor.
    pub head: LogHead,
    /// The pairing secret.
    pub secret: PairingSecret,
    /// End of validity, milliseconds since the Unix epoch on the inviting device's clock.
    pub expires_at_ms: u64,
}

impl fmt::Debug for OfferContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferContent")
            .field("server_url", &self.server_url.as_str())
            .field("server", &self.server)
            .field("account", &self.account)
            .field("inviter", &self.inviter)
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// Bytes of an offer body besides the URL and the pin: the version byte, nine length prefixes
/// and the fixed fields (server, account, inviter, head index, head hash, P, expiry).
const OFFER_FIXED_LEN: usize = 1 + 9 * 4 + 16 + 16 + 16 + 8 + 32 + ENTROPY_LEN + 8;

impl OfferContent {
    /// The offer body, in a buffer with room for `extra` more bytes. The body holds the pairing
    /// secret, so it is written into a buffer of its final size: a buffer that grew would leave
    /// copies of P in the freed memory, which `Zeroizing` never sees (security review, info).
    fn body(&self, extra: usize) -> Result<Zeroizing<Vec<u8>>, PairingError> {
        let url = parse_server_url(self.server_url.as_str())?;
        let pin_len = self.spki_pin.map_or(0, |p| p.len());
        let mut w = Writer::with_capacity(OFFER_FIXED_LEN + url.as_str().len() + pin_len + extra);
        w.u8(OFFER_VERSION)
            .field(url.as_str().as_bytes())
            .field(self.spki_pin.as_ref().map_or(&[][..], |p| p.as_slice()))
            .field(self.server.as_bytes())
            .field(self.account.as_bytes())
            .field(self.inviter.as_bytes())
            .field_u64(self.head.index)
            .field(self.head.hash.as_bytes())
            .field(self.secret.0.as_ref())
            .field_u64(self.expires_at_ms);
        Ok(Zeroizing::new(w.into_bytes()))
    }

    /// Signs the offer with the inviting device's keys (`identity` belongs to
    /// [`OfferContent::inviter`]).
    pub fn sign(self, identity: &DeviceIdentity) -> Result<PairingOffer, PairingError> {
        if self.head.index == 0 {
            return Err(PairingError::Malformed);
        }
        let body = self.body(0)?;
        let signature = Signature::from_bytes(identity.sign(&offer_message(&body)));
        Ok(PairingOffer {
            content: self,
            signature,
        })
    }
}

fn offer_message(body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::with_capacity(body.len() + 4 + LABEL_OFFER.len());
    w.field(LABEL_OFFER).raw(body);
    Zeroizing::new(w.into_bytes())
}

/// A signed offer (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingOffer {
    /// What it says.
    pub content: OfferContent,
    /// The inviting device's signature.
    pub signature: Signature,
}

/// Where a device of the account connects from now on, taken from a verified offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddress {
    /// The server's URL.
    pub url: Url,
    /// The SPKI pin; `None` moves the device to the platform verifier (public CA).
    pub spki_pin: Option<[u8; 32]>,
}

impl PairingOffer {
    /// The offer's wire bytes (module docs), wiped on drop. The app shows them as base64url in
    /// a QR code.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PairingError> {
        let mut bytes = self.content.body(SIGNATURE_LEN)?;
        bytes.extend_from_slice(self.signature.as_bytes());
        Ok(bytes)
    }

    /// Reads an offer strictly. Checks no signature: that needs the verified log
    /// ([`PairingOffer::verify_inviter`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, PairingError> {
        let m = || PairingError::Malformed;
        let body_len = bytes.len().checked_sub(SIGNATURE_LEN).ok_or_else(m)?;
        let (body, signature) = bytes.split_at(body_len);
        let signature = Signature::from_slice(signature).ok_or_else(m)?;
        let mut r = Reader::new(body);
        let version = r.u8().ok_or_else(m)?;
        if version != OFFER_VERSION {
            return Err(PairingError::Version(version));
        }
        let text = std::str::from_utf8(r.field().ok_or_else(m)?).map_err(|_| PairingError::Url)?;
        let server_url = parse_server_url(text)?;
        // One spelling: the parser's serialization.
        if server_url.as_str() != text {
            return Err(PairingError::Url);
        }
        let spki_pin = match r.field().ok_or_else(m)? {
            [] => None,
            pin => Some(<[u8; 32]>::try_from(pin).map_err(|_| PairingError::Malformed)?),
        };
        let server = ServerId::from_bytes(r.field_fixed().ok_or_else(m)?);
        let account = AccountId::from_bytes(r.field_fixed().ok_or_else(m)?);
        let inviter = DeviceId::from_bytes(r.field_fixed().ok_or_else(m)?);
        let index = r.field_u64().ok_or_else(m)?;
        let hash = LogHash::from_bytes(r.field_fixed().ok_or_else(m)?);
        let mut secret = Zeroizing::new([0u8; ENTROPY_LEN]);
        secret.copy_from_slice(r.field().filter(|s| s.len() == ENTROPY_LEN).ok_or_else(m)?);
        let expires_at_ms = r.field_u64().ok_or_else(m)?;
        r.finish().ok_or_else(m)?;
        if index == 0 {
            return Err(PairingError::Malformed);
        }
        Ok(Self {
            content: OfferContent {
                server_url,
                spki_pin,
                server,
                account,
                inviter,
                head: LogHead { index, hash },
                secret: PairingSecret(secret),
                expires_at_ms,
            },
            signature,
        })
    }

    /// Refuses an offer whose time is over; `now_ms` is the caller's clock.
    pub fn check_fresh(&self, now_ms: u64) -> Result<(), PairingError> {
        if now_ms >= self.content.expires_at_ms {
            return Err(PairingError::Expired);
        }
        Ok(())
    }

    /// Checks the signature against the inviter's key in the verified log `state`: the inviter
    /// must be a current, regular device of it.
    pub fn verify_inviter(&self, state: &AccountState) -> Result<(), PairingError> {
        let inviter = state
            .device(&self.content.inviter)
            .filter(|d| d.is_current() && !d.recovery)
            .ok_or(PairingError::Signature)?;
        let body = self.content.body(0)?;
        if !verify(
            &inviter.keys.sign,
            &offer_message(&body),
            self.signature.as_bytes(),
        ) {
            return Err(PairingError::Signature);
        }
        Ok(())
    }

    /// For a device that already belongs to the account and scans this offer (ADR 0001,
    /// section 6, pin rotation): the server address to use from now on, only if the offer is of
    /// this account (`state`) and server (`server`), its log head is in the verified log
    /// ([`PairingError::AheadOfLog`]: fetch and verify the log, then ask again) and its signature
    /// verifies against the inviter's current key there. The device does not pair.
    pub fn server_address(
        &self,
        state: &AccountState,
        server: &ServerId,
    ) -> Result<ServerAddress, PairingError> {
        let c = &self.content;
        if c.account != *state.account() || c.server != *server {
            return Err(PairingError::OtherAccount);
        }
        // An inviter this device already knows signs before anything else counts (security
        // review M2): a forged offer in its name with a head far ahead would otherwise send the
        // device to fetch a log from the offer's server first. Only an inviter the verified log
        // does not list yet makes the device fetch the log.
        if state
            .device(&c.inviter)
            .is_some_and(|d| d.is_current() && !d.recovery)
        {
            self.verify_inviter(state)?;
        }
        if c.head.index > state.len() {
            return Err(PairingError::AheadOfLog {
                index: c.head.index,
            });
        }
        if !state.contains(&c.head) {
            return Err(PairingError::NotJoined);
        }
        self.verify_inviter(state)?;
        Ok(ServerAddress {
            url: c.server_url.clone(),
            spki_pin: c.spki_pin,
        })
    }
}

/// The new device's check of the log the server shows it after the pairing: it must extend the
/// offer's head, list this device with these keys added after that head, and vouch for the
/// inviter who signed the offer.
pub fn check_joined(
    state: &AccountState,
    offer: &PairingOffer,
    me: &DeviceId,
    keys: &DevicePublicKeys,
) -> Result<(), PairingError> {
    let anchor = &offer.content.head;
    if state.account() != &offer.content.account || !state.contains(anchor) {
        return Err(PairingError::NotJoined);
    }
    let record = state.device(me).ok_or(PairingError::NotJoined)?;
    if record.keys != *keys
        || !record.is_current()
        || record.recovery
        || record.added_at <= anchor.index
    {
        return Err(PairingError::NotJoined);
    }
    offer.verify_inviter(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devicelog::tests::{created, dev, Dev, ACCOUNT};
    use crate::devicelog::{EntryKind, LogDevice};
    use crate::entropy::{FixedEntropy, OsEntropy};

    const SERVER: ServerId = ServerId::from_bytes([4; 16]);

    fn content(secret: PairingSecret, inviter: DeviceId, head: LogHead) -> OfferContent {
        OfferContent {
            server_url: parse_server_url("https://drive.example/").unwrap(),
            spki_pin: Some([7; 32]),
            server: SERVER,
            account: ACCOUNT,
            inviter,
            head,
            secret,
            expires_at_ms: 1_000 + OFFER_LIFETIME_MS,
        }
    }

    fn signed(inviter: &Dev, head: LogHead) -> PairingOffer {
        content(
            PairingSecret::generate(&mut OsEntropy).unwrap(),
            inviter.id,
            head,
        )
        .sign(&inviter.identity)
        .unwrap()
    }

    // Security review N13: the sealed name shows its length only to its Padme length, and the
    // server's size bounds are the Padme lengths of the shortest and the longest name.
    #[test]
    fn sealed_names_are_padded_with_padme() {
        use hangar_drive_protocol::api::{SEALED_NAME_MAX_PADDED, SEALED_NAME_MIN_PADDED};
        assert_eq!(Some(SEALED_NAME_MIN_PADDED as u64), padme(8 + 1));
        assert_eq!(
            Some(SEALED_NAME_MAX_PADDED as u64),
            padme(8 + MAX_DEVICE_NAME_LEN as u64)
        );
        let secret = PairingSecret::generate(&mut OsEntropy).unwrap();
        let b = dev(2);
        let mut sizes = std::collections::BTreeSet::new();
        for len in 1..=MAX_DEVICE_NAME_LEN {
            let name = "a".repeat(len);
            let request = secret
                .request(&b.identity, &ACCOUNT, b.id, &name, &mut OsEntropy)
                .unwrap();
            assert_eq!(
                request.sealed_name.as_bytes().len(),
                SEALED_NAME_OVERHEAD + padme(8 + len as u64).unwrap() as usize
            );
            assert_eq!(request.validate(), Ok(()));
            assert_eq!(
                secret.verify_request(&ACCOUNT, &request).unwrap().name,
                name
            );
            sizes.insert(request.sealed_name.as_bytes().len());
        }
        assert!(sizes.len() < 70, "{}", sizes.len());
    }

    #[test]
    fn request_and_verify() {
        let secret = PairingSecret::generate(&mut OsEntropy).unwrap();
        let b = dev(2);
        let request = secret
            .request(&b.identity, &ACCOUNT, b.id, "Laptop", &mut OsEntropy)
            .unwrap();
        assert_eq!(request.validate(), Ok(()));
        let verified = secret.verify_request(&ACCOUNT, &request).unwrap();
        assert_eq!(verified.keys, b.identity.public_keys());
        assert_eq!(verified.name, "Laptop");
        // The name is not in the request in the clear.
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("Laptop"), "{json}");
        assert!(!request
            .sealed_name
            .as_bytes()
            .windows(6)
            .any(|w| w == b"Laptop"));

        // Another secret (the server guessing), another account, a changed field.
        let other = PairingSecret::generate(&mut OsEntropy).unwrap();
        assert_eq!(
            other.verify_request(&ACCOUNT, &request),
            Err(PairingError::Tag)
        );
        assert_eq!(
            secret.verify_request(&AccountId::from_bytes([1; 16]), &request),
            Err(PairingError::Tag)
        );
        let mut renamed = request.clone();
        renamed.sealed_name.0[30] ^= 1;
        assert_eq!(
            secret.verify_request(&ACCOUNT, &renamed),
            Err(PairingError::Tag)
        );
        // The name of another request of the same offer (the tag made to match by whoever holds
        // P) does not open for this device: the device ID is the name's associated data.
        let c = dev(3);
        let foreign = secret
            .request(&c.identity, &ACCOUNT, c.id, "Server", &mut OsEntropy)
            .unwrap();
        assert_eq!(
            secret.open_name(&ACCOUNT, &b.id, foreign.sealed_name.as_bytes()),
            Err(PairingError::Name)
        );
        assert_eq!(
            other.open_name(&ACCOUNT, &b.id, request.sealed_name.as_bytes()),
            Err(PairingError::Name)
        );
        assert_eq!(
            secret
                .open_name(&ACCOUNT, &b.id, request.sealed_name.as_bytes())
                .as_deref(),
            Ok("Laptop")
        );
        let mut swapped = request.clone();
        swapped.kem = dev(3).identity.public_keys().kem;
        assert_eq!(
            secret.verify_request(&ACCOUNT, &swapped),
            Err(PairingError::Tag)
        );
        let mut short = request.clone();
        short.tag = Blob(request.tag.0[..31].to_vec());
        assert_eq!(
            secret.verify_request(&ACCOUNT, &short),
            Err(PairingError::Tag)
        );
        for bad in ["a\nb", "", "Lap\u{202e}pot", "a\u{2028}b", "a\u{feff}"] {
            assert_eq!(
                secret
                    .request(&b.identity, &ACCOUNT, b.id, bad, &mut OsEntropy)
                    .unwrap_err(),
                PairingError::Name,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_valid_tag_with_a_bad_proof_is_refused() {
        let secret = PairingSecret::generate(&mut OsEntropy).unwrap();
        let b = dev(2);
        let keys = b.identity.public_keys();
        let proof = b.identity.prove(&ACCOUNT, &b.id, true);
        let sealed_name = secret
            .seal_name(&ACCOUNT, &b.id, "Laptop", &mut OsEntropy)
            .unwrap();
        let tag = secret
            .tag(&ACCOUNT, &b.id, &keys, &proof, &sealed_name)
            .unwrap();
        let request = PairingRequest {
            device: b.id,
            sign: keys.sign,
            kem: keys.kem,
            proof,
            sealed_name: Blob(sealed_name),
            tag: Blob(tag.to_vec()),
        };
        assert_eq!(
            secret.verify_request(&ACCOUNT, &request),
            Err(PairingError::Keys)
        );
    }

    #[test]
    fn a_sealed_name_that_is_not_a_valid_name_is_refused() {
        // A request with a valid tag whose sealed name is no valid name (made by someone who
        // holds P but not the app): refused before the person is asked.
        let secret = PairingSecret::generate(&mut OsEntropy).unwrap();
        let b = dev(2);
        let keys = b.identity.public_keys();
        let proof = b.identity.prove(&ACCOUNT, &b.id, false);
        for bad in ["Lap\u{202e}pot", " Laptop", "a\nb"] {
            let sealed_name = secret
                .seal_name(&ACCOUNT, &b.id, bad, &mut OsEntropy)
                .unwrap();
            let tag = secret
                .tag(&ACCOUNT, &b.id, &keys, &proof, &sealed_name)
                .unwrap();
            let request = PairingRequest {
                device: b.id,
                sign: keys.sign,
                kem: keys.kem,
                proof,
                sealed_name: Blob(sealed_name),
                tag: Blob(tag.to_vec()),
            };
            assert_eq!(
                secret.verify_request(&ACCOUNT, &request),
                Err(PairingError::Name),
                "{bad:?}"
            );
        }
        // Too short to hold a name at all.
        assert_eq!(
            secret.open_name(&ACCOUNT, &b.id, &[0; SEALED_NAME_OVERHEAD]),
            Err(PairingError::Name)
        );
    }

    #[test]
    fn pairing_id_and_code() {
        let secret = PairingSecret::generate(&mut FixedEntropy::counting(0xd0, 16)).unwrap();
        let again = PairingSecret::parse(&secret.reveal()).unwrap();
        assert_eq!(again, secret);
        assert_eq!(again.pairing_id().unwrap(), secret.pairing_id().unwrap());
        // A recovery code does not parse as a pairing code (other checksum label).
        let recovery =
            crate::recovery::RecoveryCode::generate(&mut FixedEntropy::counting(0xd0, 16)).unwrap();
        assert!(PairingSecret::parse(&recovery.reveal()).is_err());
        assert_eq!(format!("{secret:?}"), "PairingSecret(..)");
    }

    // Security review, info: the offer bytes hold P, so they are written into a buffer of their
    // final size, signature included; a buffer that grew would leave copies of P behind.
    #[test]
    fn offer_buffers_are_allocated_at_their_final_size() {
        let a = dev(1);
        let state = created(&a);
        for pin in [None, Some([7; 32])] {
            let mut content = content(
                PairingSecret::generate(&mut OsEntropy).unwrap(),
                a.id,
                state.head().unwrap(),
            );
            content.spki_pin = pin;
            let body = content.body(0).unwrap();
            assert_eq!(body.capacity(), body.len(), "pin {pin:?}");
            let offer = content.sign(&a.identity).unwrap();
            let wire = offer.encode().unwrap();
            assert_eq!(wire.len(), body.len() + SIGNATURE_LEN);
            assert_eq!(wire.capacity(), wire.len(), "pin {pin:?}");
        }
    }

    #[test]
    fn offer_round_trip_and_strictness() {
        let a = dev(1);
        let head = LogHead {
            index: 3,
            hash: LogHash::from_bytes([9; 32]),
        };
        let o = signed(&a, head);
        let bytes = o.encode().unwrap();
        let back = PairingOffer::decode(&bytes).unwrap();
        assert_eq!(back, o);
        assert!(!format!("{o:?}").contains("secret"));
        let mut no_pin = o.content.clone();
        no_pin.spki_pin = None;
        let no_pin = no_pin.sign(&a.identity).unwrap();
        assert_eq!(
            PairingOffer::decode(&no_pin.encode().unwrap()).unwrap(),
            no_pin
        );
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(PairingOffer::decode(&longer).is_err());
        for cut in 0..bytes.len() {
            assert!(PairingOffer::decode(&bytes[..cut]).is_err());
        }
        let mut plain = o.content.clone();
        plain.server_url = Url::parse("http://drive.example/").unwrap();
        assert_eq!(plain.sign(&a.identity).unwrap_err(), PairingError::Url);
        assert_eq!(o.check_fresh(1_000), Ok(()));
        assert_eq!(
            o.check_fresh(1_000 + OFFER_LIFETIME_MS),
            Err(PairingError::Expired)
        );
        // A URL in another spelling than the parser's is refused in an offer.
        let canonical = b"https://drive.example/";
        let at = bytes
            .windows(canonical.len())
            .position(|w| w == canonical)
            .unwrap();
        let mut other_spelling = bytes[..at - 4].to_vec();
        let text = b"https://DRIVE.example/";
        other_spelling.extend_from_slice(&(text.len() as u32).to_be_bytes());
        other_spelling.extend_from_slice(text);
        other_spelling.extend_from_slice(&bytes[at + canonical.len()..]);
        assert_eq!(
            PairingOffer::decode(&other_spelling),
            Err(PairingError::Url)
        );
    }

    #[test]
    fn server_urls() {
        for (ok, parsed) in [
            ("https://drive.example", "https://drive.example/"),
            (
                "https://drive.example:8443/base",
                "https://drive.example:8443/base",
            ),
            ("http://localhost:8080", "http://localhost:8080/"),
            ("http://LOCALHOST:8080", "http://localhost:8080/"),
            ("http://127.0.0.1", "http://127.0.0.1/"),
            ("http://[::1]:8080/", "http://[::1]:8080/"),
            ("http://[0:0:0:0:0:0:0:1]/", "http://[::1]/"),
        ] {
            assert_eq!(parse_server_url(ok).unwrap().as_str(), parsed, "{ok}");
            assert!(is_allowed_server_url(ok), "{ok}");
        }
        for bad in [
            // The userinfo forms: the host is evil.example, not localhost.
            "http://localhost:80@evil.example/",
            "http://localhost@evil.example",
            "http://127.0.0.1:80@evil.example/",
            "http://[::1]@evil.example/",
            "http://user:pass@localhost/",
            "http://:pass@localhost/",
            "https://user@drive.example/",
            "https://user:secret@drive.example/",
            "http://localhost%40evil.example/",
            "http://evil.example#@localhost/",
            "http://evil.example?@localhost/",
            "http://evil.example\\@localhost/",
            "http://drive.example",
            "http://localhost.example",
            "http://localhost./",
            "http://127.0.0.2",
            "http://[::2]/",
            "http://0.0.0.0/",
            "ftp://drive.example",
            "file:///etc/hosts",
            "https://",
            "https:///path",
            "https:drive.example",
            "https:\\\\drive.example",
            "http:\\\\localhost\\",
            "https://a b",
            "https://drive.example/\n",
            " https://drive.example/",
            // A base URL has no query or fragment: the app joins API paths onto it.
            "https://drive.example/?",
            "https://drive.example/?next=evil.example",
            "https://drive.example/#",
            "https://drive.example/#evil.example",
            "http://localhost/?@evil.example",
            "drive.example",
            "javascript:alert",
        ] {
            assert!(parse_server_url(bad).is_err(), "{bad}");
            assert!(!is_allowed_server_url(bad), "{bad}");
        }
        assert!(
            parse_server_url(&format!("https://a.example/{}", "x".repeat(MAX_URL_LEN))).is_err()
        );
    }

    #[test]
    fn a_device_of_the_account_takes_url_and_pin_only_from_a_signed_offer() {
        let a = dev(1);
        let b = dev(2);
        let mut state = created(&a);
        let entry = state
            .next_entry(
                &a.identity,
                a.id,
                0,
                EntryKind::AddDevice(LogDevice::of(&b.identity, &ACCOUNT, b.id, false)),
            )
            .unwrap();
        state.apply(&entry).unwrap();
        let head = state.head().unwrap();
        let offer = signed(&a, head);
        let address = offer.server_address(&state, &SERVER).unwrap();
        assert_eq!(address.url.as_str(), "https://drive.example/");
        assert_eq!(address.spki_pin, Some([7; 32]));

        // Signed by a stranger, or by b in a's name: refused.
        let stranger = dev(9);
        let forged = content(PairingSecret::generate(&mut OsEntropy).unwrap(), a.id, head)
            .sign(&stranger.identity)
            .unwrap();
        assert_eq!(
            forged.server_address(&state, &SERVER),
            Err(PairingError::Signature)
        );
        let in_name = content(PairingSecret::generate(&mut OsEntropy).unwrap(), a.id, head)
            .sign(&b.identity)
            .unwrap();
        assert_eq!(
            in_name.server_address(&state, &SERVER),
            Err(PairingError::Signature)
        );
        // A changed pin or URL after signing.
        let mut repinned = offer.clone();
        repinned.content.spki_pin = Some([8; 32]);
        assert_eq!(
            repinned.server_address(&state, &SERVER),
            Err(PairingError::Signature)
        );
        let mut moved = offer.clone();
        moved.content.server_url = parse_server_url("https://evil.example/").unwrap();
        assert_eq!(
            PairingOffer::decode(&moved.encode().unwrap())
                .unwrap()
                .server_address(&state, &SERVER),
            Err(PairingError::Signature)
        );
        // Another server or account, a head the log does not have yet, or a forked one.
        assert_eq!(
            offer.server_address(&state, &ServerId::from_bytes([5; 16])),
            Err(PairingError::OtherAccount)
        );
        let ahead = signed(&a, LogHead { index: 9, ..head });
        assert_eq!(
            ahead.server_address(&state, &SERVER),
            Err(PairingError::AheadOfLog { index: 9 })
        );
        // Security review M2: a forged offer in the name of a known inviter with a head ahead
        // is refused for its signature, before the device would fetch any log for it.
        let forged_ahead = content(
            PairingSecret::generate(&mut OsEntropy).unwrap(),
            a.id,
            LogHead { index: 9, ..head },
        )
        .sign(&stranger.identity)
        .unwrap();
        assert_eq!(
            forged_ahead.server_address(&state, &SERVER),
            Err(PairingError::Signature)
        );
        // An inviter the log does not list yet: the log has to be fetched first.
        let newcomer = dev(7);
        let unknown = content(
            PairingSecret::generate(&mut OsEntropy).unwrap(),
            newcomer.id,
            LogHead { index: 9, ..head },
        )
        .sign(&newcomer.identity)
        .unwrap();
        assert_eq!(
            unknown.server_address(&state, &SERVER),
            Err(PairingError::AheadOfLog { index: 9 })
        );
        let forked = signed(
            &a,
            LogHead {
                index: 2,
                hash: LogHash::from_bytes([1; 32]),
            },
        );
        assert_eq!(
            forked.server_address(&state, &SERVER),
            Err(PairingError::NotJoined)
        );
        // An inviter removed since: its offer no longer moves the device.
        let by_b = signed(&b, head);
        assert!(by_b.server_address(&state, &SERVER).is_ok());
        let removal = state
            .next_entry(&a.identity, a.id, 0, EntryKind::RemoveDevice(b.id))
            .unwrap();
        state.apply(&removal).unwrap();
        assert_eq!(
            by_b.server_address(&state, &SERVER),
            Err(PairingError::Signature)
        );
    }

    #[test]
    fn the_new_device_checks_the_log_against_the_offer() {
        let a = dev(1);
        let b = dev(2);
        let mut state = created(&a);
        let anchor = state.head().unwrap();
        let offer = signed(&a, anchor);
        let entry = state
            .next_entry(
                &a.identity,
                a.id,
                0,
                EntryKind::AddDevice(LogDevice::of(&b.identity, &ACCOUNT, b.id, false)),
            )
            .unwrap();
        state.apply(&entry).unwrap();
        let keys = b.identity.public_keys();
        assert_eq!(check_joined(&state, &offer, &b.id, &keys), Ok(()));
        // A log that does not extend the offer's head.
        let forged = signed(
            &a,
            LogHead {
                index: 1,
                hash: LogHash::from_bytes([0; 32]),
            },
        );
        assert_eq!(
            check_joined(&state, &forged, &b.id, &keys),
            Err(PairingError::NotJoined)
        );
        // Other keys under this device's id.
        let other = dev(3).identity.public_keys();
        assert_eq!(
            check_joined(&state, &offer, &b.id, &other),
            Err(PairingError::NotJoined)
        );
        // Not listed.
        assert_eq!(
            check_joined(&state, &offer, &DeviceId::from_bytes([9; 16]), &keys),
            Err(PairingError::NotJoined)
        );
        // Listed before the anchor (an old entry shown again) does not count as this pairing.
        let at_anchor = signed(&a, state.head().unwrap());
        assert_eq!(
            check_joined(&state, &at_anchor, &b.id, &keys),
            Err(PairingError::NotJoined)
        );
        // An offer whose signature does not come from the inviter the log lists.
        let mut unsigned = offer.clone();
        unsigned.signature = Signature::from_bytes([0; 64]);
        assert_eq!(
            check_joined(&state, &unsigned, &b.id, &keys),
            Err(PairingError::Signature)
        );
    }
}
