//! Device sign-in: an Ed25519 proof over a fresh server challenge, bound to the server, the
//! account and the protocol version (ADR 0001, section 6). Built after the connection proof of
//! the sister project's `hangar-team-crypto` (`src/possession.rs`, MIT, same owner).
//!
//! ```text
//! statement = field("hangar-drive/v1/session-proof") || field(server id) || field(server url)
//!             || field(account) || field(device) || field(sign public key)
//!             || field(challenge, 32 bytes) || field(protocol version, u16)
//! signature = Ed25519 with the device's sign key over statement
//! ```
//!
//! The label is used by no other signature, so neither a log entry, a commit, a record nor a
//! proof of possession verifies as a session proof. The server ID means a proof is valid for one
//! server only, and the server URL (the base URL the device connects to, [`base_url`]) that it is
//! valid for one address only: a host that relays a sign-in to the real server under the real
//! server ID (a recovery sheet or link with the real server ID and a foreign URL) holds a proof
//! for its own address, which the real server refuses against its own public URL; the challenge, new with every request and single use, makes a seen proof
//! worthless (replay); the key is part of the statement, so a signature cannot be presented
//! under another key. There is no TLS channel binding, because a reverse proxy terminates TLS.
//!
//! The server checks the proof with [`verify_session`] against the key the verified account log
//! lists now: a removed device's proof fails at once, with [`SessionError::Removed`] when it
//! verifies with the key the log last listed for that device. Only a holder of that key can make
//! such a proof, so the removed device itself learns that it was removed (and forgets the
//! account) while nobody else can ask the server whether a device was removed: every other
//! failure is [`SessionError::Signature`] or [`SessionError::UnknownDevice`]. Recovery devices
//! may sign in (they fetch their wrapped keys); the server then limits the session with
//! `hangar_drive_protocol::api::SessionScope::for_device(record.recovery)`: the log, the own
//! wrapped keys and one append that adds a regular device.

use hangar_drive_protocol::ids::{AccountId, Challenge, DeviceId, PublicKey, ServerId, Signature};
use hangar_drive_protocol::PROTOCOL_VERSION;
use thiserror::Error;
use url::Url;

use crate::devicelog::{AccountState, DeviceRecord};
use crate::encoding::framed;
use crate::identity::{verify, DeviceIdentity};

const LABEL_SESSION_PROOF: &[u8] = b"hangar-drive/v1/session-proof";

/// Why a session proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SessionError {
    /// The log does not list the device at all.
    #[error("the device is not a device of the account")]
    UnknownDevice,
    /// The proof verifies with the key the log last listed for the device, but the log removed
    /// the device.
    #[error("the device was removed from the account")]
    Removed,
    /// The signature does not verify for this server, account, device, challenge and version.
    #[error("the session proof does not verify")]
    Signature,
}

/// The server URL as the statement carries it: the URL parser's serialization with a path that
/// ends in `/`, exactly the base URL the server is configured with (`HANGAR_DRIVE_PUBLIC_URL`).
pub fn base_url(url: &Url) -> String {
    let mut base = url.as_str().to_owned();
    if !base.ends_with('/') {
        base.push('/');
    }
    base
}

fn statement(
    server: &ServerId,
    server_url: &str,
    account: &AccountId,
    device: &DeviceId,
    sign: &PublicKey,
    challenge: &Challenge,
    protocol_version: u16,
) -> Vec<u8> {
    framed(&[
        LABEL_SESSION_PROOF,
        server.as_bytes(),
        server_url.as_bytes(),
        account.as_bytes(),
        device.as_bytes(),
        sign.as_bytes(),
        challenge.as_bytes(),
        &protocol_version.to_be_bytes(),
    ])
}

impl DeviceIdentity {
    /// The proof answering `challenge` of `server`, reached at `server_url` ([`base_url`]), for
    /// this device as `device` of `account`, in this crate's protocol version.
    pub fn prove_session(
        &self,
        server: &ServerId,
        server_url: &str,
        account: &AccountId,
        device: &DeviceId,
        challenge: &Challenge,
    ) -> Signature {
        let sign = self.public_keys().sign;
        Signature::from_bytes(self.sign(&statement(
            server,
            server_url,
            account,
            device,
            &sign,
            challenge,
            PROTOCOL_VERSION,
        )))
    }
}

/// Server side: checks a session proof against the verified log `state` and returns the
/// device it signs in. `server_url` is the server's own public base URL ([`base_url`]), so a
/// proof made for another address fails. The caller has already checked that the challenge is
/// its own, fresh and unused, and consumes it whatever the result. The signature is checked
/// before the removal, so [`SessionError::Removed`] answers only a proof made with the removed
/// device's own key (module docs).
pub fn verify_session<'a>(
    state: &'a AccountState,
    server: &ServerId,
    server_url: &str,
    device: &DeviceId,
    challenge: &Challenge,
    signature: &Signature,
) -> Result<&'a DeviceRecord, SessionError> {
    let record = state.device(device).ok_or(SessionError::UnknownDevice)?;
    let message = statement(
        server,
        server_url,
        state.account(),
        device,
        &record.keys.sign,
        challenge,
        PROTOCOL_VERSION,
    );
    if !verify(&record.keys.sign, &message, signature.as_bytes()) {
        return Err(SessionError::Signature);
    }
    if !record.is_current() {
        return Err(SessionError::Removed);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devicelog::tests::{created, dev, ACCOUNT};
    use crate::devicelog::{EntryKind, LogDevice};

    const SERVER: ServerId = ServerId::from_bytes([4; 16]);
    const URL: &str = "https://drive.example/";

    #[test]
    fn proof_binds_server_device_and_challenge() {
        let a = dev(1);
        let state = created(&a);
        let challenge = Challenge::from_bytes([5; 32]);
        let proof = a
            .identity
            .prove_session(&SERVER, URL, &ACCOUNT, &a.id, &challenge);
        assert_eq!(
            verify_session(&state, &SERVER, URL, &a.id, &challenge, &proof).map(|d| d.id),
            Ok(a.id)
        );
        assert_eq!(
            verify_session(
                &state,
                &ServerId::from_bytes([5; 16]),
                URL,
                &a.id,
                &challenge,
                &proof
            ),
            Err(SessionError::Signature)
        );
        assert_eq!(
            verify_session(
                &state,
                &SERVER,
                URL,
                &a.id,
                &Challenge::from_bytes([6; 32]),
                &proof
            ),
            Err(SessionError::Signature)
        );
        assert_eq!(
            verify_session(
                &state,
                &SERVER,
                URL,
                &DeviceId::from_bytes([9; 16]),
                &challenge,
                &proof
            ),
            Err(SessionError::UnknownDevice)
        );
        // A proof for another address (a relay under the real server ID) fails at the real one.
        assert_eq!(
            verify_session(
                &state,
                &SERVER,
                "https://drive.example.evil/",
                &a.id,
                &challenge,
                &proof
            ),
            Err(SessionError::Signature)
        );
        // A proof of possession is no session proof.
        let possession = a.identity.prove(&ACCOUNT, &a.id, false);
        assert_eq!(
            verify_session(&state, &SERVER, URL, &a.id, &challenge, &possession),
            Err(SessionError::Signature)
        );
        // Another account's proof.
        let other = a.identity.prove_session(
            &SERVER,
            URL,
            &AccountId::from_bytes([1; 16]),
            &a.id,
            &challenge,
        );
        assert_eq!(
            verify_session(&state, &SERVER, URL, &a.id, &challenge, &other),
            Err(SessionError::Signature)
        );
    }

    #[test]
    fn the_base_url_ends_in_a_slash() {
        let url = |t: &str| Url::parse(t).unwrap();
        assert_eq!(
            base_url(&url("https://drive.example")),
            "https://drive.example/"
        );
        assert_eq!(
            base_url(&url("https://x.example/drive")),
            "https://x.example/drive/"
        );
        assert_eq!(
            base_url(&url("http://localhost:8080/")),
            "http://localhost:8080/"
        );
    }

    #[test]
    fn a_removed_device_cannot_sign_in() {
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
        let challenge = Challenge::from_bytes([5; 32]);
        let proof = b
            .identity
            .prove_session(&SERVER, URL, &ACCOUNT, &b.id, &challenge);
        assert!(verify_session(&state, &SERVER, URL, &b.id, &challenge, &proof).is_ok());
        let entry = state
            .next_entry(&a.identity, a.id, 0, EntryKind::RemoveDevice(b.id))
            .unwrap();
        state.apply(&entry).unwrap();
        assert_eq!(
            verify_session(&state, &SERVER, URL, &b.id, &challenge, &proof),
            Err(SessionError::Removed)
        );
        // Only a proof with the removed device's own key learns that: another key, another
        // challenge or another address get the plain refusal, as for any bad proof.
        let forged = a
            .identity
            .prove_session(&SERVER, URL, &ACCOUNT, &b.id, &challenge);
        assert_eq!(
            verify_session(&state, &SERVER, URL, &b.id, &challenge, &forged),
            Err(SessionError::Signature)
        );
        assert_eq!(
            verify_session(
                &state,
                &SERVER,
                URL,
                &b.id,
                &Challenge::from_bytes([6; 32]),
                &proof
            ),
            Err(SessionError::Signature)
        );
        assert_eq!(
            verify_session(
                &state,
                &SERVER,
                "https://drive.example.evil/",
                &b.id,
                &challenge,
                &proof
            ),
            Err(SessionError::Signature)
        );
    }
}
