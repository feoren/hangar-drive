//! Device sign-in: an Ed25519 proof over a fresh server challenge, bound to the server, the
//! account and the protocol version (ADR 0001, section 6). Built after the connection proof of
//! the sister project's `hangar-team-crypto` (`src/possession.rs`, MIT, same owner).
//!
//! ```text
//! statement = field("hangar-drive/v1/session-proof") || field(server id) || field(account)
//!             || field(device) || field(sign public key) || field(challenge, 32 bytes)
//!             || field(protocol version, u16)
//! signature = Ed25519 with the device's sign key over statement
//! ```
//!
//! The label is used by no other signature, so neither a log entry, a commit, a record nor a
//! proof of possession verifies as a session proof. The server ID means a proof is valid for one
//! server only; the challenge, new with every request and single use, makes a seen proof
//! worthless (replay); the key is part of the statement, so a signature cannot be presented
//! under another key. There is no TLS channel binding, because a reverse proxy terminates TLS.
//!
//! The server checks the proof with [`verify_session`] against the key the verified account log
//! lists now: a removed device's proof fails at once. Recovery devices may sign in (they fetch
//! their wrapped keys); the server then limits the session with
//! `hangar_drive_protocol::api::SessionScope::for_device(record.recovery)`: the log, the own
//! wrapped keys and one append that adds a regular device.

use hangar_drive_protocol::ids::{AccountId, Challenge, DeviceId, PublicKey, ServerId, Signature};
use hangar_drive_protocol::PROTOCOL_VERSION;
use thiserror::Error;

use crate::devicelog::{AccountState, DeviceRecord};
use crate::encoding::framed;
use crate::identity::{verify, DeviceIdentity};

const LABEL_SESSION_PROOF: &[u8] = b"hangar-drive/v1/session-proof";

/// Why a session proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SessionError {
    /// The device is not a current device of the account.
    #[error("the device is not a current device of the account")]
    UnknownDevice,
    /// The signature does not verify for this server, account, device, challenge and version.
    #[error("the session proof does not verify")]
    Signature,
}

fn statement(
    server: &ServerId,
    account: &AccountId,
    device: &DeviceId,
    sign: &PublicKey,
    challenge: &Challenge,
    protocol_version: u16,
) -> Vec<u8> {
    framed(&[
        LABEL_SESSION_PROOF,
        server.as_bytes(),
        account.as_bytes(),
        device.as_bytes(),
        sign.as_bytes(),
        challenge.as_bytes(),
        &protocol_version.to_be_bytes(),
    ])
}

impl DeviceIdentity {
    /// The proof answering `challenge` of `server` for this device as `device` of `account`,
    /// in this crate's protocol version.
    pub fn prove_session(
        &self,
        server: &ServerId,
        account: &AccountId,
        device: &DeviceId,
        challenge: &Challenge,
    ) -> Signature {
        let sign = self.public_keys().sign;
        Signature::from_bytes(self.sign(&statement(
            server,
            account,
            device,
            &sign,
            challenge,
            PROTOCOL_VERSION,
        )))
    }
}

/// Server side: checks a session proof against the verified log `state` and returns the
/// device it signs in. The caller has already checked that the challenge is its own, fresh
/// and unused, and consumes it whatever the result.
pub fn verify_session<'a>(
    state: &'a AccountState,
    server: &ServerId,
    device: &DeviceId,
    challenge: &Challenge,
    signature: &Signature,
) -> Result<&'a DeviceRecord, SessionError> {
    let record = state
        .device(device)
        .filter(|d| d.is_current())
        .ok_or(SessionError::UnknownDevice)?;
    let message = statement(
        server,
        state.account(),
        device,
        &record.keys.sign,
        challenge,
        PROTOCOL_VERSION,
    );
    if !verify(&record.keys.sign, &message, signature.as_bytes()) {
        return Err(SessionError::Signature);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devicelog::tests::{created, dev, ACCOUNT};
    use crate::devicelog::{EntryKind, LogDevice};

    const SERVER: ServerId = ServerId::from_bytes([4; 16]);

    #[test]
    fn proof_binds_server_device_and_challenge() {
        let a = dev(1);
        let state = created(&a);
        let challenge = Challenge::from_bytes([5; 32]);
        let proof = a
            .identity
            .prove_session(&SERVER, &ACCOUNT, &a.id, &challenge);
        assert_eq!(
            verify_session(&state, &SERVER, &a.id, &challenge, &proof).map(|d| d.id),
            Ok(a.id)
        );
        assert_eq!(
            verify_session(
                &state,
                &ServerId::from_bytes([5; 16]),
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
                &DeviceId::from_bytes([9; 16]),
                &challenge,
                &proof
            ),
            Err(SessionError::UnknownDevice)
        );
        // A proof of possession is no session proof.
        let possession = a.identity.prove(&ACCOUNT, &a.id, false);
        assert_eq!(
            verify_session(&state, &SERVER, &a.id, &challenge, &possession),
            Err(SessionError::Signature)
        );
        // Another account's proof.
        let other =
            a.identity
                .prove_session(&SERVER, &AccountId::from_bytes([1; 16]), &a.id, &challenge);
        assert_eq!(
            verify_session(&state, &SERVER, &a.id, &challenge, &other),
            Err(SessionError::Signature)
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
            .prove_session(&SERVER, &ACCOUNT, &b.id, &challenge);
        assert!(verify_session(&state, &SERVER, &b.id, &challenge, &proof).is_ok());
        let entry = state
            .next_entry(&a.identity, a.id, 0, EntryKind::RemoveDevice(b.id))
            .unwrap();
        state.apply(&entry).unwrap();
        assert_eq!(
            verify_session(&state, &SERVER, &b.id, &challenge, &proof),
            Err(SessionError::UnknownDevice)
        );
    }
}
