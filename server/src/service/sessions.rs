//! Device sign-in (ADR 0001, section 6): a challenge, the device's Ed25519 proof checked with
//! `verify_session` against the verified log, and a short-lived bearer token that the server
//! stores only as SHA-256. The session's scope comes from the log (recovery device or not) and
//! is kept with the token hash.
//!
//! **Stateless challenges** (finding M1): asking for a challenge writes nothing. The 32 bytes
//! of the protocol's challenge are `expiry (u64, ms) || nonce (8) || tag (16)`, where the tag is
//! the first 16 bytes of `HMAC-SHA-256(server secret, label || server || account || device ||
//! expiry || nonce)`. The server checks the tag and the expiry at the proof. Only a challenge
//! whose proof verified is written, to `used_challenges` until it expires, so it is accepted
//! once. A flood of challenge requests therefore costs no database write and cannot fill a
//! table, and a flood of bad proofs never reaches the database at all. The device signs the 32
//! bytes as before; the wire format is unchanged.
//!
//! Failed proofs count against [`Scope::ProofFailures`], keyed by account and device and only
//! for devices the account's log lists, so the table holds only real devices.

use hangar_drive_crypto::session::verify_session;
use hangar_drive_crypto::{Entropy, OsEntropy};
use hangar_drive_protocol::api::{
    ChallengeRequest, ChallengeResponse, ErrorCode, ProofRequest, SessionResponse, SessionScope,
};
use hangar_drive_protocol::ids::{AccountId, Challenge, DeviceId, SessionToken};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::app::{account_by_id, sha256, App};
use crate::db::{begin_write, i64_of, u64_of};
use crate::error::{ApiError, ApiResult};
use crate::http::ratelimit::Scope;

/// Seconds a challenge is valid.
pub const CHALLENGE_SECS: u32 = 60;
/// Seconds a session token is valid (ADR 0001: about an hour, renewed by a new proof).
pub const SESSION_SECS: u32 = 3600;
const CHALLENGE_LABEL: &[u8] = b"hangar-drive/v1/server-challenge";
/// Bytes of the truncated tag in a challenge.
const TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// An authenticated session.
#[derive(Debug, Clone)]
pub struct Session {
    pub account_pk: i64,
    pub account: AccountId,
    pub device: DeviceId,
    pub scope: SessionScope,
    pub token_hash: [u8; 32],
    pub expires_ms: u64,
}

/// The challenge MAC: HMAC-SHA-256 (RFC 2104, the `hmac` crate the crypto crate uses) under the
/// server secret, over length-prefixed parts, so no two different part lists give the same
/// message. `None` only if the key were refused, which HMAC never does (any key length works).
fn mac_over(key: &[u8; 32], parts: &[&[u8]]) -> Option<HmacSha256> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).ok()?;
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    Some(mac)
}

/// The MAC of a challenge: bound to this server, the account, the device, the expiry and the
/// nonce, under a label of its own.
fn challenge_mac(
    app: &App,
    account: &AccountId,
    device: &DeviceId,
    expiry: &[u8],
    nonce: &[u8],
) -> Option<HmacSha256> {
    mac_over(
        app.server_secret.expose(),
        &[
            CHALLENGE_LABEL,
            app.server_id.as_bytes(),
            account.as_bytes(),
            device.as_bytes(),
            expiry,
            nonce,
        ],
    )
}

/// `POST /session/challenge`. Answers the same for unknown accounts and devices, so the
/// endpoint tells nobody which accounts exist; the proof fails for them. Writes nothing.
pub fn challenge(app: &App, request: &ChallengeRequest) -> ApiResult<ChallengeResponse> {
    let expires = app.now_ms() + u64::from(CHALLENGE_SECS) * 1000;
    let mut nonce = [0u8; 8];
    OsEntropy
        .fill(&mut nonce)
        .map_err(|_| ApiError::internal(&"no randomness for a challenge"))?;
    let expiry = expires.to_be_bytes();
    let mac = challenge_mac(app, &request.account, &request.device, &expiry, &nonce)
        .ok_or_else(|| ApiError::internal(&"challenge key refused"))?
        .finalize()
        .into_bytes();
    // The tag is the left 16 bytes of the MAC (128 bits, RFC 2104, section 5): a forgery
    // succeeds with probability 2^-128 per try, and a challenge lives a minute.
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&expiry);
    bytes[8..16].copy_from_slice(&nonce);
    bytes[16..].copy_from_slice(&mac[..TAG_LEN]);
    Ok(ChallengeResponse {
        server: app.server_id,
        challenge: Challenge::from_bytes(bytes),
        expires_in_secs: CHALLENGE_SECS,
    })
}

/// Whether `challenge` is one this server made for the account and device and has not expired.
/// Returns its expiry. The tag is compared in constant time (`verify_truncated_left`, which
/// uses `subtle`), before the expiry is even read.
fn check_challenge(app: &App, request: &ProofRequest) -> Option<u64> {
    let bytes = request.challenge.as_bytes();
    let (expiry, rest) = bytes.split_at(8);
    let (nonce, tag) = rest.split_at(8);
    challenge_mac(app, &request.account, &request.device, expiry, nonce)?
        .verify_truncated_left(tag)
        .ok()?;
    let expires = u64::from_be_bytes(expiry.try_into().ok()?);
    let now = app.now_ms();
    (expires > now && expires <= now + u64::from(CHALLENGE_SECS) * 1000).then_some(expires)
}

fn failure_key(account: &AccountId, device: &DeviceId) -> Vec<u8> {
    [account.as_bytes().as_slice(), device.as_bytes().as_slice()].concat()
}

/// `POST /session/proof`.
pub async fn proof(app: &App, request: &ProofRequest) -> ApiResult<SessionResponse> {
    let now = app.now_ms();
    let expires_challenge = check_challenge(app, request).ok_or(ErrorCode::ChallengeInvalid)?;
    let key = failure_key(&request.account, &request.device);
    if app.limiter.exceeded(Scope::ProofFailures, &key, now / 1000) {
        return Err(ErrorCode::RateLimited.into());
    }
    let mut conn = app.db.acquire().await?;
    let Some(account) = account_by_id(&mut conn, &request.account).await? else {
        return Err(ErrorCode::ProofInvalid.into());
    };
    let state = app
        .states
        .get(&mut conn, account.pk, account.id, account.log_length)
        .await?;
    drop(conn);
    let record = match verify_session(
        &state,
        &app.server_id,
        &request.device,
        &request.challenge,
        &request.signature,
    ) {
        Ok(record) => *record,
        Err(_) => {
            if state.device(&request.device).is_some() {
                app.limiter.hit(Scope::ProofFailures, &key, now / 1000);
            }
            return Err(ErrorCode::ProofInvalid.into());
        }
    };
    let mut token = [0u8; 32];
    OsEntropy
        .fill(&mut token)
        .map_err(|_| ApiError::internal(&"no randomness for a token"))?;
    let token = SessionToken::from_bytes(token);
    let expires = now + u64::from(SESSION_SECS) * 1000;
    let mut tx = begin_write(&app.db).await?;
    sqlx::query("DELETE FROM used_challenges WHERE expires_ms <= ?")
        .bind(i64_of(now))
        .execute(&mut *tx)
        .await?;
    let fresh =
        sqlx::query("INSERT OR IGNORE INTO used_challenges (challenge, expires_ms) VALUES (?, ?)")
            .bind(request.challenge.as_bytes().as_slice())
            .bind(i64_of(expires_challenge))
            .execute(&mut *tx)
            .await?;
    if fresh.rows_affected() != 1 {
        // The same signed challenge again: a replay.
        return Err(ErrorCode::ChallengeInvalid.into());
    }
    sqlx::query(
        "INSERT INTO sessions (token_hash, account_pk, device, recovery, expires_ms) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(sha256(token.expose()).as_slice())
    .bind(account.pk)
    .bind(request.device.as_bytes().as_slice())
    .bind(i64::from(record.recovery))
    .bind(i64_of(expires))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(SessionResponse {
        token,
        expires_in_secs: SESSION_SECS,
    })
}

/// The session of a bearer token, or `unauthorized`. A device the verified log no longer lists
/// as current loses its session here even if the removal's own revocation was missed.
pub async fn authenticate(app: &App, token: &SessionToken) -> ApiResult<Session> {
    let hash = sha256(token.expose());
    let mut conn = app.db.acquire().await?;
    type Row = (i64, Vec<u8>, i64, i64, i64, Vec<u8>, i64);
    let row: Option<Row> = sqlx::query_as(
        "SELECT s.account_pk, s.device, s.recovery, s.appended, s.expires_ms, a.id, a.log_length \
         FROM sessions s JOIN accounts a ON a.pk = s.account_pk WHERE s.token_hash = ?",
    )
    .bind(hash.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some((account_pk, device, recovery, appended, expires, account, log_length)) = row else {
        return Err(ErrorCode::Unauthorized.into());
    };
    let expires_ms = u64_of(expires);
    if expires_ms <= app.now_ms() {
        return Err(ErrorCode::Unauthorized.into());
    }
    let (Some(device), Some(account)) = (
        DeviceId::from_slice(&device),
        AccountId::from_slice(&account),
    ) else {
        return Err(ApiError::internal(&"stored session with a malformed ID"));
    };
    let state = app
        .states
        .get(&mut conn, account_pk, account, u64_of(log_length))
        .await?;
    if !state.device(&device).is_some_and(|d| d.is_current()) {
        return Err(ErrorCode::Unauthorized.into());
    }
    let scope = if recovery != 0 {
        SessionScope::Recovery {
            appended: appended != 0,
        }
    } else {
        SessionScope::Device
    };
    Ok(Session {
        account_pk,
        account,
        device,
        scope,
        token_hash: hash,
        expires_ms,
    })
}

/// Whether the session still exists and has not expired (long-lived streams check it).
pub async fn still_valid(app: &App, token_hash: &[u8; 32]) -> ApiResult<bool> {
    let expires: Option<i64> =
        sqlx::query_scalar("SELECT expires_ms FROM sessions WHERE token_hash = ?")
            .bind(token_hash.as_slice())
            .fetch_optional(&app.db)
            .await?;
    Ok(expires.is_some_and(|e| u64_of(e) > app.now_ms()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn mac(key: &[u8; 32], parts: &[&[u8]]) -> HmacSha256 {
        mac_over(key, parts).unwrap()
    }

    #[test]
    fn the_mac_is_hmac_sha256_over_length_prefixed_parts() {
        // RFC 4231, test case 2, through the same crate: key "Jefe".
        let mut plain = <HmacSha256 as KeyInit>::new_from_slice(b"Jefe").unwrap();
        plain.update(b"what do ya want for nothing?");
        assert_eq!(
            hex(&plain.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Each part carries its length as a big-endian u64 in front.
        let key = [0x0bu8; 32];
        let mut framed = <HmacSha256 as KeyInit>::new_from_slice(&key).unwrap();
        framed.update(&2u64.to_be_bytes());
        framed.update(b"ab");
        framed.update(&1u64.to_be_bytes());
        framed.update(b"c");
        let expected = framed.finalize().into_bytes();
        assert_eq!(mac(&key, &[b"ab", b"c"]).finalize().into_bytes(), expected);
        // Moving a byte between parts or changing the key changes the MAC.
        assert_ne!(mac(&key, &[b"a", b"bc"]).finalize().into_bytes(), expected);
        assert_ne!(
            mac(&[0x0c; 32], &[b"ab", b"c"]).finalize().into_bytes(),
            expected
        );
    }

    #[test]
    fn the_truncated_tag_is_the_left_half_and_checked_whole() {
        let key = [7u8; 32];
        let full = mac(&key, &[b"m"]).finalize().into_bytes();
        let tag = &full[..TAG_LEN];
        assert!(mac(&key, &[b"m"]).verify_truncated_left(tag).is_ok());
        for i in 0..TAG_LEN {
            let mut bad = tag.to_vec();
            bad[i] ^= 1;
            assert!(mac(&key, &[b"m"]).verify_truncated_left(&bad).is_err());
        }
        // The right half, an empty tag or one of another key never pass.
        assert!(mac(&key, &[b"m"])
            .verify_truncated_left(&full[TAG_LEN..])
            .is_err());
        assert!(mac(&key, &[b"m"]).verify_truncated_left(&[]).is_err());
        assert!(mac(&[8u8; 32], &[b"m"]).verify_truncated_left(tag).is_err());
    }
}
