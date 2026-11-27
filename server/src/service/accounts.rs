//! Invites and accounts (ADR 0001, section 6, "Accounts"): the operator creates a single-use,
//! expiring invite with the admin CLI; the server keeps only its SHA-256. An account is created
//! with an invite and the device log's first entry, which the same verifier as on the devices
//! checks.

use hangar_drive_crypto::devicelog::{AccountState, LogEntry};
use hangar_drive_crypto::{Entropy, OsEntropy};
use hangar_drive_protocol::api::{
    CreateAccountRequest, CreateAccountResponse, ErrorCode, FeedChange,
};
use hangar_drive_protocol::ids::{InviteToken, ServerId};

use crate::app::{account_by_id, sha256, App};
use crate::db::{begin_write, i64_of, Db};
use crate::error::{ApiError, ApiResult};
use crate::service::feed;

const SERVER_ID_KEY: &str = "server_id";
const DAY_MS: u64 = 86_400_000;
/// Longest invite lifetime the CLI accepts.
pub const MAX_INVITE_DAYS: u32 = 90;

/// The server's ID, made with 16 random bytes at the first start and kept for good: clients pin
/// it, and session proofs and server key numbers are bound to it.
pub async fn ensure_server_id(db: &Db) -> Result<ServerId, sqlx::Error> {
    let mut fresh = [0u8; 16];
    OsEntropy
        .fill(&mut fresh)
        .map_err(|_| sqlx::Error::Protocol("no randomness for the server ID".into()))?;
    sqlx::query("INSERT OR IGNORE INTO server_meta (key, value) VALUES (?, ?)")
        .bind(SERVER_ID_KEY)
        .bind(fresh.as_slice())
        .execute(db)
        .await?;
    let stored: Vec<u8> = sqlx::query_scalar("SELECT value FROM server_meta WHERE key = ?")
        .bind(SERVER_ID_KEY)
        .fetch_one(db)
        .await?;
    ServerId::from_slice(&stored)
        .ok_or_else(|| sqlx::Error::Protocol("stored server ID has the wrong length".into()))
}

/// Creates an invite valid for `days` days and returns it with its expiry. The token is shown
/// once; the database holds only its hash.
pub async fn create_invite(
    db: &Db,
    now_ms: u64,
    days: u32,
) -> Result<(InviteToken, u64), sqlx::Error> {
    let mut bytes = [0u8; 16];
    OsEntropy
        .fill(&mut bytes)
        .map_err(|_| sqlx::Error::Protocol("no randomness for the invite".into()))?;
    let token = InviteToken::from_bytes(bytes);
    let expires_ms = now_ms.saturating_add(u64::from(days.clamp(1, MAX_INVITE_DAYS)) * DAY_MS);
    sqlx::query("INSERT INTO invites (token_hash, created_ms, expires_ms) VALUES (?, ?, ?)")
        .bind(sha256(token.expose()).as_slice())
        .bind(i64_of(now_ms))
        .bind(i64_of(expires_ms))
        .execute(db)
        .await?;
    Ok((token, expires_ms))
}

/// Where the hash of the last invite made by [`first_start_invite`] is kept.
const FIRST_INVITE_KEY: &str = "first_start_invite";
/// Lifetime of the invite a fresh server prints at start.
pub const FIRST_INVITE_DAYS: u32 = 7;

/// The invite a server without any account prints in its log at start, so an operator whose
/// container host has no terminal (a NAS) can still create the first account. Each start
/// replaces the previous one if it is still unused, so only the newest printed link works; once
/// an account exists, nothing is created and the marker goes away.
pub async fn first_start_invite(
    db: &Db,
    now_ms: u64,
) -> Result<Option<(InviteToken, u64)>, sqlx::Error> {
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(db)
        .await?;
    let previous: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM server_meta WHERE key = ?")
            .bind(FIRST_INVITE_KEY)
            .fetch_optional(db)
            .await?;
    if let Some(hash) = &previous {
        // An unused earlier link was only ever shown in an older log: retire it.
        sqlx::query("DELETE FROM invites WHERE token_hash = ? AND used_ms IS NULL")
            .bind(hash.as_slice())
            .execute(db)
            .await?;
    }
    if accounts > 0 {
        if previous.is_some() {
            sqlx::query("DELETE FROM server_meta WHERE key = ?")
                .bind(FIRST_INVITE_KEY)
                .execute(db)
                .await?;
        }
        return Ok(None);
    }
    let (token, expires_ms) = create_invite(db, now_ms, FIRST_INVITE_DAYS).await?;
    sqlx::query("INSERT OR REPLACE INTO server_meta (key, value) VALUES (?, ?)")
        .bind(FIRST_INVITE_KEY)
        .bind(sha256(token.expose()).as_slice())
        .execute(db)
        .await?;
    Ok(Some((token, expires_ms)))
}

/// `POST /accounts`.
/// Whether `request` repeats a creation that went through but whose answer the device never got
/// (finding E2E-1: a retry from the same device must carry on): its invite is used and its
/// account exists with exactly this signed entry 1. Only the device that made the entry can send
/// it, and the answer is the server ID, which the challenge tells anyone.
async fn is_repeat(
    tx: &mut sqlx::SqliteConnection,
    request: &CreateAccountRequest,
) -> ApiResult<bool> {
    let used: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM invites WHERE token_hash = ? AND used_ms IS NOT NULL")
            .bind(sha256(request.invite.expose()).as_slice())
            .fetch_optional(&mut *tx)
            .await?;
    if used.is_none() {
        return Ok(false);
    }
    let first: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT e.entry FROM log_entries e JOIN accounts a ON a.pk = e.account_pk \
         WHERE a.id = ? AND e.idx = 1",
    )
    .bind(request.account.as_bytes().as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    Ok(first.as_deref() == Some(request.genesis.as_bytes()))
}

pub async fn create_account(
    app: &App,
    request: CreateAccountRequest,
) -> ApiResult<CreateAccountResponse> {
    let now = app.now_ms();
    let genesis = request.genesis.as_bytes();
    let issuer = LogEntry::decode(genesis)
        .map_err(|_| ApiError::new(ErrorCode::LogEntryRefused))?
        .issuer;
    let mut state = AccountState::new(request.account);
    state
        .admit_genesis(genesis, &issuer)
        .map_err(|_| ApiError::new(ErrorCode::LogEntryRefused))?;

    // The invite first, then the account ID (finding L2): without a valid invite nobody learns
    // whether an account ID exists. A taken ID rolls the transaction back, so the invite is not
    // used up by it.
    let mut tx = begin_write(&app.db).await?;
    let used = sqlx::query(
        "UPDATE invites SET used_ms = ? WHERE token_hash = ? AND used_ms IS NULL AND expires_ms > ?",
    )
    .bind(i64_of(now))
    .bind(sha256(request.invite.expose()).as_slice())
    .bind(i64_of(now))
    .execute(&mut *tx)
    .await?;
    if used.rows_affected() != 1 {
        if is_repeat(&mut tx, &request).await? {
            return Ok(CreateAccountResponse {
                server: app.server_id,
            });
        }
        return Err(ErrorCode::InviteInvalid.into());
    }
    if account_by_id(&mut tx, &request.account).await?.is_some() {
        return Err(ErrorCode::AlreadyExists.into());
    }
    let pk: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (id, created_ms, log_length) VALUES (?, ?, 1) RETURNING pk",
    )
    .bind(request.account.as_bytes().as_slice())
    .bind(i64_of(now))
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO log_entries (account_pk, idx, entry) VALUES (?, 1, ?)")
        .bind(pk)
        .bind(genesis)
        .execute(&mut *tx)
        .await?;
    let pushed = feed::push(&mut tx, pk, &FeedChange::DeviceLog { length: 1 }).await?;
    tx.commit().await?;
    app.states.put(pk, std::sync::Arc::new(state));
    pushed.notify(app);
    tracing::info!(account = %request.account, "account created");
    Ok(CreateAccountResponse {
        server: app.server_id,
    })
}
