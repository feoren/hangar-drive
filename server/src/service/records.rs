//! Sealed account records (ADR 0001, section 3, "Record freshness"). The server cannot open
//! them; it checks what the clear header lets it check before it stores a new version:
//!
//! - the version is exactly the stored one plus one (compare and swap), and the header names
//!   the same version, so two devices cannot both write one version;
//! - the sender in the header is the session's device, a current regular device of the
//!   verified log ("current sender": a removed device's record is refused even with a valid
//!   signature from before its removal);
//! - the header's epoch is the log's current epoch and its log head is in the server's log;
//! - the sender's signature over the record as this key (finding L3,
//!   `verify_record_signature`): the server cannot decrypt, but it can refuse bytes that no
//!   device of the account signed, so a session alone cannot store garbage under a record;
//! - the account's record bytes stay within the record cap R (finding L3), which the disk
//!   bound counts.
//!
//! Devices verify signature, seal and the replay guard themselves.

use hangar_drive_crypto::record::{record_header, verify_record_signature, MAX_RECORD_LEN};
use hangar_drive_protocol::api::{ErrorCode, FeedChange, RecordKey, RecordPut, RecordResponse};
use hangar_drive_protocol::ids::Blob;

use crate::app::{account_by_pk, App};
use crate::db::{begin_write, i64_of, u64_of};
use crate::error::ApiResult;
use crate::service::feed;
use crate::service::sessions::Session;

/// Records one account may hold at most (one `folder-keys` per folder plus two).
pub const MAX_RECORDS_PER_ACCOUNT: i64 = 4096;
/// The largest sealed record.
pub const MAX_RECORD_BYTES: usize = MAX_RECORD_LEN;

fn folder_bytes(key: &RecordKey) -> Vec<u8> {
    key.id_bytes()
}

pub async fn get(app: &App, session: &Session, key: RecordKey) -> ApiResult<RecordResponse> {
    let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT version, data FROM records WHERE account_pk = ? AND kind = ? AND folder = ?",
    )
    .bind(session.account_pk)
    .bind(key.kind.label())
    .bind(folder_bytes(&key))
    .fetch_optional(&app.db)
    .await?;
    let (version, data) = row.ok_or(ErrorCode::NotFound)?;
    Ok(RecordResponse {
        key,
        version: u64_of(version),
        data: Blob(data),
    })
}

pub async fn put(
    app: &App,
    session: &Session,
    key: RecordKey,
    put: RecordPut,
) -> ApiResult<RecordResponse> {
    let data = put.data.as_bytes();
    if data.len() > MAX_RECORD_BYTES {
        return Err(ErrorCode::TooLarge.into());
    }
    let header = record_header(data).ok_or(ErrorCode::BadRequest)?;
    if put.version == 0 || header.version != put.version {
        return Err(ErrorCode::BadRequest.into());
    }
    if header.sender != session.device {
        return Err(ErrorCode::Forbidden.into());
    }
    let mut tx = begin_write(&app.db).await?;
    let account = account_by_pk(&mut tx, session.account_pk)
        .await?
        .ok_or(ErrorCode::NotFound)?;
    let state = app
        .states
        .get(&mut tx, account.pk, account.id, account.log_length)
        .await?;
    let sender_ok = state
        .device(&session.device)
        .is_some_and(|d| d.is_current() && !d.recovery);
    if !sender_ok {
        return Err(ErrorCode::Forbidden.into());
    }
    let epoch_ok = state
        .current_epoch()
        .is_some_and(|e| e.epoch == header.epoch && header.head.index >= e.index);
    if !epoch_ok || !state.contains(&header.head) {
        return Err(ErrorCode::BadRequest.into());
    }
    if verify_record_signature(&state, &key, data).is_err() {
        return Err(ErrorCode::BadRequest.into());
    }
    let stored: Option<(i64, i64)> = sqlx::query_as(
        "SELECT version, LENGTH(data) FROM records WHERE account_pk = ? AND kind = ? AND folder = ?",
    )
    .bind(account.pk)
    .bind(key.kind.label())
    .bind(folder_bytes(&key))
    .fetch_optional(&mut *tx)
    .await?;
    let expected = stored.map_or(1, |(v, _)| u64_of(v) + 1);
    if put.version != expected {
        return Err(ErrorCode::RecordVersion.into());
    }
    let used: i64 = sqlx::query_scalar("SELECT record_bytes FROM accounts WHERE pk = ?")
        .bind(account.pk)
        .fetch_one(&mut *tx)
        .await?;
    let old_len = stored.map_or(0, |(_, len)| u64_of(len));
    let new_total = u64_of(used)
        .saturating_sub(old_len)
        .saturating_add(data.len() as u64);
    if new_total > app.limits.record_cap && new_total > u64_of(used) {
        return Err(ErrorCode::QuotaExceeded.into());
    }
    if stored.is_none() {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE account_pk = ?")
            .bind(account.pk)
            .fetch_one(&mut *tx)
            .await?;
        if count >= MAX_RECORDS_PER_ACCOUNT {
            return Err(ErrorCode::QuotaExceeded.into());
        }
    }
    sqlx::query(
        "INSERT INTO records (account_pk, kind, folder, version, data) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT (account_pk, kind, folder) DO UPDATE SET version = excluded.version, data = excluded.data",
    )
    .bind(account.pk)
    .bind(key.kind.label())
    .bind(folder_bytes(&key))
    .bind(i64_of(put.version))
    .bind(data)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE accounts SET record_bytes = ? WHERE pk = ?")
        .bind(i64_of(new_total))
        .bind(account.pk)
        .execute(&mut *tx)
        .await?;
    let pushed = feed::push(
        &mut tx,
        account.pk,
        &FeedChange::Record {
            key,
            version: put.version,
        },
    )
    .await?;
    tx.commit().await?;
    pushed.notify(app);
    Ok(RecordResponse {
        key,
        version: put.version,
        data: put.data,
    })
}
