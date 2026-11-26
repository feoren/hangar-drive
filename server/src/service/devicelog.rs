//! The device log on the server (ADR 0001, section 4): pages of entries, the atomic append that
//! `AccountState::admit_batch` and `append_wraps_fit` check, and each device's wrapped epoch
//! secrets. A removal ends the removed devices' sessions and deletes their uncommitted uploads in
//! the same transaction.

use std::sync::Arc;

use hangar_drive_crypto::devicelog::BatchShape;
use hangar_drive_crypto::epoch::append_wraps_fit;
use hangar_drive_protocol::api::{
    ErrorCode, FeedChange, LogAppendRequest, LogAppendResponse, LogPage, WrappedKeyResponse,
    MAX_LOG_PAGE,
};
use hangar_drive_protocol::ids::{Blob, Epoch};

use crate::app::{account_by_pk, App, AppState};
use crate::db::{begin_write, i64_of, u64_of};
use crate::error::{ApiError, ApiResult};
use crate::service::sessions::Session;
use crate::service::{feed, objects, retention};

/// `GET /account/log?after=N`.
pub async fn page(app: &App, session: &Session, after: u64) -> ApiResult<LogPage> {
    let mut conn = app.db.acquire().await?;
    let account = account_by_pk(&mut conn, session.account_pk)
        .await?
        .ok_or(ErrorCode::NotFound)?;
    let entries: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT entry FROM log_entries WHERE account_pk = ? AND idx > ? ORDER BY idx LIMIT ?",
    )
    .bind(session.account_pk)
    .bind(i64_of(after))
    .bind(i64_of(MAX_LOG_PAGE as u64))
    .fetch_all(&mut *conn)
    .await?;
    Ok(LogPage {
        first_index: after.saturating_add(1),
        entries: entries.into_iter().map(Blob).collect(),
        length: account.log_length,
    })
}

/// `POST /account/log`.
pub async fn append(
    app: &AppState,
    session: &Session,
    request: LogAppendRequest,
) -> ApiResult<LogAppendResponse> {
    request
        .validate()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    session
        .scope
        .check_append(&request)
        .map_err(|_| ApiError::new(ErrorCode::Forbidden))?;
    let mut tx = begin_write(&app.db).await?;
    let account = account_by_pk(&mut tx, session.account_pk)
        .await?
        .ok_or(ErrorCode::NotFound)?;
    let state = app
        .states
        .get(&mut tx, account.pk, account.id, account.log_length)
        .await?;
    let batch = state
        .admit_batch(
            request.entries.iter().map(|e| e.as_bytes()),
            &session.device,
        )
        .map_err(|_| ApiError::new(ErrorCode::LogEntryRefused))?;
    let wraps_fit = append_wraps_fit(
        &batch,
        request.wraps.iter().map(|w| (&w.device, w.data.as_bytes())),
        request
            .device_wrap
            .as_ref()
            .map(|w| (&w.device, w.data.as_bytes())),
    );
    if !wraps_fit {
        return Err(ErrorCode::LogEntryRefused.into());
    }
    if matches!(
        session.scope,
        hangar_drive_protocol::api::SessionScope::Recovery { .. }
    ) {
        // The one append of a recovery session, recorded in the same transaction.
        let marked =
            sqlx::query("UPDATE sessions SET appended = 1 WHERE token_hash = ? AND appended = 0")
                .bind(session.token_hash.as_slice())
                .execute(&mut *tx)
                .await?;
        if marked.rows_affected() != 1 {
            return Err(ErrorCode::Forbidden.into());
        }
    }
    let first = account.log_length + 1;
    for (offset, entry) in request.entries.iter().enumerate() {
        sqlx::query("INSERT INTO log_entries (account_pk, idx, entry) VALUES (?, ?, ?)")
            .bind(account.pk)
            .bind(i64_of(first + offset as u64))
            .bind(entry.as_bytes())
            .execute(&mut *tx)
            .await?;
    }
    let length = batch.state.len();
    sqlx::query("UPDATE accounts SET log_length = ? WHERE pk = ?")
        .bind(i64_of(length))
        .bind(account.pk)
        .execute(&mut *tx)
        .await?;
    let mut pushed = Vec::new();
    let mut dropped_files = Vec::new();
    match &batch.shape {
        BatchShape::Rotation { removed, epoch } => {
            for wrap in &request.wraps {
                store_wrap(
                    &mut tx,
                    account.pk,
                    *epoch,
                    wrap.device.as_bytes(),
                    wrap.data.as_bytes(),
                )
                .await?;
            }
            let now = app.now_ms();
            for device in removed {
                sqlx::query("DELETE FROM sessions WHERE account_pk = ? AND device = ?")
                    .bind(account.pk)
                    .bind(device.as_bytes().as_slice())
                    .execute(&mut *tx)
                    .await?;
                // Its uncommitted uploads go now, not 24 hours later (security review MEDIUM 3).
                let keys =
                    objects::drop_uploads_of(&mut tx, account.pk, account.id, device, now).await?;
                dropped_files.extend(keys);
            }
            pushed
                .push(feed::push(&mut tx, account.pk, &FeedChange::Epoch { epoch: *epoch }).await?);
        }
        BatchShape::AddDevice { .. } => {
            if let (Some(wrap), Some(epoch)) = (&request.device_wrap, batch.state.current_epoch()) {
                store_wrap(
                    &mut tx,
                    account.pk,
                    epoch.epoch,
                    wrap.device.as_bytes(),
                    wrap.data.as_bytes(),
                )
                .await?;
            }
        }
    }
    pushed.push(feed::push(&mut tx, account.pk, &FeedChange::DeviceLog { length }).await?);
    let head = batch
        .state
        .head()
        .ok_or_else(|| ApiError::internal(&"admitted log without head"))?;
    tx.commit().await?;
    app.states.put(account.pk, Arc::new(batch.state));
    feed::notify_all(app, &pushed);
    if !dropped_files.is_empty() {
        // In the background: a removal can drop many files, and the append is already durable.
        // Files a shutdown leaves behind have no row and go with the orphan sweep.
        let app = app.clone();
        tokio::spawn(async move { retention::remove_object_files(&app, dropped_files).await });
    }
    Ok(LogAppendResponse { head })
}

async fn store_wrap(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    epoch: Epoch,
    device: &[u8],
    data: &[u8],
) -> ApiResult<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO epoch_keys (account_pk, epoch, device, data) VALUES (?, ?, ?, ?)",
    )
    .bind(account_pk)
    .bind(i64::from(epoch.0))
    .bind(device)
    .bind(data)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `GET /account/epochs/{epoch}/key`: only the session device's own wrapped key.
pub async fn epoch_key(app: &App, session: &Session, epoch: u32) -> ApiResult<WrappedKeyResponse> {
    let data: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT data FROM epoch_keys WHERE account_pk = ? AND epoch = ? AND device = ?",
    )
    .bind(session.account_pk)
    .bind(i64::from(epoch))
    .bind(session.device.as_bytes().as_slice())
    .fetch_optional(&app.db)
    .await?;
    let data = data.ok_or(ErrorCode::NotFound)?;
    Ok(WrappedKeyResponse {
        epoch: Epoch(epoch),
        data: Blob(data),
    })
}

/// The log length, for tests and status.
pub async fn length(app: &App, account_pk: i64) -> ApiResult<u64> {
    let len: i64 = sqlx::query_scalar("SELECT log_length FROM accounts WHERE pk = ?")
        .bind(account_pk)
        .fetch_one(&app.db)
        .await?;
    Ok(u64_of(len))
}
