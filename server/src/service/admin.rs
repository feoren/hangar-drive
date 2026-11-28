//! What the admin CLI does besides invites: status, immediate purges and lifting pins
//! (ADR 0001, section 5: "Immediate purges go only through a server CLI"; the operator can lift
//! a garbage pin). Nothing here is reachable over HTTP.

use hangar_drive_protocol::api::FeedChange;
use hangar_drive_protocol::ids::{AccountId, CommitId, FolderId};

use crate::app::{account_by_id, App};
use crate::db::{begin_write, i64_of, u64_of};
use crate::error::{ApiError, ApiResult};
use crate::service::feed;
use crate::service::retention::{self, Mode, Outcome};
use crate::service::usage;

/// One account in the status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStatus {
    pub id: AccountId,
    pub devices: u64,
    pub folders: u64,
    pub retired_folders: u64,
    pub live_bytes: u64,
    pub stored_bytes: u64,
    pub pins: u64,
    pub warnings: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub accounts: Vec<AccountStatus>,
    pub open_invites: u64,
    pub disk_available: Option<u64>,
    pub disk_reserve: u64,
}

fn warning_names(state: i64) -> Vec<&'static str> {
    use crate::service::notices::*;
    [
        (WARN_RETAINED, "retained bytes above quota"),
        (WARN_MIN_COUNT, "minimum count cap reached"),
        (WARN_PIN_CAP, "pin cap reached"),
        (WARN_ACCOUNT_BUDGET, "account upload budget used up"),
        (WARN_QUOTA, "live bytes near quota"),
        (WARN_DISK, "disk below reserve"),
    ]
    .into_iter()
    .filter(|(bit, _)| state & bit != 0)
    .map(|(_, name)| name)
    .collect()
}

pub async fn status(app: &App) -> ApiResult<Status> {
    let mut conn = app.db.acquire().await?;
    let rows: Vec<(i64, Vec<u8>, i64, i64, i64)> = sqlx::query_as(
        "SELECT pk, id, live_data_bytes, live_dir_bytes, warn_state FROM accounts ORDER BY created_ms",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut accounts = Vec::with_capacity(rows.len());
    for (pk, id, data, dir, warn) in rows {
        let Some(id) = AccountId::from_slice(&id) else {
            continue;
        };
        let (folders, retired): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(retired_ms IS NOT NULL), 0) FROM folders WHERE account_pk = ? AND head_pk IS NOT NULL",
        )
        .bind(pk)
        .fetch_one(&mut *conn)
        .await?;
        let stored: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(o.size), 0) FROM objects o JOIN folders f ON f.pk = o.folder_pk WHERE f.account_pk = ?",
        )
        .bind(pk)
        .fetch_one(&mut *conn)
        .await?;
        let pins: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pins WHERE account_pk = ? AND lapsed_ms IS NULL AND until_ms > ?",
        )
        .bind(pk)
        .bind(i64_of(app.now_ms()))
        .fetch_one(&mut *conn)
        .await?;
        let length: i64 = sqlx::query_scalar("SELECT log_length FROM accounts WHERE pk = ?")
            .bind(pk)
            .fetch_one(&mut *conn)
            .await?;
        let state = app.states.get(&mut conn, pk, id, u64_of(length)).await?;
        accounts.push(AccountStatus {
            id,
            devices: state.current_devices().filter(|d| !d.recovery).count() as u64,
            folders: u64_of(folders),
            retired_folders: u64_of(retired),
            live_bytes: u64_of(data).saturating_add(u64_of(dir)),
            stored_bytes: u64_of(stored),
            pins: u64_of(pins),
            warnings: warning_names(warn),
        });
    }
    let open: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invites WHERE used_ms IS NULL AND expires_ms > ?")
            .bind(i64_of(app.now_ms()))
            .fetch_one(&mut *conn)
            .await?;
    Ok(Status {
        accounts,
        open_invites: u64_of(open),
        disk_available: app.disk.available(),
        disk_reserve: app.limits.disk_reserve,
    })
}

async fn account_pk(app: &App, account: &AccountId) -> ApiResult<i64> {
    let mut conn = app.db.acquire().await?;
    account_by_id(&mut conn, account)
        .await?
        .map(|a| a.pk)
        .ok_or_else(|| ApiError::new(hangar_drive_protocol::api::ErrorCode::NotFound))
}

/// Deletes an account with everything it holds.
pub async fn purge_account(app: &App, account: &AccountId) -> ApiResult<()> {
    let pk = account_pk(app, account).await?;
    let mut tx = begin_write(&app.db).await?;
    sqlx::query("DELETE FROM accounts WHERE pk = ?")
        .bind(pk)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    app.states.forget(pk);
    let store = app.store.clone();
    let account = *account;
    tokio::task::spawn_blocking(move || store.delete_account(&account))
        .await
        .map_err(|e| ApiError::internal(&e))??;
    Ok(())
}

/// Deletes one folder with every commit body and object; the devices see it retired.
pub async fn purge_folder(app: &App, account: &AccountId, folder: &FolderId) -> ApiResult<()> {
    let pk = account_pk(app, account).await?;
    let mut tx = begin_write(&app.db).await?;
    let row: Option<(i64, Option<i64>, i64, i64)> = sqlx::query_as(
        "SELECT pk, retired_ms, live_data_bytes, live_dir_bytes FROM folders WHERE account_pk = ? AND id = ?",
    )
    .bind(pk)
    .bind(folder.as_bytes().as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let (folder_pk, retired, data, dir) =
        row.ok_or_else(|| ApiError::new(hangar_drive_protocol::api::ErrorCode::NotFound))?;
    if retired.is_none() {
        usage::shift_account_live(&mut tx, pk, -data, -dir).await?;
    }
    // The operator's purge also ends the folder's pins, which no longer go with it by
    // themselves (finding M3).
    sqlx::query("DELETE FROM pins WHERE folder_pk = ?")
        .bind(folder_pk)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM folders WHERE pk = ?")
        .bind(folder_pk)
        .execute(&mut *tx)
        .await?;
    // Until the directory is gone, no upload may make the folder again or put a file into it,
    // and an upload that put its file in place before this commit refuses at its own
    // (`service::objects::store`). The garbage collection removes a tombstone left by a failed
    // removal below.
    sqlx::query(
        "INSERT OR IGNORE INTO folder_tombstones (account_pk, folder_id, created_ms) VALUES (?, ?, ?)",
    )
    .bind(pk)
    .bind(folder.as_bytes().as_slice())
    .bind(i64_of(app.now_ms()))
    .execute(&mut *tx)
    .await?;
    usage::count_folder_removal(&mut tx, pk).await?;
    usage::recount_pending(&mut tx, pk).await?;
    let pushed = feed::push(&mut tx, pk, &FeedChange::FolderRetired { folder: *folder }).await?;
    tx.commit().await?;
    pushed.notify(app);
    let store = app.store.clone();
    let (account, folder) = (*account, *folder);
    tokio::task::spawn_blocking(move || store.delete_folder(&account, &folder))
        .await
        .map_err(|e| ApiError::internal(&e))??;
    sqlx::query("DELETE FROM folder_tombstones WHERE account_pk = ? AND folder_id = ?")
        .bind(pk)
        .bind(folder.as_bytes().as_slice())
        .execute(&app.db)
        .await?;
    Ok(())
}

/// Deletes every retained byte of an account at once: only the live trees and young uploads
/// stay; other commit bodies, pins and retired folders go.
pub async fn purge_retained(app: &App, account: &AccountId) -> ApiResult<Outcome> {
    let pk = account_pk(app, account).await?;
    retention::account_step(app, pk, Mode::PurgeRetained).await
}

/// A pin as the CLI lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinInfo {
    pub account: AccountId,
    pub folder: FolderId,
    pub commit: CommitId,
    pub created_ms: u64,
    pub until_ms: u64,
    pub lapsed: bool,
}

pub async fn pins(app: &App) -> ApiResult<Vec<PinInfo>> {
    type PinRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, Option<i64>);
    let rows: Vec<PinRow> = sqlx::query_as(
        "SELECT a.id, f.id, p.commit_id, p.created_ms, p.until_ms, p.lapsed_ms FROM pins p \
         JOIN accounts a ON a.pk = p.account_pk JOIN folders f ON f.pk = p.folder_pk ORDER BY p.created_ms",
    )
    .fetch_all(&app.db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(a, f, c, created, until, lapsed)| {
            Some(PinInfo {
                account: AccountId::from_slice(&a)?,
                folder: FolderId::from_slice(&f)?,
                commit: CommitId::from_slice(&c)?,
                created_ms: u64_of(created),
                until_ms: u64_of(until),
                lapsed: lapsed.is_some(),
            })
        })
        .collect())
}

/// Lifts the pins on `commit` of the account. Returns how many were lifted.
pub async fn lift_pin(app: &App, account: &AccountId, commit: &CommitId) -> ApiResult<u64> {
    let pk = account_pk(app, account).await?;
    let lifted = sqlx::query("DELETE FROM pins WHERE account_pk = ? AND commit_id = ?")
        .bind(pk)
        .bind(commit.as_bytes().as_slice())
        .execute(&app.db)
        .await?;
    Ok(lifted.rows_affected())
}
