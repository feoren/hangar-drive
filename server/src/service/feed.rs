//! The account change feed (ADR 0001, section 3, "Change feed"). Every account level change
//! takes the next account sequence and one entry. An entry replaces the older entry of the same
//! kind and key, so the feed holds the newest entry per key and stays bounded; a device that
//! pulls from its cursor still sees every key that changed after it.

use hangar_drive_protocol::api::{FeedChange, FeedEntry, FeedPage, Notice, MAX_FEED_PAGE};

use crate::app::App;
use crate::db::{i64_of, u64_of};
use crate::error::{ApiError, ApiResult};

/// The coalescing key of a change: kind plus the ID it is about.
pub fn coalesce_key(change: &FeedChange) -> String {
    match change {
        FeedChange::DeviceLog { .. } => "device_log".into(),
        FeedChange::Epoch { .. } => "epoch".into(),
        FeedChange::Record { key, .. } => match key.folder {
            Some(folder) => format!("record:{}:{folder}", key.kind.label()),
            None => format!("record:{}", key.kind.label()),
        },
        FeedChange::FolderHead { folder, .. } => format!("folder_head:{folder}"),
        FeedChange::FolderCreated { folder } => format!("folder_created:{folder}"),
        FeedChange::FolderRetired { folder } => format!("folder_retired:{folder}"),
        FeedChange::Notice { notice } => match notice {
            Notice::AnomalyPin { folder, commit, .. } => format!("notice:pin:{folder}:{commit}"),
            Notice::QuotaWarning { .. } => "notice:quota".into(),
            Notice::RetainedOverQuota { .. } => "notice:retained".into(),
            Notice::MinimumCountCap { .. } => "notice:minimum_count".into(),
            Notice::DeviceBudget { device } => format!("notice:device_budget:{device}"),
            Notice::AccountBudget => "notice:account_budget".into(),
            Notice::DiskReserve => "notice:disk_reserve".into(),
            Notice::Unknown => "notice:unknown".into(),
        },
        FeedChange::Unknown => "unknown".into(),
    }
}

/// Appends `change` to the account's feed inside the caller's transaction and returns its
/// sequence. The caller notifies the push hub after the commit ([`Pushed::notify`]).
pub async fn push(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    change: &FeedChange,
) -> ApiResult<Pushed> {
    let seq: i64 = sqlx::query_scalar(
        "UPDATE accounts SET feed_seq = feed_seq + 1 WHERE pk = ? RETURNING feed_seq",
    )
    .bind(account_pk)
    .fetch_one(&mut *conn)
    .await?;
    let key = coalesce_key(change);
    let json = serde_json::to_string(change).map_err(|e| ApiError::internal(&e))?;
    sqlx::query("DELETE FROM feed WHERE account_pk = ? AND coalesce_key = ?")
        .bind(account_pk)
        .bind(&key)
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO feed (account_pk, seq, coalesce_key, change) VALUES (?, ?, ?, ?)")
        .bind(account_pk)
        .bind(seq)
        .bind(&key)
        .bind(json)
        .execute(&mut *conn)
        .await?;
    Ok(Pushed {
        account_pk,
        seq: u64_of(seq),
    })
}

/// A feed entry that is in the transaction; tell the push hub once it committed.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Pushed {
    pub account_pk: i64,
    pub seq: u64,
}

impl Pushed {
    pub fn notify(self, app: &App) {
        app.events.notify(self.account_pk, self.seq);
    }
}

/// Notifies the newest of several pushes of one account.
pub fn notify_all(app: &App, pushed: &[Pushed]) {
    for p in pushed {
        p.notify(app);
    }
}

/// `GET /account/feed?after=N`.
pub async fn page(app: &App, account_pk: i64, after: u64) -> ApiResult<FeedPage> {
    let mut conn = app.db.acquire().await?;
    let sequence: i64 = sqlx::query_scalar("SELECT feed_seq FROM accounts WHERE pk = ?")
        .bind(account_pk)
        .fetch_one(&mut *conn)
        .await?;
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT seq, change FROM feed WHERE account_pk = ? AND seq > ? ORDER BY seq LIMIT ?",
    )
    .bind(account_pk)
    .bind(i64_of(after))
    .bind(i64_of(MAX_FEED_PAGE as u64 + 1))
    .fetch_all(&mut *conn)
    .await?;
    let more = rows.len() > MAX_FEED_PAGE;
    let mut entries = Vec::with_capacity(rows.len().min(MAX_FEED_PAGE));
    for (seq, change) in rows.into_iter().take(MAX_FEED_PAGE) {
        let change: FeedChange =
            serde_json::from_str(&change).map_err(|e| ApiError::internal(&e))?;
        entries.push(FeedEntry {
            sequence: u64_of(seq),
            change,
        });
    }
    Ok(FeedPage {
        entries,
        sequence: u64_of(sequence),
        more,
    })
}

/// The account's current feed sequence.
pub async fn current(app: &App, account_pk: i64) -> ApiResult<u64> {
    let seq: i64 = sqlx::query_scalar("SELECT feed_seq FROM accounts WHERE pk = ?")
        .bind(account_pk)
        .fetch_one(&app.db)
        .await?;
    Ok(u64_of(seq))
}
