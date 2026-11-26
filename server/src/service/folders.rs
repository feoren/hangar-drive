//! Folders (ADR 0001, sections 3 and 5). Objects and commits are addressed per account and
//! folder: every lookup is by the session's account and the folder ID, so a folder ID of
//! another account names a different folder, never that one (no IDOR). A folder row exists from
//! the first upload; it gets its head with the first commit. Retiring supersedes the last head
//! and takes the folder's bytes out of the live bytes; within the window any device can bring
//! it back. A retirement drops every live object of the folder at once, so it goes through the
//! burst signal like any commit that drops file data (finding M3): a large folder retired by a
//! compromised device pins its last head and every device is told.

use hangar_drive_protocol::api::{ErrorCode, FeedChange};
use hangar_drive_protocol::ids::{CommitId, FolderId};

use crate::app::App;
use crate::db::{begin_write, i64_of, u64_of};
use crate::error::ApiResult;
use crate::service::commits::{self, Burst, Drops};
use crate::service::feed;
use crate::service::notices;
use crate::service::sessions::Session;
use crate::service::usage::{self, Bytes};

/// Folders one account may have at most, retired ones included.
pub const MAX_FOLDERS_PER_ACCOUNT: i64 = 1024;

#[derive(Debug, Clone, Copy)]
pub struct FolderRow {
    pub pk: i64,
    pub seq: u64,
    pub head_pk: Option<i64>,
    pub retired_ms: Option<u64>,
    pub live: Bytes,
    /// Live file objects (chunks and manifests), for the burst threshold.
    pub live_file_objects: u64,
}

/// What the commit call needs of a head.
#[derive(Debug, Clone, Copy)]
pub struct HeadRow {
    pub pk: i64,
    pub id: CommitId,
    pub seq: u64,
    pub height: u64,
    pub generation: u32,
    pub log_index: u64,
}

pub async fn find(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    folder: &FolderId,
) -> ApiResult<Option<FolderRow>> {
    type Row = (i64, i64, Option<i64>, Option<i64>, i64, i64, i64);
    let row: Option<Row> = sqlx::query_as(
        "SELECT pk, seq, head_pk, retired_ms, live_data_bytes, live_dir_bytes, live_file_objects \
         FROM folders WHERE account_pk = ? AND id = ?",
    )
    .bind(account_pk)
    .bind(folder.as_bytes().as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(
        row.map(|(pk, seq, head_pk, retired, data, dir, files)| FolderRow {
            pk,
            seq: u64_of(seq),
            head_pk,
            retired_ms: retired.map(u64_of),
            live: Bytes {
                data: u64_of(data),
                dir: u64_of(dir),
            },
            live_file_objects: u64_of(files),
        }),
    )
}

/// The folder, created without a head if it does not exist yet (first upload of a new folder).
pub async fn find_or_create(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    folder: &FolderId,
    now_ms: u64,
) -> ApiResult<FolderRow> {
    if let Some(row) = find(conn, account_pk, folder).await? {
        return Ok(row);
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM folders WHERE account_pk = ?")
        .bind(account_pk)
        .fetch_one(&mut *conn)
        .await?;
    if count >= MAX_FOLDERS_PER_ACCOUNT {
        return Err(ErrorCode::QuotaExceeded.into());
    }
    let pk: i64 = sqlx::query_scalar(
        "INSERT INTO folders (account_pk, id, created_ms) VALUES (?, ?, ?) RETURNING pk",
    )
    .bind(account_pk)
    .bind(folder.as_bytes().as_slice())
    .bind(i64_of(now_ms))
    .fetch_one(&mut *conn)
    .await?;
    Ok(FolderRow {
        pk,
        seq: 0,
        head_pk: None,
        retired_ms: None,
        live: Bytes::default(),
        live_file_objects: 0,
    })
}

pub async fn head(conn: &mut sqlx::SqliteConnection, commit_pk: i64) -> ApiResult<HeadRow> {
    let (id, seq, height, generation, log_index): (Vec<u8>, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT commit_id, seq, height, generation, log_index FROM commits WHERE pk = ?",
    )
    .bind(commit_pk)
    .fetch_one(&mut *conn)
    .await?;
    Ok(HeadRow {
        pk: commit_pk,
        id: CommitId::from_slice(&id)
            .ok_or_else(|| crate::error::ApiError::internal(&"stored commit ID length"))?,
        seq: u64_of(seq),
        height: u64_of(height),
        generation: u32::try_from(generation).unwrap_or(0),
        log_index: u64_of(log_index),
    })
}

/// `POST /folders/{folder}/retire`.
pub async fn retire(app: &App, session: &Session, folder: FolderId) -> ApiResult<()> {
    let now = app.now_ms();
    let mut tx = begin_write(&app.db).await?;
    let row = find(&mut tx, session.account_pk, &folder)
        .await?
        .ok_or(ErrorCode::NotFound)?;
    let Some(head_pk) = row.head_pk else {
        return Err(ErrorCode::NotFound.into());
    };
    if row.retired_ms.is_some() {
        return Err(ErrorCode::FolderRetired.into());
    }
    sqlx::query("UPDATE folders SET retired_ms = ? WHERE pk = ?")
        .bind(i64_of(now))
        .bind(row.pk)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE commits SET superseded_ms = ? WHERE pk = ?")
        .bind(i64_of(now))
        .bind(head_pk)
        .execute(&mut *tx)
        .await?;
    usage::shift_account_live(
        &mut tx,
        session.account_pk,
        -i64_of(row.live.data),
        -i64_of(row.live.dir),
    )
    .await?;
    let mut pushed = vec![
        feed::push(
            &mut tx,
            session.account_pk,
            &FeedChange::FolderRetired { folder },
        )
        .await?,
    ];
    let head = head(&mut tx, head_pk).await?;
    let burst = Burst {
        account_pk: session.account_pk,
        folder_pk: row.pk,
        folder,
        parent_seq: head.seq,
        live_after: Bytes::default(),
        files_after: 0,
        device: session.device,
    };
    let drops = Drops {
        objects: row.live_file_objects,
        bytes: row.live.data,
    };
    if let Some(p) = commits::detect_burst(app, &mut tx, &burst, &drops, now).await? {
        pushed.push(p);
    }
    tx.commit().await?;
    feed::notify_all(app, &pushed);
    Ok(())
}

/// `DELETE /folders/{folder}/retire`: brings a retired folder back within the window. Its tree
/// becomes live again, so the quota applies, and the bytes count against the budgets like any
/// retained bytes made live again. If a standing pin holds the retired head (a retirement that
/// set off the burst signal, finding M3), its tree goes through the pin restore allowance first,
/// as every restore of a pinned tree does: undoing a harmful retirement does not wait for the
/// budget the harmful device may have used up.
pub async fn bring_back(app: &App, session: &Session, folder: FolderId) -> ApiResult<()> {
    let now = app.now_ms();
    let mut tx = begin_write(&app.db).await?;
    let row = find(&mut tx, session.account_pk, &folder)
        .await?
        .ok_or(ErrorCode::NotFound)?;
    let (Some(head_pk), Some(retired)) = (row.head_pk, row.retired_ms) else {
        return Err(ErrorCode::BadRequest.into());
    };
    if retired.saturating_add(app.limits.retention_ms) <= now {
        return Err(ErrorCode::NotFound.into());
    }
    let before = usage::live(&mut tx, session.account_pk).await?;
    let mut after = before;
    after.add(row.live);
    if !usage::commit_fits(&app.limits, before, after) {
        return Err(ErrorCode::QuotaExceeded.into());
    }
    let head_seq = head(&mut tx, head_pk).await?.seq;
    let pinned: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM pins WHERE folder_pk = ? AND seq = ? AND lapsed_ms IS NULL AND until_ms > ? LIMIT 1",
    )
    .bind(row.pk)
    .bind(i64_of(head_seq))
    .bind(i64_of(now))
    .fetch_optional(&mut *tx)
    .await?;
    let mut paid = row.live.all();
    if pinned.is_some() {
        paid -= usage::take_allowance(&mut tx, &app.limits, session.account_pk, paid, now).await?;
    }
    let hit = usage::charge_budget(
        &mut tx,
        &app.limits,
        session.account_pk,
        &session.device,
        paid,
        now,
    )
    .await?;
    if let Err(hit) = hit {
        drop(tx);
        notices::budget_hit(app, session.account_pk, &session.device, hit).await?;
        return Err(ErrorCode::BudgetExceeded.into());
    }
    sqlx::query("UPDATE folders SET retired_ms = NULL WHERE pk = ?")
        .bind(row.pk)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE commits SET superseded_ms = NULL WHERE pk = ?")
        .bind(head_pk)
        .execute(&mut *tx)
        .await?;
    usage::shift_account_live(
        &mut tx,
        session.account_pk,
        i64_of(row.live.data),
        i64_of(row.live.dir),
    )
    .await?;
    let pushed = feed::push(
        &mut tx,
        session.account_pk,
        &FeedChange::FolderCreated { folder },
    )
    .await?;
    tx.commit().await?;
    pushed.notify(app);
    Ok(())
}
