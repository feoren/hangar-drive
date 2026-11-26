//! Objects (ADR 0001, sections 3 and 5): `objects/missing`, the idempotent upload with header,
//! size, quota, budget and disk reserve checks, and the download. Every object is addressed by
//! the session's account, the folder and its ID.

use std::path::PathBuf;

use hangar_drive_crypto::object::{blob_len, blob_len_fits, object_header};
use hangar_drive_protocol::api::Notice;
use hangar_drive_protocol::api::{
    ErrorCode, MissingObjectsRequest, MissingObjectsResponse, UploadResponse,
};
use hangar_drive_protocol::ids::{FolderId, ObjectId};
use hangar_drive_protocol::object::{ObjectType, MAX_OBJECT_PLAINTEXT_LEN};

use crate::app::App;
use crate::db::{begin_write, i64_of, u64_of};
use crate::error::{ApiError, ApiResult};
use crate::service::folders;
use crate::service::notices::{self, WARN_DISK};
use crate::service::sessions::Session;
use crate::service::usage::{self, Bytes};
use crate::store::ObjectKey;

/// The largest blob any object type may have: a file manifest or directory node with the
/// largest plaintext (about 34 MiB).
pub fn max_blob_len() -> usize {
    blob_len(MAX_OBJECT_PLAINTEXT_LEN).unwrap_or(usize::MAX)
}

/// `POST /folders/{folder}/objects/missing`.
pub async fn missing(
    app: &App,
    session: &Session,
    folder: FolderId,
    request: MissingObjectsRequest,
) -> ApiResult<MissingObjectsResponse> {
    request
        .validate()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    let mut conn = app.db.acquire().await?;
    let Some(row) = folders::find(&mut conn, session.account_pk, &folder).await? else {
        return Ok(MissingObjectsResponse {
            missing: request.ids,
        });
    };
    if row.retired_ms.is_some() {
        return Err(ErrorCode::FolderRetired.into());
    }
    let mut missing = Vec::new();
    for id in request.ids {
        let held: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM objects WHERE folder_pk = ? AND object_id = ?")
                .bind(row.pk)
                .bind(id.as_bytes().as_slice())
                .fetch_optional(&mut *conn)
                .await?;
        if held.is_none() {
            missing.push(id);
        }
    }
    Ok(MissingObjectsResponse { missing })
}

/// What the upload handler must know before it reads the body.
pub enum Precheck {
    /// Already stored: answer `stored: false` without reading the body.
    Held,
    /// Read the body.
    Receive,
}

/// The checks that need no body: the folder is not retired, whether the object is already
/// held, and that the disk stays above its reserve with the `expected` bytes of this upload on
/// top of what uploads in flight still write (finding M5).
pub async fn precheck(
    app: &App,
    session: &Session,
    folder: &FolderId,
    id: &ObjectId,
    expected: u64,
) -> ApiResult<Precheck> {
    let mut conn = app.db.acquire().await?;
    if let Some(row) = folders::find(&mut conn, session.account_pk, folder).await? {
        if row.retired_ms.is_some() {
            return Err(ErrorCode::FolderRetired.into());
        }
        let held: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM objects WHERE folder_pk = ? AND object_id = ?")
                .bind(row.pk)
                .bind(id.as_bytes().as_slice())
                .fetch_optional(&mut *conn)
                .await?;
        if held.is_some() {
            return Ok(Precheck::Held);
        }
    }
    drop(conn);
    if !usage::disk_has_room(app, expected) {
        return Err(disk_reserve_hit(app, session).await);
    }
    Ok(Precheck::Receive)
}

async fn disk_reserve_hit(app: &App, session: &Session) -> ApiError {
    tracing::warn!("operator warning: the disk is below its free reserve; uploads are refused");
    match notices::raise(app, session.account_pk, WARN_DISK, Notice::DiskReserve).await {
        Ok(()) => ApiError::new(ErrorCode::DiskReserve),
        Err(error) => error,
    }
}

/// A received body in the store's staging area. Removed on drop unless installed.
pub struct Staged {
    pub path: PathBuf,
    pub len: usize,
    pub head: Vec<u8>,
    installed: bool,
}

impl Staged {
    pub fn new(path: PathBuf, len: usize, head: Vec<u8>) -> Self {
        Self {
            path,
            len,
            head,
            installed: false,
        }
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.installed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Stores a received object (module docs).
pub async fn store(
    app: &App,
    session: &Session,
    folder: FolderId,
    id: ObjectId,
    mut staged: Staged,
) -> ApiResult<UploadResponse> {
    let (_, kind) = object_header(&staged.head).ok_or(ErrorCode::BadRequest)?;
    if !blob_len_fits(kind, staged.len) {
        let too_long = blob_len(kind.max_plaintext_len()).is_some_and(|max| staged.len > max);
        return Err(if too_long {
            ErrorCode::TooLarge
        } else {
            ErrorCode::BadRequest
        }
        .into());
    }
    let size = u64::try_from(staged.len).map_err(|_| ApiError::new(ErrorCode::TooLarge))?;
    let key = ObjectKey {
        account: session.account,
        folder,
        id,
    };
    let lock_key = [folder.as_bytes().as_slice(), id.as_bytes().as_slice()].concat();
    let _guard = app.object_locks.lock(&lock_key).await;
    let now = app.now_ms();

    // Checks first, so a refused upload costs no disk flush; then the file, then its row.
    let mut tx = begin_write(&app.db).await?;
    let row = folders::find_or_create(&mut tx, session.account_pk, &folder, now).await?;
    if row.retired_ms.is_some() {
        return Err(ErrorCode::FolderRetired.into());
    }
    let held: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM objects WHERE folder_pk = ? AND object_id = ?")
            .bind(row.pk)
            .bind(id.as_bytes().as_slice())
            .fetch_optional(&mut *tx)
            .await?;
    if held.is_some() {
        tx.commit().await?;
        return Ok(UploadResponse { stored: false });
    }
    let live = usage::live(&mut tx, session.account_pk).await?;
    let pending = usage::pending(&mut tx, session.account_pk).await?;
    if !usage::upload_fits(&app.limits, live, pending, Bytes::of(kind, size)) {
        return Err(ErrorCode::QuotaExceeded.into());
    }
    if let Err(hit) = usage::charge_budget(
        &mut tx,
        &app.limits,
        session.account_pk,
        &session.device,
        size,
        now,
    )
    .await?
    {
        drop(tx);
        notices::budget_hit(app, session.account_pk, &session.device, hit).await?;
        return Err(ErrorCode::BudgetExceeded.into());
    }
    // Again with the body on disk: other uploads may have filled the disk while this one was
    // received (finding M5). The staged file itself is already part of the used space.
    if usage::below_disk_reserve(app) {
        drop(tx);
        return Err(disk_reserve_hit(app, session).await);
    }
    sqlx::query("INSERT INTO objects (folder_pk, object_id, kind, size, uploaded_ms) VALUES (?, ?, ?, ?, ?)")
        .bind(row.pk)
        .bind(id.as_bytes().as_slice())
        .bind(i64::from(kind.to_byte()))
        .bind(i64_of(size))
        .bind(i64_of(now))
        .execute(&mut *tx)
        .await?;
    usage::shift_pending(&mut tx, session.account_pk, Bytes::of(kind, size), 1).await?;
    // The file goes in place before the row is committed, so a committed row always has its
    // file. A crash in between leaves a file without a row, which the sweep removes.
    let store = app.store.clone();
    let path = staged.path.clone();
    tokio::task::spawn_blocking(move || store.install(&path, &key))
        .await
        .map_err(|e| ApiError::internal(&e))??;
    staged.installed = true;
    if let Err(error) = tx.commit().await {
        let store = app.store.clone();
        let _ = tokio::task::spawn_blocking(move || store.delete(&key)).await;
        return Err(error.into());
    }
    Ok(UploadResponse { stored: true })
}

/// `GET /folders/{folder}/objects/{id}`: the open file and its length.
pub async fn open(
    app: &App,
    session: &Session,
    folder: FolderId,
    id: ObjectId,
) -> ApiResult<(std::fs::File, u64)> {
    let mut conn = app.db.acquire().await?;
    let row = folders::find(&mut conn, session.account_pk, &folder)
        .await?
        .ok_or(ErrorCode::NotFound)?;
    let size: Option<i64> =
        sqlx::query_scalar("SELECT size FROM objects WHERE folder_pk = ? AND object_id = ?")
            .bind(row.pk)
            .bind(id.as_bytes().as_slice())
            .fetch_optional(&mut *conn)
            .await?;
    let size = size.ok_or(ErrorCode::NotFound)?;
    drop(conn);
    let key = ObjectKey {
        account: session.account,
        folder,
        id,
    };
    let store = app.store.clone();
    let file = tokio::task::spawn_blocking(move || store.open(&key))
        .await
        .map_err(|e| ApiError::internal(&e))?
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                // Deleted by the garbage collection between the row read and the open.
                ApiError::new(ErrorCode::NotFound)
            } else {
                ApiError::internal(&e)
            }
        })?;
    Ok((file, u64_of(size)))
}

/// The kind of a stored object byte, for callers outside this module.
pub fn object_kind(byte: i64) -> ObjectType {
    usage::kind_of(byte)
}
