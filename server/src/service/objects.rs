//! Objects (ADR 0001, sections 3 and 5): `objects/missing`, the idempotent upload with header,
//! size, quota, budget and disk reserve checks, and the download. Every object is addressed by
//! the session's account, the folder and its ID.

use std::collections::BTreeMap;
use std::path::PathBuf;

use hangar_drive_crypto::object::{blob_len, blob_len_fits, object_header};
use hangar_drive_protocol::api::Notice;
use hangar_drive_protocol::api::{
    ErrorCode, MissingObjectsRequest, MissingObjectsResponse, UploadResponse,
};
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, ObjectId};
use hangar_drive_protocol::object::{ObjectType, MAX_OBJECT_PLAINTEXT_LEN};

use crate::app::{App, AppState, OwnedUploadSlot};
use crate::db::{begin_write, i64_of, u64_of};
use crate::error::{ApiError, ApiResult, RETRY_SOON_S};
use crate::service::commits::push_hex;
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
    // One statement for the whole list (at most `MAX_MISSING_QUERY` IDs) instead of one per ID:
    // the IDs travel as a JSON array of hex strings, as in the commit call, and come back as
    // their positions in the request, so the answer keeps the request's order.
    let mut json = String::with_capacity(request.ids.len() * (ObjectId::LEN * 2 + 3) + 2);
    json.push('[');
    for (i, id) in request.ids.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('"');
        push_hex(&mut json, id.as_bytes());
        json.push('"');
    }
    json.push(']');
    let positions: Vec<i64> = sqlx::query_scalar(
        "SELECT j.key FROM json_each(?) j WHERE NOT EXISTS \
           (SELECT 1 FROM objects o WHERE o.folder_pk = ? AND o.object_id = unhex(j.value)) \
         ORDER BY j.key",
    )
    .bind(json.as_str())
    .bind(row.pk)
    .fetch_all(&mut *conn)
    .await?;
    let missing = positions
        .into_iter()
        .filter_map(|i| usize::try_from(i).ok())
        .filter_map(|i| request.ids.get(i).copied())
        .collect();
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
/// held, and that the disk stays above its reserve with what uploads in flight still write
/// (finding M5). The caller claims this upload's expected bytes in [`App::staging`] first, so
/// they are part of that sum and two uploads cannot both pass on the same free space.
pub async fn precheck(
    app: &App,
    session: &Session,
    folder: &FolderId,
    id: &ObjectId,
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
    if !usage::disk_has_room(app, 0) {
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

/// What [`observe`] saw before the file went in place.
#[derive(Debug, Clone, Copy)]
struct Seen {
    /// The folder if it existed.
    folder: Option<SeenFolder>,
    /// The account's count of folder removals (`usage::folder_removals`), read first.
    removals: Option<i64>,
}

/// The folder as [`observe`] saw it.
#[derive(Debug, Clone, Copy)]
struct SeenFolder {
    pk: i64,
    created_ms: i64,
    /// It had a head: only an operator purge removes such a folder without a tombstone left.
    committed: bool,
}

/// A folder row as [`folder_identity`] reads it.
#[derive(Debug, Clone, Copy, sqlx::FromRow)]
struct FolderIdentity {
    pk: i64,
    created_ms: i64,
    retired_ms: Option<i64>,
    committed: bool,
}

/// What [`observe`] found under the stripe lock, before the file goes in place.
enum Observed {
    /// The object has a row: its file must not be touched.
    Held,
    /// Put the file in place.
    Install(Seen),
}

/// What [`record`] did in the write transaction.
enum Recorded {
    Stored,
    /// A row appeared after [`observe`]. Only an upload of the same object inserts object rows,
    /// and it holds the same stripe, so this does not happen; should it, the file is the row's
    /// now and stays.
    Held,
}

/// Stores a received object (module docs).
///
/// **Order** (throughput review 2026-11-28): under the object's stripe lock, (1) read-only
/// checks: the account's count of folder removals, the folder is not retired or being removed,
/// the object has no row (mandatory: the file of an object with a row is never replaced) and
/// the quota has room; (2) the file goes in place with its directory flushed, outside the
/// database's write lock, which before was held across the rename and the directory flush and
/// so queued every upload of the server behind one disk flush; (3) one write transaction
/// repeats every check (removals, retired, held, quota, budget, disk reserve) and inserts the
/// row. A refusal in (3) removes the file again, still under the stripe lock.
///
/// **Invariant: a committed row always has its file.** The file is durable before the row
/// commits. The garbage collection and the orphan sweep remove a single file only under the
/// same stripe lock and only without a row, so they wait for this upload to commit or give up.
///
/// A folder's directory is removed whole without stripe locks (garbage collection, `purge
/// folder`) and may take this upload's file with it. Every transaction that deletes folders of
/// the account raises `accounts.folder_removals` and leaves a tombstone that goes only after the
/// directory is gone (`purge account` deletes the account row, which (3) notices the same way).
/// So: a removal committed after (1) read the count changes it, and (3) refuses
/// ([`removal_raced`]); a removal committed before that read either still has its tombstone,
/// which (1) and the folder creation in (3) refuse, or has removed its directory already, before
/// this file went in place. This holds for a folder that existed in (1) and for one that another
/// upload made after (1).
///
/// **Cancellation:** the steps run in a task of their own that owns the stripe guard and the
/// account's upload slot, so a request whose connection drops cannot release the stripe while a
/// file is being put in place or removed, nor free its slot while the task still works (no more
/// than `HANGAR_DRIVE_UPLOADS_PER_ACCOUNT` uploads of one account in this step). A crash
/// between (2) and the commit leaves a file without a row, which the orphan sweep removes after
/// an hour.
pub async fn store(
    app: &AppState,
    session: &Session,
    folder: FolderId,
    id: ObjectId,
    staged: Staged,
    slot: OwnedUploadSlot,
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
    let (app, session) = (app.clone(), session.clone());
    tokio::spawn(async move {
        // The account's upload slot is held until the task ends (follow-up review).
        let _slot = slot;
        store_locked(&app, &session, folder, id, kind, size, staged).await
    })
    .await
    .map_err(|e| ApiError::internal(&e))?
}

/// [`store`] from the stripe lock on, inside its own task.
async fn store_locked(
    app: &App,
    session: &Session,
    folder: FolderId,
    id: ObjectId,
    kind: ObjectType,
    size: u64,
    mut staged: Staged,
) -> ApiResult<UploadResponse> {
    let key = ObjectKey {
        account: session.account,
        folder,
        id,
    };
    let lock_key = [folder.as_bytes().as_slice(), id.as_bytes().as_slice()].concat();
    let _guard = app.object_locks.lock(&lock_key).await;

    let seen = match observe(app, session, &folder, &id, Bytes::of(kind, size)).await? {
        Observed::Held => return Ok(UploadResponse { stored: false }),
        Observed::Install(seen) => seen,
    };
    if usage::below_disk_reserve(app) {
        return Err(disk_reserve_hit(app, session).await);
    }

    let store = app.store.clone();
    let path = staged.path.clone();
    let installed = tokio::task::spawn_blocking(move || store.install(&path, &key))
        .await
        .map_err(|e| ApiError::internal(&e))
        .and_then(|r| r.map_err(ApiError::from));
    if let Err(error) = installed {
        // The rename may have happened before the directory flush failed.
        remove_unrecorded(app, key).await;
        return Err(error);
    }
    staged.installed = true;
    if let Some(hook) = &app.hooks.upload_installed {
        hook().await;
    }

    match record(app, session, &folder, &id, kind, size, seen).await {
        Ok(Recorded::Stored) => Ok(UploadResponse { stored: true }),
        Ok(Recorded::Held) => Ok(UploadResponse { stored: false }),
        Err(error) => {
            remove_unrecorded(app, key).await;
            Err(error)
        }
    }
}

/// Removes the file of an upload that got no row, while the caller still holds the object's
/// stripe lock, so no row can appear for it meanwhile. A failure only logs: the orphan sweep
/// removes the file later.
async fn remove_unrecorded(app: &App, key: ObjectKey) {
    let store = app.store.clone();
    match tokio::task::spawn_blocking(move || store.delete(&key)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!(error = %e, "removing a refused upload failed"),
        Err(e) => tracing::error!(error = %e, "removing a refused upload failed"),
    }
}

/// The folder's tombstone: its directory is still being removed.
async fn tombstoned(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    folder: &FolderId,
) -> ApiResult<bool> {
    let hit: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM folder_tombstones WHERE account_pk = ? AND folder_id = ?",
    )
    .bind(account_pk)
    .bind(folder.as_bytes().as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(hit.is_some())
}

/// In (3) of [`store`], after the account's folder removals changed since (1): whether this
/// upload must stop, and how (follow-up review LOW 2). `None`: the folder (1) saw is still the
/// same row, so its directory was not removed, and the upload goes on.
///
/// - the folder is being removed (tombstone), or another row has its ID now, or (1) saw no
///   folder (it may have been made and removed since): `rate_limited` for a few seconds, the
///   device tries again;
/// - the folder (1) saw had a head and is gone with its directory (an operator purge):
///   `folder_retired`, so the device stops instead of making the deleted folder again;
/// - the folder (1) saw never had a head and is gone: the garbage collection also deletes such
///   a folder a day after it was made when it holds no objects (a device that uploaded without
///   committing and slept), so it is not a purge: `rate_limited` for a few seconds, and the
///   device's retry makes the folder again;
/// - the account is gone: `rate_limited`, the next call finds no session.
async fn removal_raced(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    folder: &FolderId,
    seen: Seen,
    removals_now: Option<i64>,
) -> ApiResult<Option<ApiError>> {
    let soon = || Some(ApiError::rate_limited(Some(RETRY_SOON_S)));
    if removals_now.is_none() || tombstoned(conn, account_pk, folder).await? {
        return Ok(soon());
    }
    let now = folder_identity(conn, account_pk, folder).await?;
    Ok(match (seen.folder, now) {
        (Some(before), Some(now)) if (before.pk, before.created_ms) == (now.pk, now.created_ms) => {
            None
        }
        (Some(before), None) if before.committed => Some(ErrorCode::FolderRetired.into()),
        _ => soon(),
    })
}

/// The folder's key, creation time, retirement and whether it has a head, if it exists.
async fn folder_identity(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    folder: &FolderId,
) -> ApiResult<Option<FolderIdentity>> {
    Ok(sqlx::query_as(
        "SELECT pk, created_ms, retired_ms, head_pk IS NOT NULL AS committed          FROM folders WHERE account_pk = ? AND id = ?",
    )
    .bind(account_pk)
    .bind(folder.as_bytes().as_slice())
    .fetch_optional(&mut *conn)
    .await?)
}

/// Step (1) of [`store`]: read-only, outside any write transaction. Only the held check is
/// authoritative (no other call inserts object rows while the stripe is held); the others
/// spare a refused upload the disk flush and are repeated in [`record`].
async fn observe(
    app: &App,
    session: &Session,
    folder: &FolderId,
    id: &ObjectId,
    new: Bytes,
) -> ApiResult<Observed> {
    let mut conn = app.db.acquire().await?;
    // First, before any look at the folder (see `store`).
    let removals = usage::folder_removals(&mut conn, session.account_pk).await?;
    let seen = match folder_identity(&mut conn, session.account_pk, folder).await? {
        Some(row) if row.retired_ms.is_some() => return Err(ErrorCode::FolderRetired.into()),
        Some(row) => {
            let held: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM objects WHERE folder_pk = ? AND object_id = ?")
                    .bind(row.pk)
                    .bind(id.as_bytes().as_slice())
                    .fetch_optional(&mut *conn)
                    .await?;
            if held.is_some() {
                return Ok(Observed::Held);
            }
            Some(SeenFolder {
                pk: row.pk,
                created_ms: row.created_ms,
                committed: row.committed,
            })
        }
        None => {
            // The folder was deleted and its directory is still being removed (overall review
            // N2): a file put there now could be removed with it.
            if tombstoned(&mut conn, session.account_pk, folder).await? {
                return Err(ApiError::rate_limited(Some(RETRY_SOON_S)));
            }
            None
        }
    };
    let live = usage::live(&mut conn, session.account_pk).await?;
    let pending = usage::device_pending(&mut conn, session.account_pk, &session.device).await?;
    if !usage::upload_fits(&app.limits, live, pending, new) {
        return Err(ErrorCode::QuotaExceeded.into());
    }
    Ok(Observed::Install(Seen {
        folder: seen,
        removals,
    }))
}

/// Step (3) of [`store`]: every check again and the row, in one write transaction.
async fn record(
    app: &App,
    session: &Session,
    folder: &FolderId,
    id: &ObjectId,
    kind: ObjectType,
    size: u64,
    seen: Seen,
) -> ApiResult<Recorded> {
    let now = app.now_ms();
    let mut tx = begin_write(&app.db).await?;
    // A folder removal since step (1) may have taken this upload's file with its directory.
    let removals = usage::folder_removals(&mut tx, session.account_pk).await?;
    if removals != seen.removals {
        if let Some(refusal) =
            removal_raced(&mut tx, session.account_pk, folder, seen, removals).await?
        {
            return Err(refusal);
        }
    }
    let row = folders::find_or_create(&mut tx, session.account_pk, folder, now).await?;
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
        return Ok(Recorded::Held);
    }
    let live = usage::live(&mut tx, session.account_pk).await?;
    let pending = usage::device_pending(&mut tx, session.account_pk, &session.device).await?;
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
    // received (finding M5). The file itself is already part of the used space.
    if usage::below_disk_reserve(app) {
        drop(tx);
        return Err(disk_reserve_hit(app, session).await);
    }
    sqlx::query(
        "INSERT INTO objects (folder_pk, object_id, kind, size, uploaded_ms, uploader) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(row.pk)
    .bind(id.as_bytes().as_slice())
    .bind(i64::from(kind.to_byte()))
    .bind(i64_of(size))
    .bind(i64_of(now))
    .bind(session.device.as_bytes().as_slice())
    .execute(&mut *tx)
    .await?;
    usage::shift_pending(&mut tx, session.account_pk, Bytes::of(kind, size), 1).await?;
    tx.commit().await?;
    Ok(Recorded::Stored)
}

/// Deletes the uncommitted uploads of a removed device, in the transaction that removes it
/// (security review MEDIUM 3), and gives back the budget they paid. Returns the keys whose files
/// the caller removes after the commit ([`crate::service::retention::remove_object_files`]); a
/// crash before that leaves files without rows, which the orphan sweep removes.
///
/// No reference or side reference can name an uncommitted object (a commit declares every object
/// it references), so the rows go without touching any tree. An honest device that skipped its
/// own upload of the same object because the server held it gets `missing objects` at its commit
/// and uploads it again, as after the 24 hour deletion.
///
/// **Budget:** each deleted byte is taken off the device's minute in which it was paid, so the
/// account budget the removed device used for garbage is free again at once. Only bytes of
/// deleted objects are given back: what the device made live stays paid, so removing devices
/// never lets anything stay stored beyond the budgets.
pub async fn drop_uploads_of(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    account: AccountId,
    device: &DeviceId,
    now_ms: u64,
) -> ApiResult<Vec<ObjectKey>> {
    let rows: Vec<(Vec<u8>, Vec<u8>, i64, i64)> = sqlx::query_as(
        "SELECT f.id, o.object_id, o.size, o.uploaded_ms FROM objects o JOIN folders f ON f.pk = o.folder_pk \
         WHERE f.account_pk = ? AND o.declared = 0 AND o.uploader = ?",
    )
    .bind(account_pk)
    .bind(device.as_bytes().as_slice())
    .fetch_all(&mut *conn)
    .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let since = now_ms.saturating_sub(usage::BUDGET_WINDOW_MS);
    let mut paid: BTreeMap<u64, u64> = BTreeMap::new();
    let mut keys = Vec::with_capacity(rows.len());
    for (folder, id, size, uploaded_ms) in rows {
        let uploaded_ms = u64_of(uploaded_ms);
        if uploaded_ms > since {
            let minute = uploaded_ms - uploaded_ms % usage::MINUTE_MS;
            let entry = paid.entry(minute).or_default();
            *entry = entry.saturating_add(u64_of(size));
        }
        if let (Some(folder), Some(id)) = (FolderId::from_slice(&folder), ObjectId::from_slice(&id))
        {
            keys.push(ObjectKey {
                account,
                folder,
                id,
            });
        }
    }
    sqlx::query(
        "DELETE FROM objects WHERE declared = 0 AND uploader = ? \
         AND folder_pk IN (SELECT pk FROM folders WHERE account_pk = ?)",
    )
    .bind(device.as_bytes().as_slice())
    .bind(account_pk)
    .execute(&mut *conn)
    .await?;
    for (minute, bytes) in paid {
        sqlx::query(
            "UPDATE budget_minutes SET bytes = MAX(0, bytes - ?) \
             WHERE account_pk = ? AND device = ? AND minute_ms = ?",
        )
        .bind(i64_of(bytes))
        .bind(account_pk)
        .bind(device.as_bytes().as_slice())
        .bind(i64_of(minute))
        .execute(&mut *conn)
        .await?;
    }
    usage::recount_pending(conn, account_pk).await?;
    Ok(keys)
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
