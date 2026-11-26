//! The atomic commit call and the delta pull (ADR 0001, section 3, "One head per folder").
//!
//! The call is one write transaction: compare and swap on the head, every server check of the
//! ADR, the reference deltas against the trees they are relative to, the quota and the budgets,
//! then the side commit, the new head, the reference intervals, the folder sequence and the feed
//! entry. A refused call writes nothing.
//!
//! Reference deltas are checked against the server's own view of the trees: an added object
//! must be held and not already in the parent's tree, a dropped one must be in it. The server
//! cannot see inside the trees, but it can hold every device to its own declarations, so the
//! live set it computes is exactly what the devices declared, and no device can make the server
//! forget an object by declaring nothing.
//!
//! The deltas are checked as sets (finding M4): their IDs go into a temporary table, and each
//! rule is one query over it, so a delta of 2^20 IDs costs a handful of statements instead of
//! millions of single lookups under the write lock.
//!
//! **Budgets** (ADR 0001, section 5): uploads are counted at upload; at the commit, every object
//! the call makes reachable again counts, the head's added objects that a commit declared
//! before, and, since a side commit keeps what it adds for the window (finding H1), the side
//! commit's added objects that a commit declared before and that are not live. Both go through
//! the pin restore allowance first.

use hangar_drive_crypto::commit::SignedCommit;
use hangar_drive_crypto::devicelog::AccountState;
use hangar_drive_protocol::api::{
    CommitRequest, CommitResponse, CommitRole, DeltaCommit, DeltaPage, ErrorCode, FeedChange,
    Notice, MAX_DELTA_PAGE,
};
use hangar_drive_protocol::ids::{Blob, DeviceId, FolderId, ObjectId};

use crate::app::{account_by_pk, App};
use crate::db::{begin_write, i64_of, u64_of, Tx};
use crate::error::{ApiError, ApiResult, MAX_MISSING_LISTED};
use crate::service::feed::{self, Pushed};
use crate::service::folders::{self, FolderRow, HeadRow};
use crate::service::notices;
use crate::service::sessions::Session;
use crate::service::usage::{self, Bytes};

/// The rolling window of the burst signal.
pub const BURST_WINDOW_MS: u64 = 3_600_000;
/// No second pin of a folder within this time after one.
const PIN_COOLDOWN_MS: u64 = 3_600_000;

/// Which list of the call an ID came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    HeadAdded = 0,
    HeadDropped = 1,
    SideAdded = 2,
    SideDropped = 3,
}

impl Part {
    fn code(self) -> i64 {
        self as i64
    }
}

/// Fills the temporary table `commit_ids` with the call's IDs.
async fn load_ids(tx: &mut Tx, request: &CommitRequest) -> ApiResult<()> {
    for sql in [
        "CREATE TEMP TABLE IF NOT EXISTS commit_ids (id BLOB NOT NULL, part INTEGER NOT NULL, PRIMARY KEY (part, id)) WITHOUT ROWID",
        "CREATE TEMP TABLE IF NOT EXISTS commit_revived (object_pk INTEGER PRIMARY KEY, size INTEGER NOT NULL)",
        "DELETE FROM commit_ids",
        "DELETE FROM commit_revived",
    ] {
        sqlx::query(sql).execute(&mut **tx).await?;
    }
    let mut lists: Vec<(Part, &[ObjectId])> = vec![
        (Part::HeadAdded, &request.head.delta.added),
        (Part::HeadDropped, &request.head.delta.dropped),
    ];
    if let Some(side) = &request.side {
        lists.push((Part::SideAdded, &side.delta.added));
        lists.push((Part::SideDropped, &side.delta.dropped));
    }
    // One static statement per list: the IDs travel as one JSON array of hex strings, which
    // SQLite unpacks itself, so no SQL text depends on the request.
    for (part, ids) in lists {
        if ids.is_empty() {
            continue;
        }
        let hex: Vec<String> = ids.iter().map(ObjectId::to_hex).collect();
        let json = serde_json::to_string(&hex).map_err(|e| ApiError::internal(&e))?;
        sqlx::query("INSERT INTO commit_ids (id, part) SELECT unhex(value), ? FROM json_each(?)")
            .bind(part.code())
            .bind(json)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// IDs of `part` the folder does not hold, at most as many as an error lists.
async fn not_held(tx: &mut Tx, folder_pk: i64, part: Part) -> ApiResult<Vec<ObjectId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT c.id FROM commit_ids c LEFT JOIN objects o ON o.folder_pk = ? AND o.object_id = c.id \
         WHERE c.part = ? AND o.pk IS NULL LIMIT ?",
    )
    .bind(folder_pk)
    .bind(part.code())
    .bind(i64_of(MAX_MISSING_LISTED as u64))
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .iter()
        .filter_map(|id| ObjectId::from_slice(id))
        .collect())
}

/// How many objects of `part` are in the tree of the head at `seq`.
async fn count_in_tree(tx: &mut Tx, folder_pk: i64, part: Part, seq: u64) -> ApiResult<u64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM commit_ids c JOIN objects o ON o.folder_pk = ? AND o.object_id = c.id \
         WHERE c.part = ? AND EXISTS (SELECT 1 FROM refs r WHERE r.object_pk = o.pk \
               AND r.added_seq <= ? AND (r.dropped_seq IS NULL OR r.dropped_seq > ?))",
    )
    .bind(folder_pk)
    .bind(part.code())
    .bind(i64_of(seq))
    .bind(i64_of(seq))
    .fetch_one(&mut **tx)
    .await?;
    Ok(u64_of(n))
}

/// Bytes and file object count of `part` (held objects only).
async fn part_bytes(tx: &mut Tx, folder_pk: i64, part: Part) -> ApiResult<(Bytes, u64)> {
    let (data, dir, files): (i64, i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(CASE WHEN o.kind <> 3 THEN o.size ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN o.kind = 3 THEN o.size ELSE 0 END), 0), \
                COALESCE(SUM(o.kind <> 3), 0) \
         FROM commit_ids c JOIN objects o ON o.folder_pk = ? AND o.object_id = c.id WHERE c.part = ?",
    )
    .bind(folder_pk)
    .bind(part.code())
    .fetch_one(&mut **tx)
    .await?;
    Ok((
        Bytes {
            data: u64_of(data),
            dir: u64_of(dir),
        },
        u64_of(files),
    ))
}

/// Checks the delta of `added` and `dropped` against the tree of the head at `base` (`None`:
/// the empty tree).
async fn check_delta(
    tx: &mut Tx,
    folder_pk: i64,
    added: (Part, usize),
    dropped: (Part, usize),
    base: Option<u64>,
) -> ApiResult<()> {
    let missing = not_held(tx, folder_pk, added.0).await?;
    if !missing.is_empty() {
        return Err(ApiError::missing(missing));
    }
    if !not_held(tx, folder_pk, dropped.0).await?.is_empty() {
        return Err(ErrorCode::CommitRefused.into());
    }
    match base {
        None => {
            if dropped.1 > 0 {
                return Err(ErrorCode::CommitRefused.into());
            }
        }
        Some(seq) => {
            if count_in_tree(tx, folder_pk, added.0, seq).await? > 0
                || count_in_tree(tx, folder_pk, dropped.0, seq).await? != dropped.1 as u64
            {
                return Err(ErrorCode::CommitRefused.into());
            }
        }
    }
    Ok(())
}

fn decode(
    upload: &hangar_drive_protocol::api::CommitUpload,
    state: &AccountState,
    folder: &FolderId,
) -> ApiResult<SignedCommit> {
    let commit = SignedCommit::decode(upload.commit.as_bytes())
        .map_err(|_| ApiError::new(ErrorCode::CommitRefused))?;
    commit
        .verify_for_server(state, folder)
        .map_err(|_| ApiError::new(ErrorCode::CommitRefused))?;
    Ok(commit)
}

async fn mark(tx: &mut Tx, folder_pk: i64, device: &[u8]) -> ApiResult<u64> {
    let counter: Option<i64> =
        sqlx::query_scalar("SELECT counter FROM device_marks WHERE folder_pk = ? AND device = ?")
            .bind(folder_pk)
            .bind(device)
            .fetch_optional(&mut **tx)
            .await?;
    Ok(counter.map_or(0, u64_of))
}

/// The side commit's base: a head of this folder (every head is on the first-parent chain of
/// the current head, since the server keeps one linear chain).
async fn side_base(tx: &mut Tx, folder_pk: i64, id: &[u8]) -> ApiResult<Option<(HeadRow, bool)>> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT pk, expired FROM commits WHERE folder_pk = ? AND commit_id = ? AND role = 'head'",
    )
    .bind(folder_pk)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        None => Ok(None),
        Some((pk, expired)) => Ok(Some((folders::head(tx, pk).await?, expired != 0))),
    }
}

/// What the burst check saw of a change of a folder.
pub struct Drops {
    /// Replaced or dropped file objects (chunks and manifests).
    pub objects: u64,
    /// Their bytes.
    pub bytes: u64,
}

/// Bytes the call makes reachable again that a commit declared before (module docs): written
/// to `commit_revived` and summed, `(all, of them in the tree of an admitted pin)`.
async fn revived(
    tx: &mut Tx,
    folder_pk: i64,
    current_seq: Option<u64>,
    now: u64,
) -> ApiResult<(u64, u64)> {
    sqlx::query(
        "INSERT OR IGNORE INTO commit_revived (object_pk, size) SELECT o.pk, o.size FROM commit_ids c \
         JOIN objects o ON o.folder_pk = ? AND o.object_id = c.id WHERE c.part = ? AND o.declared = 1",
    )
    .bind(folder_pk)
    .bind(Part::HeadAdded.code())
    .execute(&mut **tx)
    .await?;
    // A side commit keeps what it adds for the window, so an object it adds that is not live
    // is held again from now on: a revival like any other (finding H1). Without this, a device
    // could keep garbage stored for ever by declaring it in a side commit shortly before each
    // window ends, paying the budget only at the first upload.
    sqlx::query(
        "INSERT OR IGNORE INTO commit_revived (object_pk, size) SELECT o.pk, o.size FROM commit_ids c \
         JOIN objects o ON o.folder_pk = ? AND o.object_id = c.id WHERE c.part = ? AND o.declared = 1 \
         AND NOT EXISTS (SELECT 1 FROM refs r WHERE r.object_pk = o.pk AND r.added_seq <= ? \
                         AND r.dropped_seq IS NULL)",
    )
    .bind(folder_pk)
    .bind(Part::SideAdded.code())
    .bind(i64_of(current_seq.unwrap_or(0)))
    .execute(&mut **tx)
    .await?;
    let (all, pinned): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(v.size), 0), COALESCE(SUM(CASE WHEN EXISTS ( \
             SELECT 1 FROM pins p JOIN refs r ON r.object_pk = v.object_pk \
             WHERE p.folder_pk = ? AND p.lapsed_ms IS NULL AND p.until_ms > ? \
               AND r.added_seq <= p.seq AND (r.dropped_seq IS NULL OR r.dropped_seq > p.seq)) \
           THEN v.size ELSE 0 END), 0) FROM commit_revived v",
    )
    .bind(folder_pk)
    .bind(i64_of(now))
    .fetch_one(&mut **tx)
    .await?;
    Ok((u64_of(all), u64_of(pinned)))
}

/// Marks every object of the head's and the side commit's added lists as declared, and takes
/// the ones that were not out of the account's uncommitted bytes.
async fn declare_added(tx: &mut Tx, account_pk: i64, folder_pk: i64) -> ApiResult<()> {
    let (data, dir): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(CASE WHEN o.kind <> 3 THEN o.size ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN o.kind = 3 THEN o.size ELSE 0 END), 0) FROM objects o \
         WHERE o.declared = 0 AND o.pk IN (SELECT o2.pk FROM commit_ids c JOIN objects o2 \
               ON o2.folder_pk = ? AND o2.object_id = c.id WHERE c.part IN (?, ?))",
    )
    .bind(folder_pk)
    .bind(Part::HeadAdded.code())
    .bind(Part::SideAdded.code())
    .fetch_one(&mut **tx)
    .await?;
    usage::shift_pending(
        tx,
        account_pk,
        Bytes {
            data: u64_of(data),
            dir: u64_of(dir),
        },
        -1,
    )
    .await?;
    sqlx::query(
        "UPDATE objects SET declared = 1 WHERE declared = 0 AND pk IN (SELECT o.pk FROM commit_ids c \
         JOIN objects o ON o.folder_pk = ? AND o.object_id = c.id WHERE c.part IN (?, ?))",
    )
    .bind(folder_pk)
    .bind(Part::HeadAdded.code())
    .bind(Part::SideAdded.code())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// `POST /folders/{folder}/commit`.
pub async fn commit(
    app: &App,
    session: &Session,
    folder: FolderId,
    request: CommitRequest,
) -> ApiResult<CommitResponse> {
    request
        .validate()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    let now = app.now_ms();
    let mut tx = begin_write(&app.db).await?;
    let account = account_by_pk(&mut tx, session.account_pk)
        .await?
        .ok_or(ErrorCode::NotFound)?;
    let state = app
        .states
        .get(&mut tx, account.pk, account.id, account.log_length)
        .await?;

    let existing = folders::find(&mut tx, account.pk, &folder).await?;
    if existing.is_some_and(|f| f.retired_ms.is_some()) {
        return Err(ErrorCode::FolderRetired.into());
    }
    let current: Option<HeadRow> = match existing.and_then(|f| f.head_pk) {
        Some(pk) => Some(folders::head(&mut tx, pk).await?),
        None => None,
    };
    // Compare and swap.
    if request.expected_head != current.map(|h| h.id) {
        return Err(ApiError::head_moved(current.map(|h| h.id)));
    }

    let head = decode(&request.head, &state, &folder)?;
    let side = request
        .side
        .as_ref()
        .map(|s| decode(s, &state, &folder))
        .transpose()?;
    let h = &head.commit;
    // A device publishes only commits it signed itself: no device can replay another device's
    // signed commit under its own session.
    if h.side || h.device != session.device {
        return Err(ErrorCode::CommitRefused.into());
    }
    let row: FolderRow = match existing {
        Some(row) => row,
        None => folders::find_or_create(&mut tx, account.pk, &folder, now).await?,
    };
    let head_mark = mark(&mut tx, row.pk, h.device.as_bytes()).await?;
    if h.counter <= head_mark {
        return Err(ErrorCode::CommitRefused.into());
    }

    // Parents, height and "nothing goes back" along the first-parent chain.
    let mut side_info: Option<(SignedCommit, HeadRow)> = None;
    match &current {
        None => {
            if !h.parents.is_empty() || side.is_some() {
                return Err(ErrorCode::CommitRefused.into());
            }
        }
        Some(parent) => {
            if h.parents.first() != Some(&parent.id)
                || h.generation.0 < parent.generation
                || h.log_head.index < parent.log_index
            {
                return Err(ErrorCode::CommitRefused.into());
            }
            match (h.parents.get(1), side) {
                (None, None) => {
                    if h.height != parent.height + 1 {
                        return Err(ErrorCode::CommitRefused.into());
                    }
                }
                (Some(second), Some(side)) => {
                    let s = &side.commit;
                    if side.id != *second
                        || !s.side
                        || s.reanchor
                        || s.device != h.device
                        || s.counter <= head_mark
                        || s.counter >= h.counter
                        || s.parents.len() != 1
                    {
                        return Err(ErrorCode::CommitRefused.into());
                    }
                    let (base, expired) = side_base(&mut tx, row.pk, s.parents[0].as_bytes())
                        .await?
                        .ok_or(ErrorCode::CommitRefused)?;
                    if expired {
                        return Err(ErrorCode::BaseExpired.into());
                    }
                    if s.height != base.height + 1
                        || s.generation.0 < base.generation
                        || s.log_head.index < base.log_index
                        || h.height != parent.height.max(s.height) + 1
                    {
                        return Err(ErrorCode::CommitRefused.into());
                    }
                    side_info = Some((side, base));
                }
                _ => return Err(ErrorCode::CommitRefused.into()),
            }
        }
    }

    // Reference deltas: the head's against the live set (the tree of the current head), the
    // side commit's against its base.
    load_ids(&mut tx, &request).await?;
    check_delta(
        &mut tx,
        row.pk,
        (Part::HeadAdded, request.head.delta.added.len()),
        (Part::HeadDropped, request.head.delta.dropped.len()),
        current.map(|c| c.seq),
    )
    .await?;
    if let (Some((_, base)), Some(upload)) = (&side_info, &request.side) {
        check_delta(
            &mut tx,
            row.pk,
            (Part::SideAdded, upload.delta.added.len()),
            (Part::SideDropped, upload.delta.dropped.len()),
            Some(base.seq),
        )
        .await?;
    }

    // Quota at commit.
    let (gained, files_gained) = part_bytes(&mut tx, row.pk, Part::HeadAdded).await?;
    let (lost, files_lost) = part_bytes(&mut tx, row.pk, Part::HeadDropped).await?;
    let before = usage::live(&mut tx, account.pk).await?;
    let after = Bytes {
        data: before
            .data
            .saturating_add(gained.data)
            .saturating_sub(lost.data),
        dir: before
            .dir
            .saturating_add(gained.dir)
            .saturating_sub(lost.dir),
    };
    if !usage::commit_fits(&app.limits, before, after) {
        return Err(ErrorCode::QuotaExceeded.into());
    }

    // Budgets: retained objects this call holds again (module docs).
    let (revived_all, in_pin) = revived(&mut tx, row.pk, current.map(|c| c.seq), now).await?;
    let mut revived_paid = revived_all - in_pin;
    if in_pin > 0 {
        let revived_free =
            usage::take_allowance(&mut tx, &app.limits, account.pk, in_pin, now).await?;
        revived_paid += in_pin - revived_free;
    }
    if let Err(hit) = usage::charge_budget(
        &mut tx,
        &app.limits,
        account.pk,
        &session.device,
        revived_paid,
        now,
    )
    .await?
    {
        drop(tx);
        notices::budget_hit(app, account.pk, &session.device, hit).await?;
        return Err(ErrorCode::BudgetExceeded.into());
    }

    // Write.
    let seq = row.seq + 1;
    if let Some((side, base)) = &side_info {
        let s = &side.commit;
        let side_pk: i64 = sqlx::query_scalar(
            "INSERT INTO commits (folder_pk, commit_id, seq, role, body, height, device, generation, log_index, base_seq, server_ms, superseded_ms) \
             VALUES (?, ?, ?, 'side', ?, ?, ?, ?, ?, ?, ?, ?) RETURNING pk",
        )
        .bind(row.pk)
        .bind(side.id.as_bytes().as_slice())
        .bind(i64_of(seq))
        .bind(side.wire.as_slice())
        .bind(i64_of(s.height))
        .bind(s.device.as_bytes().as_slice())
        .bind(i64::from(s.generation.0))
        .bind(i64_of(s.log_head.index))
        .bind(i64_of(base.seq))
        .bind(i64_of(now))
        .bind(i64_of(now))
        .fetch_one(&mut *tx)
        .await
        .map_err(conflict_or_internal)?;
        sqlx::query(
            "INSERT OR IGNORE INTO side_refs (commit_pk, object_pk) SELECT ?, o.pk FROM commit_ids c \
             JOIN objects o ON o.folder_pk = ? AND o.object_id = c.id WHERE c.part = ?",
        )
        .bind(side_pk)
        .bind(row.pk)
        .bind(Part::SideAdded.code())
        .execute(&mut *tx)
        .await?;
    }
    let head_pk: i64 = sqlx::query_scalar(
        "INSERT INTO commits (folder_pk, commit_id, seq, role, body, height, device, generation, log_index, server_ms) \
         VALUES (?, ?, ?, 'head', ?, ?, ?, ?, ?, ?) RETURNING pk",
    )
    .bind(row.pk)
    .bind(head.id.as_bytes().as_slice())
    .bind(i64_of(seq))
    .bind(head.wire.as_slice())
    .bind(i64_of(h.height))
    .bind(h.device.as_bytes().as_slice())
    .bind(i64::from(h.generation.0))
    .bind(i64_of(h.log_head.index))
    .bind(i64_of(now))
    .fetch_one(&mut *tx)
    .await
    .map_err(conflict_or_internal)?;
    if let Some(parent) = &current {
        sqlx::query("UPDATE commits SET superseded_ms = ? WHERE pk = ?")
            .bind(i64_of(now))
            .bind(parent.pk)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO refs (folder_pk, object_pk, added_seq) SELECT ?, o.pk, ? FROM commit_ids c \
         JOIN objects o ON o.folder_pk = ? AND o.object_id = c.id WHERE c.part = ?",
    )
    .bind(row.pk)
    .bind(i64_of(seq))
    .bind(row.pk)
    .bind(Part::HeadAdded.code())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE refs SET dropped_seq = ? WHERE dropped_seq IS NULL AND object_pk IN \
         (SELECT o.pk FROM commit_ids c JOIN objects o ON o.folder_pk = ? AND o.object_id = c.id WHERE c.part = ?)",
    )
    .bind(i64_of(seq))
    .bind(row.pk)
    .bind(Part::HeadDropped.code())
    .execute(&mut *tx)
    .await?;
    declare_added(&mut tx, account.pk, row.pk).await?;
    let folder_live = Bytes {
        data: row
            .live
            .data
            .saturating_add(gained.data)
            .saturating_sub(lost.data),
        dir: row
            .live
            .dir
            .saturating_add(gained.dir)
            .saturating_sub(lost.dir),
    };
    let files_after = row
        .live_file_objects
        .saturating_add(files_gained)
        .saturating_sub(files_lost);
    sqlx::query(
        "UPDATE folders SET seq = ?, head_pk = ?, live_data_bytes = ?, live_dir_bytes = ?, live_file_objects = ? WHERE pk = ?",
    )
    .bind(i64_of(seq))
    .bind(head_pk)
    .bind(i64_of(folder_live.data))
    .bind(i64_of(folder_live.dir))
    .bind(i64_of(files_after))
    .bind(row.pk)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE accounts SET live_data_bytes = ?, live_dir_bytes = ? WHERE pk = ?")
        .bind(i64_of(after.data))
        .bind(i64_of(after.dir))
        .bind(account.pk)
        .execute(&mut *tx)
        .await?;
    let top_counter = h.counter;
    sqlx::query(
        "INSERT INTO device_marks (folder_pk, device, counter) VALUES (?, ?, ?) \
         ON CONFLICT (folder_pk, device) DO UPDATE SET counter = MAX(counter, excluded.counter)",
    )
    .bind(row.pk)
    .bind(h.device.as_bytes().as_slice())
    .bind(i64_of(top_counter))
    .execute(&mut *tx)
    .await?;

    let mut pushed: Vec<Pushed> = Vec::new();
    if current.is_none() {
        pushed.push(feed::push(&mut tx, account.pk, &FeedChange::FolderCreated { folder }).await?);
    }
    pushed.push(
        feed::push(
            &mut tx,
            account.pk,
            &FeedChange::FolderHead {
                folder,
                sequence: seq,
            },
        )
        .await?,
    );

    // Anomaly signal: replaced or dropped file data.
    let drops = Drops {
        objects: files_lost,
        bytes: lost.data,
    };
    if let Some(parent) = &current {
        let burst = Burst {
            account_pk: account.pk,
            folder_pk: row.pk,
            folder,
            parent_seq: parent.seq,
            live_after: folder_live,
            files_after,
            device: session.device,
        };
        if let Some(p) = detect_burst(app, &mut tx, &burst, &drops, now).await? {
            pushed.push(p);
        }
    }
    if after.all() >= app.limits.quota / 10 * 9 {
        if let Some(p) = notices::raise_in(
            &mut tx,
            account.pk,
            notices::WARN_QUOTA,
            Some(Notice::QuotaWarning {
                live_bytes: after.all(),
                quota_bytes: app.limits.quota,
            }),
        )
        .await?
        {
            pushed.push(p);
        }
    }
    tx.commit().await?;
    feed::notify_all(app, &pushed);
    Ok(CommitResponse {
        head: head.id,
        sequence: seq,
    })
}

/// A commit ID that is already stored in the folder (a replayed commit) is a refused commit.
fn conflict_or_internal(error: sqlx::Error) -> ApiError {
    match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            ApiError::new(ErrorCode::CommitRefused)
        }
        _ => ApiError::from(error),
    }
}

/// The folder a change happened in, for the burst signal.
pub struct Burst {
    pub account_pk: i64,
    pub folder_pk: i64,
    pub folder: FolderId,
    /// The head the change replaced (a new head's parent, or the retired head).
    pub parent_seq: u64,
    /// The folder's live bytes after the change.
    pub live_after: Bytes,
    /// The folder's live file objects after the change.
    pub files_after: u64,
    /// The device that made the change.
    pub device: DeviceId,
}

/// The burst signal (ADR 0001, section 5, "Anomaly pinning"): within the rolling hour, the
/// folder's changes replaced or dropped at least [`crate::config::Limits::burst_objects`] file
/// objects (finding L4: the configured count or the configured share of the folder's file
/// objects, whichever is smaller, at least 20) that make up at least `anomaly_percent` of its
/// file data; or a device that has used up its upload budget drops file data. The pin holds the
/// last commit before the burst: the parent of the oldest change in the window. A retirement
/// counts as dropping every live object (finding M3).
pub async fn detect_burst(
    app: &App,
    tx: &mut Tx,
    burst: &Burst,
    drops: &Drops,
    now: u64,
) -> ApiResult<Option<Pushed>> {
    if drops.objects == 0 {
        return Ok(None);
    }
    sqlx::query("INSERT INTO drop_events (folder_pk, at_ms, parent_seq, objects, bytes) VALUES (?, ?, ?, ?, ?)")
        .bind(burst.folder_pk)
        .bind(i64_of(now))
        .bind(i64_of(burst.parent_seq))
        .bind(i64_of(drops.objects))
        .bind(i64_of(drops.bytes))
        .execute(&mut **tx)
        .await?;
    let since = i64_of(now.saturating_sub(BURST_WINDOW_MS));
    let (objects, bytes, first_parent): (i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT COALESCE(SUM(objects), 0), COALESCE(SUM(bytes), 0), MIN(parent_seq) FROM drop_events WHERE folder_pk = ? AND at_ms > ?",
    )
    .bind(burst.folder_pk)
    .bind(since)
    .fetch_one(&mut **tx)
    .await?;
    let (objects, bytes) = (u64_of(objects), u64_of(bytes));
    let limits = &app.limits;
    let base = burst.live_after.data.saturating_add(bytes).max(1);
    let share_hit =
        u128::from(bytes) * 100 >= u128::from(base) * u128::from(limits.anomaly_percent);
    let files_before = burst.files_after.saturating_add(objects);
    let mass = objects >= limits.burst_objects(files_before) && share_hit;
    let (device_used, _) = usage::budget_used(tx, burst.account_pk, &burst.device, now).await?;
    let budget_spent = device_used >= limits.device_budget && drops.bytes > 0;
    if !mass && !budget_spent {
        return Ok(None);
    }
    let recent: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM pins WHERE folder_pk = ? AND created_ms > ? LIMIT 1")
            .bind(burst.folder_pk)
            .bind(i64_of(now.saturating_sub(PIN_COOLDOWN_MS)))
            .fetch_optional(&mut **tx)
            .await?;
    if recent.is_some() {
        return Ok(None);
    }
    let pin_seq = first_parent.map_or(burst.parent_seq, u64_of);
    let pinned: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT commit_id FROM commits WHERE folder_pk = ? AND seq = ? AND role = 'head'",
    )
    .bind(burst.folder_pk)
    .bind(i64_of(pin_seq))
    .fetch_optional(&mut **tx)
    .await?;
    let Some((commit_id,)) = pinned else {
        return Ok(None);
    };
    let commit = hangar_drive_protocol::ids::CommitId::from_slice(&commit_id)
        .ok_or_else(|| ApiError::internal(&"stored commit ID length"))?;
    let until = now.saturating_add(limits.pin_ms());
    sqlx::query(
        "INSERT INTO pins (account_pk, folder_pk, commit_id, seq, created_ms, until_ms) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(burst.account_pk)
    .bind(burst.folder_pk)
    .bind(commit_id.as_slice())
    .bind(i64_of(pin_seq))
    .bind(i64_of(now))
    .bind(i64_of(until))
    .execute(&mut **tx)
    .await?;
    if let Some(account) = account_by_pk(tx, burst.account_pk).await? {
        tracing::warn!(account = %account.id, %commit, "operator warning: a burst of replaced or dropped objects pinned a commit");
    }
    Ok(Some(
        feed::push(
            tx,
            burst.account_pk,
            &FeedChange::Notice {
                notice: Notice::AnomalyPin {
                    folder: burst.folder,
                    commit,
                    until_ms: until,
                },
            },
        )
        .await?,
    ))
}

/// `GET /folders/{folder}/commits?after=N`. A head and its side commit share a sequence and are
/// never split across pages.
///
/// A folder this account holds nothing of yet has the empty chain (sequence 0), not
/// `NotFound` (finding E2E-2, ADR 0001, section 3, "API"): a new folder pulls before its first
/// upload and commit, and the in-memory server the engine is tested against answers the same.
/// Folder IDs are random and looked up per account, so the answer tells nothing about another
/// account's folders.
pub async fn delta(
    app: &App,
    session: &Session,
    folder: FolderId,
    after: u64,
) -> ApiResult<DeltaPage> {
    let mut conn = app.db.acquire().await?;
    let Some(row) = folders::find(&mut conn, session.account_pk, &folder).await? else {
        return Ok(DeltaPage {
            commits: Vec::new(),
            sequence: 0,
            more: false,
        });
    };
    // Up to half a page of sequences: each has a head and at most one side commit.
    let limit = (MAX_DELTA_PAGE / 2) as u64;
    let rows: Vec<(i64, String, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, role, body FROM commits WHERE folder_pk = ? AND seq > ? AND seq <= ? ORDER BY seq, role DESC",
    )
    .bind(row.pk)
    .bind(i64_of(after))
    .bind(i64_of(after.saturating_add(limit)))
    .fetch_all(&mut *conn)
    .await?;
    let mut commits = Vec::with_capacity(rows.len());
    for (seq, role, body) in rows {
        commits.push(DeltaCommit {
            sequence: u64_of(seq),
            role: if role == "side" {
                CommitRole::Side
            } else {
                CommitRole::Head
            },
            commit: Blob(body),
        });
    }
    Ok(DeltaPage {
        commits,
        sequence: row.seq,
        more: after.saturating_add(limit) < row.seq,
    })
}
