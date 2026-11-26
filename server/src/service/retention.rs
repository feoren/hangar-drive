//! Retention and garbage collection (ADR 0001, section 5): a mark-and-sweep step per account.
//!
//! **Mark**, in one write transaction per account, in the order of the retention classes, so
//! no byte counts against two caps:
//!
//! 1. and 2. **live and window:** the trees of every head from the oldest one whose window still
//!    runs (superseded less than W ago) up to the current head, which is one range of the
//!    folder sequence; what side commits uploaded less than W ago add to their base; uploads
//!    without a commit younger than 24 hours. A side commit does not hold its base tree: the
//!    base is a head and is retained by its own rules (finding H1: otherwise a side commit on an
//!    old base, sent shortly before each window ends, would keep that base's tree for ever
//!    without any budget). A side commit is restorable while its base is retained.
//! 3. **pins:** the standing pins of the account, oldest first; each is admitted while the bytes
//!    only admitted pins retain stay within P = Q + H, and lapses for good otherwise.
//! 4. **minimum count:** of every folder that is not retired, the newest heads up to the minimum
//!    count whose window has ended, in the order their windows ended, while the bytes only they
//!    retain stay within C; a tree beyond the cap expires.
//!
//! Then: every head whose tree is not retained expires (its server times are dropped, its body
//! stays), side commits past their window are deleted with their body, retired folders past
//! their window are deleted whole once no admitted pin holds them (finding M3), and every
//! object nothing retains is deleted.
//!
//! **Sweep:** after the transaction the files of the deleted objects are removed, each under the
//! object's stripe lock and only if no row came back in between (a new upload of the same
//! object). Rarely, files the database does not know (a crash between file and row) are removed
//! once they are older than an hour.
//!
//! The reference intervals (`refs`) make every tree a range query, so the step needs no walk
//! over directory nodes, which the server cannot read anyway.

use std::time::Duration;

use hangar_drive_protocol::api::{FeedChange, Notice};
use hangar_drive_protocol::ids::{AccountId, CommitId, FolderId, ObjectId};

use crate::app::App;
use crate::db::{begin_write, i64_of, u64_of, Tx};
use crate::error::{ApiError, ApiResult};
use crate::service::feed::{self, Pushed};
use crate::service::notices::{
    self, WARN_ACCOUNT_BUDGET, WARN_DISK, WARN_MIN_COUNT, WARN_PIN_CAP, WARN_QUOTA, WARN_RETAINED,
};
use crate::service::usage::{self, BUDGET_WINDOW_MS};
use crate::store::ObjectKey;

/// An upload without a commit is deleted this long after it arrived.
pub const PENDING_MS: u64 = 86_400_000;
/// A file without a database row is removed by the sweep once it is this old.
const ORPHAN_FILE_AGE: Duration = Duration::from_secs(3600);

/// What a step did (logged, and checked by the tests).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Outcome {
    pub deleted_objects: u64,
    pub deleted_bytes: u64,
    pub expired_heads: u64,
    pub deleted_side_commits: u64,
    pub lapsed_pins: u64,
    pub deleted_folders: u64,
}

impl Outcome {
    fn add(&mut self, other: Outcome) {
        self.deleted_objects += other.deleted_objects;
        self.deleted_bytes += other.deleted_bytes;
        self.expired_heads += other.expired_heads;
        self.deleted_side_commits += other.deleted_side_commits;
        self.lapsed_pins += other.lapsed_pins;
        self.deleted_folders += other.deleted_folders;
    }
}

/// How a step treats retained data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The rules of the ADR.
    Normal,
    /// The operator's immediate purge: keep only live trees and young uploads; delete every
    /// other commit (bodies included), every pin and every retired folder.
    PurgeRetained,
}

/// Files to remove after the transaction.
struct Doomed {
    objects: Vec<ObjectKey>,
    /// Deleted folders of the account, each with a tombstone until its files are gone.
    folders: Vec<(AccountId, FolderId)>,
    account_pk: i64,
}

/// One step over every account, then the housekeeping of expired rows.
pub async fn run_step(app: &App) -> ApiResult<Outcome> {
    let accounts: Vec<i64> = sqlx::query_scalar("SELECT pk FROM accounts ORDER BY pk")
        .fetch_all(&app.db)
        .await?;
    let mut total = Outcome::default();
    for pk in accounts {
        total.add(account_step(app, pk, Mode::Normal).await?);
    }
    housekeeping(app).await?;
    Ok(total)
}

/// Deletes expired sessions, challenges, pairing slots and old invites.
pub async fn housekeeping(app: &App) -> ApiResult<()> {
    let now = i64_of(app.now_ms());
    let mut tx = begin_write(&app.db).await?;
    for sql in [
        "DELETE FROM sessions WHERE expires_ms <= ?",
        "DELETE FROM used_challenges WHERE expires_ms <= ?",
        "DELETE FROM pairing WHERE expires_ms <= ?",
    ] {
        sqlx::query(sql).bind(now).execute(&mut *tx).await?;
    }
    // Used or expired invites are kept a month for the operator's status, then go.
    sqlx::query("DELETE FROM invites WHERE expires_ms <= ?")
        .bind(now - i64_of(30 * 86_400_000))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// The step for one account (module docs).
pub async fn account_step(app: &App, account_pk: i64, mode: Mode) -> ApiResult<Outcome> {
    let now = app.now_ms();
    let limits = app.limits;
    let window_start = now.saturating_sub(limits.retention_ms);
    let mut outcome = Outcome::default();
    let mut pushed: Vec<Pushed> = Vec::new();
    let mut tx = begin_write(&app.db).await?;
    let Some(account) = crate::app::account_by_pk(&mut tx, account_pk).await? else {
        return Ok(outcome);
    };
    let mut doomed = Doomed {
        objects: Vec::new(),
        folders: Vec::new(),
        account_pk,
    };

    // Pins that ended (all of them in a purge).
    sqlx::query("DELETE FROM pins WHERE account_pk = ? AND (until_ms <= ? OR ? = 1)")
        .bind(account_pk)
        .bind(i64_of(now))
        .bind(i64::from(mode == Mode::PurgeRetained))
        .execute(&mut *tx)
        .await?;

    // Retired folders past their window (all of them in a purge) that no standing pin holds,
    // and folders that never got a commit and hold nothing a day after they were made. A pin
    // that lapsed holds nothing beyond the normal rules and goes with its folder.
    let retire_limit = if mode == Mode::PurgeRetained {
        now + 1
    } else {
        window_start
    };
    let gone: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT pk, id FROM folders WHERE account_pk = ? AND \
         ((retired_ms IS NOT NULL AND retired_ms <= ? \
           AND NOT EXISTS (SELECT 1 FROM pins p WHERE p.folder_pk = folders.pk AND p.lapsed_ms IS NULL)) OR \
          (head_pk IS NULL AND created_ms <= ? AND NOT EXISTS (SELECT 1 FROM objects o WHERE o.folder_pk = folders.pk)))",
    )
    .bind(account_pk)
    .bind(i64_of(retire_limit))
    .bind(i64_of(now.saturating_sub(PENDING_MS)))
    .fetch_all(&mut *tx)
    .await?;
    for (pk, id) in gone {
        sqlx::query("DELETE FROM pins WHERE folder_pk = ?")
            .bind(pk)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM folders WHERE pk = ?")
            .bind(pk)
            .execute(&mut *tx)
            .await?;
        // Until its files are removed, the folder cannot be made again (overall review N2).
        sqlx::query(
            "INSERT OR IGNORE INTO folder_tombstones (account_pk, folder_id, created_ms) VALUES (?, ?, ?)",
        )
        .bind(account_pk)
        .bind(id.as_slice())
        .bind(i64_of(now))
        .execute(&mut *tx)
        .await?;
        outcome.deleted_folders += 1;
    }

    reset_temp_tables(&mut tx).await?;
    let window_from = if mode == Mode::PurgeRetained {
        u64::MAX
    } else {
        window_start
    };

    // Classes 1 and 2: the window range of every folder with a head. A retired folder has no
    // live tree; once the window after its retirement ended, only a pin can still hold it
    // (class 3, within the pin cap), so it has no range.
    sqlx::query(
        "INSERT INTO gc_ranges (folder_pk, lo, hi) \
         SELECT f.pk, COALESCE(MIN(c.seq), f.seq), f.seq FROM folders f \
         LEFT JOIN commits c ON c.folder_pk = f.pk AND c.role = 'head' AND c.expired = 0 \
              AND (c.superseded_ms IS NULL OR c.superseded_ms > ?) \
         WHERE f.account_pk = ? AND f.head_pk IS NOT NULL \
           AND (f.retired_ms IS NULL OR f.retired_ms > ?) GROUP BY f.pk",
    )
    .bind(i64_of(window_from.min(i64::MAX as u64)))
    .bind(account_pk)
    .bind(i64_of(window_start))
    .execute(&mut *tx)
    .await?;
    if mode == Mode::PurgeRetained {
        // Only the current head of each folder.
        sqlx::query("UPDATE gc_ranges SET lo = hi")
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT OR IGNORE INTO gc_keep (object_pk) SELECT r.object_pk FROM refs r \
         JOIN gc_ranges g ON g.folder_pk = r.folder_pk \
         WHERE r.added_seq <= g.hi AND (r.dropped_seq IS NULL OR r.dropped_seq > g.lo)",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO gc_heads (commit_pk) SELECT c.pk FROM commits c \
         JOIN gc_ranges g ON g.folder_pk = c.folder_pk \
         WHERE c.role = 'head' AND c.seq >= g.lo AND c.seq <= g.hi",
    )
    .execute(&mut *tx)
    .await?;
    // Side commits in their window: what they add (not their base, module docs).
    if mode == Mode::Normal {
        sqlx::query(
            "INSERT OR IGNORE INTO gc_keep (object_pk) SELECT s.object_pk FROM side_refs s \
             JOIN commits c ON c.pk = s.commit_pk JOIN folders f ON f.pk = c.folder_pk \
             WHERE f.account_pk = ? AND c.superseded_ms > ?",
        )
        .bind(account_pk)
        .bind(i64_of(window_start))
        .execute(&mut *tx)
        .await?;
    }
    // Young uploads without a commit.
    sqlx::query(
        "INSERT OR IGNORE INTO gc_keep (object_pk) SELECT o.pk FROM objects o JOIN folders f ON f.pk = o.folder_pk \
         WHERE f.account_pk = ? AND o.declared = 0 AND o.uploaded_ms > ?",
    )
    .bind(account_pk)
    .bind(i64_of(now.saturating_sub(PENDING_MS)))
    .execute(&mut *tx)
    .await?;

    // Class 3: pins in creation order.
    type PinRow = (i64, i64, i64, Vec<u8>, Vec<u8>, i64);
    let pins: Vec<PinRow> = sqlx::query_as(
        "SELECT p.pk, p.folder_pk, p.seq, p.commit_id, f.id, p.until_ms FROM pins p JOIN folders f ON f.pk = p.folder_pk \
         WHERE p.account_pk = ? AND p.lapsed_ms IS NULL ORDER BY p.created_ms, p.pk",
    )
    .bind(account_pk)
    .fetch_all(&mut *tx)
    .await?;
    let pin_cap = limits.pin_cap();
    let mut pin_bytes = 0u64;
    let mut cap_reached = false;
    for (pin_pk, folder_pk, seq, commit_id, folder_id, _until) in pins {
        let extra = tree_extra_bytes(&mut tx, folder_pk, u64_of(seq)).await?;
        if pin_bytes.saturating_add(extra) <= pin_cap {
            pin_bytes += extra;
            keep_tree(&mut tx, folder_pk, u64_of(seq)).await?;
            continue;
        }
        cap_reached = true;
        sqlx::query("UPDATE pins SET lapsed_ms = ? WHERE pk = ?")
            .bind(i64_of(now))
            .bind(pin_pk)
            .execute(&mut *tx)
            .await?;
        outcome.lapsed_pins += 1;
        let (Some(folder), Some(commit)) = (
            FolderId::from_slice(&folder_id),
            CommitId::from_slice(&commit_id),
        ) else {
            continue;
        };
        tracing::warn!(account = %account.id, %commit, "operator warning: an anomaly pin lapsed under the pin cap");
        // The pin notice again, ending now: the devices show that the pin lapsed.
        pushed.push(
            feed::push(
                &mut tx,
                account_pk,
                &FeedChange::Notice {
                    notice: Notice::AnomalyPin {
                        folder,
                        commit,
                        until_ms: now,
                    },
                },
            )
            .await?,
        );
    }
    if cap_reached || (pin_cap > 0 && pin_bytes >= pin_cap) {
        notices::raise_in(&mut tx, account_pk, WARN_PIN_CAP, None).await?;
    } else {
        notices::clear_in(&mut tx, account_pk, WARN_PIN_CAP).await?;
    }

    // Class 4: the minimum count, oldest window end first.
    if mode == Mode::Normal {
        let candidates: Vec<(i64, i64, i64)> = sqlx::query_as(
            "SELECT c.pk, c.folder_pk, c.seq FROM commits c JOIN folders f ON f.pk = c.folder_pk \
             JOIN gc_ranges g ON g.folder_pk = c.folder_pk \
             WHERE f.account_pk = ? AND f.retired_ms IS NULL AND c.role = 'head' AND c.expired = 0 \
               AND c.seq < g.lo AND c.seq > f.seq - ? \
             ORDER BY c.superseded_ms, c.seq",
        )
        .bind(account_pk)
        .bind(i64::from(limits.min_commits))
        .fetch_all(&mut *tx)
        .await?;
        let mut held = 0u64;
        let mut over = false;
        for (commit_pk, folder_pk, seq) in candidates {
            let extra = tree_extra_bytes(&mut tx, folder_pk, u64_of(seq)).await?;
            if held.saturating_add(extra) > limits.min_count_cap {
                over = true;
                continue;
            }
            held += extra;
            keep_tree(&mut tx, folder_pk, u64_of(seq)).await?;
            sqlx::query("INSERT OR IGNORE INTO gc_heads (commit_pk) VALUES (?)")
                .bind(commit_pk)
                .execute(&mut *tx)
                .await?;
        }
        if over {
            if let Some(p) = notices::raise_in(
                &mut tx,
                account_pk,
                WARN_MIN_COUNT,
                Some(Notice::MinimumCountCap {
                    held_bytes: held,
                    cap_bytes: limits.min_count_cap,
                }),
            )
            .await?
            {
                pushed.push(p);
            }
        } else {
            notices::clear_in(&mut tx, account_pk, WARN_MIN_COUNT).await?;
        }
    }

    // Heads that pins and the minimum count hold keep their tree as well.
    sqlx::query(
        "INSERT OR IGNORE INTO gc_heads (commit_pk) SELECT c.pk FROM commits c \
         JOIN gc_points p ON p.folder_pk = c.folder_pk AND p.seq = c.seq WHERE c.role = 'head'",
    )
    .execute(&mut *tx)
    .await?;

    // Expire, delete side commits and heads (purge), and the objects nothing retains.
    if mode == Mode::PurgeRetained {
        let deleted = sqlx::query(
            "DELETE FROM commits WHERE folder_pk IN (SELECT pk FROM folders WHERE account_pk = ?) \
             AND pk NOT IN (SELECT commit_pk FROM gc_heads)",
        )
        .bind(account_pk)
        .execute(&mut *tx)
        .await?;
        outcome.deleted_side_commits += deleted.rows_affected();
    } else {
        let deleted = sqlx::query(
            "DELETE FROM commits WHERE role = 'side' AND superseded_ms <= ? \
             AND folder_pk IN (SELECT pk FROM folders WHERE account_pk = ?)",
        )
        .bind(i64_of(window_start))
        .bind(account_pk)
        .execute(&mut *tx)
        .await?;
        outcome.deleted_side_commits += deleted.rows_affected();
        let expired = sqlx::query(
            "UPDATE commits SET expired = 1, server_ms = NULL, superseded_ms = NULL \
             WHERE role = 'head' AND expired = 0 AND folder_pk IN (SELECT pk FROM folders WHERE account_pk = ?) \
             AND pk NOT IN (SELECT commit_pk FROM gc_heads)",
        )
        .bind(account_pk)
        .execute(&mut *tx)
        .await?;
        outcome.expired_heads += expired.rows_affected();
    }
    let unretained: Vec<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT f.id, o.object_id, o.size FROM objects o JOIN folders f ON f.pk = o.folder_pk \
         WHERE f.account_pk = ? AND o.pk NOT IN (SELECT object_pk FROM gc_keep)",
    )
    .bind(account_pk)
    .fetch_all(&mut *tx)
    .await?;
    for (folder, id, size) in unretained {
        if let (Some(folder), Some(id)) = (FolderId::from_slice(&folder), ObjectId::from_slice(&id))
        {
            doomed.objects.push(ObjectKey {
                account: account.id,
                folder,
                id,
            });
        }
        outcome.deleted_objects += 1;
        outcome.deleted_bytes += u64_of(size);
    }
    sqlx::query(
        "DELETE FROM objects WHERE folder_pk IN (SELECT pk FROM folders WHERE account_pk = ?) \
         AND pk NOT IN (SELECT object_pk FROM gc_keep)",
    )
    .bind(account_pk)
    .execute(&mut *tx)
    .await?;

    // Rolling counters.
    usage::recount_pending(&mut tx, account_pk).await?;
    sqlx::query("DELETE FROM budget_minutes WHERE account_pk = ? AND minute_ms <= ?")
        .bind(account_pk)
        .bind(i64_of(now.saturating_sub(BUDGET_WINDOW_MS)))
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM allowance_minutes WHERE account_pk = ? AND minute_ms <= ?")
        .bind(account_pk)
        .bind(i64_of(window_start))
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM drop_events WHERE at_ms <= ? AND folder_pk IN (SELECT pk FROM folders WHERE account_pk = ?)",
    )
    .bind(i64_of(now.saturating_sub(crate::service::commits::BURST_WINDOW_MS)))
    .bind(account_pk)
    .execute(&mut *tx)
    .await?;

    // Warnings that ended, and retained bytes above the quota.
    let live = usage::live(&mut tx, account_pk).await?;
    let stored: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(o.size), 0) FROM objects o JOIN folders f ON f.pk = o.folder_pk WHERE f.account_pk = ?",
    )
    .bind(account_pk)
    .fetch_one(&mut *tx)
    .await?;
    let retained = u64_of(stored).saturating_sub(live.all());
    if retained > limits.quota {
        if let Some(p) = notices::raise_in(
            &mut tx,
            account_pk,
            WARN_RETAINED,
            Some(Notice::RetainedOverQuota {
                retained_bytes: retained,
                quota_bytes: limits.quota,
            }),
        )
        .await?
        {
            pushed.push(p);
        }
    } else {
        notices::clear_in(&mut tx, account_pk, WARN_RETAINED).await?;
    }
    if live.all() < limits.quota / 10 * 9 {
        notices::clear_in(&mut tx, account_pk, WARN_QUOTA).await?;
    }
    if !usage::below_disk_reserve(app) {
        notices::clear_in(&mut tx, account_pk, WARN_DISK).await?;
    }
    let account_used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(bytes), 0) FROM budget_minutes WHERE account_pk = ?",
    )
    .bind(account_pk)
    .fetch_one(&mut *tx)
    .await?;
    if u64_of(account_used) < limits.account_budget {
        notices::clear_in(&mut tx, account_pk, WARN_ACCOUNT_BUDGET).await?;
    }
    sqlx::query(
        "DELETE FROM device_warnings WHERE account_pk = ? AND \
         (SELECT COALESCE(SUM(b.bytes), 0) FROM budget_minutes b WHERE b.account_pk = device_warnings.account_pk AND b.device = device_warnings.device) < ?",
    )
    .bind(account_pk)
    .bind(i64_of(limits.device_budget))
    .execute(&mut *tx)
    .await?;

    // Every tombstone of the account, also one a crash left behind before its files went.
    let tombstones: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT folder_id FROM folder_tombstones WHERE account_pk = ?")
            .bind(account_pk)
            .fetch_all(&mut *tx)
            .await?;
    doomed.folders = tombstones
        .iter()
        .filter_map(|id| FolderId::from_slice(id))
        .map(|folder| (account.id, folder))
        .collect();
    tx.commit().await?;
    feed::notify_all(app, &pushed);
    remove_files(app, doomed).await;
    if outcome != Outcome::default() {
        tracing::info!(
            account = %account.id,
            deleted_objects = outcome.deleted_objects,
            deleted_bytes = outcome.deleted_bytes,
            expired_heads = outcome.expired_heads,
            deleted_side_commits = outcome.deleted_side_commits,
            lapsed_pins = outcome.lapsed_pins,
            deleted_folders = outcome.deleted_folders,
            "garbage collection"
        );
    }
    Ok(outcome)
}

async fn reset_temp_tables(tx: &mut Tx) -> ApiResult<()> {
    for sql in [
        "CREATE TEMP TABLE IF NOT EXISTS gc_keep (object_pk INTEGER PRIMARY KEY)",
        "CREATE TEMP TABLE IF NOT EXISTS gc_heads (commit_pk INTEGER PRIMARY KEY)",
        "CREATE TEMP TABLE IF NOT EXISTS gc_ranges (folder_pk INTEGER PRIMARY KEY, lo INTEGER NOT NULL, hi INTEGER NOT NULL)",
        "CREATE TEMP TABLE IF NOT EXISTS gc_points (folder_pk INTEGER NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY (folder_pk, seq)) WITHOUT ROWID",
        "DELETE FROM gc_keep",
        "DELETE FROM gc_heads",
        "DELETE FROM gc_ranges",
        "DELETE FROM gc_points",
    ] {
        sqlx::query(sql).execute(&mut **tx).await?;
    }
    Ok(())
}

/// Bytes of the tree at `seq` that nothing kept so far retains.
async fn tree_extra_bytes(tx: &mut Tx, folder_pk: i64, seq: u64) -> ApiResult<u64> {
    let bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(o.size), 0) FROM objects o WHERE o.pk IN \
           (SELECT r.object_pk FROM refs r WHERE r.folder_pk = ? AND r.added_seq <= ? AND (r.dropped_seq IS NULL OR r.dropped_seq > ?)) \
         AND o.pk NOT IN (SELECT object_pk FROM gc_keep)",
    )
    .bind(folder_pk)
    .bind(i64_of(seq))
    .bind(i64_of(seq))
    .fetch_one(&mut **tx)
    .await?;
    Ok(u64_of(bytes))
}

async fn keep_tree(tx: &mut Tx, folder_pk: i64, seq: u64) -> ApiResult<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO gc_keep (object_pk) SELECT r.object_pk FROM refs r \
         WHERE r.folder_pk = ? AND r.added_seq <= ? AND (r.dropped_seq IS NULL OR r.dropped_seq > ?)",
    )
    .bind(folder_pk)
    .bind(i64_of(seq))
    .bind(i64_of(seq))
    .execute(&mut **tx)
    .await?;
    sqlx::query("INSERT OR IGNORE INTO gc_points (folder_pk, seq) VALUES (?, ?)")
        .bind(folder_pk)
        .bind(i64_of(seq))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Removes the files of deleted rows. A file whose row came back (the same object uploaded
/// again after the transaction) stays.
async fn remove_files(app: &App, doomed: Doomed) {
    for (account, folder) in doomed.folders {
        let store = app.store.clone();
        match tokio::task::spawn_blocking(move || store.delete_folder(&account, &folder)).await {
            Ok(Ok(())) => {
                // Only now may the folder ID be used again (overall review N2). Should this
                // fail, the next step removes the (empty) directory again and retries.
                let cleared = sqlx::query(
                    "DELETE FROM folder_tombstones WHERE account_pk = ? AND folder_id = ?",
                )
                .bind(doomed.account_pk)
                .bind(folder.as_bytes().as_slice())
                .execute(&app.db)
                .await;
                if let Err(error) = cleared {
                    tracing::error!(%error, "clearing a deleted folder's tombstone failed");
                }
            }
            Ok(Err(error)) => {
                tracing::error!(%error, "removing a deleted folder's objects failed");
            }
            Err(error) => {
                tracing::error!(%error, "removing a deleted folder's objects failed");
            }
        }
    }
    remove_object_files(app, doomed.objects).await;
}

/// Removes the files of deleted object rows, each under the object's stripe lock and only if no
/// row came back in between (the same object uploaded again after the transaction).
pub async fn remove_object_files(app: &App, keys: Vec<ObjectKey>) {
    for key in keys {
        let lock_key = [
            key.folder.as_bytes().as_slice(),
            key.id.as_bytes().as_slice(),
        ]
        .concat();
        let _guard = app.object_locks.lock(&lock_key).await;
        match row_exists(app, &key).await {
            Ok(false) => {}
            Ok(true) => continue,
            Err(_) => continue,
        }
        let store = app.store.clone();
        if let Ok(Err(error)) = tokio::task::spawn_blocking(move || store.delete(&key)).await {
            tracing::error!(%error, "removing a deleted object failed");
        }
    }
}

async fn row_exists(app: &App, key: &ObjectKey) -> ApiResult<bool> {
    let hit: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM objects o JOIN folders f ON f.pk = o.folder_pk JOIN accounts a ON a.pk = f.account_pk \
         WHERE a.id = ? AND f.id = ? AND o.object_id = ?",
    )
    .bind(key.account.as_bytes().as_slice())
    .bind(key.folder.as_bytes().as_slice())
    .bind(key.id.as_bytes().as_slice())
    .fetch_optional(&app.db)
    .await?;
    Ok(hit.is_some())
}

/// Removes files the database does not know that are older than an hour (module docs).
pub async fn sweep_orphan_files(app: &App) -> ApiResult<u64> {
    let store = app.store.clone();
    let now = std::time::SystemTime::now();
    let candidates = tokio::task::spawn_blocking(move || {
        let mut found = Vec::new();
        store.walk(&mut |key, modified| {
            if now
                .duration_since(modified)
                .is_ok_and(|age| age >= ORPHAN_FILE_AGE)
            {
                found.push(key);
            }
        })?;
        Ok::<_, std::io::Error>(found)
    })
    .await
    .map_err(|e| ApiError::internal(&e))??;
    let mut removed = 0;
    for key in candidates {
        let lock_key = [
            key.folder.as_bytes().as_slice(),
            key.id.as_bytes().as_slice(),
        ]
        .concat();
        let _guard = app.object_locks.lock(&lock_key).await;
        if row_exists(app, &key).await? {
            continue;
        }
        let store = app.store.clone();
        tokio::task::spawn_blocking(move || store.delete(&key))
            .await
            .map_err(|e| ApiError::internal(&e))??;
        removed += 1;
    }
    if removed > 0 {
        tracing::info!(removed, "removed object files without a database row");
    }
    Ok(removed)
}

/// The background job: a step every `interval`, the file sweep once a day, until shutdown.
/// Steps never overlap (one task), and a failed step is logged and retried at the next tick.
pub async fn run_job(app: std::sync::Arc<App>, interval: Duration) {
    let mut shutdown = app.shutdown.clone();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_sweep: Option<std::time::Instant> = None;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.wait_for(|stop| *stop) => return,
        }
        let started = std::time::Instant::now();
        match run_step(&app).await {
            Ok(_) => tracing::debug!(
                ms = started.elapsed().as_millis() as u64,
                "garbage collection step done"
            ),
            Err(error) => tracing::error!(?error, "garbage collection step failed"),
        }
        if last_sweep.is_none_or(|t| t.elapsed() >= Duration::from_secs(86_400)) {
            last_sweep = Some(std::time::Instant::now());
            if let Err(error) = sweep_orphan_files(&app).await {
                tracing::error!(?error, "file sweep failed");
            }
        }
    }
}
