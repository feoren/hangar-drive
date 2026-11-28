//! Quota, upload budgets, the pin restore allowance and the disk reserve (ADR 0001, section 5,
//! "Quota and retained storage").
//!
//! - **Live bytes** are the padded sizes of the objects in the current heads of the account's
//!   folders that are not retired, kept as counters per folder and account and changed in the
//!   same transaction as every head. Chunks and file manifests (data) and directory nodes are
//!   counted apart, because directory nodes may use the headroom.
//! - **Upload check:** a data object must keep live data plus the uploading device's own
//!   uncommitted data within Q, and every object must keep all live bytes plus the device's own
//!   uncommitted bytes within Q + H. Counting only data against Q mirrors the commit check, and
//!   deletes (new directory nodes only) still succeed at a full quota while the headroom is
//!   free. Only the device's own uploads count (security review MEDIUM 3): otherwise one
//!   compromised device could upload a quota of garbage it never commits and lock every honest
//!   device out for 24 hours. What all devices together leave uncommitted is bounded by the
//!   account budget, since every upload pays it, and the commit check still holds live bytes to
//!   the quota. Removing a device deletes its uncommitted uploads at once
//!   ([`crate::service::objects::drop_uploads_of`]).
//! - **Commit check:** refused only if it raises data above Q or all live bytes above Q + H.
//! - **Budgets:** bytes made live per rolling 24 hours, per device and per account: uploads at
//!   upload, retained objects a commit revives at the commit. The device budget defaults to half
//!   the account budget ([`crate::config::Limits::for_quota`]), so one device never uses up the
//!   budget of the others.
//! - **Pin restore allowance:** revived objects in the tree of an admitted pin cost no budget up
//!   to P = Q + H per account in any rolling window W.
//! - **Running counters** (finding M4): uncommitted uploads are a counter per account, changed
//!   with every upload and declaration, and one per device in `device_pending`, kept by triggers
//!   on `objects` (migration `0004_device_uploads.sql`); budgets and the allowance are kept per minute, so no
//!   request sums over every upload of a day. A minute counts while it started within the
//!   window, so a byte leaves a rolling window at most a minute early.

use hangar_drive_protocol::ids::DeviceId;
use hangar_drive_protocol::object::ObjectType;

use crate::app::App;
use crate::config::Limits;
use crate::db::{i64_of, u64_of};
use crate::error::ApiResult;

pub const BUDGET_WINDOW_MS: u64 = 86_400_000;
/// Width of one budget and allowance counter.
pub const MINUTE_MS: u64 = 60_000;

fn minute_of(ms: u64) -> u64 {
    ms - ms % MINUTE_MS
}

/// Data (chunks and manifests) and directory node bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bytes {
    pub data: u64,
    pub dir: u64,
}

impl Bytes {
    pub fn all(&self) -> u64 {
        self.data.saturating_add(self.dir)
    }

    pub fn of(kind: ObjectType, size: u64) -> Self {
        if kind == ObjectType::DirectoryNode {
            Self { data: 0, dir: size }
        } else {
            Self { data: size, dir: 0 }
        }
    }

    pub fn add(&mut self, other: Bytes) {
        self.data = self.data.saturating_add(other.data);
        self.dir = self.dir.saturating_add(other.dir);
    }
}

/// The object type of a stored `kind` byte; unknown bytes never pass the upload check.
pub fn kind_of(byte: i64) -> ObjectType {
    u8::try_from(byte)
        .ok()
        .and_then(|b| ObjectType::from_byte(b).ok())
        .unwrap_or(ObjectType::Chunk)
}

pub async fn live(conn: &mut sqlx::SqliteConnection, account_pk: i64) -> ApiResult<Bytes> {
    let (data, dir): (i64, i64) =
        sqlx::query_as("SELECT live_data_bytes, live_dir_bytes FROM accounts WHERE pk = ?")
            .bind(account_pk)
            .fetch_one(&mut *conn)
            .await?;
    Ok(Bytes {
        data: u64_of(data),
        dir: u64_of(dir),
    })
}

/// Uploads no commit has declared yet (a running counter).
pub async fn pending(conn: &mut sqlx::SqliteConnection, account_pk: i64) -> ApiResult<Bytes> {
    let (data, dir): (i64, i64) =
        sqlx::query_as("SELECT pending_data_bytes, pending_dir_bytes FROM accounts WHERE pk = ?")
            .bind(account_pk)
            .fetch_one(&mut *conn)
            .await?;
    Ok(Bytes {
        data: u64_of(data),
        dir: u64_of(dir),
    })
}

/// Uncommitted uploads of one device of the account (a running counter kept by triggers).
pub async fn device_pending(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    device: &DeviceId,
) -> ApiResult<Bytes> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT data_bytes, dir_bytes FROM device_pending WHERE account_pk = ? AND device = ?",
    )
    .bind(account_pk)
    .bind(device.as_bytes().as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map_or_else(Bytes::default, |(data, dir)| Bytes {
        data: u64_of(data),
        dir: u64_of(dir),
    }))
}

/// Adds (`sign` 1) or removes (`sign` -1) uncommitted bytes.
pub async fn shift_pending(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    bytes: Bytes,
    sign: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE accounts SET pending_data_bytes = MAX(0, pending_data_bytes + ?), \
         pending_dir_bytes = MAX(0, pending_dir_bytes + ?) WHERE pk = ?",
    )
    .bind(sign.saturating_mul(i64_of(bytes.data)))
    .bind(sign.saturating_mul(i64_of(bytes.dir)))
    .bind(account_pk)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Sets the counters of uncommitted bytes, per account and per device, from the objects
/// themselves. The garbage collection, the purges and a device removal call it after they
/// delete objects, so the counters never drift for long.
pub async fn recount_pending(conn: &mut sqlx::SqliteConnection, account_pk: i64) -> ApiResult<()> {
    sqlx::query("DELETE FROM device_pending WHERE account_pk = ?")
        .bind(account_pk)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO device_pending (account_pk, device, data_bytes, dir_bytes) \
         SELECT f.account_pk, o.uploader, \
                COALESCE(SUM(CASE WHEN o.kind <> 3 THEN o.size ELSE 0 END), 0), \
                COALESCE(SUM(CASE WHEN o.kind = 3 THEN o.size ELSE 0 END), 0) \
         FROM objects o JOIN folders f ON f.pk = o.folder_pk \
         WHERE f.account_pk = ? AND o.declared = 0 AND o.uploader IS NOT NULL \
         GROUP BY f.account_pk, o.uploader",
    )
    .bind(account_pk)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE accounts SET \
           pending_data_bytes = (SELECT COALESCE(SUM(o.size), 0) FROM objects o JOIN folders f ON f.pk = o.folder_pk \
                                 WHERE f.account_pk = accounts.pk AND o.declared = 0 AND o.kind <> 3), \
           pending_dir_bytes = (SELECT COALESCE(SUM(o.size), 0) FROM objects o JOIN folders f ON f.pk = o.folder_pk \
                                WHERE f.account_pk = accounts.pk AND o.declared = 0 AND o.kind = 3) \
         WHERE pk = ?",
    )
    .bind(account_pk)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The upload check (module docs); `pending` is the uploading device's own uncommitted bytes.
pub fn upload_fits(limits: &Limits, live: Bytes, pending: Bytes, new: Bytes) -> bool {
    let all = live
        .all()
        .saturating_add(pending.all())
        .saturating_add(new.all());
    if all > limits.pin_cap() {
        return false;
    }
    new.data == 0
        || live
            .data
            .saturating_add(pending.data)
            .saturating_add(new.data)
            <= limits.quota
}

/// The commit check (module docs).
pub fn commit_fits(limits: &Limits, before: Bytes, after: Bytes) -> bool {
    let data_ok = after.data <= before.data || after.data <= limits.quota;
    let all_ok = after.all() <= before.all() || after.all() <= limits.pin_cap();
    data_ok && all_ok
}

/// Which budget an upload or revival would exceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetHit {
    Device,
    Account,
}

/// Bytes the device and the account made live in the rolling 24 hours.
pub async fn budget_used(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    device: &DeviceId,
    now_ms: u64,
) -> ApiResult<(u64, u64)> {
    let since = i64_of(now_ms.saturating_sub(BUDGET_WINDOW_MS));
    let (device_used, account_used): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(CASE WHEN device = ? THEN bytes ELSE 0 END), 0), COALESCE(SUM(bytes), 0) \
         FROM budget_minutes WHERE account_pk = ? AND minute_ms > ?",
    )
    .bind(device.as_bytes().as_slice())
    .bind(account_pk)
    .bind(since)
    .fetch_one(&mut *conn)
    .await?;
    Ok((u64_of(device_used), u64_of(account_used)))
}

/// Checks and records `bytes` made live by `device`. On a hit nothing is recorded; the caller
/// rolls back and raises the notice in a transaction of its own.
pub async fn charge_budget(
    conn: &mut sqlx::SqliteConnection,
    limits: &Limits,
    account_pk: i64,
    device: &DeviceId,
    bytes: u64,
    now_ms: u64,
) -> ApiResult<Result<(), BudgetHit>> {
    if bytes == 0 {
        return Ok(Ok(()));
    }
    let (device_used, account_used) = budget_used(conn, account_pk, device, now_ms).await?;
    if device_used.saturating_add(bytes) > limits.device_budget {
        return Ok(Err(BudgetHit::Device));
    }
    if account_used.saturating_add(bytes) > limits.account_budget {
        return Ok(Err(BudgetHit::Account));
    }
    sqlx::query(
        "INSERT INTO budget_minutes (account_pk, device, minute_ms, bytes) VALUES (?, ?, ?, ?) \
         ON CONFLICT (account_pk, minute_ms, device) DO UPDATE SET bytes = bytes + excluded.bytes",
    )
    .bind(account_pk)
    .bind(device.as_bytes().as_slice())
    .bind(i64_of(minute_of(now_ms)))
    .bind(i64_of(bytes))
    .execute(&mut *conn)
    .await?;
    Ok(Ok(()))
}

/// What of `bytes` (revived from an admitted pin's tree) the allowance still covers; records it.
pub async fn take_allowance(
    conn: &mut sqlx::SqliteConnection,
    limits: &Limits,
    account_pk: i64,
    bytes: u64,
    now_ms: u64,
) -> ApiResult<u64> {
    if bytes == 0 {
        return Ok(0);
    }
    let since = i64_of(now_ms.saturating_sub(limits.retention_ms));
    let used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(bytes), 0) FROM allowance_minutes WHERE account_pk = ? AND minute_ms > ?",
    )
    .bind(account_pk)
    .bind(since)
    .fetch_one(&mut *conn)
    .await?;
    let free = limits.pin_cap().saturating_sub(u64_of(used));
    let covered = free.min(bytes);
    if covered > 0 {
        sqlx::query(
            "INSERT INTO allowance_minutes (account_pk, minute_ms, bytes) VALUES (?, ?, ?) \
             ON CONFLICT (account_pk, minute_ms) DO UPDATE SET bytes = bytes + excluded.bytes",
        )
        .bind(account_pk)
        .bind(i64_of(minute_of(now_ms)))
        .bind(i64_of(covered))
        .execute(&mut *conn)
        .await?;
    }
    Ok(covered)
}

/// Whether the disk is below its reserve. `None` from the platform counts as enough space.
/// Bytes that uploads in flight announced but have not written yet count as used (finding M5).
pub fn below_disk_reserve(app: &App) -> bool {
    !disk_has_room(app, 0)
}

/// Whether `extra` more bytes keep the disk above its reserve, counting the bytes uploads in
/// flight still write.
pub fn disk_has_room(app: &App, extra: u64) -> bool {
    app.disk.available().is_none_or(|free| {
        free.saturating_sub(app.staging.outstanding())
            .saturating_sub(extra)
            >= app.limits.disk_reserve
    })
}

/// Moves a folder's live bytes into or out of the account's (retire, bring back, purge).
pub async fn shift_account_live(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    data: i64,
    dir: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE accounts SET live_data_bytes = MAX(0, live_data_bytes + ?), live_dir_bytes = MAX(0, live_dir_bytes + ?) WHERE pk = ?",
    )
    .bind(data)
    .bind(dir)
    .bind(account_pk)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Raises the account's count of folder removals (migration 0006), in the transaction that
/// deletes folders of the account. An upload in flight compares it before and after putting its
/// file in place (`service::objects::store`).
pub async fn count_folder_removal(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
) -> ApiResult<()> {
    sqlx::query("UPDATE accounts SET folder_removals = folder_removals + 1 WHERE pk = ?")
        .bind(account_pk)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The account's count of folder removals; `None` once the account is gone.
pub async fn folder_removals(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
) -> ApiResult<Option<i64>> {
    Ok(
        sqlx::query_scalar("SELECT folder_removals FROM accounts WHERE pk = ?")
            .bind(account_pk)
            .fetch_optional(&mut *conn)
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        let mut l = Limits::for_quota(1000);
        l.headroom = 100;
        l
    }

    fn data(n: u64) -> Bytes {
        Bytes { data: n, dir: 0 }
    }

    fn dir(n: u64) -> Bytes {
        Bytes { data: 0, dir: n }
    }

    #[test]
    fn uploads_of_data_stop_at_the_quota_and_directory_nodes_use_the_headroom() {
        let l = limits();
        assert!(upload_fits(&l, data(900), data(50), data(50)));
        assert!(!upload_fits(&l, data(900), data(50), data(51)));
        assert!(upload_fits(&l, data(1000), dir(50), dir(50)));
        assert!(!upload_fits(&l, data(1000), dir(50), dir(51)));
        // Directory bytes do not take room from data below the quota, but the total is capped.
        assert!(upload_fits(
            &l,
            Bytes { data: 900, dir: 90 },
            Bytes::default(),
            data(100)
        ));
        assert!(!upload_fits(
            &l,
            Bytes {
                data: 900,
                dir: 101
            },
            Bytes::default(),
            data(100)
        ));
    }

    #[test]
    fn commits_that_do_not_raise_live_bytes_always_pass() {
        let l = limits();
        let full = Bytes {
            data: 1200,
            dir: 50,
        };
        assert!(commit_fits(
            &l,
            full,
            Bytes {
                data: 1100,
                dir: 60
            }
        ));
        assert!(!commit_fits(&l, data(900), data(1001)));
        assert!(commit_fits(&l, data(900), data(1000)));
        assert!(!commit_fits(
            &l,
            Bytes {
                data: 1000,
                dir: 90
            },
            Bytes {
                data: 1000,
                dir: 101
            }
        ));
        assert!(commit_fits(
            &l,
            Bytes {
                data: 1000,
                dir: 90
            },
            Bytes {
                data: 1000,
                dir: 100
            }
        ));
    }
}
