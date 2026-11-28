//! The device log on the server (ADR 0001, section 4): pages of entries, the atomic append that
//! `AccountState::admit_batch` and `append_wraps_fit` check, and each device's wrapped epoch
//! secrets. A removal ends the removed devices' sessions and deletes their uncommitted uploads in
//! the same transaction.
//!
//! **Throttle** (server security review, follow-up of the crypto review): the log has a fixed
//! length limit, so a compromised current device that appended rotations as fast as the call
//! limits allowed (about 8000 calls in three minutes) filled it, and the device could no longer
//! be removed. Appends that add a device or rotate without a removal count against
//! [`Scope::LogAppendAccount`], rotations without a removal also against
//! [`Scope::LogRotateAccount`] (one an hour). A batch that removes devices, the rotation the log
//! has due and the one append of a recovery session (the recovery batch, which adds the new
//! device and lets it remove and rotate in the same call) are never limited.
//!
//! **Added devices per day** (security review follow-up, M1): a device that adds a throwaway
//! device, removes it and rotates appends three entries per added device, and removals are
//! free, so thirty adds an hour filled the log up to its reserve in about four days. Adds also
//! count against [`ADDS_PER_DAY`] per account and day, which bounds that to 60 entries a day:
//! about 134 days from an empty log to the reserve, which still keeps every device removable.
//! Twenty new devices in one day is far above any household's pairing. The log has no time of
//! its own, so this is a server rule, not a format rule. The count lives in memory like the
//! other limits; until the limiter has a day scope of its own it is kept here. The log format reserves the room for removals as a first line; this is the second.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use hangar_drive_crypto::devicelog::BatchShape;
use hangar_drive_crypto::epoch::append_wraps_fit;
use hangar_drive_protocol::api::{
    ErrorCode, FeedChange, LogAppendRequest, LogAppendResponse, LogPage, WrappedKeyResponse,
    MAX_LOG_PAGE,
};
use hangar_drive_protocol::ids::{AccountId, Blob, Epoch};

use crate::app::{account_by_pk, App, AppState};
use crate::db::{begin_write, i64_of, u64_of};
use crate::error::{ApiError, ApiResult};
use crate::http::ratelimit::{RateLimiter, Scope};
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
    let recovery = matches!(
        session.scope,
        hangar_drive_protocol::api::SessionScope::Recovery { .. }
    );
    let throttled = Throttle::of(&batch.shape, state.rotation_due(), recovery);
    let now_s = app.now_ms() / 1000;
    if !throttled.admit(&app.limiter, &account.id, now_s) {
        return Err(ApiError::rate_limited(throttled.wait_s(
            &app.limiter,
            &account.id,
            now_s,
        )));
    }
    if recovery {
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
    // A recovery stores the new device's wrap of the epoch before the batch, then is a rotation.
    if let (BatchShape::Recovery { epoch, .. }, Some(wrap)) = (&batch.shape, &request.device_wrap) {
        if let Some(before) = epoch.0.checked_sub(1).filter(|e| *e > 0) {
            store_wrap(
                &mut tx,
                account.pk,
                Epoch(before),
                wrap.device.as_bytes(),
                wrap.data.as_bytes(),
            )
            .await?;
        }
    }
    match &batch.shape {
        BatchShape::Rotation { removed, epoch } | BatchShape::Recovery { removed, epoch, .. } => {
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

/// Which account limits an admitted append counts against (module docs, "Throttle").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Throttle {
    /// Removals with their rotation, the rotation the log has due, and the one append of a
    /// recovery session: never limited, so a stolen device always stays removable.
    Free,
    /// A new device.
    Append,
    /// A rotation without a removal that nothing made due.
    Rotation,
}

impl Throttle {
    fn of(shape: &BatchShape, rotation_due: bool, recovery: bool) -> Self {
        match shape {
            _ if recovery => Throttle::Free,
            BatchShape::Recovery { .. } => Throttle::Free,
            BatchShape::Rotation { removed, .. } if !removed.is_empty() || rotation_due => {
                Throttle::Free
            }
            BatchShape::Rotation { .. } => Throttle::Rotation,
            BatchShape::AddDevice { .. } => Throttle::Append,
        }
    }

    /// After a refused [`Throttle::admit`]: seconds until every limit that refused it has room
    /// again, for `Retry-After`.
    fn wait_s(self, limiter: &RateLimiter, account: &AccountId, now_s: u64) -> Option<u64> {
        let key = account.as_bytes().as_slice();
        let wait = |scope| {
            limiter
                .blocked(scope, key, now_s)
                .err()
                .map(|d| d.retry_after_s)
        };
        match self {
            Throttle::Free => None,
            Throttle::Append => {
                let day = day_adds().wait_s(account, now_s);
                day.max(wait(Scope::LogAppendAccount))
            }
            Throttle::Rotation => wait(Scope::LogAppendAccount).max(wait(Scope::LogRotateAccount)),
        }
    }

    /// Counts the append; `false` when a limit is used up. Nothing is counted then, so a
    /// refused rotation does not use up the account's appends.
    fn admit(self, limiter: &RateLimiter, account: &AccountId, now_s: u64) -> bool {
        let key = account.as_bytes().as_slice();
        match self {
            Throttle::Free => true,
            Throttle::Append => {
                let mut days = day_adds();
                if days.exceeded(account, now_s)
                    || !limiter.hit(Scope::LogAppendAccount, key, now_s)
                {
                    return false;
                }
                days.record(*account, now_s);
                true
            }
            Throttle::Rotation => {
                if limiter.exceeded(Scope::LogAppendAccount, key, now_s)
                    || limiter.exceeded(Scope::LogRotateAccount, key, now_s)
                {
                    return false;
                }
                limiter.hit(Scope::LogRotateAccount, key, now_s)
                    && limiter.hit(Scope::LogAppendAccount, key, now_s)
            }
        }
    }
}

/// Devices one account may add per day (module docs, "Added devices per day").
pub const ADDS_PER_DAY: usize = 20;
const DAY_S: u64 = 86_400;
/// Accounts whose adds of the last day are kept; above it, accounts without an add in the
/// last day are forgotten first.
const MAX_TRACKED_ACCOUNTS: usize = 100_000;

/// The times of each account's adds in the last day.
#[derive(Debug, Default)]
struct DayAdds(HashMap<AccountId, VecDeque<u64>>);

impl DayAdds {
    fn recent(&mut self, account: &AccountId, now_s: u64) -> usize {
        let Some(times) = self.0.get_mut(account) else {
            return 0;
        };
        while times
            .front()
            .is_some_and(|t| now_s.saturating_sub(*t) >= DAY_S)
        {
            times.pop_front();
        }
        times.len()
    }

    fn exceeded(&mut self, account: &AccountId, now_s: u64) -> bool {
        self.recent(account, now_s) >= ADDS_PER_DAY
    }

    /// Seconds until the oldest add of a full day leaves it.
    fn wait_s(&mut self, account: &AccountId, now_s: u64) -> Option<u64> {
        if !self.exceeded(account, now_s) {
            return None;
        }
        let oldest = self.0.get(account)?.front()?;
        Some(oldest.saturating_add(DAY_S).saturating_sub(now_s).max(1))
    }

    fn record(&mut self, account: AccountId, now_s: u64) {
        if self.0.len() >= MAX_TRACKED_ACCOUNTS && !self.0.contains_key(&account) {
            self.0.retain(|_, times| {
                times
                    .back()
                    .is_some_and(|t| now_s.saturating_sub(*t) < DAY_S)
            });
            if self.0.len() >= MAX_TRACKED_ACCOUNTS {
                // Only reachable with more busy accounts than any server holds; forgetting
                // makes the limit looser, never refuses an honest add.
                self.0.clear();
            }
        }
        self.0.entry(account).or_default().push_back(now_s);
    }
}

fn day_adds() -> std::sync::MutexGuard<'static, DayAdds> {
    static DAY_ADDS: OnceLock<Mutex<DayAdds>> = OnceLock::new();
    DAY_ADDS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_drive_protocol::ids::DeviceId;

    fn rotation(removed: usize) -> BatchShape {
        BatchShape::Rotation {
            removed: (0..removed)
                .map(|i| DeviceId::from_bytes([i as u8; 16]))
                .collect(),
            epoch: Epoch(2),
        }
    }

    #[test]
    fn removals_due_rotations_and_recovery_are_never_throttled() {
        let add = BatchShape::AddDevice {
            device: DeviceId::from_bytes([9; 16]),
        };
        let recovery = BatchShape::Recovery {
            by: DeviceId::from_bytes([8; 16]),
            device: DeviceId::from_bytes([9; 16]),
            removed: vec![DeviceId::from_bytes([7; 16])],
            epoch: Epoch(3),
        };
        assert_eq!(Throttle::of(&rotation(1), false, false), Throttle::Free);
        assert_eq!(Throttle::of(&rotation(0), true, false), Throttle::Free);
        assert_eq!(Throttle::of(&add, true, true), Throttle::Free);
        assert_eq!(Throttle::of(&rotation(0), false, true), Throttle::Free);
        assert_eq!(Throttle::of(&recovery, false, true), Throttle::Free);
        assert_eq!(Throttle::of(&recovery, false, false), Throttle::Free);
        assert_eq!(Throttle::of(&rotation(0), false, false), Throttle::Rotation);
        assert_eq!(Throttle::of(&add, false, false), Throttle::Append);
    }

    #[test]
    fn one_plain_rotation_an_hour_and_removals_after_every_limit() {
        let limiter = RateLimiter::new();
        let account = AccountId::from_bytes([0x71; 16]);
        assert!(Throttle::Rotation.admit(&limiter, &account, 0));
        assert!(!Throttle::Rotation.admit(&limiter, &account, 1));
        assert_eq!(Throttle::Rotation.wait_s(&limiter, &account, 1), Some(3599));
        let other = AccountId::from_bytes([0x72; 16]);
        assert!(Throttle::Rotation.admit(&limiter, &other, 1), "per account");
        // Adds: the day budget binds before the hourly appends do.
        for _ in 0..ADDS_PER_DAY {
            assert!(Throttle::Append.admit(&limiter, &account, 2));
        }
        assert!(!Throttle::Append.admit(&limiter, &account, 2));
        for _ in 0..1000 {
            assert!(Throttle::Free.admit(&limiter, &account, 2), "removals pass");
        }
        assert!(Throttle::Rotation.admit(&limiter, &account, 3600));
    }

    // Security review follow-up, M1: added devices count per account and day, a refused add
    // counts nothing, and a day later the budget is back.
    #[test]
    fn adds_are_bounded_per_day() {
        let limiter = RateLimiter::new();
        let account = AccountId::from_bytes([0x73; 16]);
        let hourly = Scope::LogAppendAccount.rule().limit as usize;
        assert!(ADDS_PER_DAY < hourly, "the day budget is the tighter one");
        // Spread over the day, so the hourly limit never binds.
        for k in 0..ADDS_PER_DAY {
            assert!(Throttle::Append.admit(&limiter, &account, k as u64 * 3600));
        }
        let late = (ADDS_PER_DAY as u64) * 3600;
        assert!(!Throttle::Append.admit(&limiter, &account, late));
        assert!(!Throttle::Append.admit(&limiter, &account, late + 1));
        assert_eq!(
            Throttle::Append.wait_s(&limiter, &account, late + 1),
            Some(DAY_S - late - 1),
            "until the first add of the day leaves it"
        );
        // The first add of the day leaves the window a day after it.
        assert!(Throttle::Append.admit(&limiter, &account, DAY_S));
        assert!(!Throttle::Append.admit(&limiter, &account, DAY_S + 1));
        // Another account has its own budget.
        let other = AccountId::from_bytes([0x74; 16]);
        assert!(Throttle::Append.admit(&limiter, &other, late));
    }
}
