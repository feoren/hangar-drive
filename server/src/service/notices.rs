//! Operator warnings and the matching feed notices (ADR 0001, section 5, "Operator warning").
//! Every condition is raised once when it starts (a bit in `accounts.warn_state`, a row in
//! `device_warnings`) and cleared by the garbage collection when it ends, so neither the log
//! nor the devices see the same warning on every request. The notice is one of the protocol's
//! closed list; the server sends no text of its own.

use hangar_drive_protocol::api::{FeedChange, Notice};
use hangar_drive_protocol::ids::DeviceId;

use crate::app::{account_by_pk, App};
use crate::db::begin_write;
use crate::error::ApiResult;
use crate::service::feed::{self, Pushed};
use crate::service::usage::BudgetHit;

pub const WARN_RETAINED: i64 = 1;
pub const WARN_MIN_COUNT: i64 = 1 << 1;
pub const WARN_PIN_CAP: i64 = 1 << 2;
pub const WARN_ACCOUNT_BUDGET: i64 = 1 << 3;
pub const WARN_QUOTA: i64 = 1 << 4;
pub const WARN_DISK: i64 = 1 << 5;

fn label(bit: i64) -> &'static str {
    match bit {
        WARN_RETAINED => "retained bytes exceed the account quota",
        WARN_MIN_COUNT => "bytes held only by the minimum commit count reached their cap",
        WARN_PIN_CAP => "bytes held only by anomaly pins reached the pin cap",
        WARN_ACCOUNT_BUDGET => "the account reached its upload budget",
        WARN_QUOTA => "live bytes are near the account quota",
        WARN_DISK => "the disk is below its free reserve; uploads are refused",
        _ => "warning",
    }
}

/// Raises `bit` with `notice` inside the caller's transaction if it is not raised yet.
pub async fn raise_in(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    bit: i64,
    notice: Option<Notice>,
) -> ApiResult<Option<Pushed>> {
    let set = sqlx::query(
        "UPDATE accounts SET warn_state = warn_state | ? WHERE pk = ? AND (warn_state & ?) = 0",
    )
    .bind(bit)
    .bind(account_pk)
    .bind(bit)
    .execute(&mut *conn)
    .await?;
    if set.rows_affected() == 0 {
        return Ok(None);
    }
    if let Some(account) = account_by_pk(conn, account_pk).await? {
        tracing::warn!(account = %account.id, warning = label(bit), "operator warning");
    }
    match notice {
        Some(notice) => Ok(Some(
            feed::push(conn, account_pk, &FeedChange::Notice { notice }).await?,
        )),
        None => Ok(None),
    }
}

/// Clears `bit` once the condition is over.
pub async fn clear_in(
    conn: &mut sqlx::SqliteConnection,
    account_pk: i64,
    bit: i64,
) -> ApiResult<()> {
    sqlx::query("UPDATE accounts SET warn_state = warn_state & ~? WHERE pk = ?")
        .bind(bit)
        .bind(account_pk)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Raises a condition in a transaction of its own (after the request's transaction was rolled
/// back because of it).
pub async fn raise(app: &App, account_pk: i64, bit: i64, notice: Notice) -> ApiResult<()> {
    let mut tx = begin_write(&app.db).await?;
    let pushed = raise_in(&mut tx, account_pk, bit, Some(notice)).await?;
    tx.commit().await?;
    if let Some(p) = pushed {
        p.notify(app);
    }
    Ok(())
}

/// A device or the account hit its upload budget.
pub async fn budget_hit(
    app: &App,
    account_pk: i64,
    device: &DeviceId,
    hit: BudgetHit,
) -> ApiResult<()> {
    match hit {
        BudgetHit::Account => {
            raise(app, account_pk, WARN_ACCOUNT_BUDGET, Notice::AccountBudget).await
        }
        BudgetHit::Device => {
            let mut tx = begin_write(&app.db).await?;
            let new = sqlx::query(
                "INSERT OR IGNORE INTO device_warnings (account_pk, device) VALUES (?, ?)",
            )
            .bind(account_pk)
            .bind(device.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
            let mut pushed = None;
            if new.rows_affected() == 1 {
                if let Some(account) = account_by_pk(&mut tx, account_pk).await? {
                    tracing::warn!(account = %account.id, %device, "operator warning: a device reached its upload budget");
                }
                pushed = Some(
                    feed::push(
                        &mut tx,
                        account_pk,
                        &FeedChange::Notice {
                            notice: Notice::DeviceBudget { device: *device },
                        },
                    )
                    .await?,
                );
            }
            tx.commit().await?;
            if let Some(p) = pushed {
                p.notify(app);
            }
            Ok(())
        }
    }
}
