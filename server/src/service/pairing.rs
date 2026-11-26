//! Pairing slots (ADR 0001, section 4, "Pairing"): the inviting device reserves a slot under the
//! pairing ID of its offer with its session, the new device posts its request into that slot
//! without a session, and the inviting device fetches it. The pairing ID is derived from the
//! 128-bit pairing secret of the offer; the server never learns the secret: the request's tag is
//! an HMAC under it, which the inviting device checks.
//!
//! Reservation (finding M2): a `POST` without a session may only fill a slot that a device of
//! some account reserved, that has not expired and that is still empty, exactly once. Before,
//! anyone could create slots under invented IDs until the server's slot limit refused every
//! real pairing. Now each account holds at most [`MAX_OPEN_PAIRINGS`] open slots, and only the
//! reserving account can read its slot.
//!
//! Lifetime (finding E2E-6): the request carries the new device's name sealed under a key only
//! the holders of the pairing secret derive, and the inviting device closes the slot with
//! `DELETE` once the person answered, so the request leaves the server at once; a slot nobody
//! closes is deleted when it expires, by the next reservation and by the periodic housekeeping
//! of the collection job (`retention::housekeeping`).

use hangar_drive_crypto::pairing::OFFER_LIFETIME_MS;
use hangar_drive_protocol::api::{
    ErrorCode, PairingRequest, PairingReservation, MAX_OPEN_PAIRINGS,
};
use hangar_drive_protocol::ids::PairingId;

use crate::app::App;
use crate::db::{begin_write, i64_of};
use crate::error::{ApiError, ApiResult};
use crate::service::sessions::Session;

/// `PUT /pairing/{id}` (the inviting device, before it shows the offer).
pub async fn reserve(app: &App, session: &Session, id: PairingId) -> ApiResult<PairingReservation> {
    let now = app.now_ms();
    let expires = now + OFFER_LIFETIME_MS;
    let mut tx = begin_write(&app.db).await?;
    sqlx::query("DELETE FROM pairing WHERE expires_ms <= ?")
        .bind(i64_of(now))
        .execute(&mut *tx)
        .await?;
    let owner: Option<i64> = sqlx::query_scalar("SELECT account_pk FROM pairing WHERE id = ?")
        .bind(id.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await?;
    match owner {
        Some(pk) if pk == session.account_pk => {
            // Reserving again is idempotent; the slot keeps its expiry.
            tx.commit().await?;
        }
        Some(_) => return Err(ErrorCode::AlreadyExists.into()),
        None => {
            let open: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing WHERE account_pk = ?")
                .bind(session.account_pk)
                .fetch_one(&mut *tx)
                .await?;
            if open >= i64::try_from(MAX_OPEN_PAIRINGS).unwrap_or(i64::MAX) {
                return Err(ErrorCode::RateLimited.into());
            }
            sqlx::query("INSERT INTO pairing (id, account_pk, expires_ms) VALUES (?, ?, ?)")
                .bind(id.as_bytes().as_slice())
                .bind(session.account_pk)
                .bind(i64_of(expires))
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
    }
    Ok(PairingReservation {
        expires_in_secs: u32::try_from(OFFER_LIFETIME_MS / 1000).unwrap_or(u32::MAX),
    })
}

/// `POST /pairing/{id}` (no session: the new device has none yet).
pub async fn post(app: &App, id: PairingId, request: PairingRequest) -> ApiResult<()> {
    request
        .validate()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    let now = app.now_ms();
    let json = serde_json::to_string(&request).map_err(|e| ApiError::internal(&e))?;
    let mut tx = begin_write(&app.db).await?;
    let filled = sqlx::query(
        "UPDATE pairing SET request = ? WHERE id = ? AND request IS NULL AND expires_ms > ?",
    )
    .bind(json)
    .bind(id.as_bytes().as_slice())
    .bind(i64_of(now))
    .execute(&mut *tx)
    .await?;
    if filled.rows_affected() == 1 {
        tx.commit().await?;
        return Ok(());
    }
    let reserved: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM pairing WHERE id = ? AND expires_ms > ?")
            .bind(id.as_bytes().as_slice())
            .bind(i64_of(now))
            .fetch_optional(&mut *tx)
            .await?;
    Err(match reserved {
        // Written once: nobody can replace a request that is already there.
        Some(_) => ErrorCode::AlreadyExists,
        None => ErrorCode::NotFound,
    }
    .into())
}

/// `DELETE /pairing/{id}` (the inviting device, once the person accepted or declined): deletes
/// the slot and the request in it. Only a slot of the session's account; closing a slot that is
/// gone already is no error, so a retry after a lost answer succeeds.
pub async fn close(app: &App, session: &Session, id: PairingId) -> ApiResult<()> {
    let mut tx = begin_write(&app.db).await?;
    sqlx::query("DELETE FROM pairing WHERE id = ? AND account_pk = ?")
        .bind(id.as_bytes().as_slice())
        .bind(session.account_pk)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// `GET /pairing/{id}` (the inviting device, only of its own account).
pub async fn get(app: &App, session: &Session, id: PairingId) -> ApiResult<PairingRequest> {
    let json: Option<Option<String>> = sqlx::query_scalar(
        "SELECT request FROM pairing WHERE id = ? AND account_pk = ? AND expires_ms > ?",
    )
    .bind(id.as_bytes().as_slice())
    .bind(session.account_pk)
    .bind(i64_of(app.now_ms()))
    .fetch_optional(&app.db)
    .await?;
    let json = json.flatten().ok_or(ErrorCode::NotFound)?;
    serde_json::from_str(&json).map_err(|e| ApiError::internal(&e))
}
