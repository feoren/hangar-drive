//! Account recovery with the recovery sheet (ADR 0001, sections 2.3 and 4, "Recovery";
//! [ux-concept, 4.4]; open point A).
//!
//! The sheet carries the server address, the server ID and the account ID in the clear
//! ([`crate::links::RecoverySheet`]) and the code, which the person types. The code alone
//! derives the offline recovery device: its keys (`RecoveryCode::identity`) and its device ID
//! (`RecoveryCode::device_id`). The steps:
//!
//! 1. **Recovery session:** the installation signs in as the recovery device, at the server
//!    the sheet names (the server ID is checked at the sign-in). The session may only read the
//!    log, fetch the recovery device's wrapped keys and make one append
//!    (`hangar_drive_protocol::api::SessionScope::Recovery`).
//! 2. **Check:** the verified log must list the recovery device, current, as a recovery device
//!    with exactly the keys the code derives; otherwise the code belongs to another account or
//!    was used up (its device removed).
//! 3. **Add:** the recovery device unwraps the current epoch's secret and appends one add
//!    device entry for the new regular device with that secret wrapped to it (`device_wrap`).
//!    While a rotation is due this is the one exception the log allows (finding M5).
//! 4. **Join:** the new device signs in on its own, joins at the log head the append returned
//!    (the anchor), and then removes the lost devices and the used recovery device and rotates,
//!    as any removal (`crate::removal`), and adds a new recovery device for a new code.

use hangar_drive_crypto::devicelog::{AccountState, LogDevice};
use hangar_drive_crypto::epoch;
use hangar_drive_crypto::recovery::RecoveryCode;
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::api::{LogAppendRequest, WrappedKeyEntry};
use hangar_drive_protocol::ids::{AccountId, Blob, LogHead};

use crate::chunker::DynEntropy;
use crate::error::SyncError;
use crate::ports::{NetError, ServerApi};

/// Why the recovery device could not add the new device.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    /// The account's log does not list this code's recovery device at all.
    #[error("the code does not belong to this account")]
    Unknown,
    /// The recovery device was removed: the code was used before.
    #[error("the code was used before")]
    Used,
    /// The server or the log failed.
    #[error(transparent)]
    Sync(#[from] SyncError),
}

impl From<NetError> for RecoveryError {
    fn from(e: NetError) -> Self {
        RecoveryError::Sync(e.into())
    }
}

/// The verified log of `account`, read through `server` (every page, each entry verified).
pub fn fetch_log(
    server: &mut dyn ServerApi,
    account: AccountId,
) -> Result<AccountState, SyncError> {
    let mut state = AccountState::new(account);
    loop {
        let page = server.log(state.len())?;
        if page.entries.is_empty() {
            return Ok(state);
        }
        if page.first_index != state.len() + 1 {
            return Err(SyncError::Net(NetError::Protocol(
                "log page out of order".into(),
            )));
        }
        for entry in &page.entries {
            state.apply(entry.as_bytes())?;
        }
        if state.len() >= page.length {
            return Ok(state);
        }
    }
}

/// Steps 1 to 3 of the module docs: `server` is signed in as the recovery device of `code`.
/// Adds `device` to `account` and returns the log head after the append, the anchor the new
/// device joins at.
pub fn add_device_with_code(
    server: &mut dyn ServerApi,
    account: AccountId,
    code: &RecoveryCode,
    device: LogDevice,
    now_ms: u64,
    entropy: &mut dyn Entropy,
) -> Result<LogHead, RecoveryError> {
    let identity = code
        .identity()
        .map_err(|_| SyncError::Invalid("the recovery identity"))?;
    let recovery = code
        .device_id()
        .map_err(|_| SyncError::Invalid("the recovery device ID"))?;
    let state = fetch_log(server, account)?;
    let record = state.device(&recovery).ok_or(RecoveryError::Unknown)?;
    if !record.recovery || record.keys != identity.public_keys() {
        return Err(RecoveryError::Unknown);
    }
    if !record.is_current() {
        return Err(RecoveryError::Used);
    }
    let current = state
        .current_epoch()
        .copied()
        .ok_or(SyncError::NotSetUp("the account has no epoch"))?;
    let wrapped = server.epoch_key(current.epoch)?;
    let secret = epoch::unwrap(
        &identity,
        &account,
        current.epoch,
        &recovery,
        wrapped.data.as_bytes(),
        &current.commitment,
    )
    .map_err(SyncError::from)?;
    let addition = epoch::add_device(
        &state,
        &identity,
        recovery,
        now_ms,
        device,
        Some(&secret),
        &mut DynEntropy(entropy),
    )
    .map_err(SyncError::from)?;
    let response = server.append_log(&LogAppendRequest {
        entries: vec![Blob(addition.entry.clone())],
        wraps: Vec::new(),
        device_wrap: addition.wrap.map(|data| WrappedKeyEntry {
            device: device.id,
            data: Blob(data),
        }),
    })?;
    Ok(response.head)
}
