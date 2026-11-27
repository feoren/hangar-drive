//! Account recovery with the recovery sheet (ADR 0001, sections 2.3 and 4, "Recovery";
//! [ux-concept, 4.4]; open point A).
//!
//! The sheet carries the server address, the server ID, the account ID and the genesis anchor in
//! the clear ([`crate::links::RecoverySheet`]) and the code, which the person types. The code
//! alone derives the offline recovery device: its keys (`RecoveryCode::identity`) and its device
//! ID (`RecoveryCode::device_id`). The steps:
//!
//! 0. **Sheet:** the sheet's anchor tag must be the code's tag over the sheet's account and
//!    genesis anchor (`RecoverySheet::is_for`). A link can come from anyone, and whoever knows
//!    the account's log could build an account of their own that lists this code's recovery
//!    device and wraps a secret they know to it; such an account has another genesis, and nobody
//!    without the code can make the tag for it (security review "recovery link as phishing").
//! 1. **Recovery session:** the installation signs in as the recovery device, at the server
//!    the sheet names (the server ID is checked at the sign-in). The session may only read the
//!    log, fetch the recovery device's wrapped keys and make one append
//!    (`hangar_drive_protocol::api::SessionScope::Recovery`).
//! 2. **Check:** the verified log must start with the sheet's genesis anchor (the hash of the
//!    account's first entry, N1), so the server cannot hand over another account's log or one it
//!    made up, and it must list the recovery device, current, as a recovery device with exactly
//!    the keys the code derives; otherwise the code belongs to another account or was used up
//!    (its device removed). The log is read with a bound on its length (N4). A server refuses a
//!    removed device's sign-in, so a used code is mostly told by the sign-in itself: its proof,
//!    made with the code's own key, is answered with `DeviceRemoved` (finding E2E-5), which
//!    nobody without the code can get.
//! 3. **Choice:** the verified log names the account's devices ([`prepare`]); the person picks
//!    which to remove before anything is written. Nothing is in the account yet, so stopping
//!    here leaves the account and the code as they were.
//! 4. **One append** ([`build_recovery`] and [`send_recovery`], ADR 0001, amendment "recovery
//!    in one piece, adds per day, delta check on a growing log", H1): the log is read again and
//!    must still end at the head the person chose from ([`RecoveryError::ListChanged`]
//!    otherwise, security review "recovery" M1). The recovery device unwraps the current
//!    epoch's secret, and one batch adds the new regular device (signed by the recovery
//!    device), removes the chosen devices and every recovery device, the used one included, and
//!    rotates (both signed by the new device), with the rotation's wraps and the new device's
//!    wrap of the epoch before (`device_wrap`). Nobody can write between the add and the
//!    rotation, so a hostile device cannot remove the new device first. The batch always
//!    removes the used recovery device, so the code is spent exactly when the batch is in.
//! 5. **Join:** the new device signs in on its own, joins at the log head after the batch (the
//!    anchor), re-seals and writes the barriers with its own removal as any removal
//!    (`crate::removal`, whose append finds the removals in the log already), and adds a new
//!    recovery device for a new code. Between the send and the join the caller keeps the new
//!    device's key and what the join needs (the engine's pending recovery, security review
//!    "recovery" H1): whether the batch is in is told by the new device's own verified log, not
//!    by the server's answer.

use hangar_drive_crypto::devicelog::{AccountState, LogDevice, LogEntry, MAX_LOG_ENTRIES};
use hangar_drive_crypto::epoch::{self, AccountSecret};
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_crypto::recovery::{RecoveryCode, RecoverySheet};
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::api::{LogAppendRequest, WrappedKeyEntry};
use hangar_drive_protocol::ids::{AccountId, Blob, DeviceId, LogHead};

use crate::chunker::DynEntropy;
use crate::error::SyncError;
use crate::ports::{NetError, ServerApi};

/// Why the recovery device could not add the new device.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    /// The sheet was not made for this code: it names an account or a genesis anchor the code
    /// does not vouch for (a forged or mixed-up link).
    #[error("the sheet does not belong to this code")]
    WrongSheet,
    /// The account's log does not list this code's recovery device at all, or it does not
    /// start with the sheet's genesis anchor.
    #[error("the code does not belong to this account")]
    Unknown,
    /// The recovery device was removed: the code was used before.
    #[error("the code was used before")]
    Used,
    /// The account's log moved on since the person was shown its devices (security review
    /// "recovery" M1): a device added in between would survive the recovery unseen. Nothing was
    /// written; the person chooses again from the new list.
    #[error("the account's devices changed since they were shown")]
    ListChanged,
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
///
/// A server cannot make the client read without end (N4): a log longer than
/// [`MAX_LOG_ENTRIES`] is refused before any entry of it is read, every page must move the log
/// forward, and at most [`MAX_LOG_ENTRIES`] pages are read.
pub fn fetch_log(
    server: &mut dyn ServerApi,
    account: AccountId,
) -> Result<AccountState, SyncError> {
    fetch_log_entries(server, account).map(|(state, _)| state)
}

/// [`fetch_log`] with the entries, for the issue times of the devices.
pub fn fetch_log_entries(
    server: &mut dyn ServerApi,
    account: AccountId,
) -> Result<(AccountState, Vec<Vec<u8>>), SyncError> {
    let protocol = |what: &str| SyncError::Net(NetError::Protocol(what.into()));
    let mut state = AccountState::new(account);
    let mut log: Vec<Vec<u8>> = Vec::new();
    for _ in 0..MAX_LOG_ENTRIES {
        let page = server.log(state.len())?;
        if page.length > MAX_LOG_ENTRIES {
            return Err(protocol("the log is longer than any log can be"));
        }
        if page.entries.is_empty() {
            return Ok((state, log));
        }
        if page.first_index != state.len() + 1 {
            return Err(protocol("log page out of order"));
        }
        let room = MAX_LOG_ENTRIES.saturating_sub(state.len());
        if u64::try_from(page.entries.len()).unwrap_or(u64::MAX) > room {
            return Err(protocol("the log is longer than any log can be"));
        }
        for entry in &page.entries {
            state.apply(entry.as_bytes())?;
            log.push(entry.0.clone());
        }
        if state.len() >= page.length {
            return Ok((state, log));
        }
    }
    Err(protocol("the log does not end"))
}

/// A device of the account the recovery can remove, as the verified log names it. The sealed
/// device names are out of reach for the recovery session, so a device has no name here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogDeviceInfo {
    /// The device.
    pub id: DeviceId,
    /// When the entry that added it was issued (its issuer's clock), milliseconds.
    pub added_ms: u64,
}

/// What steps 0 to 2 found: the verified log, and the account's regular devices.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The verified log.
    pub state: AccountState,
    /// The current regular devices, in log order.
    pub devices: Vec<LogDeviceInfo>,
}

/// Steps 0 to 2 of the module docs: `server` is signed in as the recovery device of `code`.
/// Checks the sheet against the code before anything is read, then the verified log against
/// the sheet and the code. Writes nothing.
pub fn prepare(
    server: &mut dyn ServerApi,
    sheet: &RecoverySheet,
    code: &RecoveryCode,
) -> Result<Prepared, RecoveryError> {
    if !sheet.is_for(code) {
        return Err(RecoveryError::WrongSheet);
    }
    let identity = code
        .identity()
        .map_err(|_| SyncError::Invalid("the recovery identity"))?;
    let recovery = code
        .device_id()
        .map_err(|_| SyncError::Invalid("the recovery device ID"))?;
    let (state, log) = match fetch_log_entries(server, sheet.account) {
        Ok(found) => found,
        Err(SyncError::Net(NetError::DeviceRemoved(_))) => return Err(RecoveryError::Used),
        Err(e) => return Err(e.into()),
    };
    if state.hash_at(1) != Some(&sheet.genesis) {
        return Err(RecoveryError::Unknown);
    }
    let record = state.device(&recovery).ok_or(RecoveryError::Unknown)?;
    if !record.recovery || record.keys != identity.public_keys() {
        return Err(RecoveryError::Unknown);
    }
    if !record.is_current() {
        return Err(RecoveryError::Used);
    }
    let devices = state
        .current_devices()
        .filter(|d| !d.recovery)
        .map(|d| LogDeviceInfo {
            id: d.id,
            added_ms: usize::try_from(d.added_at.saturating_sub(1))
                .ok()
                .and_then(|at| log.get(at))
                .and_then(|entry| LogEntry::decode(entry).ok())
                .map_or(0, |entry| entry.issued_at_ms),
        })
        .collect();
    Ok(Prepared { state, devices })
}

/// What the one append made.
#[derive(Debug, Clone)]
pub struct Recovered {
    /// The log head after the batch, computed here: the anchor the new device joins at.
    pub head: LogHead,
    /// Every device the batch removed: the chosen ones and every recovery device.
    pub removed: Vec<DeviceId>,
}

/// The one batch of step 4, built and not sent yet: the caller records what it needs to finish
/// the recovery after any failure before it sends the batch (security review "recovery" H1).
#[derive(Debug, Clone)]
pub struct RecoveryBatch {
    /// The append.
    pub request: LogAppendRequest,
    /// The log head after the batch, computed here (security review I1).
    pub head: LogHead,
    /// Every device the batch removes: the chosen ones and every recovery device.
    pub removed: Vec<DeviceId>,
}

/// Step 4 of the module docs without the send: `server` is signed in as the recovery device of
/// `code`. Reads the log again and refuses with [`RecoveryError::ListChanged`] when its head is
/// not `shown`, the head of the log the person chose from (security review "recovery" M1).
/// Otherwise it removes `remove` (those of them that are current regular devices besides
/// `device`) and every current recovery device, adds `device` with the keys of `identity` and
/// rotates, in one batch. Writes nothing.
#[allow(clippy::too_many_arguments)]
pub fn build_recovery(
    server: &mut dyn ServerApi,
    sheet: &RecoverySheet,
    code: &RecoveryCode,
    identity: &DeviceIdentity,
    device: LogDevice,
    remove: &[DeviceId],
    shown: &LogHead,
    now_ms: u64,
    entropy: &mut dyn Entropy,
) -> Result<RecoveryBatch, RecoveryError> {
    let prepared = prepare(server, sheet, code)?;
    let state = prepared.state;
    if state.head().as_ref() != Some(shown) {
        return Err(RecoveryError::ListChanged);
    }
    let recovery_identity = code
        .identity()
        .map_err(|_| SyncError::Invalid("the recovery identity"))?;
    let recovery = code
        .device_id()
        .map_err(|_| SyncError::Invalid("the recovery device ID"))?;
    let secret: Option<AccountSecret> = match state.current_epoch().copied() {
        None => None,
        Some(current) => {
            let wrapped = server.epoch_key(current.epoch)?;
            Some(
                epoch::unwrap(
                    &recovery_identity,
                    &sheet.account,
                    current.epoch,
                    &recovery,
                    wrapped.data.as_bytes(),
                    &current.commitment,
                )
                .map_err(SyncError::from)?,
            )
        }
    };
    // The chosen devices that are still current regular devices, then every recovery device:
    // the used code stops working with the same batch.
    let mut removed: Vec<DeviceId> = remove
        .iter()
        .copied()
        .filter(|id| *id != device.id)
        .filter(|id| {
            state
                .device(id)
                .is_some_and(|d| d.is_current() && !d.recovery)
        })
        .collect();
    removed.sort();
    removed.dedup();
    removed.extend(state.current_devices().filter(|d| d.recovery).map(|d| d.id));
    let batch = epoch::recover(
        &state,
        &recovery_identity,
        recovery,
        identity,
        device,
        &removed,
        secret.as_ref(),
        now_ms,
        &mut DynEntropy(entropy),
    )
    .map_err(SyncError::from)?;
    // The head after the batch, computed here (security review I1): the anchor the new device
    // joins at must not be a value the server chose.
    let head = batch
        .state
        .head()
        .ok_or(SyncError::Invalid("no log head after the batch"))?;
    let request = LogAppendRequest {
        entries: batch.entries.iter().cloned().map(Blob).collect(),
        wraps: batch
            .rotation
            .wraps
            .iter()
            .map(|(id, data)| WrappedKeyEntry {
                device: *id,
                data: Blob(data.clone()),
            })
            .collect(),
        device_wrap: batch.device_wrap.map(|data| WrappedKeyEntry {
            device: device.id,
            data: Blob(data),
        }),
    };
    Ok(RecoveryBatch {
        request,
        head,
        removed,
    })
}

/// Sends a batch of [`build_recovery`]. An error here does not tell whether the server took
/// the batch: a lost answer and a head the server made up look the same as a refusal. The new
/// device's own verified log tells (`crate::engine`, "pending recovery").
pub fn send_recovery(
    server: &mut dyn ServerApi,
    batch: &RecoveryBatch,
) -> Result<Recovered, SyncError> {
    let response = server.append_log(&batch.request)?;
    if response.head != batch.head {
        return Err(SyncError::Net(NetError::Protocol(
            "the server's log head after the append is not the one this device computed".into(),
        )));
    }
    Ok(Recovered {
        head: batch.head,
        removed: batch.removed.clone(),
    })
}

/// Step 4 of the module docs in one call: [`build_recovery`], then [`send_recovery`].
#[allow(clippy::too_many_arguments)]
pub fn recover_with_code(
    server: &mut dyn ServerApi,
    sheet: &RecoverySheet,
    code: &RecoveryCode,
    identity: &DeviceIdentity,
    device: LogDevice,
    remove: &[DeviceId],
    shown: &LogHead,
    now_ms: u64,
    entropy: &mut dyn Entropy,
) -> Result<Recovered, RecoveryError> {
    let batch = build_recovery(
        server, sheet, code, identity, device, remove, shown, now_ms, entropy,
    )?;
    Ok(send_recovery(server, &batch)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_drive_crypto::identity::DeviceIdentity;
    use hangar_drive_protocol::api::*;
    use hangar_drive_protocol::ids::*;

    /// A server whose log page claims `length` and repeats one empty-looking page.
    struct Liar {
        length: u64,
        calls: u64,
    }

    macro_rules! refuse {
        ($($name:ident($($arg:ty),*) -> $out:ty;)*) => {
            $(fn $name(&mut self, $(_: $arg),*) -> Result<$out, NetError> {
                Err(NetError::Unreachable)
            })*
        };
    }

    impl ServerApi for Liar {
        fn log(&mut self, _after: u64) -> Result<LogPage, NetError> {
            self.calls += 1;
            Ok(LogPage {
                first_index: 1,
                entries: vec![Blob(vec![1, 2, 3])],
                length: self.length,
            })
        }
        refuse! {
            create_account(&CreateAccountRequest) -> CreateAccountResponse;
            challenge(&AccountId, &DeviceId) -> ChallengeResponse;
            proof(&AccountId, &DeviceId, &Challenge, &Signature) -> SessionResponse;
            append_log(&LogAppendRequest) -> LogAppendResponse;
            epoch_key(Epoch) -> WrappedKeyResponse;
            record(&RecordKey) -> Option<RecordResponse>;
            put_record(&RecordKey, &RecordPut) -> ();
            feed(u64) -> FeedPage;
            reserve_pairing(&PairingId) -> PairingReservation;
            post_pairing(&PairingId, &PairingRequest) -> ();
            get_pairing(&PairingId) -> Option<PairingRequest>;
            close_pairing(&PairingId) -> ();
            missing_objects(&FolderId, &[ObjectId]) -> Vec<ObjectId>;
            put_object(&FolderId, &ObjectId, &[u8]) -> UploadResponse;
            get_object(&FolderId, &ObjectId) -> Vec<u8>;
            commit(&FolderId, &CommitRequest) -> CommitResponse;
            commits(&FolderId, u64) -> DeltaPage;
            retire(&FolderId) -> ();
            bring_back(&FolderId) -> ();
        }
    }

    /// A server that refuses the recovery device's sign-in with `code`.
    struct Refusing(ErrorCode);

    impl ServerApi for Refusing {
        fn log(&mut self, _after: u64) -> Result<LogPage, NetError> {
            // As the HTTP client reports it: `device_removed` only as the proof's answer.
            Err(match self.0 {
                ErrorCode::DeviceRemoved => NetError::DeviceRemoved(None),
                code => NetError::Server(ErrorBody::new(code)),
            })
        }
        refuse! {
            create_account(&CreateAccountRequest) -> CreateAccountResponse;
            challenge(&AccountId, &DeviceId) -> ChallengeResponse;
            proof(&AccountId, &DeviceId, &Challenge, &Signature) -> SessionResponse;
            append_log(&LogAppendRequest) -> LogAppendResponse;
            epoch_key(Epoch) -> WrappedKeyResponse;
            record(&RecordKey) -> Option<RecordResponse>;
            put_record(&RecordKey, &RecordPut) -> ();
            feed(u64) -> FeedPage;
            reserve_pairing(&PairingId) -> PairingReservation;
            post_pairing(&PairingId, &PairingRequest) -> ();
            get_pairing(&PairingId) -> Option<PairingRequest>;
            close_pairing(&PairingId) -> ();
            missing_objects(&FolderId, &[ObjectId]) -> Vec<ObjectId>;
            put_object(&FolderId, &ObjectId, &[u8]) -> UploadResponse;
            get_object(&FolderId, &ObjectId) -> Vec<u8>;
            commit(&FolderId, &CommitRequest) -> CommitResponse;
            commits(&FolderId, u64) -> DeltaPage;
            retire(&FolderId) -> ();
            bring_back(&FolderId) -> ();
        }
    }

    // E2E-5: the server tells the removed recovery device so (its own proof), which is "used";
    // a proof the server refuses as such is not.
    #[test]
    fn a_removed_recovery_device_means_the_code_was_used() {
        let code = RecoveryCode::generate(&mut hangar_drive_crypto::OsEntropy).unwrap();
        let identity = DeviceIdentity::generate(&mut hangar_drive_crypto::OsEntropy).unwrap();
        let account = AccountId::from_bytes([1; 16]);
        let device = LogDevice::of(&identity, &account, DeviceId::from_bytes([2; 16]), false);
        let sheet = RecoverySheet::new(
            hangar_drive_crypto::pairing::parse_server_url("https://drive.example/").unwrap(),
            ServerId::from_bytes([4; 16]),
            account,
            LogHash::from_bytes([3; 32]),
            None,
            &code,
        )
        .unwrap();
        let run = |code_answer: ErrorCode| {
            recover_with_code(
                &mut Refusing(code_answer),
                &sheet,
                &code,
                &identity,
                device,
                &[],
                &LogHead {
                    index: 1,
                    hash: LogHash::from_bytes([3; 32]),
                },
                0,
                &mut hangar_drive_crypto::OsEntropy,
            )
            .map(|_| ())
        };
        assert_eq!(run(ErrorCode::DeviceRemoved), Err(RecoveryError::Used));
        assert!(matches!(
            run(ErrorCode::ProofInvalid),
            Err(RecoveryError::Sync(SyncError::Net(_)))
        ));
        assert_eq!(
            prepare(&mut Refusing(ErrorCode::DeviceRemoved), &sheet, &code).map(|_| ()),
            Err(RecoveryError::Used)
        );
    }

    // N4: a log longer than any log can be is refused before a single entry is read.
    #[test]
    fn a_log_longer_than_the_maximum_is_refused_at_once() {
        let mut server = Liar {
            length: MAX_LOG_ENTRIES + 1,
            calls: 0,
        };
        let error = fetch_log(&mut server, AccountId::from_bytes([1; 16])).unwrap_err();
        assert!(
            matches!(error, SyncError::Net(NetError::Protocol(_))),
            "{error:?}"
        );
        assert_eq!(server.calls, 1);
        // Within the bound the entries are verified, and a bad one stops the read.
        let mut server = Liar {
            length: 3,
            calls: 0,
        };
        assert!(matches!(
            fetch_log(&mut server, AccountId::from_bytes([1; 16])),
            Err(SyncError::Log(_))
        ));
    }
}
