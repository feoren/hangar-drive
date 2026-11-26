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
//! 3. **Add:** the recovery device unwraps the current epoch's secret and appends one add
//!    device entry for the new regular device with that secret wrapped to it (`device_wrap`).
//!    While a rotation is due this is the one exception the log allows (finding M5).
//! 4. **Join:** the new device signs in on its own, joins at the log head the append returned
//!    (the anchor), and then removes the lost devices and the used recovery device and rotates,
//!    as any removal (`crate::removal`), and adds a new recovery device for a new code.

use hangar_drive_crypto::devicelog::{AccountState, LogDevice, MAX_LOG_ENTRIES};
use hangar_drive_crypto::epoch;
use hangar_drive_crypto::recovery::{RecoveryCode, RecoverySheet};
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::api::{LogAppendRequest, WrappedKeyEntry};
use hangar_drive_protocol::ids::{AccountId, Blob, LogHead};

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
    let protocol = |what: &str| SyncError::Net(NetError::Protocol(what.into()));
    let mut state = AccountState::new(account);
    for _ in 0..MAX_LOG_ENTRIES {
        let page = server.log(state.len())?;
        if page.length > MAX_LOG_ENTRIES {
            return Err(protocol("the log is longer than any log can be"));
        }
        if page.entries.is_empty() {
            return Ok(state);
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
        }
        if state.len() >= page.length {
            return Ok(state);
        }
    }
    Err(protocol("the log does not end"))
}

/// Steps 0 to 3 of the module docs: `server` is signed in as the recovery device of `code`.
/// Adds `device` to the account of `sheet` and returns the log head after the append, the anchor
/// the new device joins at. The sheet is checked against the code before anything is read.
pub fn add_device_with_code(
    server: &mut dyn ServerApi,
    sheet: &RecoverySheet,
    code: &RecoveryCode,
    device: LogDevice,
    now_ms: u64,
    entropy: &mut dyn Entropy,
) -> Result<LogHead, RecoveryError> {
    if !sheet.is_for(code) {
        return Err(RecoveryError::WrongSheet);
    }
    let account = sheet.account;
    let genesis = &sheet.genesis;
    let identity = code
        .identity()
        .map_err(|_| SyncError::Invalid("the recovery identity"))?;
    let recovery = code
        .device_id()
        .map_err(|_| SyncError::Invalid("the recovery device ID"))?;
    let state = match fetch_log(server, account) {
        Ok(state) => state,
        Err(SyncError::Net(NetError::DeviceRemoved(_))) => return Err(RecoveryError::Used),
        Err(e) => return Err(e.into()),
    };
    if state.hash_at(1) != Some(genesis) {
        return Err(RecoveryError::Unknown);
    }
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
    // The head after the append, computed here (security review I1): the anchor the new device
    // joins at must not be a value the server chose.
    let mut after = state.clone();
    let head = after.apply(&addition.entry).map_err(SyncError::from)?;
    let response = server.append_log(&LogAppendRequest {
        entries: vec![Blob(addition.entry.clone())],
        wraps: Vec::new(),
        device_wrap: addition.wrap.map(|data| WrappedKeyEntry {
            device: device.id,
            data: Blob(data),
        }),
    })?;
    if response.head != head {
        return Err(SyncError::Net(NetError::Protocol(
            "the server's log head after the append is not the one this device computed".into(),
        ))
        .into());
    }
    Ok(head)
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
            add_device_with_code(
                &mut Refusing(code_answer),
                &sheet,
                &code,
                device,
                0,
                &mut hangar_drive_crypto::OsEntropy,
            )
        };
        assert_eq!(run(ErrorCode::DeviceRemoved), Err(RecoveryError::Used));
        assert!(matches!(
            run(ErrorCode::ProofInvalid),
            Err(RecoveryError::Sync(SyncError::Net(_)))
        ));
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
