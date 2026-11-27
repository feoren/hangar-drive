//! The recovery sheet always gets back into an account (security review follow-ups): a stolen
//! device removes the person's device and fills the account up to the device limit with
//! devices of its own. The recovery device's added device takes the place above the limit and
//! removes every other device with its rotation, all in the recovery session's one append call,
//! so the stolen device, though online, has no moment to remove the new one.

mod common;

use common::*;
use hangar_drive_crypto::devicelog::{EntryKind, LogError, MAX_CURRENT_DEVICES, MAX_DEVICES};
use hangar_drive_protocol::api::*;
use hangar_drive_server::service::devicelog::ADDS_PER_DAY;

const DAY_MS: u64 = 24 * 3_600_000;

#[tokio::test]
async fn a_full_account_still_lets_the_recovery_sheet_in_and_remove_everyone() {
    let mut server = TestServer::start("recovery-cap").await;
    let owner = Device::new();
    let attacker = Device::new();
    let recovery = Device::with_recovery(true);
    let mut account = Account::create(&server, &owner, &[&attacker, &recovery]).await;
    let owner_client = account.sign_in(&server, &owner).await;
    assert_eq!(account.rotate(&owner_client, &owner).await.status, 200);

    // The attack: the owner's device removed, the account filled with the attacker's devices
    // (a few days, `ADDS_PER_DAY`).
    let ca = account.sign_in(&server, &attacker).await;
    let reply = account.remove(&ca, &attacker, &[owner.id]).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let mut ca = ca;
    let mut added = 0;
    while account.state.current_devices().count() < MAX_DEVICES {
        if added > 0 && added % ADDS_PER_DAY == 0 {
            server.clock.advance_ms(DAY_MS);
            ca = account.sign_in(&server, &attacker).await;
        }
        let reply = account.add(&ca, &attacker, &Device::new()).await;
        assert_eq!(
            reply.status,
            200,
            "device {added}: {}",
            String::from_utf8_lossy(&reply.body)
        );
        added += 1;
    }
    // The limit holds for a regular device (the verifier the server runs refuses the entry).
    let extra = Device::new();
    assert_eq!(
        account
            .state
            .next_entry(
                &attacker.identity,
                attacker.id,
                START_MS,
                EntryKind::AddDevice(extra.log_device(&account.id)),
            )
            .unwrap_err(),
        LogError::TooManyDevices
    );
    server.clock.advance_ms(DAY_MS);
    let ca = account.sign_in(&server, &attacker).await;

    // The recovery sheet: the new device comes in as the 65th and, in the same call, removes
    // all 64 others, the recovery device included, and rotates.
    let fresh = Device::new();
    let rec = account.sign_in(&server, &recovery).await;
    let others: Vec<_> = account.state.current_devices().map(|d| d.id).collect();
    assert_eq!(others.len(), MAX_DEVICES);
    let reply = account.recover(&rec, &recovery, &fresh, &others).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(
        account
            .state
            .current_devices()
            .map(|d| d.id)
            .collect::<Vec<_>>(),
        vec![fresh.id]
    );
    assert!(account.state.len() > MAX_CURRENT_DEVICES as u64);
    // The attacker is out before it can react: its session ended with the same call.
    assert_eq!(ca.get(LOG_PATH).await.code(), ErrorCode::Unauthorized);
    let cf = account.sign_in(&server, &fresh).await;
    assert_eq!(cf.get(FEED_PATH).await.status, 200);
    server.stop().await.unwrap();
}

// The former two steps are gone: the recovery session cannot add the new device on its own and
// leave it to the new device's next call, in which the attacker could have removed it first.
#[tokio::test]
async fn a_recovery_session_cannot_add_a_device_on_its_own() {
    let mut server = TestServer::start("recovery-one-piece").await;
    let owner = Device::new();
    let attacker = Device::new();
    let recovery = Device::with_recovery(true);
    let mut account = Account::create(&server, &owner, &[&attacker, &recovery]).await;
    let co = account.sign_in(&server, &owner).await;
    assert_eq!(account.rotate(&co, &owner).await.status, 200);
    let rec = account.sign_in(&server, &recovery).await;
    let fresh = Device::new();
    let reply = account.add(&rec, &recovery, &fresh).await;
    assert_eq!((reply.status, reply.code()), (403, ErrorCode::Forbidden));
    // A regular session cannot send the recovery shape either (it needs a recovery device).
    let ca = account.sign_in(&server, &attacker).await;
    let recovered = hangar_drive_crypto::epoch::recover(
        &account.state,
        &recovery.identity,
        recovery.id,
        &fresh.identity,
        fresh.log_device(&account.id),
        &[attacker.id],
        account.secret.as_ref(),
        START_MS,
        &mut hangar_drive_crypto::OsEntropy,
    )
    .unwrap();
    let request = LogAppendRequest {
        entries: recovered
            .entries
            .iter()
            .cloned()
            .map(hangar_drive_protocol::ids::Blob)
            .collect(),
        wraps: recovered
            .rotation
            .wraps
            .iter()
            .map(|(d, w)| WrappedKeyEntry {
                device: *d,
                data: hangar_drive_protocol::ids::Blob(w.clone()),
            })
            .collect(),
        device_wrap: recovered.device_wrap.map(|w| WrappedKeyEntry {
            device: fresh.id,
            data: hangar_drive_protocol::ids::Blob(w),
        }),
    };
    assert_eq!(
        ca.post(LOG_PATH, &request).await.code(),
        ErrorCode::LogEntryRefused
    );
    // The recovery session sends it, and the attacker's removal of the new device afterwards
    // comes too late: the attacker was removed in the same call.
    let reply = rec.post(LOG_PATH, &request).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(ca.get(LOG_PATH).await.code(), ErrorCode::Unauthorized);
    server.stop().await.unwrap();
}
