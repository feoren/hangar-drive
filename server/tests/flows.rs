//! Every flow and access rule over a real socket: accounts and sessions, default deny, the
//! recovery scope, the device log with removal, records, pairing, objects, commits with compare
//! and swap and merges, IDOR between accounts, wrong senders, the feed and SSE, rate limits and
//! trusted proxies.

mod common;

use std::time::Duration;

use common::*;
use hangar_drive_crypto::commit::{Commit, CommitContent};
use hangar_drive_crypto::record::RecordCipher;
use hangar_drive_crypto::OsEntropy;
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::ObjectType;
use hangar_drive_server::http::access::{routes, Access};
use hangar_drive_server::http::ratelimit::{RateLimiter, Scope};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn accounts_need_a_single_use_invite_and_devices_sign_in_with_a_proof() {
    let mut server = TestServer::start("accounts").await;
    let device = Device::new();
    let account = Account::create(&server, &device, &[]).await;
    assert_eq!(account.server, Some(server.app.server_id));
    let client = Client::new(server.addr);

    // Unknown, reused and expired invites.
    let other = Device::new();
    let id = AccountId::from_bytes(random());
    let request = |invite: InviteToken, account: AccountId| {
        let genesis = hangar_drive_crypto::devicelog::AccountState::new(account)
            .next_entry(
                &other.identity,
                other.id,
                START_MS,
                hangar_drive_crypto::devicelog::EntryKind::Create {
                    devices: vec![other.log_device(&account)],
                },
            )
            .unwrap();
        CreateAccountRequest {
            invite,
            account,
            genesis: Blob(genesis),
        }
    };
    let reply = client
        .post(
            ACCOUNTS_PATH,
            &request(InviteToken::from_bytes([9; 16]), id),
        )
        .await;
    assert_eq!(
        (reply.status, reply.code()),
        (403, ErrorCode::InviteInvalid)
    );
    let invite = server.invite().await;
    let reused = InviteToken::from_bytes(*invite.expose());
    let repeated = InviteToken::from_bytes(*invite.expose());
    let first = request(invite, id);
    let genesis = first.genesis.clone();
    assert_eq!(client.post(ACCOUNTS_PATH, &first).await.status, 201);
    // Finding E2E-1: the same request again (its answer was lost) succeeds again, so the
    // device can carry on; the same invite with another entry 1 for the account does not.
    let reply = client
        .post(
            ACCOUNTS_PATH,
            &CreateAccountRequest {
                invite: InviteToken::from_bytes(*repeated.expose()),
                account: id,
                genesis: genesis.clone(),
            },
        )
        .await;
    assert_eq!(reply.status, 201, "a repeat of the same creation");
    assert_eq!(
        reply.json::<CreateAccountResponse>().server,
        server.app.server_id
    );
    let third = Device::new();
    let another = hangar_drive_crypto::devicelog::AccountState::new(id)
        .next_entry(
            &third.identity,
            third.id,
            START_MS,
            hangar_drive_crypto::devicelog::EntryKind::Create {
                devices: vec![third.log_device(&id)],
            },
        )
        .unwrap();
    let reply = client
        .post(
            ACCOUNTS_PATH,
            &CreateAccountRequest {
                invite: repeated,
                account: id,
                genesis: Blob(another),
            },
        )
        .await;
    assert_eq!(
        (reply.status, reply.code()),
        (403, ErrorCode::InviteInvalid),
        "not the same creation"
    );
    let reply = client
        .post(
            ACCOUNTS_PATH,
            &request(reused, AccountId::from_bytes(random())),
        )
        .await;
    assert_eq!(
        reply.code(),
        ErrorCode::InviteInvalid,
        "an invite is used once"
    );
    // Without a valid invite nobody learns whether an account ID exists (finding L2): the
    // invite is checked first.
    let reply = client
        .post(
            ACCOUNTS_PATH,
            &request(InviteToken::from_bytes([7; 16]), id),
        )
        .await;
    assert_eq!(
        (reply.status, reply.code()),
        (403, ErrorCode::InviteInvalid),
        "an existing account ID with a wrong invite looks like any other"
    );
    // An existing account ID is refused without using the invite.
    let fresh = server.invite().await;
    let keep = InviteToken::from_bytes(*fresh.expose());
    let reply = client.post(ACCOUNTS_PATH, &request(fresh, id)).await;
    assert_eq!(
        (reply.status, reply.code()),
        (409, ErrorCode::AlreadyExists)
    );
    let reply = client
        .post(
            ACCOUNTS_PATH,
            &request(keep, AccountId::from_bytes(random())),
        )
        .await;
    assert_eq!(reply.status, 201, "the invite was still unused");
    let expired = server.invite().await;
    server.clock.advance_ms(8 * DAY_MS);
    let reply = client
        .post(
            ACCOUNTS_PATH,
            &request(expired, AccountId::from_bytes(random())),
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::InviteInvalid, "expired");
    // A genesis entry that does not verify.
    let reply = client
        .post(
            ACCOUNTS_PATH,
            &CreateAccountRequest {
                invite: server.invite().await,
                account: AccountId::from_bytes(random()),
                genesis: Blob(vec![1, 2, 3]),
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::LogEntryRefused);

    // Sign-in: a wrong signature, a replayed proof, an expired challenge, a forged challenge.
    let challenge = |device: DeviceId| ChallengeRequest {
        account: account.id,
        device,
    };
    let c: ChallengeResponse = client
        .post(CHALLENGE_PATH, &challenge(device.id))
        .await
        .json();
    let wrong = Device::new().identity.prove_session(
        &c.server,
        TEST_URL,
        &account.id,
        &device.id,
        &c.challenge,
    );
    let reply = client
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: device.id,
                challenge: c.challenge,
                server_url: TEST_URL.into(),
                signature: wrong,
            },
        )
        .await;
    assert_eq!((reply.status, reply.code()), (401, ErrorCode::ProofInvalid));
    // Only a proof that verifies uses the challenge up (finding M1): the wrong signature did
    // not, the right one does, and the same proof again is a replay.
    let right =
        device
            .identity
            .prove_session(&c.server, TEST_URL, &account.id, &device.id, &c.challenge);
    let proof = ProofRequest {
        account: account.id,
        device: device.id,
        challenge: c.challenge,
        server_url: TEST_URL.into(),
        signature: right,
    };
    assert_eq!(client.post(PROOF_PATH, &proof).await.status, 200);
    let reply = client.post(PROOF_PATH, &proof).await;
    assert_eq!(
        reply.code(),
        ErrorCode::ChallengeInvalid,
        "a challenge is used once"
    );
    // The challenge is bound to the device it was made for.
    let other_device = Device::new();
    let signature = other_device.identity.prove_session(
        &c.server,
        TEST_URL,
        &account.id,
        &other_device.id,
        &c.challenge,
    );
    let reply = client
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: other_device.id,
                challenge: c.challenge,
                server_url: TEST_URL.into(),
                signature,
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::ChallengeInvalid);
    // 32 bytes the server never made.
    let forged = Challenge::from_bytes(random());
    let signature =
        device
            .identity
            .prove_session(&c.server, TEST_URL, &account.id, &device.id, &forged);
    let reply = client
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: device.id,
                challenge: forged,
                server_url: TEST_URL.into(),
                signature,
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::ChallengeInvalid);
    let c: ChallengeResponse = client
        .post(CHALLENGE_PATH, &challenge(device.id))
        .await
        .json();
    server.clock.advance_ms(61_000);
    let signature =
        device
            .identity
            .prove_session(&c.server, TEST_URL, &account.id, &device.id, &c.challenge);
    let reply = client
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: device.id,
                challenge: c.challenge,
                server_url: TEST_URL.into(),
                signature,
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::ChallengeInvalid, "expired");
    // A challenge for an unknown account looks the same.
    let reply = client
        .post(
            CHALLENGE_PATH,
            &ChallengeRequest {
                account: AccountId::from_bytes(random()),
                device: device.id,
            },
        )
        .await;
    assert_eq!(reply.status, 200);

    // The token works, expires after an hour, and is never accepted in the query.
    let session = account.sign_in(&server, &device).await;
    let reply = session.get(LOG_PATH).await;
    assert_eq!(reply.status, 200);
    let page: LogPage = reply.json();
    assert_eq!(
        (page.first_index, page.entries.len(), page.length),
        (1, 1, 1)
    );
    let token = session.token.clone().unwrap();
    let reply = client.get(&format!("{LOG_PATH}?token={token}")).await;
    assert_eq!(reply.status, 401);
    server.clock.advance_ms(3_601_000);
    assert_eq!(session.get(LOG_PATH).await.code(), ErrorCode::Unauthorized);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn every_session_route_is_denied_without_a_valid_token() {
    let mut server = TestServer::start("deny").await;
    let folder = FolderId::from_bytes([1; 16]);
    let object = ObjectId::from_bytes([2; 32]);
    let concrete = |path: &str| {
        path.replace("{folder}", &folder.to_hex())
            .replace("{id}", &object.to_hex())
            .replace("{epoch}", "1")
            .replace("{kind}", "folders")
            .replace("{pairing}", &"03".repeat(16))
    };
    let mut garbage = Client::new(server.addr);
    garbage.token = Some("A".repeat(43));
    for route in routes() {
        let Access::Call(_) = route.access else {
            continue;
        };
        let path = concrete(route.path);
        let method = route.method.as_str();
        for client in [Client::new(server.addr), garbage.clone()] {
            let reply = client.send(method, &path, &json!({})).await;
            assert_eq!(
                (reply.status, reply.code()),
                (401, ErrorCode::Unauthorized),
                "{method} {path}"
            );
        }
    }
    server.stop().await.unwrap();
}

#[tokio::test]
async fn malformed_requests_get_error_codes_only() {
    let mut server = TestServer::start("malformed").await;
    let device = Device::new();
    let account = Account::create(&server, &device, &[]).await;
    let client = account.sign_in(&server, &device).await;
    let reply = raw(server.addr, "POST", CHALLENGE_PATH, &[], b"{not json").await;
    assert_eq!((reply.status, reply.code()), (400, ErrorCode::BadRequest));
    let reply = client
        .post(
            CHALLENGE_PATH,
            &json!({ "account": account.id, "device": device.id, "admin": true }),
        )
        .await;
    assert_eq!(
        reply.code(),
        ErrorCode::BadRequest,
        "unknown fields are refused"
    );
    let reply = client
        .get(&commits_path(&FolderId::from_bytes([1; 16])).replace("0101", "zz01"))
        .await;
    assert_eq!(reply.code(), ErrorCode::BadRequest);
    let reply = client.get(&format!("{FEED_PATH}?after=-1")).await;
    assert_eq!(reply.code(), ErrorCode::BadRequest);
    let reply = client.get(&format!("{FEED_PATH}?after=1&x=2")).await;
    assert_eq!(reply.code(), ErrorCode::BadRequest);
    let reply = client.get("/api/v1/account/records/settings").await;
    assert_eq!(reply.code(), ErrorCode::BadRequest);
    let big = vec![b' '; 70 * 1024];
    let reply = raw(server.addr, "POST", CHALLENGE_PATH, &[], &big).await;
    assert_eq!((reply.status, reply.code()), (413, ErrorCode::TooLarge));
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_recovery_session_reads_the_log_and_its_keys_and_adds_one_regular_device() {
    let mut server = TestServer::start("recovery").await;
    let mut owner = Device::new();
    let recovery = Device::with_recovery(true);
    let mut account = Account::create(&server, &owner, &[&recovery]).await;
    let owner_client = account.sign_in(&server, &owner).await;
    assert_eq!(account.rotate(&owner_client, &owner).await.status, 200);

    let rec = account.sign_in(&server, &recovery).await;
    assert_eq!(rec.get(LOG_PATH).await.status, 200);
    let reply = rec.get(&epoch_key_path(Epoch(1))).await;
    assert_eq!(reply.status, 200);
    let key: WrappedKeyResponse = reply.json();
    assert_eq!(key.data.as_bytes().len(), WRAPPED_KEY_LEN);
    let folder = Folder::new();
    let obj = Obj::new(ObjectType::Chunk, 10);
    for reply in [
        rec.get(FEED_PATH).await,
        rec.get(EVENTS_PATH).await,
        rec.get("/api/v1/account/records/folders").await,
        upload(&rec, &folder.id, &obj).await,
        rec.post(
            &missing_objects_path(&folder.id),
            &MissingObjectsRequest { ids: vec![obj.id] },
        )
        .await,
        rec.post(
            &commit_path(&folder.id),
            &folder.request(&folder.next(&account, &mut owner), &[], &[]),
        )
        .await,
        rec.get(&pairing_path(&PairingId::from_bytes([1; 16])))
            .await,
        rec.post(&retire_path(&folder.id), &json!({})).await,
    ] {
        assert_eq!((reply.status, reply.code()), (403, ErrorCode::Forbidden));
    }
    // Anything but one entry with the new device's key is not the recovery shape.
    let shaped = hangar_drive_crypto::epoch::add_device(
        &account.state,
        &recovery.identity,
        recovery.id,
        START_MS,
        Device::new().log_device(&account.id),
        account.secret.as_ref(),
        &mut OsEntropy,
    )
    .unwrap();
    let two = LogAppendRequest {
        entries: vec![Blob(shaped.entry.clone()), Blob(shaped.entry.clone())],
        wraps: vec![],
        device_wrap: None,
    };
    assert_eq!(rec.post(LOG_PATH, &two).await.code(), ErrorCode::Forbidden);
    let no_wrap = LogAppendRequest {
        entries: vec![Blob(shaped.entry)],
        wraps: vec![],
        device_wrap: None,
    };
    assert_eq!(
        rec.post(LOG_PATH, &no_wrap).await.code(),
        ErrorCode::Forbidden
    );
    // One regular device, once.
    let new = Device::new();
    let reply = account.add(&rec, &recovery, &new).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let second = Device::new();
    let reply = account.add(&rec, &recovery, &second).await;
    assert_eq!((reply.status, reply.code()), (403, ErrorCode::Forbidden));
    assert_eq!(rec.get(LOG_PATH).await.status, 200, "reading stays allowed");
    // The new device has its key of the current epoch and full access.
    let new_client = account.sign_in(&server, &new).await;
    assert_eq!(new_client.get(&epoch_key_path(Epoch(1))).await.status, 200);
    assert_eq!(new_client.get(FEED_PATH).await.status, 200);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_removed_device_loses_its_session_proof_and_commits_at_once() {
    let mut server = TestServer::start("removal").await;
    let a = Device::new();
    let mut account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(account.rotate(&ca, &a).await.status, 200);
    let mut b = Device::new();
    assert_eq!(account.add(&ca, &a, &b).await.status, 200);
    let cb = account.sign_in(&server, &b).await;
    let mut folder = Folder::new();
    assert_eq!(
        folder.commit(&cb, &account, &mut b, &[], &[]).await.status,
        200
    );
    // A commit signed by b before its removal, published later.
    let backdated = folder.next(&account, &mut b);

    // A removal without its rotation is refused.
    let entry = account
        .state
        .next_entry(
            &a.identity,
            a.id,
            START_MS,
            hangar_drive_crypto::devicelog::EntryKind::RemoveDevice(b.id),
        )
        .unwrap();
    let reply = ca
        .post(
            LOG_PATH,
            &LogAppendRequest {
                entries: vec![Blob(entry)],
                wraps: vec![],
                device_wrap: None,
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::LogEntryRefused);
    // Wraps that do not cover the remaining devices are refused.
    let rotation = hangar_drive_crypto::epoch::rotate(
        &account.state,
        &a.identity,
        a.id,
        START_MS,
        &mut OsEntropy,
    )
    .unwrap();
    let reply = ca
        .post(
            LOG_PATH,
            &LogAppendRequest {
                entries: vec![Blob(rotation.entry)],
                wraps: vec![],
                device_wrap: None,
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::LogEntryRefused);

    let reply = account.remove(&ca, &a, &[b.id]).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(cb.get(LOG_PATH).await.code(), ErrorCode::Unauthorized);
    let c = Client::new(server.addr);
    let ch: ChallengeResponse = c
        .post(
            CHALLENGE_PATH,
            &ChallengeRequest {
                account: account.id,
                device: b.id,
            },
        )
        .await
        .json();
    let signature =
        b.identity
            .prove_session(&ch.server, TEST_URL, &account.id, &b.id, &ch.challenge);
    let reply = c
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: b.id,
                challenge: ch.challenge,
                server_url: TEST_URL.into(),
                signature,
            },
        )
        .await;
    // Finding E2E-3: the removed device's own proof learns that it was removed (so it forgets
    // the account), once per challenge; nobody without its key learns it.
    assert_eq!(
        (reply.status, reply.code()),
        (403, ErrorCode::DeviceRemoved)
    );
    let replay = c
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: b.id,
                challenge: ch.challenge,
                server_url: TEST_URL.into(),
                signature,
            },
        )
        .await;
    assert_eq!(replay.code(), ErrorCode::ChallengeInvalid, "used up");
    let ch: ChallengeResponse = c
        .post(
            CHALLENGE_PATH,
            &ChallengeRequest {
                account: account.id,
                device: b.id,
            },
        )
        .await
        .json();
    let forged = a
        .identity
        .prove_session(&ch.server, TEST_URL, &account.id, &b.id, &ch.challenge);
    let reply = c
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: b.id,
                challenge: ch.challenge,
                server_url: TEST_URL.into(),
                signature: forged,
            },
        )
        .await;
    assert_eq!(
        (reply.status, reply.code()),
        (401, ErrorCode::ProofInvalid),
        "another key never learns of the removal"
    );
    // Not even another device can publish the removed device's commit (signer removed, and not
    // its own commit).
    let reply = ca
        .post(
            &commit_path(&folder.id),
            &folder.request(&backdated, &[], &[]),
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);
    // The feed announced log and epoch.
    let page = feed(&ca, 0).await;
    assert!(page
        .entries
        .iter()
        .any(|e| matches!(e.change, FeedChange::Epoch { epoch: Epoch(2) })));
    assert!(page.entries.iter().any(
        |e| matches!(e.change, FeedChange::DeviceLog { length } if length == account.state.len())
    ));
    server.stop().await.unwrap();
}

#[tokio::test]
async fn records_follow_the_version_rule_and_need_the_current_sender() {
    let mut server = TestServer::start("records").await;
    let a = Device::new();
    let mut account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let key = RecordKey::new(RecordKind::Folders, None).unwrap();
    let path = record_path(&key);
    assert_eq!(ca.get(&path).await.code(), ErrorCode::NotFound);
    assert_eq!(account.rotate(&ca, &a).await.status, 200);
    let b = Device::new();
    assert_eq!(account.add(&ca, &a, &b).await.status, 200);
    let cipher =
        RecordCipher::for_epoch(&account.state, account.secret.as_ref().unwrap(), Epoch(1))
            .unwrap();
    let head = account.head();
    let seal = |version: u64, device: &Device| {
        cipher
            .seal(
                &key,
                version,
                &device.identity,
                &device.id,
                &head,
                b"list",
                &mut OsEntropy,
            )
            .unwrap()
    };
    let put = |version: u64, data: Vec<u8>| RecordPut {
        version,
        data: Blob(data),
    };
    // Version 2 before 1.
    let reply = ca.send("PUT", &path, &put(2, seal(2, &a))).await;
    assert_eq!(
        (reply.status, reply.code()),
        (409, ErrorCode::RecordVersion)
    );
    // A record whose header names another sender than the session's device.
    let reply = ca.send("PUT", &path, &put(1, seal(1, &b))).await;
    assert_eq!(reply.code(), ErrorCode::Forbidden);
    // Header and request disagree on the version.
    let reply = ca.send("PUT", &path, &put(1, seal(2, &a))).await;
    assert_eq!(reply.code(), ErrorCode::BadRequest);
    let reply = ca.send("PUT", &path, &put(1, seal(1, &a))).await;
    assert_eq!(reply.status, 200);
    let reply = ca.send("PUT", &path, &put(1, seal(1, &a))).await;
    assert_eq!(
        reply.code(),
        ErrorCode::RecordVersion,
        "no second version 1"
    );
    let stored: RecordResponse = ca.get(&path).await.json();
    assert_eq!(stored.version, 1);
    let page = feed(&ca, 0).await;
    assert!(page
        .entries
        .iter()
        .any(|e| e.change == FeedChange::Record { key, version: 1 }));
    // A folder key ring is per folder.
    let ring =
        RecordKey::new(RecordKind::FolderKeys, Some(FolderId::from_bytes(random()))).unwrap();
    let data = cipher
        .seal(
            &ring,
            1,
            &a.identity,
            &a.id,
            &account.head(),
            b"ring",
            &mut OsEntropy,
        )
        .unwrap();
    assert_eq!(
        ca.send("PUT", &record_path(&ring), &put(1, data))
            .await
            .status,
        200
    );
    // After b is removed and the epoch rotated, a record sealed under the old epoch is refused.
    let cb = account.sign_in(&server, &b).await;
    let old = seal(2, &b);
    assert_eq!(account.remove(&ca, &a, &[b.id]).await.status, 200);
    assert_eq!(
        cb.send("PUT", &path, &put(2, old.clone())).await.code(),
        ErrorCode::Unauthorized
    );
    let reply = ca.send("PUT", &path, &put(2, seal(2, &a))).await;
    assert_eq!(
        reply.code(),
        ErrorCode::BadRequest,
        "sealed under an old epoch"
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn pairing_slots_are_reserved_by_the_inviter_and_written_once() {
    let mut server = TestServer::start("pairing").await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let other = Device::new();
    let other_account = Account::create(&server, &other, &[]).await;
    let co = other_account.sign_in(&server, &other).await;
    let new = Device::new();
    let id = PairingId::from_bytes(random());
    let request = PairingRequest {
        device: new.id,
        sign: new.identity.public_keys().sign,
        kem: new.identity.public_keys().kem,
        proof: Signature::from_bytes([4; 64]),
        sealed_name: Blob(vec![6; SEALED_NAME_OVERHEAD + 6]),
        tag: Blob(vec![5; 32]),
    };
    let anonymous = Client::new(server.addr);
    // Finding M2: without a reservation nobody can create a slot, so invented IDs cannot fill
    // the server's slots and lock out real pairings.
    let reply = anonymous.post(&pairing_path(&id), &request).await;
    assert_eq!((reply.status, reply.code()), (404, ErrorCode::NotFound));
    for _ in 0..20 {
        let reply = anonymous
            .post(&pairing_path(&PairingId::from_bytes(random())), &request)
            .await;
        assert!(matches!(
            reply.code(),
            ErrorCode::NotFound | ErrorCode::RateLimited
        ));
    }
    let slots: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing")
        .fetch_one(&server.app.db)
        .await
        .unwrap();
    assert_eq!(slots, 0, "no slot without a session");
    // The inviting device reserves the slot; reserving again is idempotent.
    assert_eq!(
        anonymous.send("PUT", &pairing_path(&id), &()).await.code(),
        ErrorCode::Unauthorized
    );
    let reply = ca.send("PUT", &pairing_path(&id), &()).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json::<PairingReservation>(),
        PairingReservation {
            expires_in_secs: 600
        }
    );
    assert_eq!(ca.send("PUT", &pairing_path(&id), &()).await.status, 200);
    // Another account can neither take nor read it.
    assert_eq!(
        co.send("PUT", &pairing_path(&id), &()).await.code(),
        ErrorCode::AlreadyExists
    );
    assert_eq!(
        ca.get(&pairing_path(&id)).await.code(),
        ErrorCode::NotFound,
        "still empty"
    );
    assert_eq!(
        anonymous.post(&pairing_path(&id), &request).await.status,
        204
    );
    let reply = anonymous.post(&pairing_path(&id), &request).await;
    assert_eq!(
        reply.code(),
        ErrorCode::AlreadyExists,
        "nobody replaces a waiting request"
    );
    let mut bad = request.clone();
    bad.sealed_name = Blob(vec![6; SEALED_NAME_OVERHEAD]);
    let reply = anonymous
        .post(&pairing_path(&PairingId::from_bytes(random())), &bad)
        .await;
    assert_eq!(reply.code(), ErrorCode::BadRequest);
    assert_eq!(
        anonymous.get(&pairing_path(&id)).await.code(),
        ErrorCode::Unauthorized
    );
    assert_eq!(
        co.get(&pairing_path(&id)).await.code(),
        ErrorCode::NotFound,
        "another account cannot read the request"
    );
    let got: PairingRequest = ca.get(&pairing_path(&id)).await.json();
    assert_eq!(got, request);
    // At most four open slots per account.
    for _ in 0..3 {
        let reply = ca
            .send("PUT", &pairing_path(&PairingId::from_bytes(random())), &())
            .await;
        assert_eq!(reply.status, 200);
    }
    let reply = ca
        .send("PUT", &pairing_path(&PairingId::from_bytes(random())), &())
        .await;
    assert_eq!(reply.code(), ErrorCode::RateLimited);
    assert_eq!(
        co.send("PUT", &pairing_path(&PairingId::from_bytes(random())), &())
            .await
            .status,
        200,
        "the limit is per account"
    );
    server.clock.advance_ms(11 * 60_000);
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        ca.get(&pairing_path(&id)).await.code(),
        ErrorCode::NotFound,
        "expired with the offer"
    );
    assert_eq!(
        ca.send("PUT", &pairing_path(&PairingId::from_bytes(random())), &())
            .await
            .status,
        200,
        "expired slots free their places"
    );
    server.stop().await.unwrap();
}

/// Finding E2E-6: the inviting device closes its slot once the person answered, so the request
/// leaves the server at once; a slot nobody closes goes with the periodic housekeeping.
#[tokio::test]
async fn a_pairing_slot_is_closed_by_its_account_and_expired_slots_are_swept() {
    let mut server = TestServer::start("pairing-close").await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let other = Device::new();
    let other_account = Account::create(&server, &other, &[]).await;
    let co = other_account.sign_in(&server, &other).await;
    let new = Device::new();
    let request = PairingRequest {
        device: new.id,
        sign: new.identity.public_keys().sign,
        kem: new.identity.public_keys().kem,
        proof: Signature::from_bytes([4; 64]),
        sealed_name: Blob(vec![6; SEALED_NAME_OVERHEAD + 6]),
        tag: Blob(vec![5; 32]),
    };
    let anonymous = Client::new(server.addr);
    let slots = |server: &TestServer| {
        let db = server.app.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pairing")
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };
    let id = PairingId::from_bytes(random());
    assert_eq!(ca.send("PUT", &pairing_path(&id), &()).await.status, 200);
    assert_eq!(
        anonymous.post(&pairing_path(&id), &request).await.status,
        204
    );
    // Only the reserving account closes it; nobody without a session, no other account.
    assert_eq!(
        anonymous.delete(&pairing_path(&id)).await.code(),
        ErrorCode::Unauthorized
    );
    assert_eq!(co.delete(&pairing_path(&id)).await.status, 204);
    let got: PairingRequest = ca.get(&pairing_path(&id)).await.json();
    assert_eq!(got, request, "another account's close changes nothing");
    assert_eq!(ca.delete(&pairing_path(&id)).await.status, 204);
    assert_eq!(slots(&server).await, 0, "the request left the server");
    assert_eq!(ca.get(&pairing_path(&id)).await.code(), ErrorCode::NotFound);
    assert_eq!(
        anonymous.post(&pairing_path(&id), &request).await.code(),
        ErrorCode::NotFound,
        "a closed slot takes no second request"
    );
    assert_eq!(
        ca.delete(&pairing_path(&id)).await.status,
        204,
        "closing again is no error (a retry after a lost answer)"
    );
    // A slot nobody closes: deleted by the housekeeping once it expired, not before.
    let forgotten = PairingId::from_bytes(random());
    assert_eq!(
        ca.send("PUT", &pairing_path(&forgotten), &()).await.status,
        200
    );
    hangar_drive_server::service::retention::housekeeping(&server.app)
        .await
        .unwrap();
    assert_eq!(slots(&server).await, 1, "still open");
    server.clock.advance_ms(11 * 60_000);
    hangar_drive_server::service::retention::housekeeping(&server.app)
        .await
        .unwrap();
    assert_eq!(slots(&server).await, 0, "expired and swept");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn objects_upload_once_with_checked_headers_and_sizes() {
    let mut server = TestServer::start("objects").await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let folder = FolderId::from_bytes(random());
    let chunk = Obj::new(ObjectType::Chunk, 1000);
    let reply = ca
        .post(
            &missing_objects_path(&folder),
            &MissingObjectsRequest {
                ids: vec![chunk.id],
            },
        )
        .await;
    assert_eq!(
        reply.json::<MissingObjectsResponse>().missing,
        vec![chunk.id]
    );
    let reply = upload(&ca, &folder, &chunk).await;
    assert_eq!(reply.status, 201);
    assert!(reply.json::<UploadResponse>().stored);
    let reply = upload(&ca, &folder, &chunk).await;
    assert_eq!(
        (reply.status, reply.json::<UploadResponse>().stored),
        (200, false)
    );
    let reply = ca
        .post(
            &missing_objects_path(&folder),
            &MissingObjectsRequest {
                ids: vec![chunk.id, ObjectId::from_bytes([7; 32])],
            },
        )
        .await;
    assert_eq!(
        reply.json::<MissingObjectsResponse>().missing,
        vec![ObjectId::from_bytes([7; 32])]
    );
    let reply = ca
        .post(
            &missing_objects_path(&folder),
            &MissingObjectsRequest {
                ids: vec![chunk.id, chunk.id],
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::BadRequest);
    let reply = ca.get(&object_path(&folder, &chunk.id)).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, chunk.blob);
    assert_eq!(
        reply.header("content-type").as_deref(),
        Some("application/octet-stream")
    );
    // A wrong header, a wrong Padmé length, an unknown type, a chunk above 4 MiB.
    let id = |b: u8| ObjectId::from_bytes([b; 32]);
    let mut bad = chunk.blob.clone();
    bad[0] = 2;
    assert_eq!(
        ca.put_bytes(&object_path(&folder, &id(1)), &bad)
            .await
            .code(),
        ErrorCode::BadRequest
    );
    let short = &chunk.blob[..chunk.blob.len() - 1];
    assert_eq!(
        ca.put_bytes(&object_path(&folder, &id(2)), short)
            .await
            .code(),
        ErrorCode::BadRequest
    );
    let mut kind = chunk.blob.clone();
    kind[5] = 9;
    assert_eq!(
        ca.put_bytes(&object_path(&folder, &id(3)), &kind)
            .await
            .code(),
        ErrorCode::BadRequest
    );
    // Padmé rounds a little above 4 MiB to the same blob length, so go one Padmé step further.
    let huge = blob(ObjectType::Chunk, 4 * 1024 * 1024 + 128 * 1024);
    let reply = ca.put_bytes(&object_path(&folder, &id(4)), &huge).await;
    assert_eq!((reply.status, reply.code()), (413, ErrorCode::TooLarge));
    // The same length is fine for a file manifest, whose limit is higher.
    let manifest = Obj {
        id: id(5),
        blob: blob(ObjectType::FileManifest, 4 * 1024 * 1024 + 128 * 1024),
    };
    assert_eq!(upload(&ca, &folder, &manifest).await.status, 201);
    let reply = ca.get(&object_path(&folder, &id(1))).await;
    assert_eq!(reply.code(), ErrorCode::NotFound);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn objects_and_folders_of_another_account_are_out_of_reach() {
    let mut server = TestServer::start("idor").await;
    let mut x = Device::new();
    let ax = Account::create(&server, &x, &[]).await;
    let cx = ax.sign_in(&server, &x).await;
    let mut y = Device::new();
    let ay = Account::create(&server, &y, &[]).await;
    let cy = ay.sign_in(&server, &y).await;
    let mut fx = Folder::new();
    let secret = Obj::new(ObjectType::Chunk, 64);
    assert_eq!(upload(&cx, &fx.id, &secret).await.status, 201);
    assert_eq!(
        fx.commit(&cx, &ax, &mut x, &[&secret], &[]).await.status,
        200
    );

    // Y names X's folder ID: it is a different folder for Y, one Y holds nothing of, with the
    // empty chain every unknown folder has (finding E2E-2), not X's commits.
    assert_eq!(
        cy.get(&object_path(&fx.id, &secret.id)).await.code(),
        ErrorCode::NotFound
    );
    let page: DeltaPage = cy.get(&commits_path(&fx.id)).await.json();
    assert_eq!(
        page,
        DeltaPage {
            commits: Vec::new(),
            sequence: 0,
            more: false,
        }
    );
    let unknown: DeltaPage = cy
        .get(&commits_path(&FolderId::from_bytes(random())))
        .await
        .json();
    assert_eq!(unknown, page, "the same answer as for any folder");
    let missing: MissingObjectsResponse = cy
        .post(
            &missing_objects_path(&fx.id),
            &MissingObjectsRequest {
                ids: vec![secret.id],
            },
        )
        .await
        .json();
    assert_eq!(missing.missing, vec![secret.id]);
    let mut fy = Folder {
        id: fx.id,
        head: None,
    };
    let reply = fy.commit(&cy, &ay, &mut y, &[&secret], &[]).await;
    assert_eq!(reply.code(), ErrorCode::MissingObjects);
    assert_eq!(reply.json::<ErrorBody>().missing, vec![secret.id]);
    assert_eq!(
        cy.post(&retire_path(&fx.id), &json!({})).await.code(),
        ErrorCode::NotFound
    );
    // Y's upload under the same IDs does not touch X's object.
    let impostor = Obj {
        id: secret.id,
        blob: blob(ObjectType::Chunk, 64),
    };
    assert_eq!(upload(&cy, &fx.id, &impostor).await.status, 201);
    assert_eq!(
        cx.get(&object_path(&fx.id, &secret.id)).await.body,
        secret.blob
    );
    // A commit for Y's account signed for X's account is refused.
    let foreign = fx.next(&ax, &mut x);
    let reply = cy
        .post(
            &commit_path(&fx.id),
            &Folder {
                id: fx.id,
                head: None,
            }
            .request(&foreign, &[], &[]),
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn commits_compare_and_swap_merge_and_check_their_deltas() {
    let mut server = TestServer::start("commits").await;
    let mut a = Device::new();
    let mut account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut b = Device::new();
    assert_eq!(account.add(&ca, &a, &b).await.status, 200);
    let cb = account.sign_in(&server, &b).await;
    let mut folder = Folder::new();
    let o1 = Obj::new(ObjectType::Chunk, 100);
    let o2 = Obj::new(ObjectType::FileManifest, 50);
    let root = Obj::new(ObjectType::DirectoryNode, 40);
    for o in [&o1, &o2, &root] {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    // A first commit that names a missing object.
    let ghost = Obj::new(ObjectType::Chunk, 10);
    let reply = folder
        .commit(&ca, &account, &mut a, &[&o1, &ghost], &[])
        .await;
    assert_eq!(
        (reply.status, reply.code()),
        (400, ErrorCode::MissingObjects)
    );
    assert_eq!(reply.json::<ErrorBody>().missing, vec![ghost.id]);
    // Dropping something that is not in the tree.
    let reply = folder.commit(&ca, &account, &mut a, &[&o1], &[&o2]).await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);
    let reply = folder
        .commit(&ca, &account, &mut a, &[&o1, &o2, &root], &[])
        .await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let base = folder.entry().unwrap();
    let base_head = folder.head.clone();
    // Adding what is already live is refused.
    let reply = folder.commit(&ca, &account, &mut a, &[&o1], &[]).await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);

    // A device publishes only its own commits.
    let by_a = folder.next(&account, &mut a);
    let reply = cb
        .post(&commit_path(&folder.id), &folder.request(&by_a, &[], &[]))
        .await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);

    // a commits H; b, still on the base, loses the swap and learns the head.
    let o3 = Obj::new(ObjectType::Chunk, 30);
    assert_eq!(upload(&ca, &folder.id, &o3).await.status, 201);
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&o3], &[&o1])
            .await
            .status,
        200
    );
    let h = folder.entry().unwrap();
    let stale = Folder {
        id: folder.id,
        head: base_head.clone(),
    };
    let c_side = stale.next(&account, &mut b);
    let reply = cb
        .post(&commit_path(&folder.id), &stale.request(&c_side, &[], &[]))
        .await;
    assert_eq!((reply.status, reply.code()), (409, ErrorCode::HeadMoved));
    assert_eq!(reply.json::<ErrorBody>().current_head, Some(h.commit));
    // Replaying an accepted commit is refused.
    let (accepted, _) = folder.head.clone().unwrap();
    let mut replay = folder.request(&accepted, &[], &[]);
    replay.expected_head = Some(h.commit);
    assert_eq!(
        ca.post(&commit_path(&folder.id), &replay).await.code(),
        ErrorCode::CommitRefused
    );

    // b merges: side commit C on the base (marked as side), merge M on H.
    let side = Commit::side(
        account.id,
        folder.id,
        &base,
        CommitContent {
            root: ObjectId::from_bytes(random()),
            generation: Generation(1),
            device: b.id,
            log_head: account.head(),
            counter: b.next_counter(),
        },
    )
    .sign(&b.identity)
    .unwrap();
    let merge = Commit::merge(
        account.id,
        folder.id,
        &h,
        &side,
        CommitContent {
            root: ObjectId::from_bytes(random()),
            generation: Generation(1),
            device: b.id,
            log_head: account.head(),
            counter: b.next_counter(),
        },
    )
    .sign(&b.identity)
    .unwrap();
    let o4 = Obj::new(ObjectType::Chunk, 20);
    assert_eq!(upload(&cb, &folder.id, &o4).await.status, 201);
    let side_upload = CommitUpload {
        commit: Blob(side.wire.clone()),
        delta: ReferenceDelta {
            added: vec![o4.id],
            dropped: vec![o2.id],
        },
    };
    // The merge alone, without its side commit, is refused.
    let mut request = folder.request(&merge, &[&o4], &[]);
    let reply = cb.post(&commit_path(&folder.id), &request).await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);
    // A side commit presented as the head is refused.
    let as_head = CommitRequest {
        expected_head: Some(h.commit),
        head: side_upload.clone(),
        side: None,
    };
    assert_eq!(
        cb.post(&commit_path(&folder.id), &as_head).await.code(),
        ErrorCode::CommitRefused
    );
    request.side = Some(side_upload);
    let reply = cb.post(&commit_path(&folder.id), &request).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let response: CommitResponse = reply.json();
    assert_eq!(response.sequence, 3);

    // The delta pull: three heads and the side commit sharing the merge's sequence.
    let page: DeltaPage = ca.get(&commits_path(&folder.id)).await.json();
    assert_eq!(page.sequence, 3);
    assert!(!page.more);
    let roles: Vec<(u64, CommitRole)> = page.commits.iter().map(|c| (c.sequence, c.role)).collect();
    assert_eq!(
        roles,
        vec![
            (1, CommitRole::Head),
            (2, CommitRole::Head),
            (3, CommitRole::Side),
            (3, CommitRole::Head)
        ]
    );
    let after: DeltaPage = ca
        .get(&format!("{}?after=2", commits_path(&folder.id)))
        .await
        .json();
    assert_eq!(after.commits.len(), 2);
    // The feed: the folder was created and has its newest head.
    let page = feed(&ca, 0).await;
    assert!(page
        .entries
        .iter()
        .any(|e| e.change == FeedChange::FolderCreated { folder: folder.id }));
    assert!(page.entries.iter().any(|e| e.change
        == FeedChange::FolderHead {
            folder: folder.id,
            sequence: 3
        }));
    let heads = page
        .entries
        .iter()
        .filter(|e| matches!(e.change, FeedChange::FolderHead { .. }))
        .count();
    assert_eq!(heads, 1, "the feed keeps the newest head per folder");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn retired_folders_refuse_writes_and_come_back_within_the_window() {
    let mut server = TestServer::start("retire").await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut folder = Folder::new();
    let o = Obj::new(ObjectType::Chunk, 100);
    assert_eq!(upload(&ca, &folder.id, &o).await.status, 201);
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&o], &[])
            .await
            .status,
        200
    );
    assert_eq!(
        ca.post(&retire_path(&folder.id), &json!({})).await.status,
        204
    );
    assert_eq!(
        ca.post(&retire_path(&folder.id), &json!({})).await.code(),
        ErrorCode::FolderRetired
    );
    let reply = folder.commit(&ca, &account, &mut a, &[], &[]).await;
    assert_eq!(
        (reply.status, reply.code()),
        (410, ErrorCode::FolderRetired)
    );
    let other = Obj::new(ObjectType::Chunk, 10);
    assert_eq!(
        upload(&ca, &folder.id, &other).await.code(),
        ErrorCode::FolderRetired
    );
    assert_eq!(
        ca.get(&commits_path(&folder.id)).await.status,
        200,
        "history stays readable"
    );
    let page = feed(&ca, 0).await;
    assert!(page
        .entries
        .iter()
        .any(|e| e.change == FeedChange::FolderRetired { folder: folder.id }));
    assert_eq!(ca.delete(&retire_path(&folder.id)).await.status, 204);
    assert_eq!(
        folder.commit(&ca, &account, &mut a, &[], &[]).await.status,
        200
    );
    // Retired again, then the window passes: the folder is gone for good.
    assert_eq!(
        ca.post(&retire_path(&folder.id), &json!({})).await.status,
        204
    );
    server.clock.advance_ms(31 * DAY_MS);
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        ca.delete(&retire_path(&folder.id)).await.code(),
        ErrorCode::NotFound
    );
    let outcome = server.gc().await;
    assert_eq!(outcome.deleted_folders, 1);
    let page: DeltaPage = ca.get(&commits_path(&folder.id)).await.json();
    assert!(
        page.commits.is_empty() && page.sequence == 0,
        "gone for good: {page:?}"
    );
    server.stop().await.unwrap();
}

async fn read_until(stream: &mut TcpStream, needle: &str, seen: &mut String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !seen.contains(needle) {
        let mut buffer = [0u8; 1024];
        let n = tokio::time::timeout_at(deadline, stream.read(&mut buffer))
            .await
            .expect("no event in time")
            .unwrap();
        assert!(n > 0, "stream closed");
        seen.push_str(&String::from_utf8_lossy(&buffer[..n]));
    }
}

#[tokio::test]
async fn the_event_stream_carries_only_the_account_sequence() {
    let mut server = TestServer::start("sse").await;
    let a = Device::new();
    let mut account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let head = format!(
        "GET {EVENTS_PATH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
        ca.token.as_ref().unwrap()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut seen = String::new();
    read_until(&mut stream, "{\"sequence\":1}", &mut seen).await;
    assert!(seen
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    assert!(seen.to_ascii_lowercase().contains("x-accel-buffering: no"));
    assert!(seen.contains("event: sequence"));
    assert_eq!(account.rotate(&ca, &a).await.status, 200);
    // A rotation adds two feed entries (epoch, log); the stream reports the newest sequence.
    read_until(&mut stream, "{\"sequence\":3}", &mut seen).await;
    assert!(
        !seen.contains("epoch"),
        "the event names no change, only the sequence"
    );
    // The polling fallback reads the same feed.
    let page = feed(&ca, 1).await;
    assert_eq!(page.sequence, 3);
    assert_eq!(page.entries.len(), 2);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn sign_in_invite_pairing_and_upload_are_rate_limited() {
    // Limits divided by 30: challenge and proof 2 per minute and address, failed proofs 1 per
    // ten minutes and device, invites 1 per hour, anonymous pairing posts 1 per ten minutes.
    let mut server = TestServer::with(
        "ratelimit",
        Options {
            limiter: RateLimiter::scaled(30),
            ..Options::default()
        },
    )
    .await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let client = Client::new(server.addr);
    let challenge = ChallengeRequest {
        account: account.id,
        device: a.id,
    };
    assert_eq!(client.post(CHALLENGE_PATH, &challenge).await.status, 200);
    let reply = client.post(CHALLENGE_PATH, &challenge).await;
    assert_eq!((reply.status, reply.code()), (429, ErrorCode::RateLimited));
    assert_eq!(reply.header("retry-after").as_deref(), Some("60"));
    server.clock.advance_ms(61_000);
    // Invites: the creation above used the one of this window.
    let reply = client
        .post(
            ACCOUNTS_PATH,
            &CreateAccountRequest {
                invite: server.invite().await,
                account: AccountId::from_bytes(random()),
                genesis: Blob(vec![1]),
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::RateLimited);
    // Failed proofs count per account and listed device (finding M1); after one, even a valid
    // proof of that device waits for the window.
    let c: ChallengeResponse = client.post(CHALLENGE_PATH, &challenge).await.json();
    let proof = |signature| ProofRequest {
        account: account.id,
        device: a.id,
        challenge: c.challenge,
        server_url: TEST_URL.into(),
        signature,
    };
    let wrong =
        Device::new()
            .identity
            .prove_session(&c.server, TEST_URL, &account.id, &a.id, &c.challenge);
    assert_eq!(
        client.post(PROOF_PATH, &proof(wrong)).await.code(),
        ErrorCode::ProofInvalid
    );
    let right = a
        .identity
        .prove_session(&c.server, TEST_URL, &account.id, &a.id, &c.challenge);
    assert_eq!(
        client.post(PROOF_PATH, &proof(right)).await.code(),
        ErrorCode::RateLimited
    );
    // Devices the log does not list leave no trace in that table.
    server.clock.advance_ms(61_000);
    let stranger = Device::new();
    for _ in 0..2 {
        let c: ChallengeResponse = client
            .post(
                CHALLENGE_PATH,
                &ChallengeRequest {
                    account: account.id,
                    device: stranger.id,
                },
            )
            .await
            .json();
        let signature = stranger.identity.prove_session(
            &c.server,
            TEST_URL,
            &account.id,
            &stranger.id,
            &c.challenge,
        );
        let reply = client
            .post(
                PROOF_PATH,
                &ProofRequest {
                    account: account.id,
                    device: stranger.id,
                    challenge: c.challenge,
                    server_url: TEST_URL.into(),
                    signature,
                },
            )
            .await;
        assert_eq!(reply.code(), ErrorCode::ProofInvalid);
    }
    assert_eq!(
        server.app.limiter.keys(Scope::ProofFailures),
        1,
        "only the listed device was counted"
    );
    server.clock.advance_ms(600_000);
    let right = a
        .identity
        .prove_session(&c.server, TEST_URL, &account.id, &a.id, &c.challenge);
    assert_eq!(
        client.post(PROOF_PATH, &proof(right)).await.code(),
        ErrorCode::ChallengeInvalid,
        "the window ended; the challenge expired meanwhile"
    );
    // Pairing: one anonymous post per window and address.
    let request = PairingRequest {
        device: a.id,
        sign: a.identity.public_keys().sign,
        kem: a.identity.public_keys().kem,
        proof: Signature::from_bytes([4; 64]),
        sealed_name: Blob(vec![6; SEALED_NAME_OVERHEAD + 5]),
        tag: Blob(vec![5; 32]),
    };
    let (first, second) = (
        PairingId::from_bytes(random()),
        PairingId::from_bytes(random()),
    );
    for id in [&first, &second] {
        assert_eq!(ca.send("PUT", &pairing_path(id), &()).await.status, 200);
    }
    assert_eq!(
        client.post(&pairing_path(&first), &request).await.status,
        204
    );
    let reply = client.post(&pairing_path(&second), &request).await;
    assert_eq!(reply.code(), ErrorCode::RateLimited);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn one_network_shares_a_higher_limit_across_its_addresses() {
    // Finding M1: an attacker with many addresses of one network (an IPv6 /48 has 65536 /64s)
    // gets the network's limit, not one per address. Scaled by 30: 2 per address, 8 per
    // network and minute.
    let mut server = TestServer::with(
        "netlimit",
        Options {
            limiter: RateLimiter::scaled(30),
            trusted: "127.0.0.1",
            ..Options::default()
        },
    )
    .await;
    let challenge = ChallengeRequest {
        account: AccountId::from_bytes(random()),
        device: DeviceId::from_bytes(random()),
    };
    let mut ok = 0;
    for i in 0..12u16 {
        let mut c = Client::new(server.addr);
        c.extra = vec![("X-Forwarded-For", format!("2001:db8:7:{i:x}::1"))];
        if c.post(CHALLENGE_PATH, &challenge).await.status == 200 {
            ok += 1;
        }
    }
    assert_eq!(ok, 8);
    let mut elsewhere = Client::new(server.addr);
    elsewhere.extra = vec![("X-Forwarded-For", "2001:db8:8::1".into())];
    assert_eq!(
        elsewhere.post(CHALLENGE_PATH, &challenge).await.status,
        200,
        "another network has its own limit"
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn forwarded_addresses_count_only_from_trusted_proxies() {
    let limited = || RateLimiter::scaled(60);
    // Not trusted: the header changes nothing, every request is the peer's.
    let mut server = TestServer::with(
        "xff-untrusted",
        Options {
            limiter: limited(),
            ..Options::default()
        },
    )
    .await;
    let mut a = Client::new(server.addr);
    a.extra = vec![("X-Forwarded-For", "198.51.100.1".into())];
    let mut b = Client::new(server.addr);
    b.extra = vec![("X-Forwarded-For", "198.51.100.2".into())];
    let challenge = |n: u8| ChallengeRequest {
        account: AccountId::from_bytes([n; 16]),
        device: DeviceId::from_bytes([n; 16]),
    };
    assert_eq!(a.post(CHALLENGE_PATH, &challenge(1)).await.status, 200);
    assert_eq!(
        b.post(CHALLENGE_PATH, &challenge(2)).await.code(),
        ErrorCode::RateLimited
    );
    server.stop().await.unwrap();
    // Trusted: each forwarded client has its own limit, and a spoofed entry left of the proxy's
    // does not help.
    let mut server = TestServer::with(
        "xff-trusted",
        Options {
            limiter: limited(),
            trusted: "127.0.0.1",
            ..Options::default()
        },
    )
    .await;
    let mut a = Client::new(server.addr);
    a.extra = vec![("X-Forwarded-For", "198.51.100.1".into())];
    let mut b = Client::new(server.addr);
    b.extra = vec![("X-Forwarded-For", "198.51.100.2".into())];
    let mut spoof = Client::new(server.addr);
    spoof.extra = vec![("X-Forwarded-For", "203.0.113.9, 198.51.100.1".into())];
    assert_eq!(a.post(CHALLENGE_PATH, &challenge(1)).await.status, 200);
    assert_eq!(b.post(CHALLENGE_PATH, &challenge(2)).await.status, 200);
    assert_eq!(
        spoof.post(CHALLENGE_PATH, &challenge(3)).await.code(),
        ErrorCode::RateLimited
    );
    server.stop().await.unwrap();
}

// Sign-in relay (security review, open point "session binding"): a recovery sheet or link with
// this server's real ID and a foreign URL makes the device sign its proof for the foreign host.
// That host can hand the proof on to the real server, but a server that knows its public URL
// refuses a proof for any other address; its own address still signs in.
#[tokio::test]
async fn a_proof_for_another_address_is_refused_by_a_server_with_a_public_url() {
    let mut server = TestServer::start("flows-relay").await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let client = Client::new(server.addr);
    let challenge = ChallengeRequest {
        account: account.id,
        device: a.id,
    };
    for relay in ["https://drive.example.evil/", "https://evil.example/"] {
        let c: ChallengeResponse = client.post(CHALLENGE_PATH, &challenge).await.json();
        let signature =
            a.identity
                .prove_session(&c.server, relay, &account.id, &a.id, &c.challenge);
        let reply = client
            .post(
                PROOF_PATH,
                &ProofRequest {
                    account: account.id,
                    device: a.id,
                    challenge: c.challenge,
                    server_url: relay.into(),
                    signature,
                },
            )
            .await;
        assert_eq!(
            (reply.status, reply.code()),
            (401, ErrorCode::ProofInvalid),
            "{relay}"
        );
        // The failure counts like any failed proof (finding M1); the next window is clean.
        server.clock.advance_ms(61_000);
    }
    // The relay also cannot claim the real address over a proof made for its own.
    let c: ChallengeResponse = client.post(CHALLENGE_PATH, &challenge).await.json();
    let signature = a.identity.prove_session(
        &c.server,
        "https://evil.example/",
        &account.id,
        &a.id,
        &c.challenge,
    );
    let reply = client
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: a.id,
                challenge: c.challenge,
                server_url: TEST_URL.into(),
                signature,
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::ProofInvalid);
    server.clock.advance_ms(61_000);
    account.sign_in(&server, &a).await;
    server.stop().await.unwrap();
}
