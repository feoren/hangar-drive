//! The server security review (MEDIUM 2, the device log throttle of the crypto follow-up, and
//! the measurement of MEDIUM 2): commits load their IDs before the write lock, refused commits
//! brake the account, and rotations without a removal are throttled while removals never are.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::ObjectId;
use hangar_drive_protocol::object::ObjectType;
use hangar_drive_server::app::{Hook, Hooks};
use hangar_drive_server::http::ratelimit::Scope;

/// A hook that reports each arrival and waits until the test releases it.
struct Gate {
    arrived: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
    calls: Arc<AtomicUsize>,
}

impl Gate {
    fn new() -> Self {
        Self {
            arrived: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn hook(&self) -> Hook {
        let (arrived, release, calls) = (
            self.arrived.clone(),
            self.release.clone(),
            self.calls.clone(),
        );
        Arc::new(move || {
            let (arrived, release) = (arrived.clone(), release.clone());
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                arrived.notify_one();
                let _ = release.acquire().await;
            })
        })
    }

    fn open(&self) {
        self.release.add_permits(1000);
    }
}

async fn gated_server(name: &str, gate: &Gate) -> TestServer {
    TestServer::with(
        name,
        Options {
            hooks: Hooks {
                commit_prepared: Some(gate.hook()),
            },
            ..Options::default()
        },
    )
    .await
}

/// A first commit of a new folder that adds `ids`, none of which the server holds.
fn phantom_request(account: &Account, device: &mut Device, folder: &Folder) -> CommitRequest {
    let mut ids: Vec<ObjectId> = (0..8).map(|_| ObjectId::from_bytes(random())).collect();
    ids.sort();
    let commit = folder.next_adding(account, device, &ids);
    let mut request = folder.request(&commit, &[], &[]);
    request.head.delta.added = ids;
    request
}

#[tokio::test]
async fn a_slow_commit_does_not_block_another_accounts_sign_in() {
    // MEDIUM 2: the commit took the global write lock before it loaded its IDs, so a commit of
    // one account that took long there made the sign-in, uploads and pairing of every other
    // account wait for it (and fail after the 10 s busy timeout). The gate stops the commit at
    // the end of the work it now does without the lock.
    let gate = Gate::new();
    let mut server = gated_server("review-m2-slow-commit", &gate).await;
    let mut a = Device::new();
    let account_a = Account::create(&server, &a, &[]).await;
    let ca = account_a.sign_in(&server, &a).await;
    let b = Device::new();
    let account_b = Account::create(&server, &b, &[]).await;

    let folder = Folder::new();
    let obj = Obj::new(ObjectType::DirectoryNode, 100);
    assert_eq!(upload(&ca, &folder.id, &obj).await.status, 201);
    let commit = folder.next_with(&account_a, &mut a, &[&obj], &[]);
    let request = folder.request(&commit, &[&obj], &[]);
    let path = commit_path(&folder.id);
    let pending = {
        let ca = ca.clone();
        tokio::spawn(async move { ca.post(&path, &request).await })
    };
    tokio::time::timeout(Duration::from_secs(20), gate.arrived.notified())
        .await
        .expect("the commit reached the gate");

    // Another account signs in (a write: the session row) while the commit waits.
    let started = Instant::now();
    let cb = tokio::time::timeout(Duration::from_secs(5), account_b.sign_in(&server, &b))
        .await
        .expect("the sign-in does not wait for the other account's commit");
    assert!(cb.token.is_some());
    assert!(started.elapsed() < Duration::from_secs(5));

    gate.open();
    let reply = pending.await.unwrap();
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_commit_whose_objects_go_meanwhile_is_refused_under_the_lock() {
    // The held check runs again under the write lock: an object the collection deleted after
    // the first check must not become part of a tree.
    let gate = Gate::new();
    let mut server = gated_server("review-m2-recheck", &gate).await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let folder = Folder::new();
    let obj = Obj::new(ObjectType::DirectoryNode, 100);
    assert_eq!(upload(&ca, &folder.id, &obj).await.status, 201);
    let commit = folder.next_with(&account, &mut a, &[&obj], &[]);
    let request = folder.request(&commit, &[&obj], &[]);
    let path = commit_path(&folder.id);
    let pending = {
        let ca = ca.clone();
        tokio::spawn(async move { ca.post(&path, &request).await })
    };
    tokio::time::timeout(Duration::from_secs(20), gate.arrived.notified())
        .await
        .expect("the commit reached the gate");
    // What the collection does to an uncommitted object: its row goes in a write transaction.
    sqlx::query("DELETE FROM objects WHERE object_id = ?")
        .bind(obj.id.as_bytes().as_slice())
        .execute(&server.app.db)
        .await
        .unwrap();
    gate.open();
    let reply = pending.await.unwrap();
    assert_eq!(reply.code(), ErrorCode::MissingObjects);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn commits_of_objects_the_server_does_not_hold_end_before_the_lock() {
    let gate = Gate::new();
    let mut server = gated_server("review-m2-phantom", &gate).await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let folder = Folder::new();
    let request = phantom_request(&account, &mut a, &folder);
    let reply = ca.post(&commit_path(&folder.id), &request).await;
    assert_eq!(reply.code(), ErrorCode::MissingObjects);
    assert_eq!(
        gate.calls.load(Ordering::SeqCst),
        0,
        "the call never got to the write lock"
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn refused_commits_brake_the_device_and_no_other_account() {
    // MEDIUM 2 (b): an account that keeps sending commits that cannot pass is refused before
    // its next body is read, for the rest of the window.
    let mut server = TestServer::start("review-m2-brake").await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut b = Device::new();
    let other = Account::create(&server, &b, &[]).await;
    let cb = other.sign_in(&server, &b).await;
    let folder = Folder::new();
    let limit = Scope::CommitRefusedDevice.rule().limit;
    for _ in 0..limit {
        let request = phantom_request(&account, &mut a, &folder);
        let reply = ca.post(&commit_path(&folder.id), &request).await;
        assert_eq!(reply.code(), ErrorCode::MissingObjects);
    }
    let request = phantom_request(&account, &mut a, &folder);
    let reply = ca.post(&commit_path(&folder.id), &request).await;
    assert_eq!(
        reply.code(),
        ErrorCode::RateLimited,
        "the account is braked"
    );

    let other_folder = Folder::new();
    let request = phantom_request(&other, &mut b, &other_folder);
    let reply = cb.post(&commit_path(&other_folder.id), &request).await;
    assert_eq!(
        reply.code(),
        ErrorCode::MissingObjects,
        "another account is not"
    );

    server
        .clock
        .advance_ms(Scope::CommitRefusedDevice.rule().window_s * 1000);
    let request = phantom_request(&account, &mut a, &folder);
    let reply = ca.post(&commit_path(&folder.id), &request).await;
    assert_eq!(reply.code(), ErrorCode::MissingObjects, "after the window");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn device_log_appends_are_throttled_and_removals_never() {
    // Crypto follow-up: a compromised current device filled the device log at the call rate
    // and could then no longer be removed. The log format now refuses rotations nothing made
    // due; adding devices is throttled per account (rotations without a removal too, unit
    // tests in `service::devicelog`), and a removal passes after every limit is used up.
    let mut server = TestServer::start("review-log-throttle").await;
    let a = Device::new();
    let thief = Device::new();
    let mut account = Account::create(&server, &a, &[&thief]).await;
    let ca = account.sign_in(&server, &a).await;
    let ct = account.sign_in(&server, &thief).await;
    assert_eq!(
        account.rotate(&ct, &thief).await.status,
        200,
        "the first epoch"
    );
    let hourly = Scope::LogAppendAccount.rule().limit as usize;
    let daily = hangar_drive_server::service::devicelog::ADDS_PER_DAY;
    assert!(daily < hourly);
    // The thief adds devices until the account's adds of the day are used up (security review
    // follow-up, M1: per day, which binds before the hourly appends).
    let mut added = 0;
    loop {
        let reply = account.add(&ct, &thief, &Device::new()).await;
        if reply.status != 200 {
            assert_eq!(reply.code(), ErrorCode::RateLimited);
            break;
        }
        added += 1;
        assert!(added <= daily, "the adds are limited");
    }
    assert_eq!(added, daily);
    let reply = account.add(&ca, &a, &Device::new()).await;
    assert_eq!(
        reply.code(),
        ErrorCode::RateLimited,
        "per account, not per device"
    );
    // The removal of the thief with its rotation still passes.
    let reply = account.remove(&ca, &a, &[thief.id]).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    server.clock.advance_ms(3_600_000);
    let ca = account.sign_in(&server, &a).await;
    let reply = account.add(&ca, &a, &Device::new()).await;
    assert_eq!(reply.code(), ErrorCode::RateLimited, "not after an hour");
    server.clock.advance_ms(24 * 3_600_000);
    let ca = account.sign_in(&server, &a).await;
    let reply = account.add(&ca, &a, &Device::new()).await;
    assert_eq!(reply.status, 200, "after the day");
    server.stop().await.unwrap();
}

/// A server with every limit divided by 30 (100 calls per address and minute), an account with
/// an honest device and a thief behind the same address, both signed in.
async fn shared_address(name: &str) -> (TestServer, Account, Device, Client, Device, Client) {
    let server = TestServer::with(
        name,
        Options {
            limiter: hangar_drive_server::http::ratelimit::RateLimiter::scaled(30),
            ..Options::default()
        },
    )
    .await;
    let a = Device::new();
    let thief = Device::new();
    let account = Account::create(&server, &a, &[&thief]).await;
    let ca = account.sign_in(&server, &a).await;
    let ct = account.sign_in(&server, &thief).await;
    (server, account, a, ca, thief, ct)
}

#[tokio::test]
async fn made_up_tokens_from_the_same_address_do_not_lock_out_a_session() {
    // Follow-up review M2: a device in the same household (same public address) sent calls
    // with made-up tokens and used up the address's limit for every session behind it, also
    // for the call that removes it.
    let (mut server, mut account, a, ca, thief, _ct) = shared_address("review-m2-made-up").await;
    let mut flood = Client::new(server.addr);
    flood.token = Some(
        hangar_drive_protocol::ids::SessionToken::from_bytes(random())
            .expose_base64url()
            .to_string(),
    );
    let limit = Scope::CallIp.rule().limit / 30;
    for _ in 0..limit {
        flood.get(FEED_PATH).await;
    }
    assert_eq!(flood.get(FEED_PATH).await.code(), ErrorCode::RateLimited);
    assert_eq!(
        ca.get(FEED_PATH).await.status,
        200,
        "the session still works"
    );
    let reply = account.remove(&ca, &a, &[thief.id]).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_flooding_device_does_not_keep_another_device_from_removing_it() {
    let (mut server, mut account, a, ca, thief, ct) = shared_address("review-m2-flood").await;
    let limit = Scope::CallDevice.rule().limit / 30;
    for _ in 0..limit {
        ct.get(FEED_PATH).await;
    }
    assert_eq!(
        ct.get(FEED_PATH).await.code(),
        ErrorCode::RateLimited,
        "the thief uses up its own limit"
    );
    assert_eq!(ca.get(FEED_PATH).await.status, 200);
    let reply = account.remove(&ca, &a, &[thief.id]).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    // The thief's own limit is still used up, so its next call is refused before the lookup.
    assert_eq!(ct.get(FEED_PATH).await.code(), ErrorCode::RateLimited);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_token_the_server_issued_is_not_admitted_by_its_tag_alone() {
    // The tag only picks the limit: a revoked session's token stays refused.
    let (mut server, mut account, a, ca, thief, ct) = shared_address("review-m2-revoked").await;
    assert_eq!(account.remove(&ca, &a, &[thief.id]).await.status, 200);
    let token =
        hangar_drive_protocol::ids::SessionToken::from_base64url(ct.token.as_deref().unwrap())
            .unwrap();
    assert!(hangar_drive_server::service::sessions::issued_here(
        &server.app,
        &token
    ));
    assert_eq!(ct.get(FEED_PATH).await.code(), ErrorCode::Unauthorized);
    server.stop().await.unwrap();
}

/// A measurement, not a check (run with `--ignored --nocapture`, ideally with `--release`): a
/// commit with the largest delta, every ID one the server does not hold, and how long a write
/// of another account waits for the write lock meanwhile.
#[tokio::test]
#[ignore]
async fn m2_measure_a_refused_commit_with_the_largest_delta() {
    let mut server = TestServer::start("review-m2-measure").await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let folder = Folder::new();
    // The folder exists, as after a first upload.
    let obj = Obj::new(ObjectType::DirectoryNode, 100);
    assert_eq!(upload(&ca, &folder.id, &obj).await.status, 201);
    let mut ids: Vec<ObjectId> = (0..MAX_REFERENCE_DELTA_IDS)
        .map(|_| ObjectId::from_bytes(random()))
        .collect();
    ids.sort();
    let commit = folder.next_adding(&account, &mut a, &ids);
    let mut request = folder.request(&commit, &[], &[]);
    request.head.delta.added = ids;
    let body = serde_json::to_vec(&request).unwrap();
    drop(request);
    let headers = [
        (
            "Authorization",
            format!("Bearer {}", ca.token.clone().unwrap()),
        ),
        ("Content-Type", "application/json".to_owned()),
    ];
    let path = commit_path(&folder.id);
    let addr = server.addr;
    let started = Instant::now();
    let call = tokio::spawn(async move { raw(addr, "POST", &path, &headers, &body).await });
    // Writes of "another account" (an empty write transaction) while the call runs.
    let mut longest = Duration::ZERO;
    let mut writes = 0u32;
    while !call.is_finished() {
        let t = Instant::now();
        let tx = hangar_drive_server::db::begin_write(&server.app.db)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        longest = longest.max(t.elapsed());
        writes += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let reply = call.await.unwrap();
    eprintln!(
        "refused commit with {} phantom IDs: status {} in {:?}; {} writes beside it, the \
         longest waited {:?} for the write lock",
        MAX_REFERENCE_DELTA_IDS,
        reply.status,
        started.elapsed(),
        writes,
        longest
    );
    assert_eq!(reply.status, 400);
    server.stop().await.unwrap();
}
