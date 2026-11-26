//! One attack per finding of the server security review (2026-11-26), over a real socket with a
//! manual clock. Each test failed before its fix. Findings covered elsewhere: M1 and M2 in
//! `flows.rs` (sign-in, pairing), L4 and M1 units in `config.rs` and `ratelimit.rs`, L6 in
//! `main.rs`, the deployment files (M4, M6, L1, L7) in `deploy_files.rs`.

mod common;

use std::time::Duration;

use common::*;
use hangar_drive_crypto::record::RecordCipher;
use hangar_drive_crypto::OsEntropy;
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::ObjectType;
use hangar_drive_server::config::{Concurrency, Limits};
use hangar_drive_server::http::ratelimit::RateLimiter;
use hangar_drive_server::DataDirLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A chunk of 4142 bytes on the wire (4000 bytes of plaintext).
fn chunk() -> Obj {
    Obj::new(ObjectType::Chunk, 4000)
}

fn tiny() -> Obj {
    Obj::new(ObjectType::Chunk, 16)
}

fn small(quota: u64, headroom: u64) -> Limits {
    let mut limits = Limits::for_quota(quota);
    limits.headroom = headroom;
    limits.min_commits = 1;
    limits.account_budget = 1 << 40;
    limits.device_budget = 1 << 40;
    limits
}

fn pins(page: &FeedPage) -> Vec<CommitId> {
    page.entries
        .iter()
        .filter_map(|e| match &e.change {
            FeedChange::Notice {
                notice: Notice::AnomalyPin { commit, .. },
            } => Some(*commit),
            _ => None,
        })
        .collect()
}

const W_DAYS: u64 = 30;

// ---------------------------------------------------------------------------------------------
// H1: side commits held old objects without budget
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn h1_declaring_garbage_again_in_a_side_commit_costs_budget() {
    // One chunk of budget per day.
    let mut limits = small(1 << 30, 1 << 20);
    limits.account_budget = 5_000;
    limits.device_budget = 5_000;
    let mut server = TestServer::with(
        "h1-side-revival",
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut folder = Folder::new();
    assert_eq!(
        folder.commit(&ca, &account, &mut a, &[], &[]).await.status,
        200
    );
    // Garbage, uploaded once (paid) and declared only by a side commit: never live.
    let garbage = chunk();
    assert_eq!(upload(&ca, &folder.id, &garbage).await.status, 201);
    let base = folder.entry().unwrap();
    assert_eq!(
        folder
            .merge(&ca, &account, &mut a, &base, &[&garbage], &[], &[])
            .await
            .status,
        200
    );
    // Just before the window ends, the budget of the day is spent on something else, and the
    // garbage is declared again by a new side commit.
    server.clock.advance_ms((W_DAYS - 1) * DAY_MS);
    let ca = account.sign_in(&server, &a).await;
    let other = chunk();
    assert_eq!(upload(&ca, &folder.id, &other).await.status, 201);
    let base = folder.entry().unwrap();
    let reply = folder
        .merge(&ca, &account, &mut a, &base, &[&garbage], &[], &[])
        .await;
    assert_eq!(
        (reply.status, reply.code()),
        (507, ErrorCode::BudgetExceeded),
        "reviving retained garbage through a side commit is paid like any revival"
    );
    // So the garbage goes once the window of its first side commit has ended.
    server.clock.advance_ms(2 * DAY_MS);
    server.gc().await;
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        ca.get(&object_path(&folder.id, &garbage.id)).await.code(),
        ErrorCode::NotFound
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn h1_a_side_commit_on_an_old_base_does_not_extend_that_tree() {
    let mut server = TestServer::with(
        "h1-side-base",
        Options {
            limits: small(1 << 30, 1 << 20),
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut folder = Folder::new();
    let x = chunk();
    assert_eq!(upload(&ca, &folder.id, &x).await.status, 201);
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&x], &[])
            .await
            .status,
        200
    );
    let old = folder.entry().unwrap();
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[], &[&x])
            .await
            .status,
        200
    );
    // A side commit on the old head just before its window ends: free before the fix, and it
    // kept the old tree for another window, again and again.
    server.clock.advance_ms((W_DAYS - 1) * DAY_MS);
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        folder
            .merge(&ca, &account, &mut a, &old, &[], &[], &[])
            .await
            .status,
        200
    );
    server.clock.advance_ms(2 * DAY_MS);
    server.gc().await;
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        ca.get(&object_path(&folder.id, &x.id)).await.code(),
        ErrorCode::NotFound,
        "the old tree ends with its own window"
    );
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// M1: sign-in DoS
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn m1_challenges_write_nothing_to_the_database() {
    let mut server = TestServer::start("m1-stateless").await;
    let client = Client::new(server.addr);
    for _ in 0..40 {
        let reply = client
            .post(
                CHALLENGE_PATH,
                &ChallengeRequest {
                    account: AccountId::from_bytes(random()),
                    device: DeviceId::from_bytes(random()),
                },
            )
            .await;
        assert_eq!(reply.status, 200);
    }
    let used: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM used_challenges")
        .fetch_one(&server.app.db)
        .await
        .unwrap();
    assert_eq!(used, 0, "only verified proofs are remembered");
    assert!(
        data_dir_of("m1-stateless").join("server.secret").is_file(),
        "the server secret lives in the data folder"
    );
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// M3: retiring a folder and pins of retired folders
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn m3_retiring_a_large_folder_pins_its_last_head_until_the_pin_ends() {
    let mut server = TestServer::with(
        "m3-retire",
        Options {
            limits: small(1 << 30, 1 << 20),
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut folder = Folder::new();
    let files: Vec<Obj> = (0..25).map(|_| tiny()).collect();
    for o in &files {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    let refs: Vec<&Obj> = files.iter().collect();
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &refs, &[])
            .await
            .status,
        200
    );
    let last = folder.head.clone().unwrap().0;
    let reply = ca.post(&retire_path(&folder.id), &()).await;
    assert_eq!(reply.status, 204);
    assert_eq!(
        pins(&feed(&ca, 0).await),
        vec![last.id],
        "a retirement drops every live object and pins the last head"
    );
    // After the window the retired folder stays, because the pin holds it.
    server.clock.advance_ms((W_DAYS + 1) * DAY_MS);
    server.gc().await;
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        ca.get(&object_path(&folder.id, &files[0].id)).await.status,
        200
    );
    // The pin no longer goes with its folder: deleting the folder row alone is refused.
    let folder_pk: i64 = sqlx::query_scalar("SELECT pk FROM folders WHERE id = ?")
        .bind(folder.id.as_bytes().as_slice())
        .fetch_one(&server.app.db)
        .await
        .unwrap();
    assert!(sqlx::query("DELETE FROM folders WHERE pk = ?")
        .bind(folder_pk)
        .execute(&server.app.db)
        .await
        .is_err());
    // Once the pin ended, the folder goes.
    server.clock.advance_ms(60 * DAY_MS);
    let outcome = server.gc().await;
    assert_eq!(outcome.deleted_folders, 1);
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        ca.get(&object_path(&folder.id, &files[0].id)).await.code(),
        ErrorCode::NotFound
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn m3_bringing_back_a_pinned_retired_folder_uses_the_pin_restore_allowance() {
    // A folder built over two days fits each day's budget, but not one day's budget at once.
    // Retiring it sets off a pin; bringing it back makes the pinned tree live again, which the
    // pin restore allowance covers like any restore of a pinned tree (ADR 0001, section 5).
    let files: Vec<Obj> = (0..26).map(|_| tiny()).collect();
    let half: u64 = files[..13].iter().map(|o| o.blob.len() as u64).sum();
    let mut limits = small(1 << 30, 1 << 20);
    limits.account_budget = half + half / 2;
    limits.device_budget = half + half / 2;
    let mut server = TestServer::with(
        "m3-bring-back",
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let mut folder = Folder::new();
    for day in files.chunks(13) {
        let ca = account.sign_in(&server, &a).await;
        for o in day {
            assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
        }
        let refs: Vec<&Obj> = day.iter().collect();
        assert_eq!(
            folder
                .commit(&ca, &account, &mut a, &refs, &[])
                .await
                .status,
            200
        );
        server.clock.advance_ms(DAY_MS + 60_000);
    }
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(ca.post(&retire_path(&folder.id), &()).await.status, 204);
    assert_eq!(pins(&feed(&ca, 0).await).len(), 1, "the retirement pinned");
    assert_eq!(
        ca.delete(&retire_path(&folder.id)).await.status,
        204,
        "the pinned tree comes back without waiting for the budget"
    );
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// L4: burst threshold for small folders
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn l4_a_folder_below_500_files_can_set_off_a_pin() {
    // The default limits: 500 objects or 30 %, now min(500, 30 % of the folder), at least 20.
    let mut server = TestServer::with(
        "l4-burst",
        Options {
            limits: small(1 << 30, 1 << 20),
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut folder = Folder::new();
    let files: Vec<Obj> = (0..60).map(|_| tiny()).collect();
    for o in &files {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    let all: Vec<&Obj> = files.iter().collect();
    assert_eq!(
        folder.commit(&ca, &account, &mut a, &all, &[]).await.status,
        200
    );
    let before = folder.head.clone().unwrap().0;
    let gone: Vec<&Obj> = files.iter().take(20).collect();
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[], &gone)
            .await
            .status,
        200
    );
    assert_eq!(pins(&feed(&ca, 0).await), vec![before.id]);
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// M4: concurrency of large bodies, running counters
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn m4_commits_wait_for_a_free_heavy_slot() {
    let mut server = TestServer::with(
        "m4-heavy",
        Options {
            concurrency: Concurrency {
                heavy_requests: 1,
                ..Concurrency::default()
            },
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let folder = Folder::new();
    let held = server.app.heavy.clone().acquire_owned().await.unwrap();
    let commit = folder.next(&account, &mut a);
    let request = folder.request(&commit, &[], &[]);
    let path = commit_path(&folder.id);
    let pending = tokio::spawn(async move { ca.post(&path, &request).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!pending.is_finished(), "the commit waits for the slot");
    drop(held);
    let reply = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.status, 200);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn m4_one_account_cannot_hold_every_heavy_slot() {
    // One account dribbles the bodies of its commits (up to two minutes each); with a share of
    // the slots per account, the commits of another account still go through at once.
    let mut server = TestServer::with(
        "m4-heavy-share",
        Options {
            concurrency: Concurrency {
                heavy_requests: 2,
                ..Concurrency::default()
            },
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let mut b = Device::new();
    let account_a = Account::create(&server, &a, &[]).await;
    let account_b = Account::create(&server, &b, &[]).await;
    let ca = account_a.sign_in(&server, &a).await;
    let cb = account_b.sign_in(&server, &b).await;
    let folder = Folder::new();
    let path = commit_path(&folder.id);
    let mut slow = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\
             Content-Type: application/json\r\nContent-Length: 100000\r\n\r\n{{",
            ca.token.as_deref().unwrap()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        slow.push(stream);
        // The first one takes the share before the second arrives.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // The second slow commit of account A found A's share taken.
    let mut reply = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(3), slow[1].read(&mut reply))
        .await
        .expect("refused at once")
        .unwrap();
    assert!(String::from_utf8_lossy(&reply[..n]).starts_with("HTTP/1.1 429"));
    let fb = Folder::new();
    let commit = fb.next(&account_b, &mut b);
    let request = fb.request(&commit, &[], &[]);
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        cb.post(&commit_path(&fb.id), &request),
    )
    .await
    .expect("account B does not wait for account A");
    assert_eq!(reply.status, 200);
    let _ = &mut a;
    drop(slow);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn m4_uncommitted_bytes_are_a_running_counter() {
    let mut server = TestServer::start("m4-counter").await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let pk = server.account_pk(&account.id).await;
    let pending = || async {
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT pending_data_bytes, pending_dir_bytes FROM accounts WHERE pk = ?",
        )
        .bind(pk)
        .fetch_one(&server.app.db)
        .await
        .unwrap()
    };
    let mut folder = Folder::new();
    let (c, d, left) = (chunk(), Obj::new(ObjectType::DirectoryNode, 64), chunk());
    for o in [&c, &d, &left] {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    assert_eq!(
        pending().await,
        (
            i64::try_from(c.size() + left.size()).unwrap(),
            i64::try_from(d.size()).unwrap()
        )
    );
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&c, &d], &[])
            .await
            .status,
        200
    );
    assert_eq!(pending().await, (i64::try_from(left.size()).unwrap(), 0));
    server.clock.advance_ms(DAY_MS + 1);
    server.gc().await;
    assert_eq!(pending().await, (0, 0), "the upload without a commit went");
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// M5: staging bytes and uploads per account
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn m5_uploads_per_account_are_limited() {
    let mut server = TestServer::with(
        "m5-slots",
        Options {
            concurrency: Concurrency {
                uploads_per_account: 1,
                ..Concurrency::default()
            },
            ..Options::default()
        },
    )
    .await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let pk = server.account_pk(&account.id).await;
    let folder = FolderId::from_bytes(random());
    let o = chunk();
    let slot = server.app.uploads.take(pk, 1).unwrap();
    assert_eq!(
        upload(&ca, &folder, &o).await.code(),
        ErrorCode::RateLimited
    );
    drop(slot);
    assert_eq!(upload(&ca, &folder, &o).await.status, 201);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn m5_bytes_other_uploads_still_write_count_against_the_reserve() {
    let mut server = TestServer::start("m5-staging").await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let folder = FolderId::from_bytes(random());
    let o = chunk();
    let reserve = server.app.limits.disk_reserve;
    // Room for this upload, but not on top of 8000 bytes another upload is about to write.
    server.disk.set(reserve + 10_000);
    let claim = server.app.staging.claim(8_000);
    assert_eq!(
        upload(&ca, &folder, &o).await.code(),
        ErrorCode::DiskReserve
    );
    drop(claim);
    assert_eq!(upload(&ca, &folder, &o).await.status, 201);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn m5_the_reserve_is_checked_again_before_the_object_is_installed() {
    let mut server = TestServer::start("m5-recheck").await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let folder = FolderId::from_bytes(random());
    let o = chunk();
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let head = format!(
        "PUT {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {}\r\n\
         Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        object_path(&folder, &o.id),
        ca.token.clone().unwrap(),
        o.blob.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let half = o.blob.len() / 2;
    stream.write_all(&o.blob[..half]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Other uploads filled the disk while this one was on its way.
    server.disk.set(0);
    stream.write_all(&o.blob[half..]).await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    let text = String::from_utf8_lossy(&reply);
    assert!(text.contains("disk_reserve"), "{text}");
    server.disk.set(u64::MAX / 2);
    assert_eq!(
        upload(&ca, &folder, &o).await.status,
        201,
        "nothing was kept"
    );
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// M6: connections per address, public body timeout, limits before the body
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn m6_one_address_holds_only_its_share_of_connections() {
    let mut server = TestServer::with(
        "m6-conns",
        Options {
            concurrency: Concurrency {
                connections_per_ip: 2,
                ..Concurrency::default()
            },
            ..Options::default()
        },
    )
    .await;
    let _one = TcpStream::connect(server.addr).await.unwrap();
    let _two = TcpStream::connect(server.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut three = TcpStream::connect(server.addr).await.unwrap();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(3), three.read(&mut buf))
        .await
        .expect("the third connection is closed at once, not held");
    assert!(matches!(read, Ok(0) | Err(_)));
    drop(_one);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reply = raw(
        server.addr,
        "GET",
        hangar_drive_protocol::HEALTH_PATH,
        &[],
        b"",
    )
    .await;
    assert_eq!(reply.status, 200, "a closed connection frees its place");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn m6_a_public_body_must_arrive_within_ten_seconds() {
    let mut server = TestServer::start("m6-slow").await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let head = format!(
        "POST {CHALLENGE_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: 200\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let started = std::time::Instant::now();
    // A byte every two seconds: never idle long enough for the idle timeout.
    let trickle = async {
        loop {
            if stream.write_all(b" ").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mut probe = [0u8; 1];
            match tokio::time::timeout(Duration::from_millis(10), stream.peek(&mut probe)).await {
                Ok(Ok(n)) if n > 0 => break,
                _ => {}
            }
        }
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply).await;
        reply
    };
    let reply = tokio::time::timeout(Duration::from_secs(25), trickle)
        .await
        .expect("the server gives up on the body");
    let elapsed = started.elapsed();
    let text = String::from_utf8_lossy(&reply);
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn m6_limits_apply_before_the_body_is_read() {
    let mut server = TestServer::with(
        "m6-before-body",
        Options {
            limiter: RateLimiter::scaled(30),
            ..Options::default()
        },
    )
    .await;
    let client = Client::new(server.addr);
    let challenge = ChallengeRequest {
        account: AccountId::from_bytes(random()),
        device: DeviceId::from_bytes(random()),
    };
    for _ in 0..2 {
        assert_eq!(client.post(CHALLENGE_PATH, &challenge).await.status, 200);
    }
    // Headers that promise a body that never comes: the refusal does not wait for it.
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let head = format!(
        "POST {CHALLENGE_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: 100\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut reply = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut reply))
        .await
        .expect("refused before the body")
        .unwrap();
    let text = String::from_utf8_lossy(&reply[..n]);
    assert!(text.starts_with("HTTP/1.1 429"), "{text}");
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// L3: record signatures and the record cap
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn l3_records_need_the_senders_signature_and_fit_the_record_cap() {
    let mut limits = small(1 << 30, 1 << 20);
    limits.record_cap = 3_000;
    let mut server = TestServer::with(
        "l3-records",
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let a = Device::new();
    let mut account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(account.rotate(&ca, &a).await.status, 200);
    let cipher =
        RecordCipher::for_epoch(&account.state, account.secret.as_ref().unwrap(), Epoch(1))
            .unwrap();
    let head = account.head();
    let key = RecordKey::new(RecordKind::Folders, None).unwrap();
    let seal = |version: u64, plaintext: &[u8]| {
        cipher
            .seal(
                &key,
                version,
                &a.identity,
                &a.id,
                &head,
                plaintext,
                &mut OsEntropy,
            )
            .unwrap()
    };
    // A valid header with bytes no device signed.
    let mut forged = seal(1, b"list");
    let last = forged.len() - 1;
    forged[last] ^= 0x55;
    let reply = ca
        .send(
            "PUT",
            &record_path(&key),
            &RecordPut {
                version: 1,
                data: Blob(forged),
            },
        )
        .await;
    assert_eq!(
        reply.code(),
        ErrorCode::BadRequest,
        "unsigned bytes are refused"
    );
    let reply = ca
        .send(
            "PUT",
            &record_path(&key),
            &RecordPut {
                version: 1,
                data: Blob(seal(1, b"list")),
            },
        )
        .await;
    assert_eq!(reply.status, 200);
    // The cap counts the account's stored records; replacing one counts only the new size.
    let big = vec![7u8; 4_000];
    let reply = ca
        .send(
            "PUT",
            &record_path(&key),
            &RecordPut {
                version: 2,
                data: Blob(seal(2, &big)),
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::QuotaExceeded);
    let reply = ca
        .send(
            "PUT",
            &record_path(&key),
            &RecordPut {
                version: 2,
                data: Blob(seal(2, &big[..2_000])),
            },
        )
        .await;
    assert_eq!(reply.status, 200);
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// L5: gc and purge while the server runs
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn l5_the_data_folder_is_locked_while_the_server_runs() {
    let mut server = TestServer::start("l5-lock").await;
    let dir = data_dir_of("l5-lock");
    assert!(matches!(
        DataDirLock::acquire(&dir),
        Err(hangar_drive_server::LockError::InUse)
    ));
    server.stop().await.unwrap();
    assert!(DataDirLock::acquire(&dir).is_ok(), "free once it stopped");
}

/// A measurement, not a check (run with `--ignored`): a commit whose delta adds 200 000 held
/// objects. With the set-based check the call is a handful of statements under the write lock.
#[tokio::test]
#[ignore]
async fn m4_measure_a_large_delta() {
    let mut server = TestServer::with(
        "m4-measure",
        Options {
            limits: small(1 << 40, 1 << 30),
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let folder = Folder::new();
    let pk = server.account_pk(&account.id).await;
    let folder_pk: i64 = sqlx::query_scalar(
        "INSERT INTO folders (account_pk, id, created_ms) VALUES (?, ?, 0) RETURNING pk",
    )
    .bind(pk)
    .bind(folder.id.as_bytes().as_slice())
    .fetch_one(&server.app.db)
    .await
    .unwrap();
    let ids: Vec<ObjectId> = (0..200_000)
        .map(|_| ObjectId::from_bytes(random()))
        .collect();
    let mut tx = server.app.db.begin().await.unwrap();
    for id in &ids {
        sqlx::query("INSERT INTO objects (folder_pk, object_id, kind, size, uploaded_ms) VALUES (?, ?, 1, 100, 0)")
            .bind(folder_pk)
            .bind(id.as_bytes().as_slice())
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let commit = folder.next(&account, &mut a);
    let mut request = folder.request(&commit, &[], &[]);
    request.head.delta.added = ids;
    let started = std::time::Instant::now();
    let reply = ca.post(&commit_path(&folder.id), &request).await;
    eprintln!(
        "commit with 200000 added IDs: {} in {:?}",
        reply.status,
        started.elapsed()
    );
    assert_eq!(reply.status, 200);
    server.stop().await.unwrap();
}
