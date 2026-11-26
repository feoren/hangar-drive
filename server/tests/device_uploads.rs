//! One device cannot lock the other devices of its account out (security review 2026-11-26,
//! MEDIUM 3 and LOW 2): uncommitted uploads count only against the device that sent them,
//! removing a device deletes them and gives their budget back at once, the default device
//! budget is half the account budget, and a device holds at most two event streams.

mod common;

use std::time::Duration;

use common::*;
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::ObjectType;
use hangar_drive_server::config::Limits;
use hangar_drive_server::store::ObjectKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A chunk of 4142 bytes on the wire (4000 bytes of plaintext).
const CHUNK: u64 = 4142;

fn chunk() -> Obj {
    Obj::new(ObjectType::Chunk, 4000)
}

/// Limits with a quota of `chunks` chunks and the default budgets for it.
fn limits_for(chunks: u64) -> Limits {
    let mut limits = Limits::for_quota(chunks * CHUNK);
    limits.headroom = 1 << 20;
    limits.min_commits = 1;
    limits
}

/// Account with a first device `a` and a second device `b`, both signed in.
async fn two_devices(server: &TestServer) -> (Account, Device, Client, Device, Client) {
    let a = Device::new();
    let mut account = Account::create(server, &a, &[]).await;
    let ca = account.sign_in(server, &a).await;
    assert_eq!(account.rotate(&ca, &a).await.status, 200);
    let b = Device::new();
    assert_eq!(account.add(&ca, &a, &b).await.status, 200);
    let cb = account.sign_in(server, &b).await;
    (account, a, ca, b, cb)
}

/// Uploads fresh chunks until the server refuses one; returns the stored ones and the refusal.
async fn upload_until_refused(
    client: &Client,
    folder: &FolderId,
    at_most: u64,
) -> (Vec<Obj>, Reply) {
    let mut stored = Vec::new();
    for _ in 0..at_most {
        let obj = chunk();
        let reply = upload(client, folder, &obj).await;
        if reply.status != 201 {
            return (stored, reply);
        }
        stored.push(obj);
    }
    panic!("the server took {at_most} chunks without refusing one");
}

async fn pending_counters(server: &TestServer, account_pk: i64) -> (i64, Vec<(Vec<u8>, i64)>) {
    let account: i64 = sqlx::query_scalar("SELECT pending_data_bytes FROM accounts WHERE pk = ?")
        .bind(account_pk)
        .fetch_one(&server.app.db)
        .await
        .unwrap();
    let devices: Vec<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT device, data_bytes FROM device_pending WHERE account_pk = ? AND data_bytes > 0 ORDER BY device",
    )
    .bind(account_pk)
    .fetch_all(&server.app.db)
    .await
    .unwrap();
    (account, devices)
}

#[tokio::test]
async fn removing_a_device_deletes_its_uncommitted_uploads_and_frees_the_budget_at_once() {
    // The operator gave one device the whole account budget, so device a alone can use it up.
    let mut limits = limits_for(10);
    limits.account_budget = 5 * CHUNK;
    limits.device_budget = limits.account_budget;
    let mut server = TestServer::with(
        "device-uploads-removal",
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let (mut account, mut a, ca, b, cb) = two_devices(&server).await;
    let pk = server.account_pk(&account.id).await;
    let mut folder = Folder::new();

    // a uses up the account budget with uploads.
    let (garbage, refused) = upload_until_refused(&ca, &folder.id, 10).await;
    assert_eq!(garbage.len(), 5);
    assert_eq!(
        (refused.status, refused.code()),
        (507, ErrorCode::BudgetExceeded)
    );
    // It commits one of them; the other four stay uncommitted.
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&garbage[0]], &[])
            .await
            .status,
        200
    );
    let a_bytes = a.id.as_bytes().to_vec();
    assert_eq!(
        pending_counters(&server, pk).await,
        (4 * CHUNK as i64, vec![(a_bytes.clone(), 4 * CHUNK as i64)])
    );
    // Before the removal b is locked out: the account budget is gone.
    let reply = upload(&cb, &folder.id, &chunk()).await;
    assert_eq!(
        (reply.status, reply.code()),
        (507, ErrorCode::BudgetExceeded)
    );

    // b removes a: a's uncommitted uploads go in the same transaction.
    let reply = account.remove(&cb, &b, &[a.id]).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(pending_counters(&server, pk).await, (0, vec![]));
    let left: Vec<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT object_id, declared FROM objects o JOIN folders f ON f.pk = o.folder_pk WHERE f.account_pk = ?",
    )
    .bind(pk)
    .fetch_all(&server.app.db)
    .await
    .unwrap();
    assert_eq!(left, vec![(garbage[0].id.as_bytes().to_vec(), 1)]);
    // Their files follow in the background; the committed object keeps its file.
    let key = |obj: &Obj| ObjectKey {
        account: account.id,
        folder: folder.id,
        id: obj.id,
    };
    let mut gone = false;
    for _ in 0..100 {
        gone = garbage[1..]
            .iter()
            .all(|obj| server.app.store.open(&key(obj)).is_err());
        if gone {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        gone,
        "the removed device's uncommitted files are still there"
    );
    assert!(server.app.store.open(&key(&garbage[0])).is_ok());

    // b uploads at once: the four deleted chunks' budget is back, the committed one stays paid.
    let (mine, refused) = upload_until_refused(&cb, &folder.id, 10).await;
    assert_eq!(mine.len(), 4);
    assert_eq!(refused.code(), ErrorCode::BudgetExceeded);
    let mut b = b;
    let refs: Vec<&Obj> = mine.iter().collect();
    assert_eq!(
        folder
            .commit(&cb, &account, &mut b, &refs, &[])
            .await
            .status,
        200
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn with_the_default_budgets_one_device_cannot_lock_the_others_out() {
    let limits = limits_for(10);
    assert_eq!(limits.device_budget, limits.account_budget / 2);
    let mut server = TestServer::with(
        "device-uploads-defaults",
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let (account, _a, ca, mut b, cb) = two_devices(&server).await;
    let mut folder = Folder::new();

    // a uploads as much as it can and never commits: half the account budget.
    let (garbage, refused) = upload_until_refused(&ca, &folder.id, 20).await;
    assert_eq!(garbage.len(), 5);
    assert_eq!(refused.code(), ErrorCode::BudgetExceeded);
    // a stays stopped across folders as well.
    let other = Folder::new();
    assert_eq!(
        upload(&ca, &other.id, &chunk()).await.code(),
        ErrorCode::BudgetExceeded
    );

    // b still uploads its own half and commits it, without removing a.
    let (mine, refused) = upload_until_refused(&cb, &folder.id, 20).await;
    assert_eq!(mine.len(), 5);
    assert_eq!(refused.code(), ErrorCode::BudgetExceeded);
    let refs: Vec<&Obj> = mine.iter().collect();
    assert_eq!(
        folder
            .commit(&cb, &account, &mut b, &refs, &[])
            .await
            .status,
        200
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn another_devices_uncommitted_uploads_do_not_count_against_the_quota() {
    // Budgets out of the way: this is about the quota alone.
    let mut limits = limits_for(4);
    limits.account_budget = 1 << 40;
    limits.device_budget = 1 << 40;
    let mut server = TestServer::with(
        "device-uploads-quota",
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let (account, mut a, ca, mut b, cb) = two_devices(&server).await;
    let mut folder = Folder::new();

    // a's uncommitted uploads fill the quota; its own next upload is refused.
    let (garbage, refused) = upload_until_refused(&ca, &folder.id, 10).await;
    assert_eq!(garbage.len(), 4);
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);

    // b uploads and commits within the quota all the same.
    let (mine, refused) = upload_until_refused(&cb, &folder.id, 10).await;
    assert_eq!(mine.len(), 4);
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);
    let refs: Vec<&Obj> = mine[..3].iter().collect();
    assert_eq!(
        folder
            .commit(&cb, &account, &mut b, &refs, &[])
            .await
            .status,
        200
    );
    // The commit check still holds live bytes to the quota: a cannot commit its garbage now.
    let refs: Vec<&Obj> = garbage.iter().collect();
    let reply = folder.commit(&ca, &account, &mut a, &refs, &[]).await;
    assert_eq!(
        (reply.status, reply.code()),
        (507, ErrorCode::QuotaExceeded)
    );
    // The collection agrees with the running counters.
    let pk = server.account_pk(&account.id).await;
    let before = pending_counters(&server, pk).await;
    server.gc().await;
    assert_eq!(pending_counters(&server, pk).await, before);
    assert_eq!(before.0, 5 * CHUNK as i64);
    server.stop().await.unwrap();
}

/// Opens `GET /account/events` and reads up to the first event.
async fn open_stream(client: &Client) -> TcpStream {
    let mut stream = TcpStream::connect(client.addr).await.unwrap();
    let token = client.token.clone().unwrap();
    let head = format!(
        "GET /api/v1/account/events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains("event: sequence") {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("no first event")
            .unwrap();
        assert!(
            n > 0,
            "stream closed early: {}",
            String::from_utf8_lossy(&seen)
        );
        seen.extend_from_slice(&buf[..n]);
    }
    assert!(String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 200"));
    stream
}

/// Whether the server ends the stream within `wait` (`Connection: close`, so the connection
/// closes with the response).
async fn ends_within(stream: &mut TcpStream, wait: Duration) -> bool {
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
            Err(_) => return false,
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => {}
        }
    }
}

#[tokio::test]
async fn a_third_event_stream_of_a_device_closes_its_oldest() {
    let mut server = TestServer::start("device-streams").await;
    let (_account, _a, ca, _b, cb) = two_devices(&server).await;
    let mut first = open_stream(&ca).await;
    let mut second = open_stream(&ca).await;
    let mut others = open_stream(&cb).await;
    assert_eq!(server.app.events.open_streams(), 3);

    let mut third = open_stream(&ca).await;
    assert!(ends_within(&mut first, Duration::from_secs(5)).await);
    assert!(!ends_within(&mut second, Duration::from_millis(200)).await);
    assert!(!ends_within(&mut third, Duration::from_millis(200)).await);
    assert!(!ends_within(&mut others, Duration::from_millis(200)).await);

    // However often a reopens, it never holds more than two of the account's slots.
    let mut held = Vec::new();
    for _ in 0..40 {
        held.push(open_stream(&ca).await);
    }
    assert!(server.app.events.open_streams() <= 3);
    assert!(!ends_within(&mut others, Duration::from_millis(200)).await);
    drop(held);
    server.stop().await.unwrap();
}
