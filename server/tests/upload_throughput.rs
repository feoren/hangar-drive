//! Upload throughput review 2026-11-28: the configurable upload rate with an exact
//! `Retry-After`, the upload's file going in place outside the database's write lock (and what
//! must still hold: a refused upload leaves no file, an object with a row is never replaced, a
//! committed row always has its file, the sweeps wait for an upload in flight), the set based
//! `objects/missing` query and the delayed first file sweep.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::*;
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::ObjectType;
use hangar_drive_server::app::{Hook, Hooks};
use hangar_drive_server::config::Limits;
use hangar_drive_server::service::retention;
use hangar_drive_server::store::ObjectKey;

/// Stops every upload at the `upload_installed` hook until opened.
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
                // Each permit lets one upload through ([`Gate::pass_one`]).
                if let Ok(permit) = release.acquire().await {
                    permit.forget();
                }
            })
        })
    }

    fn open(&self) {
        self.release.add_permits(1000);
    }

    fn pass_one(&self) {
        self.release.add_permits(1);
    }

    async fn wait_for_calls(&self, n: usize) {
        for _ in 0..500 {
            if self.calls() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the hook was not reached {n} times");
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

async fn gated(name: &str, gate: &Gate, limits: Option<Limits>) -> TestServer {
    let mut options = Options {
        hooks: Hooks {
            upload_installed: Some(gate.hook()),
            ..Hooks::default()
        },
        ..Options::default()
    };
    if let Some(limits) = limits {
        options.limits = limits;
    }
    TestServer::with(name, options).await
}

async fn signed_in(server: &TestServer) -> (Account, Client) {
    let a = Device::new();
    let account = Account::create(server, &a, &[]).await;
    let client = account.sign_in(server, &a).await;
    (account, client)
}

fn key_of(account: &Account, folder: &FolderId, id: &ObjectId) -> ObjectKey {
    ObjectKey {
        account: account.id,
        folder: *folder,
        id: *id,
    }
}

/// The object's file in the test server's data folder (layout of `store::FsStore`).
fn file_of(name: &str, key: &ObjectKey) -> PathBuf {
    let id = key.id.to_hex();
    data_dir_of(name)
        .join("objects")
        .join(key.account.to_hex())
        .join(key.folder.to_hex())
        .join(&id[0..2])
        .join(&id[2..4])
        .join(id)
}

async fn rows_of(server: &TestServer, id: &ObjectId) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM objects WHERE object_id = ?")
        .bind(id.as_bytes().as_slice())
        .fetch_one(&server.app.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_upload_rate_is_the_operators_and_retry_after_names_the_rest_of_the_window() {
    let mut server = TestServer::with(
        "throughput-rate",
        Options {
            uploads_per_minute: Some(60),
            ..Options::default()
        },
    )
    .await;
    assert_eq!(
        server
            .app
            .limiter
            .rule(hangar_drive_server::http::ratelimit::Scope::UploadAccount)
            .limit,
        60
    );
    let (_, client) = signed_in(&server).await;
    let folder = FolderId::from_bytes(random());
    for _ in 0..60 {
        let reply = upload(&client, &folder, &Obj::new(ObjectType::Chunk, 10)).await;
        assert_eq!(reply.status, 201);
    }
    let reply = upload(&client, &folder, &Obj::new(ObjectType::Chunk, 10)).await;
    assert_eq!((reply.status, reply.code()), (429, ErrorCode::RateLimited));
    assert_eq!(reply.header("retry-after").as_deref(), Some("60"));
    server.clock.advance_ms(25_000);
    let reply = upload(&client, &folder, &Obj::new(ObjectType::Chunk, 10)).await;
    assert_eq!(reply.status, 429);
    assert_eq!(
        reply.header("retry-after").as_deref(),
        Some("35"),
        "the rest of the window, not a flat minute"
    );
    server.clock.advance_ms(35_000);
    let reply = upload(&client, &folder, &Obj::new(ObjectType::Chunk, 10)).await;
    assert_eq!(reply.status, 201, "a new window");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn an_upload_refused_after_its_file_went_in_place_leaves_no_file() {
    // The budget is only checked in the write transaction, after the file is in place.
    let first = Obj::new(ObjectType::Chunk, 4000);
    let mut limits = Limits::for_quota(1 << 30);
    limits.headroom = 1 << 20;
    limits.device_budget = first.size() + 10;
    let name = "throughput-refused-budget";
    let mut server = TestServer::with(
        name,
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let (account, client) = signed_in(&server).await;
    let folder = FolderId::from_bytes(random());
    assert_eq!(upload(&client, &folder, &first).await.status, 201);
    let second = Obj::new(ObjectType::Chunk, 4000);
    let reply = upload(&client, &folder, &second).await;
    assert_eq!(reply.code(), ErrorCode::BudgetExceeded);
    assert!(
        !file_of(name, &key_of(&account, &folder, &second.id)).exists(),
        "the refused upload's file is removed"
    );
    assert_eq!(rows_of(&server, &second.id).await, 0);
    assert!(file_of(name, &key_of(&account, &folder, &first.id)).is_file());
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_disk_that_fills_while_the_file_goes_in_place_refuses_and_removes_it() {
    let gate = Gate::new();
    let name = "throughput-refused-disk";
    let mut server = gated(name, &gate, None).await;
    let (account, client) = signed_in(&server).await;
    let folder = FolderId::from_bytes(random());
    let obj = Obj::new(ObjectType::Chunk, 1000);
    let path = object_path(&folder, &obj.id);
    let blob = obj.blob.clone();
    let sending = tokio::spawn(async move { client.put_bytes(&path, &blob).await });
    gate.arrived.notified().await;
    let file = file_of(name, &key_of(&account, &folder, &obj.id));
    assert!(file.is_file(), "in place before the transaction");
    server.disk.set(0);
    gate.open();
    let reply = sending.await.unwrap();
    assert_eq!(reply.code(), ErrorCode::DiskReserve);
    assert!(!file.exists(), "removed again");
    assert_eq!(rows_of(&server, &obj.id).await, 0);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_second_upload_of_an_object_never_replaces_its_file() {
    let gate = Gate::new();
    let name = "throughput-no-overwrite";
    let mut server = gated(name, &gate, None).await;
    let (account, client) = signed_in(&server).await;
    let client = Arc::new(client);
    let folder = FolderId::from_bytes(random());
    let first = Obj::new(ObjectType::Chunk, 1000);
    // Same ID, other bytes: a device that tries to replace a stored object.
    let other = Obj {
        id: first.id,
        blob: blob(ObjectType::Chunk, 1000),
    };
    assert_ne!(first.blob, other.blob);
    let (c, path, bytes) = (
        client.clone(),
        object_path(&folder, &first.id),
        first.blob.clone(),
    );
    let one = tokio::spawn(async move { c.put_bytes(&path, &bytes).await });
    gate.arrived.notified().await;
    // The first upload holds the object's stripe with its file in place and no row yet. The
    // second passes the check before the body (no row), sends its body and waits for the
    // stripe.
    let (c, path, bytes) = (
        client.clone(),
        object_path(&folder, &other.id),
        other.blob.clone(),
    );
    let two = tokio::spawn(async move { c.put_bytes(&path, &bytes).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    gate.open();
    let one = one.await.unwrap();
    let two = two.await.unwrap();
    assert_eq!(one.status, 201);
    assert_eq!(
        (two.status, two.json::<UploadResponse>().stored),
        (200, false)
    );
    assert_eq!(gate.calls(), 1, "the second never put a file in place");
    let stored = std::fs::read(file_of(name, &key_of(&account, &folder, &first.id))).unwrap();
    assert_eq!(stored, first.blob);
    assert_eq!(rows_of(&server, &first.id).await, 1);
    // And once more after the row is there, through the check before the body.
    let three = upload(&client, &folder, &other).await;
    assert_eq!(
        (three.status, three.json::<UploadResponse>().stored),
        (200, false)
    );
    let reply = client.get(&object_path(&folder, &first.id)).await;
    assert_eq!(reply.body, first.blob);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_folder_deleted_while_the_file_goes_in_place_refuses_the_upload() {
    // The operator purges a committed folder (its rows, then its directory) after the upload put
    // its file in place: the directory removal took the file with it, so the row must not
    // commit, and the device stops instead of making the purged folder again (follow-up LOW 2).
    let gate = Gate::new();
    let name = "throughput-folder-purged";
    let mut server = gated(name, &gate, None).await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let client = account.sign_in(&server, &a).await;
    let mut chain = Folder::new();
    let folder = chain.id;
    gate.pass_one();
    let first = Obj::new(ObjectType::Chunk, 100);
    assert_eq!(upload(&client, &folder, &first).await.status, 201);
    assert_eq!(
        chain
            .commit(&client, &account, &mut a, &[&first], &[])
            .await
            .status,
        200
    );
    let obj = Obj::new(ObjectType::Chunk, 100);
    let (path, bytes) = (object_path(&folder, &obj.id), obj.blob.clone());
    let sending = tokio::spawn(async move { client.put_bytes(&path, &bytes).await });
    gate.wait_for_calls(2).await;
    let file = file_of(name, &key_of(&account, &folder, &obj.id));
    assert!(file.is_file());
    hangar_drive_server::service::admin::purge_folder(&server.app, &account.id, &folder)
        .await
        .unwrap();
    assert!(!file.exists(), "removed with the folder's directory");
    gate.open();
    let reply = sending.await.unwrap();
    assert_eq!(reply.code(), ErrorCode::FolderRetired);
    assert_eq!(
        rows_of(&server, &obj.id).await,
        0,
        "no row without its file"
    );
    let folders: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM folders WHERE id = ?")
        .bind(folder.as_bytes().as_slice())
        .fetch_one(&server.app.db)
        .await
        .unwrap();
    assert_eq!(folders, 0, "the purged folder is not made again");
    server.stop().await.unwrap();
}

/// Makes the folder as another upload would, after the gated upload's check saw none.
async fn make_folder(server: &TestServer, account: &Account, folder: &FolderId, created_ms: u64) {
    let account_pk = server.account_pk(&account.id).await;
    sqlx::query("INSERT INTO folders (account_pk, id, created_ms) VALUES (?, ?, ?)")
        .bind(account_pk)
        .bind(folder.as_bytes().as_slice())
        .bind(created_ms as i64)
        .execute(&server.app.db)
        .await
        .unwrap();
}

/// How a folder that appeared after the upload's check gets removed.
#[derive(Clone, Copy)]
enum Removal {
    PurgeFolder,
    PurgeRetained,
}

/// Follow-up review MEDIUM 1: the upload's check sees no folder, another upload makes it, and
/// it is removed with its directory before the upload's transaction. Without the removal count
/// the transaction made the folder again and committed a row whose file was gone.
async fn folder_made_and_removed_after_the_check(name: &str, removal: Removal) {
    let gate = Gate::new();
    let mut server = gated(name, &gate, None).await;
    let (account, client) = signed_in(&server).await;
    let folder = FolderId::from_bytes(random());
    let obj = Obj::new(ObjectType::Chunk, 100);
    let (path, bytes) = (object_path(&folder, &obj.id), obj.blob.clone());
    let sending = tokio::spawn(async move { client.put_bytes(&path, &bytes).await });
    gate.wait_for_calls(1).await;
    let file = file_of(name, &key_of(&account, &folder, &obj.id));
    assert!(file.is_file());
    match removal {
        Removal::PurgeFolder => {
            make_folder(&server, &account, &folder, server.clock.now()).await;
            hangar_drive_server::service::admin::purge_folder(&server.app, &account.id, &folder)
                .await
                .unwrap();
        }
        Removal::PurgeRetained => {
            // Old enough and without objects: the garbage collection deletes it whole.
            make_folder(&server, &account, &folder, server.clock.now() - 2 * DAY_MS).await;
            let outcome =
                hangar_drive_server::service::admin::purge_retained(&server.app, &account.id)
                    .await
                    .unwrap();
            assert_eq!(outcome.deleted_folders, 1);
        }
    }
    assert!(!file.exists(), "removed with the folder's directory");
    gate.open();
    let reply = sending.await.unwrap();
    assert_eq!((reply.status, reply.code()), (429, ErrorCode::RateLimited));
    assert_eq!(reply.header("retry-after").as_deref(), Some("2"));
    assert_eq!(
        rows_of(&server, &obj.id).await,
        0,
        "no row without its file"
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_folder_made_after_the_check_and_purged_refuses_the_upload() {
    folder_made_and_removed_after_the_check("throughput-made-purged", Removal::PurgeFolder).await;
}

#[tokio::test]
async fn a_folder_made_after_the_check_and_collected_refuses_the_upload() {
    folder_made_and_removed_after_the_check("throughput-made-collected", Removal::PurgeRetained)
        .await;
}

#[tokio::test]
async fn a_never_committed_folder_collected_during_the_upload_asks_to_retry() {
    // Acceptance review: the garbage collection deletes a folder that never got a commit and
    // holds no objects a day after it was made, without a tombstone left once its directory is
    // gone. That is no purge: the device must try again, not stop the folder for good.
    let gate = Gate::new();
    let name = "throughput-uncommitted-collected";
    let mut server = gated(name, &gate, None).await;
    let (account, client) = signed_in(&server).await;
    let folder = FolderId::from_bytes(random());
    make_folder(&server, &account, &folder, server.clock.now() - 2 * DAY_MS).await;
    let obj = Obj::new(ObjectType::Chunk, 100);
    let (path, bytes) = (object_path(&folder, &obj.id), obj.blob.clone());
    let sending = tokio::spawn(async move { client.put_bytes(&path, &bytes).await });
    gate.wait_for_calls(1).await;
    let file = file_of(name, &key_of(&account, &folder, &obj.id));
    assert!(file.is_file());
    let outcome = hangar_drive_server::service::admin::purge_retained(&server.app, &account.id)
        .await
        .unwrap();
    assert_eq!(outcome.deleted_folders, 1);
    gate.open();
    let reply = sending.await.unwrap();
    assert_eq!((reply.status, reply.code()), (429, ErrorCode::RateLimited));
    assert_eq!(reply.header("retry-after").as_deref(), Some("2"));
    assert!(!file.exists());
    assert_eq!(rows_of(&server, &obj.id).await, 0);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_folder_still_being_removed_refuses_for_a_moment() {
    // Follow-up LOW 2: the folder is deleted with a tombstone (its directory not removed yet)
    // after the check: try again in a few seconds, and the file is removed.
    let gate = Gate::new();
    let name = "throughput-tombstone";
    let mut server = gated(name, &gate, None).await;
    let (account, client) = signed_in(&server).await;
    let client = Arc::new(client);
    let folder = FolderId::from_bytes(random());
    gate.pass_one();
    assert_eq!(
        upload(&client, &folder, &Obj::new(ObjectType::Chunk, 100))
            .await
            .status,
        201
    );
    let obj = Obj::new(ObjectType::Chunk, 100);
    let (c, path, bytes) = (
        client.clone(),
        object_path(&folder, &obj.id),
        obj.blob.clone(),
    );
    let sending = tokio::spawn(async move { c.put_bytes(&path, &bytes).await });
    gate.wait_for_calls(2).await;
    let account_pk = server.account_pk(&account.id).await;
    // What the garbage collection's transaction does for a deleted folder.
    let mut tx = server.app.db.begin().await.unwrap();
    for (sql, with_id) in [
        ("DELETE FROM folders WHERE account_pk = ? AND id = ?", true),
        (
            "INSERT INTO folder_tombstones (account_pk, folder_id, created_ms) VALUES (?, ?, 0)",
            true,
        ),
        (
            "UPDATE accounts SET folder_removals = folder_removals + 1 WHERE pk = ?",
            false,
        ),
    ] {
        let query = sqlx::query(sql).bind(account_pk);
        let query = if with_id {
            query.bind(folder.as_bytes().as_slice())
        } else {
            query
        };
        query.execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    gate.open();
    let reply = sending.await.unwrap();
    assert_eq!((reply.status, reply.code()), (429, ErrorCode::RateLimited));
    assert_eq!(reply.header("retry-after").as_deref(), Some("2"));
    assert!(!file_of(name, &key_of(&account, &folder, &obj.id)).exists());
    assert_eq!(rows_of(&server, &obj.id).await, 0);
    // While the tombstone stands, a new upload is refused before its file goes in place.
    let again = upload(&client, &folder, &Obj::new(ObjectType::Chunk, 100)).await;
    assert_eq!(again.header("retry-after").as_deref(), Some("2"));
    assert_eq!(gate.calls(), 2);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_removal_of_another_folder_does_not_stop_an_upload() {
    // The count is per account: a removed folder next to it costs the upload nothing when its
    // own folder is still the same row.
    let gate = Gate::new();
    let name = "throughput-other-removal";
    let mut server = gated(name, &gate, None).await;
    let (account, client) = signed_in(&server).await;
    let client = Arc::new(client);
    let folder = FolderId::from_bytes(random());
    let other = FolderId::from_bytes(random());
    gate.pass_one();
    assert_eq!(
        upload(&client, &folder, &Obj::new(ObjectType::Chunk, 100))
            .await
            .status,
        201
    );
    gate.pass_one();
    assert_eq!(
        upload(&client, &other, &Obj::new(ObjectType::Chunk, 100))
            .await
            .status,
        201
    );
    let obj = Obj::new(ObjectType::Chunk, 100);
    let (c, path, bytes) = (
        client.clone(),
        object_path(&folder, &obj.id),
        obj.blob.clone(),
    );
    let sending = tokio::spawn(async move { c.put_bytes(&path, &bytes).await });
    gate.wait_for_calls(3).await;
    hangar_drive_server::service::admin::purge_folder(&server.app, &account.id, &other)
        .await
        .unwrap();
    gate.open();
    assert_eq!(sending.await.unwrap().status, 201);
    assert!(file_of(name, &key_of(&account, &folder, &obj.id)).is_file());
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_busy_upload_slot_asks_to_retry_in_a_second() {
    // Follow-up LOW 4: a slot frees within moments, not a minute.
    let gate = Gate::new();
    let mut server = TestServer::with(
        "throughput-busy-slot",
        Options {
            hooks: Hooks {
                upload_installed: Some(gate.hook()),
                ..Hooks::default()
            },
            concurrency: hangar_drive_server::config::Concurrency {
                uploads_per_account: 1,
                ..Default::default()
            },
            ..Options::default()
        },
    )
    .await;
    let (_, client) = signed_in(&server).await;
    let client = Arc::new(client);
    let folder = FolderId::from_bytes(random());
    let obj = Obj::new(ObjectType::Chunk, 100);
    let (c, path, bytes) = (
        client.clone(),
        object_path(&folder, &obj.id),
        obj.blob.clone(),
    );
    let first = tokio::spawn(async move { c.put_bytes(&path, &bytes).await });
    gate.wait_for_calls(1).await;
    let reply = upload(&client, &folder, &Obj::new(ObjectType::Chunk, 100)).await;
    assert_eq!((reply.status, reply.code()), (429, ErrorCode::RateLimited));
    assert_eq!(reply.header("retry-after").as_deref(), Some("1"));
    gate.open();
    assert_eq!(first.await.unwrap().status, 201);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn an_upload_finishes_after_its_connection_dropped() {
    // Follow-up LOW 3: the stripe and the file belong to a task of their own, so a dropped
    // request cannot leave the stripe free while the file is in place without a row.
    let gate = Gate::new();
    let name = "throughput-dropped";
    let mut server = gated(name, &gate, None).await;
    let (account, client) = signed_in(&server).await;
    let folder = FolderId::from_bytes(random());
    let obj = Obj::new(ObjectType::Chunk, 100);
    let (path, bytes) = (object_path(&folder, &obj.id), obj.blob.clone());
    let sending = tokio::spawn(async move { client.put_bytes(&path, &bytes).await });
    gate.wait_for_calls(1).await;
    let account_pk = server.account_pk(&account.id).await;
    assert_eq!(server.app.uploads.in_flight(account_pk), 1);
    // The client goes away while the server holds the stripe.
    sending.abort();
    let _ = sending.await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        server.app.uploads.in_flight(account_pk),
        1,
        "the upload slot stays with the task that still works"
    );
    gate.open();
    let mut stored = false;
    for _ in 0..200 {
        if rows_of(&server, &obj.id).await == 1 {
            stored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(stored, "the upload went on without its connection");
    let mut freed = false;
    for _ in 0..200 {
        if server.app.uploads.in_flight(account_pk) == 0 {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(freed, "the slot is freed once the task ended");
    assert!(file_of(name, &key_of(&account, &folder, &obj.id)).is_file());
    server.stop().await.unwrap();
}

#[tokio::test]
async fn concurrent_uploads_of_one_object_store_it_once() {
    let name = "throughput-concurrent";
    let mut server = TestServer::start(name).await;
    let (account, client) = signed_in(&server).await;
    let client = Arc::new(client);
    let folder = FolderId::from_bytes(random());
    let obj = Arc::new(Obj::new(ObjectType::Chunk, 50_000));
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let (c, o) = (client.clone(), obj.clone());
        tasks.push(tokio::spawn(async move {
            c.put_bytes(&object_path(&folder, &o.id), &o.blob).await
        }));
    }
    let mut created = 0;
    for task in tasks {
        let reply = task.await.unwrap();
        match reply.status {
            201 => created += 1,
            200 => assert!(!reply.json::<UploadResponse>().stored),
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(created, 1, "exactly one upload stored it");
    assert_eq!(rows_of(&server, &obj.id).await, 1);
    let stored = std::fs::read(file_of(name, &key_of(&account, &folder, &obj.id))).unwrap();
    assert_eq!(stored, obj.blob);
    // Nothing left in the staging area.
    let staging: Vec<_> = std::fs::read_dir(data_dir_of(name).join("staging"))
        .unwrap()
        .collect();
    assert!(staging.is_empty(), "{staging:?}");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn the_orphan_sweep_waits_for_an_upload_in_flight() {
    let gate = Gate::new();
    let name = "throughput-sweep-waits";
    let mut server = gated(name, &gate, None).await;
    let (account, client) = signed_in(&server).await;
    let folder = FolderId::from_bytes(random());
    let obj = Obj::new(ObjectType::Chunk, 1000);
    let (path, bytes) = (object_path(&folder, &obj.id), obj.blob.clone());
    let sending = tokio::spawn(async move { client.put_bytes(&path, &bytes).await });
    gate.arrived.notified().await;
    // The file is in place without a row; make it look old enough for the sweep.
    let file = file_of(name, &key_of(&account, &folder, &obj.id));
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(2 * 3600))
        .unwrap();
    let app = server.app.clone();
    let sweep = tokio::spawn(async move { retention::sweep_orphan_files(&app).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !sweep.is_finished(),
        "the sweep waits for the object's stripe"
    );
    gate.open();
    assert_eq!(sending.await.unwrap().status, 201);
    assert_eq!(sweep.await.unwrap().unwrap(), 0, "the row is there now");
    assert!(file.is_file(), "a committed row keeps its file");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn missing_answers_a_full_list_in_request_order() {
    let mut server = TestServer::start("throughput-missing").await;
    let (_, client) = signed_in(&server).await;
    let folder = FolderId::from_bytes(random());
    let held: Vec<Obj> = (0..5).map(|_| Obj::new(ObjectType::Chunk, 10)).collect();
    for obj in &held {
        assert_eq!(upload(&client, &folder, obj).await.status, 201);
    }
    // The largest list the protocol allows, the held IDs spread over it.
    let mut ids: Vec<ObjectId> = (0..MAX_MISSING_QUERY - held.len())
        .map(|_| ObjectId::from_bytes(random()))
        .collect();
    for (i, obj) in held.iter().enumerate() {
        ids.insert(i * 1000, obj.id);
    }
    assert_eq!(ids.len(), MAX_MISSING_QUERY);
    let expected: Vec<ObjectId> = ids
        .iter()
        .copied()
        .filter(|id| !held.iter().any(|o| o.id == *id))
        .collect();
    let reply = client
        .post(
            &missing_objects_path(&folder),
            &MissingObjectsRequest { ids: ids.clone() },
        )
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json::<MissingObjectsResponse>().missing, expected);
    // Held only, and none held.
    let only_held: Vec<ObjectId> = held.iter().map(|o| o.id).collect();
    let reply = client
        .post(
            &missing_objects_path(&folder),
            &MissingObjectsRequest { ids: only_held },
        )
        .await;
    assert!(reply.json::<MissingObjectsResponse>().missing.is_empty());
    let other = FolderId::from_bytes(random());
    let reply = client
        .post(
            &missing_objects_path(&other),
            &MissingObjectsRequest { ids: ids.clone() },
        )
        .await;
    assert_eq!(
        reply.json::<MissingObjectsResponse>().missing,
        ids,
        "another folder holds none of them"
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn the_first_file_sweep_runs_an_hour_after_the_start() {
    let name = "throughput-first-sweep";
    let mut server = TestServer::start(name).await;
    // A file without a row, old enough for the sweep.
    let key = ObjectKey {
        account: AccountId::from_bytes(random()),
        folder: FolderId::from_bytes(random()),
        id: ObjectId::from_bytes(random()),
    };
    let staged = server.app.store.staging_path().unwrap();
    std::fs::write(&staged, b"orphan").unwrap();
    server.app.store.install(&staged, &key).unwrap();
    let file = file_of(name, &key);
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(2 * 3600))
        .unwrap();
    let job = tokio::spawn(retention::run_job(
        server.app.clone(),
        Duration::from_millis(10),
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(file.is_file(), "no sweep right after the start");
    server
        .clock
        .advance_ms(retention::FIRST_SWEEP_DELAY_MS - 1000);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(file.is_file(), "not before the hour");
    server.clock.advance_ms(1000);
    let mut swept = false;
    for _ in 0..200 {
        if !file.exists() {
            swept = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(swept, "swept once the hour is over");
    job.abort();
    server.stop().await.unwrap();
}
