//! A measurement, not a check (overall review N4; run with `--ignored --nocapture`): the heap a
//! commit call with the largest reference delta holds at its peak, on top of what the test
//! itself holds. Its own test binary, because the counting allocator counts the whole process.
//!
//! The server holds up to `HANGAR_DRIVE_HEAVY_REQUESTS` such calls at once, so this peak times
//! that number must stay well below the container's `mem_limit` (`docker-compose.yml`).
//! SQLite allocates outside the Rust allocator and is not counted; the IDs reach it in pages of
//! a few hundred KiB (`load_ids`), and its temporary tables spill to disk beyond its small page
//! cache, so its share stays small.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use hangar_drive_protocol::api::{commit_path, MAX_REFERENCE_DELTA_IDS};
use hangar_drive_protocol::ids::ObjectId;

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = CURRENT.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

// SAFETY: every call forwards to the system allocator with the caller's layout and pointer
// unchanged, so the allocator contract is the system allocator's; the counters only observe.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded as is (see the impl).
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded as is (see the impl).
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded as is (see the impl).
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded as is (see the impl).
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            // The old block and the new one may both exist for a moment inside realloc.
            grew(new_size);
            CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const MIB: f64 = 1024.0 * 1024.0;

#[tokio::test]
#[ignore]
async fn n4_measure_the_heap_peak_of_a_commit_with_the_largest_delta() {
    let mut limits = hangar_drive_server::config::Limits::for_quota(1 << 40);
    limits.headroom = 1 << 30;
    limits.account_budget = 1 << 50;
    limits.device_budget = 1 << 50;
    let mut server = TestServer::with(
        "n4-memory",
        Options {
            limits,
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
    // The largest delta one commit may carry, every object held, so the call runs to the end.
    let mut ids: Vec<ObjectId> = (0..MAX_REFERENCE_DELTA_IDS)
        .map(|_| ObjectId::from_bytes(random()))
        .collect();
    ids.sort();
    let mut tx = server.app.db.begin().await.unwrap();
    for page in ids.chunks(10_000) {
        let hex: Vec<String> = page.iter().map(ObjectId::to_hex).collect();
        sqlx::query(
            "INSERT INTO objects (folder_pk, object_id, kind, size, uploaded_ms) \
             SELECT ?, unhex(value), 1, 100, 0 FROM json_each(?)",
        )
        .bind(folder_pk)
        .bind(serde_json::to_string(&hex).unwrap())
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    let commit = folder.next_adding(&account, &mut a, &ids);
    let mut request = folder.request(&commit, &[], &[]);
    request.head.delta.added = ids;
    let body = serde_json::to_vec(&request).unwrap();
    drop(request);
    let token = ca.token.clone().unwrap();
    let headers = [
        ("Authorization", format!("Bearer {token}")),
        ("Content-Type", "application/json".to_owned()),
    ];
    let path = commit_path(&folder.id);
    let baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let started = std::time::Instant::now();
    let reply = raw(server.addr, "POST", &path, &headers, &body).await;
    let elapsed = started.elapsed();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    eprintln!(
        "commit with {} added IDs, body {:.1} MiB: status {} in {:?}, heap peak of the call \
         {:.1} MiB ({:.0} bytes per ID)",
        MAX_REFERENCE_DELTA_IDS,
        body.len() as f64 / MIB,
        reply.status,
        elapsed,
        peak as f64 / MIB,
        peak as f64 / MAX_REFERENCE_DELTA_IDS as f64,
    );
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    server.stop().await.unwrap();
}
