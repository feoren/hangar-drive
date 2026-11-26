//! Quota, budgets, the disk reserve, the retention window, uncommitted uploads, the minimum
//! count with its cap, anomaly pins with the lasting pin cap and the pin restore allowance, and
//! expired bases (ADR 0001, section 5), over a real socket with a manual clock.

mod common;

use common::*;
use hangar_drive_crypto::commit::{Commit, CommitContent, DeltaDigest};
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::ObjectType;
use hangar_drive_server::config::Limits;
use hangar_drive_server::service::admin;

/// A chunk of 4142 bytes on the wire (4000 bytes of plaintext).
fn chunk() -> Obj {
    Obj::new(ObjectType::Chunk, 4000)
}

fn dir() -> Obj {
    Obj::new(ObjectType::DirectoryNode, 64)
}

fn small(quota: u64, headroom: u64) -> Limits {
    let mut limits = Limits::for_quota(quota);
    limits.headroom = headroom;
    limits.min_commits = 1;
    // Budgets default to the quota; the tests that check them set them on purpose.
    limits.account_budget = 1 << 40;
    limits.device_budget = 1 << 40;
    limits
}

fn notices(page: &FeedPage) -> Vec<Notice> {
    page.entries
        .iter()
        .filter_map(|e| match &e.change {
            FeedChange::Notice { notice } => Some(notice.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn the_quota_counts_live_bytes_at_upload_and_at_commit_and_never_blocks_deletes() {
    let mut server = TestServer::with(
        "quota",
        Options {
            limits: small(10_000, 2_000),
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut folder = Folder::new();
    let (c1, c2, c3) = (chunk(), chunk(), chunk());
    assert_eq!(c1.size(), 4142);
    assert_eq!(upload(&ca, &folder.id, &c1).await.status, 201);
    assert_eq!(upload(&ca, &folder.id, &c2).await.status, 201);
    // Uncommitted uploads count: a third chunk would exceed the quota.
    let reply = upload(&ca, &folder.id, &c3).await;
    assert_eq!(
        (reply.status, reply.code()),
        (507, ErrorCode::QuotaExceeded)
    );
    // Directory nodes use the headroom.
    let d1 = dir();
    assert_eq!(upload(&ca, &folder.id, &d1).await.status, 201);
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&c1, &c2, &d1], &[])
            .await
            .status,
        200
    );
    assert_eq!(
        upload(&ca, &folder.id, &c3).await.code(),
        ErrorCode::QuotaExceeded
    );
    // A delete needs only a new directory node, which the headroom allows at a full quota.
    let d2 = dir();
    assert_eq!(upload(&ca, &folder.id, &d2).await.status, 201);
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&d2], &[&c2, &d1])
            .await
            .status,
        200
    );
    assert_eq!(upload(&ca, &folder.id, &c3).await.status, 201);
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&c3], &[])
            .await
            .status,
        200
    );
    // Reviving the retained c2 would raise live data above the quota.
    let reply = folder.commit(&ca, &account, &mut a, &[&c2], &[]).await;
    assert_eq!(
        (reply.status, reply.code()),
        (507, ErrorCode::QuotaExceeded)
    );
    // Swapping c1 for c2 does not raise the live bytes and passes.
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&c2], &[&c1])
            .await
            .status,
        200
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn device_and_account_budgets_limit_bytes_made_live_per_day() {
    let mut limits = small(1 << 30, 1 << 20);
    limits.device_budget = 5_000;
    limits.account_budget = 9_000;
    let mut server = TestServer::with(
        "budget",
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let mut account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let b = Device::new();
    assert_eq!(account.add(&ca, &a, &b).await.status, 200);
    let cb = account.sign_in(&server, &b).await;
    let mut folder = Folder::new();
    let (c1, c2, c3) = (chunk(), chunk(), chunk());
    assert_eq!(upload(&ca, &folder.id, &c1).await.status, 201);
    let reply = upload(&ca, &folder.id, &c2).await;
    assert_eq!(
        (reply.status, reply.code()),
        (507, ErrorCode::BudgetExceeded)
    );
    // Another device has its own budget, but the account's is shared.
    assert_eq!(upload(&cb, &folder.id, &c2).await.status, 201);
    assert_eq!(
        upload(&cb, &folder.id, &c3).await.code(),
        ErrorCode::BudgetExceeded
    );
    let page = feed(&ca, 0).await;
    let n = notices(&page);
    assert!(n.contains(&Notice::DeviceBudget { device: a.id }), "{n:?}");
    assert!(
        n.contains(&Notice::DeviceBudget { device: b.id }) || n.contains(&Notice::AccountBudget),
        "{n:?}"
    );
    // Moving data that is already live costs nothing.
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&c1, &c2], &[])
            .await
            .status,
        200
    );
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[], &[&c2])
            .await
            .status,
        200
    );
    // After a day the budgets are free again; reviving the retained c2 is counted at the commit.
    server.clock.advance_ms(DAY_MS + 1);
    server.gc().await;
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(upload(&ca, &folder.id, &c3).await.status, 201);
    let reply = folder.commit(&ca, &account, &mut a, &[&c2], &[]).await;
    assert_eq!(
        reply.code(),
        ErrorCode::BudgetExceeded,
        "4142 revived on top of 4142 uploaded"
    );
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&c3], &[])
            .await
            .status,
        200,
        "a declared upload costs nothing more"
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn below_the_disk_reserve_every_upload_is_refused() {
    let mut server = TestServer::start("disk").await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    server.disk.set(1024);
    let folder = Folder::new();
    let reply = upload(&ca, &folder.id, &chunk()).await;
    assert_eq!((reply.status, reply.code()), (507, ErrorCode::DiskReserve));
    assert!(notices(&feed(&ca, 0).await).contains(&Notice::DiskReserve));
    server.disk.set(u64::MAX / 2);
    assert_eq!(upload(&ca, &folder.id, &chunk()).await.status, 201);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn superseded_trees_stay_for_the_window_and_uploads_without_commit_for_a_day() {
    let mut server = TestServer::with(
        "window",
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
    let (o1, o2, pending) = (chunk(), chunk(), chunk());
    for o in [&o1, &o2, &pending] {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&o1], &[])
            .await
            .status,
        200
    );
    let first = folder.head.clone().unwrap().0;
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&o2], &[&o1])
            .await
            .status,
        200
    );

    server.clock.advance_ms(DAY_MS - 60_000);
    assert_eq!(
        server.gc().await.deleted_objects,
        0,
        "everything is younger than its limit"
    );
    server.clock.advance_ms(120_000);
    let outcome = server.gc().await;
    assert_eq!(
        (outcome.deleted_objects, outcome.expired_heads),
        (1, 0),
        "only the upload without a commit"
    );
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        ca.get(&object_path(&folder.id, &pending.id)).await.code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        ca.get(&object_path(&folder.id, &o1.id)).await.status,
        200,
        "in the window"
    );

    server.clock.advance_ms(29 * DAY_MS - 120_000);
    assert_eq!(
        server.gc().await.deleted_objects,
        0,
        "the window still runs"
    );
    server.clock.advance_ms(2 * 60_000);
    let outcome = server.gc().await;
    assert_eq!((outcome.deleted_objects, outcome.expired_heads), (1, 1));
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        ca.get(&object_path(&folder.id, &o1.id)).await.code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        ca.get(&object_path(&folder.id, &o2.id)).await.status,
        200,
        "live"
    );
    // The expired head's body stays for the frontier check.
    let page: DeltaPage = ca.get(&commits_path(&folder.id)).await.json();
    assert_eq!(page.commits[0].commit.as_bytes(), first.wire.as_slice());
    assert_eq!(page.commits.len(), 2);
    // A further step deletes nothing more.
    assert_eq!(server.gc().await, Default::default());
    server.stop().await.unwrap();
}

#[tokio::test]
async fn the_minimum_count_keeps_old_heads_within_its_byte_cap() {
    for (name, cap, kept) in [("mincount", 1 << 30, true), ("mincount-cap", 4_000, false)] {
        let mut limits = small(1 << 30, 1 << 20);
        limits.min_commits = 3;
        limits.min_count_cap = cap;
        let mut server = TestServer::with(
            name,
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
        let (o1, o2, o3) = (chunk(), chunk(), chunk());
        for o in [&o1, &o2, &o3] {
            assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
        }
        assert_eq!(
            folder
                .commit(&ca, &account, &mut a, &[&o1], &[])
                .await
                .status,
            200
        );
        assert_eq!(
            folder
                .commit(&ca, &account, &mut a, &[&o2], &[&o1])
                .await
                .status,
            200
        );
        assert_eq!(
            folder
                .commit(&ca, &account, &mut a, &[&o3], &[&o2])
                .await
                .status,
            200
        );
        server.clock.advance_ms(31 * DAY_MS);
        let outcome = server.gc().await;
        let ca = account.sign_in(&server, &a).await;
        if kept {
            assert_eq!(outcome.deleted_objects, 0, "{name}");
            assert_eq!(ca.get(&object_path(&folder.id, &o1.id)).await.status, 200);
        } else {
            // Neither old tree fits a cap below one chunk: both expire as without a minimum.
            assert_eq!(
                (outcome.deleted_objects, outcome.expired_heads),
                (2, 2),
                "{name}"
            );
            let n = notices(&feed(&ca, 0).await);
            assert!(
                n.iter().any(|n| matches!(
                    n,
                    Notice::MinimumCountCap {
                        cap_bytes: 4_000,
                        ..
                    }
                )),
                "{n:?}"
            );
        }
        server.stop().await.unwrap();
    }
}

#[tokio::test]
async fn a_burst_pins_the_commit_before_it_and_its_restore_costs_no_budget() {
    let mut limits = small(100_000, 10_000);
    limits.anomaly_min_objects = 2;
    limits.anomaly_percent = 50;
    limits.device_budget = 12_000;
    limits.account_budget = 12_000;
    let mut server = TestServer::with(
        "pin",
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
    let (x1, x2) = (chunk(), chunk());
    for o in [&x1, &x2] {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&x1, &x2], &[])
            .await
            .status,
        200
    );
    let pinned = folder.head.clone().unwrap().0;
    // The burst: every file object dropped at once.
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[], &[&x1, &x2])
            .await
            .status,
        200
    );
    let n = notices(&feed(&ca, 0).await);
    let until = n
        .iter()
        .find_map(|n| match n {
            Notice::AnomalyPin {
                folder: f,
                commit,
                until_ms,
            } if *f == folder.id && *commit == pinned.id => Some(*until_ms),
            _ => None,
        })
        .expect("a pin notice");
    assert_eq!(until, server.clock.now() + 90 * DAY_MS);
    // The upload budget is almost used up (8284 of 12000); reviving the pinned tree is free.
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&x1, &x2], &[])
            .await
            .status,
        200
    );
    // Dropped again, the pinned tree outlives the window.
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[], &[&x1, &x2])
            .await
            .status,
        200
    );
    server.clock.advance_ms(31 * DAY_MS);
    assert_eq!(server.gc().await.deleted_objects, 0);
    let pins = admin::pins(&server.app).await.unwrap();
    assert_eq!(pins.len(), 1);
    // The operator lifts it; the next step frees the tree.
    assert_eq!(
        admin::lift_pin(&server.app, &account.id, &pinned.id)
            .await
            .unwrap(),
        1
    );
    assert_eq!(server.gc().await.deleted_objects, 2);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn pins_beyond_the_lasting_pin_cap_lapse_in_creation_order() {
    // P = Q + H = 10100: one pinned tree of two chunks (8284) fits, a second does not.
    let mut limits = small(10_000, 100);
    limits.anomaly_min_objects = 2;
    limits.anomaly_percent = 50;
    let mut server = TestServer::with(
        "pincap",
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut first = Folder::new();
    let mut second = Folder::new();
    let (a1, a2, b1, b2) = (chunk(), chunk(), chunk(), chunk());
    for o in [&a1, &a2] {
        assert_eq!(upload(&ca, &first.id, o).await.status, 201);
    }
    assert_eq!(
        first
            .commit(&ca, &account, &mut a, &[&a1, &a2], &[])
            .await
            .status,
        200
    );
    assert_eq!(
        first
            .commit(&ca, &account, &mut a, &[], &[&a1, &a2])
            .await
            .status,
        200
    );
    for o in [&b1, &b2] {
        assert_eq!(upload(&ca, &second.id, o).await.status, 201);
    }
    assert_eq!(
        second
            .commit(&ca, &account, &mut a, &[&b1, &b2], &[])
            .await
            .status,
        200
    );
    let lapsing = second.head.clone().unwrap().0;
    assert_eq!(
        second
            .commit(&ca, &account, &mut a, &[], &[&b1, &b2])
            .await
            .status,
        200
    );
    assert_eq!(admin::pins(&server.app).await.unwrap().len(), 2);
    // Within the window both pins hold nothing alone and are admitted.
    let outcome = server.gc().await;
    assert_eq!((outcome.lapsed_pins, outcome.deleted_objects), (0, 0));
    server.clock.advance_ms(31 * DAY_MS);
    let outcome = server.gc().await;
    assert_eq!((outcome.lapsed_pins, outcome.deleted_objects), (1, 2));
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(
        ca.get(&object_path(&first.id, &a1.id)).await.status,
        200,
        "the first pin wins"
    );
    assert_eq!(
        ca.get(&object_path(&second.id, &b1.id)).await.code(),
        ErrorCode::NotFound
    );
    let n = notices(&feed(&ca, 0).await);
    assert!(
        n.iter().any(|n| matches!(n, Notice::AnomalyPin { commit, until_ms, .. } if *commit == lapsing.id && *until_ms == server.clock.now())),
        "the lapse is announced: {n:?}"
    );
    // A lapsed pin never comes back.
    let outcome = server.gc().await;
    assert_eq!(outcome.lapsed_pins, 0);
    assert!(admin::pins(&server.app)
        .await
        .unwrap()
        .iter()
        .any(|p| p.lapsed));
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_side_commit_on_an_expired_base_gets_base_expired() {
    let mut server = TestServer::with(
        "base",
        Options {
            limits: small(1 << 30, 1 << 20),
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let mut account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut b = Device::new();
    assert_eq!(account.add(&ca, &a, &b).await.status, 200);
    let mut folder = Folder::new();
    assert_eq!(
        folder.commit(&ca, &account, &mut a, &[], &[]).await.status,
        200
    );
    let base = folder.entry().unwrap();
    assert_eq!(
        folder.commit(&ca, &account, &mut a, &[], &[]).await.status,
        200
    );
    server.clock.advance_ms(31 * DAY_MS);
    assert_eq!(server.gc().await.expired_heads, 1);
    let h = folder.entry().unwrap();
    let content = |device: &mut Device| CommitContent {
        root: ObjectId::from_bytes(random()),
        generation: Generation(1),
        device: device.id,
        log_head: account.head(),
        counter: device.next_counter(),
        delta: DeltaDigest::of(false, &[], &[]).unwrap(),
    };
    let side = Commit::side(account.id, folder.id, &base, content(&mut b))
        .sign(&b.identity)
        .unwrap();
    let merge = Commit::merge(account.id, folder.id, &h, &side, content(&mut b))
        .sign(&b.identity)
        .unwrap();
    let mut request = folder.request(&merge, &[], &[]);
    request.side = Some(CommitUpload {
        commit: Blob(side.wire.clone()),
        delta: ReferenceDelta::default(),
    });
    let cb = account.sign_in(&server, &b).await;
    let reply = cb.post(&commit_path(&folder.id), &request).await;
    assert_eq!((reply.status, reply.code()), (409, ErrorCode::BaseExpired));
    // The merge with the single parent H goes through.
    let single = folder.next(&account, &mut b);
    assert_eq!(
        cb.post(&commit_path(&folder.id), &folder.request(&single, &[], &[]))
            .await
            .status,
        200
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_purge_of_retained_data_keeps_only_live_trees() {
    let mut server = TestServer::with(
        "purge",
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
    let (o1, o2) = (chunk(), chunk());
    for o in [&o1, &o2] {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&o1], &[])
            .await
            .status,
        200
    );
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&o2], &[&o1])
            .await
            .status,
        200
    );
    let outcome = admin::purge_retained(&server.app, &account.id)
        .await
        .unwrap();
    assert_eq!(outcome.deleted_objects, 1);
    assert_eq!(
        ca.get(&object_path(&folder.id, &o1.id)).await.code(),
        ErrorCode::NotFound
    );
    assert_eq!(ca.get(&object_path(&folder.id, &o2.id)).await.status, 200);
    let page: DeltaPage = ca.get(&commits_path(&folder.id)).await.json();
    assert_eq!(page.commits.len(), 1, "a purge removes the old bodies too");
    admin::purge_account(&server.app, &account.id)
        .await
        .unwrap();
    assert_eq!(ca.get(LOG_PATH).await.code(), ErrorCode::Unauthorized);
    server.stop().await.unwrap();
}
