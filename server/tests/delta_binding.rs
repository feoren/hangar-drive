//! Reference deltas bound to the tree (ADR 0001, amendment "reference deltas bound to the
//! tree"; security review 2026-11-26, finding HIGH and LOW 1): the server checks every uploaded
//! delta against the digest its commit signs, keeps the new root live, answers a diff that does
//! not fit its live set with `delta_mismatch`, and takes a full delta as the new live set, also
//! after the collection deleted objects a broken view no longer held. The burst signal counts
//! against the window's starting size, so garbage added first does not dilute it.

mod common;

use common::*;
use hangar_drive_crypto::commit::{Commit, CommitContent, DeltaDigest};
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::ObjectType;
use hangar_drive_server::config::Limits;

fn chunk() -> Obj {
    Obj::new(ObjectType::Chunk, 4000)
}

fn dir() -> Obj {
    Obj::new(ObjectType::DirectoryNode, 64)
}

fn limits() -> Limits {
    let mut limits = Limits::for_quota(1 << 30);
    limits.min_commits = 1;
    limits.account_budget = 1 << 40;
    limits.device_budget = 1 << 40;
    limits
}

/// A commit on the folder's head with `root` and the signed digest `digest`, uploaded with
/// `added` and `dropped` (which need not match the digest).
fn signed(
    folder: &Folder,
    account: &Account,
    device: &mut Device,
    root: ObjectId,
    digest: DeltaDigest,
) -> hangar_drive_crypto::commit::SignedCommit {
    let content = CommitContent {
        root,
        delta: digest,
        ..folder.content(account, device, &[], &[])
    };
    let commit = match folder.entry() {
        None => Commit::first(account.id, folder.id, content),
        Some(entry) => Commit::on(account.id, folder.id, &entry, content),
    };
    commit.sign(&device.identity).unwrap()
}

/// Sends `commit` with the delta `added`, `dropped` and records it as the head when accepted.
async fn send(
    folder: &mut Folder,
    client: &Client,
    commit: hangar_drive_crypto::commit::SignedCommit,
    added: Vec<ObjectId>,
    dropped: Vec<ObjectId>,
) -> Reply {
    let mut request = folder.request(&commit, &[], &[]);
    request.head.delta = ReferenceDelta { added, dropped };
    let reply = client.post(&commit_path(&folder.id), &request).await;
    if reply.status == 200 {
        let response: CommitResponse = reply.json();
        folder.head = Some((commit, response.sequence));
    }
    reply
}

/// A full commit of `tree` (the whole reachable set), its root `root`.
async fn full(
    folder: &mut Folder,
    client: &Client,
    account: &Account,
    device: &mut Device,
    root: ObjectId,
    tree: &[&Obj],
) -> Reply {
    let ids = sorted(tree);
    let digest = DeltaDigest::of(true, &ids, &[]).unwrap();
    let commit = signed(folder, account, device, root, digest);
    send(folder, client, commit, ids, Vec::new()).await
}

async fn missing(client: &Client, folder: &FolderId, objects: &[&Obj]) -> Vec<ObjectId> {
    let reply = client
        .post(
            &missing_objects_path(folder),
            &MissingObjectsRequest {
                ids: objects.iter().map(|o| o.id).collect(),
            },
        )
        .await;
    assert_eq!(reply.status, 200);
    let mut ids = reply.json::<MissingObjectsResponse>().missing;
    ids.sort();
    ids
}

#[tokio::test]
async fn a_head_that_keeps_its_root_but_drops_it_is_refused() {
    let mut server = TestServer::with(
        "delta-root",
        Options {
            limits: limits(),
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut folder = Folder::new();
    let (root, f1, f2) = (dir(), chunk(), chunk());
    for o in [&root, &f1, &f2] {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    let all = sorted(&[&root, &f1, &f2]);
    let first = signed(
        &folder,
        &account,
        &mut a,
        root.id,
        DeltaDigest::of(false, &all, &[]).unwrap(),
    );
    let reply = send(&mut folder, &ca, first, all.clone(), vec![]).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    // Attack 1 of the finding: the same root, and every object of the parent's tree dropped,
    // the root with it. The server would hold the folder as empty and collect it.
    let attack = signed(
        &folder,
        &account,
        &mut a,
        root.id,
        DeltaDigest::of(false, &[], &all).unwrap(),
    );
    let reply = send(&mut folder, &ca, attack, vec![], all.clone()).await;
    assert_eq!(
        (reply.status, reply.code()),
        (409, ErrorCode::DeltaMismatch)
    );
    assert_eq!(reply.json::<ErrorBody>().missing, vec![root.id]);
    // A root that was never live does not pass either.
    let ghost = ObjectId::from_bytes(random());
    let commit = signed(
        &folder,
        &account,
        &mut a,
        ghost,
        DeltaDigest::of(false, &[], &[]).unwrap(),
    );
    let reply = send(&mut folder, &ca, commit, vec![], vec![]).await;
    assert_eq!(reply.code(), ErrorCode::DeltaMismatch);
    assert_eq!(reply.json::<ErrorBody>().missing, vec![ghost]);
    // A full delta without its own root is no reachable set.
    let commit = signed(
        &folder,
        &account,
        &mut a,
        root.id,
        DeltaDigest::of(true, &sorted(&[&f1, &f2]), &[]).unwrap(),
    );
    let reply = send(&mut folder, &ca, commit, sorted(&[&f1, &f2]), vec![]).await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_delta_the_commit_did_not_sign_is_refused() {
    let mut server = TestServer::with(
        "delta-hash",
        Options {
            limits: limits(),
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut folder = Folder::new();
    let (root, f1) = (dir(), chunk());
    for o in [&root, &f1] {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&root, &f1], &[])
            .await
            .status,
        200
    );
    // Garbage declared as added on top of what the commit signed (attack 3 of the finding):
    // the delta no longer matches the digest, whatever the tree.
    let garbage = chunk();
    assert_eq!(upload(&ca, &folder.id, &garbage).await.status, 201);
    let commit = folder.next_with(&account, &mut a, &[], &[]);
    let reply = send(&mut folder, &ca, commit, vec![garbage.id], vec![]).await;
    assert_eq!(
        (reply.status, reply.code()),
        (400, ErrorCode::CommitRefused)
    );
    // A digest over other IDs, the mode flipped, and a drop hidden from the digest.
    let commit = signed(
        &folder,
        &account,
        &mut a,
        root.id,
        DeltaDigest::of(false, &[ObjectId::from_bytes(random())], &[]).unwrap(),
    );
    let reply = send(&mut folder, &ca, commit, vec![garbage.id], vec![]).await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);
    // A full digest over the garbage alone, sent as the delta it signed but read as a diff:
    // the server takes the mode from the signed commit, and the root check still holds.
    let commit = signed(
        &folder,
        &account,
        &mut a,
        garbage.id,
        DeltaDigest::of(true, &[garbage.id], &[]).unwrap(),
    );
    let reply = send(&mut folder, &ca, commit, vec![garbage.id], vec![f1.id]).await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);
    // A drop hidden from the digest.
    let diff = signed(
        &folder,
        &account,
        &mut a,
        root.id,
        DeltaDigest::of(false, &[garbage.id], &[]).unwrap(),
    );
    let reply = send(&mut folder, &ca, diff, vec![garbage.id], vec![f1.id]).await;
    assert_eq!(reply.code(), ErrorCode::CommitRefused);
    // Nothing of it reached the live set: the signed diff that drops f1 still fits.
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[], &[&f1])
            .await
            .status,
        200
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_full_delta_rebuilds_a_broken_live_set_with_objects_uploaded_again() {
    let mut server = TestServer::with(
        "delta-full",
        Options {
            limits: limits(),
            ..Options::default()
        },
    )
    .await;
    let (mut a, mut b) = (Device::new(), Device::new());
    let mut account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(account.add(&ca, &a, &b).await.status, 200);
    let mut folder = Folder::new();
    let (root, f1, f2) = (dir(), chunk(), chunk());
    for o in [&root, &f1, &f2] {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    let tree = [&root, &f1, &f2];
    assert_eq!(
        full(&mut folder, &ca, &account, &mut a, root.id, &tree)
            .await
            .status,
        200
    );
    // A compromised device drops every file of the tree but keeps the root: the server cannot
    // tell, every device refuses the head, and once the window ends the collection deletes the
    // files (attack 1 of the finding without the root).
    let attack = signed(
        &folder,
        &account,
        &mut a,
        root.id,
        DeltaDigest::of(false, &[], &sorted(&[&f1, &f2])).unwrap(),
    );
    assert_eq!(
        send(&mut folder, &ca, attack, vec![], sorted(&[&f1, &f2]))
            .await
            .status,
        200
    );
    server.clock.advance_ms(31 * DAY_MS);
    assert_eq!(server.gc().await.deleted_objects, 2);
    let cb = account.sign_in(&server, &b).await;
    assert_eq!(missing(&cb, &folder.id, &tree).await, sorted(&[&f1, &f2]));
    // A diff that names the files does not fit the broken view, and the answer says which.
    let new_root = dir();
    assert_eq!(upload(&cb, &folder.id, &new_root).await.status, 201);
    let probe = signed(
        &folder,
        &account,
        &mut b,
        root.id,
        DeltaDigest::of(false, &[], &sorted(&[&f1])).unwrap(),
    );
    let reply = send(&mut folder, &cb, probe, vec![], sorted(&[&f1])).await;
    assert_eq!(
        (reply.status, reply.code()),
        (409, ErrorCode::DeltaMismatch)
    );
    assert_eq!(reply.json::<ErrorBody>().missing, vec![f1.id]);
    // The repair: the same tree with a full delta. The deleted files are asked for, uploaded
    // again, and then the server's live set is the tree again.
    let repaired = [&new_root, &f1, &f2];
    let reply = full(&mut folder, &cb, &account, &mut b, new_root.id, &repaired).await;
    assert_eq!(
        (reply.status, reply.code()),
        (400, ErrorCode::MissingObjects)
    );
    let mut asked = reply.json::<ErrorBody>().missing;
    asked.sort();
    assert_eq!(asked, sorted(&[&f1, &f2]));
    for o in [&f1, &f2] {
        assert_eq!(upload(&cb, &folder.id, o).await.status, 201);
    }
    let reply = full(&mut folder, &cb, &account, &mut b, new_root.id, &repaired).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    // The old root left the live set, the files are in it: honest diffs fit again, and the
    // collection keeps the tree.
    assert_eq!(
        folder
            .commit(&cb, &account, &mut b, &[], &[&f1])
            .await
            .status,
        200
    );
    server.clock.advance_ms(31 * DAY_MS);
    server.gc().await;
    let cb = account.sign_in(&server, &b).await;
    assert_eq!(missing(&cb, &folder.id, &[&new_root, &f2]).await, vec![]);
    assert_eq!(
        missing(&cb, &folder.id, &[&root, &f1]).await,
        sorted(&[&root, &f1])
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn garbage_added_first_does_not_dilute_the_burst_signal() {
    // Scaled: 20 chunks stand for 20 GB of real data, 80 chunks of garbage for four times as
    // much. Dropping every real chunk is 20 % of the data just before the drop, below the 30 %
    // threshold, but 100 % of the data at the start of the window.
    let mut limits = limits();
    limits.anomaly_min_objects = 20;
    limits.anomaly_percent = 30;
    let mut server = TestServer::with(
        "delta-burst",
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
    let root = dir();
    assert_eq!(upload(&ca, &folder.id, &root).await.status, 201);
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&root], &[])
            .await
            .status,
        200
    );
    let real: Vec<Obj> = (0..20).map(|_| chunk()).collect();
    for o in &real {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    let real_refs: Vec<&Obj> = real.iter().collect();
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &real_refs, &[])
            .await
            .status,
        200
    );
    let real_head = folder.head.clone().unwrap().0;
    // Two hours later, outside the window of the real data's own commit.
    server.clock.advance_ms(2 * 3_600_000);
    let ca = account.sign_in(&server, &a).await;
    let garbage: Vec<Obj> = (0..80).map(|_| chunk()).collect();
    for o in &garbage {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    let garbage_refs: Vec<&Obj> = garbage.iter().collect();
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &garbage_refs, &[])
            .await
            .status,
        200
    );
    let garbage_head = folder.entry().map(|e| e.commit);
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[], &real_refs)
            .await
            .status,
        200
    );
    let pinned = feed(&ca, 0)
        .await
        .entries
        .iter()
        .find_map(|e| match &e.change {
            FeedChange::Notice {
                notice:
                    Notice::AnomalyPin {
                        folder: f, commit, ..
                    },
            } if *f == folder.id => Some(*commit),
            _ => None,
        });
    // The pin holds the head before the drop: the real data, with the garbage beside it.
    assert!(pinned.is_some(), "the diluted burst sets off a pin");
    assert_eq!(pinned, garbage_head);
    assert_ne!(pinned, Some(real_head.id));
    server.stop().await.unwrap();
}

#[tokio::test]
async fn bringing_back_what_a_removed_device_dropped_costs_no_budget() {
    // MEDIUM 2 of the follow-up review: a removed device's drops, made back live by the barrier
    // or the repair after its removal, must not wait for a device budget its damage used up.
    let mut limits = limits();
    limits.device_budget = 20_000;
    let mut server = TestServer::with(
        "delta-budget",
        Options {
            limits,
            ..Options::default()
        },
    )
    .await;
    let (mut a, mut c) = (Device::new(), Device::new());
    let mut account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(account.add(&ca, &a, &c).await.status, 200);
    let cc = account.sign_in(&server, &c).await;
    let mut folder = Folder::new();
    let (root, f1, f2, f3) = (dir(), chunk(), chunk(), chunk());
    for o in [&root, &f1, &f2, &f3] {
        assert_eq!(upload(&ca, &folder.id, o).await.status, 201);
    }
    let tree = [&root, &f1, &f2, &f3];
    assert_eq!(
        full(&mut folder, &ca, &account, &mut a, root.id, &tree)
            .await
            .status,
        200
    );
    // C drops every file with a diff that keeps the tree: three file objects set off no pin.
    let files = sorted(&[&f1, &f2, &f3]);
    let attack = signed(
        &folder,
        &account,
        &mut c,
        root.id,
        DeltaDigest::of(false, &[], &files).unwrap(),
    );
    assert_eq!(
        send(&mut folder, &cc, attack, vec![], files.clone())
            .await
            .status,
        200
    );
    assert_eq!(account.remove(&ca, &a, &[c.id]).await.status, 200);
    let ca = account.sign_in(&server, &a).await;
    // A has used about 12.6 kB of its 20 kB today; the files are another 12.4 kB. Without the
    // exemption the full delta that brings them back is refused with `budget_exceeded`.
    let reply = full(&mut folder, &ca, &account, &mut a, root.id, &tree).await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    // A drop and revival of its own still pays: the exemption is only for the removed device.
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[], &[&f1, &f2])
            .await
            .status,
        200
    );
    let reply = folder.commit(&ca, &account, &mut a, &[&f1, &f2], &[]).await;
    assert_eq!(reply.code(), ErrorCode::BudgetExceeded);
    server.stop().await.unwrap();
}
