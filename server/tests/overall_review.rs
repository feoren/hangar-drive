//! One attack per server finding of the overall security review (2026-11-26), over a real socket
//! with a manual clock. Each test failed before its fix. Covered elsewhere: the reversed rate
//! limit test of M1 in `flows.rs`, N3 and the call limits in the unit tests of `client_ip.rs`
//! and `ratelimit.rs`, `secure_delete` in `db.rs`, HSTS of a TLS server in `tls_cli.rs`, the
//! N4 measurement in `commit_memory.rs`.

mod common;

use std::sync::{mpsc, Arc, Mutex};

use common::*;
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::ObjectType;
use hangar_drive_server::config::Limits;
use hangar_drive_server::http::ratelimit::Scope;
use hangar_drive_server::store::ObjectStore;

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

fn pins(page: &FeedPage) -> usize {
    page.entries
        .iter()
        .filter(|e| {
            matches!(
                &e.change,
                FeedChange::Notice {
                    notice: Notice::AnomalyPin { .. }
                }
            )
        })
        .count()
}

const W_DAYS: u64 = 30;

// ---------------------------------------------------------------------------------------------
// M1: bad proofs in a device's name locked the device out
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn m1_a_third_party_does_not_lock_a_device_out() {
    let mut server = TestServer::start("m1-lockout").await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let client = Client::new(server.addr);
    let challenge = ChallengeRequest {
        account: account.id,
        device: a.id,
    };
    // Anyone knows the account and device IDs (they are in the log the server shows every
    // device) and can send proofs in the device's name: with another key, or signed for
    // another address. Far more than the failure limit, within the address limits.
    let failures = Scope::ProofFailures.rule().limit + 5;
    let attacker = Device::new();
    let mut last = ErrorCode::Unknown;
    for i in 0..failures {
        let c: ChallengeResponse = client.post(CHALLENGE_PATH, &challenge).await.json();
        let url = if i % 2 == 0 {
            TEST_URL
        } else {
            "https://relay.example/"
        };
        let signature =
            attacker
                .identity
                .prove_session(&c.server, url, &account.id, &a.id, &c.challenge);
        let reply = client
            .post(
                PROOF_PATH,
                &ProofRequest {
                    account: account.id,
                    device: a.id,
                    challenge: c.challenge,
                    server_url: url.into(),
                    signature,
                    log_length: None,
                },
            )
            .await;
        last = reply.code();
    }
    assert_eq!(
        last,
        ErrorCode::RateLimited,
        "failing proofs over the limit wait for the window"
    );
    // The device itself signs in at once.
    let c: ChallengeResponse = client.post(CHALLENGE_PATH, &challenge).await.json();
    let signature = a
        .identity
        .prove_session(&c.server, TEST_URL, &account.id, &a.id, &c.challenge);
    let reply = client
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: a.id,
                challenge: c.challenge,
                server_url: TEST_URL.into(),
                signature,
                log_length: None,
            },
        )
        .await;
    assert_eq!(
        reply.status,
        200,
        "a valid proof goes through: {:?}",
        String::from_utf8_lossy(&reply.body)
    );
    // A proof for another address names a device the log does not list: no key is kept for it,
    // in the URL branch as in the signature branch.
    let keys_before = server.app.limiter.keys(Scope::ProofFailures);
    let stranger = Device::new();
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
        "https://relay.example/",
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
                server_url: "https://relay.example/".into(),
                signature,
                log_length: None,
            },
        )
        .await;
    assert_eq!(reply.code(), ErrorCode::ProofInvalid);
    assert_eq!(
        server.app.limiter.keys(Scope::ProofFailures),
        keys_before,
        "an unlisted device leaves no trace"
    );
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// N1: the pin restore allowance paid every bring-back of the same pinned folder
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn n1_the_allowance_brings_a_pinned_folder_back_only_once() {
    // A folder of two days' uploads, a budget of one and a half days: only the allowance lets
    // its whole tree come back at once.
    let files: Vec<Obj> = (0..26).map(|_| tiny()).collect();
    let half: u64 = files[..13].iter().map(|o| o.blob.len() as u64).sum();
    let mut limits = small(1 << 30, 1 << 20);
    limits.account_budget = half + half / 2;
    limits.device_budget = half + half / 2;
    let mut server = TestServer::with(
        "n1-bring-back",
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
    assert_eq!(pins(&feed(&ca, 0).await), 1, "the retirement pinned");
    assert_eq!(
        ca.delete(&retire_path(&folder.id)).await.status,
        204,
        "the first bring-back is covered by the allowance"
    );
    // Retire and bring back again, after the pin cooldown: the standing pin (and any pin a
    // new retirement adds) holds the same head, so the tree would come back for free again
    // and again.
    server.clock.advance_ms(2 * 3_600_000);
    let ca = account.sign_in(&server, &a).await;
    assert_eq!(ca.post(&retire_path(&folder.id), &()).await.status, 204);
    let standing: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pins WHERE lapsed_ms IS NULL AND until_ms > ?")
            .bind(i64::try_from(server.clock.now()).unwrap())
            .fetch_one(&server.app.db)
            .await
            .unwrap();
    assert!(standing >= 1, "a pin still holds the head");
    assert_eq!(
        ca.delete(&retire_path(&folder.id)).await.code(),
        ErrorCode::BudgetExceeded,
        "a second bring-back of the same pinned head pays the budget"
    );
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// N2: an upload while the collection removed a deleted folder's files was lost
// ---------------------------------------------------------------------------------------------

/// The file store, stopped inside its first `delete_folder` until the test lets it go on.
struct GatedStore {
    inner: Arc<dyn ObjectStore>,
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    go: Mutex<Option<mpsc::Receiver<()>>>,
}

impl ObjectStore for GatedStore {
    fn staging_path(&self) -> std::io::Result<std::path::PathBuf> {
        self.inner.staging_path()
    }
    fn install(
        &self,
        staged: &std::path::Path,
        key: &hangar_drive_server::store::ObjectKey,
    ) -> std::io::Result<()> {
        self.inner.install(staged, key)
    }
    fn open(&self, key: &hangar_drive_server::store::ObjectKey) -> std::io::Result<std::fs::File> {
        self.inner.open(key)
    }
    fn delete(&self, key: &hangar_drive_server::store::ObjectKey) -> std::io::Result<()> {
        self.inner.delete(key)
    }
    fn delete_folder(&self, account: &AccountId, folder: &FolderId) -> std::io::Result<()> {
        let go = self.go.lock().unwrap().take();
        if let Some(go) = go {
            let _ = self.entered.send(());
            let _ = go.recv();
        }
        self.inner.delete_folder(account, folder)
    }
    fn delete_account(&self, account: &AccountId) -> std::io::Result<()> {
        self.inner.delete_account(account)
    }
    fn walk(
        &self,
        visit: &mut dyn FnMut(hangar_drive_server::store::ObjectKey, std::time::SystemTime),
    ) -> std::io::Result<()> {
        self.inner.walk(visit)
    }
}

#[tokio::test]
async fn n2_an_upload_while_a_deleted_folder_is_removed_is_not_lost() {
    let (entered_tx, mut entered) = tokio::sync::mpsc::unbounded_channel();
    let (go, go_rx) = mpsc::channel();
    let gate = Mutex::new(Some(go_rx));
    let mut server = TestServer::with(
        "n2-tombstone",
        Options {
            limits: small(1 << 30, 1 << 20),
            store_layer: Some(Box::new(move |inner| {
                Arc::new(GatedStore {
                    inner,
                    entered: entered_tx,
                    go: gate,
                }) as Arc<dyn ObjectStore>
            })),
            ..Options::default()
        },
    )
    .await;
    let mut a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let mut folder = Folder::new();
    let old = tiny();
    assert_eq!(upload(&ca, &folder.id, &old).await.status, 201);
    assert_eq!(
        folder
            .commit(&ca, &account, &mut a, &[&old], &[])
            .await
            .status,
        200
    );
    assert_eq!(ca.post(&retire_path(&folder.id), &()).await.status, 204);
    server.clock.advance_ms((W_DAYS + 1) * DAY_MS);
    // The collection deletes the folder's rows, then stops before its files go.
    let app = server.app.clone();
    let gc = tokio::spawn(async move {
        hangar_drive_server::service::retention::run_step(&app)
            .await
            .unwrap()
    });
    entered.recv().await.unwrap();
    // A device uploads into the same folder ID in that moment (any device of the account can
    // pick the ID; an honest one would be one that never saw the folder go).
    let ca = account.sign_in(&server, &a).await;
    let new = tiny();
    let reply = upload(&ca, &folder.id, &new).await;
    assert_eq!(
        reply.code(),
        ErrorCode::RateLimited,
        "the folder is not made again while its files are being removed"
    );
    go.send(()).unwrap();
    assert_eq!(gc.await.unwrap().deleted_folders, 1);
    // Once the files are gone the ID is free again, and what is uploaded then stays.
    assert_eq!(upload(&ca, &folder.id, &new).await.status, 201);
    assert_eq!(
        ca.get(&object_path(&folder.id, &new.id)).await.status,
        200,
        "the new object's file exists"
    );
    let tombstones: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM folder_tombstones")
        .fetch_one(&server.app.db)
        .await
        .unwrap();
    assert_eq!(tombstones, 0);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn n2_a_tombstone_left_by_a_crash_is_finished_by_the_next_step() {
    let mut server = TestServer::start("n2-crash").await;
    let a = Device::new();
    let account = Account::create(&server, &a, &[]).await;
    let ca = account.sign_in(&server, &a).await;
    let folder = FolderId::from_bytes(random());
    // The state after a crash between the collection's commit and the removal of the files.
    let pk = server.account_pk(&account.id).await;
    sqlx::query(
        "INSERT INTO folder_tombstones (account_pk, folder_id, created_ms) VALUES (?, ?, 0)",
    )
    .bind(pk)
    .bind(folder.as_bytes().as_slice())
    .execute(&server.app.db)
    .await
    .unwrap();
    let obj = tiny();
    assert_eq!(
        upload(&ca, &folder, &obj).await.code(),
        ErrorCode::RateLimited
    );
    server.gc().await;
    assert_eq!(upload(&ca, &folder, &obj).await.status, 201);
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Info: HSTS only where the server is the TLS end
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_server_behind_a_proxy_sets_no_hsts() {
    let mut server = TestServer::start("hsts-plain").await;
    let reply = Client::new(server.addr)
        .get(hangar_drive_protocol::HEALTH_PATH)
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("strict-transport-security"), None);
    server.stop().await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Info: the bearer token is looked up only within the rate limit
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn made_up_tokens_meet_the_rate_limit_before_the_token_lookup() {
    // Scaled by 30: 100 calls per address and minute.
    let mut server = TestServer::with(
        "bearer-limit",
        Options {
            limiter: hangar_drive_server::http::ratelimit::RateLimiter::scaled(30),
            ..Options::default()
        },
    )
    .await;
    let mut client = Client::new(server.addr);
    client.token = Some(base64url(&random::<32>()));
    let limit = Scope::CallIp.rule().limit / 30;
    for _ in 0..limit {
        assert_eq!(client.get(FEED_PATH).await.code(), ErrorCode::Unauthorized);
    }
    assert_eq!(
        client.get(FEED_PATH).await.code(),
        ErrorCode::RateLimited,
        "beyond the limit the token is not looked up at all"
    );
    server.stop().await.unwrap();
}
