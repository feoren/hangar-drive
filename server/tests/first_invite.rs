//! The invite a server without any account prints at start, for container hosts without a
//! terminal (accounts::first_start_invite).

mod common;

use common::*;
use hangar_drive_server::service::accounts::{first_start_invite, FIRST_INVITE_DAYS};

const DAY_MS: u64 = 86_400_000;

async fn unused_invites(server: &TestServer) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM invites WHERE used_ms IS NULL")
        .fetch_one(&server.app.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_fresh_server_gets_one_invite_and_each_start_replaces_it() {
    let mut server = TestServer::start("first-invite-fresh").await;
    let now = server.clock.now();

    let (first, expires) = first_start_invite(&server.app.db, now)
        .await
        .unwrap()
        .expect("a server without accounts makes an invite");
    assert_eq!(expires, now + u64::from(FIRST_INVITE_DAYS) * DAY_MS);
    assert_eq!(unused_invites(&server).await, 1);

    // The next start retires the unused link it printed before.
    let (second, _) = first_start_invite(&server.app.db, now)
        .await
        .unwrap()
        .expect("still no account");
    assert_ne!(first.expose(), second.expose());
    assert_eq!(unused_invites(&server).await, 1);

    // The newest link creates the account; the older one no longer works.
    let device = Device::new();
    let account = Account::create_with_invite(&server, &device, first).await;
    assert!(
        account.is_err(),
        "a replaced first-start invite must not work"
    );
    assert!(
        Account::create_with_invite(&server, &device, second)
            .await
            .is_ok(),
        "the newest first-start invite creates the account"
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn a_server_with_an_account_prints_no_invite_and_keeps_operator_invites() {
    let mut server = TestServer::start("first-invite-account").await;
    let now = server.clock.now();
    let printed = first_start_invite(&server.app.db, now).await.unwrap();
    assert!(printed.is_some());

    let device = Device::new();
    Account::create(&server, &device, &[]).await;
    // An invite the operator made with the CLI stays valid.
    let _operator = server.invite().await;
    let before = unused_invites(&server).await;

    assert!(first_start_invite(&server.app.db, now)
        .await
        .unwrap()
        .is_none());
    // The unused first-start invite is retired, the operator's is not, and the marker is gone.
    assert_eq!(unused_invites(&server).await, before - 1);
    let marker: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM server_meta WHERE key = 'first_start_invite'")
            .fetch_optional(&server.app.db)
            .await
            .unwrap();
    assert!(marker.is_none(), "the first-start marker is removed");
    assert!(first_start_invite(&server.app.db, now)
        .await
        .unwrap()
        .is_none());
    assert_eq!(unused_invites(&server).await, before - 1);
    server.stop().await.unwrap();
}
