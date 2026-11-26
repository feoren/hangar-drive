//! The server on a real socket: health, error replies for unknown routes, the container self
//! check, slow and idle connections, and the graceful shutdown with an open SSE stream.

mod common;

use std::time::Duration;

use common::*;
use hangar_drive_protocol::api::{ErrorCode, EVENTS_PATH};
use hangar_drive_protocol::{ServerInfo, HEALTH_PATH, PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn health_reports_version_and_protocol() {
    let mut server = TestServer::start("health").await;
    let reply = Client::new(server.addr).get(HEALTH_PATH).await;
    assert_eq!(reply.status, 200);
    let info: ServerInfo = reply.json();
    assert_eq!(info.protocol_version, PROTOCOL_VERSION);
    assert_eq!(info, ServerInfo::new(hangar_drive_server::VERSION));
    assert_eq!(
        reply.header("x-content-type-options").as_deref(),
        Some("nosniff")
    );
    assert_eq!(reply.header("cache-control").as_deref(), Some("no-store"));
    server.stop().await.unwrap();
}

/// `HANGAR_DRIVE_PUBLIC_URL` is required: every sign-in is bound to it (ADR 0001, section 6).
#[tokio::test]
async fn the_server_does_not_start_without_its_public_url() {
    let dir = data_dir("no-public-url");
    let config = hangar_drive_server::config::Config::from_lookup(|name| {
        (name == "HANGAR_DRIVE_DATA_DIR").then(|| dir.clone().into_os_string())
    })
    .unwrap();
    assert_eq!(config.public_url, None);
    let deps = hangar_drive_server::Deps {
        gc_job: false,
        ..hangar_drive_server::Deps::default()
    };
    match hangar_drive_server::build(&config, deps).await {
        Err(error @ hangar_drive_server::StartError::PublicUrlMissing) => {
            let text = error.to_string();
            assert!(
                text.contains("HANGAR_DRIVE_PUBLIC_URL=https://drive.example.org/"),
                "the message says how to set it: {text}"
            );
        }
        Err(other) => panic!("another error: {other}"),
        Ok(_) => panic!("the server started without its public URL"),
    }
}

#[tokio::test]
async fn unknown_paths_and_methods_answer_with_error_codes() {
    let mut server = TestServer::start("unknown").await;
    let client = Client::new(server.addr);
    let reply = client.get("/").await;
    assert_eq!((reply.status, reply.code()), (404, ErrorCode::NotFound));
    let reply = client.get("/api/v1/nothing").await;
    assert_eq!((reply.status, reply.code()), (404, ErrorCode::NotFound));
    let reply = client.post(HEALTH_PATH, &serde_json::json!({})).await;
    assert_eq!(reply.status, 405);
    assert_eq!(reply.code(), ErrorCode::BadRequest);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn the_container_self_check_sees_a_running_server_only() {
    let mut server = TestServer::start("probe").await;
    let addr = server.addr;
    let timeout = Duration::from_secs(3);
    let up =
        tokio::task::spawn_blocking(move || hangar_drive_server::probe::health_ok(addr, timeout))
            .await
            .unwrap();
    assert!(up.unwrap());
    server.stop().await.unwrap();
    let down =
        tokio::task::spawn_blocking(move || hangar_drive_server::probe::health_ok(addr, timeout))
            .await
            .unwrap();
    assert!(!matches!(down, Ok(true)));
}

#[tokio::test]
async fn slow_headers_and_idle_connections_are_closed() {
    let mut server = TestServer::with(
        "slow",
        Options {
            header_timeout: Some(Duration::from_millis(500)),
            ..Options::default()
        },
    )
    .await;
    // Half a request line, then nothing (slowloris).
    let mut slow = TcpStream::connect(server.addr).await.unwrap();
    slow.write_all(b"GET /api/v1/hea").await.unwrap();
    let mut buffer = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(5), slow.read_to_end(&mut buffer)).await;
    assert!(closed.is_ok(), "the server kept a slow connection open");
    // A connection that never sends anything.
    let mut idle = TcpStream::connect(server.addr).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), idle.read_to_end(&mut buffer)).await;
    assert!(closed.is_ok(), "the server kept an idle connection open");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn shutdown_ends_open_event_streams_within_the_grace_period() {
    let mut server = TestServer::start("shutdown").await;
    let device = Device::new();
    let account = Account::create(&server, &device, &[]).await;
    let client = account.sign_in(&server, &device).await;
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    let head = format!(
        "GET {EVENTS_PATH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
        client.token.as_ref().unwrap()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut first = vec![0u8; 512];
    let n = stream.read(&mut first).await.unwrap();
    assert!(String::from_utf8_lossy(&first[..n]).contains("200 OK"));
    let started = std::time::Instant::now();
    server.stop().await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the stream held the shutdown"
    );
    assert!(TcpStream::connect(server.addr).await.is_err());
}

#[tokio::test]
async fn the_join_page_is_static_with_its_own_strict_policy() {
    let mut server = TestServer::start("join").await;
    let client = Client::new(server.addr);
    let csp = "default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; \
               form-action 'none'; frame-ancestors 'none'";
    for (path, kind) in [
        ("/join", "text/html"),
        ("/join.js", "text/javascript"),
        ("/join.css", "text/css"),
    ] {
        let reply = client.get(path).await;
        assert_eq!(reply.status, 200, "{path}");
        assert!(
            reply
                .header("content-type")
                .is_some_and(|t| t.starts_with(kind)),
            "{path}"
        );
        assert_eq!(
            reply.header("content-security-policy").as_deref(),
            Some(csp)
        );
        assert_eq!(reply.header("cache-control").as_deref(), Some("no-store"));
        assert_eq!(
            reply.header("referrer-policy").as_deref(),
            Some("no-referrer")
        );
    }
    let page = String::from_utf8(client.get("/join").await.body).unwrap();
    assert!(page.contains("<script src=\"join.js\" defer></script>"));
    assert!(!page.contains("<script>"), "no inline script");
    assert!(page.contains("hangar-drive://join"));
    // The API keeps its own policy.
    let reply = client.get(HEALTH_PATH).await;
    assert_eq!(
        reply.header("content-security-policy").as_deref(),
        Some("default-src 'none'; frame-ancestors 'none'")
    );
    server.stop().await.unwrap();
}
