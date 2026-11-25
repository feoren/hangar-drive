//! The server on a real socket: the health reply, unknown routes, the self check of the container
//! image and the graceful shutdown.

use std::net::SocketAddr;
use std::time::Duration;

use hangar_drive_protocol::{ServerInfo, HEALTH_PATH, PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

struct Running {
    addr: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

async fn start() -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(hangar_drive_server::serve(listener, async {
        let _ = stopped.await;
    }));
    Running { addr, stop, task }
}

/// One HTTP/1.1 request; returns the status code and the body.
async fn request(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();
    let (head, body) = reply.split_once("\r\n\r\n").unwrap();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap();
    (status, body.to_owned())
}

#[tokio::test]
async fn health_reports_version_and_protocol() {
    let server = start().await;
    let (status, body) = request(server.addr, "GET", HEALTH_PATH).await;
    assert_eq!(status, 200);
    let info: ServerInfo = serde_json::from_str(&body).unwrap();
    assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.protocol_version, PROTOCOL_VERSION);
    assert_eq!(info, ServerInfo::new(hangar_drive_server::VERSION));
}

#[tokio::test]
async fn unknown_paths_and_methods_are_refused() {
    let server = start().await;
    assert_eq!(request(server.addr, "GET", "/").await.0, 404);
    assert_eq!(request(server.addr, "GET", "/api/v1/nothing").await.0, 404);
    assert_eq!(request(server.addr, "POST", HEALTH_PATH).await.0, 405);
}

#[tokio::test]
async fn the_container_self_check_sees_a_running_server_only() {
    let server = start().await;
    let addr = server.addr;
    let timeout = Duration::from_secs(3);
    let up =
        tokio::task::spawn_blocking(move || hangar_drive_server::probe::health_ok(addr, timeout))
            .await
            .unwrap();
    assert!(up.unwrap());

    server.stop.send(()).unwrap();
    server.task.await.unwrap().unwrap();
    let down =
        tokio::task::spawn_blocking(move || hangar_drive_server::probe::health_ok(addr, timeout))
            .await
            .unwrap();
    assert!(!matches!(down, Ok(true)));
}

#[tokio::test]
async fn stops_when_the_shutdown_future_completes() {
    let server = start().await;
    assert_eq!(request(server.addr, "GET", HEALTH_PATH).await.0, 200);
    server.stop.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), server.task)
        .await
        .expect("the server did not stop within 5 s");
    result.unwrap().unwrap();
    assert!(TcpStream::connect(server.addr).await.is_err());
}
