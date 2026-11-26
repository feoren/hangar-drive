//! Security review N5: plain HTTP is allowed only to the loopback address, and such a request
//! must never go through a proxy from the environment, which would see the session token in
//! the clear. A test binary of its own, because it sets the process's proxy variables.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use hangar_drive_sync::http::{HttpServer, RetryPolicy, ServerConfig};

/// A server that answers every request with `body` and records the request lines.
fn server(body: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(mut tcp) = tcp else { continue };
            let mut reader = BufReader::new(tcp.try_clone().unwrap());
            let mut first = String::new();
            let _ = reader.read_line(&mut first);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            log.lock().unwrap().push(first);
            let _ = write!(
                tcp,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (port, seen)
}

#[test]
fn a_loopback_server_is_never_reached_through_a_proxy() {
    let health = r#"{"version":"0.1.0","protocol_version":1}"#;
    let (proxy_port, proxy_seen) = server(health);
    let (port, seen) = server(health);
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    // This binary runs this one test, so no other thread reads the environment meanwhile.
    for name in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(name, &proxy);
    }
    for name in ["NO_PROXY", "no_proxy"] {
        std::env::remove_var(name);
    }
    let mut config = ServerConfig::new(&format!("http://127.0.0.1:{port}"), None).unwrap();
    config.retry = RetryPolicy {
        attempts: 1,
        ..RetryPolicy::default()
    };
    let mut client = HttpServer::new(config, None).unwrap();
    client.check_health().unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(
        proxy_seen.lock().unwrap().is_empty(),
        "{:?}",
        proxy_seen.lock().unwrap()
    );
}
