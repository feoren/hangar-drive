//! The HTTP client against local servers on 127.0.0.1: the SPKI pin inside the TLS handshake
//! (nothing is sent to a server with another key), sign-in and token renewal, retries and the
//! closed list of error codes.
//!
//! The two certificates and keys below are throwaway self-signed P-256 test certificates
//! (CN=localhost, 127.0.0.1) made only for this test; they protect nothing.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hangar_drive_protocol::api::{ErrorCode, LogPage};
use hangar_drive_protocol::ids::{AccountId, Blob, DeviceId, FolderId, Signature};
use hangar_drive_sync::http::{
    HttpServer, PinVerifier, RetryPolicy, ServerConfig, SessionIdentity,
};
use hangar_drive_sync::ports::{NetError, ServerApi};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const CA: &str = "3082019c30820141a003020102021479d702a5e2b79a02374f0f8c60f089938ba5e344300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f73743020170d3236313132363036333433345a180f32313236313130323036333433345a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004cd761b63398e4aeb59c2afedc7033a71f5198e1f1dd24face4bd180bef43372281e323ff6f156babb07054a5324d476690bd287fbbdcd7dddbf383d6a045f36ea36f306d301d0603551d0e0416041451ada22fd80f8856196462487c5b3d6c236ed462301f0603551d2304183016801451ada22fd80f8856196462487c5b3d6c236ed462300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300a06082a8648ce3d0403020349003046022100e74d9cab16fdafc06104260d7ee4ce9e3a4580d37b8b9eb3ba765d742174a21f022100dfebc8e15db95a1b2a326eb275ce00cfb307fad19146083d1ab1a9e69bf78ed3";
const KA: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420de4b5c4deeeb187b2519390b606d3136b874a6d361309fb7e35640c8bc584ac1a14403420004cd761b63398e4aeb59c2afedc7033a71f5198e1f1dd24face4bd180bef43372281e323ff6f156babb07054a5324d476690bd287fbbdcd7dddbf383d6a045f36e";
const CB: &str = "3082019b30820141a003020102021475f5c44624329d986f046019ba55c9d89991e7bd300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f73743020170d3236313132363036333433345a180f32313236313130323036333433345a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004239ea446f926b9bd169530aae6c122d37d08f487a3f8c2d1af0473991407394490edc3adcf1b0315cb4355f90ef248d104134dca3d8db4842e17961d7224f333a36f306d301d0603551d0e04160414abf4af524dccee26f5f8f6c0aad1f23ac6280f0f301f0603551d23041830168014abf4af524dccee26f5f8f6c0aad1f23ac6280f0f300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300a06082a8648ce3d0403020348003045022003d22c2a4acb573281bde227b65dc452074199d9c2dc8a2d28cee6fb1c457293022100a25b6d7e74caec453e31d94a05e9d4f3ac3a6e43f2e5de6ff985fac327d7c8b4";
const KB: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420a2ff02833d11bf0e8f085049083b6cc7b64b40fcf2f55c79ddf8bc5ddcb8a4eba14403420004239ea446f926b9bd169530aae6c122d37d08f487a3f8c2d1af0473991407394490edc3adcf1b0315cb4355f90ef248d104134dca3d8db4842e17961d7224f333";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn pin(cert: &str) -> [u8; 32] {
    PinVerifier::pin_of(&CertificateDer::from(hex(cert))).unwrap()
}

/// Reads one HTTP/1.1 request (head and a body of Content-Length bytes).
fn read_request(stream: &mut dyn Read) -> Option<String> {
    let mut reader = BufReader::new(stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return if head.is_empty() { None } else { Some(head) };
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let len = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).ok()?;
    Some(head + &String::from_utf8_lossy(&body))
}

fn respond(stream: &mut dyn Write, status: &str, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}

const HEALTH: &str = r#"{"version":"0.1.0","protocol_version":1}"#;

/// A TLS server with this certificate that answers the health check; records every request.
fn tls_server(cert: &str, key: &str) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(hex(cert))],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(hex(key))),
    )
    .unwrap();
    let config = Arc::new(config);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(mut tcp) = tcp else { continue };
            let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                continue;
            };
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            if let Some(request) = read_request(&mut tls) {
                log.lock().unwrap().push(request);
                respond(&mut tls, "200 OK", HEALTH);
            }
        }
    });
    (port, seen)
}

fn one_attempt(mut config: ServerConfig) -> ServerConfig {
    config.retry = RetryPolicy {
        attempts: 1,
        ..RetryPolicy::default()
    };
    config
}

#[test]
fn a_matching_pin_connects() {
    let (port, seen) = tls_server(CA, KA);
    let config = ServerConfig::new(&format!("https://127.0.0.1:{port}"), Some(pin(CA))).unwrap();
    let mut server = HttpServer::new(config, None).unwrap();
    let info = server.check_health().unwrap();
    assert_eq!(info.protocol_version, 1);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn another_key_aborts_in_the_handshake_before_anything_is_sent() {
    let (port, seen) = tls_server(CB, KB);
    let config = one_attempt(
        ServerConfig::new(&format!("https://127.0.0.1:{port}"), Some(pin(CA))).unwrap(),
    );
    let identity = SessionIdentity {
        account: AccountId::from_bytes([1; 16]),
        device: DeviceId::from_bytes([2; 16]),
        prover: Box::new(|_, _, _, _, _| Signature::from_bytes([0; 64])),
    };
    let mut server = HttpServer::new(config, Some(identity)).unwrap();
    assert_eq!(server.check_health().unwrap_err(), NetError::PinMismatch);
    // An authenticated call: still nothing reaches the server, no challenge, no token.
    assert_eq!(server.feed(0).unwrap_err(), NetError::PinMismatch);
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        seen.lock().unwrap().is_empty(),
        "{:?}",
        seen.lock().unwrap()
    );
}

#[test]
fn without_a_pin_a_self_signed_server_is_refused() {
    let (port, seen) = tls_server(CA, KA);
    let config =
        one_attempt(ServerConfig::new(&format!("https://127.0.0.1:{port}"), None).unwrap());
    let mut server = HttpServer::new(config, None).unwrap();
    assert!(matches!(
        server.check_health().unwrap_err(),
        NetError::Tls(_) | NetError::Unreachable
    ));
    assert!(seen.lock().unwrap().is_empty());
}

type Script = Vec<(&'static str, &'static str)>;

/// A plain HTTP server on 127.0.0.1 that answers from a script, one answer per request.
fn script_server(answers: Script) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut answers = answers.into_iter();
        for tcp in listener.incoming() {
            let Ok(mut tcp): Result<TcpStream, _> = tcp else {
                continue;
            };
            if let Some(request) = read_request(&mut tcp) {
                log.lock().unwrap().push(request);
                let (status, body) = answers.next().unwrap_or(("500 Internal Server Error", ""));
                respond(&mut tcp, status, body);
            }
        }
    });
    (port, seen)
}

#[test]
fn sign_in_renewal_retries_and_error_codes() {
    let challenge = r#"{"server":"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e","challenge":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","expires_in_secs":60}"#;
    let session =
        r#"{"token":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","expires_in_secs":3600}"#;
    let feed = r#"{"entries":[],"sequence":4,"more":false}"#;
    let (port, seen) = script_server(vec![
        ("200 OK", challenge),
        ("200 OK", session),
        ("503 Service Unavailable", ""),
        ("200 OK", feed),
        ("401 Unauthorized", r#"{"code":"unauthorized"}"#),
        ("200 OK", challenge),
        ("200 OK", session),
        ("200 OK", feed),
        (
            "409 Conflict",
            r#"{"code":"head_moved","current_head":"0101010101010101010101010101010101010101010101010101010101010101"}"#,
        ),
    ]);
    let mut config = ServerConfig::new(&format!("http://127.0.0.1:{port}"), None).unwrap();
    config.retry = RetryPolicy {
        attempts: 3,
        base: Duration::from_millis(10),
        max: Duration::from_millis(50),
    };
    let identity = SessionIdentity {
        account: AccountId::from_bytes([1; 16]),
        device: DeviceId::from_bytes([2; 16]),
        prover: Box::new(|_, _, _, _, _| Signature::from_bytes([3; 64])),
    };
    let mut server = HttpServer::new(config, Some(identity)).unwrap();
    // Sign-in, then a 503 retried.
    assert_eq!(server.feed(0).unwrap().sequence, 4);
    // A 401 signs in again and repeats the request.
    assert_eq!(server.feed(4).unwrap().sequence, 4);
    let err = server
        .commits(&FolderId::from_bytes([5; 16]), 0)
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::HeadMoved));
    let requests = seen.lock().unwrap();
    assert!(requests[0].starts_with("POST /api/v1/session/challenge"));
    assert!(requests[3].starts_with("GET /api/v1/account/feed?after=0"));
    // The token travels only in the header, never in a path or query.
    let token = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    for r in requests.iter() {
        assert!(!r.lines().next().unwrap().contains(token));
    }
    assert!(
        requests[3].contains(&format!("Bearer {token}"))
            || requests[3].contains(&format!("bearer {token}"))
    );
}

/// A plain HTTP event server: answers sign-in, then the first event stream stays silent after
/// its head and the second one sends one event.
fn silent_then_event_server() -> (u16, Arc<Mutex<Vec<String>>>) {
    let challenge = r#"{"server":"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e","challenge":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","expires_in_secs":60}"#;
    let session =
        r#"{"token":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","expires_in_secs":3600}"#;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut streams = 0;
        let mut held = Vec::new();
        for tcp in listener.incoming() {
            let Ok(mut tcp): Result<TcpStream, _> = tcp else {
                continue;
            };
            let Some(request) = read_request(&mut tcp) else {
                continue;
            };
            log.lock().unwrap().push(request.clone());
            if request.starts_with("POST /api/v1/session/challenge") {
                respond(&mut tcp, "200 OK", challenge);
            } else if request.starts_with("POST /api/v1/session/proof") {
                respond(&mut tcp, "200 OK", session);
            } else {
                streams += 1;
                let _ = write!(
                    tcp,
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"
                );
                if streams > 1 {
                    let _ = write!(tcp, "data: {{\"sequence\":7}}\n\n");
                }
                let _ = tcp.flush();
                // Keep the connection open and silent.
                held.push(tcp);
            }
        }
    });
    (port, seen)
}

#[test]
fn a_silent_event_stream_times_out_and_is_opened_again() {
    let (port, seen) = silent_then_event_server();
    let mut config = ServerConfig::new(&format!("http://127.0.0.1:{port}"), None).unwrap();
    config.event_read_timeout = Duration::from_millis(300);
    config.retry = RetryPolicy {
        attempts: 1,
        base: Duration::from_millis(10),
        max: Duration::from_millis(20),
    };
    let identity = SessionIdentity {
        account: AccountId::from_bytes([1; 16]),
        device: DeviceId::from_bytes([2; 16]),
        prover: Box::new(|_, _, _, _, _| Signature::from_bytes([3; 64])),
    };
    let mut server = HttpServer::new(config, Some(identity)).unwrap();
    let started = std::time::Instant::now();
    let mut got = Vec::new();
    let mut rounds = 0;
    server
        .follow_events(
            |s| {
                got.push(s);
                false
            },
            || {
                rounds += 1;
                rounds < 5
            },
        )
        .unwrap();
    assert_eq!(got, vec![7], "the second stream delivered its event");
    assert!(started.elapsed() < Duration::from_secs(10));
    let streams = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.starts_with("GET /api/v1/account/events"))
        .count();
    assert_eq!(
        streams, 2,
        "the silent stream was given up and opened again"
    );
}

#[test]
fn a_used_challenge_starts_the_sign_in_once_more() {
    let challenge = r#"{"server":"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e","challenge":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","expires_in_secs":60}"#;
    let session =
        r#"{"token":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","expires_in_secs":3600}"#;
    let feed = r#"{"entries":[],"sequence":2,"more":false}"#;
    let (port, seen) = script_server(vec![
        ("200 OK", challenge),
        ("401 Unauthorized", r#"{"code":"challenge_invalid"}"#),
        ("200 OK", challenge),
        ("200 OK", session),
        ("200 OK", feed),
    ]);
    let config = one_attempt(ServerConfig::new(&format!("http://127.0.0.1:{port}"), None).unwrap());
    let identity = SessionIdentity {
        account: AccountId::from_bytes([1; 16]),
        device: DeviceId::from_bytes([2; 16]),
        prover: Box::new(|_, _, _, _, _| Signature::from_bytes([3; 64])),
    };
    let mut server = HttpServer::new(config, Some(identity)).unwrap();
    assert_eq!(server.feed(0).unwrap().sequence, 2);
    let requests = seen.lock().unwrap();
    let challenges = requests
        .iter()
        .filter(|r| r.starts_with("POST /api/v1/session/challenge"))
        .count();
    assert_eq!(challenges, 2);
}

/// Security review H2: `device_removed` means "removed" only as the answer to this device's own
/// proof; on any other route (here the feed, with a token) it is a protocol error, so a server
/// cannot make the device forget its account with the code on an arbitrary call.
#[test]
fn device_removed_counts_only_as_the_answer_to_the_proof() {
    let challenge = r#"{"server":"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e","challenge":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","expires_in_secs":60}"#;
    let session =
        r#"{"token":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","expires_in_secs":3600}"#;
    let removed = r#"{"code":"device_removed"}"#;
    let identity = || SessionIdentity {
        account: AccountId::from_bytes([1; 16]),
        device: DeviceId::from_bytes([2; 16]),
        prover: Box::new(|_, _, _, _, _| Signature::from_bytes([3; 64])),
    };
    let (port, _) = script_server(vec![("200 OK", challenge), ("403 Forbidden", removed)]);
    let config = one_attempt(ServerConfig::new(&format!("http://127.0.0.1:{port}"), None).unwrap());
    let mut server = HttpServer::new(config, Some(identity())).unwrap();
    assert_eq!(server.feed(0).unwrap_err(), NetError::DeviceRemoved(None));

    // The proof names the log length this device verified, and the log the server sends with
    // the answer reaches the engine as it is (checked there against the own head).
    let removed_with_log =
        r#"{"code":"device_removed","removal_log":{"first_index":8,"entries":["AQI"],"length":9}}"#;
    let (port, seen) = script_server(vec![
        ("200 OK", challenge),
        ("403 Forbidden", removed_with_log),
    ]);
    let config = one_attempt(ServerConfig::new(&format!("http://127.0.0.1:{port}"), None).unwrap());
    let mut server = HttpServer::new(config, Some(identity())).unwrap();
    server.set_known_log_length(7);
    assert_eq!(
        server.feed(0).unwrap_err(),
        NetError::DeviceRemoved(Some(LogPage {
            first_index: 8,
            entries: vec![Blob(vec![1, 2])],
            length: 9,
        }))
    );
    let requests = seen.lock().unwrap();
    let proof = requests
        .iter()
        .find(|r| r.starts_with("POST /api/v1/session/proof"))
        .expect("a proof");
    assert!(proof.contains(r#""log_length":7"#), "{proof}");
    drop(requests);

    let (port, _) = script_server(vec![
        ("200 OK", challenge),
        ("200 OK", session),
        ("403 Forbidden", removed),
    ]);
    let config = one_attempt(ServerConfig::new(&format!("http://127.0.0.1:{port}"), None).unwrap());
    let mut server = HttpServer::new(config, Some(identity())).unwrap();
    let error = server.feed(0).unwrap_err();
    assert!(matches!(error, NetError::Protocol(_)), "{error:?}");
}

/// Security review, info: the pin mismatch flag counts only for the handshake that set it. A
/// later failure that is no TLS failure (here a server that stops answering) is "unreachable",
/// not another "the server identifies itself differently".
#[test]
fn a_later_timeout_is_not_reported_as_a_pin_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(hex(CB))],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(hex(KB))),
        )
        .unwrap(),
    );
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for (n, tcp) in listener.incoming().enumerate() {
            let Ok(mut tcp) = tcp else { continue };
            if n == 0 {
                // The first connection presents key B.
                let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                    continue;
                };
                let _ = conn.complete_io(&mut tcp);
            } else {
                // Later ones are accepted and never answered.
                held.push(tcp);
            }
        }
    });
    let mut config = one_attempt(
        ServerConfig::new(&format!("https://127.0.0.1:{port}"), Some(pin(CA))).unwrap(),
    );
    config.timeout = Duration::from_millis(500);
    let mut server = HttpServer::new(config, None).unwrap();
    assert_eq!(server.check_health().unwrap_err(), NetError::PinMismatch);
    assert_eq!(server.check_health().unwrap_err(), NetError::Unreachable);
}
