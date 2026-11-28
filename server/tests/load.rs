//! Load test against a running server, for example the image in Docker (throughput review of
//! the server image). Ignored in the check suite: it needs a server started for it and takes a
//! while. Each run needs a fresh server, since it creates the account with the first-start
//! invite the server prints to its log while no account exists.
//!
//! ```sh
//! docker run -d --name drive-load -p 127.0.0.1:18080:8080 --read-only --cap-drop ALL \
//!   -e HANGAR_DRIVE_PUBLIC_URL=http://localhost:18080/ \
//!   -e HANGAR_DRIVE_UPLOADS_PER_MINUTE=12000 hangar-drive-server
//! docker logs drive-load 2>&1 | grep -o 'join#[^.]*'      # the invite, after "join#"
//! HANGAR_DRIVE_LOAD_ADDR=127.0.0.1:18080 HANGAR_DRIVE_LOAD_URL=http://localhost:18080/ \
//!   HANGAR_DRIVE_LOAD_INVITE=<invite> \
//!   cargo test -p hangar-drive-server --test load -- --ignored --nocapture
//! ```
//!
//! Optional: `HANGAR_DRIVE_LOAD_SMALL` (small objects, default 2000), `HANGAR_DRIVE_LOAD_LARGE`
//! (4 MiB objects, default 32), `HANGAR_DRIVE_LOAD_PARALLEL` (connections, default 4, as the
//! app uses). Every request runs on a kept-alive connection, as the app's client does.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use hangar_drive_crypto::devicelog::{AccountState, EntryKind};
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::{ObjectType, CHUNK_SIZE};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn number(name: &str, default: usize) -> usize {
    var(name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// One HTTP/1.1 connection that stays open across requests.
struct KeepAlive {
    addr: SocketAddr,
    token: String,
    stream: Option<BufReader<TcpStream>>,
}

struct Answer {
    status: u16,
    retry_after: Option<u64>,
    body: Vec<u8>,
}

impl KeepAlive {
    fn new(addr: SocketAddr, token: &str) -> Self {
        Self {
            addr,
            token: token.to_owned(),
            stream: None,
        }
    }

    /// One request; a connection the server closed while idle (its keep-alive timeout) is
    /// opened again once, as HTTP clients do.
    async fn request(&mut self, method: &str, path: &str, kind: &str, body: &[u8]) -> Answer {
        if let Some(answer) = self.try_request(method, path, kind, body).await {
            return answer;
        }
        self.stream = None;
        self.try_request(method, path, kind, body)
            .await
            .expect("the server closed a fresh connection")
    }

    async fn try_request(
        &mut self,
        method: &str,
        path: &str,
        kind: &str,
        body: &[u8],
    ) -> Option<Answer> {
        if self.stream.is_none() {
            let stream = TcpStream::connect(self.addr).await.unwrap();
            stream.set_nodelay(true).unwrap();
            self.stream = Some(BufReader::new(stream));
        }
        let stream = self.stream.as_mut().unwrap();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\
             Content-Type: {kind}\r\nContent-Length: {}\r\n\r\n",
            self.token,
            body.len()
        );
        if stream.get_mut().write_all(head.as_bytes()).await.is_err()
            || stream.get_mut().write_all(body).await.is_err()
        {
            return None;
        }
        let mut status = 0;
        let mut length = 0usize;
        let mut chunked = false;
        let mut close = false;
        let mut retry_after = None;
        loop {
            let mut line = String::new();
            let read = stream.read_line(&mut line).await.unwrap_or(0);
            if read == 0 && status == 0 {
                return None;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if status == 0 {
                status = line.split_whitespace().nth(1).unwrap().parse().unwrap();
                continue;
            }
            let (name, value) = line.split_once(':').unwrap();
            let (name, value) = (name.to_ascii_lowercase(), value.trim());
            match name.as_str() {
                "content-length" => length = value.parse().unwrap(),
                "transfer-encoding" => chunked = value.eq_ignore_ascii_case("chunked"),
                "connection" => close = value.eq_ignore_ascii_case("close"),
                "retry-after" => retry_after = value.parse().ok(),
                _ => {}
            }
        }
        let mut body = Vec::new();
        if chunked {
            loop {
                let mut size = String::new();
                stream.read_line(&mut size).await.unwrap();
                let size = usize::from_str_radix(size.trim(), 16).unwrap();
                let mut chunk = vec![0u8; size + 2];
                stream.read_exact(&mut chunk).await.unwrap();
                if size == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..size]);
            }
        } else {
            body.resize(length, 0);
            stream.read_exact(&mut body).await.unwrap();
        }
        if close {
            self.stream = None;
        }
        Some(Answer {
            status,
            retry_after,
            body,
        })
    }
}

/// Latencies of one phase.
struct Phase {
    name: &'static str,
    started: Instant,
    times: Vec<Duration>,
    bytes: u64,
    retries: usize,
}

impl Phase {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            started: Instant::now(),
            times: Vec::new(),
            bytes: 0,
            retries: 0,
        }
    }

    fn report(mut self) {
        let wall = self.started.elapsed();
        self.times.sort();
        let at = |q: f64| {
            let i = ((self.times.len() as f64 - 1.0) * q).round() as usize;
            self.times.get(i).copied().unwrap_or_default().as_secs_f64() * 1000.0
        };
        println!(
            "{:<14} n={:<5} wall={:>7.2}s  {:>8.1}/s  {:>7.1} MiB/s  p50={:>7.1}ms p95={:>7.1}ms max={:>7.1}ms  retries(429)={}",
            self.name,
            self.times.len(),
            wall.as_secs_f64(),
            self.times.len() as f64 / wall.as_secs_f64(),
            self.bytes as f64 / (1u64 << 20) as f64 / wall.as_secs_f64(),
            at(0.5),
            at(0.95),
            at(1.0),
            self.retries
        );
    }
}

/// Uploads `objects` over `parallel` connections; waits out every 429 as the app does.
async fn upload_all(
    name: &'static str,
    addr: SocketAddr,
    token: &str,
    folder: FolderId,
    objects: Arc<Vec<Obj>>,
    parallel: usize,
) {
    let mut phase = Phase::new(name);
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..parallel {
        let (objects, next, token) = (objects.clone(), next.clone(), token.to_owned());
        workers.push(tokio::spawn(async move {
            let mut conn = KeepAlive::new(addr, &token);
            let (mut times, mut retries) = (Vec::new(), 0);
            loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(obj) = objects.get(i) else { break };
                loop {
                    let t = Instant::now();
                    let answer = conn
                        .request(
                            "PUT",
                            &object_path(&folder, &obj.id),
                            "application/octet-stream",
                            &obj.blob,
                        )
                        .await;
                    if answer.status == 429 {
                        retries += 1;
                        let wait = answer.retry_after.unwrap_or(1);
                        tokio::time::sleep(Duration::from_secs(wait)).await;
                        continue;
                    }
                    assert_eq!(
                        answer.status,
                        201,
                        "{}",
                        String::from_utf8_lossy(&answer.body)
                    );
                    times.push(t.elapsed());
                    break;
                }
            }
            (times, retries)
        }));
    }
    for worker in workers {
        let (times, retries) = worker.await.unwrap();
        phase.times.extend(times);
        phase.retries += retries;
    }
    phase.bytes = objects.iter().map(|o| o.size()).sum();
    phase.report();
}

async fn download_all(
    addr: SocketAddr,
    token: &str,
    folder: FolderId,
    objects: Arc<Vec<Obj>>,
    parallel: usize,
) {
    let mut phase = Phase::new("download 4MiB");
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..parallel {
        let (objects, next, token) = (objects.clone(), next.clone(), token.to_owned());
        workers.push(tokio::spawn(async move {
            let mut conn = KeepAlive::new(addr, &token);
            let mut times = Vec::new();
            loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(obj) = objects.get(i) else { break };
                let t = Instant::now();
                let answer = conn
                    .request("GET", &object_path(&folder, &obj.id), "text/plain", b"")
                    .await;
                assert_eq!(answer.status, 200);
                assert_eq!(answer.body, obj.blob);
                times.push(t.elapsed());
            }
            times
        }));
    }
    for worker in workers {
        phase.times.extend(worker.await.unwrap());
    }
    phase.bytes = objects.iter().map(|o| o.size()).sum();
    phase.report();
}

async fn create_account(addr: SocketAddr, invite: &str, device: &Device) -> Account {
    let invite: InviteToken = serde_json::from_value(serde_json::json!(invite)).unwrap();
    let id = AccountId::from_bytes(random());
    let mut state = AccountState::new(id);
    let genesis = state
        .next_entry(
            &device.identity,
            device.id,
            START_MS,
            EntryKind::Create {
                devices: vec![device.log_device(&id)],
            },
        )
        .unwrap();
    let reply = Client::new(addr)
        .post(
            ACCOUNTS_PATH,
            &CreateAccountRequest {
                invite,
                account: id,
                genesis: Blob(genesis.clone()),
            },
        )
        .await;
    assert_eq!(
        reply.status,
        201,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let created: CreateAccountResponse = reply.json();
    state.apply(&genesis).unwrap();
    Account {
        id,
        state,
        secret: None,
        server: Some(created.server),
    }
}

async fn sign_in(addr: SocketAddr, url: &str, account: &Account, device: &Device) -> String {
    let client = Client::new(addr);
    let reply = client
        .post(
            CHALLENGE_PATH,
            &ChallengeRequest {
                account: account.id,
                device: device.id,
            },
        )
        .await;
    assert_eq!(reply.status, 200);
    let challenge: ChallengeResponse = reply.json();
    let signature = device.identity.prove_session(
        &challenge.server,
        url,
        &account.id,
        &device.id,
        &challenge.challenge,
    );
    let reply = client
        .post(
            PROOF_PATH,
            &ProofRequest {
                account: account.id,
                device: device.id,
                challenge: challenge.challenge,
                server_url: url.into(),
                signature,
                log_length: None,
            },
        )
        .await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let session: SessionResponse = reply.json();
    session.token.expose_base64url().to_string()
}

/// Opens the event stream and sends the moment each event line arrives.
async fn listen(addr: SocketAddr, token: &str) -> tokio::sync::mpsc::Receiver<Instant> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "GET {EVENTS_PATH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\
         Accept: text/event-stream\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            if line.contains("event:") || line.starts_with("data:") {
                let _ = tx.send(Instant::now()).await;
            }
        }
    });
    rx
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a running server: see the module docs"]
async fn load() {
    let (Some(addr), Some(url), Some(invite)) = (
        var("HANGAR_DRIVE_LOAD_ADDR"),
        var("HANGAR_DRIVE_LOAD_URL"),
        var("HANGAR_DRIVE_LOAD_INVITE"),
    ) else {
        panic!("set HANGAR_DRIVE_LOAD_ADDR, HANGAR_DRIVE_LOAD_URL and HANGAR_DRIVE_LOAD_INVITE");
    };
    let addr: SocketAddr = addr.parse().unwrap();
    let small = number("HANGAR_DRIVE_LOAD_SMALL", 2000);
    let large = number("HANGAR_DRIVE_LOAD_LARGE", 32);
    let parallel = number("HANGAR_DRIVE_LOAD_PARALLEL", 4);
    println!("load test: {small} small, {large} large objects, {parallel} connections");

    let mut device = Device::new();
    let account = create_account(addr, &invite, &device).await;
    let token = sign_in(addr, &url, &account, &device).await;
    let client = Client {
        addr,
        token: Some(token.clone()),
        extra: Vec::new(),
    };
    let mut events = listen(addr, &token).await;
    let mut folder = Folder::new();

    // Health on a kept-alive connection: the floor of every call.
    let mut phase = Phase::new("health");
    let mut conn = KeepAlive::new(addr, &token);
    for _ in 0..200 {
        let t = Instant::now();
        let answer = conn
            .request("GET", hangar_drive_protocol::HEALTH_PATH, "text/plain", b"")
            .await;
        assert_eq!(answer.status, 200);
        phase.times.push(t.elapsed());
    }
    phase.report();

    // Small objects: a chunk of a small file, about 2 KiB on the wire.
    let objects: Arc<Vec<Obj>> = Arc::new(
        (0..small)
            .map(|_| Obj::new(ObjectType::Chunk, 2000))
            .collect(),
    );
    upload_all(
        "put small",
        addr,
        &token,
        folder.id,
        objects.clone(),
        parallel,
    )
    .await;

    // The app asks for the missing objects of a commit before it uploads; here all are held.
    let mut phase = Phase::new("missing 4096");
    for ids in objects.chunks(MAX_MISSING_QUERY) {
        let request = MissingObjectsRequest {
            ids: ids.iter().map(|o| o.id).collect(),
        };
        let body = serde_json::to_vec(&request).unwrap();
        let t = Instant::now();
        let answer = conn
            .request(
                "POST",
                &missing_objects_path(&folder.id),
                "application/json",
                &body,
            )
            .await;
        assert_eq!(answer.status, 200);
        let reply: MissingObjectsResponse = serde_json::from_slice(&answer.body).unwrap();
        assert!(reply.missing.is_empty());
        phase.times.push(t.elapsed());
    }
    phase.report();

    while events.try_recv().is_ok() {}
    let mut phase = Phase::new("commit small");
    let refs: Vec<&Obj> = objects.iter().collect();
    let t = Instant::now();
    let reply = folder
        .commit(&client, &account, &mut device, &refs, &[])
        .await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    phase.times.push(t.elapsed());
    phase.report();
    match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
        Ok(Some(at)) => println!(
            "sse            event {:.1}ms after the commit call started",
            (at - t).as_secs_f64() * 1000.0
        ),
        _ => println!("sse            no event within 5 s"),
    }

    // Large objects: full chunks (4 MiB plaintext).
    let big: Arc<Vec<Obj>> = Arc::new(
        (0..large)
            .map(|_| Obj::new(ObjectType::Chunk, CHUNK_SIZE as usize))
            .collect(),
    );
    upload_all("put 4MiB", addr, &token, folder.id, big.clone(), parallel).await;
    let refs: Vec<&Obj> = big.iter().collect();
    let mut phase = Phase::new("commit large");
    let t = Instant::now();
    let reply = folder
        .commit(&client, &account, &mut device, &refs, &[])
        .await;
    assert_eq!(reply.status, 200);
    phase.times.push(t.elapsed());
    phase.report();
    download_all(addr, &token, folder.id, big, parallel).await;

    // The change feed as a device reads it after a sleep.
    let mut phase = Phase::new("feed page");
    for _ in 0..50 {
        let t = Instant::now();
        let answer = conn
            .request("GET", &format!("{FEED_PATH}?after=0"), "text/plain", b"")
            .await;
        assert_eq!(answer.status, 200);
        phase.times.push(t.elapsed());
    }
    phase.report();
}
