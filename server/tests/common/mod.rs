//! Helpers for the integration tests: a server on a real socket with a manual clock and a
//! fake disk, a minimal HTTP/1.1 client, and devices that build real signed log entries and
//! commits with the crypto crate. Test data lives under `tests/.tmp/` of the repository.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hangar_drive_crypto::commit::{ChainEntry, Commit, CommitContent, SignedCommit};
use hangar_drive_crypto::devicelog::{AccountState, EntryKind, LogDevice};
use hangar_drive_crypto::epoch::{self, AccountSecret};
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_crypto::object::blob_len;
use hangar_drive_crypto::{Entropy, OsEntropy};
use hangar_drive_protocol::api::*;
use hangar_drive_protocol::ids::*;
use hangar_drive_protocol::object::ObjectType;
use hangar_drive_server::app::AppState;
use hangar_drive_server::clock::ManualClock;
use hangar_drive_server::config::{Concurrency, Config, Limits};
use hangar_drive_server::disk::FixedDiskSpace;
use hangar_drive_server::http::ratelimit::RateLimiter;
use hangar_drive_server::{Deps, Server};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub const START_MS: u64 = 1_800_000_000_000;
pub const DAY_MS: u64 = 86_400_000;
/// The base URL the test devices sign their session proofs for.
pub const TEST_URL: &str = "https://drive.example/";

pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsEntropy.fill(&mut bytes).unwrap();
    bytes
}

/// A fresh data folder under the repository's `tests/.tmp/`.
pub fn data_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/.tmp/server-it")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The data folder of a test server, without clearing it.
pub fn data_dir_of(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/.tmp/server-it")
        .join(name)
}

pub struct Options {
    pub limits: Limits,
    pub limiter: RateLimiter,
    pub trusted: &'static str,
    pub header_timeout: Option<Duration>,
    pub tls: bool,
    pub concurrency: Concurrency,
    /// `HANGAR_DRIVE_PUBLIC_URL`, which `serve` needs; the test devices sign for [`TEST_URL`].
    pub public_url: &'static str,
    /// Wraps the object store (`Deps::store_layer`).
    pub store_layer: Option<hangar_drive_server::StoreLayer>,
}

impl Default for Options {
    fn default() -> Self {
        let mut limits = Limits::for_quota(1 << 30);
        limits.headroom = 1 << 20;
        Self {
            limits,
            limiter: RateLimiter::new(),
            trusted: "",
            header_timeout: None,
            tls: false,
            concurrency: Concurrency::default(),
            public_url: TEST_URL,
            store_layer: None,
        }
    }
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub app: AppState,
    pub clock: ManualClock,
    pub disk: Arc<FixedDiskSpace>,
    stop: Option<oneshot::Sender<()>>,
    pub task: Option<JoinHandle<std::io::Result<()>>>,
}

impl TestServer {
    pub async fn start(name: &str) -> Self {
        Self::with(name, Options::default()).await
    }

    pub async fn with(name: &str, options: Options) -> Self {
        let dir = data_dir(name);
        let mut vars: Vec<(&str, String)> =
            vec![("HANGAR_DRIVE_DATA_DIR", dir.display().to_string())];
        if !options.trusted.is_empty() {
            vars.push(("HANGAR_DRIVE_TRUSTED_PROXIES", options.trusted.to_owned()));
        }
        if options.tls {
            let testdata = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
            vars.push((
                "HANGAR_DRIVE_TLS_CERT",
                testdata.join("cert.pem").display().to_string(),
            ));
            vars.push((
                "HANGAR_DRIVE_TLS_KEY",
                testdata.join("key.pem").display().to_string(),
            ));
        }
        vars.push(("HANGAR_DRIVE_SHUTDOWN_GRACE_SECS", "3".into()));
        vars.push(("HANGAR_DRIVE_PUBLIC_URL", options.public_url.to_owned()));
        let mut config = Config::from_lookup(|name| {
            vars.iter().find(|(k, _)| *k == name).map(|(_, v)| v.into())
        })
        .unwrap();
        config.limits = options.limits;
        config.concurrency = options.concurrency;
        let clock = ManualClock::new(START_MS);
        let disk = Arc::new(FixedDiskSpace::new(u64::MAX / 2));
        let deps = Deps {
            clock: Arc::new(clock.clone()),
            disk: Some(disk.clone()),
            limiter: options.limiter,
            gc_job: false,
            store_layer: options.store_layer,
        };
        let mut server: Server = hangar_drive_server::build(&config, deps).await.unwrap();
        if let Some(timeout) = options.header_timeout {
            server = server.with_header_timeout(timeout);
        }
        let app = server.app.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(hangar_drive_server::serve(server, listener, async {
            let _ = stopped.await;
        }));
        Self {
            addr,
            app,
            clock,
            disk,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub async fn stop(&mut self) -> std::io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.task.take() {
            Some(task) => tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("the server did not stop in time")
                .unwrap(),
            None => Ok(()),
        }
    }

    pub async fn invite(&self) -> InviteToken {
        hangar_drive_server::service::accounts::create_invite(&self.app.db, self.clock.now(), 7)
            .await
            .unwrap()
            .0
    }

    /// The account's row key in the database.
    pub async fn account_pk(&self, account: &AccountId) -> i64 {
        sqlx::query_scalar("SELECT pk FROM accounts WHERE id = ?")
            .bind(account.as_bytes().as_slice())
            .fetch_one(&self.app.db)
            .await
            .unwrap()
    }

    pub async fn gc(&self) -> hangar_drive_server::service::retention::Outcome {
        hangar_drive_server::service::retention::run_step(&self.app)
            .await
            .unwrap()
    }
}

pub trait Now {
    fn now(&self) -> u64;
}

impl Now for ManualClock {
    fn now(&self) -> u64 {
        use hangar_drive_server::clock::Clock;
        self.now_ms()
    }
}

/// A reply.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: String,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "{e}: {} {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    pub fn value(&self) -> Value {
        self.json()
    }

    /// The error code of an error reply.
    pub fn code(&self) -> ErrorCode {
        self.json::<ErrorBody>().code
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.lines().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_owned())
        })
    }
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(end) = body.windows(2).position(|w| w == b"\r\n") else {
            return out;
        };
        let size = usize::from_str_radix(std::str::from_utf8(&body[..end]).unwrap().trim(), 16)
            .unwrap_or(0);
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&body[end + 2..end + 2 + size]);
        body = &body[end + 2 + size + 2..];
    }
}

/// One HTTP/1.1 request on a new connection.
pub async fn raw(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Reply {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    let split = reply
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header end");
    let head = String::from_utf8_lossy(&reply[..split]).into_owned();
    let mut body = reply[split + 4..].to_vec();
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body = dechunk(&body);
    }
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    Reply {
        status,
        headers: head,
        body,
    }
}

/// A client with an optional session token.
#[derive(Clone)]
pub struct Client {
    pub addr: SocketAddr,
    pub token: Option<String>,
    pub extra: Vec<(&'static str, String)>,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            token: None,
            extra: Vec::new(),
        }
    }

    fn headers(&self, content_type: Option<&str>) -> Vec<(&str, String)> {
        let mut headers: Vec<(&str, String)> =
            self.extra.iter().map(|(k, v)| (*k, v.clone())).collect();
        if let Some(token) = &self.token {
            headers.push(("Authorization", format!("Bearer {token}")));
        }
        if let Some(ct) = content_type {
            headers.push(("Content-Type", ct.to_owned()));
        }
        headers
    }

    pub async fn get(&self, path: &str) -> Reply {
        raw(self.addr, "GET", path, &self.headers(None), b"").await
    }

    pub async fn delete(&self, path: &str) -> Reply {
        raw(self.addr, "DELETE", path, &self.headers(None), b"").await
    }

    pub async fn send<T: Serialize>(&self, method: &str, path: &str, body: &T) -> Reply {
        let body = serde_json::to_vec(body).unwrap();
        raw(
            self.addr,
            method,
            path,
            &self.headers(Some("application/json")),
            &body,
        )
        .await
    }

    pub async fn post<T: Serialize>(&self, path: &str, body: &T) -> Reply {
        self.send("POST", path, body).await
    }

    pub async fn put_bytes(&self, path: &str, body: &[u8]) -> Reply {
        raw(
            self.addr,
            "PUT",
            path,
            &self.headers(Some("application/octet-stream")),
            body,
        )
        .await
    }
}

/// A device with its keys.
pub struct Device {
    pub id: DeviceId,
    pub identity: DeviceIdentity,
    pub recovery: bool,
    pub counter: u64,
}

impl Device {
    pub fn new() -> Self {
        Self::with_recovery(false)
    }

    pub fn with_recovery(recovery: bool) -> Self {
        Self {
            id: DeviceId::from_bytes(random()),
            identity: DeviceIdentity::generate(&mut OsEntropy).unwrap(),
            recovery,
            counter: 0,
        }
    }

    pub fn log_device(&self, account: &AccountId) -> LogDevice {
        LogDevice::of(&self.identity, account, self.id, self.recovery)
    }

    pub fn next_counter(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }
}

/// An account as the test sees it: its verified log, the current epoch secret and the devices.
pub struct Account {
    pub id: AccountId,
    pub state: AccountState,
    pub secret: Option<AccountSecret>,
    pub server: Option<ServerId>,
}

impl Account {
    /// Creates the account on the server with `first` (and `others`) in the genesis entry.
    pub async fn create(server: &TestServer, first: &Device, others: &[&Device]) -> Self {
        let id = AccountId::from_bytes(random());
        let mut state = AccountState::new(id);
        let mut devices = vec![first.log_device(&id)];
        devices.extend(others.iter().map(|d| d.log_device(&id)));
        let genesis = state
            .next_entry(
                &first.identity,
                first.id,
                START_MS,
                EntryKind::Create { devices },
            )
            .unwrap();
        let reply = Client::new(server.addr)
            .post(
                ACCOUNTS_PATH,
                &CreateAccountRequest {
                    invite: server.invite().await,
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
        Self {
            id,
            state,
            secret: None,
            server: Some(created.server),
        }
    }

    /// Signs in `device` and returns a client with its token.
    pub async fn sign_in(&self, server: &TestServer, device: &Device) -> Client {
        let client = Client::new(server.addr);
        let reply = client
            .post(
                CHALLENGE_PATH,
                &ChallengeRequest {
                    account: self.id,
                    device: device.id,
                },
            )
            .await;
        assert_eq!(reply.status, 200);
        let challenge: ChallengeResponse = reply.json();
        let signature = device.identity.prove_session(
            &challenge.server,
            TEST_URL,
            &self.id,
            &device.id,
            &challenge.challenge,
        );
        let reply = client
            .post(
                PROOF_PATH,
                &ProofRequest {
                    account: self.id,
                    device: device.id,
                    challenge: challenge.challenge,
                    server_url: TEST_URL.into(),
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
        Client {
            addr: server.addr,
            token: Some(session.token.expose_base64url().to_string()),
            extra: Vec::new(),
        }
    }

    /// Rotates the epoch through `client` (issued by `device`).
    pub async fn rotate(&mut self, client: &Client, device: &Device) -> Reply {
        let rotation = epoch::rotate(
            &self.state,
            &device.identity,
            device.id,
            START_MS,
            &mut OsEntropy,
        )
        .unwrap();
        let request = LogAppendRequest {
            entries: vec![Blob(rotation.entry.clone())],
            wraps: rotation
                .wraps
                .iter()
                .map(|(d, w)| WrappedKeyEntry {
                    device: *d,
                    data: Blob(w.clone()),
                })
                .collect(),
            device_wrap: None,
        };
        let reply = client.post(LOG_PATH, &request).await;
        if reply.status == 200 {
            self.state.apply(&rotation.entry).unwrap();
            self.secret = Some(rotation.secret);
        }
        reply
    }

    /// Adds `new` through `client` (issued by `issuer`).
    pub async fn add(&mut self, client: &Client, issuer: &Device, new: &Device) -> Reply {
        let addition = epoch::add_device(
            &self.state,
            &issuer.identity,
            issuer.id,
            START_MS,
            new.log_device(&self.id),
            self.secret.as_ref(),
            &mut OsEntropy,
        )
        .unwrap();
        let request = LogAppendRequest {
            entries: vec![Blob(addition.entry.clone())],
            wraps: Vec::new(),
            device_wrap: addition.wrap.map(|w| WrappedKeyEntry {
                device: new.id,
                data: Blob(w),
            }),
        };
        let reply = client.post(LOG_PATH, &request).await;
        if reply.status == 200 {
            self.state.apply(&addition.entry).unwrap();
        }
        reply
    }

    /// Removes `targets` and rotates through `client` (issued by `issuer`).
    pub async fn remove(
        &mut self,
        client: &Client,
        issuer: &Device,
        targets: &[DeviceId],
    ) -> Reply {
        let removal = epoch::remove_devices(
            &self.state,
            &issuer.identity,
            issuer.id,
            START_MS,
            targets,
            &mut OsEntropy,
        )
        .unwrap();
        let request = LogAppendRequest {
            entries: removal.entries.iter().cloned().map(Blob).collect(),
            wraps: removal
                .rotation
                .wraps
                .iter()
                .map(|(d, w)| WrappedKeyEntry {
                    device: *d,
                    data: Blob(w.clone()),
                })
                .collect(),
            device_wrap: None,
        };
        let reply = client.post(LOG_PATH, &request).await;
        if reply.status == 200 {
            self.state = removal.state;
            self.secret = Some(removal.rotation.secret);
        }
        reply
    }

    pub fn head(&self) -> LogHead {
        self.state.head().unwrap()
    }
}

/// A blob with a valid header and a valid Padmé length for a plaintext of `len` bytes. The
/// server cannot open objects, so random contents are as good as real ones here.
pub fn blob(kind: ObjectType, len: usize) -> Vec<u8> {
    let total = blob_len(len).unwrap();
    let mut bytes = vec![0u8; total];
    OsEntropy.fill(&mut bytes).unwrap();
    bytes[0] = 1;
    bytes[1..5].copy_from_slice(&1u32.to_be_bytes());
    bytes[5] = kind.to_byte();
    bytes
}

/// An object to upload: ID and blob.
pub struct Obj {
    pub id: ObjectId,
    pub blob: Vec<u8>,
}

impl Obj {
    pub fn new(kind: ObjectType, len: usize) -> Self {
        Self {
            id: ObjectId::from_bytes(random()),
            blob: blob(kind, len),
        }
    }

    pub fn size(&self) -> u64 {
        self.blob.len() as u64
    }
}

pub async fn upload(client: &Client, folder: &FolderId, obj: &Obj) -> Reply {
    let reply = client
        .put_bytes(&object_path(folder, &obj.id), &obj.blob)
        .await;
    if reply.status >= 400 {
        eprintln!(
            "upload refused: {} {}",
            reply.status,
            String::from_utf8_lossy(&reply.body)
        );
    }
    reply
}

/// The folder as the test tracks it: its chain.
pub struct Folder {
    pub id: FolderId,
    pub head: Option<(SignedCommit, u64)>,
}

impl Folder {
    pub fn new() -> Self {
        Self {
            id: FolderId::from_bytes(random()),
            head: None,
        }
    }

    pub fn entry(&self) -> Option<ChainEntry> {
        self.head.as_ref().map(|(c, seq)| ChainEntry {
            commit: c.id,
            height: c.commit.height,
            sequence: *seq,
            generation: c.commit.generation,
            log_index: c.commit.log_head.index,
        })
    }

    /// The next normal commit by `device` (first commit if there is no head).
    pub fn next(&self, account: &Account, device: &mut Device) -> SignedCommit {
        let content = CommitContent {
            root: ObjectId::from_bytes(random()),
            generation: Generation(1),
            device: device.id,
            log_head: account.head(),
            counter: device.next_counter(),
        };
        let commit = match self.entry() {
            None => Commit::first(account.id, self.id, content),
            Some(entry) => Commit::on(account.id, self.id, &entry, content),
        };
        commit.sign(&device.identity).unwrap()
    }

    pub fn request(
        &self,
        commit: &SignedCommit,
        added: &[&Obj],
        dropped: &[&Obj],
    ) -> CommitRequest {
        CommitRequest {
            expected_head: self.head.as_ref().map(|(c, _)| c.id),
            head: CommitUpload {
                commit: Blob(commit.wire.clone()),
                delta: ReferenceDelta {
                    added: added.iter().map(|o| o.id).collect(),
                    dropped: dropped.iter().map(|o| o.id).collect(),
                },
            },
            side: None,
        }
    }

    /// Commits a merge by `device`: a side commit on `base` that adds `side_added`, and a
    /// merge commit on the current head with the head delta `added`, `dropped`.
    #[allow(clippy::too_many_arguments)]
    pub async fn merge(
        &mut self,
        client: &Client,
        account: &Account,
        device: &mut Device,
        base: &ChainEntry,
        side_added: &[&Obj],
        added: &[&Obj],
        dropped: &[&Obj],
    ) -> Reply {
        let content = |device: &mut Device| CommitContent {
            root: ObjectId::from_bytes(random()),
            generation: Generation(1),
            device: device.id,
            log_head: account.head(),
            counter: device.next_counter(),
        };
        let side = Commit::side(account.id, self.id, base, content(device))
            .sign(&device.identity)
            .unwrap();
        let head = self.entry().expect("a merge needs a head");
        let merge = Commit::merge(account.id, self.id, &head, &side, content(device))
            .sign(&device.identity)
            .unwrap();
        let mut request = self.request(&merge, added, dropped);
        request.side = Some(CommitUpload {
            commit: Blob(side.wire.clone()),
            delta: ReferenceDelta {
                added: side_added.iter().map(|o| o.id).collect(),
                dropped: Vec::new(),
            },
        });
        let reply = client.post(&commit_path(&self.id), &request).await;
        if reply.status == 200 {
            let response: CommitResponse = reply.json();
            self.head = Some((merge, response.sequence));
        }
        reply
    }

    /// Commits a normal commit with the given delta and records it as the head.
    pub async fn commit(
        &mut self,
        client: &Client,
        account: &Account,
        device: &mut Device,
        added: &[&Obj],
        dropped: &[&Obj],
    ) -> Reply {
        let commit = self.next(account, device);
        let request = self.request(&commit, added, dropped);
        let reply = client.post(&commit_path(&self.id), &request).await;
        if reply.status == 200 {
            let response: CommitResponse = reply.json();
            self.head = Some((commit, response.sequence));
        }
        reply
    }
}

/// The feed entries after `after`.
pub async fn feed(client: &Client, after: u64) -> FeedPage {
    let reply = client.get(&format!("{FEED_PATH}?after={after}")).await;
    assert_eq!(reply.status, 200);
    reply.json()
}
