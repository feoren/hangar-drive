//! End to end against the real server: `hangar_drive_server::build` and `serve` (what the
//! binary's `serve` command runs, with its real clock, disk probe, rate limiter and collection
//! job) on a socket of this machine with a data folder under `tests/.tmp/`, the invite from the
//! operator's admin function, and real engines: [`EngineCore`] with the SQLite index, the real
//! file system (`localfs`) with its watcher, the HTTP client and the operating system's
//! randomness. Only the keychain is a fake, and the clock runs ahead of the system clock on
//! demand so that the delete delay passes without waiting.
//!
//! One test walks the core flow: account with recovery group, a folder with small, multi-chunk,
//! Unicode and nested files, pairing with a reserved offer, changes, moves and deletes, an
//! offline conflict across a server stop, a held mass delete, restores of a file and a
//! directory and a reset of the whole folder, removing a device with barriers, a recovery with
//! the sheet and the code, a server restart, and at the end a search for plaintext in the
//! server's data folder.
//!
//! The other tests each pin one finding of this flow against the real server (E2E-1 to E2E-6):
//! each failed until its fix and guards it now. The flow runs without any workaround and checks
//! all six as well.
//!
//! Platform notes:
//! - Incoming deletes go through the real `LocalFs::trash_file`: the system's recycle bin
//!   (Windows shell, macOS Finder, the XDG trash on Linux) or the quarantine of the sync root.
//!   A few small marker files of this test therefore land in the recycle bin of the machine
//!   that runs it, as in `tests/localfs.rs`. Where the file went is recorded per call; a
//!   quarantined file is checked byte for byte.
//! - The server binds the first address `localhost` resolves to (`::1` or `127.0.0.1`), because
//!   the client allows plain HTTP to `localhost` only and connects to that address first.
//! - Names are compared as the file system returns them; Unicode names are written in NFC,
//!   which NTFS, APFS and ext4 keep as written.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::api::{self, ErrorCode};
use hangar_drive_protocol::ids::{
    AccountId, Challenge, DeviceId, Epoch, FolderId, ItemId, ObjectId, PairingId, Signature,
};
use hangar_drive_protocol::name::is_ignored;
use hangar_drive_server::config::{
    Config, DATA_DIR_VAR, PORT_VAR, PUBLIC_URL_VAR, SHUTDOWN_GRACE_VAR,
};
use hangar_drive_server::Deps;
use hangar_drive_sync::api::{
    ApiResult, BackendEvent, Connection, FolderStatus, InspectedLink, PairResult, RecoverError,
    RestoreOutcome, SetupState, StopReasonApi, Warning,
};
use hangar_drive_sync::engine::{
    prover, real_root_check, real_server_factory, EngineCore, EnginePorts, EngineSettings,
    FsFactory, ServerFactory,
};
use hangar_drive_sync::http::{HttpServer, RetryPolicy, ServerConfig, SessionIdentity};
use hangar_drive_sync::index::SqliteStore;
use hangar_drive_sync::localfs::LocalFs;
use hangar_drive_sync::ports::{
    Clock, Expect, FileSystem, FsError, Keychain, KeychainError, ListEntry, NetError, ServerApi,
    Stat,
};
use hangar_drive_sync::trash::Trashed;
use hangar_drive_sync::watch::{ChangeSource, FolderWatcher};
use zeroize::Zeroizing;

/// A harmless marker in file contents, searched for in the server's data folder at the end.
const MARKER: &str = "hangar-e2e-plaintext-marker-5d1c";
/// How long one wait for the devices to agree may take before the test fails with a report.
const WAIT: Duration = Duration::from_secs(90);

// ------------------------------------------------------------------------------------------
// Test directory
// ------------------------------------------------------------------------------------------

/// The test's directory below the repository's `tests/.tmp/`: removed when the test passes,
/// kept when it fails, so the folders, indexes and the server's data can be looked at.
struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repository root")
            .to_path_buf();
        let dir = repo
            .join("tests")
            .join(".tmp")
            .join(format!("e2e-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test directory");
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("e2e: test data kept for diagnosis in {}", self.0.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

// ------------------------------------------------------------------------------------------
// The real server
// ------------------------------------------------------------------------------------------

struct Running {
    app: hangar_drive_server::app::AppState,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// The server as the binary runs it, in this process on its own runtime.
struct TestServer {
    runtime: tokio::runtime::Runtime,
    data_dir: PathBuf,
    addr: SocketAddr,
    running: Option<Running>,
}

impl TestServer {
    fn start(data_dir: PathBuf) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("runtime");
        // The client allows plain HTTP only to `localhost` and connects to the first address
        // it resolves to, so the server listens there (a free port chosen by the system).
        let ip = ("localhost", 0)
            .to_socket_addrs()
            .expect("localhost resolves")
            .next()
            .expect("an address for localhost")
            .ip();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind(SocketAddr::new(ip, 0)))
            .expect("listen");
        let addr = listener.local_addr().expect("local address");
        let mut server = Self {
            runtime,
            data_dir,
            addr,
            running: None,
        };
        server.serve(listener);
        server
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    fn url(&self) -> String {
        format!("http://localhost:{}/", self.port())
    }

    fn config(&self) -> Config {
        let vars: Vec<(&str, String)> = vec![
            (DATA_DIR_VAR, self.data_dir.display().to_string()),
            (PORT_VAR, self.port().to_string()),
            (PUBLIC_URL_VAR, self.url()),
            (SHUTDOWN_GRACE_VAR, "2".into()),
        ];
        Config::from_lookup(|name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(v))
        })
        .expect("server configuration")
    }

    fn serve(&mut self, listener: tokio::net::TcpListener) {
        let config = self.config();
        let server = self
            .runtime
            .block_on(hangar_drive_server::build(&config, Deps::default()))
            .expect("server build");
        let app = server.app.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = self
            .runtime
            .spawn(hangar_drive_server::serve(server, listener, async move {
                let _ = stopped.await;
            }));
        self.running = Some(Running { app, stop, task });
    }

    fn stop(&mut self) {
        let Some(running) = self.running.take() else {
            return;
        };
        let _ = running.stop.send(());
        let result = self
            .runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(30), running.task).await })
            .expect("the server stopped in time")
            .expect("the server task did not panic");
        result.expect("the server stopped cleanly");
    }

    /// Stops and starts the server on the same port and data folder.
    fn restart(&mut self) {
        self.stop();
        let deadline = Instant::now() + Duration::from_secs(20);
        let listener = loop {
            match self
                .runtime
                .block_on(tokio::net::TcpListener::bind(self.addr))
            {
                Ok(listener) => break listener,
                Err(e) if Instant::now() < deadline => {
                    eprintln!("e2e: port {} not free yet ({e})", self.port());
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => panic!("the port did not become free again: {e}"),
            }
        };
        self.serve(listener);
    }

    /// The operator's single-use invite, made by the admin function the CLI's `invite` command
    /// calls, and its link as the CLI prints it.
    fn invite(&self) -> String {
        let running = self.running.as_ref().expect("server running");
        let (token, _expires) = self
            .runtime
            .block_on(hangar_drive_server::service::accounts::create_invite(
                &running.app.db,
                running.app.now_ms(),
                7,
            ))
            .expect("invite");
        hangar_drive_server::links::invite_link(&self.url(), &token, &running.app.server_id, None)
    }

    fn server_id_hex(&self) -> String {
        self.running
            .as_ref()
            .expect("server running")
            .app
            .server_id
            .to_hex()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            let _ = running.stop.send(());
            let _ = self.runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(10), running.task).await
            });
        }
    }
}

// ------------------------------------------------------------------------------------------
// Device ports
// ------------------------------------------------------------------------------------------

/// The system clock plus an offset the test moves forward (the delete delay, the silent
/// server); never backwards.
#[derive(Clone, Default)]
struct TestClock(Rc<Cell<i64>>);

impl TestClock {
    fn skip(&self, ms: i64) {
        self.0.set(self.0.get() + ms);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_millis();
        i64::try_from(now).expect("milliseconds fit") + self.0.get()
    }
}

/// The keychain fake: a map the test can read (the device identity for the removal check).
#[derive(Clone, Default)]
struct FakeKeychain(Rc<RefCell<BTreeMap<String, Vec<u8>>>>);

impl Keychain for FakeKeychain {
    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        Ok(self.0.borrow().get(key).map(|v| Zeroizing::new(v.clone())))
    }
    fn store(&mut self, key: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.0.borrow_mut().insert(key.to_owned(), secret.to_vec());
        Ok(())
    }
    fn delete(&mut self, key: &str) -> Result<(), KeychainError> {
        self.0.borrow_mut().remove(key);
        Ok(())
    }
}

/// Where an incoming delete went.
#[derive(Debug, Clone)]
struct Trashing {
    item: ItemId,
    path: String,
    to: Trashed,
}

#[derive(Default)]
struct FsLog {
    trashed: Vec<Trashing>,
    removed: Vec<String>,
}

type SharedFsLog = Arc<Mutex<FsLog>>;

/// The real `LocalFs`, every call passed through unchanged; trash and remove calls are
/// recorded so the test can tell the recycle bin, the quarantine and a delete apart.
struct TrackedFs {
    inner: Arc<LocalFs>,
    log: SharedFsLog,
}

impl FileSystem for TrackedFs {
    fn stat(&self, path: &[String]) -> Result<Option<Stat>, FsError> {
        self.inner.stat(path)
    }
    fn list(&self, path: &[String]) -> Result<Vec<ListEntry>, FsError> {
        self.inner.list(path)
    }
    fn read_at(&self, path: &[String], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        self.inner.read_at(path, offset, buf)
    }
    fn create_dir(&self, path: &[String]) -> Result<(), FsError> {
        self.inner.create_dir(path)
    }
    fn write_atomic(
        &self,
        path: &[String],
        fill: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<(), FsError>,
        mtime_ms: i64,
        executable: bool,
        replace: Option<Expect>,
    ) -> Result<Stat, FsError> {
        self.inner
            .write_atomic(path, fill, mtime_ms, executable, replace)
    }
    fn rename(&self, from: &[String], to: &[String]) -> Result<(), FsError> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &[String], expect: Expect) -> Result<(), FsError> {
        let result = self.inner.remove_file(path, expect);
        if result.is_ok() {
            self.log.lock().expect("log").removed.push(path.join("/"));
        }
        result
    }
    fn trash_file(
        &self,
        item: &ItemId,
        path: &[String],
        expect: Expect,
    ) -> Result<Trashed, FsError> {
        let result = self.inner.trash_file(item, path, expect);
        if let Ok(to) = &result {
            self.log.lock().expect("log").trashed.push(Trashing {
                item: *item,
                path: path.join("/"),
                to: *to,
            });
        }
        result
    }
    fn expect_directories(&self, ids: Vec<(Vec<String>, u128)>) {
        self.inner.expect_directories(ids)
    }
    fn remove_dir(&self, path: &[String]) -> Result<(), FsError> {
        self.inner.remove_dir(path)
    }
    fn set_meta(
        &self,
        path: &[String],
        mtime_ms: i64,
        executable: bool,
        expect: Expect,
    ) -> Result<(), FsError> {
        self.inner.set_meta(path, mtime_ms, executable, expect)
    }
    fn mtime_tolerance_ms(&self) -> i64 {
        self.inner.mtime_tolerance_ms()
    }
    fn exec_supported(&self) -> bool {
        self.inner.exec_supported()
    }
}

// ------------------------------------------------------------------------------------------
// Recorded server calls
// ------------------------------------------------------------------------------------------

/// Every connection of a device goes through this wrapper, which forwards each call unchanged
/// to the real `HttpServer` and keeps the last failed calls for the failure report.
struct Recorded {
    inner: Box<dyn ServerApi>,
    errors: CallLog,
}

/// The last failed server calls of a device.
type CallLog = Rc<RefCell<Vec<String>>>;

impl Recorded {
    fn note<T>(&self, call: &str, result: Result<T, NetError>) -> Result<T, NetError> {
        if let Err(e) = &result {
            let mut log = self.errors.borrow_mut();
            log.push(format!("{call}: {e:?}"));
            let excess = log.len().saturating_sub(20);
            log.drain(..excess);
        }
        result
    }
}

impl ServerApi for Recorded {
    fn create_account(
        &mut self,
        request: &api::CreateAccountRequest,
    ) -> Result<api::CreateAccountResponse, NetError> {
        let result = self.inner.create_account(request);
        self.note("create_account", result)
    }
    fn challenge(
        &mut self,
        account: &AccountId,
        device: &DeviceId,
    ) -> Result<api::ChallengeResponse, NetError> {
        let result = self.inner.challenge(account, device);
        self.note("challenge", result)
    }
    fn proof(
        &mut self,
        account: &AccountId,
        device: &DeviceId,
        challenge: &Challenge,
        signature: &Signature,
    ) -> Result<api::SessionResponse, NetError> {
        let result = self.inner.proof(account, device, challenge, signature);
        self.note("proof", result)
    }
    fn log(&mut self, after: u64) -> Result<api::LogPage, NetError> {
        let result = self.inner.log(after);
        self.note("log", result)
    }
    fn append_log(
        &mut self,
        request: &api::LogAppendRequest,
    ) -> Result<api::LogAppendResponse, NetError> {
        let result = self.inner.append_log(request);
        self.note("append_log", result)
    }
    fn epoch_key(&mut self, epoch: Epoch) -> Result<api::WrappedKeyResponse, NetError> {
        let result = self.inner.epoch_key(epoch);
        self.note("epoch_key", result)
    }
    fn record(&mut self, key: &api::RecordKey) -> Result<Option<api::RecordResponse>, NetError> {
        let result = self.inner.record(key);
        self.note("record", result)
    }
    fn put_record(&mut self, key: &api::RecordKey, put: &api::RecordPut) -> Result<(), NetError> {
        let result = self.inner.put_record(key, put);
        self.note("put_record", result)
    }
    fn feed(&mut self, after: u64) -> Result<api::FeedPage, NetError> {
        let result = self.inner.feed(after);
        self.note("feed", result)
    }
    fn reserve_pairing(&mut self, id: &PairingId) -> Result<api::PairingReservation, NetError> {
        let result = self.inner.reserve_pairing(id);
        self.note("reserve_pairing", result)
    }
    fn post_pairing(
        &mut self,
        id: &PairingId,
        request: &api::PairingRequest,
    ) -> Result<(), NetError> {
        let result = self.inner.post_pairing(id, request);
        self.note("post_pairing", result)
    }
    fn get_pairing(&mut self, id: &PairingId) -> Result<Option<api::PairingRequest>, NetError> {
        let result = self.inner.get_pairing(id);
        self.note("get_pairing", result)
    }
    fn close_pairing(&mut self, id: &PairingId) -> Result<(), NetError> {
        let result = self.inner.close_pairing(id);
        self.note("close_pairing", result)
    }
    fn missing_objects(
        &mut self,
        folder: &FolderId,
        ids: &[ObjectId],
    ) -> Result<Vec<ObjectId>, NetError> {
        let result = self.inner.missing_objects(folder, ids);
        self.note("missing_objects", result)
    }
    fn put_object(
        &mut self,
        folder: &FolderId,
        id: &ObjectId,
        blob: &[u8],
    ) -> Result<api::UploadResponse, NetError> {
        let result = self.inner.put_object(folder, id, blob);
        self.note("put_object", result)
    }
    fn get_object(&mut self, folder: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError> {
        let result = self.inner.get_object(folder, id);
        self.note("get_object", result)
    }
    fn commit(
        &mut self,
        folder: &FolderId,
        request: &api::CommitRequest,
    ) -> Result<api::CommitResponse, NetError> {
        let result = self.inner.commit(folder, request);
        self.note("commit", result)
    }
    fn commits(&mut self, folder: &FolderId, after: u64) -> Result<api::DeltaPage, NetError> {
        let result = self.inner.commits(folder, after);
        self.note("commits", result)
    }
    fn retire(&mut self, folder: &FolderId) -> Result<(), NetError> {
        let result = self.inner.retire(folder);
        self.note("retire", result)
    }
    fn bring_back(&mut self, folder: &FolderId) -> Result<(), NetError> {
        let result = self.inner.bring_back(folder);
        self.note("bring_back", result)
    }
    fn seen_pin(&self) -> Option<[u8; 32]> {
        self.inner.seen_pin()
    }
}

/// The real server factory (`engine::real_server_factory`) behind [`Recorded`].
fn server_factory(errors: &CallLog) -> ServerFactory {
    let real = real_server_factory();
    let errors = Rc::clone(errors);
    Box::new(move |config, identity| {
        Ok(Box::new(Recorded {
            inner: real(config, identity)?,
            errors: Rc::clone(&errors),
        }) as Box<dyn ServerApi>)
    })
}

/// `engine::real_fs_factory` with the recording wrapper around the same `LocalFs`.
fn tracked_fs_factory(log: SharedFsLog) -> FsFactory {
    Box::new(move |path| {
        let fs = Arc::new(LocalFs::new(path)?);
        let watcher = FolderWatcher::start(&fs)
            .ok()
            .map(|w| Box::new(w) as Box<dyn ChangeSource>);
        let tracked = TrackedFs {
            inner: fs,
            log: Arc::clone(&log),
        };
        Ok((Box::new(tracked) as Box<dyn FileSystem>, watcher))
    })
}

// ------------------------------------------------------------------------------------------
// Devices
// ------------------------------------------------------------------------------------------

/// One installation: an engine with its own index, keychain and sync folder.
struct Peer {
    label: &'static str,
    core: EngineCore,
    root: PathBuf,
    keychain: FakeKeychain,
    fs_log: SharedFsLog,
    errors: CallLog,
    events: Vec<BackendEvent>,
}

impl Peer {
    fn open(scratch: &Path, label: &'static str, clock: &TestClock) -> Self {
        let home = scratch.join(label);
        let root = home.join("Docs");
        std::fs::create_dir_all(&root).expect("sync folder");
        std::fs::create_dir_all(home.join("index")).expect("index folder");
        let store = SqliteStore::open(&home.join("index").join("index.sqlite3")).expect("index");
        let keychain = FakeKeychain::default();
        let fs_log = SharedFsLog::default();
        let errors = CallLog::default();
        let ports = EnginePorts {
            store: Box::new(store),
            keychain: Box::new(keychain.clone()),
            clock: Box::new(clock.clone()),
            entropy: Box::new(hangar_drive_crypto::OsEntropy),
            fs: tracked_fs_factory(Arc::clone(&fs_log)),
            server: server_factory(&errors),
            roots: real_root_check(),
        };
        let core = EngineCore::open(ports, EngineSettings::default()).expect("engine");
        Self {
            label,
            core,
            root,
            keychain,
            fs_log,
            errors,
            events: Vec::new(),
        }
    }

    fn root_text(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }

    fn tick(&mut self) {
        let events = self.core.tick();
        self.events.extend(events);
    }

    fn path(&self, rel: &str) -> PathBuf {
        rel.split('/').fold(self.root.clone(), |p, n| p.join(n))
    }

    fn write(&self, rel: &str, content: &[u8]) {
        let path = self.path(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent directory");
        }
        std::fs::write(&path, content).expect("write");
    }

    fn files(&self) -> BTreeMap<String, Vec<u8>> {
        files_of(&self.root)
    }

    fn has_warning(&self, f: impl Fn(&Warning) -> bool) -> bool {
        self.core.snapshot().warnings.iter().any(f)
    }

    fn device_id(&self, name: &str) -> String {
        self.core
            .list_devices()
            .expect("devices")
            .devices
            .into_iter()
            .find(|d| d.name == name)
            .unwrap_or_else(|| panic!("{}: no device {name}", self.label))
            .id
    }

    /// The paths of the server's current head tree of `folder` as this device verified it.
    fn head_paths(&mut self, folder: &str) -> Option<BTreeSet<String>> {
        let timeline = self.core.get_timeline(folder, 1).ok()?;
        let head = timeline.entries.first()?.id.clone();
        let tree = self.core.get_tree_at(folder, &head).ok()?;
        Some(tree.nodes.into_iter().map(|n| n.path).collect())
    }

    fn head_id(&mut self, folder: &str) -> String {
        self.core
            .get_timeline(folder, 1)
            .expect("timeline")
            .entries
            .first()
            .expect("a head")
            .id
            .clone()
    }
}

/// Every file and directory below `root` as the engine sees it (the reserved directory and the
/// built-in ignore list left out): files with their bytes, directories as `path/` and nothing.
fn files_of(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_ignored(&name, prefix.is_empty()) {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                walk(&entry.path(), &rel, out);
            } else if kind.is_file() {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    out.insert(rel, bytes);
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

/// A short listing of a tree for failure reports: path and size, contents of small text files.
fn listing(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut out = String::new();
    for (path, bytes) in files {
        if path.ends_with('/') {
            out.push_str(&format!("    {path}\n"));
        } else if bytes.len() <= 80 {
            out.push_str(&format!(
                "    {path} = {:?}\n",
                String::from_utf8_lossy(bytes)
            ));
        } else {
            out.push_str(&format!("    {path} ({} bytes)\n", bytes.len()));
        }
    }
    out
}

fn diagnose(peers: &[&mut Peer]) -> String {
    let mut out = String::new();
    for p in peers {
        let snap = p.core.snapshot();
        out.push_str(&format!(
            "--- {}: connection {:?}, pending {}\n  folders: {:?}\n  warnings: {:?}\n",
            p.label, snap.sync.connection, snap.sync.pending_files, snap.folders, snap.warnings
        ));
        out.push_str(&format!(
            "  failed server calls: {:?}
",
            p.errors.borrow()
        ));
        out.push_str(&listing(&p.files()));
    }
    out
}

/// Ticks every device until `check` answers, at most [`WAIT`]. Each round lets one extra
/// second of engine time pass, so the delete delay (10 s) runs out within a few rounds.
fn wait_for<T>(
    peers: &mut [&mut Peer],
    clock: &TestClock,
    what: &str,
    mut check: impl FnMut(&mut [&mut Peer]) -> Option<T>,
) -> T {
    let started = Instant::now();
    loop {
        for p in peers.iter_mut() {
            p.tick();
        }
        if let Some(value) = check(peers) {
            return value;
        }
        if started.elapsed() > WAIT {
            panic!(
                "timed out after {:?} waiting for {what}\n{}",
                WAIT,
                diagnose(peers)
            );
        }
        clock.skip(1_000);
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Ticks every device `rounds` times (for checks that something does NOT happen).
fn run_rounds(peers: &mut [&mut Peer], clock: &TestClock, rounds: usize) {
    for _ in 0..rounds {
        for p in peers.iter_mut() {
            p.tick();
        }
        clock.skip(1_000);
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn same_files(peers: &[&mut Peer]) -> bool {
    let first = peers[0].files();
    peers[1..].iter().all(|p| p.files() == first)
}

/// Deterministic bytes that do not compress and contain no marker (xorshift64*).
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
    }
    out.truncate(len);
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every file below `dir` that contains `needle`.
fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                if contains(&bytes, needle) {
                    hits.push(path);
                }
            }
        }
    }
    hits
}

fn dir_size(dir: &Path) -> (u64, usize) {
    let (mut bytes, mut files) = (0, 0);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(meta) = entry.metadata() {
                bytes += meta.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

fn is_auth_refusal(error: &NetError) -> bool {
    matches!(
        error.code(),
        Some(ErrorCode::Unauthorized)
            | Some(ErrorCode::Forbidden)
            | Some(ErrorCode::ProofInvalid)
            | Some(ErrorCode::ChallengeInvalid)
            | Some(ErrorCode::DeviceRemoved)
    )
}

struct Steps {
    started: Instant,
    last: Instant,
}

impl Steps {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            last: now,
        }
    }
    fn done(&mut self, step: &str) {
        let now = Instant::now();
        eprintln!(
            "e2e: {step} done in {:.1} s (total {:.1} s)",
            (now - self.last).as_secs_f64(),
            (now - self.started).as_secs_f64()
        );
        self.last = now;
    }
}

// ------------------------------------------------------------------------------------------
// The flow
// ------------------------------------------------------------------------------------------

/// Finding E2E-1: an engine creates an account with the operator's invite. Against the real
/// server, the group check fails with `Unauthorized` after the invite was redeemed, so the
/// account is left with entry 1 only and the invite is used up.
#[test]
fn a_new_account_is_created_against_the_real_server() {
    let scratch = Scratch::new("account");
    let clock = TestClock::default();
    let server = TestServer::start(scratch.0.join("server"));
    let invite = server.invite();
    let mut a = Peer::open(&scratch.0, "a", &clock);
    let ApiResult::Ok(code) = a.core.begin_account(&invite, "Laptop A").expect("begin") else {
        panic!("the invite was refused");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    let confirmed = a.core.confirm_recovery_group(&group);
    assert!(
        matches!(confirmed, Ok(true)),
        "the group check must create the account, got {confirmed:?}"
    );
    assert_eq!(a.core.snapshot().setup, SetupState::Done);
    let folder = a.core.add_folder(&a.root_text(), "Docs").expect("a folder");
    a.write("plan.txt", MARKER.as_bytes());
    wait_for(&mut [&mut a], &clock, "the first file on the server", |p| {
        p[0].head_paths(&folder)?.contains("plan.txt").then_some(())
    });
}

/// Finding E2E-2: a new folder's first files reach the server. The real server answered the
/// first `GET /folders/{id}/commits` of a folder it holds no object or commit of with
/// `NotFound`; `FolderSync::pull` took that as a failure, so the first commit was never
/// published and the folder stayed at "uploading" for good.
#[test]
fn a_new_folder_publishes_its_first_files_against_the_real_server() {
    let scratch = Scratch::new("folder");
    let clock = TestClock::default();
    let server = TestServer::start(scratch.0.join("server"));
    let invite = server.invite();
    let mut a = Peer::open(&scratch.0, "a", &clock);
    let ApiResult::Ok(code) = a.core.begin_account(&invite, "Laptop A").expect("begin") else {
        panic!("the invite was refused");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.core.confirm_recovery_group(&group).expect("account"));
    let folder = a.core.add_folder(&a.root_text(), "Docs").expect("a folder");
    a.write("plan.txt", MARKER.as_bytes());
    wait_for(&mut [&mut a], &clock, "the first file on the server", |p| {
        p[0].head_paths(&folder)?.contains("plan.txt").then_some(())
    });
}

/// A new account on `server` for `a`, as `name`; returns the code.
fn create_account(
    a: &mut Peer,
    server: &TestServer,
    name: &str,
) -> hangar_drive_sync::api::RecoveryCodeView {
    let invite = server.invite();
    let ApiResult::Ok(code) = a.core.begin_account(&invite, name).expect("begin") else {
        panic!("the invite was refused");
    };
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a.core.confirm_recovery_group(&group).expect("account"));
    code
}

/// `joiner` joins the account of `inviter` through a pairing offer, as `name`.
fn pair(inviter: &mut Peer, joiner: &mut Peer, name: &str, clock: &TestClock) {
    let offer = inviter.core.create_pairing_offer().expect("offer");
    let ApiResult::Ok(_) = joiner
        .core
        .start_pairing(&offer.link, name)
        .expect("start pairing")
    else {
        panic!("pairing refused");
    };
    let request = wait_for(&mut [&mut *inviter], clock, "the pair request", |p| {
        p[0].events.iter().find_map(|e| match e {
            BackendEvent::PairRequest { request } => Some(request.clone()),
            _ => None,
        })
    });
    inviter
        .core
        .answer_pair_request(&request.offer_id, true)
        .expect("accept");
    wait_for(&mut [&mut *joiner], clock, "joining", |p| {
        p[0].events.iter().find_map(|e| match e {
            BackendEvent::PairResult {
                result: PairResult::Joined { .. },
            } => Some(()),
            BackendEvent::PairResult {
                result: PairResult::Failed { error },
            } => panic!("pairing failed: {error:?}"),
            _ => None,
        })
    });
}

/// Finding E2E-3: a device another device removed shows that it was removed (ADR 0001,
/// `Warning::Removed`). The engine learns it only from the account log (`Account::refresh`), but
/// the real server refuses the removed device's sign-in (`ProofInvalid`), so it never reads the
/// log again: the window keeps showing "online" without a warning, and every pass signs in
/// again until the server answers `RateLimited`. The in-memory server lets a removed device read
/// the log, so `tests/engine.rs` passed. Now the server answers the removed device's own proof
/// with `DeviceRemoved`, and the engine forgets the account (security review L1).
#[test]
fn a_removed_device_learns_that_it_was_removed() {
    let scratch = Scratch::new("removed");
    let clock = TestClock::default();
    let server = TestServer::start(scratch.0.join("server"));
    let mut a = Peer::open(&scratch.0, "a", &clock);
    create_account(&mut a, &server, "Laptop A");
    let mut b = Peer::open(&scratch.0, "b", &clock);
    pair(&mut a, &mut b, "Desktop B", &clock);
    let b_id = a.device_id("Desktop B");
    a.core.remove_device(&b_id).expect("remove B");
    wait_for(
        &mut [&mut a, &mut b],
        &clock,
        "B showing it was removed",
        |p| {
            p[1].has_warning(|w| matches!(w, Warning::Removed { .. }))
                .then_some(())
        },
    );
    assert_eq!(b.core.snapshot().setup, SetupState::Needed);
    assert!(
        b.keychain.0.borrow().is_empty(),
        "B's secrets are gone: {:?}",
        b.keychain.0.borrow().keys().collect::<Vec<_>>()
    );
    // B stops signing in: a few more rounds without a single new failed call.
    let failed = b.errors.borrow().len();
    run_rounds(&mut [&mut a, &mut b], &clock, 3);
    assert_eq!(b.errors.borrow().len(), failed, "{:?}", b.errors.borrow());
}

/// Finding E2E-4: a device recovered with the sheet and the code shows its own name.
/// `EngineCore::recover_account` adds the new device to the log through the recovery device
/// (`recovery::add_device_with_code`) but never wrote its name into the sealed device names
/// (pairing does, in `Account::add_device`), so `listDevices` showed it with an empty name, on
/// this device and on every other. Not specific to the real server.
#[test]
fn a_recovered_device_shows_its_own_name() {
    let scratch = Scratch::new("recovered");
    let clock = TestClock::default();
    let server = TestServer::start(scratch.0.join("server"));
    let mut a = Peer::open(&scratch.0, "a", &clock);
    let code = create_account(&mut a, &server, "Laptop A");
    let mut c = Peer::open(&scratch.0, "c", &clock);
    assert_eq!(
        c.core
            .recover_account(&code.sheet.link, &code.groups.join("-"), "Rescue C")
            .expect("recover"),
        ApiResult::Ok(())
    );
    let a_id = a.device_id("Laptop A");
    c.core
        .finish_recovery_cleanup(std::slice::from_ref(&a_id))
        .expect("cleanup");
    c.tick();
    let devices = c.core.list_devices().expect("devices").devices;
    assert_eq!(devices.len(), 1, "{devices:?}");
    assert_eq!(devices[0].name, "Rescue C", "{devices:?}");
}

/// Finding E2E-5: a recovery code that was used is reported as used (`RecoverError::Used`, the
/// window's "this code was used before"). `recovery::add_device_with_code` tells "used" from
/// "unknown" by reading the log as the recovery device, but after the cleanup the real server
/// refused that removed device's sign-in (`ProofInvalid`), which `recover_account` mapped to
/// `Unknown` ("does not belong to an account on this server"). Same cause as E2E-3: the server
/// now answers the code's own proof with `DeviceRemoved`.
#[test]
fn a_used_recovery_code_is_reported_as_used() {
    let scratch = Scratch::new("used");
    let clock = TestClock::default();
    let server = TestServer::start(scratch.0.join("server"));
    let mut a = Peer::open(&scratch.0, "a", &clock);
    let code = create_account(&mut a, &server, "Laptop A");
    let text = code.groups.join("-");
    let mut c = Peer::open(&scratch.0, "c", &clock);
    assert_eq!(
        c.core
            .recover_account(&code.sheet.link, &text, "Rescue C")
            .expect("recover"),
        ApiResult::Ok(())
    );
    c.core.finish_recovery_cleanup(&[]).expect("cleanup");
    let mut again = Peer::open(&scratch.0, "again", &clock);
    assert_eq!(
        again
            .core
            .recover_account(&code.sheet.link, &text, "Again")
            .expect("used code"),
        ApiResult::Err(RecoverError::Used)
    );
}

/// Finding E2E-6: after a pairing went through, the new device's name is not left in plaintext
/// on the server (ADR 0001: device names are a sealed record). The pairing request carried the
/// name in the clear (`PairingRequest::name`); the server stored the request in its `pairing`
/// table and kept the row after the offer was answered, until a later reservation of any
/// account deleted expired rows (`service/pairing.rs`). Now the name is sealed under a key
/// derived from the pairing secret, and the inviting device closes the slot once answered.
#[test]
fn a_pairing_leaves_no_device_name_on_the_server() {
    let scratch = Scratch::new("pairing");
    let clock = TestClock::default();
    let mut server = TestServer::start(scratch.0.join("server"));
    let mut a = Peer::open(&scratch.0, "a", &clock);
    create_account(&mut a, &server, "Laptop A");
    let mut b = Peer::open(&scratch.0, "b", &clock);
    let name = "Desktop e2e-name-7b2d";
    pair(&mut a, &mut b, name, &clock);
    run_rounds(&mut [&mut a, &mut b], &clock, 2);
    server.stop();
    // The answered slot was closed at once, long before it expires.
    let db = rusqlite::Connection::open(server.data_dir.join("drive.sqlite3")).expect("database");
    let open: i64 = db
        .query_row("SELECT COUNT(*) FROM pairing", [], |row| row.get(0))
        .expect("pairing slots");
    assert_eq!(open, 0, "the answered slot was closed");
    drop(db);
    let hits = files_containing(&server.data_dir, name.as_bytes());
    assert!(
        hits.is_empty(),
        "the device name is in plaintext in {hits:?}"
    );
}

#[test]
fn the_core_flow_works_against_the_real_server() {
    // Declared first, dropped last: engines and server close their files before it is removed.
    let scratch = Scratch::new("flow");
    let mut steps = Steps::new();
    let clock = TestClock::default();
    let mut server = TestServer::start(scratch.0.join("server"));
    let host = format!("localhost:{}", server.port());

    // -- 1. The operator's invite; A creates the account with the recovery group check. -----
    let invite = server.invite();
    let mut a = Peer::open(&scratch.0, "a", &clock);
    assert_eq!(a.core.snapshot().setup, SetupState::Needed);
    assert!(matches!(
        a.core.check_invite(&invite),
        ApiResult::Ok(ref c) if c.host == host && !c.pinned && !c.punycode
    ));
    let ApiResult::Ok(code) = a.core.begin_account(&invite, "Laptop A").expect("begin") else {
        panic!("the invite was refused");
    };
    assert_eq!(code.groups.len(), 8);
    assert!((2..=8).contains(&code.check_group));
    assert_eq!(code.sheet.server_id, server.server_id_hex());
    assert_eq!(code.sheet.server_url, server.url());
    assert!(code.sheet.link.starts_with("hangar-drive://recover#"));
    assert!(
        !code.sheet.link.contains(&code.groups.join("")),
        "the sheet's link never carries the code"
    );
    assert!(!a.core.confirm_recovery_group("0000").expect("wrong group"));
    assert_eq!(a.core.snapshot().setup, SetupState::Needed);
    let group = code.groups[code.check_group as usize - 1].clone();
    assert!(a
        .core
        .confirm_recovery_group(&group.to_ascii_lowercase())
        .expect("group check"));
    assert_eq!(a.core.snapshot().setup, SetupState::Done);
    let account = a.core.snapshot().account.expect("account info");
    assert_eq!(account.host, host);
    // The invite is single-use: a second installation gets as far as the code, then the
    // server refuses the account.
    {
        let mut late = Peer::open(&scratch.0, "late", &clock);
        let ApiResult::Ok(late_code) = late.core.begin_account(&invite, "Late").expect("begin")
        else {
            panic!("begin");
        };
        let late_group = late_code.groups[late_code.check_group as usize - 1].clone();
        assert!(
            late.core.confirm_recovery_group(&late_group).is_err(),
            "a used invite must not create a second account"
        );
        assert_eq!(late.core.snapshot().setup, SetupState::Needed);
    }
    steps.done("1 account");

    // -- 2. A adds a folder and writes small, multi-chunk, Unicode and nested files. --------
    let folder = a
        .core
        .add_folder(&a.root_text(), "E2E Docs")
        .expect("add folder");
    let notes_v1 = format!("First version of the notes.\n{MARKER}\n").into_bytes();
    // 9 MiB and a bit: three chunks of the 4 MiB chunker, the marker at both ends.
    let mut big = noise(9 * 1024 * 1024 + 12_345, 7);
    big[..MARKER.len()].copy_from_slice(MARKER.as_bytes());
    let end = big.len() - MARKER.len();
    big[end..].copy_from_slice(MARKER.as_bytes());
    let unicode_dir = "\u{dc}n\u{ef}c\u{f6}d\u{e9} Ordner";
    let unicode_file = "Gr\u{fc}\u{df}e \u{65e5}\u{672c}\u{8a9e} \u{2713}.txt";
    let unicode_path = format!("{unicode_dir}/{unicode_file}");
    let unicode_content = format!("Unicode content \u{2713} {MARKER}").into_bytes();
    a.write("notes.txt", &notes_v1);
    a.write("big/archive.bin", &big);
    a.write(&unicode_path, &unicode_content);
    a.write("sub/deeper/leaf.txt", b"leaf content");
    a.write("sub/empty.txt", b"");
    a.write("old/obsolete.txt", b"obsolete content");
    a.write("old/also-old.md", b"# old notes");
    let step2 = a.files();
    let expected: BTreeSet<String> = step2
        .keys()
        .map(|k| k.trim_end_matches('/').to_owned())
        .collect();
    wait_for(
        &mut [&mut a],
        &clock,
        "A's first files on the server",
        |p| {
            let up = p[0].core.snapshot().folders[0].status == FolderStatus::UpToDate;
            let head = p[0].head_paths(&folder)?;
            (up && expected.is_subset(&head)).then_some(())
        },
    );
    steps.done("2 folder and files");

    // -- 3. Pairing: A offers (slot reserved), B joins, both confirm, B gets the folder. -----
    let offer = a.core.create_pairing_offer().expect("offer");
    assert_eq!(offer.code.len(), 8);
    assert_eq!(offer.host, host);
    let mut b = Peer::open(&scratch.0, "b", &clock);
    let ApiResult::Ok(InspectedLink::Pair {
        host: offer_host,
        account: offer_account,
        pinned,
    }) = b.core.inspect_link(&offer.link)
    else {
        panic!("the offer does not read");
    };
    assert_eq!(offer_host, host);
    assert_eq!(offer_account, offer.account);
    assert!(!pinned);
    let ApiResult::Ok(safety_b) = b
        .core
        .start_pairing(&offer.link, "Desktop B")
        .expect("start pairing")
    else {
        panic!("pairing refused");
    };
    let request = wait_for(&mut [&mut a], &clock, "the pair request on A", |p| {
        p[0].events.iter().find_map(|e| match e {
            BackendEvent::PairRequest { request } => Some(request.clone()),
            _ => None,
        })
    });
    assert_eq!(request.device_name, "Desktop B");
    assert_eq!(
        request.safety, safety_b,
        "both devices show the same number"
    );
    a.core
        .answer_pair_request(&request.offer_id, true)
        .expect("accept");
    let joined = wait_for(&mut [&mut b], &clock, "B joining", |p| {
        p[0].events.iter().find_map(|e| match e {
            BackendEvent::PairResult {
                result: PairResult::Joined { devices },
            } => Some(devices.clone()),
            BackendEvent::PairResult {
                result: PairResult::Failed { error },
            } => panic!("pairing failed: {error:?}"),
            _ => None,
        })
    });
    // B confirms the devices: itself and A.
    assert_eq!(joined.len(), 2, "{joined:?}");
    assert!(joined.iter().any(|d| d.is_this && d.name == "Desktop B"));
    assert!(joined.iter().any(|d| !d.is_this && d.name == "Laptop A"));
    assert_eq!(a.core.list_devices().expect("devices").devices.len(), 2);
    let remote = b.core.snapshot().remote_folders;
    assert!(
        remote
            .iter()
            .any(|f| f.id == folder && f.name == "E2E Docs"),
        "{remote:?}"
    );
    b.core
        .add_account_folder(&folder, &b.root_text())
        .expect("B joins the folder");
    wait_for(&mut [&mut a, &mut b], &clock, "B with A's files", |p| {
        (p[1].files() == step2).then_some(())
    });
    assert_eq!(b.files().get("big/archive.bin"), Some(&big), "byte equal");
    let before_changes = a.head_id(&folder);
    steps.done("3 pairing");

    // -- 4. B changes, moves and deletes; A sees the same, deletes are trashed. --------------
    let notes_v2 = b"Second version, edited on B.\n".to_vec();
    b.write("notes.txt", &notes_v2);
    std::fs::rename(
        b.path("sub/deeper/leaf.txt"),
        b.path(&format!("{unicode_dir}/leaf.txt")),
    )
    .expect("move a file");
    std::fs::rename(b.path("big"), b.path("large")).expect("rename a directory");
    std::fs::remove_dir_all(b.path("old")).expect("delete a directory");
    let step4 = b.files();
    assert!(step4.contains_key("large/archive.bin") && !step4.contains_key("old/"));
    wait_for(&mut [&mut a, &mut b], &clock, "A with B's changes", |p| {
        (p[0].files() == step4 && p[1].files() == step4).then_some(())
    });
    {
        let log = a.fs_log.lock().expect("log");
        assert!(
            log.removed.is_empty(),
            "incoming deletes are never deleted for good: {:?}",
            log.removed
        );
        for (name, content) in [
            ("old/obsolete.txt", b"obsolete content".as_slice()),
            ("old/also-old.md", b"# old notes".as_slice()),
        ] {
            let t = log
                .trashed
                .iter()
                .find(|t| t.path == name)
                .unwrap_or_else(|| panic!("{name} was not trashed: {:?}", log.trashed));
            eprintln!("e2e: A put {name} into {:?}", t.to);
            if t.to == Trashed::Quarantine {
                let file = name.rsplit('/').next().expect("name");
                let kept = a
                    .root
                    .join(".hangar-drive")
                    .join("trash")
                    .join(t.item.to_hex())
                    .join(file);
                assert_eq!(std::fs::read(&kept).expect("quarantined file"), content);
            }
        }
    }
    let trash = a.core.get_trash(&folder, 50).expect("trash");
    for name in ["obsolete.txt", "also-old.md"] {
        assert!(
            trash.iter().any(|t| t.name == name && t.dir == "old"),
            "{name} restorable from the history: {trash:?}"
        );
    }
    steps.done("4 change, move, delete");

    // -- 5. Both edit the same file while the server is down: one conflict copy, nothing lost.
    server.stop();
    let a_offline = b"Offline edit on A.\n".to_vec();
    let b_offline = b"Offline edit on B, a little longer.\n".to_vec();
    a.write("notes.txt", &a_offline);
    b.write("notes.txt", &b_offline);
    // Two minutes without an answer: the window shows the server as silent. (Each pass against
    // the stopped server takes several seconds on Windows, where a refused connection to
    // localhost is retried by the system, so there is one pass per device.)
    clock.skip(150_000);
    a.tick();
    b.tick();
    for p in [&a, &b] {
        let connection = p.core.snapshot().sync.connection;
        assert!(
            matches!(connection, Connection::ServerSilent { .. }),
            "{}: {connection:?}",
            p.label
        );
    }
    server.restart();
    wait_for(
        &mut [&mut a, &mut b],
        &clock,
        "the conflict on both devices",
        |p| {
            let done = same_files(p)
                && p.iter().all(|x| {
                    x.core.list_conflicts().len() == 1
                        && x.core.snapshot().sync.connection == Connection::Online
                });
            done.then_some(())
        },
    );
    for p in [&a, &b] {
        let groups = p.core.list_conflicts();
        assert_eq!(groups.len(), 1, "{}: {groups:?}", p.label);
        let group = &groups[0];
        assert_eq!(group.path, "notes.txt");
        assert_eq!(group.versions.len(), 2, "exactly one copy: {group:?}");
        assert!(group.versions[0].original && !group.versions[1].original);
    }
    let files = a.files();
    let with = |content: &[u8]| {
        files
            .iter()
            .filter(|(_, c)| c.as_slice() == content)
            .count()
    };
    assert_eq!(
        with(&a_offline),
        1,
        "A's edit kept once\n{}",
        listing(&files)
    );
    assert_eq!(
        with(&b_offline),
        1,
        "B's edit kept once\n{}",
        listing(&files)
    );
    assert_eq!(files.len(), step4.len() + 1, "one more file: the copy");
    let group = a.core.list_conflicts().remove(0);
    a.core.keep_both_conflict(&group.id).expect("keep both");
    wait_for(
        &mut [&mut a, &mut b],
        &clock,
        "the conflict resolved",
        |p| {
            p.iter()
                .all(|x| x.core.list_conflicts().is_empty())
                .then_some(())
        },
    );
    steps.done("5 offline conflict");

    // -- 6. A deletes more than 100 files: held until the person decides. -------------------
    for i in 0..120 {
        a.write(
            &format!("bulk/file-{i:03}.txt"),
            format!("bulk {i}").as_bytes(),
        );
    }
    wait_for(&mut [&mut a, &mut b], &clock, "the bulk files on B", |p| {
        (same_files(p) && p[1].files().contains_key("bulk/file-119.txt")).then_some(())
    });
    let with_bulk = b.files();
    std::fs::remove_dir_all(a.path("bulk")).expect("delete the bulk files");
    let held = wait_for(
        &mut [&mut a, &mut b],
        &clock,
        "the mass delete warning",
        |p| {
            p[0].core
                .snapshot()
                .warnings
                .into_iter()
                .find_map(|w| match w {
                    Warning::MassDelete {
                        folder_id, count, ..
                    } if folder_id == folder => Some(count),
                    _ => None,
                })
        },
    );
    assert!(held >= 120, "{held} deletes held");
    let names = a.core.list_mass_delete(&folder).expect("held names");
    assert!(
        (0..120).all(|i| names.contains(&format!("bulk/file-{i:03}.txt"))),
        "{names:?}"
    );
    // Nothing is deleted anywhere while the decision is open.
    run_rounds(&mut [&mut a, &mut b], &clock, 15);
    assert_eq!(b.files(), with_bulk, "B keeps every file");
    let head = a.head_paths(&folder).expect("head");
    assert!(head.contains("bulk/file-000.txt") && head.contains("bulk/file-119.txt"));
    assert!(a.has_warning(|w| matches!(w, Warning::MassDelete { .. })));
    // The person keeps the files: they come back on A.
    let n = a.core.resolve_mass_delete(&folder, true).expect("decide");
    assert!(n >= 120);
    wait_for(
        &mut [&mut a, &mut b],
        &clock,
        "the bulk files back on A",
        |p| {
            let back = p[0].files() == with_bulk && p[1].files() == with_bulk;
            (back && !p[0].has_warning(|w| matches!(w, Warning::MassDelete { .. }))).then_some(())
        },
    );
    steps.done("6 mass delete held");

    // -- 7. Restore: an earlier version of a file, a whole directory, the whole folder. ------
    let timeline = a.core.get_timeline(&folder, 500).expect("timeline");
    let mut first_notes = None;
    for entry in timeline.entries.iter().rev() {
        let tree = a.core.get_tree_at(&folder, &entry.id).expect("tree");
        if tree.nodes.iter().any(|n| n.path == "notes.txt") {
            first_notes = Some(entry.id.clone());
            break;
        }
    }
    let first_notes = first_notes.expect("a version with notes.txt");
    let outcome = a
        .core
        .restore_file(&folder, &first_notes, "notes.txt")
        .expect("restore a file");
    let RestoreOutcome::Done {
        count, renamed_to, ..
    } = outcome
    else {
        panic!("restore of a file: {outcome:?}");
    };
    assert_eq!(count, 1);
    let restored_name = renamed_to.unwrap_or_else(|| "notes.txt".into());
    eprintln!("e2e: the first version came back as {restored_name}");
    wait_for(&mut [&mut a, &mut b], &clock, "the first notes back", |p| {
        let ok = same_files(p) && p[0].files().get(&restored_name) == Some(&notes_v1);
        ok.then_some(())
    });
    let after_file_restore = a.files();
    let after_file_restore_head = a.head_id(&folder);
    let outcome = a
        .core
        .restore_file(&folder, &before_changes, "old")
        .expect("restore a directory");
    assert!(
        matches!(outcome, RestoreOutcome::Done { .. }),
        "restore of a directory: {outcome:?}"
    );
    wait_for(
        &mut [&mut a, &mut b],
        &clock,
        "the old directory back",
        |p| {
            let f = p[0].files();
            let ok = same_files(p)
                && f.get("old/obsolete.txt").map(Vec::as_slice)
                    == Some(b"obsolete content".as_slice())
                && f.get("old/also-old.md").map(Vec::as_slice) == Some(b"# old notes".as_slice());
            ok.then_some(())
        },
    );
    // The whole folder back to the state before the directory came back.
    let outcome = a
        .core
        .reset_folder(&folder, &after_file_restore_head)
        .expect("reset the folder");
    assert!(
        matches!(outcome, RestoreOutcome::Done { .. }),
        "reset of the folder: {outcome:?}"
    );
    wait_for(&mut [&mut a, &mut b], &clock, "the folder reset", |p| {
        (p[0].files() == after_file_restore && p[1].files() == after_file_restore).then_some(())
    });
    steps.done("7 restore");

    // -- 8. A removes B: B uploads nothing any more, A writes the barriers. ------------------
    let account_id = AccountId::from_hex(&offer.account).expect("account id");
    let b_id = a.device_id("Desktop B");
    let a_id = a.device_id("Laptop A");
    // A session of B's own key, signed in before the removal (what B's engine holds).
    let identity_bytes = b
        .keychain
        .0
        .borrow()
        .get("device-identity")
        .cloned()
        .expect("B's identity in its keychain");
    let b_identity = DeviceIdentity::import(&identity_bytes).expect("identity");
    let mut config = ServerConfig::new(&server.url(), None).expect("config");
    config.retry = RetryPolicy {
        attempts: 1,
        ..RetryPolicy::default()
    };
    let mut b_session = HttpServer::new(
        config,
        Some(SessionIdentity {
            account: account_id,
            device: DeviceId::from_hex(&b_id).expect("device id"),
            prover: prover(b_identity),
        }),
    )
    .expect("client");
    let folder_id = FolderId::from_hex(&folder).expect("folder id");
    let probe = ObjectId::from_bytes([0x42; 32]);
    b_session
        .feed(0)
        .expect("B is signed in before the removal");
    b_session
        .missing_objects(&folder_id, &[probe])
        .expect("B may upload before the removal");
    let head_before = a.head_id(&folder);
    a.core.remove_device(&b_id).expect("remove B");
    let devices = a.core.list_devices().expect("devices").devices;
    assert!(devices.iter().all(|d| d.id != b_id), "{devices:?}");
    let head_after = a.head_id(&folder);
    assert_ne!(head_before, head_after, "the barrier is a new head");
    let barrier = a
        .core
        .get_timeline(&folder, 1)
        .expect("timeline")
        .entries
        .remove(0);
    assert_eq!(barrier.device, "Laptop A", "A wrote the barrier");
    // The server refuses B's session, old token or new sign-in; B's own new proof learns that
    // it was removed (E2E-3).
    let refused = b_session.feed(0).expect_err("feed after the removal");
    assert_eq!(
        refused.code(),
        Some(ErrorCode::DeviceRemoved),
        "{refused:?}"
    );
    let refused = b_session
        .missing_objects(&folder_id, &[probe])
        .expect_err("upload check after the removal");
    assert!(is_auth_refusal(&refused), "{refused:?}");
    let refused = b_session
        .put_object(&folder_id, &probe, &[0u8; 64])
        .expect_err("upload after the removal");
    assert!(is_auth_refusal(&refused), "{refused:?}");
    // B's engine keeps running: it shows that it was removed and forgets the account (E2E-3),
    // and a new file never reaches A.
    b.write("written-after-removal.txt", b"must not arrive");
    wait_for(
        &mut [&mut a, &mut b],
        &clock,
        "B showing it was removed",
        |p| {
            p[1].has_warning(|w| matches!(w, Warning::Removed { .. }))
                .then_some(())
        },
    );
    assert_eq!(b.core.snapshot().setup, SetupState::Needed);
    assert!(!b.keychain.0.borrow().contains_key("device-identity"));
    run_rounds(&mut [&mut a, &mut b], &clock, 4);
    assert!(!a.files().contains_key("written-after-removal.txt"));
    let head = a.head_paths(&folder).expect("head");
    assert!(!head.contains("written-after-removal.txt"));
    assert!(
        a.core
            .snapshot()
            .warnings
            .iter()
            .all(|w| !matches!(w, Warning::RemovedHeads { .. } | Warning::MassDelete { .. })),
        "{:?}",
        a.core.snapshot().warnings
    );
    steps.done("8 remove B");

    // -- 9. Recovery: C uses the sheet (version 2) and the code, gets the files, removes the
    //       lost devices. -------------------------------------------------------------------
    let expected_c = a.files();
    let mut c = Peer::open(&scratch.0, "c", &clock);
    assert!(matches!(
        c.core.inspect_link(&code.sheet.link),
        ApiResult::Ok(InspectedLink::Recover { ref account, ref host, .. })
            if *account == offer.account && *host == format!("localhost:{}", server.port())
    ));
    let code_text = code.groups.join("-");
    let typo = format!("{}X", &code_text[..code_text.len() - 1]);
    assert_eq!(
        c.core
            .recover_account(&code.sheet.link, &typo, "Rescue C")
            .expect("typo"),
        ApiResult::Err(RecoverError::Typo)
    );
    assert_eq!(
        c.core
            .recover_account(&code.sheet.link, &code_text, "Rescue C")
            .expect("recover"),
        ApiResult::Ok(())
    );
    let lost = c.core.recovery_devices().expect("old devices");
    assert_eq!(lost.len(), 1, "only A is left to remove: {lost:?}");
    assert_eq!(lost[0].id, a_id);
    let renewed = c
        .core
        .finish_recovery_cleanup(std::slice::from_ref(&a_id))
        .expect("cleanup");
    assert_ne!(renewed.groups, code.groups);
    assert_eq!(renewed.sheet.account_id, code.sheet.account_id);
    let renewed_group = renewed.groups[renewed.check_group as usize - 1].clone();
    assert!(c
        .core
        .confirm_recovery_group(&renewed_group)
        .expect("renewed group"));
    let devices = c.core.list_devices().expect("devices").devices;
    assert_eq!(devices.len(), 1, "{devices:?}");
    assert!(devices[0].is_this, "{devices:?}");
    assert_eq!(devices[0].name, "Rescue C", "E2E-4: {devices:?}");
    assert!(c
        .core
        .snapshot()
        .remote_folders
        .iter()
        .any(|f| f.id == folder));
    c.core
        .add_account_folder(&folder, &c.root_text())
        .expect("C syncs the folder");
    wait_for(&mut [&mut c], &clock, "C with the account's files", |p| {
        (p[0].files() == expected_c).then_some(())
    });
    let snap = c.core.snapshot();
    assert!(
        snap.folders.iter().all(|f| f.status
            != FolderStatus::Stopped {
                reason: StopReasonApi::RemovedHeads
            }),
        "the barriers cover the removed devices' heads: {:?}",
        snap.folders
    );
    assert!(
        snap.warnings
            .iter()
            .all(|w| !matches!(w, Warning::RemovedHeads { .. })),
        "{:?}",
        snap.warnings
    );
    assert_eq!(c.files().get("large/archive.bin"), Some(&big));
    // The used code is spent, and the window says so (E2E-5).
    {
        let mut again = Peer::open(&scratch.0, "again", &clock);
        let answer = again
            .core
            .recover_account(&code.sheet.link, &code_text, "Again")
            .expect("used code");
        assert_eq!(answer, ApiResult::Err(RecoverError::Used));
        assert_eq!(again.core.snapshot().setup, SetupState::Needed);
    }
    // A, removed by C, uploads nothing any more either, and shows that it was removed (E2E-3).
    a.write("written-by-removed-a.txt", b"must not arrive");
    wait_for(
        &mut [&mut a, &mut c],
        &clock,
        "A showing it was removed",
        |p| {
            p[0].has_warning(|w| matches!(w, Warning::Removed { .. }))
                .then_some(())
        },
    );
    run_rounds(&mut [&mut a, &mut c], &clock, 5);
    assert!(!c.files().contains_key("written-by-removed-a.txt"));
    steps.done("9 recovery");

    // -- 10. A second device D pairs with C; the server restarts; both keep syncing. --------
    let offer = c.core.create_pairing_offer().expect("offer");
    let mut d = Peer::open(&scratch.0, "d", &clock);
    let ApiResult::Ok(_) = d
        .core
        .start_pairing(&offer.link, "Tablet D")
        .expect("start pairing")
    else {
        panic!("pairing refused");
    };
    let request = wait_for(&mut [&mut c], &clock, "the pair request on C", |p| {
        p[0].events.iter().find_map(|e| match e {
            BackendEvent::PairRequest { request } => Some(request.clone()),
            _ => None,
        })
    });
    c.core
        .answer_pair_request(&request.offer_id, true)
        .expect("accept");
    wait_for(&mut [&mut d], &clock, "D joining", |p| {
        p[0].events.iter().find_map(|e| match e {
            BackendEvent::PairResult {
                result: PairResult::Joined { .. },
            } => Some(()),
            BackendEvent::PairResult {
                result: PairResult::Failed { error },
            } => panic!("pairing failed: {error:?}"),
            _ => None,
        })
    });
    d.core
        .add_account_folder(&folder, &d.root_text())
        .expect("D syncs the folder");
    wait_for(&mut [&mut c, &mut d], &clock, "D with the files", |p| {
        (p[1].files() == expected_c).then_some(())
    });
    server.restart();
    c.write("after-restart-c.txt", b"written on C after the restart");
    d.write("after-restart-d.txt", b"written on D after the restart");
    wait_for(
        &mut [&mut c, &mut d],
        &clock,
        "C and D after the restart",
        |p| {
            let f = p[0].files();
            let ok = same_files(p)
                && f.contains_key("after-restart-c.txt")
                && f.contains_key("after-restart-d.txt");
            ok.then_some(())
        },
    );
    for p in [&c, &d] {
        assert_eq!(p.core.snapshot().sync.connection, Connection::Online);
    }
    steps.done("10 server restart");

    // -- 11. No plaintext in the server's data folder. ---------------------------------------
    server.stop();
    let data = server.data_dir.clone();
    let (bytes, count) = dir_size(&data);
    assert!(
        bytes > big.len() as u64 && count > 3,
        "the data folder holds the objects ({bytes} bytes in {count} files)"
    );
    let mut needles: Vec<(String, Vec<u8>)> = vec![
        ("marker".into(), MARKER.as_bytes().to_vec()),
        ("folder name".into(), b"E2E Docs".to_vec()),
        ("notes v2".into(), notes_v2.clone()),
        ("A's offline edit".into(), a_offline.clone()),
        ("B's offline edit".into(), b_offline.clone()),
        (
            "big file, middle".into(),
            big[5_000_000..5_000_064].to_vec(),
        ),
    ];
    for name in [
        "notes.txt",
        "archive.bin",
        "leaf.txt",
        "empty.txt",
        "obsolete.txt",
        "also-old.md",
        "file-000.txt",
        "after-restart-c.txt",
        "written-after-removal.txt",
        unicode_dir,
        unicode_file,
    ] {
        needles.push((format!("name {name}"), name.as_bytes().to_vec()));
    }
    let mut leaks = Vec::new();
    for (what, needle) in &needles {
        for hit in files_containing(&data, needle) {
            leaks.push(format!("{what} in {}", hit.display()));
        }
    }
    // Device names are sealed records only, those of paired devices as well (E2E-6).
    for name in ["Laptop A", "Desktop B", "Rescue C", "Tablet D"] {
        for hit in files_containing(&data, name.as_bytes()) {
            leaks.push(format!("device name {name} in {}", hit.display()));
        }
    }
    assert!(
        leaks.is_empty(),
        "plaintext on the server:\n{}",
        leaks.join("\n")
    );
    steps.done("11 plaintext search");
}
