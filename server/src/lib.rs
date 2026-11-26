//! The Hangar Drive sync server (ADR 0001): accounts and devices, the device log, sealed
//! records, encrypted objects, the commit log with one head per folder, the account change feed
//! with SSE, retention and garbage collection, and the admin CLI in the same binary.
//!
//! Layers: `http` parses and answers, `service` holds every rule, `db` and `store` keep data.
//! Operations: `docs/self-hosting.md`.

#![deny(unsafe_code)]

pub mod app;
pub mod clock;
pub mod config;
pub mod db;
pub mod disk;
pub mod error;
pub mod events;
pub mod http;
pub mod links;
pub mod probe;
pub mod service;
pub mod store;
pub mod tls;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use app::{App, AppState, ObjectLocks, StagingBytes, StateCache, UploadSlots};
use clock::{Clock, SystemClock};
use config::Config;
use disk::{DiskSpace, FsDiskSpace};
use events::EventHub;
use http::ratelimit::RateLimiter;
use store::FsStore;

/// Version of this server program, as reported at the health endpoint.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long a client may take to send a request's headers; also how long an idle keep-alive
/// connection stays open (hyper starts this timer whenever it waits for the next request).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a TLS handshake may take.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections served at once; beyond it the server stops accepting until one closes.
pub const MAX_CONNECTIONS: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("data folder {0}: {1}")]
    DataDir(String, std::io::Error),
    #[error(transparent)]
    Db(#[from] db::DbError),
    #[error("database: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error(
        "{var} is not set. Set it to the address devices reach this server under, for example \
         {var}=https://drive.example.org/ (http://localhost:8080/ only for a test on this \
         machine): every sign-in is bound to it, so a host that relays sign-ins under this \
         server's ID is refused",
        var = config::PUBLIC_URL_VAR
    )]
    PublicUrlMissing,
}

/// Why the data folder lock was not taken.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error(
        "the server is running on this data folder; stop it first (docker compose stop server)"
    )]
    InUse,
    #[error("data folder lock {0}: {1}")]
    Io(String, std::io::Error),
}

/// An exclusive lock on `server.lock` in the data folder (finding L5). `serve` holds it for its
/// whole life, and the admin commands that delete data (`gc`, `purge`) take it too, so such a
/// command never runs beside a serving process: the server keeps per-object locks and caches in
/// memory that another process would not see. The operating system drops the lock when the
/// process ends, also after a crash, so no stale lock file can block a restart.
#[derive(Debug)]
pub struct DataDirLock {
    _file: std::fs::File,
}

impl DataDirLock {
    pub const FILE: &'static str = "server.lock";

    pub fn acquire(data_dir: &std::path::Path) -> Result<Self, LockError> {
        let path = data_dir.join(Self::FILE);
        let io = |e: std::io::Error| LockError::Io(path.display().to_string(), e);
        std::fs::create_dir_all(data_dir).map_err(io)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(io)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(LockError::InUse),
            Err(std::fs::TryLockError::Error(e)) => Err(io(e)),
        }
    }
}

/// What tests replace: the clock, the disk probe and the rate limiter.
pub struct Deps {
    pub clock: Arc<dyn Clock>,
    pub disk: Option<Arc<dyn DiskSpace>>,
    pub limiter: RateLimiter,
    /// Start the garbage collection job (off in tests that drive steps themselves).
    pub gc_job: bool,
}

impl Default for Deps {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            disk: None,
            limiter: RateLimiter::new(),
            gc_job: true,
        }
    }
}

/// A built server, ready to serve.
pub struct Server {
    pub app: AppState,
    pub router: Router,
    shutdown: watch::Sender<bool>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    header_timeout: Duration,
    grace: Duration,
    lock: DataDirLock,
}

/// Opens the data folder and the database and builds the app (shared by `serve` and the CLI).
pub async fn open_app(
    config: &Config,
    deps: Deps,
) -> Result<(AppState, watch::Sender<bool>), StartError> {
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| StartError::DataDir(config.data_dir.display().to_string(), e))?;
    let db = db::connect(&config.database_path()).await?;
    let store = FsStore::open(config.objects_dir(), config.data_dir.join("staging"))
        .map_err(|e| StartError::DataDir(config.data_dir.display().to_string(), e))?;
    let server_id = service::accounts::ensure_server_id(&db).await?;
    let server_secret = app::load_or_create_secret(&config.data_dir.join("server.secret"))
        .map_err(|e| StartError::DataDir(config.data_dir.display().to_string(), e))?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let disk = deps
        .disk
        .unwrap_or_else(|| Arc::new(FsDiskSpace::new(&config.data_dir)));
    let app = Arc::new(App {
        db,
        store: Arc::new(store),
        clock: deps.clock,
        disk,
        limits: config.limits,
        server_id,
        public_url: config.public_url.clone(),
        trusted_proxies: config.trusted_proxies.clone(),
        limiter: deps.limiter,
        events: EventHub::new(),
        states: StateCache::default(),
        object_locks: ObjectLocks::default(),
        server_secret,
        heavy: Arc::new(tokio::sync::Semaphore::new(
            usize::try_from(config.concurrency.heavy_requests).unwrap_or(1),
        )),
        heavy_accounts: UploadSlots::default(),
        uploads: UploadSlots::default(),
        staging: StagingBytes::default(),
        concurrency: config.concurrency,
        shutdown: shutdown_rx,
    });
    Ok((app, shutdown))
}

/// Builds the server for `config`. Refuses without [`Config::public_url`]: the session proofs
/// are bound to that address (ADR 0001, section 6, "Server URL").
pub async fn build(config: &Config, deps: Deps) -> Result<Server, StartError> {
    if config.public_url.is_none() {
        return Err(StartError::PublicUrlMissing);
    }
    let gc_job = deps.gc_job;
    let lock = DataDirLock::acquire(&config.data_dir)?;
    let (app, shutdown) = open_app(config, deps).await?;
    if app.disk.available().is_none() {
        tracing::warn!(
            "free disk space is unknown on this platform; the disk reserve is not enforced"
        );
    }
    let tls = match &config.tls {
        Some(files) => Some(tokio_rustls::TlsAcceptor::from(tls::server_config(
            &files.cert,
            &files.key,
        )?)),
        None => None,
    };
    if gc_job {
        tokio::spawn(service::retention::run_job(app.clone(), config.gc_interval));
    }
    Ok(Server {
        router: http::router(app.clone()),
        app,
        shutdown,
        tls,
        header_timeout: HEADER_READ_TIMEOUT,
        grace: config.shutdown_grace,
        lock,
    })
}

impl Server {
    /// Shorter header and idle timeout (tests).
    pub fn with_header_timeout(mut self, timeout: Duration) -> Self {
        self.header_timeout = timeout;
        self
    }

    /// Whether the server terminates TLS itself.
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }
}

/// Serves until `signal` completes, then stops accepting, ends the SSE streams and waits up to
/// the shutdown grace period for open requests. Not `axum::serve`: it sets no timer, so a
/// client could hold a socket by sending its headers byte by byte (slowloris), and it has no
/// TLS.
pub async fn serve(
    server: Server,
    listener: TcpListener,
    signal: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let Server {
        app,
        router,
        shutdown,
        tls,
        header_timeout,
        grace,
        lock,
    } = server;
    let per_ip = Arc::new(PeerConnections::default());
    let (stop, stopped) = watch::channel(false);
    let (alive, mut open) = mpsc::channel::<()>(1);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    tokio::pin!(signal);
    loop {
        let permit = tokio::select! {
            permit = slots.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
            () = &mut signal => break,
        };
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut signal => break,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "accepting a connection failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // Connections per client address (finding M6). A trusted proxy carries many clients
        // over its own address and limits them itself (`limit_conn` in the proxy examples).
        let peer_slot = if app.trusted_proxies.iter().any(|n| n.contains(peer.ip())) {
            None
        } else {
            match per_ip.take(
                http::client_ip::rate_key(Some(peer.ip())),
                app.concurrency.connections_per_ip,
            ) {
                Some(slot) => Some(slot),
                None => {
                    drop(stream);
                    continue;
                }
            }
        };
        let _ = stream.set_nodelay(true);
        let service = TowerToHyperService::new(tower::Layer::layer(
            &axum::Extension(axum::extract::ConnectInfo(peer)),
            router.clone(),
        ));
        let mut stopped = stopped.clone();
        let alive = alive.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _peer_slot = peer_slot;
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout);
            match tls {
                None => {
                    let connection = builder.serve_connection(TokioIo::new(stream), service);
                    drive(connection, &mut stopped).await;
                }
                Some(acceptor) => {
                    let Ok(Ok(stream)) =
                        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                    else {
                        return;
                    };
                    let connection = builder.serve_connection(TokioIo::new(stream), service);
                    drive(connection, &mut stopped).await;
                }
            }
            drop(alive);
        });
    }
    drop(listener);
    tracing::info!("shutting down: closing connections");
    // Ends the SSE streams and the background job first, then lets requests in flight finish.
    let _ = shutdown.send(true);
    let _ = stop.send(true);
    drop(alive);
    if tokio::time::timeout(grace, open.recv()).await.is_err() {
        tracing::warn!("requests still open after the shutdown grace period");
    }
    app.db.close().await;
    drop(lock);
    Ok(())
}

/// Open connections per client address key.
#[derive(Default)]
struct PeerConnections {
    open: std::sync::Mutex<std::collections::HashMap<Vec<u8>, u32>>,
}

struct PeerSlot {
    owner: Arc<PeerConnections>,
    key: Vec<u8>,
}

impl PeerConnections {
    fn take(self: &Arc<Self>, key: Vec<u8>, max: u32) -> Option<PeerSlot> {
        let mut open = self.open.lock().ok()?;
        let count = open.entry(key.clone()).or_insert(0);
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(PeerSlot {
            owner: self.clone(),
            key,
        })
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        if let Ok(mut open) = self.owner.open.lock() {
            if let Some(count) = open.get_mut(&self.key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    open.remove(&self.key);
                }
            }
        }
    }
}

async fn drive<I, S>(
    connection: hyper::server::conn::http1::Connection<I, S>,
    stopped: &mut watch::Receiver<bool>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::service::HttpService<hyper::body::Incoming>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S::ResBody: 'static,
    <S::ResBody as hyper::body::Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut connection = std::pin::pin!(connection);
    tokio::select! {
        _ = connection.as_mut() => {}
        _ = async { stopped.wait_for(|stop| *stop).await.map(|_| ()) } => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}
