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
/// How long a TLS handshake may take: a handshake of TLS 1.3 is one round trip, and a slow one
/// holds a connection slot before any limit sees a request (server security review, LOW 1).
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
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
    /// Wraps the file system store (tests that stop the store at a chosen moment); `None`
    /// uses it as it is.
    pub store_layer: Option<StoreLayer>,
    /// Points where tests stop a call ([`app::Hooks`]).
    pub hooks: app::Hooks,
}

/// A wrapper around the object store ([`Deps::store_layer`]).
pub type StoreLayer =
    Box<dyn FnOnce(Arc<dyn store::ObjectStore>) -> Arc<dyn store::ObjectStore> + Send>;

impl Default for Deps {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            disk: None,
            limiter: RateLimiter::new(),
            gc_job: true,
            store_layer: None,
            hooks: app::Hooks::default(),
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
    prepare_data_dir(&config.data_dir)
        .map_err(|e| StartError::DataDir(config.data_dir.display().to_string(), e))?;
    let db = db::connect(&config.database_path()).await?;
    let store = FsStore::open(config.objects_dir(), config.data_dir.join("staging"))
        .map_err(|e| StartError::DataDir(config.data_dir.display().to_string(), e))?;
    let server_id = service::accounts::ensure_server_id(&db).await?;
    let server_secret = app::load_or_create_secret(&config.data_dir.join("server.secret"))
        .map_err(|e| StartError::DataDir(config.data_dir.display().to_string(), e))?;
    let store: Arc<dyn store::ObjectStore> = Arc::new(store);
    let store = match deps.store_layer {
        Some(layer) => layer(store),
        None => store,
    };
    let (shutdown, shutdown_rx) = watch::channel(false);
    let disk = deps
        .disk
        .unwrap_or_else(|| Arc::new(FsDiskSpace::new(&config.data_dir)));
    let app = Arc::new(App {
        db,
        store,
        clock: deps.clock,
        disk,
        limits: config.limits,
        server_id,
        public_url: config.public_url.clone(),
        trusted_proxies: config.trusted_proxies.clone(),
        forwarder_warnings: Default::default(),
        limiter: deps
            .limiter
            .with_uploads_per_minute(config.uploads_per_minute),
        events: EventHub::new(),
        states: StateCache::default(),
        object_locks: ObjectLocks::default(),
        server_secret,
        heavy: Arc::new(tokio::sync::Semaphore::new(
            usize::try_from(config.concurrency.heavy_requests).unwrap_or(1),
        )),
        heavy_waiting: Default::default(),
        heavy_accounts: UploadSlots::default(),
        uploads: UploadSlots::default(),
        staging: StagingBytes::default(),
        concurrency: config.concurrency,
        shutdown: shutdown_rx,
        hooks: deps.hooks,
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
    // Only the serving process clears it, under the lock: an admin command beside it must not
    // remove the temporary files of the server's open database.
    clear_dir(&config.sqlite_tmp_dir())
        .map_err(|e| StartError::DataDir(config.data_dir.display().to_string(), e))?;
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
    let router = http::router(app.clone());
    // HSTS only where this server is the TLS end (overall review, info); behind a reverse
    // proxy the proxy decides, since only it knows whether every client reaches it over https.
    let router = if tls.is_some() {
        http::with_hsts(router)
    } else {
        router
    };
    Ok(Server {
        router,
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
        // Connections per client address (finding M6) and per network (server security review,
        // LOW 1). A trusted proxy carries many clients over its own address and limits them
        // itself (`limit_conn` in the proxy examples).
        let peer_slot = if app.trusted_proxies.iter().any(|n| n.contains(peer.ip())) {
            None
        } else {
            // The network cap only while the slots run short (follow-up review L4): many
            // honest clients of one provider share a network, and they lock each other out
            // only when one network could otherwise take what is left.
            let crowded = slots.available_permits() < MAX_CONNECTIONS / 2;
            match per_ip.take(
                http::client_ip::rate_key(Some(peer.ip())),
                http::client_ip::connection_net_key(Some(peer.ip())),
                app.concurrency.connections_per_ip,
                crowded.then(|| app.concurrency.connections_per_net()),
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

/// Open connections per client address key and per network key (server security review,
/// LOW 1): with TLS in the server and no proxy, 64 addresses of one network could otherwise
/// take every one of the [`MAX_CONNECTIONS`] slots. The network is an IPv4 /24 or an IPv6 /48,
/// and its cap applies only while fewer than half the slots are free (follow-up review L4).
#[derive(Default)]
struct PeerConnections {
    open: std::sync::Mutex<std::collections::HashMap<Vec<u8>, u32>>,
}

struct PeerSlot {
    owner: Arc<PeerConnections>,
    keys: [Vec<u8>; 2],
}

impl PeerConnections {
    /// A slot for a connection from the address `ip` (at most `max_ip` at once) of the network
    /// `net` (at most `max_net`, `None`: not capped now, but counted). The address and network
    /// keys never collide ([`http::client_ip::connection_net_key`]), so one map holds both.
    fn take(
        self: &Arc<Self>,
        ip: Vec<u8>,
        net: Vec<u8>,
        max_ip: u32,
        max_net: Option<u32>,
    ) -> Option<PeerSlot> {
        let mut open = self.open.lock().ok()?;
        let count = |open: &std::collections::HashMap<Vec<u8>, u32>, key: &Vec<u8>| {
            open.get(key).copied().unwrap_or(0)
        };
        if count(&open, &ip) >= max_ip || max_net.is_some_and(|max| count(&open, &net) >= max) {
            return None;
        }
        for key in [&ip, &net] {
            *open.entry(key.clone()).or_insert(0) += 1;
        }
        Some(PeerSlot {
            owner: self.clone(),
            keys: [ip, net],
        })
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        if let Ok(mut open) = self.owner.open.lock() {
            for key in &self.keys {
                if let Some(count) = open.get_mut(key) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        open.remove(key);
                    }
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

/// Creates the data folder and its folder for SQLite's temporary files
/// ([`Config::sqlite_tmp_dir`]). On Unix both are made private to the server's user (0700):
/// a server started by hand outside the image would otherwise leave the database and
/// `server.secret` readable through a folder others may list and enter.
fn prepare_data_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    private_dir(dir)?;
    let tmp = dir.join(Config::SQLITE_TMP_DIR);
    std::fs::create_dir_all(&tmp)?;
    private_dir(&tmp)
}

#[cfg(unix)]
fn private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir)?.permissions().mode();
    if mode & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_dir(_dir: &std::path::Path) -> std::io::Result<()> {
    // Windows: the folder inherits the access list of its parent; the server image is Linux.
    Ok(())
}

/// Removes everything in `dir` (temporary files a crash left behind); a missing folder is
/// created by [`prepare_data_dir`] afterwards.
fn clear_dir(dir: &std::path::Path) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_network_cannot_take_every_connection_slot() {
        // LOW 1: 64 connections from each of many addresses of one network.
        let peers = Arc::new(PeerConnections::default());
        let concurrency = config::Concurrency::default();
        let (per_ip, per_net) = (
            concurrency.connections_per_ip,
            concurrency.connections_per_net(),
        );
        let mut slots = Vec::new();
        for host in 0..=255u8 {
            let ip = std::net::IpAddr::from([203, 0, 113, host]);
            for _ in 0..per_ip {
                match peers.take(
                    http::client_ip::rate_key(Some(ip)),
                    http::client_ip::connection_net_key(Some(ip)),
                    per_ip,
                    Some(per_net),
                ) {
                    Some(slot) => slots.push(slot),
                    None => break,
                }
            }
        }
        assert_eq!(
            slots.len(),
            per_net as usize,
            "the network shares one limit"
        );
        assert!(slots.len() < MAX_CONNECTIONS / 2);
        let other = std::net::IpAddr::from([198, 51, 100, 7]);
        let take_other = || {
            peers.take(
                http::client_ip::rate_key(Some(other)),
                http::client_ip::connection_net_key(Some(other)),
                per_ip,
                Some(per_net),
            )
        };
        assert!(take_other().is_some(), "another network still connects");
        slots.clear();
        assert!(
            peers.open.lock().unwrap().is_empty(),
            "every count goes back to zero"
        );
        // One address still has its own, lower limit.
        let one = std::net::IpAddr::from([192, 0, 2, 1]);
        let mine: Vec<_> = (0..per_ip + 5)
            .filter_map(|_| {
                peers.take(
                    http::client_ip::rate_key(Some(one)),
                    http::client_ip::connection_net_key(Some(one)),
                    per_ip,
                    Some(per_net),
                )
            })
            .collect();
        assert_eq!(mine.len(), per_ip as usize);
    }

    #[test]
    fn a_providers_network_is_capped_only_per_24_and_only_when_slots_run_short() {
        // Follow-up review L4: one client of a provider held the cap of its /16, and every
        // other customer of that /16 was locked out.
        let peers = Arc::new(PeerConnections::default());
        let (per_ip, per_net) = (64, 256);
        let take = |ip: std::net::IpAddr, max_net: Option<u32>| {
            peers.take(
                http::client_ip::rate_key(Some(ip)),
                http::client_ip::connection_net_key(Some(ip)),
                per_ip,
                max_net,
            )
        };
        let mut held = Vec::new();
        for host in 0..4u8 {
            for _ in 0..per_ip {
                held.extend(take(
                    std::net::IpAddr::from([100, 64, 7, host]),
                    Some(per_net),
                ));
            }
        }
        assert_eq!(held.len(), per_net as usize, "the /24 is full");
        assert!(take(std::net::IpAddr::from([100, 64, 7, 99]), Some(per_net)).is_none());
        assert!(
            take(std::net::IpAddr::from([100, 64, 8, 1]), Some(per_net)).is_some(),
            "the next /24 of the same /16 connects"
        );
        assert!(
            take(std::net::IpAddr::from([100, 64, 7, 99]), None).is_some(),
            "with slots to spare the network is not capped"
        );
    }

    #[test]
    fn the_data_folder_and_its_temporary_folder_are_private() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/.tmp/server-unit/private-data-dir");
        let _ = std::fs::remove_dir_all(&dir);
        prepare_data_dir(&dir).unwrap();
        let tmp = dir.join(Config::SQLITE_TMP_DIR);
        assert!(tmp.is_dir());
        std::fs::write(tmp.join("etilqs_leftover"), b"x").unwrap();
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        clear_dir(&tmp).unwrap();
        assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for d in [&dir, &tmp] {
                let mode = std::fs::metadata(d).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o700, "{}", d.display());
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
