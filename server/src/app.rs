//! What every request and job shares: database, object store, clock, limits and the in-memory
//! parts (verified device logs, push hub, rate limits, per-object locks).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use hangar_drive_crypto::devicelog::AccountState;
use hangar_drive_protocol::ids::{AccountId, ServerId};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::clock::Clock;
use crate::config::{Concurrency, IpNet, Limits};
use crate::db::{u64_of, Db};
use crate::disk::DiskSpace;
use crate::error::{ApiError, ApiResult};
use crate::events::EventHub;
use crate::http::ratelimit::RateLimiter;
use crate::store::ObjectStore;

pub struct App {
    pub db: Db,
    pub store: Arc<dyn ObjectStore>,
    pub clock: Arc<dyn Clock>,
    pub disk: Arc<dyn DiskSpace>,
    pub limits: Limits,
    pub server_id: ServerId,
    /// `HANGAR_DRIVE_PUBLIC_URL` (`Config::public_url`): a session proof must name it, so a host
    /// that relays a sign-in under this server's ID is refused. `serve` does not start without
    /// it ([`crate::build`]); only the admin commands, which serve nothing, run without it, and
    /// a proof is then refused, never checked against the URL the device signed.
    pub public_url: Option<String>,
    pub trusted_proxies: Vec<IpNet>,
    /// Unlisted local proxies already warned about (overall review N3).
    pub forwarder_warnings: crate::http::client_ip::ForwarderWarnings,
    pub limiter: RateLimiter,
    pub events: Arc<EventHub>,
    pub states: StateCache,
    pub object_locks: ObjectLocks,
    /// Key of the stateless sign-in challenges (`server.secret` in the data folder).
    pub server_secret: ServerSecret,
    /// Commits and record writes in progress (finding M4).
    pub heavy: Arc<tokio::sync::Semaphore>,
    /// Calls waiting for a slot of [`App::heavy`] now; while any waits, heavy bodies must keep
    /// their least pace (`http::extract::HEAVY_PACE`, follow-up review L3).
    pub heavy_waiting: std::sync::atomic::AtomicUsize,
    /// Slots of [`App::heavy`] each account holds: at most half of them, so one account that
    /// dribbles its bodies cannot stall the commits of every other account.
    pub heavy_accounts: UploadSlots,
    /// Uploads in flight per account (finding M5).
    pub uploads: UploadSlots,
    /// Bytes uploads in flight may still write to the staging area (finding M5).
    pub staging: StagingBytes,
    pub concurrency: Concurrency,
    /// Becomes true when the server shuts down; long-lived streams end on it.
    pub shutdown: watch::Receiver<bool>,
    /// Points where tests stop a call ([`Hooks`]); empty in a serving process.
    pub hooks: Hooks,
}

/// A test hook: awaited at a fixed point of a call.
pub type Hook = Arc<dyn Fn() -> futures_util::future::BoxFuture<'static, ()> + Send + Sync>;

/// Test hooks (`Deps::hooks`). Each is `None` in a serving process.
#[derive(Clone, Default)]
pub struct Hooks {
    /// Awaited by a commit call after it loaded its IDs and checked that the objects exist,
    /// right before it takes the write lock (server security review, MEDIUM 2).
    pub commit_prepared: Option<Hook>,
    /// Awaited by an upload after its file went in place and before its write transaction,
    /// while it holds the object's stripe lock (`service::objects::store`).
    pub upload_installed: Option<Hook>,
}

pub type AppState = Arc<App>;

impl App {
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }
}

/// SHA-256, for token and invite hashes.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Accounts whose verified device log is cached at most; beyond it the cache starts over.
const MAX_CACHED_STATES: usize = 10_000;

/// The verified device log per account. Verifying a log means checking every signature, so the
/// server keeps the result and replaces it only when the log grows. Every use compares the
/// cached length with the database's `log_length` (read in the caller's transaction), so a log
/// changed by another process (the admin CLI) is verified again.
#[derive(Default)]
pub struct StateCache {
    states: Mutex<HashMap<i64, Arc<AccountState>>>,
}

impl StateCache {
    /// The verified state of `account_pk` with `length` entries, read through `conn`.
    pub async fn get(
        &self,
        conn: &mut sqlx::SqliteConnection,
        account_pk: i64,
        account: AccountId,
        length: u64,
    ) -> ApiResult<Arc<AccountState>> {
        if let Some(state) = self.cached(account_pk) {
            if state.len() == length {
                return Ok(state);
            }
        }
        let entries: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT entry FROM log_entries WHERE account_pk = ? ORDER BY idx")
                .bind(account_pk)
                .fetch_all(&mut *conn)
                .await?;
        let state = AccountState::from_entries(account, entries.iter().map(Vec::as_slice))
            .map_err(|e| ApiError::internal(&format!("stored device log does not verify: {e}")))?;
        if state.len() != length {
            return Err(ApiError::internal(&"stored device log length differs"));
        }
        let state = Arc::new(state);
        self.put(account_pk, state.clone());
        Ok(state)
    }

    fn cached(&self, account_pk: i64) -> Option<Arc<AccountState>> {
        self.states.lock().ok()?.get(&account_pk).cloned()
    }

    /// Stores the state after an accepted append.
    pub fn put(&self, account_pk: i64, state: Arc<AccountState>) {
        if let Ok(mut states) = self.states.lock() {
            if states.len() >= MAX_CACHED_STATES && !states.contains_key(&account_pk) {
                states.clear();
            }
            states.insert(account_pk, state);
        }
    }

    pub fn forget(&self, account_pk: i64) {
        if let Ok(mut states) = self.states.lock() {
            states.remove(&account_pk);
        }
    }
}

/// An account row as most services need it.
#[derive(Debug, Clone, Copy)]
pub struct AccountRow {
    pub pk: i64,
    pub id: AccountId,
    pub log_length: u64,
}

pub async fn account_by_pk(
    conn: &mut sqlx::SqliteConnection,
    pk: i64,
) -> ApiResult<Option<AccountRow>> {
    let row: Option<(Vec<u8>, i64)> =
        sqlx::query_as("SELECT id, log_length FROM accounts WHERE pk = ?")
            .bind(pk)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(row.and_then(|(id, len)| {
        Some(AccountRow {
            pk,
            id: AccountId::from_slice(&id)?,
            log_length: u64_of(len),
        })
    }))
}

pub async fn account_by_id(
    conn: &mut sqlx::SqliteConnection,
    id: &AccountId,
) -> ApiResult<Option<AccountRow>> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT pk, log_length FROM accounts WHERE id = ?")
            .bind(id.as_bytes().as_slice())
            .fetch_optional(&mut *conn)
            .await?;
    Ok(row.map(|(pk, len)| AccountRow {
        pk,
        id: *id,
        log_length: u64_of(len),
    }))
}

/// Striped locks over object keys. An upload holds its stripe from the existence check through
/// putting its file in place to the committed database row (or the removal of its file when
/// the row is refused); the garbage collection and the orphan sweep hold it while they remove a
/// file without a row, so neither can remove the file of an upload in between, and no upload
/// can put a file over an object that has a row.
pub struct ObjectLocks {
    stripes: Vec<tokio::sync::Mutex<()>>,
}

impl Default for ObjectLocks {
    fn default() -> Self {
        Self {
            stripes: (0..64).map(|_| tokio::sync::Mutex::new(())).collect(),
        }
    }
}

impl ObjectLocks {
    pub async fn lock(&self, key: &[u8]) -> tokio::sync::MutexGuard<'_, ()> {
        let index = key.iter().fold(0usize, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(usize::from(*b))
        });
        self.stripes[index % self.stripes.len()].lock().await
    }
}

/// The 32 byte secret the sign-in challenges are authenticated with. It never leaves the
/// process and is never logged.
#[derive(Clone)]
pub struct ServerSecret([u8; 32]);

impl ServerSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ServerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerSecret(..)")
    }
}

/// Reads the server secret from `path`, or makes it at the first start: 32 random bytes in a
/// new file only the server's user can read, flushed before it is used. A file of another
/// length is an error and is never replaced silently: that would hide a damaged data folder.
///
/// The new secret is written to `server.secret.tmp` and renamed into place, so a crash while
/// writing never leaves a short `server.secret` that blocks every later start. On Unix an
/// existing secret that group or others may read (a restore from a backup, a manual copy) is
/// set back to 0600 before it is used.
pub fn load_or_create_secret(path: &std::path::Path) -> std::io::Result<ServerSecret> {
    use std::io::{Read, Write};
    match std::fs::File::open(path) {
        Ok(mut file) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if file.metadata()?.permissions().mode() & 0o077 != 0 {
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                }
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| std::io::Error::other("server.secret must hold exactly 32 bytes"))?;
            Ok(ServerSecret(bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = [0u8; 32];
            hangar_drive_crypto::Entropy::fill(&mut hangar_drive_crypto::OsEntropy, &mut bytes)
                .map_err(|_| std::io::Error::other("no randomness for the server secret"))?;
            let temp = path.with_extension("secret.tmp");
            // A leftover of a crash holds no secret anyone used; it is simply replaced.
            match std::fs::remove_file(&temp) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, path)?;
            #[cfg(unix)]
            if let Some(dir) = path.parent() {
                std::fs::File::open(dir)?.sync_all()?;
            }
            Ok(ServerSecret(bytes))
        }
        Err(e) => Err(e),
    }
}

/// Uploads in flight per account. A slot is taken before the body is read and freed when the
/// guard drops, whatever the outcome.
#[derive(Default)]
pub struct UploadSlots {
    open: Mutex<HashMap<i64, u32>>,
}

/// One upload's slot.
pub struct UploadSlot<'a> {
    slots: &'a UploadSlots,
    account_pk: i64,
}

/// An upload's slot in [`App::uploads`] that owns its app, so it can move into the task that
/// stores the upload and live until that task ends, even when the request is dropped
/// (`service::objects::store`).
pub struct OwnedUploadSlot {
    app: AppState,
    account_pk: i64,
}

impl OwnedUploadSlot {
    /// A slot of [`App::uploads`] for the account, or `None` if it already has `max` uploads in
    /// flight.
    pub fn take(app: &AppState, account_pk: i64, max: u32) -> Option<Self> {
        app.uploads.acquire(account_pk, max).then(|| Self {
            app: app.clone(),
            account_pk,
        })
    }
}

impl Drop for OwnedUploadSlot {
    fn drop(&mut self) {
        self.app.uploads.release(self.account_pk);
    }
}

impl UploadSlots {
    /// A slot for the account, or `None` if it already has `max` uploads in flight.
    pub fn take(&self, account_pk: i64, max: u32) -> Option<UploadSlot<'_>> {
        self.acquire(account_pk, max).then(|| UploadSlot {
            slots: self,
            account_pk,
        })
    }

    fn acquire(&self, account_pk: i64, max: u32) -> bool {
        let Ok(mut open) = self.open.lock() else {
            return false;
        };
        let count = open.entry(account_pk).or_insert(0);
        if *count >= max {
            return false;
        }
        *count += 1;
        true
    }

    fn release(&self, account_pk: i64) {
        if let Ok(mut open) = self.open.lock() {
            if let Some(count) = open.get_mut(&account_pk) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    open.remove(&account_pk);
                }
            }
        }
    }

    /// Uploads in flight of the account.
    pub fn in_flight(&self, account_pk: i64) -> u32 {
        self.open
            .lock()
            .ok()
            .and_then(|open| open.get(&account_pk).copied())
            .unwrap_or(0)
    }
}

impl Drop for UploadSlot<'_> {
    fn drop(&mut self) {
        self.slots.release(self.account_pk);
    }
}

/// Bytes that uploads in flight announced but have not written yet. The disk reserve check
/// counts them as used, so many uploads that start at the same moment cannot each see the same
/// free space and together fill the disk (finding M5). Bytes already written show in the free
/// space itself and leave the counter.
#[derive(Default)]
pub struct StagingBytes {
    outstanding: std::sync::atomic::AtomicU64,
}

/// One upload's announced bytes; what it has not written is released on drop.
pub struct StagingClaim<'a> {
    bytes: &'a StagingBytes,
    left: u64,
}

impl StagingBytes {
    pub fn claim(&self, bytes: u64) -> StagingClaim<'_> {
        self.outstanding
            .fetch_add(bytes, std::sync::atomic::Ordering::SeqCst);
        StagingClaim {
            bytes: self,
            left: bytes,
        }
    }

    pub fn outstanding(&self) -> u64 {
        self.outstanding.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl StagingClaim<'_> {
    /// `n` bytes were written to the staging file.
    pub fn wrote(&mut self, n: u64) {
        let n = n.min(self.left);
        self.left -= n;
        self.bytes
            .outstanding
            .fetch_sub(n, std::sync::atomic::Ordering::SeqCst);
    }

    /// Bytes this claim still holds.
    pub fn left(&self) -> u64 {
        self.left
    }
}

impl Drop for StagingClaim<'_> {
    fn drop(&mut self) {
        self.bytes
            .outstanding
            .fetch_sub(self.left, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_slots_and_staging_claims_are_released_on_drop() {
        let slots = UploadSlots::default();
        let a = slots.take(1, 2).unwrap();
        let b = slots.take(1, 2).unwrap();
        assert!(slots.take(1, 2).is_none());
        assert!(slots.take(2, 2).is_some(), "another account");
        drop(a);
        assert_eq!(slots.in_flight(1), 1);
        drop(b);
        assert_eq!(slots.in_flight(1), 0);

        let staging = StagingBytes::default();
        let mut claim = staging.claim(100);
        let other = staging.claim(50);
        assert_eq!(staging.outstanding(), 150);
        claim.wrote(30);
        assert_eq!(staging.outstanding(), 120);
        claim.wrote(500);
        assert_eq!((claim.left(), staging.outstanding()), (0, 50));
        drop(other);
        drop(claim);
        assert_eq!(staging.outstanding(), 0);
    }

    #[test]
    fn the_server_secret_is_made_once_and_kept() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/.tmp/server-unit/secret");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.secret");
        let first = load_or_create_secret(&path).unwrap();
        let again = load_or_create_secret(&path).unwrap();
        assert_eq!(first.expose(), again.expose());
        assert_eq!(format!("{first:?}"), "ServerSecret(..)");
        std::fs::write(&path, b"short").unwrap();
        assert!(load_or_create_secret(&path).is_err());
    }

    #[test]
    fn a_crash_while_writing_the_secret_does_not_block_the_next_start() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/.tmp/server-unit/secret-crash");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.secret");
        // What a crash between creating and filling the file leaves behind.
        std::fs::write(dir.join("server.secret.tmp"), b"half").unwrap();
        let made = load_or_create_secret(&path).unwrap();
        assert!(!dir.join("server.secret.tmp").exists());
        assert_eq!(std::fs::read(&path).unwrap(), made.expose());
    }

    #[cfg(unix)]
    #[test]
    fn the_secret_is_readable_by_the_server_user_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/.tmp/server-unit/secret-mode");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.secret");
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        load_or_create_secret(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        load_or_create_secret(&path).unwrap();
        assert_eq!(mode(&path), 0o600, "a loose secret is tightened at start");
    }
}
