//! SQLite in WAL mode through sqlx. Every query binds its parameters; SQL texts are static, and
//! column and table names never come from input.

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Connection, Sqlite, SqliteConnection, SqlitePool, Transaction};
use tokio::sync::OwnedMutexGuard;

pub type Db = SqlitePool;
pub type Tx = WriteTx<'static>;

/// Why the database did not open.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Connections of the pool.
pub const MAX_CONNECTIONS: u32 = 8;
/// `PRAGMA cache_size`: negative is KiB, so 16 MiB per connection.
const CACHE_SIZE_KIB: &str = "-16384";
/// `PRAGMA journal_size_limit`: 64 MiB.
const JOURNAL_SIZE_LIMIT: &str = "67108864";
/// How long a write waits for SQLite's write lock, and for its turn at [`begin_write`].
const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// Opens (and creates) the database at `path` and applies the embedded migrations.
pub async fn connect(path: &Path) -> Result<Db, DbError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        // FULL: an accepted commit call or log append survives a power failure; a device
        // stores its frontier after the server confirmed, so a lost confirmed write would look
        // like a rollback to it.
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        // Deleted rows (expired sessions' token hashes, dropped records, deleted folders'
        // reference lists) are overwritten with zeros instead of lingering in free pages,
        // where a copy of the database file would still hold them (overall review, info). The
        // WAL keeps a deleted page only until the next checkpoint.
        .pragma("secure_delete", "ON")
        // Page cache per connection, in KiB when negative: 16 MiB instead of SQLite's 2 MiB, so
        // the object and reference indexes of a large account stay in memory. The pool has at
        // most `MAX_CONNECTIONS` connections, 128 MiB together at worst, which the container's
        // 1 GiB `mem_limit` holds beside the heavy slots' bodies (docker-compose.yml).
        .pragma("cache_size", CACHE_SIZE_KIB)
        // The WAL file is cut back to this after a checkpoint instead of keeping its largest
        // size: one large commit no longer leaves a WAL of gigabytes on disk for good.
        .pragma("journal_size_limit", JOURNAL_SIZE_LIMIT)
        .busy_timeout(BUSY_TIMEOUT);
    let pool = SqlitePoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .min_connections(1)
        .connect_with(options)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// A write transaction that takes the write lock at once. Without `IMMEDIATE`, two transactions
/// started as readers could fail with `SQLITE_BUSY` on their first write; this way they wait for
/// each other. Every compare and swap of the server relies on it.
///
/// **Turns** (throughput review of the server image): the writers of one database first queue
/// for their turn in this process, first come first served, and only then take SQLite's lock.
/// SQLite itself lets a waiting writer sleep and retry (1, 2, 5, 10 ... 100 ms between tries),
/// so with several uploads at once a writer often slept on after the lock was free again: on a
/// fast disk single uploads took over a second at the tail, on a spinning disk worse. With the
/// queue, the next writer starts the moment the previous one commits. Here the turn is taken
/// before a pool connection, so these queued writers hold no connection that readers need; only
/// a commit ([`begin_write_on`]) waits with its connection, and `config::MAX_HEAVY_REQUESTS`
/// keeps those to half the pool.
///
/// A writer that waited [`BUSY_TIMEOUT`] for its turn goes on without it to SQLite's own lock
/// (and logs it): a code path that nested two write transactions would then fail on SQLite's
/// busy timeout as before instead of waiting for itself forever. Processes beside the server
/// (the admin CLI) are covered by SQLite's lock alone, as before.
pub async fn begin_write(db: &Db) -> Result<Tx, sqlx::Error> {
    let turn = take_turn(db).await;
    let tx = db.begin_with("BEGIN IMMEDIATE").await?;
    Ok(WriteTx { tx, _turn: turn })
}

/// [`begin_write`] on a connection the caller already holds, for a call that prepares its
/// temporary tables on that connection before it takes the write lock (the commit call, server
/// security review MEDIUM 2). Temporary tables belong to one connection. `db` is the pool the
/// connection belongs to: its writers share the queue. The caller holds the connection while it
/// waits for its turn; at most `config::MAX_HEAVY_REQUESTS` commits do so at once.
pub async fn begin_write_on<'c>(
    db: &Db,
    conn: &'c mut SqliteConnection,
) -> Result<WriteTx<'c>, sqlx::Error> {
    let turn = take_turn(db).await;
    let tx = conn.begin_with("BEGIN IMMEDIATE").await?;
    Ok(WriteTx { tx, _turn: turn })
}

/// An open write transaction and its turn ([`begin_write`]). It reads as the connection, so
/// queries run on `&mut *tx` as on a plain transaction. Dropped without [`WriteTx::commit`], it
/// rolls back, and the turn passes on.
pub struct WriteTx<'c> {
    tx: Transaction<'c, Sqlite>,
    _turn: Option<OwnedMutexGuard<()>>,
}

impl WriteTx<'_> {
    /// Commits; the turn passes on only afterwards.
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        let WriteTx { tx, _turn } = self;
        tx.commit().await
    }
}

impl Deref for WriteTx<'_> {
    type Target = SqliteConnection;

    fn deref(&self) -> &SqliteConnection {
        &self.tx
    }
}

impl DerefMut for WriteTx<'_> {
    fn deref_mut(&mut self) -> &mut SqliteConnection {
        &mut self.tx
    }
}

/// The queue of writers of each database file in this process.
fn queue_of(db: &Db) -> Option<Arc<tokio::sync::Mutex<()>>> {
    static QUEUES: OnceLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let path = db.connect_options().get_filename().to_path_buf();
    let mut queues = QUEUES.get_or_init(Default::default).lock().ok()?;
    Some(queues.entry(path).or_default().clone())
}

async fn take_turn(db: &Db) -> Option<OwnedMutexGuard<()>> {
    let queue = queue_of(db)?;
    match tokio::time::timeout(BUSY_TIMEOUT, queue.lock_owned()).await {
        Ok(turn) => Some(turn),
        Err(_) => {
            tracing::warn!(
                "a write waited {}s for its turn; it goes on to the database's own lock",
                BUSY_TIMEOUT.as_secs()
            );
            None
        }
    }
}

/// A `u64` as SQLite's `INTEGER`, saturating (no stored value comes near `i64::MAX`).
pub fn i64_of(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// An `INTEGER` read back; negative values (never written) read as 0.
pub fn u64_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn deleted_rows_are_overwritten() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/.tmp/server-unit/db-secure-delete");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = super::connect(&dir.join("meta.db")).await.unwrap();
        let on: i64 = sqlx::query_scalar("PRAGMA secure_delete")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(on, 1, "every connection of the pool deletes securely");
        db.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn writers_take_turns_in_the_order_they_came() {
        // Throughput review of the server image: SQLite's own busy wait let writers sleep and
        // retry in no order, and often long after the lock was free.
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/.tmp/server-unit/db-write-turns");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = super::connect(&dir.join("meta.db")).await.unwrap();
        let first = super::begin_write(&db).await.unwrap();
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut writers = Vec::new();
        for i in 0..5 {
            let (db, order) = (db.clone(), order.clone());
            writers.push(tokio::spawn(async move {
                let tx = super::begin_write(&db).await.unwrap();
                let started = std::time::Instant::now();
                order.lock().unwrap().push(i);
                tx.commit().await.unwrap();
                started
            }));
            // Each one queued before the next comes.
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
        let released = std::time::Instant::now();
        first.commit().await.unwrap();
        let mut starts = Vec::new();
        for writer in writers {
            starts.push(writer.await.unwrap());
        }
        assert_eq!(*order.lock().unwrap(), vec![0, 1, 2, 3, 4]);
        let waited = starts[0].saturating_duration_since(released);
        assert!(
            waited < std::time::Duration::from_millis(500),
            "the next writer starts when the lock is free, not after a sleep: {waited:?}"
        );
        db.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn every_connection_has_the_cache_and_wal_limits() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/.tmp/server-unit/db-pragmas");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = super::connect(&dir.join("meta.db")).await.unwrap();
        // Several connections at once, so not only the first one is looked at.
        let mut held = Vec::new();
        for _ in 0..3 {
            let mut conn = db.acquire().await.unwrap();
            let cache: i64 = sqlx::query_scalar("PRAGMA cache_size")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
            let limit: i64 = sqlx::query_scalar("PRAGMA journal_size_limit")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
            let sync: i64 = sqlx::query_scalar("PRAGMA synchronous")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
            let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
            assert_eq!(cache, -16384);
            assert_eq!(limit, 64 << 20);
            assert_eq!(sync, 2, "FULL stays");
            assert_eq!(mode, "wal");
            held.push(conn);
        }
        drop(held);
        db.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
