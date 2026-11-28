//! SQLite in WAL mode through sqlx. Every query binds its parameters; SQL texts are static, and
//! column and table names never come from input.

use std::path::Path;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Connection, Sqlite, SqliteConnection, SqlitePool, Transaction};

pub type Db = SqlitePool;
pub type Tx = Transaction<'static, Sqlite>;

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
        .busy_timeout(Duration::from_secs(10));
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
/// each other (busy timeout). Every compare and swap of the server relies on it.
pub async fn begin_write(db: &Db) -> Result<Tx, sqlx::Error> {
    db.begin_with("BEGIN IMMEDIATE").await
}

/// [`begin_write`] on a connection the caller already holds, for a call that prepares its
/// temporary tables on that connection before it takes the write lock (the commit call, server
/// security review MEDIUM 2). Temporary tables belong to one connection.
pub async fn begin_write_on(
    conn: &mut SqliteConnection,
) -> Result<Transaction<'_, Sqlite>, sqlx::Error> {
    conn.begin_with("BEGIN IMMEDIATE").await
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
