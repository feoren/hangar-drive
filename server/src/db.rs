//! SQLite in WAL mode through sqlx. Every query binds its parameters; SQL texts are static, and
//! column and table names never come from input.

use std::path::Path;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Sqlite, SqlitePool, Transaction};

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
        .busy_timeout(Duration::from_secs(10));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
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

/// A `u64` as SQLite's `INTEGER`, saturating (no stored value comes near `i64::MAX`).
pub fn i64_of(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// An `INTEGER` read back; negative values (never written) read as 0.
pub fn u64_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}
