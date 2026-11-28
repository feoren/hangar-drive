//! The local index in SQLite (ADR 0001, section 3): the remote, synced and local trees with
//! size, mtime and file ID, the folder metadata (verified chain, cursor, journal), chunk lists,
//! the object cache and the account state. It lives in the platform's config directory
//! ([`default_index_path`]), never inside a sync folder.
//!
//! Every [`Store::save_folder`] is one transaction, so a crash leaves the index at the end of a
//! step, never in between. WAL mode with `synchronous = NORMAL` keeps the index consistent
//! after a crash of the app or the OS; after a power loss the last transaction may be missing,
//! and the next round redoes it from disk and server.
//!
//! The index holds names and paths in plain text, like the files themselves (ADR 0001,
//! Consequences: "Local plaintext"); nothing secret is stored here.

use std::path::{Path, PathBuf};

use hangar_drive_protocol::ids::{FolderId, ItemId, ObjectId};
use rusqlite::{params, Connection, OptionalExtension};

use crate::ports::{ChunkList, SaveBatch, Store, StoreError, StoredFolder};
use crate::tree::{ContentKey, FileVersion, Node, NodeKind, TreeDelta};

/// The index directory: on Unix only the owner may enter it (0700), because the index holds
/// every synced path in plain text (security review L7). Windows keeps the ACL of the user's
/// application data folder, which already admits only the user, the system and administrators.
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    let io = |e: std::io::Error| StoreError::Db(e.to_string());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(io)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir).map_err(io)?;
    Ok(())
}

/// Creates the database file with mode 0600 on Unix before SQLite opens it.
fn create_private_file(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(StoreError::Db(e.to_string())),
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Mode 0600 for an index file that exists (Unix).
fn restrict_file(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(StoreError::Db(e.to_string())),
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The schema version this code writes ([`SqliteStore::open`] migrates older ones).
pub const SCHEMA_VERSION: i64 = 1;

const TREE_REMOTE: i64 = 0;
const TREE_SYNCED: i64 = 1;
const TREE_LOCAL: i64 = 2;

const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS account (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS folders (folder BLOB PRIMARY KEY, meta BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS nodes (
    folder BLOB NOT NULL,
    tree INTEGER NOT NULL,
    item BLOB NOT NULL,
    parent BLOB NOT NULL,
    name TEXT NOT NULL,
    kind INTEGER NOT NULL,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    exec INTEGER NOT NULL,
    content BLOB,
    conflict_of BLOB,
    PRIMARY KEY (folder, tree, item)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS file_ids (
    folder BLOB NOT NULL,
    item BLOB NOT NULL,
    file_id BLOB NOT NULL,
    PRIMARY KEY (folder, item)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS chunks (
    folder BLOB NOT NULL,
    content BLOB NOT NULL,
    generation INTEGER,
    chunks BLOB NOT NULL,
    PRIMARY KEY (folder, content)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS objects (
    folder BLOB NOT NULL,
    digest BLOB NOT NULL,
    id BLOB NOT NULL,
    PRIMARY KEY (folder, digest)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS plaintexts (
    folder BLOB NOT NULL,
    id BLOB NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (folder, id)
) WITHOUT ROWID;
";

/// The index file in the platform's local config directory (`%LOCALAPPDATA%` on Windows,
/// `~/Library/Application Support` on macOS, `$XDG_CONFIG_HOME` or `~/.config` on Linux).
pub fn default_index_path() -> Option<PathBuf> {
    dirs::config_local_dir().map(|d| d.join("Hangar Drive").join("index.sqlite3"))
}

fn db(e: rusqlite::Error) -> StoreError {
    StoreError::Db(e.to_string())
}

/// Free bytes and size of the volume of a directory (`space::free_bytes`, `space::volume_bytes`).
type SpaceProbe = fn(&Path) -> (Option<u64>, Option<u64>);

fn probe_space(dir: &Path) -> (Option<u64>, Option<u64>) {
    (
        crate::space::free_bytes(dir),
        crate::space::volume_bytes(dir),
    )
}

/// Cache bytes written between two readings of the free space.
const SPACE_CHECK_BYTES: u64 = 8 * 1024 * 1024;
/// The longest time between two readings of the free space while the cache is written.
const SPACE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Whether the index volume has room for more cache rows (security review, MEDIUM 3): the free
/// space is read again after [`SPACE_CHECK_BYTES`] or [`SPACE_CHECK_INTERVAL`], not before each
/// row, and the cache needs the reserve a download leaves free ([`crate::folder::disk_reserve`]),
/// so the index never fills the system drive. Unknown free space is no reason to stop: every
/// supported platform reports it, and the folder state the index holds must still be written.
struct SpaceGuard {
    dir: Option<PathBuf>,
    probe: SpaceProbe,
    written: u64,
    checked: Option<std::time::Instant>,
    room: bool,
}

impl SpaceGuard {
    fn new(dir: Option<PathBuf>) -> Self {
        Self {
            dir,
            probe: probe_space,
            written: 0,
            checked: None,
            room: true,
        }
    }

    fn ensure(&mut self, bytes: usize) -> Result<(), StoreError> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        self.written = self.written.saturating_add(bytes as u64);
        let due = self
            .checked
            .is_none_or(|at| at.elapsed() >= SPACE_CHECK_INTERVAL)
            || self.written >= SPACE_CHECK_BYTES;
        if due {
            let (free, volume) = (self.probe)(dir);
            self.room = free.is_none_or(|f| {
                f >= crate::folder::disk_reserve(volume).saturating_add(bytes as u64)
            });
            self.written = 0;
            self.checked = Some(std::time::Instant::now());
        }
        if self.room {
            Ok(())
        } else {
            Err(StoreError::DiskFull)
        }
    }
}

/// The local index in SQLite (module docs).
pub struct SqliteStore {
    conn: Connection,
    space: SpaceGuard,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

fn kind_columns(node: &Node) -> (i64, i64, i64, i64, Option<Vec<u8>>) {
    match &node.kind {
        NodeKind::Directory => (2, 0, 0, 0, None),
        NodeKind::File(v) => (
            1,
            i64::try_from(v.size).unwrap_or(i64::MAX),
            v.mtime_ms,
            i64::from(v.executable),
            Some(v.content.0.to_vec()),
        ),
    }
}

fn blob16(bytes: &[u8]) -> Result<[u8; 16], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("expected 16 bytes".into()))
}

fn blob32(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("expected 32 bytes".into()))
}

impl SqliteStore {
    /// Opens (or creates) the index at `path` and migrates it to [`SCHEMA_VERSION`].
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        create_private_file(path)?;
        let conn = Connection::open(path).map_err(db)?;
        let mut store = Self::init(conn)?;
        store.space = SpaceGuard::new(path.parent().map(Path::to_path_buf));
        // SQLite creates `-wal` and `-shm` with the database file's mode (`findCreateFileMode`
        // in `os_unix.c`); they are set again here, so an index made by an older version is
        // private as well (security review L7).
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            restrict_file(Path::new(&name))?;
        }
        Ok(store)
    }

    /// An index in memory (tests).
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory().map_err(db)?)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db)?;
        // Deleted rows are overwritten, so the paths and names of a folder removed or of a
        // device reset do not stay readable in free pages of the file (security review, info).
        conn.pragma_update(None, "secure_delete", "ON")
            .map_err(db)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(db)?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(db)?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::Corrupt(format!(
                "the index has schema version {version}, this app knows {SCHEMA_VERSION}"
            )));
        }
        if version < 1 {
            conn.execute_batch(SCHEMA_V1).map_err(db)?;
            conn.pragma_update(None, "user_version", 1).map_err(db)?;
        }
        Ok(Self {
            conn,
            space: SpaceGuard::new(None),
        })
    }

    /// Deletes the rows of `table` of `folder` whose `column` is not in `keep`. Table and
    /// column names come only from the fixed calls in [`Store::retain_cache`].
    fn retain_rows(
        tx: &Connection,
        table: &str,
        column: &str,
        folder: &FolderId,
        keep: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<u64, StoreError> {
        let f = folder.as_bytes().as_slice();
        let mut gone: Vec<Vec<u8>> = Vec::new();
        {
            let mut stmt = tx
                .prepare(&format!("SELECT {column} FROM {table} WHERE folder = ?1"))
                .map_err(db)?;
            let rows = stmt
                .query_map(params![f], |r| r.get::<_, Vec<u8>>(0))
                .map_err(db)?;
            for row in rows {
                let value = row.map_err(db)?;
                if !keep(&blob32(&value)?) {
                    gone.push(value);
                }
            }
        }
        let mut del = tx
            .prepare(&format!(
                "DELETE FROM {table} WHERE folder = ?1 AND {column} = ?2"
            ))
            .map_err(db)?;
        for value in &gone {
            del.execute(params![f, value]).map_err(db)?;
        }
        Ok(gone.len() as u64)
    }

    fn read_nodes(&self, folder: &FolderId, tree: i64) -> Result<Vec<(ItemId, Node)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT item, parent, name, kind, size, mtime, exec, content, conflict_of
                 FROM nodes WHERE folder = ?1 AND tree = ?2",
            )
            .map_err(db)?;
        let rows = stmt
            .query_map(params![folder.as_bytes().as_slice(), tree], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<Vec<u8>>>(7)?,
                    r.get::<_, Option<Vec<u8>>>(8)?,
                ))
            })
            .map_err(db)?;
        let mut out = Vec::new();
        for row in rows {
            let (item, parent, name, kind, size, mtime, exec, content, conflict_of) =
                row.map_err(db)?;
            let kind = match (kind, content) {
                (2, _) => NodeKind::Directory,
                (1, Some(content)) => NodeKind::File(FileVersion {
                    size: u64::try_from(size).map_err(|_| StoreError::Corrupt("size".into()))?,
                    mtime_ms: mtime,
                    executable: exec != 0,
                    content: ContentKey(blob32(&content)?),
                }),
                _ => return Err(StoreError::Corrupt("node kind".into())),
            };
            out.push((
                ItemId::from_bytes(blob16(&item)?),
                Node {
                    parent: ItemId::from_bytes(blob16(&parent)?),
                    name,
                    kind,
                    conflict_of: conflict_of
                        .map(|c| blob16(&c).map(ItemId::from_bytes))
                        .transpose()?,
                },
            ));
        }
        Ok(out)
    }

    fn write_delta(
        tx: &Connection,
        folder: &FolderId,
        tree: i64,
        delta: &TreeDelta,
    ) -> Result<(), StoreError> {
        let f = folder.as_bytes().as_slice();
        {
            let mut del = tx
                .prepare_cached("DELETE FROM nodes WHERE folder = ?1 AND tree = ?2 AND item = ?3")
                .map_err(db)?;
            for id in &delta.remove {
                del.execute(params![f, tree, id.as_bytes().as_slice()])
                    .map_err(db)?;
            }
        }
        let mut up = tx
            .prepare_cached(
                "INSERT OR REPLACE INTO nodes
                 (folder, tree, item, parent, name, kind, size, mtime, exec, content, conflict_of)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )
            .map_err(db)?;
        for (id, node) in &delta.upsert {
            let (kind, size, mtime, exec, content) = kind_columns(node);
            up.execute(params![
                f,
                tree,
                id.as_bytes().as_slice(),
                node.parent.as_bytes().as_slice(),
                node.name,
                kind,
                size,
                mtime,
                exec,
                content,
                node.conflict_of.map(|c| c.as_bytes().to_vec()),
            ])
            .map_err(db)?;
        }
        Ok(())
    }
}

impl Store for SqliteStore {
    fn folders(&self) -> Result<Vec<FolderId>, StoreError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT folder FROM folders")
            .map_err(db)?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)).map_err(db)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(FolderId::from_bytes(blob16(&row.map_err(db)?)?));
        }
        Ok(out)
    }

    fn load_folder(&self, folder: &FolderId) -> Result<Option<StoredFolder>, StoreError> {
        let meta: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT meta FROM folders WHERE folder = ?1",
                params![folder.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        let Some(meta) = meta else {
            return Ok(None);
        };
        let mut file_ids = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare_cached("SELECT item, file_id FROM file_ids WHERE folder = ?1")
                .map_err(db)?;
            let rows = stmt
                .query_map(params![folder.as_bytes().as_slice()], |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .map_err(db)?;
            for row in rows {
                let (item, id) = row.map_err(db)?;
                file_ids.push((
                    ItemId::from_bytes(blob16(&item)?),
                    u128::from_be_bytes(blob16(&id)?),
                ));
            }
        }
        Ok(Some(StoredFolder {
            remote: self.read_nodes(folder, TREE_REMOTE)?,
            synced: self.read_nodes(folder, TREE_SYNCED)?,
            local: self.read_nodes(folder, TREE_LOCAL)?,
            file_ids,
            meta,
        }))
    }

    fn save_folder(&mut self, folder: &FolderId, batch: &SaveBatch) -> Result<(), StoreError> {
        let tx = self.conn.transaction().map_err(db)?;
        let f = folder.as_bytes().as_slice();
        Self::write_delta(&tx, folder, TREE_REMOTE, &batch.remote)?;
        Self::write_delta(&tx, folder, TREE_SYNCED, &batch.synced)?;
        Self::write_delta(&tx, folder, TREE_LOCAL, &batch.local)?;
        {
            let mut set = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO file_ids (folder, item, file_id) VALUES (?1, ?2, ?3)",
                )
                .map_err(db)?;
            let mut clear = tx
                .prepare_cached("DELETE FROM file_ids WHERE folder = ?1 AND item = ?2")
                .map_err(db)?;
            for (item, id) in &batch.file_ids {
                match id {
                    Some(id) => set
                        .execute(params![
                            f,
                            item.as_bytes().as_slice(),
                            id.to_be_bytes().as_slice()
                        ])
                        .map_err(db)?,
                    None => clear
                        .execute(params![f, item.as_bytes().as_slice()])
                        .map_err(db)?,
                };
            }
        }
        match &batch.meta {
            Some(meta) => {
                tx.execute(
                    "INSERT OR REPLACE INTO folders (folder, meta) VALUES (?1, ?2)",
                    params![f, meta],
                )
                .map_err(db)?;
            }
            None => {
                tx.execute(
                    "INSERT OR IGNORE INTO folders (folder, meta) VALUES (?1, x'7b7d')",
                    params![f],
                )
                .map_err(db)?;
            }
        }
        tx.commit().map_err(db)
    }

    fn delete_folder(&mut self, folder: &FolderId) -> Result<(), StoreError> {
        let tx = self.conn.transaction().map_err(db)?;
        let f = folder.as_bytes().as_slice();
        for table in [
            "folders",
            "nodes",
            "file_ids",
            "chunks",
            "objects",
            "plaintexts",
        ] {
            // Table names come from this fixed list only.
            tx.execute(
                &format!("DELETE FROM {table} WHERE folder = ?1"),
                params![f],
            )
            .map_err(db)?;
        }
        // A pull of the folder stored between pages (`folder::pull`) goes with it.
        let pull = format!("pull/{}", folder.to_hex());
        tx.execute(
            "DELETE FROM account WHERE key = ?1 OR key LIKE ?2",
            params![pull, format!("{pull}/%")],
        )
        .map_err(db)?;
        tx.commit().map_err(db)
    }

    fn chunk_list(
        &self,
        folder: &FolderId,
        content: &ContentKey,
    ) -> Result<Option<ChunkList>, StoreError> {
        let row: Option<(Option<i64>, Vec<u8>)> = self
            .conn
            .prepare_cached(
                "SELECT generation, chunks FROM chunks WHERE folder = ?1 AND content = ?2",
            )
            .map_err(db)?
            .query_row(
                params![folder.as_bytes().as_slice(), content.0.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        let Some((generation, bytes)) = row else {
            return Ok(None);
        };
        if bytes.len() % 32 != 0 {
            return Err(StoreError::Corrupt("chunk list".into()));
        }
        let chunks = bytes
            .as_chunks::<32>()
            .0
            .iter()
            .map(|c| ObjectId::from_bytes(*c))
            .collect();
        Ok(Some(ChunkList {
            generation: generation.and_then(|g| u32::try_from(g).ok()),
            chunks,
        }))
    }

    fn put_chunk_list(
        &mut self,
        folder: &FolderId,
        content: &ContentKey,
        list: &ChunkList,
    ) -> Result<(), StoreError> {
        let mut bytes = Vec::with_capacity(32 * list.chunks.len());
        for c in &list.chunks {
            bytes.extend_from_slice(c.as_bytes());
        }
        self.space.ensure(bytes.len())?;
        self.conn
            .prepare_cached(
                "INSERT OR REPLACE INTO chunks (folder, content, generation, chunks)
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(db)?
            .execute(params![
                folder.as_bytes().as_slice(),
                content.0.as_slice(),
                list.generation.map(i64::from),
                bytes
            ])
            .map_err(db)?;
        Ok(())
    }

    fn object_for(
        &self,
        folder: &FolderId,
        digest: &[u8; 32],
    ) -> Result<Option<ObjectId>, StoreError> {
        let row: Option<Vec<u8>> = self
            .conn
            .prepare_cached("SELECT id FROM objects WHERE folder = ?1 AND digest = ?2")
            .map_err(db)?
            .query_row(
                params![folder.as_bytes().as_slice(), digest.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        row.map(|b| blob32(&b).map(ObjectId::from_bytes))
            .transpose()
    }

    fn put_object_for(
        &mut self,
        folder: &FolderId,
        digest: &[u8; 32],
        id: &ObjectId,
    ) -> Result<(), StoreError> {
        self.conn
            .prepare_cached(
                "INSERT OR REPLACE INTO objects (folder, digest, id) VALUES (?1, ?2, ?3)",
            )
            .map_err(db)?
            .execute(params![
                folder.as_bytes().as_slice(),
                digest.as_slice(),
                id.as_bytes().as_slice()
            ])
            .map_err(db)?;
        Ok(())
    }

    fn plaintext(&self, folder: &FolderId, id: &ObjectId) -> Result<Option<Vec<u8>>, StoreError> {
        self.conn
            .prepare_cached("SELECT data FROM plaintexts WHERE folder = ?1 AND id = ?2")
            .map_err(db)?
            .query_row(
                params![folder.as_bytes().as_slice(), id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)
    }

    fn put_plaintext(
        &mut self,
        folder: &FolderId,
        id: &ObjectId,
        plaintext: &[u8],
    ) -> Result<(), StoreError> {
        self.space.ensure(plaintext.len())?;
        self.conn
            .prepare_cached(
                "INSERT OR REPLACE INTO plaintexts (folder, id, data) VALUES (?1, ?2, ?3)",
            )
            .map_err(db)?
            .execute(params![
                folder.as_bytes().as_slice(),
                id.as_bytes().as_slice(),
                plaintext
            ])
            .map_err(db)?;
        Ok(())
    }

    fn retain_cache(
        &mut self,
        folder: &FolderId,
        objects: &std::collections::BTreeSet<ObjectId>,
        contents: &std::collections::BTreeSet<ContentKey>,
    ) -> Result<u64, StoreError> {
        let tx = self.conn.transaction().map_err(db)?;
        let object = |id: &[u8; 32]| objects.contains(&ObjectId::from_bytes(*id));
        let content = |c: &[u8; 32]| contents.contains(&ContentKey(*c));
        let mut gone = Self::retain_rows(&tx, "plaintexts", "id", folder, &object)?;
        gone += Self::retain_rows(&tx, "objects", "id", folder, &object)?;
        gone += Self::retain_rows(&tx, "chunks", "content", folder, &content)?;
        tx.commit().map_err(db)?;
        Ok(gone)
    }

    fn account_value(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.conn
            .query_row(
                "SELECT value FROM account WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)
    }

    fn put_account_value(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO account (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(db)?;
        Ok(())
    }

    fn delete_account_value(&mut self, key: &str) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM account WHERE key = ?1", params![key])
            .map_err(db)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::tests::{file, id};
    use crate::tree::ROOT;

    #[cfg(unix)]
    #[test]
    fn the_index_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join(".tmp")
            .join(format!("index-mode-{}", std::process::id()))
            .join("hangar-drive");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("index.sqlite");
        let mut store = SqliteStore::open(&path).unwrap();
        store.put_account_value("k", b"v").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            let p = PathBuf::from(name);
            if p.exists() {
                assert_eq!(mode(&p), 0o600, "{}", p.display());
            }
        }
        drop(store);
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn folder_state_round_trips_in_one_transaction() {
        let mut store = SqliteStore::in_memory().unwrap();
        let folder = FolderId::from_bytes([1; 16]);
        let mut dir = Node::dir(ROOT, "d");
        dir.conflict_of = Some(id(9));
        let batch = SaveBatch {
            remote: TreeDelta {
                upsert: vec![
                    (id(1), dir.clone()),
                    (id(2), Node::file(id(1), "ä.txt", file(2))),
                ],
                remove: Vec::new(),
            },
            synced: TreeDelta::default(),
            local: TreeDelta {
                upsert: vec![(id(2), Node::file(ROOT, "x", file(3)))],
                remove: Vec::new(),
            },
            file_ids: vec![(id(2), Some(u128::MAX - 5))],
            meta: Some(b"{\"a\":1}".to_vec()),
        };
        store.save_folder(&folder, &batch).unwrap();
        let loaded = store.load_folder(&folder).unwrap().unwrap();
        assert_eq!(loaded.remote.len(), 2);
        assert!(loaded.remote.contains(&(id(1), dir)));
        assert_eq!(loaded.local, vec![(id(2), Node::file(ROOT, "x", file(3)))]);
        assert_eq!(loaded.file_ids, vec![(id(2), u128::MAX - 5)]);
        assert_eq!(loaded.meta, b"{\"a\":1}");
        // Removing rows and file IDs.
        let batch = SaveBatch {
            remote: TreeDelta {
                upsert: Vec::new(),
                remove: vec![id(2)],
            },
            file_ids: vec![(id(2), None)],
            ..SaveBatch::default()
        };
        store.save_folder(&folder, &batch).unwrap();
        let loaded = store.load_folder(&folder).unwrap().unwrap();
        assert_eq!(loaded.remote.len(), 1);
        assert!(loaded.file_ids.is_empty());
        assert_eq!(store.folders().unwrap(), vec![folder]);
        store.delete_folder(&folder).unwrap();
        assert!(store.load_folder(&folder).unwrap().is_none());
    }

    #[test]
    fn caches_and_account_values() {
        let mut store = SqliteStore::in_memory().unwrap();
        let folder = FolderId::from_bytes([1; 16]);
        let content = ContentKey([4; 32]);
        let list = ChunkList {
            generation: Some(2),
            chunks: vec![ObjectId::from_bytes([5; 32]), ObjectId::from_bytes([6; 32])],
        };
        store.put_chunk_list(&folder, &content, &list).unwrap();
        assert_eq!(store.chunk_list(&folder, &content).unwrap(), Some(list));
        let oid = ObjectId::from_bytes([7; 32]);
        store.put_object_for(&folder, &[8; 32], &oid).unwrap();
        assert_eq!(store.object_for(&folder, &[8; 32]).unwrap(), Some(oid));
        store.put_plaintext(&folder, &oid, b"plain").unwrap();
        assert_eq!(store.plaintext(&folder, &oid).unwrap().unwrap(), b"plain");
        store.put_account_value("account", b"v").unwrap();
        assert_eq!(store.account_value("account").unwrap().unwrap(), b"v");
        assert_eq!(store.account_value("other").unwrap(), None);
    }

    /// Security review, MEDIUM 3: the cache keeps only what it is told to, in every table,
    /// and only of that folder.
    #[test]
    fn the_cache_keeps_only_what_is_named() {
        let mut store = SqliteStore::in_memory().unwrap();
        let (a, b) = (FolderId::from_bytes([1; 16]), FolderId::from_bytes([2; 16]));
        let oid = |n: u8| ObjectId::from_bytes([n; 32]);
        let list = ChunkList {
            generation: Some(1),
            chunks: vec![oid(9)],
        };
        for folder in [a, b] {
            for n in 1..=4u8 {
                store.put_plaintext(&folder, &oid(n), b"p").unwrap();
                store.put_object_for(&folder, &[n; 32], &oid(n)).unwrap();
                store
                    .put_chunk_list(&folder, &ContentKey([n; 32]), &list)
                    .unwrap();
            }
        }
        let keep: std::collections::BTreeSet<ObjectId> = [oid(1), oid(3)].into();
        let contents: std::collections::BTreeSet<ContentKey> = [ContentKey([2; 32])].into();
        assert_eq!(store.retain_cache(&a, &keep, &contents).unwrap(), 2 + 2 + 3);
        assert!(store.plaintext(&a, &oid(1)).unwrap().is_some());
        assert!(store.plaintext(&a, &oid(2)).unwrap().is_none());
        assert_eq!(store.object_for(&a, &[3; 32]).unwrap(), Some(oid(3)));
        assert_eq!(store.object_for(&a, &[4; 32]).unwrap(), None);
        assert!(store
            .chunk_list(&a, &ContentKey([2; 32]))
            .unwrap()
            .is_some());
        assert!(store
            .chunk_list(&a, &ContentKey([1; 32]))
            .unwrap()
            .is_none());
        // The other folder keeps everything.
        assert!(store.plaintext(&b, &oid(2)).unwrap().is_some());
        let secure: i64 = store
            .conn
            .pragma_query_value(None, "secure_delete", |r| r.get(0))
            .unwrap();
        assert_eq!(secure, 1);
    }

    /// Security review, MEDIUM 3: without room beyond the reserve on the index volume, the
    /// cache is not written and the store says why; once there is room, it is written again.
    #[test]
    fn a_full_index_volume_stops_the_cache_with_its_own_error() {
        fn full(_: &Path) -> (Option<u64>, Option<u64>) {
            (Some(100 * 1024 * 1024), Some(1 << 40))
        }
        fn roomy(_: &Path) -> (Option<u64>, Option<u64>) {
            (Some(1 << 39), Some(1 << 40))
        }
        let mut store = SqliteStore::in_memory().unwrap();
        store.space = SpaceGuard::new(Some(PathBuf::from("index")));
        store.space.probe = full;
        let folder = FolderId::from_bytes([1; 16]);
        let oid = ObjectId::from_bytes([7; 32]);
        assert_eq!(
            store.put_plaintext(&folder, &oid, b"plain"),
            Err(StoreError::DiskFull)
        );
        let list = ChunkList {
            generation: None,
            chunks: vec![oid],
        };
        assert_eq!(
            store.put_chunk_list(&folder, &ContentKey([1; 32]), &list),
            Err(StoreError::DiskFull)
        );
        assert!(store.plaintext(&folder, &oid).unwrap().is_none());
        store.space.probe = roomy;
        store.space.checked = None;
        store.put_plaintext(&folder, &oid, b"plain").unwrap();
        assert_eq!(
            crate::error::SyncError::from(StoreError::DiskFull).code(),
            crate::error::ErrorKind::DiskFull
        );
    }

    /// Security review of the client changes, LOW 2: a full index volume keeps the plaintexts
    /// of an upload out of the cache, but the publish goes on with the object IDs remembered.
    #[test]
    fn a_full_index_volume_does_not_stop_remembering_an_upload() {
        fn full(_: &Path) -> (Option<u64>, Option<u64>) {
            (Some(100 * 1024 * 1024), Some(1 << 40))
        }
        let mut store = SqliteStore::in_memory().unwrap();
        store.space = SpaceGuard::new(Some(PathBuf::from("index")));
        store.space.probe = full;
        let folder = FolderId::from_bytes([1; 16]);
        let oid = ObjectId::from_bytes([7; 32]);
        let encoded = crate::codec::Encoded {
            root: oid,
            sealed: std::collections::BTreeMap::new(),
            digests: [(oid, [3; 32])].into_iter().collect(),
            plaintexts: [(oid, b"plain".to_vec())].into_iter().collect(),
            reachable: [oid].into_iter().collect(),
            chunks: std::collections::BTreeMap::new(),
        };
        crate::codec::remember_uploaded(&encoded, &folder, &mut store).unwrap();
        assert_eq!(store.object_for(&folder, &[3; 32]).unwrap(), Some(oid));
        assert!(store.plaintext(&folder, &oid).unwrap().is_none());
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
        assert!(SqliteStore::init(conn).is_err());
    }

    #[test]
    fn the_default_path_is_outside_any_sync_folder_by_construction() {
        if let Some(path) = default_index_path() {
            assert!(
                path.ends_with("Hangar Drive/index.sqlite3")
                    || path.ends_with("Hangar Drive\\index.sqlite3")
            );
        }
    }
}
