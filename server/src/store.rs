//! The object store (ADR 0001, section 3): encrypted objects on the file system behind a trait,
//! so another backend (S3 through `object_store`) can follow without touching the services.
//!
//! Layout: `<root>/<account>/<folder>/<id[0..2]>/<id[2..4]>/<id>`, all lowercase hex. Two
//! levels of 256 fan-out keep directories small (a million objects of a folder give about 16
//! per directory). An upload is written to a staging file on the same file system, flushed to
//! disk, renamed into place and the directory flushed, so a stored object is either complete or
//! absent, even after a power failure. A directory the install creates (account, folder, the
//! two fan-out levels) is flushed into its parent once, when it is made: otherwise the rename
//! would be durable inside a directory whose own entry a power failure could still lose.
//!
//! The trait is synchronous; the server calls it through `spawn_blocking`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use hangar_drive_crypto::{Entropy, OsEntropy};
use hangar_drive_protocol::ids::{AccountId, FolderId, ObjectId};

/// Where one object lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectKey {
    pub account: AccountId,
    pub folder: FolderId,
    pub id: ObjectId,
}

pub trait ObjectStore: Send + Sync + 'static {
    /// A fresh staging path for an upload on the store's file system. The caller writes the
    /// blob there and then calls [`ObjectStore::install`] or removes it.
    fn staging_path(&self) -> io::Result<PathBuf>;
    /// Moves a fully written staging file to `key`, durably. The caller has flushed the staging
    /// file to disk already (before it took the database's write lock, finding M4); this renames
    /// it and flushes the directory. An existing object is replaced by identical bytes at most
    /// (IDs are keyed hashes of the plaintext).
    fn install(&self, staged: &Path, key: &ObjectKey) -> io::Result<()>;
    /// Opens a stored object for reading.
    fn open(&self, key: &ObjectKey) -> io::Result<fs::File>;
    /// Deletes an object; a missing one is not an error.
    fn delete(&self, key: &ObjectKey) -> io::Result<()>;
    /// Deletes every object of a folder.
    fn delete_folder(&self, account: &AccountId, folder: &FolderId) -> io::Result<()>;
    /// Deletes every object of an account.
    fn delete_account(&self, account: &AccountId) -> io::Result<()>;
    /// Calls `visit` with every stored object and its modification time (for the sweep of
    /// files the database does not know).
    fn walk(&self, visit: &mut dyn FnMut(ObjectKey, SystemTime)) -> io::Result<()>;
}

/// The file system store.
#[derive(Debug, Clone)]
pub struct FsStore {
    root: PathBuf,
    staging: PathBuf,
    /// Held while an install looks for missing directories, makes them and flushes their
    /// parents. An install that finds its directory present therefore never renames into it
    /// before the install that made it has flushed its entry.
    mkdir: Arc<Mutex<()>>,
    /// Directory flushes so far (tests count them; Windows skips the flush itself).
    dir_syncs: Arc<AtomicU64>,
}

impl FsStore {
    /// A store under `root`, staging under `staging` (same file system, so the rename is
    /// atomic). Removes staging files a crash left behind.
    pub fn open(root: PathBuf, staging: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&staging)?;
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let _ = fs::remove_file(entry.path());
            }
        }
        Ok(Self {
            root,
            staging,
            mkdir: Arc::new(Mutex::new(())),
            dir_syncs: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Directory flushes so far.
    pub fn dir_syncs(&self) -> u64 {
        self.dir_syncs.load(Ordering::Relaxed)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        self.dir_syncs.fetch_add(1, Ordering::Relaxed);
        sync_dir(dir)
    }

    /// Makes `dir` and every missing parent below the root, and flushes each new directory's
    /// entry into its parent (module docs). Nothing to do when `dir` exists.
    fn create_dirs_durably(&self, dir: &Path) -> io::Result<()> {
        let _making = self
            .mkdir
            .lock()
            .map_err(|_| io::Error::other("directory lock poisoned"))?;
        let mut missing = Vec::new();
        let mut current = dir;
        while current != self.root && !current.is_dir() {
            missing.push(current);
            current = match current.parent() {
                Some(parent) => parent,
                None => break,
            };
        }
        if missing.is_empty() {
            return Ok(());
        }
        fs::create_dir_all(dir)?;
        // Deepest first; each new entry is flushed into its parent, ending at an existing one.
        for made in missing {
            let parent = made
                .parent()
                .ok_or_else(|| io::Error::other("object directory without parent"))?;
            self.sync_dir(parent)?;
        }
        Ok(())
    }

    fn folder_dir(&self, account: &AccountId, folder: &FolderId) -> PathBuf {
        self.root.join(account.to_hex()).join(folder.to_hex())
    }

    fn path(&self, key: &ObjectKey) -> PathBuf {
        let id = key.id.to_hex();
        self.folder_dir(&key.account, &key.folder)
            .join(&id[0..2])
            .join(&id[2..4])
            .join(id)
    }
}

/// Flushes a directory entry (rename, create) to disk. Windows cannot open directories as files;
/// NTFS journals the rename itself, so there it is skipped.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn not_found_ok(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

impl ObjectStore for FsStore {
    fn staging_path(&self) -> io::Result<PathBuf> {
        let mut name = [0u8; 16];
        OsEntropy
            .fill(&mut name)
            .map_err(|_| io::Error::other("no randomness for a staging name"))?;
        let name: String = name.iter().map(|b| format!("{b:02x}")).collect();
        Ok(self.staging.join(format!("{name}.part")))
    }

    fn install(&self, staged: &Path, key: &ObjectKey) -> io::Result<()> {
        let target = self.path(key);
        let dir = target
            .parent()
            .ok_or_else(|| io::Error::other("object path without parent"))?;
        self.create_dirs_durably(dir)?;
        fs::rename(staged, &target)?;
        self.sync_dir(dir)
    }

    fn open(&self, key: &ObjectKey) -> io::Result<fs::File> {
        fs::File::open(self.path(key))
    }

    fn delete(&self, key: &ObjectKey) -> io::Result<()> {
        not_found_ok(fs::remove_file(self.path(key)))
    }

    fn delete_folder(&self, account: &AccountId, folder: &FolderId) -> io::Result<()> {
        not_found_ok(fs::remove_dir_all(self.folder_dir(account, folder)))
    }

    fn delete_account(&self, account: &AccountId) -> io::Result<()> {
        not_found_ok(fs::remove_dir_all(self.root.join(account.to_hex())))
    }

    fn walk(&self, visit: &mut dyn FnMut(ObjectKey, SystemTime)) -> io::Result<()> {
        for account in fs::read_dir(&self.root)? {
            let account = account?;
            let Ok(account_id) = AccountId::from_hex(&account.file_name().to_string_lossy()) else {
                continue;
            };
            for folder in fs::read_dir(account.path())? {
                let folder = folder?;
                let Ok(folder_id) = FolderId::from_hex(&folder.file_name().to_string_lossy())
                else {
                    continue;
                };
                for a in fs::read_dir(folder.path())? {
                    let a = a?;
                    if !a.file_type()?.is_dir() {
                        continue;
                    }
                    for b in fs::read_dir(a.path())? {
                        let b = b?;
                        if !b.file_type()?.is_dir() {
                            continue;
                        }
                        for object in fs::read_dir(b.path())? {
                            let object = object?;
                            let Ok(id) = ObjectId::from_hex(&object.file_name().to_string_lossy())
                            else {
                                continue;
                            };
                            let modified = object.metadata()?.modified()?;
                            visit(
                                ObjectKey {
                                    account: account_id,
                                    folder: folder_id,
                                    id,
                                },
                                modified,
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/.tmp/server-unit")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn install_open_walk_and_delete() {
        let root = temp_root("store");
        let store = FsStore::open(root.join("objects"), root.join("staging")).unwrap();
        let key = ObjectKey {
            account: AccountId::from_bytes([1; 16]),
            folder: FolderId::from_bytes([2; 16]),
            id: ObjectId::from_bytes([0xab; 32]),
        };
        let staged = store.staging_path().unwrap();
        fs::write(&staged, b"blob").unwrap();
        store.install(&staged, &key).unwrap();
        assert!(!staged.exists(), "the staging file moved");
        let path = store.path(&key);
        let parts: Vec<String> = path
            .strip_prefix(root.join("objects"))
            .unwrap()
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            parts,
            [
                "01".repeat(16),
                "02".repeat(16),
                "ab".into(),
                "ab".into(),
                "ab".repeat(32)
            ]
        );
        let mut text = String::new();
        io::Read::read_to_string(&mut store.open(&key).unwrap(), &mut text).unwrap();
        assert_eq!(text, "blob");
        let mut seen = Vec::new();
        store.walk(&mut |k, _| seen.push(k)).unwrap();
        assert_eq!(seen, vec![key]);
        store.delete(&key).unwrap();
        store.delete(&key).unwrap();
        assert!(store.open(&key).is_err());
        store.delete_folder(&key.account, &key.folder).unwrap();
        store.delete_account(&key.account).unwrap();
    }

    #[test]
    fn new_directories_are_flushed_into_their_parents_once() {
        let root = temp_root("dir-sync");
        let store = FsStore::open(root.join("objects"), root.join("staging")).unwrap();
        let account = AccountId::from_bytes([1; 16]);
        let folder = FolderId::from_bytes([2; 16]);
        let install = |id: [u8; 32]| {
            let key = ObjectKey {
                account,
                folder,
                id: ObjectId::from_bytes(id),
            };
            let staged = store.staging_path().unwrap();
            fs::write(&staged, b"blob").unwrap();
            let before = store.dir_syncs();
            store.install(&staged, &key).unwrap();
            assert!(store.path(&key).is_file());
            store.dir_syncs() - before
        };
        // Account, folder and both fan-out levels are new: four parents, then the directory
        // that received the rename.
        assert_eq!(install([0xab; 32]), 5);
        // Same directory: only the rename's flush.
        let mut id = [0xab; 32];
        id[31] = 0x01;
        assert_eq!(install(id), 1);
        // A new second level under a known first level: its parent, then the rename's flush.
        let mut id = [0xab; 32];
        id[1] = 0xcd;
        assert_eq!(install(id), 2);
        // After the folder's directory was removed (the folder was deleted), it is made and
        // flushed again: folder and both levels, then the rename's flush.
        store.delete_folder(&account, &folder).unwrap();
        assert_eq!(install([0xab; 32]), 4);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn leftover_staging_files_are_removed_at_open() {
        let root = temp_root("staging");
        fs::create_dir_all(root.join("staging")).unwrap();
        fs::write(root.join("staging/old.part"), b"x").unwrap();
        FsStore::open(root.join("objects"), root.join("staging")).unwrap();
        assert!(!root.join("staging/old.part").exists());
    }
}
