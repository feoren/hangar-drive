//! Fixed 4 MiB chunks (ADR 0001, "Chunking"), their keyed IDs, sealing for upload, and the
//! parallel hashing of many files with backpressure.
//!
//! Hashing reads each file in [`CHUNK_SIZE`] pieces and computes the keyed chunk IDs of the
//! folder's generation; it never keeps more than one chunk per worker in memory. A file whose
//! size or modification time changes while it is read is reported as changed and hashed again
//! at the next scan, so a half-written file never becomes a version.
//!
//! A large file need not be hashed in one go: a job that may wait ([`HashJob::pausable`]) stops
//! between two chunks once the caller's stop condition holds (the round's budget, a waiting
//! command) and comes back as [`ChunkError::Paused`] with the chunk IDs so far. The next scan
//! goes on from there ([`HashJob::resume`]), so a 10 GB file never holds the engine thread for
//! its whole length. It goes on only while the file is provably the same (security review M3):
//! the same size, modification time and file ID, the same change stamp
//! ([`FileSystem::change_stamp`], the status change time, which a write that keeps size and
//! modification time moves as well), and within [`RESUME_WITHIN`] of the pause; a file without a
//! file ID or change stamp is hashed from its start. Otherwise a list of old prefix and new
//! suffix IDs could name a version that never existed.

use std::collections::BTreeMap;
use std::sync::mpsc::sync_channel;

use hangar_drive_crypto::object::{ObjectError, ObjectKeys, SealedObject};
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::ids::{Generation, ObjectId};
use hangar_drive_protocol::object::{ObjectType, CHUNK_SIZE};

use crate::ports::{EntryType, FileSystem, FsError, Stat};

/// Chunk length as a buffer size.
const CHUNK_LEN: usize = CHUNK_SIZE as usize;

/// Why a file was not hashed or a chunk not sealed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChunkError {
    /// The file system failed.
    #[error(transparent)]
    Fs(#[from] FsError),
    /// The crypto layer failed.
    #[error(transparent)]
    Object(#[from] ObjectError),
    /// The file changed while it was read.
    #[error("the file changed while it was read")]
    Changed,
    /// Hashing stopped part way at the caller's stop condition; it goes on from here.
    #[error("hashing stopped part way")]
    Paused(Box<PartialHash>),
}

/// How long after a pause a hash may go on from its chunks so far.
pub const RESUME_WITHIN: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// The chunks of a file hashed so far, to go on from while the file stays as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialHash {
    /// The file's metadata when hashing started.
    pub stat: Stat,
    /// The file's change stamp when hashing started ([`FileSystem::change_stamp`]).
    pub changed: Option<u64>,
    /// When hashing started.
    pub at: std::time::Instant,
    /// The generation whose keys made the IDs.
    pub generation: u32,
    /// The IDs of the first chunks, in order.
    pub chunks: Vec<ObjectId>,
}

impl PartialHash {
    /// Whether hashing may go on from these chunks for a file that now has `stat` and change
    /// stamp `changed` (module docs).
    fn fits(&self, stat: &Stat, changed: Option<u64>, generation: u32, count: u64) -> bool {
        self.generation == generation
            && same_file(&self.stat, stat)
            && stat.file_id.is_some()
            && changed.is_some()
            && self.changed == changed
            && self.at.elapsed() < RESUME_WITHIN
            && (self.chunks.len() as u64) < count
    }
}

/// The chunks of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashed {
    /// The file's metadata when it was read.
    pub stat: Stat,
    /// The chunk IDs in order.
    pub chunks: Vec<ObjectId>,
}

fn same_file(a: &Stat, b: &Stat) -> bool {
    a.kind == b.kind && a.size == b.size && a.mtime_ms == b.mtime_ms && a.file_id == b.file_id
}

/// Reads chunk `index` of the file at `path` into `buf` (cleared first); returns its length.
fn read_chunk(
    fs: &dyn FileSystem,
    path: &[String],
    index: u64,
    buf: &mut Vec<u8>,
) -> Result<usize, ChunkError> {
    buf.clear();
    buf.resize(CHUNK_LEN, 0);
    let start = index * CHUNK_SIZE;
    let mut filled = 0usize;
    while filled < CHUNK_LEN {
        let n = fs.read_at(path, start + filled as u64, &mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(filled)
}

/// Hashes one file under `keys` (module docs).
pub fn hash_file(
    fs: &dyn FileSystem,
    path: &[String],
    keys: &ObjectKeys,
) -> Result<Hashed, ChunkError> {
    hash_file_from(fs, path, keys, 0, None, &|| false)
}

/// [`hash_file`], going on from `resume` when the file is still what it was then, and stopping
/// between two chunks once `stop` holds ([`ChunkError::Paused`]); at least one chunk is hashed
/// per call, so every call moves the file on.
fn hash_file_from(
    fs: &dyn FileSystem,
    path: &[String],
    keys: &ObjectKeys,
    generation: u32,
    resume: Option<&PartialHash>,
    stop: &dyn Fn() -> bool,
) -> Result<Hashed, ChunkError> {
    let before = fs.stat(path)?.ok_or(FsError::NotFound)?;
    if before.kind != EntryType::File {
        return Err(ChunkError::Changed);
    }
    let count = before.size.div_ceil(CHUNK_SIZE);
    // The stamp before any content is read, so a change after it moves the stamp the next
    // resume compares. Only a file of several chunks can pause, so a scan of many small files
    // pays no extra open per file for it.
    let changed = if count > 1 {
        fs.change_stamp(path)
    } else {
        None
    };
    let (first, mut chunks, started, changed) = match resume {
        Some(p) if p.fits(&before, changed, generation, count) => {
            (p.chunks.len() as u64, p.chunks.clone(), p.at, p.changed)
        }
        _ => (
            0,
            Vec::with_capacity(usize::try_from(count).unwrap_or(0)),
            std::time::Instant::now(),
            changed,
        ),
    };
    let mut buf = Vec::with_capacity(CHUNK_LEN);
    // Every chunk before `first` was a whole one.
    let mut total = first.saturating_mul(CHUNK_SIZE);
    for index in first..count {
        if index > first && stop() {
            return Err(ChunkError::Paused(Box::new(PartialHash {
                stat: before,
                changed,
                at: started,
                generation,
                chunks,
            })));
        }
        let n = read_chunk(fs, path, index, &mut buf)?;
        if n == 0 {
            return Err(ChunkError::Changed);
        }
        total += n as u64;
        chunks.push(keys.object_id(ObjectType::Chunk, &buf)?);
    }
    let after = fs.stat(path)?.ok_or(FsError::NotFound)?;
    if !same_file(&before, &after) || total != before.size {
        return Err(ChunkError::Changed);
    }
    Ok(Hashed {
        stat: before,
        chunks,
    })
}

/// Seals chunk `index` of the file at `path` for upload; refuses a chunk whose ID is no longer
/// `expected` (the file changed since it was hashed).
pub fn seal_chunk(
    fs: &dyn FileSystem,
    path: &[String],
    index: u64,
    expected: &ObjectId,
    keys: &ObjectKeys,
    entropy: &mut dyn Entropy,
) -> Result<SealedObject, ChunkError> {
    let mut buf = Vec::with_capacity(CHUNK_LEN);
    read_chunk(fs, path, index, &mut buf)?;
    let sealed = keys.seal(ObjectType::Chunk, &buf, &mut DynEntropy(entropy))?;
    if sealed.id != *expected {
        return Err(ChunkError::Changed);
    }
    Ok(sealed)
}

/// Adapts a `&mut dyn Entropy` to the crypto crate's `impl Entropy` parameters.
pub struct DynEntropy<'a>(pub &'a mut dyn Entropy);

impl Entropy for DynEntropy<'_> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), hangar_drive_crypto::EntropyError> {
        self.0.fill(dest)
    }
}

/// One file to hash, and the generation whose keys to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashJob {
    /// The path below the root.
    pub path: Vec<String>,
    /// The generation.
    pub generation: Generation,
    /// Whether hashing may stop part way ([`ChunkError::Paused`]); only for a file the scan
    /// may leave for later.
    pub pausable: bool,
    /// The chunks an earlier scan hashed, to go on from.
    pub resume: Option<PartialHash>,
}

impl HashJob {
    /// A job that hashes the whole file.
    pub fn whole(path: Vec<String>, generation: Generation) -> Self {
        Self {
            path,
            generation,
            pausable: false,
            resume: None,
        }
    }
}

/// Hashes many files on `threads` workers. Jobs and results pass through channels of bounded
/// size, so a large scan holds at most a few chunks per worker in memory and the caller sees
/// results as they come (backpressure). Results come back in job order. A pausable job stops
/// part way once `stop` holds.
pub fn hash_many(
    fs: &dyn FileSystem,
    jobs: &[HashJob],
    keys: &BTreeMap<u32, ObjectKeys>,
    threads: usize,
    stop: &(dyn Fn() -> bool + Sync),
) -> Vec<Result<Hashed, ChunkError>> {
    let threads = threads.clamp(1, 16);
    let mut out: Vec<Option<Result<Hashed, ChunkError>>> = vec![None; jobs.len()];
    if threads == 1 || jobs.len() < 2 {
        for (slot, job) in out.iter_mut().zip(jobs) {
            *slot = Some(hash_one(fs, job, keys, stop));
        }
        return out.into_iter().flatten().collect();
    }
    let (job_tx, job_rx) = sync_channel::<(usize, &HashJob)>(threads * 2);
    let job_rx = std::sync::Mutex::new(job_rx);
    std::thread::scope(|scope| {
        let (res_tx, res_rx) = sync_channel::<(usize, Result<Hashed, ChunkError>)>(threads * 2);
        for _ in 0..threads {
            let res_tx = res_tx.clone();
            let job_rx = &job_rx;
            scope.spawn(move || loop {
                let next = match job_rx.lock() {
                    Ok(rx) => rx.recv(),
                    Err(_) => return,
                };
                let Ok((index, job)) = next else {
                    return;
                };
                if res_tx.send((index, hash_one(fs, job, keys, stop))).is_err() {
                    return;
                }
            });
        }
        drop(res_tx);
        scope.spawn(move || {
            for item in jobs.iter().enumerate() {
                if job_tx.send(item).is_err() {
                    return;
                }
            }
        });
        for (index, result) in res_rx {
            if let Some(slot) = out.get_mut(index) {
                *slot = Some(result);
            }
        }
    });
    out.into_iter()
        .map(|slot| slot.unwrap_or(Err(ChunkError::Changed)))
        .collect()
}

fn hash_one(
    fs: &dyn FileSystem,
    job: &HashJob,
    keys: &BTreeMap<u32, ObjectKeys>,
    stop: &(dyn Fn() -> bool + Sync),
) -> Result<Hashed, ChunkError> {
    let keys = keys
        .get(&job.generation.0)
        .ok_or(ObjectError::UnknownGeneration(job.generation.0))?;
    let never = || false;
    let stop: &dyn Fn() -> bool = if job.pausable { stop } else { &never };
    hash_file_from(
        fs,
        &job.path,
        keys,
        job.generation.0,
        job.resume.as_ref(),
        stop,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemFs;

    struct Fixed;
    impl Entropy for Fixed {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), hangar_drive_crypto::EntropyError> {
            dest.fill(5);
            Ok(())
        }
    }

    fn keys() -> ObjectKeys {
        let account = hangar_drive_protocol::ids::AccountId::from_bytes([1; 16]);
        let ring = hangar_drive_crypto::folder_keys::FolderKeyRing::new(
            hangar_drive_protocol::ids::FolderId::from_bytes([2; 16]),
            1,
            &mut Fixed,
        )
        .unwrap();
        ObjectKeys::from_ring(&account, &ring, Generation(1)).unwrap()
    }

    fn content(tag: u8) -> Vec<u8> {
        let mut data = vec![tag; 3 * CHUNK_LEN];
        data[0] = 0x10;
        data[CHUNK_LEN] = 0x11;
        data[2 * CHUNK_LEN] = 0x12;
        data
    }

    fn path() -> Vec<String> {
        vec!["big.bin".to_owned()]
    }

    /// A hash paused after its first chunk.
    fn paused(fs: &dyn FileSystem, keys: &ObjectKeys) -> PartialHash {
        match hash_file_from(fs, &path(), keys, 1, None, &|| true) {
            Err(ChunkError::Paused(p)) => *p,
            other => panic!("not paused: {other:?}"),
        }
    }

    /// Security review M3: a writer that changes the part already hashed but keeps size,
    /// modification time and file ID (a container that keeps its time stamp, a mapped file)
    /// moves the change stamp, so the hash starts over and names the new content only.
    #[test]
    fn a_change_that_keeps_size_and_time_starts_the_hash_over() {
        let fs = MemFs::new(true);
        let keys = keys();
        assert!(fs.user_write(&path(), &content(1)));
        let partial = paused(&fs, &keys);
        assert_eq!(partial.chunks.len(), 1);
        fs.overwrite_in_place(&path(), &content(2));
        let resumed = hash_file_from(&fs, &path(), &keys, 1, Some(&partial), &|| false).unwrap();
        let fresh = hash_file(&fs, &path(), &keys).unwrap();
        assert_eq!(
            resumed.chunks, fresh.chunks,
            "a list of old and new chunk IDs"
        );
        // Unchanged, it goes on from the chunks so far.
        let partial = paused(&fs, &keys);
        let resumed = hash_file_from(&fs, &path(), &keys, 1, Some(&partial), &|| false).unwrap();
        assert_eq!(resumed.chunks, fresh.chunks);
        assert_eq!(resumed.chunks[0], partial.chunks[0]);
    }

    /// No resume without a change stamp or a file ID, nor after [`RESUME_WITHIN`].
    #[test]
    fn a_hash_goes_on_only_while_the_file_is_provably_the_same() {
        let fs = MemFs::new(true);
        let keys = keys();
        assert!(fs.user_write(&path(), &content(3)));
        let partial = paused(&fs, &keys);
        let size = 3 * CHUNK_SIZE;
        let stat = fs.stat(&path()).unwrap().unwrap();
        let stamp = fs.change_stamp(&path());
        assert!(
            partial.fits(&stat, stamp, 1, 3),
            "an unchanged file goes on"
        );
        assert!(!partial.fits(&stat, None, 1, 3), "no change stamp");
        let no_id = Stat {
            file_id: None,
            ..stat
        };
        let mut without = partial.clone();
        without.stat.file_id = None;
        assert!(!without.fits(&no_id, stamp, 1, 3), "no file ID");
        if let Some(long_ago) = std::time::Instant::now().checked_sub(RESUME_WITHIN * 2) {
            let mut old = partial.clone();
            old.at = long_ago;
            assert!(!old.fits(&stat, stamp, 1, 3), "past the time limit");
        }
        assert!(!partial.fits(&stat, stamp, 2, 3), "another generation");
        assert_eq!(stat.size, size);
    }
}
