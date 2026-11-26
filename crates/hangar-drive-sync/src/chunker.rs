//! Fixed 4 MiB chunks (ADR 0001, "Chunking"), their keyed IDs, sealing for upload, and the
//! parallel hashing of many files with backpressure.
//!
//! Hashing reads each file in [`CHUNK_SIZE`] pieces and computes the keyed chunk IDs of the
//! folder's generation; it never keeps more than one chunk per worker in memory. A file whose
//! size or modification time changes while it is read is reported as changed and hashed again
//! at the next scan, so a half-written file never becomes a version.

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
    let before = fs.stat(path)?.ok_or(FsError::NotFound)?;
    if before.kind != EntryType::File {
        return Err(ChunkError::Changed);
    }
    let count = before.size.div_ceil(CHUNK_SIZE);
    let mut chunks = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    let mut buf = Vec::with_capacity(CHUNK_LEN);
    let mut total = 0u64;
    for index in 0..count {
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
}

/// Hashes many files on `threads` workers. Jobs and results pass through channels of bounded
/// size, so a large scan holds at most a few chunks per worker in memory and the caller sees
/// results as they come (backpressure). Results come back in job order.
pub fn hash_many(
    fs: &dyn FileSystem,
    jobs: &[HashJob],
    keys: &BTreeMap<u32, ObjectKeys>,
    threads: usize,
) -> Vec<Result<Hashed, ChunkError>> {
    let threads = threads.clamp(1, 16);
    let mut out: Vec<Option<Result<Hashed, ChunkError>>> = vec![None; jobs.len()];
    if threads == 1 || jobs.len() < 2 {
        for (slot, job) in out.iter_mut().zip(jobs) {
            *slot = Some(hash_one(fs, job, keys));
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
                if res_tx.send((index, hash_one(fs, job, keys))).is_err() {
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
) -> Result<Hashed, ChunkError> {
    let keys = keys
        .get(&job.generation.0)
        .ok_or(ObjectError::UnknownGeneration(job.generation.0))?;
    hash_file(fs, &job.path, keys)
}
