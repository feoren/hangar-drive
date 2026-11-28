//! Parallel object uploads (ADR 0001, amendment "upload throughput of the server", section
//! "Parallel uploads on the device").
//!
//! One upload at a time left the line idle for a round trip and the server's flushes per
//! object, which a first sync of many small files feels most. The folder's upload
//! (`FolderSync::run_job`) now hands objects to a [`Lane`]: a few worker threads that read a
//! chunk from the disk, seal it and send it through an [`ObjectUploader`], while the
//! controlling thread only dispatches in the queue's read order and books the results. Without
//! an uploader (test doubles, a single worker) the lane does the same work inline, so both
//! paths share one dispatcher.
//!
//! - **Order:** objects are dispatched in the queue's order (path, chunk index), so the disk is
//!   still read mostly from front to back; they may finish in another order.
//! - **Randomness:** the nonce of each seal is drawn from the round's entropy source on the
//!   controlling thread, in dispatch order, so a seeded test stays reproducible and the
//!   source never needs to be shared between threads.
//! - **Caps:** [`UPLOAD_WORKERS`] workers per upload by default, never more than
//!   [`MAX_UPLOAD_WORKERS`] (the server's default of uploads per account). The HTTP client adds
//!   [`UploadSlots`] per account connection, so uploads of several folders together never go
//!   beyond the cap either.

use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use bytes::Bytes;
use hangar_drive_crypto::object::{ObjectKeys, NONCE_LEN};
use hangar_drive_crypto::{Entropy, EntropyError};
use hangar_drive_protocol::api::UploadResponse;
use hangar_drive_protocol::ids::{FolderId, ObjectId};

use crate::chunker::seal_chunk;
use crate::ports::{FileSystem, NetError, ObjectUploader, ServerApi};

/// Objects one upload sends at once by default: enough to keep a line busy across the round
/// trip and the server's flushes, and half of the server's default of uploads per account
/// (`HANGAR_DRIVE_UPLOADS_PER_ACCOUNT`, 8), so another device of the account still finds slots.
pub const UPLOAD_WORKERS: usize = 4;
/// The most objects one upload sends at once, whatever the settings say: the server's default
/// of uploads per account. More would only collect `rate_limited` answers.
pub const MAX_UPLOAD_WORKERS: usize = 8;

/// A counting semaphore for uploads in flight, shared by every uploader of one account
/// connection.
#[derive(Debug)]
pub struct UploadSlots {
    free: Mutex<usize>,
    freed: Condvar,
}

impl UploadSlots {
    /// `slots` uploads at once (at least one).
    pub fn new(slots: usize) -> Self {
        Self {
            free: Mutex::new(slots.max(1)),
            freed: Condvar::new(),
        }
    }

    /// Waits for a free slot; it is given back when the guard drops.
    pub fn acquire(&self) -> SlotGuard<'_> {
        // The count is a plain number; one written by a thread that panicked is still whole.
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        while *free == 0 {
            free = self
                .freed
                .wait(free)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *free -= 1;
        SlotGuard(self)
    }
}

/// One taken slot of [`UploadSlots`].
#[derive(Debug)]
pub struct SlotGuard<'a>(&'a UploadSlots);

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        let mut free = self.0.free.lock().unwrap_or_else(PoisonError::into_inner);
        *free += 1;
        self.0.freed.notify_one();
    }
}

/// The nonce of one seal, drawn beforehand on the controlling thread (module docs). It hands
/// out exactly one nonce; a seal that asked for other bytes fails instead of reusing them.
struct Nonce {
    bytes: [u8; NONCE_LEN],
    used: bool,
}

impl Entropy for Nonce {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        if self.used || dest.len() != NONCE_LEN {
            return Err(EntropyError);
        }
        dest.copy_from_slice(&self.bytes);
        self.used = true;
        Ok(())
    }
}

/// Draws the nonce for one chunk seal from `entropy`.
pub(crate) fn draw_nonce(entropy: &mut dyn Entropy) -> Result<[u8; NONCE_LEN], EntropyError> {
    let mut nonce = [0u8; NONCE_LEN];
    entropy.fill(&mut nonce)?;
    Ok(nonce)
}

/// What one upload sends.
pub(crate) enum Payload {
    /// A node or manifest sealed when the tree was encoded.
    Sealed(Bytes),
    /// Chunk `index` of the file at `path`, sealed by the worker with `nonce`.
    Chunk {
        path: Vec<String>,
        index: u64,
        nonce: [u8; NONCE_LEN],
    },
}

/// One object for the lane.
pub(crate) struct Work {
    pub id: ObjectId,
    pub payload: Payload,
}

/// How one upload ended.
pub(crate) enum Outcome {
    /// The server has the object.
    Sent,
    /// The chunk did not read or did not seal to its ID: the file changed since it was hashed,
    /// or its chunks were hashed under another generation.
    Unsealable,
    /// The server call failed after the client's own retries; `blob` is what was sent, for a
    /// retry on the controlling thread.
    Failed { blob: Bytes, error: NetError },
}

/// The result of one [`Work`].
pub(crate) struct Done {
    pub id: ObjectId,
    pub outcome: Outcome,
}

/// Seals (for a chunk) and sends one object through `put`.
fn perform(
    work: Work,
    fs: &dyn FileSystem,
    keys: Option<&ObjectKeys>,
    put: impl FnOnce(Bytes) -> Result<UploadResponse, NetError>,
) -> Done {
    let id = work.id;
    let blob = match work.payload {
        Payload::Sealed(blob) => blob,
        Payload::Chunk { path, index, nonce } => {
            // The controller dispatches a chunk only with the writable keys at hand.
            let Some(keys) = keys else {
                return Done {
                    id,
                    outcome: Outcome::Unsealable,
                };
            };
            let mut nonce = Nonce {
                bytes: nonce,
                used: false,
            };
            match seal_chunk(fs, &path, index, &id, keys, &mut nonce) {
                Ok(sealed) => Bytes::from(sealed.blob),
                Err(_) => {
                    return Done {
                        id,
                        outcome: Outcome::Unsealable,
                    }
                }
            }
        }
    };
    let outcome = match put(blob.clone()) {
        Ok(_) => Outcome::Sent,
        Err(error) => Outcome::Failed { blob, error },
    };
    Done { id, outcome }
}

enum Kind {
    /// Every object is sealed and sent on the controlling thread when it is submitted.
    Inline(VecDeque<Done>),
    /// Worker threads; the sender closes with the lane.
    Workers {
        tx: Option<SyncSender<Work>>,
        rx: Receiver<Done>,
    },
}

/// Where the objects of one upload are sent (module docs).
pub(crate) struct Lane<'env> {
    fs: &'env dyn FileSystem,
    keys: Option<&'env ObjectKeys>,
    folder: FolderId,
    width: usize,
    /// Objects submitted whose result was not taken yet.
    in_flight: Vec<ObjectId>,
    kind: Kind,
}

impl<'env> Lane<'env> {
    /// A lane that does each upload on the calling thread through the [`ServerApi`].
    pub fn inline(
        fs: &'env dyn FileSystem,
        keys: Option<&'env ObjectKeys>,
        folder: FolderId,
    ) -> Self {
        Self {
            fs,
            keys,
            folder,
            width: 1,
            in_flight: Vec::new(),
            kind: Kind::Inline(VecDeque::new()),
        }
    }

    /// A lane of `width` worker threads in `scope` that send through `uploader`.
    pub fn workers<'scope>(
        scope: &'scope std::thread::Scope<'scope, 'env>,
        width: usize,
        uploader: Arc<dyn ObjectUploader>,
        fs: &'env dyn FileSystem,
        keys: Option<&'env ObjectKeys>,
        folder: FolderId,
    ) -> Self {
        let width = width.clamp(1, MAX_UPLOAD_WORKERS);
        // Bounded by the width: the controller never has more in flight, so neither side
        // blocks on a full channel, and nothing is read ahead of what is being sent.
        let (job_tx, job_rx) = sync_channel::<Work>(width);
        let (res_tx, res_rx) = sync_channel::<Done>(width);
        let job_rx = Arc::new(Mutex::new(job_rx));
        for _ in 0..width {
            let job_rx = Arc::clone(&job_rx);
            let res_tx = res_tx.clone();
            let uploader = Arc::clone(&uploader);
            scope.spawn(move || loop {
                let next = match job_rx.lock() {
                    Ok(rx) => rx.recv(),
                    Err(_) => return,
                };
                let Ok(work) = next else {
                    return;
                };
                let id = work.id;
                // A panic in a worker must still answer, or the controller would wait for it
                // for ever; it is reported as a failed upload.
                let done = catch_unwind(AssertUnwindSafe(|| {
                    perform(work, fs, keys, |blob| {
                        uploader.put_object(&folder, &id, blob)
                    })
                }))
                .unwrap_or_else(|_| Done {
                    id,
                    outcome: Outcome::Failed {
                        blob: Bytes::new(),
                        error: NetError::Protocol("the upload worker stopped".into()),
                    },
                });
                if res_tx.send(done).is_err() {
                    return;
                }
            });
        }
        Self {
            fs,
            keys,
            folder,
            width,
            in_flight: Vec::new(),
            kind: Kind::Workers {
                tx: Some(job_tx),
                rx: res_rx,
            },
        }
    }

    /// Objects the lane sends at once.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Objects submitted whose result was not taken yet.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Sends one object less at once (the server is busy); false when it sends one only.
    pub fn narrow(&mut self) -> bool {
        if self.width <= 1 {
            return false;
        }
        self.width -= 1;
        true
    }

    /// Hands `work` to the lane; an inline lane does it now through `server`.
    pub fn submit(&mut self, work: Work, server: &mut dyn ServerApi) {
        let folder = self.folder;
        let id = work.id;
        self.in_flight.push(id);
        match &mut self.kind {
            Kind::Inline(done) => {
                done.push_back(perform(work, self.fs, self.keys, |blob| {
                    server.put_object(&folder, &id, &blob)
                }));
            }
            Kind::Workers { tx, .. } => {
                if !tx.as_ref().is_some_and(|tx| tx.send(work).is_ok()) {
                    // Every worker is gone: `next` reports the object as failed.
                    tx.take();
                }
            }
        }
    }

    /// The next result; waits for a worker. `None` when nothing is in flight.
    pub fn next(&mut self) -> Option<Done> {
        if self.in_flight.is_empty() {
            return None;
        }
        let done = match &mut self.kind {
            Kind::Inline(done) => done.pop_front(),
            Kind::Workers { rx, .. } => rx.recv().ok(),
        };
        // No answer although objects are in flight: the workers are gone (which `perform`'s
        // guard against panics rules out in practice). The oldest object comes back as failed,
        // so the caller requeues it and stops instead of waiting for ever.
        let done = done.unwrap_or_else(|| Done {
            id: self.in_flight[0],
            outcome: Outcome::Failed {
                blob: Bytes::new(),
                error: NetError::Protocol("the upload worker stopped".into()),
            },
        });
        if let Some(at) = self.in_flight.iter().position(|id| *id == done.id) {
            self.in_flight.swap_remove(at);
        }
        Some(done)
    }

    /// Ends the workers once nothing is in flight.
    pub fn close(&mut self) {
        if let Kind::Workers { tx, .. } = &mut self.kind {
            tx.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use hangar_drive_protocol::object::ObjectType;

    use super::*;

    #[test]
    fn slots_never_let_more_uploads_through_than_they_hold() {
        let slots = UploadSlots::new(3);
        let now = AtomicUsize::new(0);
        let most = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..5 {
                        let _slot = slots.acquire();
                        let in_flight = now.fetch_add(1, Ordering::SeqCst) + 1;
                        most.fetch_max(in_flight, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(2));
                        now.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });
        let most = most.load(Ordering::SeqCst);
        assert!((2..=3).contains(&most), "{most}");
        assert_eq!(*slots.free.lock().unwrap(), 3, "every slot came back");
    }

    #[test]
    fn a_drawn_nonce_seals_one_object_and_only_one() {
        struct Fixed;
        impl Entropy for Fixed {
            fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
                dest.fill(5);
                Ok(())
            }
        }
        let account = hangar_drive_protocol::ids::AccountId::from_bytes([1; 16]);
        let ring = hangar_drive_crypto::folder_keys::FolderKeyRing::new(
            FolderId::from_bytes([2; 16]),
            1,
            &mut Fixed,
        )
        .unwrap();
        let keys =
            ObjectKeys::from_ring(&account, &ring, hangar_drive_protocol::ids::Generation(1))
                .unwrap();
        let mut nonce = Nonce {
            bytes: [4; NONCE_LEN],
            used: false,
        };
        // Sealing draws exactly one nonce of NONCE_LEN bytes; a drift in the crypto crate
        // fails here instead of in every upload.
        let sealed = keys.seal(ObjectType::Chunk, b"chunk", &mut nonce).unwrap();
        let opened = keys
            .open(&sealed.id, ObjectType::Chunk, &sealed.blob)
            .unwrap();
        assert_eq!(opened.as_slice(), b"chunk");
        assert!(keys.seal(ObjectType::Chunk, b"chunk", &mut nonce).is_err());
    }
}
