//! Parallel object uploads (ADR 0001, amendment "upload throughput of the server", section
//! "Parallel uploads on the device").
//!
//! One upload at a time left the line idle for a round trip and the server's flushes per
//! object, which a first sync of many small files feels most. The folder's upload
//! (`FolderSync::run_job`) now hands objects to a [`Lane`]: the controlling thread dispatches
//! them in the queue's read order, sealing threads of the round read each chunk from the disk
//! and seal it ([`Sealers`]), and a few worker threads send it through an [`ObjectUploader`]
//! while the controller books the results. Without an uploader (test doubles, a single worker)
//! the lane seals and sends inline, so both paths share one dispatcher.
//!
//! - **Order:** objects are dispatched in the queue's order (path, chunk index), so the disk is
//!   read from front to back; they may finish in another order.
//! - **Randomness:** the nonce of each seal is drawn from the round's entropy source in
//!   dispatch order, so a seeded test stays reproducible.
//! - **Responsiveness:** the workers own what they send, so they are not tied to the round. A
//!   slow or hanging server holds only them: the round waits for answers in short slices
//!   ([`Lane::next`]) and ends at its budget or as soon as a command waits, leaving what is in
//!   flight in the lane, which the folder keeps for its next round. A paused folder dispatches
//!   nothing new; the objects in flight finish or time out in the background.
//! - **Caps:** [`UPLOAD_WORKERS`] workers per upload by default, never more than
//!   [`MAX_UPLOAD_WORKERS`] (the server's default of uploads per account). The HTTP client adds
//!   [`UploadSlots`] per account connection, so uploads of several folders together never go
//!   beyond the cap either.

use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use hangar_drive_crypto::object::{ObjectKeys, NONCE_LEN};
use hangar_drive_crypto::{Entropy, EntropyError};
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
    /// Chunk `index` of the file at `path`, sealed by the lane with `nonce`.
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

/// What [`Lane::next`] found.
pub(crate) enum Next {
    /// A result.
    Done(Done),
    /// Objects are in flight, but none answered within the wait.
    Waiting,
    /// Nothing is in flight.
    Empty,
}

/// The blob of one object: a sealed node or manifest as it is, a chunk read from the disk and
/// sealed. `None` when the chunk does not read or does not seal to its ID.
fn seal(
    id: &ObjectId,
    payload: Payload,
    fs: &dyn FileSystem,
    keys: Option<&ObjectKeys>,
) -> Option<Bytes> {
    match payload {
        Payload::Sealed(blob) => Some(blob),
        Payload::Chunk { path, index, nonce } => {
            // The controller dispatches a chunk only with the writable keys at hand.
            let keys = keys?;
            let mut nonce = Nonce {
                bytes: nonce,
                used: false,
            };
            seal_chunk(fs, &path, index, id, keys, &mut nonce)
                .ok()
                .map(|sealed| Bytes::from(sealed.blob))
        }
    }
}

/// One sealed object for a worker; `None` when it did not seal, which the worker reports as
/// [`Outcome::Unsealable`] without sending anything.
struct Put {
    id: ObjectId,
    blob: Option<Bytes>,
}

/// The sealing threads of one round ([`Lane::sealers`]): they read and seal chunks in parallel
/// and hand them to the lane's workers. Scoped to the round, since they borrow its disk and
/// keys; they end once this drops and the objects already handed to them are sealed, which
/// takes milliseconds, so the round never waits on the server for them.
pub(crate) struct Sealers {
    tx: SyncSender<Work>,
}

/// The worker threads of a lane; they end once the sender drops and their request is done.
struct Workers {
    tx: Option<SyncSender<Put>>,
    rx: Receiver<Done>,
    /// Set when the lane drops (the upload went, the device signed out): what a worker still
    /// finds queued is not sent with the old session.
    dropped: Arc<AtomicBool>,
}

/// Where the objects of one upload are sent (module docs). It owns nothing borrowed, so it
/// outlives the round that started it: objects still in flight when a round ends stay with the
/// upload job of the folder and are booked by the next round.
pub(crate) struct Lane {
    folder: FolderId,
    width: usize,
    /// Objects submitted whose result was not taken yet.
    in_flight: Vec<ObjectId>,
    /// Results known without a worker: inline uploads and chunks that did not seal.
    ready: VecDeque<Done>,
    /// `None`: every upload goes through the [`ServerApi`] on the controlling thread.
    workers: Option<Workers>,
}

impl Drop for Lane {
    fn drop(&mut self) {
        if let Some(workers) = &self.workers {
            workers.dropped.store(true, Ordering::Release);
        }
    }
}

impl std::fmt::Debug for Lane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lane")
            .field("width", &self.width)
            .field("in_flight", &self.in_flight.len())
            .field("workers", &self.workers.is_some())
            .finish_non_exhaustive()
    }
}

impl Lane {
    /// A lane that does each upload on the calling thread through the [`ServerApi`].
    pub fn inline(folder: FolderId) -> Self {
        Self {
            folder,
            width: 1,
            in_flight: Vec::new(),
            ready: VecDeque::new(),
            workers: None,
        }
    }

    /// A lane of `width` worker threads that send through `uploader`. The threads are not
    /// scoped to the round: a round may end while they still wait for the server, and they end
    /// on their own once the lane drops and their request is answered or timed out. Without a
    /// single thread the lane works inline.
    pub fn workers(width: usize, uploader: Arc<dyn ObjectUploader>, folder: FolderId) -> Self {
        let width = width.clamp(1, MAX_UPLOAD_WORKERS);
        // Bounded by the width: the controller never has more in flight, so neither side
        // blocks on a full channel, and nothing is read ahead of what is being sent.
        let (job_tx, job_rx) = sync_channel::<Put>(width);
        let (res_tx, res_rx) = sync_channel::<Done>(width);
        let job_rx = Arc::new(Mutex::new(job_rx));
        let dropped = Arc::new(AtomicBool::new(false));
        let mut started = 0;
        for _ in 0..width {
            let job_rx = Arc::clone(&job_rx);
            let res_tx = res_tx.clone();
            let uploader = Arc::clone(&uploader);
            let dropped = Arc::clone(&dropped);
            let spawned = std::thread::Builder::new()
                .name("hangar-drive-upload".into())
                .spawn(move || loop {
                    let next = match job_rx.lock() {
                        Ok(rx) => rx.recv(),
                        Err(_) => return,
                    };
                    let Ok(Put { id, blob }) = next else {
                        return;
                    };
                    if dropped.load(Ordering::Acquire) {
                        return;
                    }
                    let Some(blob) = blob else {
                        if res_tx
                            .send(Done {
                                id,
                                outcome: Outcome::Unsealable,
                            })
                            .is_err()
                        {
                            return;
                        }
                        continue;
                    };
                    // A panic in a worker must still answer, or the controller would count the
                    // object in flight for ever; it is reported as a failed upload.
                    let outcome = match catch_unwind(AssertUnwindSafe(|| {
                        uploader.put_object(&folder, &id, blob.clone())
                    })) {
                        Ok(Ok(_)) => Outcome::Sent,
                        Ok(Err(error)) => Outcome::Failed { blob, error },
                        Err(_) => Outcome::Failed {
                            blob: Bytes::new(),
                            error: NetError::Protocol("the upload worker stopped".into()),
                        },
                    };
                    if res_tx.send(Done { id, outcome }).is_err() {
                        return;
                    }
                });
            if spawned.is_ok() {
                started += 1;
            }
        }
        if started == 0 {
            return Self::inline(folder);
        }
        Self {
            folder,
            width: started,
            in_flight: Vec::new(),
            ready: VecDeque::new(),
            workers: Some(Workers {
                tx: Some(job_tx),
                rx: res_rx,
                dropped,
            }),
        }
    }

    /// Takes no new objects any more: the workers end once their request is answered, and the
    /// results of what is in flight stay readable through [`Self::next`]. For a folder that
    /// does not run (paused, stopped, nothing to do), so no worker waits idle.
    pub fn close(&mut self) {
        if let Some(workers) = &mut self.workers {
            workers.tx = None;
        }
    }

    /// Whether [`Self::close`] ended the lane's workers.
    pub fn closed(&self) -> bool {
        self.workers.as_ref().is_some_and(|w| w.tx.is_none())
    }

    /// Objects the lane sends at once.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Objects submitted whose result was not taken yet.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// The objects submitted whose result was not taken yet.
    pub fn in_flight_ids(&self) -> &[ObjectId] {
        &self.in_flight
    }

    /// Sends one object less at once (the server is busy); false when it sends one only.
    pub fn narrow(&mut self) -> bool {
        if self.width <= 1 {
            return false;
        }
        self.width -= 1;
        true
    }

    /// Sealing threads for one round of a lane with workers, one per worker, in `scope`;
    /// `None` for an inline lane or when no thread starts (then [`Self::submit`] seals on the
    /// calling thread).
    pub fn sealers<'scope, 'env>(
        &self,
        scope: &'scope std::thread::Scope<'scope, 'env>,
        fs: &'env dyn FileSystem,
        keys: Option<&'env ObjectKeys>,
    ) -> Option<Sealers> {
        let put_tx = self.workers.as_ref()?.tx.as_ref()?;
        // Bounded by the width like the lane's own channels: nothing is read ahead of what is
        // being sent.
        let (tx, rx) = sync_channel::<Work>(self.width);
        let rx = Arc::new(Mutex::new(rx));
        let mut started = 0;
        for _ in 0..self.width {
            let rx = Arc::clone(&rx);
            let put_tx = put_tx.clone();
            let spawned = std::thread::Builder::new()
                .name("hangar-drive-seal".into())
                .spawn_scoped(scope, move || loop {
                    let next = match rx.lock() {
                        Ok(rx) => rx.recv(),
                        Err(_) => return,
                    };
                    let Ok(work) = next else {
                        return;
                    };
                    let id = work.id;
                    // A panic while sealing still answers, as an object that did not seal.
                    let blob = catch_unwind(AssertUnwindSafe(|| seal(&id, work.payload, fs, keys)))
                        .unwrap_or(None);
                    if put_tx.send(Put { id, blob }).is_err() {
                        return;
                    }
                });
            if spawned.is_ok() {
                started += 1;
            }
        }
        (started > 0).then_some(Sealers { tx })
    }

    /// Hands `work` to the lane: to the round's `sealers` when there are any, which seal it
    /// and pass it to a worker; else it is sealed on the calling thread (a chunk is read from
    /// `fs` and sealed with `keys`) and given to a worker, or sent now through `server` by an
    /// inline lane.
    pub fn submit(
        &mut self,
        work: Work,
        sealers: Option<&Sealers>,
        fs: &dyn FileSystem,
        keys: Option<&ObjectKeys>,
        server: &mut dyn ServerApi,
    ) {
        let id = work.id;
        self.in_flight.push(id);
        let work = match sealers {
            Some(sealers) if self.workers.is_some() => match sealers.tx.send(work) {
                Ok(()) => return,
                // Every sealing thread is gone: sealed here instead.
                Err(std::sync::mpsc::SendError(work)) => work,
            },
            _ => work,
        };
        let Some(blob) = seal(&id, work.payload, fs, keys) else {
            self.ready.push_back(Done {
                id,
                outcome: Outcome::Unsealable,
            });
            return;
        };
        match &mut self.workers {
            None => {
                let outcome = match server.put_object(&self.folder, &id, &blob) {
                    Ok(_) => Outcome::Sent,
                    Err(error) => Outcome::Failed { blob, error },
                };
                self.ready.push_back(Done { id, outcome });
            }
            Some(workers) => {
                if !workers.tx.as_ref().is_some_and(|tx| {
                    tx.send(Put {
                        id,
                        blob: Some(blob),
                    })
                    .is_ok()
                }) {
                    // Every worker is gone: `next` reports the object as failed.
                    workers.tx.take();
                }
            }
        }
    }

    /// The next result. `wait` bounds the wait for a worker (`None`: until one answers), so
    /// the caller can look at its budget and at waiting commands in between.
    pub fn next(&mut self, wait: Option<Duration>) -> Next {
        let done = match self.ready.pop_front() {
            Some(done) => Some(done),
            None if self.in_flight.is_empty() => return Next::Empty,
            None => match &self.workers {
                // Inline results are all in `ready`.
                None => None,
                Some(workers) => match wait {
                    None => workers.rx.recv().ok(),
                    Some(wait) => match workers.rx.recv_timeout(wait) {
                        Ok(done) => Some(done),
                        Err(RecvTimeoutError::Timeout) => return Next::Waiting,
                        Err(RecvTimeoutError::Disconnected) => None,
                    },
                },
            },
        };
        // No answer although objects are in flight: the workers are gone (which their guard
        // against panics rules out in practice). The oldest object comes back as failed, so
        // the caller requeues it and stops instead of waiting for ever.
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
        Next::Done(done)
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
