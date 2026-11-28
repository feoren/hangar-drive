//! Parallel object downloads.
//!
//! One download at a time left the line idle for a round trip per object, which the arrival of
//! many small files from another device feels most. A folder's apply run takes its chunks from a
//! [`FetchLane`]: a few worker threads that fetch sealed objects through an [`ObjectFetcher`],
//! ahead of the executor in the order it will write the files ([`FetchLane::ahead`]), while the
//! round's thread opens each chunk and writes the files one at a time as before.
//!
//! - **Memory:** a lane fetches ahead only while what it holds (in flight or fetched and not
//!   taken, counted by the bytes expected of each object) stays within [`FETCH_WINDOW_BYTES`],
//!   and all lanes of one engine together within [`FETCH_ACCOUNT_BYTES`] ([`FetchBudget`]), so
//!   many folders that download at once do not multiply it. A chunk the executor needs now is
//!   fetched by [`FetchLane::take`] itself, beyond the window by that one object, so it never
//!   waits on itself; objects a new plan no longer names are dropped ([`FetchLane::ahead`]).
//! - **Responsiveness:** the round waits for a chunk in slices of [`WAIT_SLICE`] and gives up
//!   the wait once its budget is spent or a command waits ([`Fetched::Stopped`]); what is in
//!   flight stays with the lane, which the folder keeps for its next round.
//! - **Caps:** [`DOWNLOAD_WORKERS`] at once by default and never more than
//!   [`MAX_DOWNLOAD_WORKERS`]; the HTTP client adds its own slots per account connection, so the
//!   folders of one device together stay within the default as well. A busy server
//!   (`rate_limited`, after the client's own `Retry-After` wait) narrows the lane by one.
//! - **Sessions:** a worker never signs in; a chunk it got `unauthorized` for is fetched again on
//!   the round's thread, which signs in and renews the token for the workers too. Once the lane
//!   drops (the folder went, the device signed out), its workers send nothing they still had
//!   queued.

use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hangar_drive_protocol::api::ErrorCode;
use hangar_drive_protocol::ids::{FolderId, ObjectId};

use crate::ports::{NetError, ObjectFetcher, ServerApi};

/// Objects one folder fetches at once by default.
pub const DOWNLOAD_WORKERS: usize = 4;
/// The most objects one folder fetches at once.
pub const MAX_DOWNLOAD_WORKERS: usize = 8;
/// Bytes one lane holds at most ahead of the executor: eight full chunks.
pub const FETCH_WINDOW_BYTES: u64 = 8 * hangar_drive_protocol::object::CHUNK_SIZE;
/// Bytes all lanes of one engine hold at most ahead together: two windows.
pub const FETCH_ACCOUNT_BYTES: u64 = 2 * FETCH_WINDOW_BYTES;
/// How long the round waits for a worker before it looks at its budget and at waiting commands.
pub const WAIT_SLICE: Duration = Duration::from_millis(50);

/// The bytes all lanes sharing it hold ahead ([`FETCH_ACCOUNT_BYTES`]). The engine's folders
/// share one through their settings; the default is a budget of its own.
#[derive(Debug, Clone, Default)]
pub struct FetchBudget(Arc<AtomicU64>);

impl FetchBudget {
    /// Bytes held by every lane of this budget.
    pub fn held(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn add(&self, bytes: u64) {
        self.0.fetch_add(bytes, Ordering::AcqRel);
    }

    fn sub(&self, bytes: u64) {
        // Every subtraction matches an earlier addition of the same lane; it never goes below
        // zero all the same.
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(bytes);
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(now) => current = now,
            }
        }
    }
}

/// What [`FetchLane::take`] got.
#[derive(Debug)]
pub(crate) enum Fetched {
    /// The sealed object.
    Blob(Vec<u8>),
    /// The server call failed after the client's own retries.
    Failed,
    /// The wait gave way to the budget or a waiting command; the fetch goes on meanwhile.
    Stopped,
}

/// The answer of one worker.
struct Got {
    id: ObjectId,
    result: Result<Vec<u8>, NetError>,
}

/// The worker threads of a lane; they end once the sender drops and their request is done.
struct Workers {
    tx: SyncSender<ObjectId>,
    rx: Receiver<Got>,
    /// Set when the lane drops: what a worker still finds queued is not sent.
    dropped: Arc<AtomicBool>,
}

/// Where the chunks of a folder's downloads come from (module docs).
pub(crate) struct FetchLane {
    folder: FolderId,
    width: usize,
    /// `None`: every object is fetched on the round's thread through the [`ServerApi`].
    workers: Option<Workers>,
    /// Objects asked for and not answered yet, with the bytes expected of each.
    in_flight: BTreeMap<ObjectId, u64>,
    /// Objects fetched and not taken yet, with the bytes they count for.
    ready: BTreeMap<ObjectId, (Vec<u8>, u64)>,
    /// Objects whose fetch failed, for the take that asks for them.
    failed: BTreeMap<ObjectId, NetError>,
    /// What the executor will take next, in its order, with the bytes expected of each.
    ahead: VecDeque<(ObjectId, u64)>,
    /// What this lane holds: the bytes of `in_flight` and `ready`.
    held: u64,
    budget: FetchBudget,
}

impl std::fmt::Debug for FetchLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchLane")
            .field("width", &self.width)
            .field("in_flight", &self.in_flight.len())
            .field("ready", &self.ready.len())
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

impl Drop for FetchLane {
    fn drop(&mut self) {
        if let Some(workers) = &self.workers {
            workers.dropped.store(true, Ordering::Release);
        }
        self.budget.sub(self.held);
    }
}

impl FetchLane {
    /// A lane that fetches each object on the round's thread when it is taken.
    pub fn inline(folder: FolderId) -> Self {
        Self {
            folder,
            width: 1,
            workers: None,
            in_flight: BTreeMap::new(),
            ready: BTreeMap::new(),
            failed: BTreeMap::new(),
            ahead: VecDeque::new(),
            held: 0,
            budget: FetchBudget::default(),
        }
    }

    /// A lane of `width` worker threads that fetch through `fetcher`, holding ahead within
    /// `budget` as well as its own window. The threads are not scoped to the round, so a round
    /// may end while they wait for the server; they end once the lane drops and their request
    /// is answered or timed out. Without a single thread the lane works inline.
    pub fn workers(
        width: usize,
        fetcher: Arc<dyn ObjectFetcher>,
        folder: FolderId,
        budget: FetchBudget,
    ) -> Self {
        let width = width.clamp(1, MAX_DOWNLOAD_WORKERS);
        // Bounded by the width: the lane never has more in flight.
        let (job_tx, job_rx) = sync_channel::<ObjectId>(width);
        let (res_tx, res_rx) = sync_channel::<Got>(width);
        let job_rx = Arc::new(Mutex::new(job_rx));
        let dropped = Arc::new(AtomicBool::new(false));
        let mut started = 0;
        for _ in 0..width {
            let job_rx = Arc::clone(&job_rx);
            let res_tx = res_tx.clone();
            let fetcher = Arc::clone(&fetcher);
            let dropped = Arc::clone(&dropped);
            let spawned = std::thread::Builder::new()
                .name("hangar-drive-download".into())
                .spawn(move || loop {
                    let next = match job_rx.lock() {
                        Ok(rx) => rx.recv(),
                        Err(_) => return,
                    };
                    let Ok(id) = next else {
                        return;
                    };
                    if dropped.load(Ordering::Acquire) {
                        return;
                    }
                    // A panic in a worker still answers, or the object would count as in flight
                    // for ever.
                    let result =
                        catch_unwind(AssertUnwindSafe(|| fetcher.get_object(&folder, &id)))
                            .unwrap_or_else(|_| {
                                Err(NetError::Protocol("the download worker stopped".into()))
                            });
                    if res_tx.send(Got { id, result }).is_err() {
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
        let mut lane = Self::inline(folder);
        lane.width = started;
        lane.workers = Some(Workers {
            tx: job_tx,
            rx: res_rx,
            dropped,
        });
        lane.budget = budget;
        lane
    }

    /// Whether the lane uses worker threads.
    pub fn parallel(&self) -> bool {
        self.workers.is_some()
    }

    /// Whether nothing is in flight or waiting to be taken: the lane can drop.
    pub fn idle(&self) -> bool {
        self.in_flight.is_empty() && self.ready.is_empty()
    }

    /// Bytes this lane holds: in flight or fetched and not taken.
    #[cfg(test)]
    pub fn held(&self) -> u64 {
        self.held
    }

    fn hold(&mut self, bytes: u64) {
        self.held = self.held.saturating_add(bytes);
        self.budget.add(bytes);
    }

    fn release(&mut self, bytes: u64) {
        self.held = self.held.saturating_sub(bytes);
        self.budget.sub(bytes);
    }

    /// What the executor will take next, in its order; replaces the earlier plan. Objects
    /// already in flight or fetched are not asked for again, and fetched ones the plan no
    /// longer names are dropped, so they hold no memory.
    pub fn ahead(&mut self, wanted: impl IntoIterator<Item = (ObjectId, u64)>) {
        let wanted: Vec<(ObjectId, u64)> = wanted.into_iter().collect();
        let named: std::collections::BTreeSet<ObjectId> =
            wanted.iter().map(|(id, _)| *id).collect();
        let stale: Vec<ObjectId> = self
            .ready
            .keys()
            .filter(|id| !named.contains(id))
            .copied()
            .collect();
        for id in stale {
            if let Some((_, bytes)) = self.ready.remove(&id) {
                self.release(bytes);
            }
        }
        // A failure belongs to the run that asked: a new plan asks again instead of failing a
        // file at once on an answer of an earlier run.
        self.failed.clear();
        self.ahead = wanted
            .into_iter()
            .filter(|(id, _)| !self.in_flight.contains_key(id) && !self.ready.contains_key(id))
            .collect();
        self.pump();
    }

    /// Hands `id` to a worker; false when every worker is gone.
    fn dispatch(&mut self, id: ObjectId, bytes: u64) -> bool {
        let Some(workers) = &self.workers else {
            return false;
        };
        if workers.tx.send(id).is_err() {
            return false;
        }
        self.in_flight.insert(id, bytes);
        self.hold(bytes);
        true
    }

    /// Books one answer. A busy server narrows the lane and the object is asked for again with
    /// the bytes it was expected to take.
    fn absorb(&mut self, got: Got) {
        let bytes = self.in_flight.remove(&got.id).unwrap_or(0);
        match got.result {
            Ok(blob) => {
                self.ready.insert(got.id, (blob, bytes));
            }
            Err(e) if e.code() == Some(ErrorCode::RateLimited) && self.width > 1 => {
                self.release(bytes);
                self.width -= 1;
                self.ahead.push_front((got.id, bytes));
            }
            Err(e) => {
                self.release(bytes);
                self.failed.insert(got.id, e);
            }
        }
    }

    /// Books what came in and fetches ahead while the lane, and all lanes of its budget, have
    /// room. The window holds for every object fetched ahead, also when nothing is in flight.
    fn pump(&mut self) {
        let mut answers = Vec::new();
        if let Some(workers) = &self.workers {
            while let Ok(got) = workers.rx.try_recv() {
                answers.push(got);
            }
        }
        for got in answers {
            self.absorb(got);
        }
        while self.in_flight.len() < self.width {
            let Some(&(id, bytes)) = self.ahead.front() else {
                break;
            };
            if self.held.saturating_add(bytes) > FETCH_WINDOW_BYTES
                || self.budget.held().saturating_add(bytes) > FETCH_ACCOUNT_BYTES
            {
                break;
            }
            self.ahead.pop_front();
            if self.in_flight.contains_key(&id) || self.ready.contains_key(&id) {
                continue;
            }
            if !self.dispatch(id, bytes) {
                break;
            }
        }
    }

    /// The sealed object `id` (about `bytes` long). It waits for a worker in slices of
    /// [`WAIT_SLICE`] and gives up the wait once `stop` holds; an inline lane fetches through
    /// `server` now.
    pub fn take(
        &mut self,
        id: &ObjectId,
        bytes: u64,
        server: &mut dyn ServerApi,
        stop: &dyn Fn() -> bool,
    ) -> Fetched {
        if self.workers.is_none() {
            return match server.get_object(&self.folder, id) {
                Ok(blob) => Fetched::Blob(blob),
                Err(_) => Fetched::Failed,
            };
        }
        loop {
            self.pump();
            if let Some((blob, counted)) = self.ready.remove(id) {
                self.release(counted);
                return Fetched::Blob(blob);
            }
            if let Some(error) = self.failed.remove(id) {
                if error.code() != Some(ErrorCode::Unauthorized) {
                    return Fetched::Failed;
                }
                // The session ran out under a worker, which never signs in: this connection
                // signs in again, which renews the token for the workers as well.
                return match server.get_object(&self.folder, id) {
                    Ok(blob) => Fetched::Blob(blob),
                    Err(_) => Fetched::Failed,
                };
            }
            if !self.in_flight.contains_key(id) {
                self.ahead.retain(|(a, _)| a != id);
                // The object needed now goes out even beyond the window, so the executor never
                // waits on its own chunk.
                if self.in_flight.len() < self.width {
                    if !self.dispatch(*id, bytes) {
                        return Fetched::Failed;
                    }
                    continue;
                }
            }
            let Some(workers) = &self.workers else {
                return Fetched::Failed;
            };
            match workers.rx.recv_timeout(WAIT_SLICE) {
                Ok(got) => self.absorb(got),
                Err(RecvTimeoutError::Timeout) => {
                    if stop() {
                        return Fetched::Stopped;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => return Fetched::Failed,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemServer;

    const CHUNK: u64 = hangar_drive_protocol::object::CHUNK_SIZE;

    /// Answers every object with as many bytes as its first ID byte says in chunks.
    struct Sized;

    impl ObjectFetcher for Sized {
        fn get_object(&self, _: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError> {
            let large = id.as_bytes()[0] == 0xaa;
            Ok(vec![0u8; if large { CHUNK as usize } else { 100 }])
        }
    }

    fn id(kind: u8, n: u8) -> ObjectId {
        let mut bytes = [0u8; 32];
        bytes[0] = kind;
        bytes[1] = n;
        ObjectId::from_bytes(bytes)
    }

    /// Security review M2: a large file first in the plan that the executor skips (no room on
    /// the disk) must not make every take of a small file fetch one more large chunk ahead.
    #[test]
    fn a_skipped_large_file_does_not_grow_what_the_lane_holds() {
        let folder = FolderId::from_bytes([1; 16]);
        let budget = FetchBudget::default();
        let mut lane = FetchLane::workers(4, Arc::new(Sized), folder, budget.clone());
        let large: Vec<(ObjectId, u64)> = (0..40).map(|n| (id(0xaa, n), CHUNK)).collect();
        let small: Vec<(ObjectId, u64)> = (0..60).map(|n| (id(0x0b, n), 100)).collect();
        lane.ahead(large.iter().chain(&small).copied());
        let shared = MemServer::new_shared();
        let mut server = MemServer::connect(
            &shared,
            hangar_drive_protocol::ids::DeviceId::from_bytes([2; 16]),
        );
        let mut most = 0;
        for (small_id, bytes) in &small {
            assert!(matches!(
                lane.take(small_id, *bytes, &mut server, &|| false),
                Fetched::Blob(_)
            ));
            most = most.max(lane.held());
        }
        assert!(
            most <= FETCH_WINDOW_BYTES + CHUNK,
            "the lane held {most} bytes"
        );
        // A new plan without the large file drops what was fetched for it.
        lane.ahead(Vec::new());
        assert!(lane.held() <= 4 * CHUNK, "only what is in flight stays");
        drop(lane);
        assert_eq!(budget.held(), 0, "a dropped lane gives its bytes back");
    }

    /// Fails the first fetch of every object at once, then answers after 50 ms, so the take
    /// below finds no answer of the second fetch yet.
    #[derive(Default)]
    struct FailsOnce(Mutex<std::collections::BTreeSet<ObjectId>>);

    impl ObjectFetcher for FailsOnce {
        fn get_object(&self, _: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError> {
            if self.0.lock().unwrap().insert(*id) {
                return Err(NetError::Unreachable);
            }
            std::thread::sleep(Duration::from_millis(50));
            Ok(vec![1u8; 100])
        }
    }

    /// A fetch that failed in an earlier run is asked for again by a new plan instead of
    /// failing the file at once.
    #[test]
    fn a_new_plan_asks_again_for_what_failed_before() {
        let folder = FolderId::from_bytes([3; 16]);
        let mut lane = FetchLane::workers(
            2,
            Arc::new(FailsOnce::default()),
            folder,
            FetchBudget::default(),
        );
        let shared = MemServer::new_shared();
        let mut server = MemServer::connect(
            &shared,
            hangar_drive_protocol::ids::DeviceId::from_bytes([2; 16]),
        );
        let wanted = id(0x0c, 1);
        lane.ahead([(wanted, 100)]);
        while lane.failed.is_empty() {
            lane.pump();
            std::thread::sleep(Duration::from_millis(5));
        }
        lane.ahead([(wanted, 100)]);
        assert!(matches!(
            lane.take(&wanted, 100, &mut server, &|| false),
            Fetched::Blob(_)
        ));
    }

    /// Security review N2: lanes of one engine share one budget, so many folders that download
    /// at once hold no more than it together.
    #[test]
    fn lanes_of_one_budget_hold_no_more_than_it_together() {
        let budget = FetchBudget::default();
        let lanes: Vec<FetchLane> = (0..5u8)
            .map(|f| {
                let mut lane = FetchLane::workers(
                    4,
                    Arc::new(Sized),
                    FolderId::from_bytes([f; 16]),
                    budget.clone(),
                );
                lane.ahead((0..40).map(|n| (id(0xaa, n), CHUNK)));
                lane
            })
            .collect();
        let total: u64 = lanes.iter().map(FetchLane::held).sum();
        assert!(total <= FETCH_ACCOUNT_BYTES, "the lanes held {total} bytes");
        assert_eq!(budget.held(), total);
    }
}
