//! The folder delta page by page (ADR 0001, amendments "delta pages" and "delta pages in the
//! engine"): the chain check of the crypto crate (`DeltaVerifier`), the check of every commit's
//! reference delta against the trees (the counted set of `DeltaWalk`) and the timeline records,
//! one page at a time. No list of the raw commits is kept: per checked head the verifier holds
//! its chain entry, this module its timeline record (which the folder keeps afterwards anyway)
//! and its root; of the commits themselves only the last page's sequences and server times.
//!
//! A pull of the round stores its state after every page in the local index: the verifier, the
//! cursor, the server times of the last page, the flags of the tree check and the timeline
//! records page by page. After a restart or a lost connection it goes on from there, as long as
//! the frontier and the device log are the ones it began with; otherwise it begins again.
//! Nothing of it is taken in before the verifier's `finish`: until then the view, the remote
//! tree and the timeline stay as they were, and any refusal drops the stored state, so a delta
//! refused once is checked again from its start.

use std::collections::BTreeMap;

use hangar_drive_crypto::commit::{
    ChainError, DeltaPart, DeltaVerdict, DeltaVerifier, FolderView, RemovedHead,
    RemovedSignerRefusal, SignedCommit,
};
use hangar_drive_crypto::epoch::BarrierPermit;
use hangar_drive_protocol::api::DeltaCommit;
use hangar_drive_protocol::ids::{Blob, CommitId, FolderId, ObjectId};
use serde::{Deserialize, Serialize};

use super::{
    Ctx, DeltaWalk, DropCount, FolderSync, Seen, TimelineRec, Verdict, UNREADABLE_AFTER_MS,
};
use crate::codec::FolderCrypto;
use crate::error::SyncError;
use crate::paging::{check_page, Order, Page, DELTA_LIMITS};
use crate::ports::{NetError, Store};

/// Most heads and side commits one pull reads (`FolderSettings::max_pull_commits`; smaller in
/// tests). The former bound of 200,000 for the delta as one list locked new devices, a
/// re-anchor and long offline devices out for good, and a hostile device wrote that many in
/// about an hour. Checked page by page, a commit costs about 200 bytes in memory (its chain
/// entry, timeline record and root), so four million are below a gigabyte. The server takes at
/// most 30 commits per minute and account (amendment "security review of the sync server",
/// M2), so a device that commits without a pause needs about 92 days to reach it, which the
/// person and the operator see long before. The pull ends anyway: every page must move the
/// cursor, and only commits the devices really signed pass the check.
pub const MAX_PULL_COMMITS: usize = 4_000_000;

/// Which check a pull runs.
#[derive(Clone, Copy)]
pub(crate) enum PullMode<'a> {
    /// Every rule, with the tree check; `persist` stores the state after every page (the
    /// pull of the round).
    Check { persist: bool },
    /// Every rule but the removed signer rule, for the holder of the permit; no tree check,
    /// as the barrier takes the verified head's tree.
    BeforeBarrier(&'a BarrierPermit),
}

/// An accepted delta, ready to be taken in.
#[derive(Debug, Clone)]
pub(crate) struct Pulled {
    /// The view with every new head.
    pub view: FolderView,
    /// New heads.
    pub heads: usize,
    /// The last new head.
    pub last_head: Option<SignedCommit>,
    /// The timeline records of every head and side commit, with the drop counts of the tree
    /// check.
    pub timeline: Vec<TimelineRec>,
    /// Heads of removed devices (in the check before a barrier).
    pub removed_heads: Vec<RemovedHead>,
    /// A tree on the way is beyond the limits of a folder.
    pub tree_limit: bool,
    /// A commit's delta could not be checked or was let through: repair at once.
    pub unchecked: bool,
}

/// The verdict of a pull.
#[derive(Debug, Clone)]
pub(crate) enum PullVerdict {
    /// Passed every rule.
    Accepted(Box<Pulled>),
    /// Refused by the removed signer rule alone.
    RemovedSigner(RemovedSignerRefusal),
}

/// The stored state of a pull between pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pending {
    /// The frontier the pull began after.
    after: u64,
    frontier: Option<CommitId>,
    /// The sequence of the last item read.
    cursor: u64,
    /// Pages read; the timeline records of page `n` are stored under [`page_key`].
    pages: u32,
    /// Items read.
    items: u64,
    /// The verifier ([`DeltaVerifier::encode`]).
    verifier: Blob,
    /// Sequence and server time of the last page's commits, for a head the verifier still
    /// holds back.
    carry: Vec<(CommitId, u64, Option<u64>)>,
    last_head: Option<Blob>,
    heads: u64,
    tree_limit: bool,
    unchecked: bool,
}

/// A page named a log head beyond this round's log or a generation it does not know yet.
fn needs_newer_log(e: &SyncError) -> bool {
    use hangar_drive_crypto::commit::CommitError;
    matches!(
        e,
        SyncError::Commit(CommitError::AheadOfLog { .. })
            | SyncError::Chain(ChainError::Commit(CommitError::AheadOfLog { .. }))
            | SyncError::Chain(ChainError::UnknownGeneration(_))
    )
}

fn state_key(folder: &FolderId) -> String {
    format!("pull/{}", folder.to_hex())
}

fn page_key(folder: &FolderId, page: u32) -> String {
    format!("pull/{}/{page}", folder.to_hex())
}

fn corrupt(e: impl std::fmt::Display) -> SyncError {
    SyncError::Corrupt(e.to_string())
}

/// Sequence and server time of each commit of a page.
type Times = BTreeMap<CommitId, (u64, Option<u64>)>;

/// Sequence and server time of a commit of the current or the last page.
type TimeOf<'a> = dyn Fn(&CommitId) -> Option<(u64, Option<u64>)> + 'a;

fn times_of(page: &[DeltaCommit]) -> Times {
    page.iter()
        .filter_map(|d| {
            SignedCommit::decode(d.commit.as_bytes())
                .ok()
                .map(|c| (c.id, (d.sequence, d.server_ms)))
        })
        .collect()
}

/// Checks every head and side commit of an accepted delta against the trees, one part of the
/// pages at a time (ADR 0001, amendment "reference deltas bound to the tree"): the delta digest
/// it signed must be the digest of `reachable(tree)` against `reachable(first parent's tree)`
/// (a side commit's: its base), or of `reachable(tree)` alone for a full delta. The server
/// applied exactly that delta to its live set, so a commit whose delta does not fit its tree
/// would let the collection delete live data or keep garbage live: it is refused like a commit
/// with a bad signature, and the folder stops until the person removes the device that wrote
/// it.
///
/// - A mismatching commit of a device the verified log has removed since is let through: such
///   commits come in only behind a barrier that the removing device or the person accepted.
/// - A tree the server no longer holds (an object is gone) is accepted as unreadable only for a
///   commit whose call is older than [`UNREADABLE_AFTER_MS`] by the server's unsigned time, or
///   whose time the server already dropped because it expired: only then may the collection
///   have taken its trees. For a younger commit of a current device it is a mismatch, so a
///   device cannot hide a forged delta behind a tree it never uploaded (HIGH 1 of the follow-up
///   review). The server decides retention anyway, so trusting its time here gives it nothing
///   it lacks.
/// - A tree beyond the limits stops the folder as `StopReason::TreeLimit` does
///   ([`Pulled::tree_limit`]).
///
/// Whatever is let through or cannot be checked sets [`Pulled::unchecked`], and the round then
/// writes a repair commit at once (`FolderSync::repair`), which resets the server's live set to
/// the tree whatever happened before.
struct TreeChecker {
    walk: DeltaWalk,
    roots: BTreeMap<CommitId, ObjectId>,
    limit: bool,
    unchecked: bool,
}

impl TreeChecker {
    /// Checks the heads, then the side commits of one part; returns the drop counts.
    fn check(
        &mut self,
        part: &DeltaPart,
        times: &TimeOf<'_>,
        reader: &FolderCrypto,
        cx: &mut Ctx<'_>,
    ) -> Result<BTreeMap<CommitId, DropCount>, SyncError> {
        let mut drops = BTreeMap::new();
        let now = u64::try_from(cx.clock.now_ms()).unwrap_or(0);
        let old_enough = |id: &CommitId| match times(id).and_then(|(_, ms)| ms) {
            None => true,
            Some(at) => now.saturating_sub(at) > UNREADABLE_AFTER_MS,
        };
        for head in &part.heads {
            self.roots.insert(head.id, head.commit.root);
        }
        for c in part.heads.iter().chain(part.sides.iter()) {
            let before = match c.commit.parents.first() {
                None => self.walk.goto(None, reader, cx)?,
                Some(parent) => match self.roots.get(parent).copied() {
                    None => Seen::Gone,
                    Some(root) => self.walk.goto(Some(root), reader, cx)?,
                },
            };
            let after = self.walk.goto(Some(c.commit.root), reader, cx)?;
            let verdict = match (&after, &before) {
                (Seen::Limit, _) | (_, Seen::Limit) => {
                    self.limit = true;
                    Verdict::Unchecked
                }
                (Seen::Set { .. }, _) if c.commit.delta.full => {
                    Verdict::of(self.walk.full_digest() == c.commit.delta)
                }
                // The move from the parent's tree to this one is the diff, since the set was
                // at the parent's tree right before.
                (
                    Seen::Set {
                        moved: Some(moved), ..
                    },
                    Seen::Set { .. },
                ) => {
                    let fits = moved.digest() == c.commit.delta;
                    if fits && !c.commit.side {
                        drops.insert(c.id, after.drops(false));
                    }
                    Verdict::of(fits)
                }
                // A tree the server no longer holds: only an old enough commit may have lost it.
                _ if old_enough(&c.id) => Verdict::Unchecked,
                _ => Verdict::Mismatch,
            };
            if c.commit.delta.full && !c.commit.side {
                if let (Seen::Set { .. }, Seen::Set { moved: Some(_), .. }) = (&before, &after) {
                    if verdict == Verdict::Fits {
                        drops.insert(c.id, after.drops(true));
                    }
                }
            }
            match verdict {
                Verdict::Fits => {}
                Verdict::Unchecked => self.unchecked = true,
                Verdict::Mismatch => {
                    let current = cx
                        .account
                        .state()
                        .device(&c.commit.device)
                        .is_some_and(|d| d.is_current());
                    if current {
                        return Err(SyncError::Chain(ChainError::Commit(
                            hangar_drive_crypto::commit::CommitError::DeltaMismatch,
                        )));
                    }
                    self.unchecked = true;
                }
            }
        }
        Ok(drops)
    }
}

/// The timeline records of one part: side commits, then heads, as for a whole delta before.
fn records(
    part: &DeltaPart,
    times: &TimeOf<'_>,
    drops: &BTreeMap<CommitId, DropCount>,
    now: i64,
) -> Vec<TimelineRec> {
    part.sides
        .iter()
        .chain(part.heads.iter())
        .map(|c| {
            let drop = drops.get(&c.id);
            TimelineRec {
                commit: c.id,
                sequence: times(&c.id).map_or(0, |(s, _)| s),
                device: c.commit.device,
                seen_at_ms: now,
                reanchor: c.commit.reanchor,
                side: c.commit.side,
                root: c.commit.root,
                dropped_files: drop.map(|d| d.dropped),
                files_before: drop.map(|d| d.before),
            }
        })
        .collect()
}

impl FolderSync {
    /// Reads and checks the delta after the frontier page by page (module docs). The stored
    /// state of [`PullMode::Check`] with `persist` stays only when the pull ended on a lost
    /// connection; any other end, a verdict or a refusal, drops it.
    pub(crate) fn pull_delta(
        &mut self,
        cx: &mut Ctx<'_>,
        mode: PullMode<'_>,
    ) -> Result<PullVerdict, SyncError> {
        let persist = matches!(mode, PullMode::Check { persist: true });
        let result = self.pull_pages(cx, mode, persist);
        // The stored state stays for a lost connection, and for a page that needs a newer log
        // than this round's: the round reads the log and goes on from the state stored before
        // that page.
        let keep = matches!(&result, Err(e) if e.is_offline() || needs_newer_log(e));
        if persist && !keep {
            self.drop_pending(cx.store)?;
        }
        result
    }

    /// Drops a stored pull.
    pub(crate) fn drop_pending(&self, store: &mut dyn Store) -> Result<(), SyncError> {
        // Pages written after the last stored state, or before the first, are there as well.
        let mut page = 0u32;
        while store
            .account_value(&page_key(&self.folder, page))?
            .is_some()
        {
            store.delete_account_value(&page_key(&self.folder, page))?;
            page = page.saturating_add(1);
        }
        store.delete_account_value(&state_key(&self.folder))?;
        Ok(())
    }

    /// A stored pull that goes on from this frontier and this device log, with its records.
    fn load_pending(
        &self,
        cx: &mut Ctx<'_>,
    ) -> Result<Option<(Pending, DeltaVerifier, Vec<TimelineRec>)>, SyncError> {
        let Some(bytes) = cx.store.account_value(&state_key(&self.folder))? else {
            return Ok(None);
        };
        let Ok(pending) = serde_json::from_slice::<Pending>(&bytes) else {
            return Ok(None);
        };
        let after = self.view.frontier().map_or(0, |f| f.sequence);
        let frontier = self.view.frontier().map(|f| f.commit);
        if pending.after != after || pending.frontier != frontier {
            return Ok(None);
        }
        // Another device log than the one the check began with: begin again.
        let Ok(verifier) = DeltaVerifier::decode(cx.account.state(), pending.verifier.as_bytes())
        else {
            return Ok(None);
        };
        let mut timeline = Vec::new();
        for page in 0..pending.pages {
            let Some(bytes) = cx.store.account_value(&page_key(&self.folder, page))? else {
                return Ok(None);
            };
            let recs: Vec<TimelineRec> = serde_json::from_slice(&bytes).map_err(corrupt)?;
            timeline.extend(recs);
        }
        Ok(Some((pending, verifier, timeline)))
    }

    fn pull_pages(
        &mut self,
        cx: &mut Ctx<'_>,
        mode: PullMode<'_>,
        persist: bool,
    ) -> Result<PullVerdict, SyncError> {
        let folder = self.folder;
        let newest = self.newest(cx)?;
        let after = self.view.frontier().map_or(0, |f| f.sequence);
        let resumed = if persist {
            self.load_pending(cx)?
        } else {
            None
        };
        // A stored check may be pinned to an older log than this round's (amendment "recovery in
        // one piece, adds per day, delta check on a growing log", M5); it may stop early.
        let mut pinned_older = resumed.is_some();
        let (mut pending, mut verifier, mut timeline) = match resumed {
            Some(found) => found,
            None => {
                if persist {
                    self.drop_pending(cx.store)?;
                }
                let verifier = match mode {
                    PullMode::Check { .. } => self.view.begin_check(cx.account.state(), newest)?,
                    PullMode::BeforeBarrier(permit) => {
                        self.view
                            .begin_check_before_barrier(cx.account.state(), newest, permit)?
                    }
                };
                let pending = Pending {
                    after,
                    frontier: self.view.frontier().map(|f| f.commit),
                    cursor: after,
                    pages: 0,
                    items: 0,
                    verifier: Blob(Vec::new()),
                    carry: Vec::new(),
                    last_head: None,
                    heads: 0,
                    tree_limit: false,
                    unchecked: false,
                };
                (pending, verifier, Vec::new())
            }
        };
        let check_trees = matches!(mode, PullMode::Check { .. });
        let reader = cx.account.folder_reader(&folder)?;
        let mut roots: BTreeMap<CommitId, ObjectId> = self
            .meta
            .timeline
            .iter()
            .chain(timeline.iter())
            .map(|t| (t.commit, t.root))
            .collect();
        if let (Some(frontier), Some(root)) = (self.view.frontier(), self.meta.remote_root) {
            roots.insert(frontier.commit, root);
        }
        let mut checker = TreeChecker {
            walk: DeltaWalk::default(),
            roots,
            limit: pending.tree_limit,
            unchecked: pending.unchecked,
        };
        let mut carry: Times = pending
            .carry
            .iter()
            .map(|(id, s, ms)| (*id, (*s, *ms)))
            .collect();
        let mut last_head = match &pending.last_head {
            Some(wire) => Some(SignedCommit::decode(wire.as_bytes()).map_err(corrupt)?),
            None => None,
        };
        let mut removed_heads = Vec::new();
        let now = cx.clock.now_ms();
        let max_items = cx.settings.max_pull_commits.max(1) as u64;
        // Pages of the stored state; it is written again only after an eighth more pages, so
        // storing stays linear in the delta (each write holds every chain entry so far).
        let mut saved_pages = pending.pages;
        let mut persist = persist;
        let view = loop {
            let page: Page<DeltaCommit> = cx.server.commits(&folder, pending.cursor)?.into();
            let last = check_page(
                pending.cursor,
                &page,
                DELTA_LIMITS.per_page,
                Order::CallPairs,
                |c: &DeltaCommit| c.sequence,
            )?;
            self.view.check_server_sequence(page.sequence)?;
            pending.items = pending.items.saturating_add(page.items.len() as u64);
            if pending.items > max_items {
                return Err(NetError::Protocol(
                    "paging: the delta is longer than this device reads".into(),
                )
                .into());
            }
            let here = times_of(&page.items);
            let part = verifier.push_page(cx.account.state(), &page.items)?;
            let times = |id: &CommitId| here.get(id).or_else(|| carry.get(id)).copied();
            let recs =
                self.take_part(&part, &times, &mut checker, check_trees, &reader, cx, now)?;
            pending.heads = pending.heads.saturating_add(part.heads.len() as u64);
            if let Some(head) = part.heads.last() {
                last_head = Some(head.clone());
            }
            removed_heads.extend(part.removed_heads.iter().copied());
            carry = here;
            pending.cursor = last;
            pending.pages = pending.pages.saturating_add(1);
            // A check pinned to an older log stops at the first call that needs the newer one;
            // that call starts the next delta (below).
            let cut = verifier.cut().is_some();
            if persist {
                let bytes = serde_json::to_vec(&recs).map_err(corrupt)?;
                cx.store
                    .put_account_value(&page_key(&folder, pending.pages - 1), &bytes)?;
                let due = pending.pages - saved_pages >= (saved_pages / 8).max(1);
                if due && !cut && page.more {
                    pending.verifier = Blob(
                        verifier
                            .encode()
                            .ok_or(SyncError::Invalid("the delta check does not encode"))?,
                    );
                    pending.carry = carry.iter().map(|(id, (s, ms))| (*id, *s, *ms)).collect();
                    pending.last_head = last_head.as_ref().map(|h| Blob(h.wire.clone()));
                    pending.tree_limit = checker.limit;
                    pending.unchecked = checker.unchecked;
                    let bytes = serde_json::to_vec(&pending).map_err(corrupt)?;
                    cx.store.put_account_value(&state_key(&folder), &bytes)?;
                    saved_pages = pending.pages;
                }
            }
            timeline.extend(recs);
            if page.more && !cut {
                continue;
            }
            let (view, rest) = match verifier.finish(cx.account.state())? {
                DeltaVerdict::RemovedSigner(refusal) => {
                    return Ok(PullVerdict::RemovedSigner(refusal))
                }
                DeltaVerdict::Accepted { view, rest } => (view, rest),
            };
            let times = |id: &CommitId| carry.get(id).copied();
            let recs =
                self.take_part(&rest, &times, &mut checker, check_trees, &reader, cx, now)?;
            timeline.extend(recs);
            pending.heads = pending.heads.saturating_add(rest.heads.len() as u64);
            if let Some(head) = rest.heads.last() {
                last_head = Some(head.clone());
            }
            removed_heads.extend(rest.removed_heads.iter().copied());
            if !(cut && pinned_older) {
                break view;
            }
            // The next delta from the accepted view, checked against this round's log: the
            // cursor goes back to the accepted frontier, the call that was cut is read again.
            pinned_older = false;
            persist = false;
            pending.cursor = view.frontier().map_or(after, |f| f.sequence);
            verifier = match mode {
                PullMode::Check { .. } => view.begin_check(cx.account.state(), newest)?,
                PullMode::BeforeBarrier(permit) => {
                    view.begin_check_before_barrier(cx.account.state(), newest, permit)?
                }
            };
            carry = Times::new();
        };
        Ok(PullVerdict::Accepted(Box::new(Pulled {
            view,
            heads: usize::try_from(pending.heads).unwrap_or(usize::MAX),
            last_head,
            timeline,
            removed_heads,
            tree_limit: checker.limit,
            unchecked: checker.unchecked,
        })))
    }

    /// The tree check (when asked) and the timeline records of one part.
    #[allow(clippy::too_many_arguments)]
    fn take_part(
        &self,
        part: &DeltaPart,
        times: &TimeOf<'_>,
        checker: &mut TreeChecker,
        check_trees: bool,
        reader: &FolderCrypto,
        cx: &mut Ctx<'_>,
        now: i64,
    ) -> Result<Vec<TimelineRec>, SyncError> {
        let drops = if check_trees {
            checker.check(part, times, reader, cx)?
        } else {
            BTreeMap::new()
        };
        Ok(records(part, times, &drops, now))
    }
}
