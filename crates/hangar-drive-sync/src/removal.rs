//! Removing a device as a persistent, resumable job (ADR 0001, section 4, "Removing a device";
//! security review N1).
//!
//! The removal has three steps, and each one survives a crash or a lost connection:
//!
//! 1. **Append:** the removal and its rotation in one append call. The job is stored before
//!    the call; a call that reached the server but lost its answer is detected at the resume,
//!    because the verified log then shows the removal.
//! 2. **Re-seal:** every folder key ring gets a new generation, and the folder list and device
//!    names are sealed under the new epoch (`reseal_after_removal`).
//! 3. **Barriers:** every folder gets a barrier commit on its head, naming the new log head and
//!    generation, after the delta was verified with the removal's [`BarrierPermit`]
//!    (`FolderView::verify_delta_before_barrier`, N2). The heads of removed devices it let in
//!    are returned for "Undo a device".
//!
//! **Takeover (N1, H1):** if the removing device goes away after step 1, any other current
//! device completes steps 2 and 3, but only where they are really missing:
//!
//! - **Re-seal:** a removal whose re-seal is missing in the verified log
//!   (`Account::reseal_due`) is re-sealed by [`complete_pending`].
//! - **Barriers:** a device never writes a barrier because its log saw a removal. Only a delta
//!   that `FolderView::check_delta` refuses by the removed signer rule yields the refusal from
//!   which `BarrierPermit::takeover` makes a permit for that one folder. The round then checks
//!   the delta with it and, when it would let heads of a removed device in, writes no barrier:
//!   the folder stops with `StopReason::RemovedHeads` and the app asks the person, who can
//!   take the heads in ([`accept_removed_heads`], then "Undo a device") or leave the folder
//!   stopped. A server that hides the removing device's barrier from an offline device
//!   therefore gets nothing in without the person (residual risk in ADR 0001, section 4).
//!
//! Two devices doing this at once are safe: records are compare-and-swap per version and a
//! barrier is a normal commit on the head, so the loser fetches the winner's result.

use std::collections::BTreeSet;

use hangar_drive_crypto::commit::{ChainError, DeltaCheck, RemovedHead};
use hangar_drive_crypto::epoch::BarrierPermit;
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::ids::{CommitId, DeviceId};
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::error::SyncError;
use crate::folder::{Ctx, FolderSettings, FolderState, FolderSync, StopReason};
use crate::ports::{Clock, FileSystem, Keychain, ServerApi, Store};

const JOB_KEY: &str = "removal-job";

/// Where a removal job stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemovalPhase {
    /// The append call may or may not have reached the server.
    Appending,
    /// The removal is in the log; the records are not re-sealed yet.
    Appended,
    /// Re-sealed; barriers are missing in some folders.
    Resealed,
    /// Done.
    Done,
}

/// The stored job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovalJob {
    /// The devices to remove.
    pub targets: Vec<DeviceId>,
    /// The step reached.
    pub phase: RemovalPhase,
}

/// What a removal (or its takeover) did.
#[derive(Debug, Clone, Default)]
pub struct RemovalOutcome {
    /// Records this device re-sealed (false: another device had done it).
    pub resealed: bool,
    /// Folders that got a barrier from this device.
    pub barriers: usize,
    /// Heads of removed devices let in before a barrier, for "Undo a device".
    pub removed_heads: Vec<RemovedHead>,
}

/// The ports the job needs besides the folders.
pub struct JobCtx<'a> {
    /// The account.
    pub account: &'a mut Account,
    /// The server.
    pub server: &'a mut dyn ServerApi,
    /// The keychain.
    pub keychain: &'a mut dyn Keychain,
    /// The index.
    pub store: &'a mut dyn Store,
    /// The clock.
    pub clock: &'a dyn Clock,
    /// Randomness.
    pub entropy: &'a mut dyn Entropy,
    /// Folder settings.
    pub settings: &'a FolderSettings,
}

/// The stored job, if one is open.
pub fn load_job(store: &dyn Store) -> Result<Option<RemovalJob>, SyncError> {
    match store.account_value(JOB_KEY)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| SyncError::Corrupt(e.to_string())),
    }
}

fn save_job(store: &mut dyn Store, job: &RemovalJob) -> Result<(), SyncError> {
    let bytes = serde_json::to_vec(job).map_err(|e| SyncError::Corrupt(e.to_string()))?;
    store.put_account_value(JOB_KEY, &bytes)?;
    Ok(())
}

/// Removes `targets` from the account and runs the job to the end (module docs). Each folder
/// is given with its sync root.
pub fn remove_devices(
    jx: &mut JobCtx<'_>,
    folders: &mut [(&mut FolderSync, &dyn FileSystem)],
    targets: &[DeviceId],
) -> Result<RemovalOutcome, SyncError> {
    if targets.is_empty() || targets.contains(jx.account.device()) {
        return Err(SyncError::Invalid(
            "a device cannot remove itself or nothing",
        ));
    }
    let mut job = match load_job(jx.store)? {
        Some(job) if job.phase != RemovalPhase::Done => job,
        _ => RemovalJob {
            targets: targets.to_vec(),
            phase: RemovalPhase::Appending,
        },
    };
    save_job(jx.store, &job)?;
    resume(jx, folders, &mut job)
}

/// Resumes an open job of this device, or completes the re-seal of another device whose
/// removal is in the log without it (N1). Returns `None` when nothing is due. Barriers are not
/// written here for other devices' removals: a folder whose delta needs one stops in its round
/// and waits for the person (module docs, H1).
pub fn complete_pending(
    jx: &mut JobCtx<'_>,
    folders: &mut [(&mut FolderSync, &dyn FileSystem)],
) -> Result<Option<RemovalOutcome>, SyncError> {
    if let Some(mut job) = load_job(jx.store)? {
        if job.phase != RemovalPhase::Done {
            return resume(jx, folders, &mut job).map(Some);
        }
    }
    if jx.account.state().last_removal_index() == 0 || !jx.account.reseal_due() {
        return Ok(None);
    }
    jx.account.refresh(jx.server, jx.keychain, jx.store)?;
    let mut outcome = RemovalOutcome::default();
    if jx.account.reseal_due() {
        outcome.resealed = jx
            .account
            .reseal_after_removal(jx.server, jx.keychain, jx.entropy)?;
        jx.account.save(jx.store)?;
    }
    Ok(Some(outcome))
}

/// The person's answer to [`StopReason::RemovedHeads`]: take the heads of the removed device
/// in and write the barrier after them, so the folder syncs again and "Undo a device" can reach
/// them (security review H1, N2). The permit comes only from a fresh refusal of the folder's
/// delta. If the server now presents removed heads the person was not shown, nothing is
/// written and the folder asks again with the new list. Returns the heads the barrier covers.
pub fn accept_removed_heads(
    jx: &mut JobCtx<'_>,
    folder: &mut FolderSync,
    fs: &dyn FileSystem,
) -> Result<RemovalOutcome, SyncError> {
    if folder.state() != FolderState::Stopped(StopReason::RemovedHeads) {
        return Err(SyncError::Invalid(
            "the folder does not wait for this decision",
        ));
    }
    let confirmed: BTreeSet<CommitId> = folder.removed_heads().iter().map(|h| h.commit).collect();
    let mut outcome = RemovalOutcome::default();
    let written = write_barrier_if_due(jx, folder, fs, Mode::Confirmed(&confirmed), &mut outcome)?;
    if written {
        outcome.barriers = 1;
    }
    Ok(outcome)
}

fn resume(
    jx: &mut JobCtx<'_>,
    folders: &mut [(&mut FolderSync, &dyn FileSystem)],
    job: &mut RemovalJob,
) -> Result<RemovalOutcome, SyncError> {
    let mut outcome = RemovalOutcome::default();
    if job.phase == RemovalPhase::Appending {
        // The append may have reached the server before a crash: the log tells.
        jx.account.refresh(jx.server, jx.keychain, jx.store)?;
        let done = job.targets.iter().all(|t| {
            jx.account
                .state()
                .device(t)
                .is_some_and(|d| !d.is_current())
        });
        if !done {
            let now = u64::try_from(jx.clock.now_ms()).unwrap_or(0);
            jx.account
                .rotate(jx.server, jx.keychain, &job.targets, now, jx.entropy)?;
            jx.account.save(jx.store)?;
        }
        job.phase = RemovalPhase::Appended;
        save_job(jx.store, job)?;
    }
    if job.phase == RemovalPhase::Appended {
        jx.account.refresh(jx.server, jx.keychain, jx.store)?;
        if jx.account.reseal_due() {
            outcome.resealed =
                jx.account
                    .reseal_after_removal(jx.server, jx.keychain, jx.entropy)?;
            jx.account.save(jx.store)?;
        }
        job.phase = RemovalPhase::Resealed;
        save_job(jx.store, job)?;
    }
    if job.phase == RemovalPhase::Resealed {
        let permit = BarrierPermit::of_own_removal(jx.account.state(), jx.account.device())
            .ok_or(SyncError::Invalid("no removal to write barriers for"))?;
        for (folder, fs) in folders.iter_mut() {
            if write_barrier_if_due(jx, folder, *fs, Mode::Removing(&permit), &mut outcome)? {
                outcome.barriers += 1;
            }
        }
        job.phase = RemovalPhase::Done;
        save_job(jx.store, job)?;
    }
    Ok(outcome)
}

/// Which permit a barrier uses.
#[derive(Clone, Copy)]
enum Mode<'a> {
    /// The removing device's own permit, in every folder.
    Removing(&'a BarrierPermit),
    /// A takeover after the person confirmed exactly these heads of removed devices.
    Confirmed(&'a BTreeSet<CommitId>),
}

/// Writes the barrier of one folder unless a head of a current device after the removal is
/// already on the chain (another device did it).
fn write_barrier_if_due(
    jx: &mut JobCtx<'_>,
    folder: &mut FolderSync,
    fs: &dyn FileSystem,
    mode: Mode<'_>,
    outcome: &mut RemovalOutcome,
) -> Result<bool, SyncError> {
    let newest = jx
        .account
        .newest_generation(folder.id())
        .ok_or(SyncError::NotSetUp("no key ring for the folder"))?;
    for _ in 0..4 {
        let delta = folder.fetch_delta(jx.server)?;
        let permit = match mode {
            Mode::Removing(permit) => *permit,
            Mode::Confirmed(_) => {
                match folder
                    .view()
                    .check_delta(jx.account.state(), newest, &delta)?
                {
                    DeltaCheck::Accepted(normal) => {
                        // Another device wrote the barrier meanwhile: take the delta in.
                        let mut cx = ctx(jx, fs);
                        folder.take_outcome(&mut cx, normal, &delta)?;
                        folder.clear_removed_heads();
                        folder.save_state(cx.store)?;
                        return Ok(false);
                    }
                    DeltaCheck::RemovedSigner(refusal) => {
                        BarrierPermit::takeover(jx.account.state(), jx.account.device(), &refusal)
                            .ok_or(SyncError::Chain(ChainError::RemovedSigner))?
                    }
                }
            }
        };
        let removal = permit.removal_index();
        let checked = folder.view().verify_delta_before_barrier(
            jx.account.state(),
            newest,
            &delta,
            &permit,
        )?;
        if let Mode::Confirmed(confirmed) = mode {
            if checked
                .removed_heads
                .iter()
                .any(|h| !confirmed.contains(&h.commit))
            {
                // The person did not see every head this barrier would cover: ask again.
                folder.hold_removed_heads(&checked.removed_heads, jx.store)?;
                outcome.removed_heads = checked.removed_heads.clone();
                return Ok(false);
            }
        }
        let view = checked.outcome.view.clone();
        let (head, sequence) = match checked.outcome.heads.last() {
            Some(h) => (h.clone(), view.frontier().map_or(0, |f| f.sequence)),
            None => match (folder.frontier_commit(), folder.view().frontier()) {
                (Some(h), Some(f)) => (h, f.sequence),
                // An empty folder has no head to put a barrier on.
                _ => return Ok(false),
            },
        };
        let covered = jx
            .account
            .state()
            .device(&head.commit.device)
            .is_some_and(|d| d.is_current())
            && head.commit.log_head.index >= removal;
        if covered {
            // The delta is already safe: take it with every rule.
            let normal = folder
                .view()
                .verify_delta(jx.account.state(), newest, &delta)?;
            let mut cx = ctx(jx, fs);
            folder.take_outcome(&mut cx, normal, &delta)?;
            return Ok(false);
        }
        let mut cx = ctx(jx, fs);
        match folder.write_barrier(
            &mut cx,
            &head,
            sequence,
            view,
            Some((&checked.outcome, &delta)),
        ) {
            Ok(()) => {
                outcome
                    .removed_heads
                    .extend(checked.removed_heads.iter().copied());
                folder.clear_removed_heads();
                folder.save_state(cx.store)?;
                return Ok(true);
            }
            // Another device wrote its barrier first: verify again.
            Err(SyncError::Net(e))
                if e.code() == Some(hangar_drive_protocol::api::ErrorCode::HeadMoved) => {}
            Err(SyncError::Chain(ChainError::OlderState)) => {}
            Err(e) => return Err(e),
        }
    }
    Err(SyncError::Invalid("the barrier lost the race too often"))
}

fn ctx<'a>(jx: &'a mut JobCtx<'_>, fs: &'a dyn FileSystem) -> Ctx<'a> {
    Ctx {
        account: jx.account,
        server: jx.server,
        keychain: jx.keychain,
        fs,
        store: jx.store,
        clock: jx.clock,
        entropy: jx.entropy,
        settings: jx.settings,
    }
}
