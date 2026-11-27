//! Removing a device (ADR 0001, section 4; security review N1 and N2): the job re-seals and
//! writes barriers, a removed device can no longer commit, and if the removing device goes away
//! right after the append, another current device completes the step and reports the heads of
//! the removed device it let in.

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::error::SyncError;
use hangar_drive_sync::folder::{
    Ctx, FolderSettings, FolderState, FolderSync, RoundReport, StopReason,
};
use hangar_drive_sync::memory::{
    ManualClock, MemFs, MemKeychain, MemServer, MemStore, SeededRandom,
};
use hangar_drive_sync::ports::NoLocalRoot;
use hangar_drive_sync::removal::{accept_removed_heads, complete_pending, remove_devices, JobCtx};

const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);
const FOLDER: FolderId = FolderId::from_bytes([0xf0; 16]);

struct Dev {
    id: DeviceId,
    fs: MemFs,
    store: MemStore,
    keys: MemKeychain,
    server: MemServer,
    rng: SeededRandom,
    account: Account,
    folder: FolderSync,
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn world() -> (Vec<Dev>, ManualClock, FolderSettings) {
    let shared = MemServer::new_shared();
    let ids: Vec<DeviceId> = (1..=3).map(|i| DeviceId::from_bytes([i; 16])).collect();
    let mut server0 = MemServer::connect(&shared, ids[0]);
    let (mut store0, mut keys0, mut rng0) = (
        MemStore::new(),
        MemKeychain::default(),
        SeededRandom::new(1),
    );
    let mut a = Account::create(
        &mut server0,
        &mut keys0,
        &mut store0,
        &mut rng0,
        0,
        InviteToken::from_bytes([9; 16]),
        ACCOUNT,
        ids[0],
        "A",
        None,
    )
    .unwrap();
    a.create_folder(&mut server0, &mut store0, FOLDER, "Docs", &mut rng0)
        .unwrap();
    let mut devs = Vec::new();
    let mut joined = Vec::new();
    for (n, id) in ids.iter().enumerate().skip(1) {
        let mut rng = SeededRandom::new(n as u64 + 10);
        let identity = DeviceIdentity::generate(&mut DynEntropy(&mut rng)).unwrap();
        a.add_device(
            &mut server0,
            &mut store0,
            LogDevice::of(&identity, &ACCOUNT, *id, false),
            &format!("D{n}"),
            0,
            &mut rng0,
        )
        .unwrap();
        joined.push((identity, *id, rng));
    }
    a.refresh(&mut server0, &mut keys0, &mut store0).unwrap();
    let folder = FolderSync::new(&a, FOLDER, "Docs");
    let fs = MemFs::new(true);
    folder.write_marker(&fs).unwrap();
    devs.push(Dev {
        id: ids[0],
        fs,
        store: store0,
        keys: keys0,
        server: server0,
        rng: rng0,
        account: a,
        folder,
    });
    for (n, (identity, id, rng)) in joined.into_iter().enumerate() {
        let mut server = MemServer::connect(&shared, id);
        let (mut store, mut keys) = (MemStore::new(), MemKeychain::default());
        let account = Account::join(
            &mut server,
            &mut keys,
            &mut store,
            identity,
            ACCOUNT,
            id,
            &format!("D{}", n + 1),
            &[],
        )
        .unwrap();
        let folder = FolderSync::new(&account, FOLDER, "Docs");
        let fs = MemFs::new(true);
        folder.write_marker(&fs).unwrap();
        devs.push(Dev {
            id,
            fs,
            store,
            keys,
            server,
            rng,
            account,
            folder,
        });
    }
    (
        devs,
        ManualClock::at(1_795_651_200_000),
        FolderSettings::default(),
    )
}

fn round(
    d: &mut Dev,
    clock: &ManualClock,
    settings: &FolderSettings,
) -> Result<RoundReport, SyncError> {
    d.account
        .refresh(&mut d.server, &mut d.keys, &mut d.store)?;
    let mut cx = Ctx {
        account: &mut d.account,
        server: &mut d.server,
        keychain: &mut d.keys,
        fs: &d.fs,
        store: &mut d.store,
        clock,
        entropy: &mut d.rng,
        settings,
    };
    d.folder.request_full_scan();
    d.folder.round(&mut cx)
}

fn job<'a>(
    d: &'a mut Dev,
    clock: &'a ManualClock,
    settings: &'a FolderSettings,
) -> (JobCtx<'a>, &'a mut FolderSync, &'a MemFs) {
    (
        JobCtx {
            account: &mut d.account,
            server: &mut d.server,
            keychain: &mut d.keys,
            store: &mut d.store,
            clock,
            entropy: &mut d.rng,
            settings,
        },
        &mut d.folder,
        &d.fs,
    )
}

#[test]
fn a_removed_device_can_no_longer_commit_and_the_others_go_on() {
    let (mut devs, clock, settings) = world();
    devs[0].fs.user_write(&p(&["a.txt"]), b"a");
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    let target = devs[2].id;
    {
        let (mut jx, folder, fs) = job(&mut devs[0], &clock, &settings);
        let outcome = remove_devices(&mut jx, &mut [(folder, fs)], &[target]).unwrap();
        assert!(outcome.resealed);
        assert_eq!(outcome.barriers, 1);
        assert!(outcome.removed_heads.is_empty());
    }
    // The removed device's next commit is refused by the server.
    devs[2].fs.user_write(&p(&["evil.txt"]), b"x");
    let result = round(&mut devs[2], &clock, &settings);
    assert!(result.is_err() || !devs[2].folder.in_sync());
    // The other device takes the barrier and keeps syncing under the new generation.
    devs[1].fs.user_write(&p(&["b.txt"]), b"b");
    let r = round(&mut devs[1], &clock, &settings).unwrap();
    assert!(r.published, "{r:?}");
    round(&mut devs[0], &clock, &settings).unwrap();
    assert_eq!(devs[0].fs.read_all(&p(&["b.txt"])).unwrap(), b"b");
    assert!(devs[0].fs.read_all(&p(&["evil.txt"])).is_none());
    assert_eq!(devs[1].account.newest_generation(&FOLDER).unwrap().0, 2);
}

#[test]
fn a_folder_without_a_sync_root_here_gets_its_barrier_without_touching_a_disk() {
    let (mut devs, clock, settings) = world();
    devs[0].fs.user_write(&p(&["a.txt"]), b"a");
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    let target = devs[2].id;
    let (mut jx, folder, _) = job(&mut devs[0], &clock, &settings);
    // The engine passes this for folders of the account that are not synced on this device;
    // every call on it fails, so the barrier path must not need the disk.
    let nowhere = NoLocalRoot;
    let outcome = remove_devices(&mut jx, &mut [(folder, &nowhere)], &[target]).unwrap();
    assert!(outcome.resealed);
    assert_eq!(outcome.barriers, 1);
}

#[test]
fn another_device_completes_the_step_when_the_remover_goes_away() {
    let (mut devs, clock, settings) = world();
    devs[0].fs.user_write(&p(&["a.txt"]), b"a");
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    // C commits; B has not pulled it yet.
    devs[2].fs.user_write(&p(&["from-c.txt"]), b"c");
    assert!(round(&mut devs[2], &clock, &settings).unwrap().published);
    // A removes C and goes away right after the append (no re-seal, no barrier).
    let target = devs[2].id;
    {
        let d = &mut devs[0];
        d.account
            .rotate(&mut d.server, &mut d.keys, &[target], 0, &mut d.rng)
            .unwrap();
    }
    // B completes the re-seal (N1), but writes no barrier just because its log saw a removal.
    {
        let d = &mut devs[1];
        d.account
            .refresh(&mut d.server, &mut d.keys, &mut d.store)
            .unwrap();
    }
    {
        let (mut jx, folder, fs) = job(&mut devs[1], &clock, &settings);
        let outcome = complete_pending(&mut jx, &mut [(folder, fs)])
            .unwrap()
            .expect("the re-seal was due");
        assert!(outcome.resealed);
        assert_eq!(outcome.barriers, 0);
        assert!(complete_pending(&mut jx, &mut [(folder, fs)])
            .unwrap()
            .is_none());
    }
    // B: the head of the removed device has no barrier after it. Only this real refusal makes
    // B look at it without the rule, and B asks the person instead of writing a barrier (H1).
    let sequence_before = devs[1].server.state().folder_sequence(&FOLDER);
    let r = round(&mut devs[1], &clock, &settings).unwrap();
    assert_eq!(r.removed_heads.len(), 1, "{r:?}");
    assert_eq!(r.removed_heads[0].device, target);
    assert_eq!(
        devs[1].folder.state(),
        FolderState::Stopped(StopReason::RemovedHeads)
    );
    assert!(devs[1].fs.read_all(&p(&["from-c.txt"])).is_none());
    assert_eq!(
        devs[1].server.state().folder_sequence(&FOLDER),
        sequence_before,
        "no barrier without the person"
    );
    // The person takes C's head in: the barrier covers it (N2) and the folder syncs again.
    {
        let (mut jx, folder, fs) = job(&mut devs[1], &clock, &settings);
        let outcome = accept_removed_heads(&mut jx, folder, fs).unwrap();
        assert_eq!(outcome.barriers, 1);
        assert_eq!(outcome.removed_heads.len(), 1);
        assert_eq!(outcome.removed_heads[0].device, target);
    }
    assert_eq!(devs[1].folder.state(), FolderState::Active);
    // "Undo a device" finds C's head on the timeline.
    assert!(devs[1]
        .folder
        .meta()
        .timeline
        .iter()
        .any(|t| t.device == target));
    round(&mut devs[1], &clock, &settings).unwrap();
    assert_eq!(devs[1].fs.read_all(&p(&["from-c.txt"])).unwrap(), b"c");
    // A comes back and syncs normally after B's barrier.
    round(&mut devs[0], &clock, &settings).unwrap();
    assert_eq!(devs[0].fs.read_all(&p(&["from-c.txt"])).unwrap(), b"c");
    devs[0].fs.user_write(&p(&["after.txt"]), b"z");
    assert!(round(&mut devs[0], &clock, &settings).unwrap().published);
}

#[test]
fn a_server_that_hides_the_barrier_from_an_offline_device_gets_nothing_in() {
    let (mut devs, clock, settings) = world();
    devs[0].fs.user_write(&p(&["a.txt"]), b"a");
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    let synced = devs[0].server.state().folder_sequence(&FOLDER);
    // C (whose key the attacker holds) commits while it is still current.
    devs[2].fs.user_write(&p(&["evil.txt"]), b"x");
    assert!(round(&mut devs[2], &clock, &settings).unwrap().published);
    let with_c = devs[0].server.state().folder_commits(&FOLDER);
    // The malicious server hides C's commit from A, so A's barrier covers nothing of C.
    devs[0].server.state().rewind_folder(&FOLDER, synced);
    let target = devs[2].id;
    {
        let (mut jx, folder, fs) = job(&mut devs[0], &clock, &settings);
        let outcome = remove_devices(&mut jx, &mut [(folder, fs)], &[target]).unwrap();
        assert_eq!(outcome.barriers, 1);
        assert!(outcome.removed_heads.is_empty());
    }
    // B was offline all along. The server now hides A's barrier from B and shows C's commit.
    devs[0]
        .server
        .state()
        .set_folder_commits(&FOLDER, with_c.clone());
    let sequence = devs[1].server.state().folder_sequence(&FOLDER);
    {
        // Nothing for B to complete on its own: A re-sealed, and B never writes a barrier
        // because its log saw a removal.
        let (mut jx, folder, fs) = job(&mut devs[1], &clock, &settings);
        let pending = complete_pending(&mut jx, &mut [(folder, fs)]).unwrap();
        assert!(pending.is_none_or(|o| o.barriers == 0));
    }
    let r = round(&mut devs[1], &clock, &settings).unwrap();
    assert_eq!(r.removed_heads.len(), 1, "{r:?}");
    assert_eq!(r.removed_heads[0].device, target);
    assert_eq!(
        devs[1].folder.state(),
        FolderState::Stopped(StopReason::RemovedHeads)
    );
    // Nothing of C reached B's disk, and B wrote no barrier that would take it in.
    assert!(devs[1].fs.read_all(&p(&["evil.txt"])).is_none());
    assert_eq!(devs[1].server.state().folder_sequence(&FOLDER), sequence);
    assert_eq!(devs[1].server.state().folder_commits(&FOLDER), with_c);
    // Further rounds stay stopped until the person decides.
    let again = round(&mut devs[1], &clock, &settings).unwrap();
    assert!(again.removed_heads.is_empty() && !again.published);
    assert!(devs[1].fs.read_all(&p(&["evil.txt"])).is_none());
}

#[test]
fn content_hashed_before_a_rotation_but_not_uploaded_still_goes_up() {
    let (mut devs, clock, settings) = world();
    devs[0].fs.user_write(&p(&["a.txt"]), b"a");
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    // B writes more files than one round has publish attempts; its round hashes them under
    // generation 1, then fails at the pull.
    let names: Vec<String> = (0..8).map(|i| format!("late-{i}.txt")).collect();
    for name in &names {
        devs[1].fs.user_write(&p(&[name]), name.as_bytes());
    }
    devs[1].server.state().online = false;
    {
        let d = &mut devs[1];
        let mut cx = Ctx {
            account: &mut d.account,
            server: &mut d.server,
            keychain: &mut d.keys,
            fs: &d.fs,
            store: &mut d.store,
            clock: &clock,
            entropy: &mut d.rng,
            settings: &settings,
        };
        d.folder.request_full_scan();
        let r = d.folder.round(&mut cx).unwrap();
        assert!(r.offline && !r.published, "{r:?}");
    }
    devs[1].server.state().online = true;
    // A removes C: the ring gets generation 2 while B's new content is still unpublished.
    let target = devs[2].id;
    {
        let (mut jx, folder, fs) = job(&mut devs[0], &clock, &settings);
        assert!(
            remove_devices(&mut jx, &mut [(folder, fs)], &[target])
                .unwrap()
                .resealed
        );
    }
    // B's next round publishes the unchanged files under generation 2, all in one round.
    let r = round(&mut devs[1], &clock, &settings).unwrap();
    assert!(r.published, "{r:?}");
    assert_eq!(devs[1].account.newest_generation(&FOLDER).unwrap().0, 2);
    round(&mut devs[0], &clock, &settings).unwrap();
    for name in &names {
        assert_eq!(
            devs[0].fs.read_all(&p(&[name])).as_deref(),
            Some(name.as_bytes())
        );
    }
}

#[test]
fn a_repair_after_a_rotation_uploads_lost_old_chunks_under_the_new_generation() {
    let (mut devs, clock, settings) = world();
    devs[0]
        .fs
        .user_write(&p(&["a.txt"]), b"sealed under generation 1");
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    let target = devs[2].id;
    {
        let (mut jx, folder, fs) = job(&mut devs[0], &clock, &settings);
        assert!(
            remove_devices(&mut jx, &mut [(folder, fs)], &[target])
                .unwrap()
                .resealed
        );
    }
    // A broken server view: nothing is live and the collection deleted every object, also
    // the chunk of a.txt that only generation 1 can name.
    let all = devs[0].server.state().live_set(&FOLDER);
    devs[0]
        .server
        .state()
        .set_live(&FOLDER, std::collections::BTreeSet::new());
    devs[0].server.state().delete_objects(&FOLDER, &all);
    // A's next publish needs the full repair, which uploads a.txt again under generation 2.
    devs[0].fs.user_write(&p(&["b.txt"]), b"b");
    let r = round(&mut devs[0], &clock, &settings).unwrap();
    assert!(r.published, "{r:?}");
    round(&mut devs[1], &clock, &settings).unwrap();
    assert_eq!(
        devs[1].fs.read_all(&p(&["a.txt"])).unwrap(),
        b"sealed under generation 1"
    );
    assert_eq!(devs[1].fs.read_all(&p(&["b.txt"])).unwrap(), b"b");
}

/// Crypto review LOW 1, the open point of the sync engine: a server showed A a version of the
/// device names that it does not keep (a compromised C bumped it, the server went back to the
/// older record). A removes B and C and is the last current device; its re-seal at its own
/// version plus one is refused, so it re-seals at the server's version plus one under the new
/// epoch, and nothing is left due. Before, the record stayed in the old epoch for good.
#[test]
fn the_last_device_reseals_at_the_server_version_after_a_forged_one() {
    let (mut devs, clock, settings) = world();
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    let key = hangar_drive_crypto::device_names::device_names_key();
    let earlier = devs[0].server.state().stored_record(&key).unwrap();
    {
        let c = &mut devs[2];
        c.account
            .refresh(&mut c.server, &mut c.keys, &mut c.store)
            .unwrap();
        for n in 0..5 {
            let me = c.id;
            c.account
                .set_device_name(
                    &mut c.server,
                    &mut c.store,
                    &me,
                    &format!("C{n}"),
                    &mut c.rng,
                )
                .unwrap();
        }
    }
    let a = &mut devs[0];
    a.account
        .refresh(&mut a.server, &mut a.keys, &mut a.store)
        .unwrap();
    // The server keeps the earlier record again.
    a.server
        .state()
        .set_stored_record(key, earlier.0, earlier.1.clone());
    let targets = [devs[1].id, devs[2].id];
    let (mut jx, folder, fs) = job(&mut devs[0], &clock, &settings);
    let outcome = remove_devices(&mut jx, &mut [(folder, fs)], &targets).unwrap();
    assert!(outcome.resealed);
    assert!(
        !devs[0].account.reseal_due(),
        "nothing is left in the old epoch"
    );
    let (version, _) = devs[0].server.state().stored_record(&key).unwrap();
    assert_eq!(version, earlier.0 + 1);
}

/// Security review L1: a server that names a version near the top for a record it cannot show
/// does not get it: the last device re-seals nothing at that version (which would have frozen
/// the record for good, or panicked one version later), and the step stays due.
#[test]
fn a_bare_high_version_from_the_server_is_not_taken() {
    let (mut devs, clock, settings) = world();
    for d in devs.iter_mut() {
        round(d, &clock, &settings).unwrap();
    }
    let key = hangar_drive_crypto::device_names::device_names_key();
    let earlier = devs[0].server.state().stored_record(&key).unwrap();
    devs[0]
        .server
        .state()
        .set_stored_record(key, u64::MAX - 1, earlier.1.clone());
    let targets = [devs[1].id, devs[2].id];
    let (mut jx, folder, fs) = job(&mut devs[0], &clock, &settings);
    remove_devices(&mut jx, &mut [(folder, fs)], &targets).unwrap();
    let (version, _) = devs[0].server.state().stored_record(&key).unwrap();
    assert_eq!(version, u64::MAX - 1, "nothing sealed at the top");
    assert!(devs[0].account.reseal_due(), "the step stays due");
}
