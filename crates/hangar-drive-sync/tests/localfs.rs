//! Integration tests on the real file system, below the repository's `tests/.tmp/`: atomic
//! writes and their preconditions, Unicode names, names Windows cannot hold, long paths, locked
//! files (Windows), the watcher, and two engines syncing through real sync roots.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::identity::DeviceIdentity;
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken};
use hangar_drive_sync::account::Account;
use hangar_drive_sync::chunker::DynEntropy;
use hangar_drive_sync::folder::{Ctx, FolderSettings, FolderSync};
use hangar_drive_sync::localfs::LocalFs;
use hangar_drive_sync::memory::{ManualClock, MemKeychain, MemServer, MemStore, SeededRandom};
use hangar_drive_sync::ports::{EntryType, Expect, FileSystem, FsError};
use hangar_drive_sync::watch::FolderWatcher;

/// A test's directory below `tests/.tmp/`. It is removed when the test passes and kept when it
/// fails, so the files can be looked at.
struct TmpDir(PathBuf);

impl std::ops::Deref for TmpDir {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.0
    }
}

impl AsRef<std::path::Path> for TmpDir {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

impl AsRef<std::ffi::OsStr> for TmpDir {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.0.as_os_str()
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn tmp(name: &str) -> TmpDir {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join(".tmp")
        .join(format!("sync-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test dir");
    TmpDir(dir)
}

fn p(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn write(
    fs: &LocalFs,
    path: &[String],
    data: &[u8],
    replace: Option<Expect>,
) -> Result<(), FsError> {
    fs.write_atomic(
        path,
        &mut |w| w.write_all(data).map_err(|e| FsError::Io(e.to_string())),
        1_700_000_000_000,
        false,
        replace,
    )
    .map(|_| ())
}

#[test]
fn atomic_writes_check_their_preconditions() {
    let dir = tmp("atomic");
    let fs = LocalFs::new(&dir).unwrap();
    write(&fs, &p(&["a.txt"]), b"one", None).unwrap();
    assert_eq!(
        write(&fs, &p(&["a.txt"]), b"two", None),
        Err(FsError::Exists)
    );
    let stat = fs.stat(&p(&["a.txt"])).unwrap().unwrap();
    assert_eq!(stat.kind, EntryType::File);
    assert_eq!(stat.size, 3);
    assert_eq!(stat.mtime_ms, 1_700_000_000_000);
    let wrong = Expect {
        size: 99,
        mtime_ms: 0,
        file_id: None,
    };
    assert_eq!(
        write(&fs, &p(&["a.txt"]), b"two", Some(wrong)),
        Err(FsError::Changed)
    );
    let right = Expect {
        size: 3,
        mtime_ms: stat.mtime_ms,
        file_id: None,
    };
    write(&fs, &p(&["a.txt"]), b"second", Some(right)).unwrap();
    assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"second");
    // Nothing is left in the temporary directory.
    let temp = dir.join(".hangar-drive").join("tmp");
    assert_eq!(std::fs::read_dir(temp).unwrap().count(), 0);
    // A delete refuses a file that changed.
    assert_eq!(fs.remove_file(&p(&["a.txt"]), right), Err(FsError::Changed));
    let now = fs.stat(&p(&["a.txt"])).unwrap().unwrap();
    fs.remove_file(
        &p(&["a.txt"]),
        Expect {
            size: now.size,
            mtime_ms: now.mtime_ms,
            file_id: None,
        },
    )
    .unwrap();
    assert!(fs.stat(&p(&["a.txt"])).unwrap().is_none());
}

#[test]
fn unicode_names_round_trip() {
    let dir = tmp("unicode");
    let fs = LocalFs::new(&dir).unwrap();
    let names = [
        "caf\u{e9}.txt",
        "cafe\u{301}-2.txt",
        "\u{6587}\u{6863}.md",
        "\u{1f600}.bin",
        "Gr\u{fc}\u{df}e",
    ];
    for name in names {
        write(&fs, &p(&[name]), name.as_bytes(), None).unwrap();
    }
    let mut listed: Vec<String> = fs
        .list(&[])
        .unwrap()
        .into_iter()
        .filter_map(|e| e.name)
        .filter(|n| n != ".hangar-drive")
        .collect();
    listed.sort();
    let mut expected: Vec<String> = names.iter().map(|s| (*s).to_owned()).collect();
    expected.sort();
    assert_eq!(listed, expected);
    let mut buf = [0u8; 64];
    let n = fs.read_at(&p(&["\u{1f600}.bin"]), 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], "\u{1f600}.bin".as_bytes());
}

#[test]
fn names_that_cannot_be_paths_are_refused_before_any_path_is_built() {
    let dir = tmp("names");
    let fs = LocalFs::new(&dir).unwrap();
    for bad in ["..", "a/b"] {
        assert!(
            matches!(fs.stat(&p(&[bad])), Err(FsError::CannotSync(_))),
            "{bad}"
        );
    }
    #[cfg(windows)]
    for bad in ["..\\escape", "C:x", "CON", "nul.txt", "a<b", "dot."] {
        assert!(
            matches!(
                write(&fs, &p(&[bad]), b"x", None),
                Err(FsError::CannotSync(_))
            ),
            "{bad}"
        );
    }
    // Nothing was created outside the root.
    assert!(!dir.join("..").join("escape").exists());
}

#[test]
fn long_paths_work() {
    let dir = tmp("long");
    let fs = LocalFs::new(&dir).unwrap();
    let mut path = Vec::new();
    for i in 0..6 {
        path.push(format!("{}{i}", "d".repeat(60)));
        fs.create_dir(&path).unwrap();
    }
    path.push("file.txt".into());
    write(&fs, &path, b"deep", None).unwrap();
    assert!(fs.full_path(&path).unwrap().as_os_str().len() > 300);
    assert_eq!(fs.stat(&path).unwrap().unwrap().size, 4);
}

#[test]
fn renames_never_replace_but_allow_a_case_only_rename() {
    let dir = tmp("rename");
    let fs = LocalFs::new(&dir).unwrap();
    write(&fs, &p(&["a.txt"]), b"a", None).unwrap();
    write(&fs, &p(&["b.txt"]), b"b", None).unwrap();
    assert_eq!(
        fs.rename(&p(&["a.txt"]), &p(&["b.txt"])),
        Err(FsError::Exists)
    );
    fs.rename(&p(&["a.txt"]), &p(&["A.TXT"])).unwrap();
    let names: Vec<String> = fs
        .list(&[])
        .unwrap()
        .into_iter()
        .filter_map(|e| e.name)
        .collect();
    assert!(names.contains(&"A.TXT".to_owned()));
    let before = fs.stat(&p(&["b.txt"])).unwrap().unwrap().file_id;
    fs.rename(&p(&["b.txt"]), &p(&["c.txt"])).unwrap();
    assert_eq!(
        fs.stat(&p(&["c.txt"])).unwrap().unwrap().file_id,
        before,
        "a move keeps the file ID"
    );
}

#[cfg(windows)]
#[test]
fn locked_files_are_reported_after_retries() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tmp("locked");
    let fs = LocalFs::new(&dir).unwrap();
    write(&fs, &p(&["doc.docx"]), b"office", None).unwrap();
    // Like Office: open without sharing.
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(dir.join("doc.docx"))
        .unwrap();
    let mut buf = [0u8; 8];
    let started = Instant::now();
    assert_eq!(
        fs.read_at(&p(&["doc.docx"]), 0, &mut buf),
        Err(FsError::Locked)
    );
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "retried with backoff"
    );
    let stat = fs.stat(&p(&["doc.docx"])).unwrap().unwrap();
    let expect = Expect {
        size: stat.size,
        mtime_ms: stat.mtime_ms,
        file_id: None,
    };
    assert_eq!(
        fs.remove_file(&p(&["doc.docx"]), expect),
        Err(FsError::Locked)
    );
    drop(holder);
    assert_eq!(fs.read_at(&p(&["doc.docx"]), 0, &mut buf).unwrap(), 6);
}

#[test]
fn links_are_reported_and_not_followed() {
    let dir = tmp("links");
    let fs = LocalFs::new(&dir).unwrap();
    write(&fs, &p(&["target.txt"]), b"t", None).unwrap();
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(dir.join("target.txt"), dir.join("link.txt")).is_ok();
    #[cfg(windows)]
    let made =
        std::os::windows::fs::symlink_file(dir.join("target.txt"), dir.join("link.txt")).is_ok();
    if made {
        let stat = fs.stat(&p(&["link.txt"])).unwrap().unwrap();
        assert_eq!(stat.kind, EntryType::Symlink);
    }
    // Without the privilege to create links (Windows without developer mode) there is nothing
    // to check.
}

/// Security review N6: a link someone puts in place of a file is never read through, so no
/// content from outside the root is uploaded as that file's.
#[test]
fn a_link_in_place_of_a_file_is_not_read() {
    let dir = tmp("read-link");
    let outside = tmp("read-link-outside");
    let fs = LocalFs::new(&dir).unwrap();
    std::fs::write(outside.join("private.txt"), b"outside the root").unwrap();
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(outside.join("private.txt"), dir.join("doc.txt")).is_ok();
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(outside.join("private.txt"), dir.join("doc.txt"))
        .is_ok();
    if !made {
        // Windows without developer mode cannot create the link; nothing to check.
        println!("no link privilege: skipped");
        return;
    }
    let mut buf = [0u8; 64];
    let read = fs.read_at(&p(&["doc.txt"]), 0, &mut buf);
    assert!(
        !matches!(read, Ok(n) if n > 0),
        "read through the link: {read:?}"
    );
}

#[test]
fn the_watcher_reports_changes_below_the_root() {
    let dir = tmp("watch");
    let fs = LocalFs::new(&dir).unwrap();
    let watcher = FolderWatcher::start(&fs).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    // Waits until the watcher names a path that `hit` accepts, or reports a rescan.
    let wait_for = |hit: &dyn Fn(&[String]) -> bool| {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            let changes = watcher.drain(Duration::from_millis(250));
            seen.extend(changes.paths);
            if changes.rescan || seen.iter().any(|p| hit(p)) {
                return;
            }
        }
        panic!("{seen:?}");
    };
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub").join("caf\u{e9}.txt"), b"x").unwrap();
    // inotify watches a new directory only after its own event, so a file written into it at
    // once may be reported as the directory alone; the partial scan lists a new directory, so
    // either path is enough.
    wait_for(&|p| {
        p.last().is_some_and(|n| n == "caf\u{e9}.txt") || p == ["sub".to_owned()].as_slice()
    });
    // Once the directory is watched, a change inside it names the file.
    std::thread::sleep(Duration::from_millis(200));
    std::fs::write(dir.join("sub").join("second.txt"), b"y").unwrap();
    wait_for(&|p| p.last().is_some_and(|n| n == "second.txt"));
    // The reserved directory is not reported.
    write(&fs, &p(&["x.txt"]), b"x", None).unwrap();
    let changes = watcher.drain(Duration::from_millis(500));
    assert!(changes
        .paths
        .iter()
        .all(|p| !p.first().is_some_and(|n| n == ".hangar-drive")));
}

#[test]
fn two_engines_sync_through_real_folders() {
    let a_dir = tmp("engine-a");
    let b_dir = tmp("engine-b");
    let a_fs = LocalFs::new(&a_dir).unwrap();
    let b_fs = LocalFs::new(&b_dir).unwrap();
    let account_id = AccountId::from_bytes([0xac; 16]);
    let folder = FolderId::from_bytes([0xf0; 16]);
    let (a_id, b_id) = (DeviceId::from_bytes([1; 16]), DeviceId::from_bytes([2; 16]));
    let shared = MemServer::new_shared();
    let mut a_server = MemServer::connect(&shared, a_id);
    let mut b_server = MemServer::connect(&shared, b_id);
    let (mut a_store, mut b_store) = (MemStore::new(), MemStore::new());
    let (mut a_keys, mut b_keys) = (MemKeychain::default(), MemKeychain::default());
    let (mut a_rng, mut b_rng) = (SeededRandom::new(1), SeededRandom::new(2));
    let mut a = Account::create(
        &mut a_server,
        &mut a_keys,
        &mut a_store,
        &mut a_rng,
        0,
        InviteToken::from_bytes([9; 16]),
        account_id,
        a_id,
        "Laptop",
        None,
    )
    .unwrap();
    a.create_folder(&mut a_server, &mut a_store, folder, "Docs", &mut a_rng)
        .unwrap();
    let b_identity = DeviceIdentity::generate(&mut DynEntropy(&mut b_rng)).unwrap();
    a.add_device(
        &mut a_server,
        &mut a_store,
        LogDevice::of(&b_identity, &account_id, b_id, false),
        "Desktop",
        0,
        &mut a_rng,
    )
    .unwrap();
    let mut b = Account::join(
        &mut b_server,
        &mut b_keys,
        &mut b_store,
        b_identity,
        account_id,
        b_id,
        "Desktop",
        &[],
    )
    .unwrap();
    a.refresh(&mut a_server, &mut a_keys, &mut a_store).unwrap();
    let mut a_folder = FolderSync::new(&a, folder, "Docs");
    let mut b_folder = FolderSync::new(&b, folder, "Docs");
    a_folder.write_marker(&a_fs).unwrap();
    b_folder.write_marker(&b_fs).unwrap();
    std::fs::create_dir(a_dir.join("Fotos")).unwrap();
    std::fs::write(
        a_dir.join("Fotos").join("Urlaub \u{e9}t\u{e9}.jpg"),
        vec![7u8; 5_000_000],
    )
    .unwrap();
    std::fs::write(a_dir.join("notiz.txt"), b"hallo").unwrap();
    let clock = ManualClock::at(1_795_651_200_000);
    let settings = FolderSettings::default();
    for _ in 0..2 {
        let mut cx = Ctx {
            account: &mut a,
            server: &mut a_server,
            keychain: &mut a_keys,
            fs: &a_fs,
            store: &mut a_store,
            clock: &clock,
            entropy: &mut a_rng,
            settings: &settings,
        };
        a_folder.request_full_scan();
        a_folder.round(&mut cx).unwrap();
        b.refresh(&mut b_server, &mut b_keys, &mut b_store).unwrap();
        let mut cx = Ctx {
            account: &mut b,
            server: &mut b_server,
            keychain: &mut b_keys,
            fs: &b_fs,
            store: &mut b_store,
            clock: &clock,
            entropy: &mut b_rng,
            settings: &settings,
        };
        b_folder.request_full_scan();
        b_folder.round(&mut cx).unwrap();
    }
    let copied = std::fs::read(b_dir.join("Fotos").join("Urlaub \u{e9}t\u{e9}.jpg")).unwrap();
    assert_eq!(copied.len(), 5_000_000);
    assert_eq!(std::fs::read(b_dir.join("notiz.txt")).unwrap(), b"hallo");
    // The server never saw a name: two chunks of the large file plus manifests and nodes.
    assert!(shared.borrow().object_count(&folder) >= 5);
    assert!(a_folder.in_sync() && b_folder.in_sync());
}

/// Measurement for `docs/wiki/raw/2026-11-26-recycle-bin-measurement.md`: run with
/// `cargo test -p hangar-drive-sync --test localfs measure_ -- --ignored --nocapture`.
#[cfg(windows)]
#[test]
#[ignore]
fn measure_recycle_bin_and_replace() {
    use hangar_drive_sync::trash::to_recycle_bin;
    let dir = tmp("measure");
    let fs = LocalFs::new(&dir).unwrap();
    println!("root: {}", fs.root().display());
    // 1. A short verbatim path.
    std::fs::write(fs.root().join("short.txt"), b"marker").unwrap();
    println!(
        "verbatim short: {:?}, still there: {}",
        to_recycle_bin(&fs.root().join("short.txt")),
        fs.root().join("short.txt").exists()
    );
    // 2. A path beyond MAX_PATH.
    let mut deep = fs.root().to_path_buf();
    while deep.as_os_str().len() < 300 {
        deep.push("d".repeat(40));
    }
    std::fs::create_dir_all(&deep).unwrap();
    let long = deep.join("long.txt");
    std::fs::write(&long, b"marker").unwrap();
    println!(
        "verbatim long ({} chars): {:?}, still there: {}",
        long.as_os_str().len(),
        to_recycle_bin(&long),
        long.exists()
    );
    // 3. ReplaceFileW: IDs and times.
    write(&fs, &p(&["r.txt"]), b"old", None).unwrap();
    let before = fs.stat(&p(&["r.txt"])).unwrap().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    write(
        &fs,
        &p(&["r.txt"]),
        b"newer",
        Some(Expect {
            size: before.size,
            mtime_ms: before.mtime_ms,
            file_id: before.file_id,
        }),
    )
    .unwrap();
    let after = fs.stat(&p(&["r.txt"])).unwrap().unwrap();
    println!(
        "replace: id before {:?} after {:?} same {}; mtime after {} (asked 1700000000000)",
        before.file_id,
        after.file_id,
        before.file_id == after.file_id,
        after.mtime_ms
    );
    // 4. A subst drive, if one can be made.
    let letter = "Q:";
    let made = std::process::Command::new("subst")
        .args([letter, &dir.to_string_lossy()])
        .status()
        .is_ok_and(|s| s.success());
    if made {
        let on_subst = std::path::PathBuf::from(format!(r"{letter}\subst.txt"));
        std::fs::write(&on_subst, b"marker").unwrap();
        println!(
            "subst drive: {:?}, still there: {}",
            to_recycle_bin(&on_subst),
            on_subst.exists()
        );
        let _ = std::process::Command::new("subst")
            .args([letter, "/D"])
            .status();
    } else {
        println!("subst drive: could not be made");
    }
}

#[test]
fn a_new_file_appears_only_through_the_rename_and_never_replaces() {
    let dir = tmp("noreplace");
    let fs = LocalFs::new(&dir).unwrap();
    let target = dir.join("new.txt");
    // No placeholder holds the name while the content is written (L2).
    fs.write_atomic(
        &p(&["new.txt"]),
        &mut |w| {
            assert!(!target.exists(), "no placeholder at the target");
            w.write_all(b"content")
                .map_err(|e| FsError::Io(e.to_string()))
        },
        1_700_000_000_000,
        false,
        None,
    )
    .unwrap();
    // A name that appears during the write is not replaced.
    let result = fs.write_atomic(
        &p(&["race.txt"]),
        &mut |w| {
            std::fs::write(dir.join("race.txt"), b"the person's file").unwrap();
            w.write_all(b"from the server")
                .map_err(|e| FsError::Io(e.to_string()))
        },
        1_700_000_000_000,
        false,
        None,
    );
    assert_eq!(result.unwrap_err(), FsError::Exists);
    assert_eq!(
        std::fs::read(dir.join("race.txt")).unwrap(),
        b"the person's file"
    );
    let temp = dir.join(".hangar-drive").join("tmp");
    assert_eq!(std::fs::read_dir(temp).unwrap().count(), 0);
}

#[test]
fn a_replace_checks_the_file_id_and_takes_the_new_one() {
    let dir = tmp("replaceid");
    let fs = LocalFs::new(&dir).unwrap();
    write(&fs, &p(&["a.txt"]), b"one", None).unwrap();
    let stat = fs.stat(&p(&["a.txt"])).unwrap().unwrap();
    // Another program saved a file of the same size and time under the name (L3).
    std::fs::remove_file(dir.join("a.txt")).unwrap();
    write(&fs, &p(&["a.txt"]), b"two", None).unwrap();
    let other = fs.stat(&p(&["a.txt"])).unwrap().unwrap();
    assert_eq!((other.size, other.mtime_ms), (stat.size, stat.mtime_ms));
    assert_ne!(other.file_id, stat.file_id);
    let expect = Expect {
        size: stat.size,
        mtime_ms: stat.mtime_ms,
        file_id: stat.file_id,
    };
    assert_eq!(
        write(&fs, &p(&["a.txt"]), b"three", Some(expect)),
        Err(FsError::Changed)
    );
    assert_eq!(
        fs.remove_file(&p(&["a.txt"]), expect),
        Err(FsError::Changed)
    );
    assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"two");
    // With the right ID the replace goes through and nothing is left behind.
    let expect = Expect {
        file_id: other.file_id,
        ..expect
    };
    let after = fs
        .write_atomic(
            &p(&["a.txt"]),
            &mut |w| {
                w.write_all(b"three")
                    .map_err(|e| FsError::Io(e.to_string()))
            },
            1_700_000_000_500,
            false,
            Some(expect),
        )
        .unwrap();
    assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"three");
    assert_eq!(after.mtime_ms, 1_700_000_000_500);
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    let temp = dir.join(".hangar-drive").join("tmp");
    assert_eq!(std::fs::read_dir(temp).unwrap().count(), 0);
}

#[test]
fn opening_a_root_empties_the_temporary_directory() {
    let dir = tmp("tmpclean");
    let temp = dir.join(".hangar-drive").join("tmp");
    std::fs::create_dir_all(&temp).unwrap();
    std::fs::write(temp.join("left-by-a-crash.part"), b"half").unwrap();
    let _fs = LocalFs::new(&dir).unwrap();
    assert_eq!(std::fs::read_dir(&temp).unwrap().count(), 0);
}

#[test]
fn quarantined_files_expire_after_thirty_days() {
    let dir = tmp("quarantine");
    let q = dir.join(".hangar-drive").join("trash");
    std::fs::create_dir_all(q.join("00112233445566778899aabbccddeeff")).unwrap();
    std::fs::write(
        q.join("00112233445566778899aabbccddeeff").join("x.txt"),
        b"marker",
    )
    .unwrap();
    let now = std::time::SystemTime::now();
    hangar_drive_sync::trash::clean_quarantine(&q, now + Duration::from_secs(29 * 86_400));
    assert_eq!(std::fs::read_dir(&q).unwrap().count(), 1, "kept for now");
    hangar_drive_sync::trash::clean_quarantine(&q, now + Duration::from_secs(31 * 86_400));
    assert_eq!(
        std::fs::read_dir(&q).unwrap().count(),
        0,
        "gone after 30 days"
    );
}

/// Security review, info: the quarantine is also cleaned while the root stays open (the hourly
/// scan calls `housekeeping`), not only when it is opened.
#[test]
fn the_quarantine_is_cleaned_while_the_root_stays_open() {
    let dir = tmp("quarantine-open");
    let fs = LocalFs::new(&dir).unwrap();
    let q = dir.join(".hangar-drive").join("trash");
    std::fs::create_dir_all(q.join("00112233445566778899aabbccddeeff")).unwrap();
    std::fs::write(
        q.join("00112233445566778899aabbccddeeff").join("x.txt"),
        b"marker",
    )
    .unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    fs.housekeeping(now_ms + 29 * 86_400_000);
    assert_eq!(std::fs::read_dir(&q).unwrap().count(), 1, "kept for now");
    fs.housekeeping(now_ms + 31 * 86_400_000);
    assert_eq!(
        std::fs::read_dir(&q).unwrap().count(),
        0,
        "gone after 30 days"
    );
}

#[cfg(windows)]
#[test]
fn incoming_deletes_go_to_the_recycle_bin_or_the_quarantine() {
    use hangar_drive_protocol::ids::ItemId;
    use hangar_drive_sync::trash::Trashed;
    let dir = tmp("trash");
    let fs = LocalFs::new(&dir).unwrap();
    let item = ItemId::from_bytes([0x5a; 16]);
    write(&fs, &p(&["gone.txt"]), b"marker", None).unwrap();
    let s = fs.stat(&p(&["gone.txt"])).unwrap().unwrap();
    let expect = |s: &hangar_drive_sync::ports::Stat| Expect {
        size: s.size,
        mtime_ms: s.mtime_ms,
        file_id: s.file_id,
    };
    // A changed file is not taken away.
    let wrong = Expect {
        size: 1,
        ..expect(&s)
    };
    assert_eq!(
        fs.trash_file(&item, &p(&["gone.txt"]), wrong),
        Err(FsError::Changed)
    );
    assert_eq!(
        fs.trash_file(&item, &p(&["gone.txt"]), expect(&s)),
        Ok(Trashed::RecycleBin)
    );
    assert!(!dir.join("gone.txt").exists());
    // A path the shell cannot recycle (beyond MAX_PATH, measured) goes to the quarantine.
    let mut names: Vec<String> = Vec::new();
    while fs.root().join(names.join("\\")).as_os_str().len() < 300 {
        names.push("d".repeat(40));
    }
    let mut path = Vec::new();
    for name in &names {
        path.push(name.clone());
        fs.create_dir(&path).unwrap();
    }
    path.push("deep.txt".into());
    write(&fs, &path, b"marker", None).unwrap();
    let s = fs.stat(&path).unwrap().unwrap();
    assert_eq!(
        fs.trash_file(&item, &path, expect(&s)),
        Ok(Trashed::Quarantine)
    );
    assert!(fs.stat(&path).unwrap().is_none());
    let kept = dir
        .join(".hangar-drive")
        .join("trash")
        .join(item.to_hex())
        .join("deep.txt");
    assert_eq!(std::fs::read(kept).unwrap(), b"marker");
}

#[cfg(windows)]
#[test]
fn a_junction_in_place_of_a_directory_is_never_followed() {
    let dir = tmp("junction");
    let outside = tmp("junction-outside");
    let fs = LocalFs::new(&dir).unwrap();
    fs.create_dir(&p(&["sub"])).unwrap();
    write(&fs, &p(&["sub", "f.txt"]), b"inside", None).unwrap();
    let sub = fs.stat(&p(&["sub"])).unwrap().unwrap();
    let file = fs.stat(&p(&["sub", "f.txt"])).unwrap().unwrap();
    let expect = Expect {
        size: file.size,
        mtime_ms: file.mtime_ms,
        file_id: None,
    };
    fs.expect_directories(vec![(p(&["sub"]), sub.file_id.unwrap())]);
    // Someone swaps the directory for a junction to a folder outside the root (L1), with a
    // file of the same size and time there, so only the directory check stops the delete.
    std::fs::rename(dir.join("sub"), dir.join("sub-old")).unwrap();
    std::fs::write(outside.join("f.txt"), b"inside").unwrap();
    let outside_file = std::fs::OpenOptions::new()
        .write(true)
        .open(outside.join("f.txt"))
        .unwrap();
    outside_file
        .set_modified(std::time::UNIX_EPOCH + Duration::from_millis(file.mtime_ms as u64))
        .unwrap();
    drop(outside_file);
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(dir.join("sub"))
        .arg(&outside)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    for result in [
        fs.remove_file(&p(&["sub", "f.txt"]), expect),
        write(&fs, &p(&["sub", "new.txt"]), b"x", None),
        fs.list(&p(&["sub"])).map(|_| ()),
    ] {
        assert_eq!(result, Err(FsError::Changed));
    }
    assert!(outside.join("f.txt").exists());
    assert!(!outside.join("new.txt").exists());
    // Without the index's IDs the junction itself is refused as well.
    fs.expect_directories(Vec::new());
    assert_eq!(
        fs.remove_file(&p(&["sub", "f.txt"]), expect),
        Err(FsError::Changed)
    );
    // A different plain directory at the same path is refused by its file ID.
    std::fs::remove_dir(dir.join("sub")).unwrap();
    std::fs::create_dir(dir.join("sub")).unwrap();
    fs.expect_directories(vec![(p(&["sub"]), sub.file_id.unwrap())]);
    assert_eq!(
        write(&fs, &p(&["sub", "new.txt"]), b"x", None),
        Err(FsError::Changed)
    );
    assert!(outside.join("f.txt").exists());
}

#[cfg(windows)]
#[test]
fn names_windows_refuses_are_listed_as_other() {
    let dir = tmp("badnames");
    let fs = LocalFs::new(&dir).unwrap();
    // Another tool can make a name with a trailing dot through the verbatim path (L10).
    std::fs::write(fs.root().join("trailing."), b"marker").unwrap();
    let listed = fs.list(&[]).unwrap();
    let entry = listed
        .iter()
        .find(|e| e.name.as_deref() == Some("trailing."))
        .unwrap();
    assert_eq!(entry.stat.kind, EntryType::Other);
}

/// A link at `.hangar-drive` or one of its directories (security review N5): no temporary
/// write and no quarantined file may land outside the root through it.
#[cfg(windows)]
fn link_dir(link: &std::path::Path, target: &std::path::Path) {
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
}

#[cfg(unix)]
fn link_dir(link: &std::path::Path, target: &std::path::Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[test]
fn a_linked_reserved_directory_takes_no_temporary_write() {
    let dir = tmp("reserved-link");
    let outside = tmp("reserved-link-outside");
    let fs = LocalFs::new(&dir).unwrap();
    let _ = std::fs::remove_dir_all(dir.join(".hangar-drive"));
    link_dir(&dir.join(".hangar-drive"), &outside);
    assert!(matches!(
        write(&fs, &p(&["new.txt"]), b"x", None),
        Err(FsError::CannotSync(_))
    ));
    assert!(!dir.join("new.txt").exists());
    assert_eq!(std::fs::read_dir(&*outside).unwrap().count(), 0);
}

#[cfg(windows)]
#[test]
fn a_linked_quarantine_takes_nothing_out_of_the_root() {
    use hangar_drive_protocol::ids::ItemId;
    let dir = tmp("trash-link");
    let outside = tmp("trash-link-outside");
    let fs = LocalFs::new(&dir).unwrap();
    // A path the shell cannot recycle (beyond MAX_PATH, measured) goes to the quarantine.
    let mut names: Vec<String> = Vec::new();
    while fs.root().join(names.join("\\")).as_os_str().len() < 300 {
        names.push("d".repeat(40));
    }
    let mut path = Vec::new();
    for name in &names {
        path.push(name.clone());
        fs.create_dir(&path).unwrap();
    }
    path.push("deep.txt".into());
    write(&fs, &path, b"marker", None).unwrap();
    let s = fs.stat(&path).unwrap().unwrap();
    let expect = Expect {
        size: s.size,
        mtime_ms: s.mtime_ms,
        file_id: s.file_id,
    };
    std::fs::create_dir_all(dir.join(".hangar-drive")).unwrap();
    let _ = std::fs::remove_dir_all(dir.join(".hangar-drive").join("trash"));
    link_dir(&dir.join(".hangar-drive").join("trash"), &outside);
    let item = ItemId::from_bytes([0x42; 16]);
    assert!(matches!(
        fs.trash_file(&item, &path, expect),
        Err(FsError::CannotSync(_))
    ));
    assert!(fs.stat(&path).unwrap().is_some(), "the file stays in place");
    assert_eq!(std::fs::read_dir(&*outside).unwrap().count(), 0);
}
