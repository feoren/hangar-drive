# Measurement: inode reuse, birth time and ctime on Linux (2026-11-26)

Own measurement for the file ID of the sync engine on Unix (replace check L3, directory check
L1). Raw output, unedited apart from shortened paths.

## Platform

- Docker Desktop on Windows 11 Pro 10.0.26300, Linux kernel `6.18.58.1-microsoft-standard-WSL2`
- Image `rust:1.100.0` (Debian, glibc), `rustc 1.100.0 (0ef1bc386 2026-11-09)`
- File systems: the container's root (`overlayfs` on the ext4 disk of the Docker VM), a
  `tmpfs`, `/dev/shm`, and the repository as a bind mount of an NTFS folder (`9p`,
  `aname=drvfs`, `cache=0x5`)

## 1. Delete and create again, 10,000 times in a tight loop

A small Rust program writes `a`, reads it with `fs::symlink_metadata`, compares inode,
`Metadata::created()` and `st_ctime` with the previous round, and removes the file:

```
/tmp/o: same_ino=9998 same_ino_and_btime=0 same_ino_and_ctime=0 no_btime=0
/tm: same_ino=0 same_ino_and_btime=0 same_ino_and_ctime=0 no_btime=0
/dev/shm: same_ino=0 same_ino_and_btime=0 same_ino_and_ctime=0 no_btime=0
```

(`/tmp/o` is on overlayfs, `/tm` and `/dev/shm` are tmpfs.)

The same with `stat` from the shell, overlayfs and the 9p bind mount:

```
== /tmp/m overlayfs
325856 birth=1795691698.2026-11-26 11:14:58.847478213 +0000 ctime=2026-11-26 11:14:58.850690056 +0000
325856 birth=1795691698.2026-11-26 11:14:58.852587892 +0000 ctime=2026-11-26 11:14:58.852587892 +0000
325856 birth=1795691698.2026-11-26 11:14:58.854315063 +0000 ctime=2026-11-26 11:14:58.854315063 +0000
== /w/tests/.tmp/m v9fs
1688849860794627 birth=0.- ctime=2026-11-26 11:14:58.891731700 +0000
1970324837505283 birth=0.- ctime=2026-11-26 11:14:58.897428300 +0000
2251799814215939 birth=0.- ctime=2026-11-26 11:14:58.903106700 +0000
```

## 2. ctime and birth time across a rename and a time change

```
echo x > a; stat; mv a b; stat; touch -m -d @1700000000 b; stat   (50 ms apart)
a 325862 ctime=2026-11-26 11:15:45.646425998 +0000 birth=2026-11-26 11:15:45.644582785 +0000
b 325862 ctime=2026-11-26 11:15:45.693749648 +0000 birth=2026-11-26 11:15:45.644582785 +0000
b 325862 ctime=2026-11-26 11:15:45.749749506 +0000 birth=2026-11-26 11:15:45.644582785 +0000
a 10133099162114306 ctime=2026-11-26 11:15:45.784124800 +0000 birth=-
b 10133099162114306 ctime=2026-11-26 11:15:45.840537800 +0000 birth=-
b 10133099162114306 ctime=2026-11-26 11:15:45.895355500 +0000 birth=-
```

(First three lines overlayfs, last three the 9p bind mount.)

## 3. The test `a_replace_checks_the_file_id_and_takes_the_new_one`, 20 runs each

`cargo test -p hangar-drive-sync --test localfs a_replace`, `CARGO_TARGET_DIR` inside the
container. "Baseline" is the same source with the birth time taken out of `unix_id`
(`Some(_) => base`), that is device and inode only, as before the change.

```
(c) baseline, repository copied to overlayfs:  0 green, 20 red of 20
    panicked at crates/hangar-drive-sync/tests/localfs.rs:547:5: assertion `left != right` failed
      left: Some(1641760222560150434208)
     right: Some(1641760222560150434208)
(b) with the birth time, overlayfs:            20 green, 0 red of 20
(d) the same loop, exit on the first red:      RESULT (d): 20 of 20 green
    whole crate on overlayfs: 69 + 3 + 6 + 12 + 4 + 13 tests, all ok
(a0) baseline, 9p bind mount:                  0 green, 20 red of 20
    panicked at crates/hangar-drive-sync/tests/localfs.rs:580:5: assertion `left == right` failed
      left: 1700000000000
     right: 1700000000500
(a) with the birth time, 9p bind mount:        0 green, 20 red of 20, all at localfs.rs:580
```

## 4. Modification times on the 9p bind mount

A file written, given the mtime `1700000000.5` (by handle or by path, with or without
`fsync`), reads back `1700000000.0` before any rename: the drvfs bind mount keeps whole seconds
only. That is the failure at line 580 in both runs on the bind mount; it is independent of the
file ID. `renameat2(RENAME_EXCHANGE)` fails there with `EINVAL` (22), so the engine falls back
to a plain rename.
