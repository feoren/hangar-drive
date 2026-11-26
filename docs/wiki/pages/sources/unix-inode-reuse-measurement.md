---
title: Inode reuse, birth time and ctime on Linux (measurement)
type: source
tags: [linux, file-system, file-id, sync-engine]
sources: []
raw: raw/2026-11-26-unix-inode-reuse-measurement.md
url:
retrieved: 2026-11-26
created: 2026-11-26
updated: 2026-11-26
---

# Inode reuse, birth time and ctime on Linux (measurement)

Own measurement in Docker (kernel 6.18 WSL2, glibc, Rust 1.100.0) for the file ID of the sync
engine on Unix (replace check L3, directory check L1).

## Key points

- On overlayfs over ext4, a deleted file's inode number goes to the next new file at once: 9,998
  of 10,000 delete and create cycles. tmpfs did not reuse a number in 10,000 cycles.
- The birth time (`Metadata::created`, `stx_btime`) differed in every one of those cycles and
  stays the same across a rename and a time change.
- `st_ctime` changes with a rename and with a time change, so it cannot be part of an ID that a
  move must keep.
- The NTFS bind mount (9p, drvfs) reports no birth time, does not reuse inode numbers in the
  measurement, keeps modification times in whole seconds only, and refuses `RENAME_EXCHANGE`.
- The test `a_replace_checks_the_file_id_and_takes_the_new_one` failed 20 of 20 times on
  overlayfs with device and inode only, and passed 20 of 20 with the birth time. On the bind mount
  it fails at the mtime assertion before and after the change.

## Significance for Hangar Drive

Basis of the conclusion "File IDs on Unix" in [[0001-foundation]], section 7. Code:
`crates/hangar-drive-sync/src/localfs.rs` (`unix_id`). Not measured: macOS (`st_birthtime`),
ext4 with 128 byte inodes, NFS, FUSE, kernels without fine-grained timestamps.
