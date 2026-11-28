---
title: Transfer responsiveness and parallel downloads (measurement)
type: source
tags: [sync-engine, performance, transfers, measurement, linux]
sources: []
raw: raw/2026-11-28-transfer-responsiveness-measurement.md
url:
retrieved: 2026-11-28
created: 2026-11-28
updated: 2026-11-28
---

# Transfer responsiveness and parallel downloads (measurement)

Own measurement on Windows 11 Pro 10.0.26300, x64, debug build, against the in-memory test
server with simulated delays, plus a check run of the sync crate on Linux in the
`rust:1.100.0` Docker image. Backs the amendment "transfers that never hold the engine thread"
in [[0001-foundation]].

## Key points

- A command (pause) is answered after 41 to 55 ms while every upload worker waits a full second
  for the server (not measured before the change; by its design a command waited for the
  uploads in flight).
- During a long upload the window gets 10 to 11 snapshots in 2 s with `bytesLeft` going down,
  within the throttle of five per second plus the pass snapshots.
- 60 small files at 20 ms per download: 2.47 s one at a time, 0.31 to 0.32 s through the
  download lane with four workers (whole round including scan and plan).
- The check of a 64 MiB part file before it lands reads it back in about 34 ms against about
  124 ms for writing it, on NTFS.
- Linux: clippy clean and 355 tests green for `hangar-drive-sync`; the Unix code
  (`localfs/unix.rs`, `cfg(unix)` paths) compiles and runs there. A Windows bind mount as the
  test directory makes the link swap tests fail (no `RENAME_EXCHANGE`), a native volume does not.

## Significance for Hangar Drive

The numbers come from a test server with simulated delays; they show that the engine thread no
longer waits for the server, not how fast a real server over a network is. That measurement is
still open (see [[overview]]).
