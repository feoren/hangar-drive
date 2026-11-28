# Transfer responsiveness and parallel downloads (own measurement)

- Date: 2026-11-28
- Platform: Windows 11 Pro 10.0.26300, x64, debug build (`cargo test`), Rust 1.100.0 per
  `rust-toolchain.toml`; the machine ran other programs at the same time, so the numbers are
  rough. Server: the in-memory test server (`crates/hangar-drive-sync/src/memory.rs`) with
  simulated delays, not a real server over a network.
- Linux: Docker image `rust:1.100.0` (Debian), the repository bind-mounted at `/src`, a named
  volume as `CARGO_TARGET_DIR`, and a named volume over `/src/tests/.tmp` so the file system
  tests run on a Linux file system.

## Commands

```
cargo test -p hangar-drive-sync --test engine_budget --test large_transfers --test http -- --nocapture
cargo test -p hangar-drive-sync --lib the_check_before_landing -- --nocapture
docker run --rm -v <repo>:/src -v <tmp volume>:/src/tests/.tmp -v <target volume>:/target \
  -e CARGO_TARGET_DIR=/target -w /src rust:1.100.0 \
  cargo clippy --locked -p hangar-drive-sync --all-targets -- -D warnings
docker run ... rust:1.100.0 cargo test --locked --no-fail-fast -p hangar-drive-sync
```

## Output (three runs in a row of the integration tests, after the review fixes)

```
the pause was taken after 50.9216ms with every upload worker waiting
10 snapshots in 2s: [19221, 19077, 18951, 18900, 18882, 18740, 18596, 18542, 18452, 18308]
60 small files at 20 ms per download: one at a time 2.4672259s, parallel 316.2539ms
test result: ok. 17 passed (engine_budget); 13 passed (large_transfers); 8 passed (http)

the pause was taken after 41.4135ms with every upload worker waiting
10 snapshots in 2s: [19239, 19095, 18951, 18900, 18812, 18668, 18542, 18524, 18380, 18136]
60 small files at 20 ms per download: one at a time 2.4649658s, parallel 315.2146ms

the pause was taken after 51.9041ms with every upload worker waiting
10 snapshots in 2s: [19221, 19077, 18951, 18934, 18812, 18668, 18542, 18524, 18380, 18136]
60 small files at 20 ms per download: one at a time 2.4764059s, parallel 314.9853ms
```

Three earlier runs before the review fixes gave 41 to 55 ms for the pause, 10 or 11 snapshots
in 2 s and 2.48 s against 0.31 s for the 60 files.

The check before a download in parts lands (16 chunks of 4 MiB on NTFS, debug and release
build alike):

```
64 MiB in parts: written in 124.7591ms, checked in 33.8724ms
64 MiB in parts: written in 123.3854ms, checked in 34.5175ms
```

Linux (`rust:1.100.0`): clippy without a warning; `cargo test -p hangar-drive-sync`: 355 passed,
0 failed, 1 ignored. With `tests/.tmp` on the Windows bind mount instead, 10 tests of
`localfs::link_swap_tests` and `localfs::tests::a_crash_after_the_swap_of_a_replace_loses_no_old_file`
fail with `ENXIO` and `EOPNOTSUPP`: that mount supports neither the link swaps nor
`RENAME_EXCHANGE`; they are not affected by the changes measured here.

## Setup of the tests

- Pause: 40 files, each upload held for 1 s by the in-memory server with four parallel upload
  workers; time from `EngineHandle::call(pause)` to its answer.
- Snapshots: 80 files, each upload 120 ms of real time and 50 ms of the work budget; snapshots
  received by the window's channel in a 2 s window during the upload (`bytesLeft` values).
- 60 small files: the round that brings them to a second device, 20 ms per download, one at a
  time against the download lane with four workers; the whole round including scan and plan.
