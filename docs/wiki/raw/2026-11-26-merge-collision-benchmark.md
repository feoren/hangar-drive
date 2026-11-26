# Merge and executor collision benchmark (own measurement)

- Date: 2026-11-26
- Platform: Windows 11 Pro 10.0.26300, x64, release build (`cargo build --release`), Rust per
  `rust-toolchain.toml`; the machine was shared with other builds, so the numbers are rough.
- Program: a small binary outside the repository that links `hangar-drive-sync` and runs, each
  once and timed with `std::time::Instant`:
  1. `merge3(t, t, t)` for an unchanged folder of n files in one directory (`file-NNNNNN.jpg`);
  2. `merge3(r, r, r)` where r holds n ASCII case variants of `abcdefghijklmnopqr.txt`;
  3. `join(remote, local)` with n files of equal names and contents on both sides;
  4. `apply` of a target with n new files in one directory onto an empty working tree, with a
     disk double that accepts every operation.

## Before (code as reviewed)

| Case | n | Time |
| --- | --- | --- |
| unchanged merge | 1,000 | 2.76 s |
| case variants | 256 | 46.4 s |
| join, identical files | 400 | 175.0 s |
| apply, new files | 2,000 | 5.72 s |

## After (linear collision fixing, `DirNames`, executor index)

| Case | n | Time |
| --- | --- | --- |
| unchanged merge | 1,000 / 8,000 / 50,000 / 262,144 | 1.28 ms / 10.1 ms / 87.5 ms / 0.67 s |
| case variants | 256 / 1,024 / 4,096 / 262,144 | 1.66 ms / 7.2 ms / 33.0 ms / 3.40 s |
| join, identical files | 400 / 5,000 / 50,000 / 262,144 | 1.34 ms / 26.6 ms / 0.34 s / 2.46 s |
| apply, new files | 2,000 / 20,000 / 100,000 / 262,144 | 4.9 ms / 54.1 ms / 0.32 s / 0.98 s |

Every merged tree passed `Tree::check`; the case variant runs made n - 1 conflict copies.
