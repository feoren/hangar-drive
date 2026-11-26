---
title: Merge and executor collision benchmark (measurement)
type: source
tags: [sync-engine, merge, performance, names, measurement]
sources: []
raw: raw/2026-11-26-merge-collision-benchmark.md
url:
retrieved: 2026-11-26
created: 2026-11-26
updated: 2026-11-26
---

# Merge and executor collision benchmark (measurement)

Own measurement on Windows 11 Pro 10.0.26300, x64, release build, on a machine shared with other
builds (rough numbers), of the collision handling of the merge and the executor before and after
the fix of security review finding HIGH 2.

## Key points

- Four cases, each timed once: an unchanged three way merge of n files in one directory, a merge
  of n ASCII case variants of one name, a join of n identical files on both sides, and an apply of
  n new files onto an empty working tree.
- **Before:** 1,000 unchanged files 2.76 s, 256 case variants 46.4 s, a join of 400 identical
  files 175.0 s, 2,000 new files 5.72 s; the growth was quadratic to cubic.
- **After:** 1,000 unchanged files 1.28 ms and 262,144 (one full directory) 0.67 s; 256 case
  variants 1.66 ms and 262,144 3.40 s; a join of 400 files 1.34 ms and 262,144 2.46 s; 2,000 new
  files 4.9 ms and 262,144 0.98 s.
- Every merged tree passed `Tree::check`; the case variant runs made one conflict copy fewer than
  there were variants.

## Significance for Hangar Drive

- Before the fix a compromised device could stop every device of the account with one directory
  well inside `MAX_DIRECTORY_ENTRIES`; after it, a full directory costs seconds, not hours. See
  the amendment "Collisions in linear time and copy names within the limit" in
  [[0001-foundation]].
- The numbers are wall clock times of single runs; the tests in `merge.rs`, `names.rs` and
  `apply.rs` bound the work by counting key computations instead, so they do not depend on the
  machine.
