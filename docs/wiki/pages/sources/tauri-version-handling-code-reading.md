---
title: "Code reading: Tauri's NSIS bundler and updater with build metadata"
type: source
tags: [tauri, updater, nsis, windows, version, semver]
sources: []
raw: raw/2026-11-26-tauri-version-handling-code-reading.md
url: https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-bundler/src/bundle/windows/nsis/mod.rs
retrieved: 2026-11-26
created: 2026-11-26
updated: 2026-11-26
---

# Code reading: Tauri with build metadata

Own reading of the source code, no build and no installer run.

## Key points
- **NSIS bundler** (`tauri-bundler`, `dev` branch, 2026-11-26): `try_add_numeric_build_number` turns
  `X.Y.Z+B` with a numeric `B` into the four-part Windows version `X.Y.Z.B`; any other input
  (including the pre-release form `X.Y.Z-B`) becomes `X.Y.Z.0`. The value feeds `VIProductVersion`
  according to the warning text in the same function.
- **Updater** (`tauri-plugin-updater` 2.14.1 with `semver` 1.0.28): without a custom comparator a
  release is an update when `release.version > current_version`. `semver::Version` derives `Ord`,
  which also compares build metadata (numerically for numeric identifiers); only
  `Version::cmp_precedence` ignores it as SemVer 2.0.0 requires.
- Conclusion, not measured: with these versions the default updater would offer `0.1.0+13` over
  `0.1.0+12`.

## Significance for Hangar Drive
- The internal form must be `X.Y.Z+B`, not `X.Y.Z-B`, or the Windows file version loses the build.
- The rule "every release raises X, Y or Z" in [[0002-version-scheme]] cannot rest on the updater
  ignoring build metadata; see the contradiction recorded there.
