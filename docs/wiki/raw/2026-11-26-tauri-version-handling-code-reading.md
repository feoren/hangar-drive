# Code reading: how Tauri handles `X.Y.Z+B` and `X.Y.Z-B`

- Date: 2026-11-26
- Method: reading the source of the crates, no build or installer run.
- Platform of the reader: Windows 11 x64 (irrelevant for the reading itself).

## 1. NSIS bundler: Windows file version

Source: `crates/tauri-bundler/src/bundle/windows/nsis/mod.rs` on the `dev` branch of
https://github.com/tauri-apps/tauri, retrieved 2026-11-26 from
https://raw.githubusercontent.com/tauri-apps/tauri/dev/crates/tauri-bundler/src/bundle/windows/nsis/mod.rs

- The template value `version_with_build` is `try_add_numeric_build_number(settings.version_string())`.
- `try_add_numeric_build_number` parses the app version with `semver::Version::parse`. If the build
  metadata is not empty and parses as `u64`, it returns `major.minor.patch.build`; otherwise it returns
  `major.minor.patch.0` (with a warning when the metadata is not numeric).
- Result: `0.1.0+12` becomes `0.1.0.12`. `0.1.0-12` is a pre-release, the build metadata is empty, so
  it becomes `0.1.0.0`.
- The warning text names `VIProductVersion` as the field this value feeds. The template file itself
  (`installer.nsi`) was not read in this session.

## 2. Updater: when a release counts as an update

Source: `tauri-plugin-updater` 2.14.1, `src/updater.rs`, and `semver` 1.0.28, from the local Cargo
registry (`~/.cargo/registry/src/<index>/`).

- `updater.rs` line 712 to 714: without a custom `version_comparator`, the decision is
  `release.version > self.current_version`.
- `current_version` is `app.package_info().version` (line 228), a `semver::Version`.
- `semver` 1.0.28, `src/lib.rs` line 157: `Version` derives `Ord`, so the comparison runs over
  major, minor, patch, pre-release **and** build metadata. `BuildMetadata` has its own `Ord`
  (`src/impls.rs` line 107): numeric identifiers compare by value.
- The doc comment of `Version::cmp_precedence` (`src/lib.rs` around line 440 to 466) shows the
  difference: `cmp_precedence` ignores build metadata (SemVer precedence), `sort()` (the derived
  `Ord`) orders `1.20.0 < 1.20.0+bc17664 < 1.20.0+c144a98`.
- Conclusion (not measured with a running updater): with the default comparator, `0.1.0+13` would
  be offered as an update over `0.1.0+12`. The SemVer 2.0.0 specification says build metadata must
  be ignored when determining precedence; this crate behavior departs from it.

## Not checked
- Whether `package_info().version` keeps the build metadata of `tauri.conf.json` at run time.
- A real update from one installed build to another.
