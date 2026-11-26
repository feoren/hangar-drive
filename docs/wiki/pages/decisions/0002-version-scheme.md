---
title: "ADR 0002: Version scheme Major.Minor.Revision-Build"
type: decision
status: accepted
superseded_by:
tags: [release, version, updater, windows]
sources: ["[[version-number-wikipedia]]", "[[tauri-version-handling-code-reading]]"]
created: 2026-11-26
updated: 2026-11-26
---

# ADR 0002: Version scheme

## Context
Hangar Drive belongs to the Hangar family, and the family uses one version scheme: `N.N.N-NNNN`,
for example `0.12.224-1548`. Following [[version-number-wikipedia]], the parts are the major
version, the minor version, the revision and a build number that is never reset; with version
control, a number that identifies the source state is a common choice for the build number.

Technical constraints:
- Tauri, Cargo and npm read the version as SemVer. In SemVer, `0.1.0-12` is a pre-release that
  sorts before `0.1.0`, and `0.1.0+12` carries `12` as build metadata.
- Tauri's NSIS bundler turns numeric build metadata into the four-part Windows file version:
  `0.1.0+12` becomes `0.1.0.12`, while `0.1.0-12` becomes `0.1.0.0`
  ([[tauri-version-handling-code-reading]]).
- A `+` is awkward in download URLs: in query strings and form data it stands for a space.
- The repository starts with its own history; there is no earlier history whose commits would have
  to be counted.

## Options
Not recorded separately; the constraints leave the split into an internal and a displayed form,
the same choice the sister desktop app made in its own ADR 0002.

## Decision
- **Meaning of the parts:** X for fundamental or incompatible changes (while X is 0, Y may also
  jump further), Y for new features, Z for bug fixes ([[version-number-wikipedia]]).
- **Internally** (`tauri.conf.json`, `Cargo.toml`, `package.json`, later `latest.json`): `X.Y.Z+B`,
  for example `0.1.0+12`. All packages of the Cargo workspace (app, crates, server) carry the same
  version as the app.
- **Displayed and in file names:** `X.Y.Z-B`, for example `0.1.0-12`, because a `+` breaks download
  URLs. NSIS makes the Windows file version `X.Y.Z.B` from the internal `+B`.
- **Build number B** = `buildNumberBase` from `package.json` plus the number of commits in the built
  state (`git rev-list --count HEAD`). It grows with every commit and is never reset. Hangar Drive
  has no earlier history, so `buildNumberBase` is `0`. The commit of build `B` is
  `git rev-list --reverse HEAD | sed -n <B minus base>p` on `main`.
- **Every release raises X, Y or Z.** Two releases must never differ only in their build number:
  SemVer precedence ignores build metadata, so tools that follow it treat them as the same version.
- **The code always carries the upcoming version.** `tauri.conf.json`, `package.json` and the
  `Cargo.toml` files state the version that will be released next, not the last published one. It is
  also the highest entry in `src/changelog.json`, with texts in all 12 UI languages and
  `"date": null` until the release. Right after a release the next version is set. Reason: the
  sister app once showed the last release in the window while What's New already collected changes
  under the next version.
- **Push once at the end** of a release, after the owner's yes.

> [!warning] Contradiction
> The sister app's ADR 0002 first stated that the Tauri updater ignores build metadata when
> comparing and gave that as the reason for "every release raises X, Y or Z"; it corrected that
> reason on 2026-11-26. The code reading of
> `tauri-plugin-updater` 2.14.1 with `semver` 1.0.28 shows the opposite for the default comparator:
> `release.version > current_version` uses the derived `Ord` of `semver::Version`, which compares
> build metadata ([[tauri-version-handling-code-reading]]). The rule stays, with the reason above;
> it does not depend on which of the two is right. A real update between two builds of one version
> was not tried.

> [!question] Unverified
> "SemVer precedence ignores build metadata" is taken from the SemVer 2.0.0 specification as cited by
> the `semver` crate's `cmp_precedence` documentation; the specification itself is not filed as a
> source here yet.

## Consequences
- `src/version.ts` reads and formats versions: `formatVersion` shows `X.Y.Z+B` as `X.Y.Z-B`,
  `withBuild` adds the build number of a development build. `vite.config.ts` injects that number as
  `__HANGAR_DRIVE_BUILD__` (`src/buildInfo.ts`); the settings dialog shows `Version X.Y.Z-B`.
- `src/versionSync.test.ts` (Vitest) requires the same version in `package.json`,
  `src-tauri/tauri.conf.json` and every member of the Cargo workspace, requires it to be the highest
  entry in `src/changelog.json` and requires every changelog item in all 12 UI languages. The Rust
  test in `src-tauri/src/lib.rs` checks the crate version against `tauri.conf.json`, `package.json`
  and the highest changelog entry, and that it follows `X.Y.Z` or `X.Y.Z+B`.
- **Follow-up: release script.** A later `tools/release.py`, modeled on the sister app's, sets
  `X.Y.Z+B` in all files, builds only from a clean working tree (so that B really identifies the
  source state) and refuses a version that is not above the last release (highest dated changelog
  entry or published release). After the release it sets the next version and adds an undated, empty
  changelog entry. Until the script exists, these steps are manual.
- The Windows installer's file version carries the build number only if the internal form uses `+`.

## Signed updates (amendment 2026-11-26, app shell security review)

The app updates itself only through `tauri-plugin-updater`, which installs an update only when its
minisign signature verifies against the public key in `src-tauri/tauri.conf.json`. Until the owner
puts that key and an endpoint there, the plugin is not registered and the command `install_update`
answers "updates are off" (`src-tauri/src/updater.rs`); no key is in the repository.

**Making the key (owner, once, on the release machine):**

1. `pnpm tauri signer generate -w "%USERPROFILE%\.tauri\hangar-drive.key"`, with a strong
   password. The private key stays in `%USERPROFILE%\.tauri\hangar-drive.key`: never in the
   repository, never in a synced or cloud folder (OneDrive, Dropbox, the Hangar Drive folders),
   backed up offline (for example on a USB stick in a safe). A lost key means no update can reach
   the installed apps any more; a leaked key means anyone can ship one.
2. Put the public key (`hangar-drive.key.pub`, one line) into `tauri.conf.json`:

   ```json
   "plugins": {
     "updater": {
       "pubkey": "<content of hangar-drive.key.pub>",
       "endpoints": ["https://<download host>/hangar-drive/latest.json"],
       "windows": { "installMode": "passive" }
     }
   }
   ```

   and `"createUpdaterArtifacts": true` under `bundle`. The endpoint comes from the release
   setup, never an internal host in the public repository.
3. At release time the build reads the key from the environment only:
   `TAURI_SIGNING_PRIVATE_KEY` (the path or the content) and
   `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, set in the release shell, never in a file of the
   repository or in `.env`.

> [!note] Checked 2026-11-26 against the installed CLI (tauri-cli 2.12.6)
> `pnpm tauri signer generate --help` lists `-w, --write-keys`; the CLI's changelog documents
> `TAURI_SIGNING_PRIVATE_KEY` (a path or the key itself for `build`) and
> `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. Check again after a major CLI update.

**Authenticode (installer signature, owner):** the updater's signature protects updates, not the
first download. The NSIS installer and the app's `.exe` should carry an Authenticode signature too,
so SmartScreen and the person can tell them from a copy:

- a code signing certificate (OV or EV) kept on a hardware token or in a cloud HSM, never as a
  `.pfx` in the repository or in a synced folder;
- `bundle.windows.signCommand` in `tauri.conf.json` calling `signtool sign /fd sha256 /tr
  <RFC 3161 timestamp URL> /td sha256 ...` (or the HSM vendor's tool), so the bundler signs the
  `.exe` and the installer; the timestamp keeps the signature valid after the certificate expires.

Neither key nor certificate exists yet; both are the owner's step before the first public release.

## Evidence
- [[version-number-wikipedia]], [[tauri-version-handling-code-reading]].
- Code: `src/version.ts`, `src/buildInfo.ts`, `vite.config.ts`, `src/changelog.json`; tests
  `src/versionSync.test.ts`, `src/version.test.ts`, `src-tauri/src/lib.rs`.
