# Index

Catalog of all wiki pages. Updated on every ingest.

## Overview
- [[overview]]: state of knowledge, open risks and questions (sources: 7, updated: 2026-11-28)

## Decisions
- [[0001-foundation]]: scope, non-goals, sync model (one head per folder, merge commits, conflict rules, change feed), server, end-to-end encryption, backup, restore and quota rules, name policy and synced file types of version 1, performance under load (sources: 6, updated: 2026-11-28)
- [[0002-version-scheme]]: version scheme X.Y.Z-B of the Hangar family, internal X.Y.Z+B, build number from the commit count, the code carries the upcoming version, changelog and version tests, signed updates, the manual release checklist (sources: 3, updated: 2026-11-27)

## Syntheses
- [[ux-concept]]: UX concept of the desktop app: setup in three steps, pairing, tray states, main window, problems, restore, devices, settings, accessibility and the full UI copy in German and English (sources: 3, updated: 2026-11-27)

## Components
_None yet._

## Sources
- [[llm-wiki-pattern]]: Karpathy's LLM Wiki idea file, the pattern this wiki follows (sources: 0, updated: 2026-11-26)
- [[merge-collision-benchmark]]: own measurement of the merge's and the executor's collision handling before and after the linear time fix (unchanged folders, case variants, joins, new files, up to 262,144 entries) on Windows 11 (sources: 0, updated: 2026-11-26)
- [[recycle-bin-measurement]]: own measurement of `IFileOperation` recycling (plain, verbatim and long paths, a subst drive) and of file IDs through `ReplaceFileW` on Windows 11 (sources: 0, updated: 2026-11-26)
- [[sync-prior-art-research]]: prior art (Syncthing, Seafile, Nextcloud, Dropbox Nucleus and others), `notify`, chunking, placeholders, storage and transport, Windows pitfalls, ransomware protection (sources: 0, updated: 2026-11-26)
- [[tauri-nsis-uninstall-code-reading]]: code reading of the Tauri NSIS template (tauri-cli 2.12.6) on upgrade and uninstall, `/UPDATE`, the "delete app data" box, custom language files, and a makensis harness run of the hook (sources: 0, updated: 2026-11-26)
- [[tauri-version-handling-code-reading]]: code reading of Tauri's NSIS file version and the updater's version comparison with build metadata (sources: 0, updated: 2026-11-26)
- [[threat-model-and-crypto-design]]: threat model per attacker, key hierarchy, object and commit formats, rollback protection, retention, pairing, recovery, reuse options, risks (sources: 0, updated: 2026-11-26)
- [[transfer-responsiveness-measurement]]: own measurement of command latency during hanging uploads, live progress snapshots, parallel against serial downloads and the check of part files on Windows 11, and the Linux run of the sync crate in Docker (sources: 0, updated: 2026-11-28)
- [[unix-inode-reuse-measurement]]: own measurement of inode reuse, birth time and ctime on overlayfs, tmpfs and a 9p bind mount in Docker, and of the replace test with and without the birth time (sources: 0, updated: 2026-11-26)
- [[version-number-wikipedia]]: German Wikipedia "Versionsnummer": major, minor, revision, build number, reset rules, major version 0 (sources: 0, updated: 2026-11-26)
