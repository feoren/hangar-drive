---
title: Sync prior art and building blocks (research)
type: source
tags: [sync, prior-art, change-detection, chunking, placeholders, storage, transport, windows, backup]
sources: []
raw: raw/2026-11-26-sync-prior-art-research.md
url:
retrieved: 2026-11-26
created: 2026-11-26
updated: 2026-11-26
---

# Sync prior art and building blocks

Research report for [[0001-foundation]]: how existing sync products work, which Rust building
blocks exist, and which platform pitfalls a Windows-first sync client meets. 49 sources, all
retrieved on 2026-11-26. Crypto questions were handed to [[threat-model-and-crypto-design]].

The raw copy differs from the report as delivered: local file paths and line references into
sibling repositories were removed for the public repository, and an author line was added.
The findings and sources are unchanged.

## Key points
- **Prior art** (Syncthing, Seafile, Nextcloud, oCIS, Cryptomator, Tresorit, Proton Drive, Filen,
  Dropbox Nucleus): central servers with a commit history are the only design where the server is
  also a backup; Syncthing's versioning does not even keep local changes.
- **Three lessons:** stable item IDs and three trees (remote, local, synced) with moves as
  first-class operations (Dropbox Nucleus); "E2EE" products fail on metadata and integrity, not
  on the cipher (CCS 2024 study, Nextcloud attacks); a server copy is a backup only if a client
  cannot destroy it.
- **Change detection:** every native API (ReadDirectoryChangesW, FSEvents, inotify) documents lost
  events, so the watcher is only a trigger and a periodic full scan is the truth. `notify` 9.0.0
  is CC0-1.0 (outside the license policy) and needs Rust 1.91; its Linux backend pulls `inotify`
  (ISC).
- **Placeholders / files on demand:** no production-ready Rust crate on any platform, cfapi has
  open OS bugs, the macOS File Provider needs a Swift extension outside Tauri's build. Version 1
  should sync normal folders.
- **Server:** content-addressed encrypted blobs on the filesystem behind a storage trait,
  metadata in SQLite via `sqlx` (same stack as the sister server), idempotent `PUT /blobs/{id}`
  plus `POST /blobs/missing` instead of tus, a monotonic per-folder sequence with delta pulls,
  push of "new head" only via SSE with polling as fallback.
- **Windows pitfalls:** case-only collisions, reserved names (`NUL.txt` included), long paths
  (`longPathAware`), sharing violations, ADS, mtime precision (2 s on FAT), NFC vs NFD between
  Windows and macOS, 8.3 short names in watcher events.
- **Backup protection:** server-side immutable history with retention the client cannot shorten,
  mass-delete prompts on the client (OneDrive 200, Nextcloud 100), a root marker that pauses
  instead of deleting, delayed delete propagation, metadata-based anomaly alerts.

> [!warning] Contradiction
> Chunking: this report proposes FastCDC v2020 with about 1 MiB average chunks for better
> dedup; [[threat-model-and-crypto-design]] recommends fixed 4 MiB chunks because CDC boundaries
> leak content and the keyed CDC of Borg, restic and others was broken (Truong et al. 2025).
> Resolved in [[0001-foundation]] in favour of fixed chunks for version 1.

## Significance for Hangar Drive
- Sets the sync model, server layout, name policy and deletion guards of [[0001-foundation]].
- Owner decisions it raised: the CC0 exception for `notify` and the MSRV; both are decided in the
  ADR.
- Follow-up measurements it proposes: a `notify` spike on Windows (buffer overflow under bulk
  copies, rename pairing).
