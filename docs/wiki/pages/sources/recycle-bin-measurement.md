---
title: Recycle bin and ReplaceFileW on Windows (measurement)
type: source
tags: [windows, recycle-bin, file-system, long-paths, sync-engine]
sources: []
raw: raw/2026-11-26-recycle-bin-measurement.md
url:
retrieved: 2026-11-26
created: 2026-11-26
updated: 2026-11-26
---

# Recycle bin and ReplaceFileW on Windows (measurement)

Own measurement on Windows 11 Pro 10.0.26300, NTFS, crate `windows` 0.62.2, for incoming deletes
(security review M2) and replaces (L3) of the sync engine.

## Key points

- `IFileOperation::DeleteItem` with `FOFX_RECYCLEONDELETE` recycles a file given by its plain
  path; the progress sink's `PostDeleteItem` reports the item created in the recycle bin.
- `SHCreateItemFromParsingName` refuses every verbatim path (`\\?\C:\...`) with
  `E_INVALIDARG`, short or long. The engine hands the shell the plain form.
- A plain path beyond `MAX_PATH` (329 characters) and a `subst` drive reach the shell, but
  `PreDeleteItem` comes without `TSF_DELETE_RECYCLE_IF_POSSIBLE`: the shell would delete for
  good. Refusing the item there keeps the file; the engine then quarantines it in the sync
  root (`.hangar-drive/trash/<item ID>/`, 30 days).
- `ReplaceFileW`: the target name takes the replacement's file ID; the backup keeps the old
  file's ID. The replacement's modification time survives.
- Not measured: FAT or exFAT removable drives and network shares.

## Significance for Hangar Drive

Answers the open question of [[ux-concept]], section 8.1, for Windows: incoming deletes reach
the recycle bin where Windows has one and the quarantine elsewhere, and never vanish. The
replace keeps a file the person saved at the last moment, because the backup's file ID shows
the change. Code: `crates/hangar-drive-sync/src/trash.rs`, `crates/hangar-drive-sync/src/localfs.rs`.
