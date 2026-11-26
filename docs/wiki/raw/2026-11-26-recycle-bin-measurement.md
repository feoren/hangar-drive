# Measurement: recycle bin and ReplaceFileW on Windows (2026-11-26)

Own measurement for the sync engine's handling of incoming deletes (security review M2) and of
replaces (L3). Raw output, unedited apart from the shortened paths.

## Platform

- Windows 11 Pro, `Microsoft Windows NT 10.0.26300.0` (from `[System.Environment]::OSVersion`)
- NTFS volume `E:`, a non-elevated user session
- Rust 1.100.0 (`rust-toolchain.toml`), crate `windows` 0.62.2, `windows-sys` 0.61.2
- Code under test: `crates/hangar-drive-sync/src/trash.rs` (`IFileOperation::DeleteItem` with
  `FOF_NO_UI | FOF_ALLOWUNDO | FOFX_RECYCLEONDELETE | FOFX_EARLYFAILURE` and a progress sink:
  `PreDeleteItem` refuses the item when `TSF_DELETE_RECYCLE_IF_POSSIBLE` is missing,
  `PostDeleteItem` records whether a recycled item was created)

## 1. Recycle bin with plain, verbatim and long paths, and a subst drive

Command (from the repository root, Git Bash):

```
cargo test -p hangar-drive-sync --test localfs measure_ -- --ignored --nocapture
```

The test `measure_recycle_bin_and_replace` (`crates/hangar-drive-sync/tests/localfs.rs`) writes
a small marker file and hands it to `to_recycle_bin`, which converts the `\\?\` root of the
sync folder to its plain form before `SHCreateItemFromParsingName`.

Output with the plain form (the shipped code):

```
root: \\?\E:\...\hangar-drive\tests\.tmp\sync-measure-30080
verbatim short: Ok(()), still there: false
verbatim long (329 chars): Err(NoRecycleBin), still there: true
replace: id before Some(194379966179515138987961496749325391991) after Some(194379966179515138987960652324395260035) same false; mtime after 1700000000000 (asked 1700000000000)
subst drive: Err(NoRecycleBin), still there: true
```

Output of the same test with the conversion removed for one run (the `\\?\` path handed to
`SHCreateItemFromParsingName` as it is), then restored:

```
verbatim short: Err(Failed("Falscher Parameter.")), still there: true
verbatim long (328 chars): Err(Failed("Falscher Parameter.")), still there: true
subst drive: Err(NoRecycleBin), still there: true
```

Results:

- A short path in plain form goes to the recycle bin; `PostDeleteItem` reports the new item.
- The shell's parser refuses every `\\?\` path with `E_INVALIDARG` ("Falscher Parameter.", the
  German message of the session); nothing is deleted.
- A path of 329 characters (beyond `MAX_PATH`) in plain form reaches the shell, but the shell
  does not offer to recycle it: `PreDeleteItem` comes without `TSF_DELETE_RECYCLE_IF_POSSIBLE`,
  the sink refuses, the file stays. Without the sink check the shell would have deleted it for
  good (with `FOF_NO_UI` there is no question).
- A `subst` drive (`subst Q: <folder>`) has no recycle bin: the same refusal, the file stays.
- In every refused case the engine moves the file to `.hangar-drive/trash/<item ID>/` instead
  (test `incoming_deletes_go_to_the_recycle_bin_or_the_quarantine`).

Not measured: removable FAT or exFAT drives and network shares (no such volume in this
session). Whether the shell reports them through the same missing flag is open; if it deletes
without asking the sink, the file is gone, so this needs a measurement before release.

## 2. File IDs through ReplaceFile

Command (PowerShell 7; `System.IO.File.Replace` calls `ReplaceFileW`):

```
$d = "E:\...\hangar-drive\tests\.tmp\replace-measure"; New-Item -ItemType Directory -Force $d | Out-Null
Set-Content "$d\target.txt" "old"; Set-Content "$d\new.txt" "newer"
$t1 = (fsutil file queryFileID "$d\target.txt"); $n1 = (fsutil file queryFileID "$d\new.txt")
[System.IO.File]::Replace("$d\new.txt", "$d\target.txt", "$d\backup.txt")
"target before: $t1"; "new before:    $n1"
"target after:  $(fsutil file queryFileID "$d\target.txt")"
"backup after:  $(fsutil file queryFileID "$d\backup.txt")"
```

Output:

```
target before: Datei-ID: 0x000000000000000000080000000798f9
new before:    Datei-ID: 0x000000000000000000070000000798fb
target after:  Datei-ID: 0x000000000000000000070000000798fb
backup after:  Datei-ID: 0x000000000000000000080000000798f9
```

Results:

- After the replace the target name carries the replacement's file ID; the backup keeps the
  replaced file's ID. The engine therefore compares the backup with the full expectation (size,
  modification time and file ID) and stores the new ID for the target.
- The modification time set on the replacement before the call is the target's afterwards
  (part 1: `mtime after 1700000000000 (asked 1700000000000)`).
