# Sync prior art and building blocks for Hangar Drive (research for ADR 0001)

- Date: 2026-11-26 (all sources retrieved on this date unless noted)
- Author: research agent (hangar-researcher), read only
- Scope: prior art, change detection, chunking/hashing, placeholders, server storage and transport, Windows pitfalls, backup and ransomware protection
- Out of scope: evaluation of the cryptography (separate review). Where sync design touches crypto, it is listed as a hand-off item.
- Project state checked: `Cargo.toml` (workspace, `rust-version = "1.89"`, license MIT), `server/Cargo.toml` (axum 0.8.9 with `http1`, `tokio`, `json` only), `Cargo.lock` (axum 0.8.9, tokio 1.54.1, hyper 1.13.0, tauri 2.12.7). The sister server project uses `sqlx` 0.9 with `sqlite-bundled` and `migrate`.
- Convention: `[UNVERIFIED]` = not confirmed in a primary source during this research.

## 1. Prior art

### 1.1 Comparison table

| Solution | Sync model | Change detection | Chunking / dedup | Conflicts | Versions / trash | What the server sees | License |
|---|---|---|---|---|---|---|---|
| Syncthing 2.1 | Peer to peer (cluster of devices, optional relays) | Filesystem watcher plus full rescan, default every 1 h (randomized 3/4 to 5/4); watcher batches 10 s, deletes delayed a further 60 s; rehash if mtime, size or permissions change [S1] | Fixed-size blocks, power of two, 128 KiB to 16 MiB, chosen so a file has < 2000 blocks; SHA-256 per block; block reuse locally and across peers [S1][S2] | Version vectors per file [S2]. On conflict the older mtime loses and is renamed `<name>.sync-conflict-<date>-<time>-<device>.<ext>`; delete vs. modify keeps the modified file as a conflict copy [S1] | Off by default; trash can, simple, staggered, external. **Only protects changes received from other devices, not local changes** [S3] | No server. Untrusted ("Receive Encrypted") devices see folder ID/label and approximate sizes; names, metadata and structure encrypted; marked beta [S4] | MPL-2.0 [S30] |
| Seafile 13 | Central server, Git-like (repo, commit, fs objects, blocks) | Client side [UNVERIFIED in detail]; server push via optional notification server (WebSocket, separate Docker image since 12.0), otherwise polling [S6][S7] | Content-defined chunking (LBFS style), average about 8 MB; content-addressed blocks deduplicated across versions [S6] | [UNVERIFIED in primary docs] conflict copies on the client | Every upload is a commit (snapshot); per-library history: keep all, none, or N days (`[history] keep_days`); trash per library, then `seaf-gc` [S8] | In encrypted libraries: **names, directory structure, sizes, editors, timestamps and changed byte ranges are plaintext**; no integrity protection. Before server 12, PBKDF2 with only 1000 iterations; web, mobile and web-created libraries decrypt on the server [S5]. ETH study (CCS 2024): file-name and metadata tampering, folder injection, unauthenticated chunking, protocol downgrade (the downgrade has been fixed) [S9] | Server AGPL-3.0, client GPL-2.0 (each with an OpenSSL exception) [S31] |
| Nextcloud (desktop client and E2EE) | Central server (WebDAV) | Per-directory ETag/ID (random, not a content hash), unchanged subtrees are skipped; local mtime comparison; `remotePollInterval` 30 s, `fullLocalDiscoveryInterval` 1 h [S10][S11] | No dedup (whole files; chunked upload only for transport) [UNVERIFIED] | Local copy renamed with a conflict marker and timestamp; conflict files are only created on the client [S10] | Versions thinned (1/2 s, then 10 s, 1 min, 1 h, 1 day, 1 week), at most 50 % of free quota [S12]; trash bin | E2EE only for empty folders, enabled from a client app [S13]. "Share with Care" (Euro S&P 2024): three practical attacks by a malicious server on confidentiality and integrity [S14] | Server AGPL-3.0 [UNVERIFIED], desktop GPL-2.0 [S30] |
| ownCloud Infinite Scale / OpenCloud | Central server (Go, "spaces") | [UNVERIFIED] | Uploads through **tus**; decomposedfs (POSIX) or S3 with POSIX metadata [S15] | [UNVERIFIED] | Versions; one trash bin per space with `purge-expired` [S15] | No built-in E2EE [UNVERIFIED]; server sees everything | Apache-2.0 (both repos) [S30] |
| Cryptomator | Not a sync engine: encrypted vault on top of any sync tool | Delegated to the host sync client | 32 KiB encryption chunks (AES-GCM, chunk number and header nonce in the AAD), no dedup [S16] | Delegated; leaves room in names for conflict suffixes of sync clients [S16] | Delegated | Names (AES-SIV with the parent dir ID as AD) and hierarchy hidden (flattened `d/XX/...`); node count, node types and approximate sizes are probably visible [S16] | GPL-3.0 [S30] |
| Tresorit | Central server, E2EE | [UNVERIFIED] | [UNVERIFIED] | Creates "conflict" copies; offers editing badges as a lock hint [S17] | Automatic version history, 10 versions (Personal) up to unlimited (Business Pro) [S17] | Contents and "relevant metadata" encrypted; the only provider in the ETH study that binds names and locations to content [S9][S17]; quota accounting needs sizes [S17] | Proprietary |
| Proton Drive | Central server, E2EE | [UNVERIFIED] | Blocks of at most 4 MB per file; block hashes chained and signed by the uploader [S18] | [UNVERIFIED] | [UNVERIFIED] | Names encrypted with the parent node key; per-node keys; metadata such as size, times and parent link exists, but the post does not say which fields are readable [S18] | Server proprietary; Windows client GPL-3.0, SDK MIT [S30] |
| Filen | Central server, E2EE | [UNVERIFIED] | Files split into chunks, each encrypted with AES-256 [S19]; chunk size [UNVERIFIED] | [UNVERIFIED] | [UNVERIFIED] | Contents encrypted; metadata details [UNVERIFIED]; backend closed (secondary source) [S19] | Clients and sync engine AGPL-3.0 [S30] |
| Dropbox (Nucleus) | Central server, no default E2EE | Three trees: remote, local, synced (merge base); planner drives them to agreement [S21] | Fixed 4 MiB blocks, SHA-256 content hash [S22] | [Not covered by the blog posts] | Version history; Rewind of a whole account or folder (paid plans); ransomware and mass-deletion alerts for teams [S23] | Everything (plaintext service) | Proprietary |

Notes on Nucleus (2020) [S20][S21]: written in Rust. Globally unique IDs persist across moves, and moves are atomic. Classic stored a move as delete plus add, so a transient failure lost files on other devices. A single deterministic control thread does the planning; hashing runs in a thread pool, file I/O on a dedicated thread. Randomized deterministic testing (CanopyCheck for the planner, Trinity for concurrency with mocked FS, network and time) checks termination, absence of panics, convergence of all three trees and absence of data loss. Tens of millions of seeded runs every night.

### 1.2 The three most important lessons for Hangar Drive

1. **Data model first: stable IDs and three trees.** Path-based identity and "move = delete + add" caused Dropbox's worst bugs; Nucleus fixed it with persistent IDs and a remote/local/synced model plus a deterministic planner that can be tested by simulation [S20][S21]. That is the cheapest time to decide it: before any sync code exists.
2. **"E2EE" claims fail on metadata and integrity, not on the cipher.** Seafile encrypts contents but leaks names, structure and sizes and does not protect integrity [S5]. The ETH study found name and metadata tampering, injection and unauthenticated chunking in 4 of 5 providers. Only Tresorit binds name and location to content [S9]. Nextcloud's E2EE was broken by a malicious server [S14]. The sync design must give the crypto layer a place to authenticate the *whole* tree state (names, parent links, chunk lists, ordering), not just the blocks. (Hand-off to the crypto review.)
3. **The server copy is only a backup if a client cannot destroy it.** Syncthing versioning ignores local changes [S3]; that is a blind spot by design. Dropbox, OneDrive and Seafile all rely on server-side history plus a point-in-time rollback [S8][S23][S24], and OneDrive and Nextcloud add a client-side mass-deletion prompt [S25][S11]. Server-side immutable history with retention that the sync credential cannot shorten is the core of the "backup" promise.

## 2. Change detection

### 2.1 `notify` crate (crates.io API, 2026-11-26)

- `notify` **9.0.0** (released 2026-11-21, MSRV **1.91**), 8.2.2 (2026-11-08, MSRV 1.88). License **CC0-1.0** for every listed version; according to the changelog CC0 applies since 6.1.0 [S26][S27].
- Sub-crates: `notify-types` 2.3.1, `notify-debouncer-full` 0.8.0, `notify-debouncer-mini` 0.8.0, `file-id` 0.2.3, all MIT OR Apache-2.0.
- Backends from `notify/Cargo.toml`: Windows `windows-sys` (MIT/Apache-2.0); Linux `inotify` 0.11.5 (**ISC**) and `mio`; macOS FSEvents via `objc2-core-services` (Zlib/Apache-2.0/MIT) or `kqueue` (MIT); polling via `walkdir` (Unlicense/MIT).
- **License impact:** CC0-1.0 (and ISC for `inotify` on Linux) fall outside the MIT/Apache-2.0/BSD policy. The sister desktop app documents CC0 as an exception for `notify` 8.2. Hangar Drive would need the same exception, plus one for ISC once Linux ships, or its own thin watcher on `windows-sys`, `objc2-core-services` and raw inotify via `libc`.
- **MSRV impact:** 9.0.0 requires Rust 1.91; the workspace declares 1.89. Either raise the MSRV or pin 8.2.x.
- 9.0 changes relevant to us [S27]: Windows buffers grew from 16 KiB to 64 KiB per watch; a **rescan event** is emitted when ReadDirectoryChangesW discards details or on malformed notifications; FSEvents reports root/ancestor renames as "root changed" and filters events from before registration when the stream is rebuilt; inotify reports renames as `MODIFY_NAME`.

### 2.2 Platform behaviour and pitfalls

**Windows, ReadDirectoryChangesW** [S28] (page updated 2025-07-01):
- When the internal buffer overflows, the call still succeeds but returns 0 bytes and the buffered changes are lost. `ERROR_NOTIFY_ENUM_DIR` also means that not all changes were recorded. In both cases you must enumerate the directory.
- Over the network the buffer may not exceed 64 KB (`ERROR_INVALID_PARAMETER`); redirectors that do not support the call fail with `ERROR_INVALID_FUNCTION`.
- Notifications may arrive under the 8.3 short name if the directory was opened by it. Changes to the watched directory itself are not reported.
- Size and last-write changes are only seen once the cache flushes to disk.
- `notify` docs: Windows may emit no event for a directory rename, and the watch survives a rename/delete of the watched path [S26].

**macOS, FSEvents** [S29] (Apple guide, 2012-12-13, archived):
- Events in a directory and its subdirectories are coalesced into one event with `MustScanSubDirs`, which requires a recursive rescan of that path.
- `UserDropped` or `KernelDropped` require a full scan of all watched directories.
- `RootChanged` requires a rescan of the root.
- The event history is advisory (older OS versions can modify the disk), so Apple recommends periodic full sweeps for backup software and starting the watch before the initial scan.

From the `notify` docs [S26]: FSEvents may hide events for files the user does not own. The number of roots per process is capped at roughly `RLIMIT_NOFILE / 12`. `std::fs::copy` on APFS creates a metadata event on the source.

**Linux, inotify** [S32] (man-pages 6.19, 2026-02-14):
- Not recursive: one watch per directory. Files can appear in a new directory before its watch exists, so scan right after adding the watch.
- Queue overflow produces `IN_Q_OVERFLOW` (events lost, rebuild caches).
- `IN_MOVED_FROM`/`IN_MOVED_TO` share a cookie but are not guaranteed to be adjacent; pairing is racy and needs a timeout. Moves in from outside produce only one half.
- Changes on network filesystems and changes made via `mmap` are not reported.
- Limits: `max_user_watches`, `max_user_instances`, `max_queued_events`.
  - Syncthing documents 8192 as the usual limit [S33].
  - A 2020 kernel patch series scales the default to about 1 % of RAM, clamped between 8192 and 1048576 [S34]. The merge into 5.11 is [UNVERIFIED].
  - The `notify` docs say that the Linux backend is not fully reliable for very large trees [S26].

**Network drives, WSL, containers** [S26]:
- NFS and similar mounts may produce no events.
- Changes from Windows to `/mnt/c` in WSL2 may not produce inotify events.
- Docker under emulation fails with "os error 38".
- For all of these, `PollWatcher` (default interval 30 s, optional content hashing) is the fallback.

### 2.3 Why a periodic scan is still needed

Every native API can lose events and says so in its own documentation: RDCW overflow and `ERROR_NOTIFY_ENUM_DIR`, FSEvents `MustScanSubDirs` and the dropped flags, inotify `IN_Q_OVERFLOW` and the non-atomic pairing of rename halves. There are further gaps:
- no events while the app is not running;
- no events from network filesystems;
- events hidden by permissions;
- watch limits.

Syncthing keeps an hourly full scan even with the watcher on, for exactly this reason [S1]. Nextcloud does a full local discovery every hour [S11]. Apple recommends periodic sweeps [S29]. Pattern: **watcher = trigger, scan = truth.** A scan compares (size, mtime, file ID or inode) against a local index and rehashes only on a mismatch, like Syncthing [S1].

## 3. Chunking and hashing

- **`fastcdc` 5.0.0** (2026-08-22, MIT) [S35][S30]:
  - Modules `v2016`, `v2020` (recommended, 64-bit gear hash, faster, same cut points as v2016) and `ronomon` (the only one whose cut points match earlier releases).
  - `FastCDC` (slice/mmap), `StreamCDC` (`Read`) and `AsyncStreamCDC` (async; feature name [UNVERIFIED]).
  - Normalization level 1 by default, configurable.
  - The docs warn that changing the minimum size almost certainly changes cut points. Treat min/avg/max and the level as **frozen protocol parameters**.
  - Note: 4.0.0 (2026-04) and 5.0.0 (2026-08) were major releases within five months. Pin the exact version and add a golden test of cut points.
- **`blake3` 1.8.7** (2026-08-20), license `CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception`. Usable under Apache-2.0, so it fits the policy. Keyed hashing and key derivation exist in the crate API [UNVERIFIED in this session; see the crate docs].
- **Typical sizes in practice:**

  | System | Chunking | Size |
  |---|---|---|
  | Syncthing | fixed | 128 KiB to 16 MiB [S2] |
  | Dropbox | fixed | 4 MiB [S22] |
  | Proton | fixed | at most 4 MB [S18] |
  | Seafile | CDC | about 8 MB average [S6] |
  | Cryptomator | encryption frames only | 32 KiB [S16] |
  | fastcdc examples | CDC | 4 to 64 KiB (backup style) [S35] |
  | restic | CDC | 512 KiB min, 1 MiB average, 8 MiB max [UNVERIFIED] |

  Assessment: for a sync product with a per-chunk request and metadata cost, an average of about 1 MiB (min 256 KiB, max 4 MiB) is a reasonable middle ground. Many more blobs than with fixed 4 MiB blocks, but insert/shift-resistant dedup for large files that are edited in the middle.
- **Hand-off to the crypto review (not evaluated here):** chunk IDs must not be a plain hash of plaintext (that allows a confirmation-of-file attack); dedup should be scoped to one key domain; CDC chunk-length sequences can fingerprint known files [UNVERIFIED]; the ETH study shows chunk order and completeness must be authenticated [S9]. Syncthing's encrypted mode gives up cross-file block reuse for this reason [S4].

## 4. Placeholders / files on demand

| Platform | API | Effort | Rust crates (2026-11-26) |
|---|---|---|---|
| Windows | Cloud Files API (cfapi) since Windows 10 1709; minifilter `cldflt.sys`, **NTFS only**; placeholder, full and pinned states; hydration policies; sync root registration through WinRT `Windows.Storage.Provider`; Microsoft says sync engines "are designed to use the Desktop Bridge" (packaging) [S36] | High: callbacks for fetch data/placeholders, dehydration, shell integration, interaction with AV filters, reparse point compatibility. The provider must still implement all sync and merge logic itself [S36] | `cloud-filter` 0.0.7 (MIT; fork of `wincs`, which is 0.1.1 Apache-2.0). README: "Experimental", "not production-ready"; documents Windows bugs (batch placeholder creation corrupts metadata, error 363; Shell delete leaves empty directories) with no fix schedule from Microsoft [S37]. 8 stars, about 32k downloads |
| macOS | File Provider (`NSFileProviderReplicatedExtension`): runs as a separate **app extension** process; system-driven enumerators, working set, sync anchors, `fetchContents`, `createItem`, `modifyItem`, `deleteItem`; blocking read on dataless files until the extension delivers [S38] | Very high for Tauri: needs a Swift/ObjC extension target in the bundle, App Group, signing and notarization, FFI into the Rust core. No Tauri precedent found. Nextcloud ships one and notes that classic folder sync and File Provider Finder integration cannot run side by side [S38]. Minimum macOS for the replicated API [UNVERIFIED] (Apple page did not render; believed macOS 11+) | `objc2-file-provider` 0.3.2 (Zlib/Apache-2.0/MIT): raw bindings only, no framework |
| Linux | FUSE | Medium (a virtual FS), but it is a mount, not files in a normal folder; desktop integration differs per DE | `fuser` 0.19.0 (MIT, active, about 7M downloads). On macOS FUSE needs macFUSE (kext, lowers security on Apple silicon; FSKit backend since 5.0 on macOS 26) or FUSE-T (NFS bridge) [S39]; macFUSE license [UNVERIFIED] |

**Recommendation:** Version 1 uses **normal folder sync** (full copies, selective sync per folder at most). Reasons:
- no mature Rust crate on any platform;
- three completely different APIs, one of them (File Provider) outside Rust/Tauri's build model;
- cfapi still has unfixed OS bugs [S37];
- placeholders multiply the states the sync engine must handle.

Keep the door open: stable item IDs, an explicit per-item local state enum (absent, present, later "placeholder") and a server API that can serve single files by ID.

## 5. Server storage and transport

### 5.1 Storage

- **Blobs:** content-addressed, immutable, encrypted objects. The local filesystem with a fan-out directory layout (like Seafile's block store and Cryptomator's `d/XX/`) is enough for V1. `object_store` 0.14.2 (MIT/Apache-2.0, Apache Arrow project, about 116M downloads) offers local FS, S3, GCS and Azure behind one trait. `opendal` 0.59.5 (Apache-2.0) is the broader alternative. oCIS shows the split "blobs on S3, metadata on POSIX" [S15] and warns that a hard kill can leave decomposedfs metadata inconsistent. Metadata belongs in a transactional database.
- **Metadata:** SQLite in WAL mode.
  - `sqlx` 0.9.1 (MIT/Apache-2.0, async, migrations, compile-time checked queries).
  - `rusqlite` 0.43.0 (MIT, synchronous, needs `spawn_blocking`).
  - `libsqlite3-sys` 0.40.0 (MIT) underneath both.
  - Recommendation: **`sqlx` with `sqlite-bundled` and `migrate`**, the same as the sister server project. One stack, shared know-how.
- **GC:** blobs referenced by no retained version are deleted by a mark-and-sweep job (Seafile `seaf-gc` [S8]). Forum reports say expired history is not always reclaimed; test the GC explicitly.

### 5.2 Uploads

- **tus 1.0.0** (2016-03-25, MIT spec) [S40]: HEAD returns `Upload-Offset`; `PATCH` with `application/offset+octet-stream`; extensions creation, creation-with-upload, expiration, checksum, termination, concatenation. Used by oCIS [S15]. The Rust ecosystem is thin: `tus_async_client` 0.2.1, last release 2022.
- **IETF "Resumable Uploads for HTTP"** (`draft-ietf-httpbis-resumable-upload`): revision **-16**, updated 2026-11-23, state "WG Document", **not an RFC** [S41].
- **Assessment:** with content-addressed chunks of about 1 MiB, tus is unnecessary. Upload = idempotent `PUT /blobs/{id}` plus batch `POST /blobs/missing` (which IDs does the server lack). An aborted file upload resumes at chunk granularity for free. The version commit is a separate atomic metadata call that references chunk IDs (compare-and-swap on the parent version). Revisit tus or the IETF draft only if single chunks become large.
- **HTTP/2:** axum 0.8.9 has an `http2` feature (hyper) that the server does not enable yet. Behind a TLS reverse proxy, HTTP/2 is mostly a matter of the proxy; multiplexing helps many small chunk requests.

### 5.3 Push to clients

- axum: WebSocket needs the `ws` feature (pulls `tokio-tungstenite` 0.30.0, MIT); SSE (`axum::response::sse`) is not feature-gated in 0.8.9 (docs.rs, crates.io feature list).
- **Recommendation:** push only a "library L has a new head sequence N" message. Clients then pull deltas over plain HTTP from their last cursor. SSE fits that one-way pattern and survives proxies more easily; WebSocket is needed only if the channel later carries client-to-server traffic. Keep polling (for example 60 s) as a fallback, as Seafile does when the notification server is not reachable [S7].

### 5.4 How Syncthing and Seafile distribute changes

- **Syncthing** [S2]: every device connects to every peer over TLS 1.3 (direct or via relays). After `ClusterConfig` each side sends a full `Index`, then `IndexUpdate`s. A per-folder sequence number plus a random index ID allow delta exchange ("send me everything after sequence N"). Peers then `Request` missing blocks from any peer that has them. Fan-out is n to n, with no central copy and no backup role.
- **Seafile** [S6][S7]: a central server keeps the commit DAG. Clients poll, or since 8.0.11/SeaDrive 3.0.1 receive WebSocket notifications from the separate notification server (port 8083 by default, its own image since 12.0), then fetch the new commits and missing blocks. Real-world reports name reverse-proxy WebSocket upgrades as a common failure [S7].
- **Takeaway:** a monotonic per-library sequence/cursor (Syncthing) on a central commit log (Seafile), plus a thin notification channel.

## 6. Windows pitfalls during sync

| Topic | Fact (source) | Consequence for the sync engine |
|---|---|---|
| Case | Windows treats names as case-insensitive; per-directory case sensitivity exists since build 17107, is inherited by new subdirectories and is mostly used with WSL [S42][S43] | Detect case-only collisions (`a.txt` vs `A.txt` from Linux) and turn them into conflicts, like Syncthing's default `caseSensitiveFS=false` safety checks (since 1.9.0) [S44]; treat case-only renames as renames |
| Reserved names | CON, PRN, AUX, NUL, COM1 to COM9, LPT1 to LPT9 and the superscript forms COM¹ to COM³ and LPT¹ to LPT³, **also with any extension** (`NUL.txt`); characters `< > : " / \ \| ? *` and 0 to 31; no trailing space or period [S42] | Validate names from macOS/Linux before writing on Windows; mark the item as "cannot sync on this device" instead of renaming it silently |
| Long paths | MAX_PATH 260; opt-in since 1607 needs **both** the `LongPathsEnabled` registry value and `longPathAware` in the manifest; `\\?\` gives about 32,767 chars, components usually 255 [S45] | Add `longPathAware` to the Tauri app manifest or always use `\\?\` paths; whether Rust `std` adds `\\?\` automatically is [UNVERIFIED]; Explorer may still fail on such paths |
| Locked files | Sharing modes are per stream; delete access needs all open streams to allow it [S46] | Expect sharing violations (Office, AV, indexer): retry with backoff, read with permissive share flags, never block the whole run [UNVERIFIED detailed strategy]. Write downloads to a temp file and rename atomically, like Syncthing (`~syncthing~<name>.tmp`) [S1] |
| NTFS streams | Named data streams `file:stream:$DATA`; no own timestamps; enumerable via `FindFirstStreamW` [S46] | Do not sync ADS in V1 (Zone.Identifier and similar are device-local); document it as a non-goal |
| Timestamps | FILETIME 100 ns; NTFS stores UTC; FAT: write time 2 s, create time 10 ms, access 1 day, stored in local time; the last-write time is final only when all write handles are closed; NTFS delays last-access updates by up to 1 h [S47] | Never use mtime alone as proof of change; compare with a tolerance (2 s on FAT/exFAT volumes) and confirm by hash; ignore atime |
| Unicode | Windows treats names as opaque WCHAR sequences and does no normalization [S45]. APFS preserves the normalization form but is normalization-insensitive (since High Sierra); HFS+ stored the normalized form (NFD) [S48] | Canonicalize names to **NFC** in the protocol, the same choice as Cryptomator [S16]; detect two names that differ only in normalization as a collision. `unicode-normalization` 0.1.26 is `(MIT OR Apache-2.0) AND Unicode-3.0`, a small additional license item |
| Short names | RDCW may report 8.3 names [S28]; 8.3 aliases may or may not exist [S42] | Resolve to long names (`GetLongPathNameW`) before path matching |
| cfapi coexistence | cfapi placeholders are reparse points hidden from most apps [S36] | Watch for OneDrive-managed folders inside a sync root; do not sync from inside another provider's sync root [UNVERIFIED as a rule; assessment] |

## 7. Backup view: protection against ransomware and deletion waves

| Measure | Example (source) |
|---|---|
| Server-side point-in-time rollback | Dropbox Rewind for an account or folder (paid plans) [S23]; OneDrive restores up to 30 days [S24]; Seafile restores a library to any snapshot within `keep_days` [S8] |
| Immutable history with retention | Seafile commits are content-addressed snapshots [S6]; Nextcloud thins versions over time and caps them at 50 % of free quota (which means versions can disappear under quota pressure) [S12] |
| Client-side mass-delete prompt | OneDrive: prompt above 200 local deletions by default, enforceable via the `LocalMassDeleteFileDeleteThreshold` policy (Microsoft message MC888872, 2024-09) [S25]; Nextcloud: `promptDeleteAllFiles` and `deleteFilesThreshold` (default 100, GUI syncs only) [S11] |
| "Folder missing" guard | Syncthing pauses a folder when the `.stfolder` marker is gone (for example an unmounted drive) instead of propagating mass deletions [S33] |
| Delayed delete propagation | Syncthing's watcher delays deletions by an extra 60 s [S1] |
| Server-side anomaly detection | Dropbox ransomware detection and mass deletion / mass move alerts with one-click restore (team plans) [S23] |
| Append-only credentials | restic `rest-server --append-only`: clients can add but not delete or modify; protects against a compromised client, not against root on the server; S3 Object Lock (compliance mode) as the stronger option (secondary sources) [S49] |
| Anti-pattern | Syncthing versioning does not keep local changes [S3]: a device encrypted by ransomware propagates new contents, and only the receivers' versioning helps |

E2EE adds one constraint: the server cannot inspect contents for entropy-based ransomware detection, so it can only use **metadata signals** (rate of modifications/deletions per device, mass renames, size churn). Whatever the server sees for that purpose is a privacy trade-off for the crypto review.

## 8. Recommendation for version 1

1. **Central server, star topology, no P2P.** The product promise includes "server keeps versions as backup"; a central commit log gives one order of events and an always-available copy. Syncthing shows that P2P has no backup role [S2][S3].
2. **Normal folder sync, no placeholders in V1.** No production-ready Rust crate exists; cfapi has open OS bugs; File Provider needs a Swift extension outside Tauri's build [S36][S37][S38]. Reserve item states and an "open file by ID" API for later.
3. **Nucleus-style data model: stable item IDs, remote/local/synced trees, moves as first-class operations.** It avoids the "move = delete + add" data-loss class that Dropbox fixed with a rewrite [S20][S21].
4. **Deterministic sync core with seeded simulation tests from day one.** Single control loop, I/O behind traits (FS, network, clock), invariants: convergence, termination, no data loss [S21]. It fits the project's "explicit state types" rule.
5. **Change detection: `notify` as a trigger, periodic full scan as the truth.** Hourly scan plus an immediate rescan on overflow/rescan events; local SQLite index with (size, mtime, file ID) [S1][S26][S27][S29][S32]. Needs a documented CC0 exception and either MSRV 1.91 for 9.0 or a pin on 8.2.x.
6. **Server-side commit log with a monotonic sequence per library; clients pull deltas from their cursor.** The Syncthing delta-index idea on Seafile's central commit DAG [S2][S6]. Simple to reason about, easy to replay after offline periods.
7. **Push via SSE (or WebSocket) that carries only "new head", with polling as a fallback.** Lowest coupling; axum supports SSE without extra features, WebSocket needs `ws`. Seafile shows that proxies break upgrades [S7].
8. **Transfer as content-addressed chunks: `PUT /blobs/{id}`, `POST /blobs/missing`, atomic commit with compare-and-swap on the parent version.** Resumption comes for free at chunk granularity; tus is not needed, and the IETF draft is still a draft (-16) [S40][S41].
9. **FastCDC `v2020` with frozen parameters (proposal: min 256 KiB / avg 1 MiB / max 4 MiB), `blake3` for hashing, exact version pin plus a golden cut-point test.** Cut points change with parameters and possibly with major releases [S35]. Chunk-ID keying, dedup scope and metadata authentication go to the crypto review [S9].
10. **Storage: encrypted blobs on the local filesystem behind a storage trait (`object_store` later for S3); metadata in SQLite via `sqlx`.** One DB stack across the Hangar servers; oCIS shows why metadata needs transactions [S15].
11. **Conflicts are never merged: keep both, the loser becomes `<name> (conflict <device> <timestamp>).<ext>`; modify beats delete.** This is what Syncthing, Nextcloud and Tresorit do [S1][S10][S17]; with E2EE the server cannot merge anyway.
12. **Server history is immutable for sync clients: versions and trash with server-enforced retention (proposal: trash 30 days, staggered versions, a minimum retention the client cannot shorten); purge only via an admin credential.** This turns the server into a real backup against ransomware and deletion waves [S8][S23][S49].
13. **Deletion guards on the client: root marker file (missing root means pause, not delete), prompt above a threshold (OneDrive 200, Nextcloud 100) and a short delay before deletions are propagated.** Cheap, proven protections [S1][S11][S25][S33].
14. **Cross-platform name policy in the protocol: NFC names, case-insensitive collision checks, Windows reserved names and trailing dot/space flagged as "cannot sync here", long paths via `longPathAware`/`\\?\`, ADS and atime not synced, mtime only with a tolerance and hash confirmation.** The Windows-first target platform makes these the day-one bugs otherwise [S42][S45][S46][S47][S48].
15. **Non-goals for V1, to be written into ADR 0001:** P2P, placeholders/files on demand, sharing between users, web or mobile access that decrypts on the server (Seafile's weak spot [S5]), collaborative editing/merge, syncing ADS/xattrs/ACLs, network drives as sync roots (no reliable events [S26][S28][S32]).

## 9. Open points and uncertainties

- `[UNVERIFIED]`: merge of the inotify 1 % RAM default into 5.11; Filen chunk size and metadata exposure; Tresorit and Proton internals beyond the cited posts; oCIS without E2EE; behaviour of versions in Nextcloud E2EE folders; minimum macOS for `NSFileProviderReplicatedExtension`; whether unpackaged Win32 apps can register a cfapi sync root without package identity; automatic `\\?\` handling in Rust `std`; restic chunk parameters; macFUSE license; `fastcdc` async feature name; `blake3` keyed API (not opened in this session).
- Partly contradictory: Nextcloud's `remotePollInterval` is described differently in two versions of its docs [S11]; Seafile's default trash retention is given as 30 days (12.0 manual) and 60 days (forum) [S8].
- Owner decisions: CC0 exception for `notify` (and ISC for `inotify` on Linux) or an own watcher; MSRV 1.91 vs. `notify` 8.2.x.
- Next steps to clarify: a spike with `notify` on Windows (RDCW overflow under 100k-file bulk copies, rename pairing); measure FastCDC parameters on a real corpus; hand the crypto items of section 3 and the metadata authentication question to the crypto review.

## Sources (all retrieved 2026-11-26)

- [S1] Syncthing, Understanding Synchronization (v2.1.0): https://docs.syncthing.net/users/syncing.html
- [S2] Syncthing, Block Exchange Protocol v1 (v2.1.0): https://docs.syncthing.net/specs/bep-v1.html
- [S3] Syncthing, File Versioning (v2.1.0): https://docs.syncthing.net/users/versioning.html
- [S4] Syncthing, Untrusted (Encrypted) Devices (v2.1.0): https://docs.syncthing.net/users/untrusted.html
- [S5] Seafile Admin Manual, Security features / encrypted libraries: https://manual.seafile.com/latest/administration/security_features/
- [S6] Seafile Manual, Data model: https://manual.seafile.com/latest/develop/data_model/
- [S7] Seafile notification server: https://manual.seafile.com/deploy/notification-server/ , https://manual.seafile.com/13.0/extension/notification-server ; forum (secondary): https://forum.seafile.com/t/notification-server-used-by-clients/18149
- [S8] Seafile history and trash: https://help.seafile.com/file_folder_managing/library_history_and_snapshots , https://help.seafile.com/file_folder_managing/setting_library_history , https://manual.seafile.com/12.0/config/seafile-conf ; forum (secondary): https://forum.seafile.com/t/q-seafile-as-ransomware-protection/19599
- [S9] Hofmann, Truong: End-to-End Encrypted Cloud Storage in the Wild: A Broken Ecosystem (CCS 2024): https://eprint.iacr.org/2024/1616 ; secondary: https://www.techtarget.com/searchSecurity/news/366614215/Study-outlines-severe-security-issues-in-cloud-providers
- [S10] Nextcloud desktop, History and Architecture (3.9): https://docs.nextcloud.com/desktop/3.9/architecture.html
- [S11] Nextcloud desktop configuration file: https://docs.nextcloud.com/server/stable/user_manual/en/desktop/configfile.html , https://docs.nextcloud.com/server/32/admin_manual/desktop/configfile.html
- [S12] Nextcloud admin manual 36, file versioning: https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/file_versioning.html
- [S13] Nextcloud, Using end-to-end encryption: https://docs.nextcloud.com/server/stable/user_manual/en/files/using_e2ee.html ; RFC: https://github.com/nextcloud/end_to_end_encryption_rfc/blob/master/RFC.md
- [S14] Albrecht, Backendal, Coppola, Paterson: Share with Care: Breaking E2EE in Nextcloud (Euro S&P 2024): https://eprint.iacr.org/2024/546
- [S15] oCIS storage-users service (8.2): https://doc.owncloud.com/ocis/8.2/admin/deployment/services/s-list/storage-users.html ; tus in oCIS: https://central.owncloud.org/t/an-engine-room-update-on-owncloud-infinite-scale-tus-io-improves-and-simplifies-uploads/28483 ; factsheet: https://oc.owncloud.com/rs/038-KRL-592/images/ownCloud_Infinite_Scale_Factsheet_4.0.pdf
- [S16] Cryptomator, Vault encryption scheme: https://docs.cryptomator.org/security/vault/
- [S17] Tresorit: https://tresorit.com/security , https://tresorit.com/blog/addressing-the-state-of-end-to-end-encrypted-cloud-storage-insights-from-tresorits-ceo-2 , https://support.tresorit.com/hc/en-us/articles/216114327 , https://tresorit.com/blog/launching-the-editing-badge-collaboration-feature
- [S18] Proton Drive security model (2020-08-31, updated 2022-09-22): https://proton.me/blog/protondrive-security
- [S19] Filen: https://filen.io/hub/content/files/2025/06/Filen-Info-Brochue-.pdf , https://filen.io/products/desktop ; secondary: https://reclaimthenet.org/recommended-tool/filen
- [S20] Dropbox, Rewriting the heart of our sync engine (2020-03-09): https://dropbox.tech/infrastructure/rewriting-the-heart-of-our-sync-engine
- [S21] Dropbox, Testing sync at Dropbox (2020-04-20): https://dropbox.tech/infrastructure/-testing-our-new-sync-engine
- [S22] Dropbox content hash: https://docs.dropboxapi.com/dropbox-api/docs/technical-reference/content-hash
- [S23] Dropbox ransomware recovery and detection: https://help.dropbox.com/security/ransomware-recovery , https://help.dropbox.com/security/ransomware-detection , https://help.dropbox.com/teams-admins/admin/security-alerts
- [S24] Microsoft, Detect ransomware and recover files with OneDrive: https://support.microsoft.com/onedrive/how-to-detect-ransomware-and-recover-files-using-onedrive
- [S25] OneDrive Group Policy: https://learn.microsoft.com/en-us/sharepoint/use-group-policy ; MC888872 (secondary mirror): https://mc.merill.net/message/MC888872
- [S26] notify 9.0.0 docs, Known Problems: https://docs.rs/notify/9.0.0/notify/ ; crates.io API: https://crates.io/api/v1/crates/notify
- [S27] notify changelog: https://github.com/notify-rs/notify/blob/main/notify/CHANGELOG.md ; manifest: https://github.com/notify-rs/notify/blob/main/notify/Cargo.toml
- [S28] Microsoft, ReadDirectoryChangesW (updated 2025-07-01): https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw
- [S29] Apple, File System Events Programming Guide (2012-12-13, archived): https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html
- [S30] GitHub repository metadata (license, activity) via api.github.com: syncthing/syncthing, nextcloud/desktop, owncloud/ocis, opencloud-eu/opencloud, cryptomator/cryptomator, ProtonDriveApps/windows-drive, ProtonDriveApps/sdk, FilenCloudDienste/filen-desktop, FilenCloudDienste/filen-sync, ho-229/cloud-filter-rs, cberner/fuser, tus/tus-resumable-upload-protocol; crate versions and licenses via https://crates.io/api/v1/crates/<name> (notify, notify-types, notify-debouncer-full, fastcdc, blake3, cloud-filter, wincs, fuser, objc2-file-provider, sqlx, rusqlite, libsqlite3-sys, object_store, opendal, tus_async_client, unicode-normalization, axum, tokio-tungstenite, inotify, fsevent-sys, objc2-core-services, windows-sys, kqueue, walkdir)
- [S31] Seafile licenses: https://github.com/haiwen/seafile-server/blob/master/LICENSE.txt , https://github.com/haiwen/seafile/blob/master/LICENSE.txt
- [S32] inotify(7), man-pages 6.19: https://man7.org/linux/man-pages/man7/inotify.7.html
- [S33] Syncthing FAQ (v2.1.0): https://docs.syncthing.net/users/faq.html
- [S34] LKML, inotify: increase default max_user_watches (2020): https://lore.kernel.org/lkml/20201026204418.23197-1-longman@redhat.com/ , https://lkml.indiana.edu/2011.1/00435.html
- [S35] fastcdc 5.0.0 docs: https://docs.rs/fastcdc/5.0.0/fastcdc/ , https://docs.rs/fastcdc/5.0.0/fastcdc/v2020/index.html
- [S36] Microsoft, Build a Cloud Sync Engine that Supports Placeholder Files (updated 2025-11-18): https://learn.microsoft.com/en-us/windows/win32/cfapi/build-a-cloud-file-sync-engine
- [S37] cloud-filter-rs README: https://github.com/ho-229/cloud-filter-rs
- [S38] Apple File Provider: https://developer.apple.com/documentation/fileprovider/nsfileproviderreplicatedextension , https://developer.apple.com/documentation/fileprovider/synchronizing-files-using-file-provider-extensions , WWDC21 10182: https://developer.apple.com/videos/play/wwdc2021/10182 ; Nextcloud: https://docs.nextcloud.com/server/stable/user_manual/en/desktop/macosfileprovider.html
- [S39] macFUSE: https://macfuse.github.io ; FUSE-T: https://github.com/macos-fuse-t/fuse-t ; secondary: https://github.com/kthchew/ExtendFS
- [S40] tus resumable upload protocol 1.0.0: https://tus.io/protocols/resumable-upload
- [S41] IETF datatracker, draft-ietf-httpbis-resumable-upload (rev 16, 2026-11-23): https://datatracker.ietf.org/doc/draft-ietf-httpbis-resumable-upload/
- [S42] Microsoft, Naming Files, Paths, and Namespaces (updated 2025-04-11): https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
- [S43] Microsoft, Case Sensitivity (WSL, updated 2026-06-02): https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity
- [S44] Syncthing, caseSensitiveFS (v2.1.0): https://docs.syncthing.net/advanced/folder-caseSensitiveFS.html
- [S45] Microsoft, Maximum Path Length Limitation (updated 2025-04-15): https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
- [S46] Microsoft, File Streams (updated 2025-07-10): https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams
- [S47] Microsoft, File Times (updated 2025-04-15): https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times
- [S48] Apple, APFS Guide FAQ (retired, 2018-06-04): https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/FAQ/FAQ.html
- [S49] restic rest-server append-only (secondary sources): https://datazone.de/en/aktuelles/restic-rest-server-zentralisiertes-backup/ , https://computingforgeeks.com/immutable-backups-ransomware-proof-linux-minio-restic-borg/ , https://wiki.archlinux.org/title/Restic
