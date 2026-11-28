---
title: "ADR 0001: Foundation: scope, sync model, server and encryption"
type: decision
tags: [scope, sync, server, backup, e2e, crypto, architecture, merge, restore, quota, performance]
sources: ["[[sync-prior-art-research]]", "[[threat-model-and-crypto-design]]", "[[unix-inode-reuse-measurement]]", "[[tauri-nsis-uninstall-code-reading]]", "[[merge-collision-benchmark]]", "[[transfer-responsiveness-measurement]]"]
status: accepted
superseded_by:
created: 2026-11-26
updated: 2026-11-28
---

# ADR 0001: Foundation

## Context

Hangar Drive is meant to be a self-hosted alternative to OneDrive or Google Drive. A desktop app
keeps chosen folders in sync across devices through the user's own server. The server runs in
Docker, distributes changes to every connected client and keeps every version as a backup for
a retention window that only the operator sets.
Everything is end-to-end encrypted, so the server stores only data it cannot read.

The repository already holds the skeleton: a Tauri 2 app, the protocol crate
`hangar-drive-protocol` and an axum server that answers `/api/v1/health`, in one Cargo workspace.
This ADR fixes what version 1 is and the architecture every later change builds on. It is based
on two reports from 2026-11-26: [[sync-prior-art-research]] and [[threat-model-and-crypto-design]].

Statements marked "conclusion" are decisions of this ADR that the two reports do not cover; they
are reasoned here and are part of the external review (see Consequences).

## Options

| Area | Options considered | Chosen |
| --- | --- | --- |
| Topology | peer to peer (Syncthing); central server (Seafile, Dropbox) | central server: only it can be the backup ([[sync-prior-art-research]], section 1) |
| Local integration | placeholders / files on demand (cfapi, File Provider, FUSE); plain folders | plain folders: no production-ready Rust crate, cfapi has open OS bugs, File Provider is outside Tauri's build |
| Chunking | FastCDC about 1 MiB average; fixed 4 MiB | fixed 4 MiB (see "Contradiction" below) |
| Dedup across users | convergent encryption; keyed IDs per folder | keyed IDs per folder and key generation: convergent encryption allows confirmation attacks |
| Crypto code | extend the sister app's team crypto crate directly (A); shared core plus `hangar-drive-crypto` (B); age (C); Cryptomator (D); MLS (E) | B ([[threat-model-and-crypto-design]], section 6.3) |
| Heads per folder | several heads on the server, merged later by any device ([[threat-model-and-crypto-design]], section 3.4); exactly one head, compare-and-swap, merge commits made by the device whose swap failed | one head (section 3, "One head per folder") |
| Push channel | WebSocket; SSE; polling | SSE that carries only "the account sequence is now N", polling as fallback |
| Uploads | tus; IETF resumable uploads draft; content-addressed chunks | content-addressed chunks, resumable per chunk for free |

> [!warning] Contradiction
> [[sync-prior-art-research]] proposes FastCDC v2020 (min 256 KiB, average 1 MiB, max 4 MiB) for
> dedup of files edited in the middle. [[threat-model-and-crypto-design]] shows that CDC
> boundaries leak content and that keyed CDC in Borg, restic, Tarsnap, Bupstash and Duplicacy was
> broken (Truong et al. 2025). Version 1 takes fixed 4 MiB chunks; a provably secure keyed CDC can
> follow after its own review, as a new object format version.

## Decision

### 1. Scope of version 1

- **Users:** one person with several own devices. The server operator may be a different person
  (family, small office), so a curious operator is an attacker from day one.
- **Formats are ready for sharing:** every object names its folder and key generation, folder
  keys are independent of account epochs, every write is signed per device. Sharing folders with
  other people is a later version and must not need re-encryption.
- **Platforms:** Windows 10 1809+ and 11 first; macOS 13+ and Linux follow (project profile).
- **License:** MIT for app, protocol crate and server.

### 2. Non-goals of version 1

- Peer-to-peer sync and LAN sync without the server.
- Placeholders or files on demand. Item states and a "fetch one file by ID" API stay reserved
  for later.
- Sharing between people and teams.
- Web or mobile access that decrypts on the server.
- Collaborative editing or automatic merging of file contents.
- Syncing NTFS alternate data streams, extended attributes or ACLs.
- Syncing symbolic links, junctions and other reparse points, hardlink identity, FIFOs, sockets
  and device nodes (section 7).
- Syncing permissions other than the execute flag, owners, and Windows file attributes such as
  hidden, system and read-only (section 7).
- User-defined ignore patterns; the built-in list of section 7 applies.
- Network drives as sync roots (no reliable change events).
- Content-defined chunking.

### 3. Architecture

- **One repository, one Cargo workspace:**
  - `src-tauri` is the app.
  - `crates/hangar-drive-protocol` holds wire types and the protocol version.
  - `crates/hangar-drive-crypto` will hold the file crypto layer.
  - `server` is the sync server with its Docker image.

  App and server share the protocol and are released together.
- **Sync core in the app:** modeled on Dropbox Nucleus. It uses stable item IDs and three trees
  (remote, local, synced), and moves are first-class operations, never delete plus add. A
  single deterministic control loop keeps file system, network and clock behind traits. Seeded
  simulation tests check convergence, termination and the absence of data loss from the first
  line of sync code.
  - **Offline:** the sync core works without the server. Local changes collect in the local tree
    against the synced tree; no commit is made while the server cannot be reached. On
    reconnecting, the device pulls the change feed and the folder deltas, then publishes and
    merges as in "One head per folder" below, however long it was offline (conclusion).
- **Change detection:** `notify` is only the trigger, and a periodic full scan is the truth.
  - The full scan runs hourly, and at once after an overflow or rescan event.
  - A local SQLite index holds size, mtime and file ID, and a file is rehashed only on a
    mismatch.
- **Server:**
  - **Storage:** encrypted objects on the file system behind a storage trait. S3 can come later
    through `object_store`.
  - **Metadata:** SQLite through `sqlx` with `sqlite-bundled` and `migrate`, the same stack as
    the sister relay server.
  - **API:**
    - Objects are stored and addressed per account and folder, because their IDs are keyed per
      folder; every call checks that the session's account owns the folder.
    - `POST /objects/missing` asks which object IDs the server lacks.
    - `PUT /objects/{id}` uploads one object; it is idempotent. The account quota and the
      device upload budget are checked here (section 5, "Quota and retained storage").
    - An atomic commit call names the head it expects and carries the new head, at most one
      side commit and their reference deltas. Its rules are in "One head per folder" below. It
      refuses a commit whose reference delta names an object the server does not hold.
    - A folder delta pull returns every commit after a folder cursor, using a monotonic
      sequence per folder.
      - **Unknown folder** (conclusion, finding E2E-2): a folder the account holds nothing of
        yet (no object, no commit; also one purged for good) has the empty chain, sequence 0
        and no commits, never `NotFound`. A new folder pulls before its first upload, and the
        in-memory server the engine is tested against answers the same. Folder IDs are random
        and looked up per account, so the answer tells nothing about another account's folders
        (no IDOR). Test `objects_and_folders_of_another_account_are_out_of_reach`.
    - An account change feed returns every account level change after an account cursor,
      using a monotonic sequence per account ("Change feed" below).
    - **Pairing slots** (conclusion, server security review M2): `PUT /pairing/{id}` reserves
      a slot under the pairing ID of an offer, with the inviting device's session, at most four
      open slots per account; `POST /pairing/{id}` without a session fills only a reserved,
      empty slot, once; `GET /pairing/{id}` reads it, only from the reserving account. Without
      the reservation anyone could create slots under invented IDs until the server's slot
      limit refused every real pairing (section 4, "Pairing").
      `DELETE /pairing/{id}` (`ApiCall::ClosePairing`, conclusion, finding E2E-6) deletes the
      slot with its request, only of the reserving account and idempotent; the inviting device
      calls it once the person accepted or declined. A slot nobody closes is deleted when it
      expires, by the next reservation and by the housekeeping of the collection job.
    - The commit call checks its reference deltas as sets in one transaction (server security
      review M4), and at most a few commits and record writes, whose bodies are held in
      memory, are worked on at once (`HANGAR_DRIVE_HEAVY_REQUESTS`, default 4). One account
      holds at most half of these slots (at least one) and is refused beyond its share at once,
      so an account that sends its bodies slowly cannot stall every other account's commits
      (conclusion, re-review of the server fixes).
  - **Push:** SSE that carries only "the account sequence is now N", with polling of the change
    feed every 60 s as fallback. One stream per device session covers the account and all its
    folders.

#### One head per folder

The server keeps exactly one head per folder. A device whose compare-and-swap fails merges and
publishes a merge commit.

- **Why one head** (conclusion): [[threat-model-and-crypto-design]] (section 3.4) allows several
  heads on the server that a device merges later. Version 1 narrows this to one head:
  - The server can refuse every new head that does not descend from the current one, so no
    client, honest or compromised, can move the head back to an old commit or set the current
    history aside. A compromised client can still sign a new commit whose tree is an old one, as
    a restore does; that is a new, visible version, not a rollback.
  - The first-parent chain from the head lists every head the folder ever had, in server order.
    Cursor, retention, the restore timeline and the quota then work on one linear sequence.
  - With several heads, two devices can merge the same heads at the same time and create new
    heads again. With compare-and-swap exactly one wins and the other merges once more.
  - Rollback and fork detection keep their strength (section 4, "Versions").
  - The cost: a device publishes only while it reaches the server and wins the swap. For one
    person's devices concurrent commits are rare, and a device that was offline merges when it
    reconnects.
- **Commit kinds:**
  - The first commit of a folder has no parent.
  - A normal commit has one parent: the base, that is the head the device last verified.
  - A side commit is the device's local state as a commit on its base. It is uploaded only
    together with a merge commit and never becomes a head.
  - A merge commit has two parents: first the current server head, second the device's own side
    commit.
  - Version 1 writes and accepts at most two parents. The format's limit of 8
    ([[threat-model-and-crypto-design]], section 8.4) stays reserved.
  - Reference deltas are always relative to the first parent ([[threat-model-and-crypto-design]],
    section 4.1), or full; every commit signs a digest of its delta (amendment "reference deltas
    bound to the tree").
- **Publishing (client):**
  1. The device builds commit C on its base B from its local tree, uploads the missing objects
     and calls commit with expected head B.
  2. If the server's head is still B, C becomes the head.
  3. Otherwise (the swap fails, or the pull before it already showed a newer head H), the
     device pulls the folder delta, verifies that H descends from its frontier (section 4) and
     merges three trees at tree level, matched by item ID: the base is the synced tree (the tree
     of B), compared with the tree of H (remote) and the tree of C (local). Rules: "File
     contents are never merged" below.
  4. It uploads C and the merge commit M (parents H, C) in one call with expected head H. If the
     head moved again, it repeats step 3 with the same C and a new M, with bounded retries and
     backoff.
  5. If the server no longer retains B's tree (the device was offline longer than the retention
     window, section 5), it cannot accept C. The device then uploads M with the single parent H.
     The merged tree is the same; only the side commit is missing from the history.
     The device takes this path only on the server's explicit "base expired" answer, which it
     cannot check. A server that claims it falsely suppresses only the side commit: every local
     change is in M's tree, as itself or as a conflict copy, and only the local moves and deletes
     that lost the merge are no longer restorable. That is less than the server can already do
     by dropping data, which is accepted (conclusion).

  Local changes made while steps 3 and 4 run go into the next round, so a merge is computed on
  fixed inputs.
- **Server checks in the commit call:**
  - The expected head equals the current head (compare-and-swap). Otherwise the call is refused
    and the answer names the current head.
  - The new head's first parent is the current head, so the server refuses every head that does
    not descend from it. Only the first commit of a folder has no parent.
  - A side commit is accepted only in the same call as a merge commit that names it as second
    parent. It is signed by the same device, its counter is above the server's mark for that
    device and below the merge commit's counter, and its own parent is an earlier head of the
    same folder, on the first-parent chain of the current head, whose tree is still retained.
    Its key generation and named log head are at least those of that parent.
  - **Side mark** (conclusion, external review finding L1): bit 1 of the commit `flags`, inside
    the signed body, marks a side commit. Every side commit carries it, and nothing else does: a
    head with the bit is refused, and so is a side commit without it, so the server can present
    neither as the other.
  - Each commit's height is one more than the highest height of its parents.
  - Along the first-parent chain, nothing goes back: a new head names a key generation and an
    account log head at least those its first parent names (conclusion). Without the log rule, a
    removed device whose key leaked could sign commits that name a log head from before its
    removal; without the generation rule, a device could keep writing under a generation the
    removed device holds.
  - As before: signature, signer valid at the named log head, per device counter above the
    server's mark for that device, every object in a reference delta held.
  - **Signer current now** (conclusion, finding H1): the signer of every commit of the call is a
    current device of the server's verified log when the call arrives, whatever log head the
    commit names. A removed device whose key leaked could otherwise sign commits that name a log
    head from before its removal.
  - The call is atomic: both commits and the new head are written in one transaction, or nothing
    is.
- **Folder sequence:** every accepted commit call increments the folder's sequence by one; the
  head and its side commit share that number. The delta pull returns the commits with a sequence
  above the cursor, in order. The cursor a device stores is the sequence of its frontier.
- **Item IDs in directory nodes:** the merge matches items by their stable item ID, so every
  directory node entry carries the item ID: 16 random bytes chosen by the device that first adds
  the item. The format outline in [[threat-model-and-crypto-design]] (section 8.4) does not show
  this field yet; adding it is a conclusion of this ADR.

#### File contents are never merged

The device merges trees, never the bytes of a file; with E2EE the server could not merge
anyway. Who keeps a name depends only on server order, never on a clock: **the version that
reached the server first keeps its name, and the local version of the merging device becomes the
conflict copy.**

| Case (base, server head, local) | Result |
| --- | --- |
| Changed on one side only | that side |
| The same change on both sides (equal object ID) | taken once, no conflict |
| A file's content changed differently on both sides | the server version keeps name and item ID; the local version becomes `<name> (conflict <device> <date>).<ext>` with a new item ID |
| Change against delete | the change wins and keeps its name; a deleted directory stays, holding the changed items |
| Both sides add different items under the same comparison key in one directory | the server item keeps the name, the local item becomes a conflict copy; two files with the same manifest ID are taken once; two directories become one under the server's item ID, and their children are merged by these rules |
| The same item moved to different places, or moves that would form a cycle | the server's move wins, the local move is dropped |
| Move on one side, content change on the other | both apply |
| Only metadata (mtime, execute flag) changed differently on both sides | the server version wins, no copy |
| An item changes kind (file to directory or back) | delete plus add with a new item ID |

- A local move or delete that loses stays in the side commit, so it remains restorable for the
  window.
- Conflict copy name: `<device>` is the merging device's name, `<date>` its local date as
  `YYYY-MM-DD` at the merge. `<ext>` is everything after the last dot, unless that dot is the
  first character; without an extension the suffix goes at the end. If the name is taken, ` 2`,
  ` 3` and so on are appended inside the parentheses. The date is only a label; it decides
  nothing. A name longer than 255 UTF-16 units is shortened: the stem first, down to its first
  character, then the extension, and the label last (amendment "collisions in linear time and
  copy names within the limit").
- The word `conflict` is written in the merging device's UI language (for example `Konflikt` in
  German), with English as the fallback; the same holds for `restored` in section 5. The whole
  name is only a label for people: no device parses it, and no rule of this ADR depends on it
  (conclusion, following [[ux-concept]]). Devices recognise a copy by its conflict link below.
- **Joining a non-empty local folder** (conclusion, following [[ux-concept]], section 6.5): when
  a folder of the account comes to a device at a place that already holds files (a new device,
  a recovery, or adding an existing account folder), the sync core treats it as a named case,
  the join. There is no synced tree yet, so it merges three trees by the rules above with the
  empty tree as base, the tree of the server head as remote and the scanned local tree as local.
  - Local items have no item IDs yet, so they are matched by comparison key, directory by
    directory, exactly as in the row "Both sides add different items under the same comparison
    key".
  - Two files with equal content (equal size and chunk IDs, computed with the folder's ID key)
    are taken once under the server's item ID. A difference only in metadata follows the
    metadata row: the server version wins, no copy.
  - A file that differs keeps the server version under its name and item ID; the local file
    becomes a conflict copy with `conflict_of`. On disk the device first renames the local file
    to the copy's name, then writes the server version under the name.
  - A local item without a counterpart is added with a new item ID; a server item without one
    is downloaded. Directories with the same key become one under the server's item ID.
  - Nothing is deleted on either side, because the empty base proves no delete. Entries the
    built-in ignore list skips (section 7) take no part. The result is published as a normal
    commit on the server head. The re-anchor with an empty base (section 4) is the same case.
- **Conflict link `conflict_of`** (conclusion): every conflict copy a merge makes carries the
  item ID of the item that kept the name, so every device pairs original and copy without
  reading the copy's name.
  - **Format:** bit 1 of the directory entry `flags` says that 16 bytes with that item ID follow
    the flags; without the bit nothing follows. Bit 1 belongs to the directory entry only, never
    to a file manifest. A parser refuses the bit without its 16 bytes and an ID equal to the
    entry's own item ID, as it refuses unknown flag bits. Several copies may name the same
    original. Files and directories may carry it, because a copy from a collision of a file with
    a directory can be a directory.
  - **Set:** only by the merging device, only on the copy, in the rows of the table above that
    make a conflict copy and for case-only and normalization-only collisions (section 7). If the
    item that kept the name is itself a copy, the new copy takes over that item's `conflict_of`,
    so a group has one original and never a chain.
  - **Kept:** while either item is edited, and when the original is moved or renamed.
  - **Dropped** by a commit that writes the copy's entry without it, in exactly these cases:
    - the person chooses "keep both" on any device;
    - the person chooses "keep this" on one version: the original's entry, with its name and item
      ID, takes the chosen content, and the copy's entry is deleted, so the field goes with it.
      The other content stays restorable through the history;
    - the person renames or moves the copy;
    - a device writes the copy's directory node while the original is not in the tree it commits
      (dangling, for example after the original was deleted or a partial restore gave it a new
      ID).
  - **Merge:** like other entry metadata, except that a dropped field wins against a kept one on
    the other side, so a pair that was tidied up never comes back. Different values on both sides
    take the server side.
  - **Trust:** only the display depends on it. No sync, retention or restore rule reads it, and a
    wrong or dangling value, which only a device holding the folder key can write, changes only
    how the conflict list groups files.
- [[sync-prior-art-research]] (section 8, item 11) gives "keep both" and "a change beats a
  delete"; which side loses, the directory and move rules and the name details are conclusions.

#### Change feed

The folder sequence covers commits only. Changes to the account reach the devices through one
sequence per account (conclusion; the reports name only the per-folder sequence).

- **Account sequence:** monotonic per account. Every account level change gets the next number
  and one feed entry:

  | Entry | Fields | The client then |
  | --- | --- | --- |
  | `device_log` | new log length | fetches and verifies the new entries from its anchor |
  | `epoch` | epoch number | fetches its wrapped epoch secret and checks it against the log's commitment |
  | `record` | record kind, record ID, version | fetches the sealed record: folder key rings (`folder-keys`), the folder list (`folders`), device names |
  | `folder_head` | folder ID, folder sequence | pulls the folder delta |
  | `folder_created`, `folder_retired` | folder ID | fetches the `folders` record; it never changes its folder list from the entry alone. Undoing a retirement is announced as `folder_created` |
  | `notice` | kind, parameters | shows a notice from a closed list of kinds (anomaly pin, quota, budget or minimum count cap warning) in the app's own i18n text; the server sends no free text, so it cannot put its own words into the app (conclusion) |

- **Coalescing:** the feed may return only the newest entry per kind and key after the cursor.
  The client applies device log, epochs and records before folder heads, so keys are present
  before the commits that need them.
- **SSE and polling:** the SSE event carries only the new account sequence; the client then
  pulls the feed from its account cursor. Polling every 60 s reads the same feed.
- **Trust:** the feed is only an index. Everything it points to is verified as before: the log
  from the pinned anchor, epoch secrets against the commitment, records by signature and the
  record replay guard (an older version is refused), commits by the frontier rule. A server that
  withholds entries performs a freeze (section 4).
- **Record freshness** (conclusion): the replay guard refuses only a version older than one this
  device has already accepted. It cannot tell a device that a newer version exists, so a server
  can serve a device that never saw it an old, validly signed version.
  - `folder-keys`: a device commits to a folder only with a ring sealed under the newest epoch
    of its verified account log, and never under a generation below the newest one on the
    first-parent chain it verified; until it has such a ring, it does not commit to that folder.
    Every device removal rotates the epoch and the removing device re-seals every ring with the
    new generation (section 4), so an old ring is caught as soon as the device knows the log, and
    the log reaches it through the log heads that commits name. Without this rule, a server
    holding a removed device's key could have devices keep writing under a generation that key
    opens. Withholding the log as well is a freeze.
    - **Generation bound to the last removal** (conclusion, finding M1): every generation in a
      ring carries the log head index at which its device made it, and a device commits only
      under a newest generation made at or after the log's last remove device entry. A ring
      re-sealed under the new epoch without a new generation, or with one made before the
      removal, is refused even though it opens.
  - `folders`: an old version only hides a new folder or shows a retired one, whose commits the
    server refuses. That is a loss of availability, like a freeze.
  - **Records of removed devices** (conclusion, finding H1): a record opens only if its sender
    is a current, regular device of the verified log, not only valid at the log head the record
    names. After every removal and its rotation the removing device therefore re-seals every
    account record under the new epoch: each `folder-keys` ring with a new generation, the
    `folders` list and the `device-names` list.
- **Folder list:** the names of synced folders live in a sealed, signed account record of kind
  `folders`, so the server sees only folder IDs (conclusion; [[threat-model-and-crypto-design]],
  section 6.1, lists records for key rings, device names and settings).
  - A new folder: the device writes the folder key ring record, the folder list record and the
    first commit.
  - Removing a folder for all devices: a folder list record without it plus a retire call. The
    server then refuses commits for that folder, and its last head counts as superseded at
    retirement (section 5). Within the window, any device can undo the retirement.

### 4. Encryption

The crypto layer follows [[threat-model-and-crypto-design]] (section 8) and only uses the
primitives the sister app already uses:

| Primitive | Crate |
| --- | --- |
| Signatures | Ed25519 (`ed25519-dalek` 3) |
| Key wrapping | HPKE base mode with X25519 (`hpke` 0.15) |
| Encryption of objects and records | XChaCha20-Poly1305 (`chacha20poly1305` 0.11) |
| Key derivation | HKDF-SHA256 |
| Keyed IDs | HMAC-SHA-256 |
| Hashes | SHA-256 |

- **Account:** a signed, hash-chained device log with one member, plus HPKE-wrapped epoch
  secrets. Folder keys are random, kept in a generational key ring per folder and sealed under the
  account epoch.
- **Separate identities:** device identities are separate per product. Every Drive label starts
  with `hangar-drive/v1/`, so no signature or key of one product is valid in another.
- **Objects:** there are three object types: chunks, file manifests and directory nodes.
  - IDs: `HMAC-SHA-256(K_id, type, plaintext)`. Dedup happens only inside a folder and key
    generation.
  - Padding: every object is padded with Padmé.
  - Opening an object recomputes the ID and refuses a mismatch. This check also commits the
    ciphertext to its key.
- **No visible tree:** names exist only inside encrypted directory nodes, each with an NFC
  comparison key. The server sees no names, paths or exact sizes.
- **Versions:** each folder has a signed commit DAG with one head on the server (section 3).
  - **Frontier (rollback):** every device keeps, per folder, the last head it verified (commit
    ID, height, folder sequence). It accepts a new head only if the first-parent chain from that
    head reaches its frontier through commits it verifies: this account and folder, signature,
    signer valid at the named log head, counter above that device's mark, height, folder
    sequence above the frontier's, and generation and named log head not below the first
    parent's (section 3). A commit that names a log head beyond the device's own makes it fetch
    and verify the log up to that head first. Otherwise, and whenever a body on the chain is
    missing, it refuses and reports "the server shows an older state"; replayed old commits fail
    the same check. It never accepts a head it cannot connect to its frontier. Side commits are
    verified the same way and against the rules of section 3, but are not part of the chain. The
    frontier of [[threat-model-and-crypto-design]] (section 3.4) is a set of heads; with one head
    on the server it has one element, and the guarantee is unchanged: only devices sign commits,
    and every commit whose first-parent chain reaches the frontier was made after it.
    - **Removed signers and the barrier commit** (conclusion, finding H1): a new head signed by
      a device that the verified log has removed since is accepted only if a later head of the
      same verified delta, signed by a current device, names a log head at or after that
      removal. After every removal and its rotation the removing device writes such a barrier
      commit in every folder: a normal commit on the current head with the same tree, naming the
      new log head and the new generation. A backdated commit of the removed device after the
      barrier fails "nothing goes back"; one before it that no barrier follows is never taken in.
      A device verifies the whole delta up to the server's sequence (every page) at once, so a
      barrier on a later page counts. Only the removing device, in its removal flow, verifies
      the delta without this rule to build the barrier on the head it finds; any other device
      does so only after the rule refused its delta and only with the person's consent ("A
      resumable job" below). Residual risk: a backdated commit that a malicious server shows the
      removing device in exactly that moment is covered by its barrier.
    - **Verified chain:** besides the frontier, every device keeps per folder the list of every
      head on the first-parent chain it has verified (commit ID, height, folder sequence), a few
      dozen bytes per head (conclusion). The re-anchor below finds its base in it.
    - **Re-anchor** (conclusion, part of the external review): the only way out of "the server
      shows an older state" for a folder whose chain is complete on the server, for example after
      the operator restored an older backup of the server. It never happens automatically.
      1. **Confirmation:** the folder stays paused until the person confirms on this device.
         The app first asks them to compare the folder safety number with another device: the
         paused device shows the number of the head the server now presents, a device that is
         not paused shows the number of its frontier. Equal numbers mean both devices see the
         same server state; different numbers mean a fork, and the person does not confirm.
         Before a device that is not paused shows its number, it pulls the change feed and the
         folder delta once, so it never shows an outdated frontier; without a connection it
         shows no number.
         Without another device, the person can confirm without comparing. Each device confirms
         for itself; no device re-anchors because another one did.
      2. **Account state first:** if the server's account log is behind the one this device
         verified, the device first publishes the signed log entries it holds beyond the
         server's log head, and then the newest `folder-keys` and `folders` records it holds;
         the server checks them as any new entry or record. Wrapped epoch secrets the server
         lost cannot be rebuilt by this device (open point for the external review).
      3. **Base:** the device verifies the server head H as any commit (signature, signer valid
         at the named log head, the rules of section 3) and its first-parent chain down to the
         newest commit that is in its verified chain; that commit is the base A. Commits on this
         part of the chain may carry counters below this device's marks, because they are older
         than its frontier. The device never lowers a mark, and only its new commit must be
         above them. If H itself is in the verified chain (the plain restore of an older state),
         A is H. If there is no such commit, or A's tree is neither on the server nor on the
         device, the base is the empty tree.
      4. **New commit:** the device merges three trees by the rules of section 3, "File
         contents are never merged": base the tree of A, remote the tree of H, local its local
         tree (the synced tree plus pending local changes). It publishes the result as a normal
         commit with the single parent H and expected head H, uploading missing objects first.
         With A equal to H the result is exactly the local tree. With the empty base every item
         of both sides is kept, equal items once and differing ones as conflict copies, so a
         re-anchor never deletes an item that its base does not prove deleted. The new commit
         becomes the frontier, with its lower height and folder sequence, and the folder cursor
         goes to its sequence. The heads of the old chain after A are kept as discarded (their
         commit IDs; conclusion, finding L2): no later delta and no later re-anchor may present
         one of them as a head again.
      - **Other devices:** a device whose frontier the server's head reaches (it was behind the
        restored state) sees a normal new head. Every other device sees "the server shows an
        older state" as well, because the re-anchored head does not reach its frontier either,
        and follows the same steps after its own confirmation. Its base is then usually H, which
        its verified chain contains, so its local changes and those of the device that
        re-anchored first are merged by the normal rules, and a change both had is taken once.
      - **What the history loses:** the commits after the base on the old chain, with their
        side commits, are no longer on the server's first-parent chain. Their versions cannot be
        restored, and "Undo a device" (section 5) cannot reach into them. The newest content
        each confirming device knew survives in its re-anchor commit; what existed only in
        versions between the base and the old frontier (an edit later overwritten, a file later
        deleted) is lost.
      - **Why the confirmation stops a silent rollback:** a re-anchor is exactly the step a
        malicious server needs to move a device to an older history or to end a fork ("Forks"
        below). Without the person it never happens, and the comparison of the folder safety
        number is the second channel that shows a fork. Content is not rolled back even then:
        from the server side the merge takes only changes that devices signed after the base,
        so an older tree from the server never replaces newer local files.
      - **Residual risk** (medium): a person who confirms without comparing lets a malicious
        server drop the history between base and old frontier, and end a fork, without that
        device detecting it. Its local content survives in its commit, and dropping history is
        no more than the server can already do by deleting data.
      - **Re-anchor mark** (conclusion, part of the external review): the commit body gets a
        `flags` field (u32) directly after the counter, inside the signed body, so the commit ID
        and the signature cover it. Bit 0 marks the commit of step 4 as a re-anchor. Bit 1 is
        the side mark (section 3). Version 1 knows no other bit; server and devices refuse
        unknown bits, and bit 0 on a first commit, a side commit or a merge commit. Every other
        commit writes 0 in bit 0.
        - The timeline shows its marker from this bit ([[ux-concept]], section 9.1). No sync,
          retention, quota or restore rule reads it, so a device that sets it falsely only adds a
          marker line.
        - The bit is in the clear, because a commit has no encrypted part. The server learns
          which commit is a re-anchor and which device wrote it. It already knows that it
          presented an older state (it restored one or chose to), and a re-anchor commit is the
          expected answer, often after the republished account state of step 2. An encrypted
          field was not chosen: it would add an encrypted part to every commit for one bit that
          tells the server little it cannot infer.
  - **Forks:** a server can keep two groups of devices on separate chains from a common commit.
    It cannot join them again without detection: a device refuses every head whose first-parent
    chain does not reach its frontier, and a merge starts only from such a head. A forked device
    therefore never takes in the other group's commits, and the fork shows only when two devices
    compare the folder safety number or when the server tries to end it. This is SUNDR's fork
    consistency. The report's statement that a fork is detected at the first merge
    ([[threat-model-and-crypto-design]], section 3.4) holds for neither model, because with
    several heads the server equally chooses which heads a device sees; the single head
    therefore does not weaken fork consistency (conclusion, part of the external review).
    - **Seen vector:** on a linear chain it is redundant. Every earlier head and its signer are
      on the first-parent chain a device verifies, so the vector would show nothing the chain
      does not, and on a fork it is never shown either. Version 1 writes it empty and refuses a
      non-empty one; the field stays in the format (conclusion).
  - **Long offline:** the bodies of heads are kept for the life of the folder (section 5), so a
    device that was offline longer than the window can still verify the chain to its frontier.
    If a body is missing anyway (after an operator purge), the device pauses the folder. It
    resumes only after the person confirms the current state, by comparing the folder safety
    number with another device or, with no other device, by accepting it explicitly as a new
    frontier (conclusion). A signed checkpoint instead of kept bodies was not chosen: it adds a
    signed object type and the question which device signs it and when, and gives no stronger
    guarantee, since its signer can only vouch for what the hash chain already proves.
  - **Freeze:** a server freeze cannot be detected without a second channel. This is accepted
    and surfaced through a folder safety number and a staleness warning.
- **Pairing:** a new device joins through a QR offer that carries a 128 bit secret and the
  account log head as its trust anchor. Without a camera, the person types the full-entropy code
  or compares safety numbers. Short codes are allowed only once there is a PAKE.
  - **Signed offer** (conclusion, finding M4): the inviting device signs the offer with its
    Ed25519 key over `field("hangar-drive/v1/pairing-offer") || offer`; the signature follows
    the offer bytes. The new device checks it against the inviter's key once it has the log, and
    a device of the account takes server URL and pin from an offer only after this check
    (section 6, "Pin rotation").
  - **Reserved slot** (conclusion, server security review M2): the inviting device reserves
    the slot of the offer's pairing ID with its session before it shows the offer
    (`ApiCall::ReservePairing`); the new device's request is accepted only into that slot
    (section 3, "Pairing slots"). The offer format does not change.
  - **Sealed name** (conclusion, finding E2E-6): the request carries the new device's name
    sealed, never in the clear, since device names are sealed records everywhere else:
    `P_name = HKDF-SHA256(P, field("hangar-drive/v1/pairing-name-key"), 32)`, `sealed_name =
    nonce (24) || XChaCha20-Poly1305(P_name, nonce, padded, aad = field("hangar-drive/v1/pairing-name")
    || field(account) || field(new device))` with `padded = length (u64) || name || zeros` to its
    Padmé length, and the request tag covers `sealed_name` instead of the name. Only who holds P
    opens it; the server checks only its size (the Padmé lengths of one and of 128 bytes of
    name). Key label and associated data differ, and the name is padded, since the overall
    security review (N13 and info, "Crypto and protocol" below). Vectors `pairing.sealed_name` and
    `pairing.tag`, recomputed by `test_vectors.py`. The inviting device closes the slot after
    the answer (section 3, "Pairing slots").
  - **Added device** (conclusion, finding L6): the append call with the add device entry
    carries exactly one wrapped key, the current epoch's secret for the new device, and no
    rotation happens; the server checks that this wrap names the added device. A new device
    needs no older epoch, because records are sealed under the newest one and folder key rings
    hold every generation.
- **Recovery:** a 128 bit recovery code with a printed recovery sheet. There is no password
  recovery.
  - **Sheet** (conclusion, sync engine review, open point A): the sheet prints the server
    address, the server ID and the account ID in the clear next to the code. The recovery
    device's keys and its device ID are derived from the code alone
    (`RecoveryCode::identity`, `RecoveryCode::device_id`, label
    `hangar-drive/v1/recovery-device-id`, vector `recovery.device_id`), so nothing else is
    needed. The sheet's public part is also the link `hangar-drive://recover#<payload>`
    (base64url of the sheet bytes, version 3: account ID, server ID, the genesis anchor, the
    code's anchor tag over account and anchor, the optional SPKI pin and the server URL; see the
    amendments "App shell and the second engine review" and "Recovery link bound to the code");
    the link never carries the code, which is always typed. The server ID is learnt before the
    code is shown, through the session challenge, which the server answers for any account and
    which writes nothing.
  - **Flow** (conclusion): the new installation signs in as the recovery device at the
    sheet's server (server ID checked at the sign-in), checks that the verified log lists that
    recovery device as current with the derived keys (otherwise the code is unknown or used
    up), unwraps the current epoch, appends one add device entry for itself with the wrap
    (`device_wrap`), joins at the log head that append returned, then removes the lost devices
    the person chose and every recovery device in one removal with its rotation, writes the
    barriers in every folder of the account (also those it does not sync yet), and adds the
    recovery device of a new code.
  - **Recovery session** (conclusion): a session of a recovery device may only fetch the device
    log, fetch its own wrapped keys of every epoch, and make exactly one append with one add
    device entry for a regular device and its wrap. The server refuses every other call. The
    protocol crate's session scope type carries the rule, so the server applies one list.
    "Exactly one append" holds per session, not per recovery device: a recovery device that
    signs in again gets a new session with its own one append (server security review, info).
    That is no gain of rights: the recovery code gives the person holding it full access to the
    account anyway, through the regular device it adds, so counting appends across sessions
    would protect nothing.
  - **Stuck log** (conclusion, finding M5): while a rotation is due, a recovery device may add
    exactly one regular device. The rotation stays due, and the new device removes the lost
    devices and the recovery device and rotates. Without this exception a log whose regular
    devices were all lost with a rotation due could never move again.
- **Removing a device:** triggers an immediate epoch rotation and a new folder key generation.
  Re-encrypting old content is an option and off by default.
  - **Atomic** (conclusion, finding M5): the server admits an append call as one batch of
    exactly one of two shapes: removals followed by their rotation, with a wrap for every device
    that stays, or one added device. The state after the batch must have no rotation due, except
    after the recovery exception above. A removal therefore never reaches the server's log
    without its rotation.
  - **Afterwards** (conclusion, finding H1): the removing device adds a generation to every
    folder key ring, re-seals every account record under the new epoch (section 3, "Record
    freshness") and writes a barrier commit in every folder ("Removed signers and the barrier
    commit" above).
  - **A resumable job, completed by any current device** (conclusion, security review N1): the
    three steps (append, re-seal, barriers) are a job the removing device stores before the
    append and resumes after a crash or a lost connection; an append whose answer was lost is
    recognised in the verified log; the resumed job takes its permit from the log entry it
    signed (`BarrierPermit::of_own_removal`). If the removing device goes away after the
    append, other current regular devices complete what is really open (conclusion, sync
    engine security review H1):
    - **Re-seal:** a removal whose re-seal is missing (a ring's newest generation made before
      the log's last removal) is re-sealed by the next current regular device that sees it.
      Records are compare-and-swap per version, so two devices doing it at once are safe.
    - **Barriers:** no device writes a barrier because its log shows a removal. Only when its
      own delta check (`FolderView::check_delta`) refuses a folder's delta by the removed signer
      rule does it get a refusal, and only from that refusal a permit for that one folder
      (`BarrierPermit::takeover`, bound to the folder ID). With it the device checks the delta
      without the rule (`verify_delta_before_barrier`). If that would let heads of a removed
      device in, it writes no barrier: the folder stops (`StopReason::RemovedHeads`) and the app shows the heads and asks the person. Taking them
      in writes the barrier after them, and the app then offers "Undo a device" for them;
      leaving the folder stopped takes nothing in. A barrier is a normal commit on the head, so
      a device that loses the race takes the winner's result.
    - **Residual risk:** a malicious server can still hide the removing device's barrier from a
      device that was offline and show it a commit of the removed device instead. That device
      no longer takes the commit in on its own, as it did before; it only stops the folder.
      What remains is the person's decision: who takes such heads in without looking adopts
      what the removed device signed, which "Undo a device" then reverts. A folder stopped this
      way is a strong sign of a malicious server or a key that leaked, so the window says that a
      removed device's changes arrived without the removal's confirmation. The removing device
      itself keeps the residual risk of the barrier rule above.
- **Exports:** if there are any, they use the age format with its STREAM payload. Neither age
  nor Cryptomator is the core.
- **Code:** option B.
  - The shared parts of the sister app's team crypto crate (identity, log, epoch, rotation,
    recovery, generic record, key ring) are extracted into a shared core with a label domain
    parameter.
  - Until then, Drive uses a git dependency pinned to a commit of the public repository.
  - The extraction is agreed with the sister project before it starts.

### 5. Backup and protection against a compromised client

- **Retention:**
  - Only the operator sets the retention, in the server config: `HANGAR_DRIVE_RETENTION_DAYS`,
    default 30, plus `HANGAR_DRIVE_RETENTION_MIN_COMMITS`, the minimum number of heads kept per
    folder, default 10 (conclusion; the reports give no default).
  - No client API deletes commits or objects. A client's "empty trash" is only a request.
  - **A commit's tree is kept for the window after the commit is superseded.** A head is
    superseded when the server accepts the next head; a side commit is superseded in the call
    that uploads it; the last head of a retired folder is superseded at retirement.
    - **Side commits** (conclusion, server security review H1): a side commit keeps for the
      window only what it adds to its base, never the base tree itself. The base is a head and
      stays retained by its own rules (its window, a pin, the minimum count); a side commit is
      restorable while its base is. Otherwise a device could send a side commit on an old head
      shortly before each window ends and keep that head's tree stored for ever, outside every
      budget. The newest
    heads of a folder up to the minimum count, the current head included, are kept regardless of
    age, within the byte cap below.
  - **Byte cap for the minimum count** (conclusion): bytes that only trees held by the minimum
    count retain (trees that are not live, whose window has ended and that no admitted pin
    holds) are capped per account, operator-set, default the account quota. These are the bytes
    of class 4 in "Retention classes" below, so a byte that an admitted pin also holds counts
    against the pin cap, never against this cap. The server admits such trees in the order in
    which their windows ended, earliest first, while the bytes that only they retain stay within
    the cap. A tree beyond the cap expires as if there were no minimum count, so the first ones
    win, as with the anomaly pins.
    - Otherwise a compromised device could create a new folder every day, upload up to the quota
      into it, drop the data in the next commit and never write to that folder again: the minimum
      count would keep the dropped tree for ever, one quota per day.
    - An honest folder rarely needs the cap: the minimum count matters only for folders that
      change rarely, and their old trees share most objects with the live tree.
  - **The signed body of a head is kept as long as the folder exists.** It holds no content and
    is a few hundred bytes. A commit whose tree is no longer retained is "expired": it cannot be
    restored or serve as a base for a side commit. [[threat-model-and-crypto-design]] (section
    4.2) keeps commits "for the window after they stop being heads"; splitting tree and body is
    a conclusion, needed for the frontier check after long offline periods (section 4).
  - **Only what the frontier check needs stays** (conclusion, data minimization): when a commit
    expires, the server drops its reference delta and its server time and keeps the body and the
    folder sequence. A side commit's body goes with its tree, because it is not on the
    first-parent chain. A retired folder, with all its bodies, is deleted once the window after
    its retirement has passed; the minimum commit count does not apply to it.
  - Immediate purges go only through a server CLI; a purge also removes the commit bodies.
- **Garbage collection:**
  - Commits carry reference deltas in the clear.
  - An object is deleted only when no retained commit declared it reachable and the newest commit
    that declared it is older than the window. A client that declares nothing cannot shorten the
    window.
  - An object that no commit ever declared (an upload whose commit never came) is deleted 24
    hours after its upload (conclusion; the reports do not cover it).
- **Anomaly pinning:** a burst of replaced or dropped objects pins the last commit before the
  burst for 90 days, and all devices are told through a feed `notice`. Upload volume per device is
  one of the signals.
  - **Burst threshold** (conclusion, server security review L4): within the rolling hour, at
    least `min(500, 30 % of the folder's file objects)` file objects, but never fewer than 20,
    that make up at least 30 % of the folder's file data. A fixed 500 alone meant a folder with
    fewer files could never set off a pin. An operator count below 20 is taken as set. The share
    also counts against the file data at the start of the window (amendment "reference deltas
    bound to the tree", LOW 1).
  - **Retirement** (conclusion, server security review M3): retiring a folder counts as
    dropping every live object of it and goes through the same burst signal: a retired folder
    with at least 20 file objects pins its last head and every device is told. A retired
    folder whose window ended is deleted only once no admitted pin holds it any more; the pin
    no longer goes with its folder (no `ON DELETE CASCADE`), so it holds for its 90 days or
    until it lapses under the pin cap or the operator lifts it. Its bytes count against the pin
    cap like any pinned tree. Before, a compromised device could retire a folder, and after the
    window the folder went with its pin: retiring was a burst the signal did not see.
    Bringing back a retired folder whose last head a standing pin holds is a restore of a
    pinned tree: its bytes go through the pin restore allowance before the budgets (conclusion,
    re-review of the server fixes), so undoing a harmful retirement does not wait for a budget.
    That holds once per pinned head (overall review N1): a later bring-back of the same head
    pays the budgets.
  - **Pin cap, a lasting invariant** (conclusion): the bytes that only admitted pins retain
    (class 3 in "Retention classes" below) never exceed the pin cap P of the account: its quota
    plus the headroom, `Q + H`, because one pinned tree was live and can therefore reach that
    size. The cap holds at every time, not only when a pin is made. A new pin holds almost
    nothing alone, since the tree it pins was live a moment ago and the window still holds it;
    its own bytes grow later, when the windows of the trees that share its objects end, and when
    an object it shares with the live tree is dropped and the window of the head that dropped it
    ends.
    - **Admission in creation order:** in every garbage collection step, before anything is
      deleted, the server walks the standing pins of the account from the oldest and admits each
      pin whose additional class 3 bytes keep the total within P. A pin that does not fit lapses
      for good: it holds nothing beyond the normal window, its tree expires once no other rule
      retains it, the server warns the operator, and every device gets an anomaly pin `notice`
      that says the pin lapsed. A lapsed pin never comes back. The first pins win, by the same
      rule as the byte cap for the minimum count. A pin that adds no class 3 bytes always fits,
      so a pin made while the cap is full is admitted until its tree would need the cap.
    - **The attack it stops:** a device makes up to Q of garbage live every day, sets off a small
      burst and then drops the garbage slowly, below the burst signal. Every day yields a pin on
      a garbage tree. Checked only at creation, every pin passed, because its garbage was still
      live or in the window, and after the windows ended 90 pins kept up to Q each. Now the first
      garbage tree whose window ends takes up to Q of P; each later one would exceed P once its
      garbage leaves the window, lapses at that step, and its garbage is collected like any
      dropped data. Class 3 stays at most P. The price: the first garbage pin occupies the cap
      for its 90 days, so a later, honest pin keeps its tree only for the window. Within the
      window it is admitted, because it holds nothing alone yet, and its state can be restored
      ("Restore" below); only after the window does it lapse. The operator, warned when the cap
      is reached, can lift the garbage pin.
  - **Retention classes** (conclusion): every stored object belongs to exactly one class, the
    first that applies, so no byte counts against two caps and none slips past both:
    1. live: reachable from a current head;
    2. window: reachable from a tree whose window is still running, declared by a commit newer
       than the window, or uploaded less than 24 hours ago without a commit;
    3. pin: reachable from the tree of an admitted pin; at most P;
    4. minimum count: reachable from a tree the minimum count holds within its cap; at most C.

    Everything else is deleted. A garbage collection step settles the pins first and then the
    minimum count, so a byte held by both counts against the pin cap, and when that pin lapses
    it moves to class 4 and is admitted there by the minimum count rules in the same step. While
    each cap counted only bytes "that nothing else retains", a byte held by both a pin and the
    minimum count counted against neither; the order of the classes closes that gap.
  - **No shared dismissal** (conclusion): "that was me" in the app hides the warning about a pin
    only on the device where the person chooses it; version 1 has no flag shared between devices.
    A `notice` comes from the server and cannot carry one, and a sealed record could be written
    by any device of the account, including the suspect device or a device it added to the log,
    which could then silence the one warning about itself on every device. The cost is one click
    per device. The pin itself stays until its 90 days end, it lapses under the pin cap, or the
    operator lifts it.
- **Restore:**
  - **A restore is a commit:** a normal commit on the current head, signed by the restoring
    device; the server has no special path for it.
    - A whole folder: the new commit's root is the root node ID of the chosen old commit.
    - A subtree or a file: the new root is the current tree with the old directory node or file
      manifest placed at the chosen path. Only the new directory nodes on the path to the root
      are uploaded.
    - The reference delta declares the restored objects again; chunks and manifests are not
      uploaded again.
  - **Only while retained:** the server accepts the restore only if it still holds every
    declared object, like any other commit. Otherwise the client shows the version as no longer
    available. The history marks expired commits; commits held by an admitted pin stay
    restorable for the pin period. Bytes a restore makes live again count against the quota and
    the upload budgets ("Quota and retained storage" below), so a restore can also wait for free
    quota or budget; bytes from the tree of an admitted pin are exempt from the budgets within
    the pin restore allowance ("Upload budgets" below).
  - **After a burst** (conclusion): the flow "burst, remove the device, reset the whole folder"
    against the rules of this section.
    1. Device D rewrites folder F. Its uploads pass the upload check and count against its
       device budget and the account budget, so at most B a day. The server pins P0, the last
       commit before the burst, and tells every device; the operator is warned that a budget was
       hit.
    2. The person removes D: its tokens end at once, the epoch rotates, a new folder key
       generation starts. D's uploads still count in the rolling 24 hours of the account budget.
    3. A device commits the root of P0 on the current head (expected head the current head,
       first parent the current head, the new generation and log head, so nothing goes back).
       Nothing is uploaded, so the headroom is not touched.
    4. Held objects: P0's objects that D replaced are in the window, held by the superseded heads,
       or, after the window, in class 3 by the pin. The commit is accepted for the whole 90 days
       unless the pin lapsed.
    5. Budgets: every revived object is in the tree of the admitted pin, so it costs no budget
       while the pin restore allowance has room. P0's tree was live, so it is at most `Q + H`,
       which the full allowance always covers. The restore runs at once, not after up to a day.
       If D used up the allowance before its removal, the rest counts against the budgets and
       waits at most a day, as without the allowance.
    6. Quota at commit: the commit is refused only if it raises the live bytes of chunks and file
       manifests above the quota, or all live bytes above the quota plus the headroom. Its result
       has the live bytes of the account at P0 plus whatever changed in the other folders since.
       The state at P0 passed the same check when it was committed, so with the other folders
       unchanged the restore passes; if D rewrote files in place, it usually does not even raise
       the live bytes. It can be refused only when the other folders grew since the burst. If D
       made them grow, undoing D in those folders first lowers the live bytes and frees the
       room; growth from honest devices is the person's data and
       needs room like any upload. No quota exemption is therefore needed. An exemption for a
       restore "not above the state before the burst" would change nothing, because the state
       before the burst is itself within the quota, except after the operator lowered it.
    7. Afterwards: the pin stays and holds almost nothing alone, because its tree is live again.
       D's commits are superseded and expire after the window. The restore drops D's garbage in
       one step, which can itself look like a burst and pin the garbage tree; that pin then sits
       behind P0 in the order and, since P0 holds almost nothing alone, fits and takes up to
       `Q + H` of the cap once the window ends, for its 90 days unless the operator lifts it.
       Later pins then keep their trees only for the window (open point for the external
       review).
  - **Item IDs** (conclusion): a whole-folder restore takes the old tree with its item IDs. In a
    partial restore, restored items keep their old ID unless that ID still exists in the current
    tree outside the restored path; then they get a new ID. If a different item holds the target
    name, the restored item becomes `<name> (restored <date>).<ext>`. New IDs rewrite only
    directory nodes, never chunks or manifests.
  - **Generations:** restored objects keep their key generation. A tree may mix generations, as
    it does after any device removal.
  - **Restore UI:**
    - A history per folder and per file, with server time, writing device and whether the tree
      has expired. An expired commit keeps only its writing device and its place in the order,
      because its server time is dropped (above).
    - "Undo a device": the person picks the suspect device and a start time (default: the
      server time of the commit the anomaly pin holds, otherwise the oldest retained commit). The app offers, as a
      whole-folder restore, the last head before the first head after that time that contains a
      commit by that device, as head or as side commit ([[threat-model-and-crypto-design]],
      section 4.2). It advises removing that device first, because otherwise it keeps writing.
    - A retired folder can be brought back within the window.
- **Quota and retained storage** (conclusion; [[threat-model-and-crypto-design]], section 4.2,
  says only "quota and rate limits per account and per device"):
  - **Live and retained bytes:** live bytes are the padded sizes of the objects reachable from
    the current heads of the account's folders. Retained bytes are those stored but no longer
    live.
  - **Account quota (operator-set):** limits live bytes only. Retained bytes do not count.
    Otherwise a compromised device could upload garbage, drop it in its next commit and lock
    every honest device out until the window ends.
  - **Checked at upload and at commit:**
    - `PUT /objects/{id}` is refused when the live bytes plus the uploading device's own
      uncommitted uploads plus the new object would exceed the quota. Only the device's own
      uploads count (amendment "One device cannot lock out the others"): counting every
      device's uploads let one compromised device block all the others with uploads it never
      commits. A commit only references objects the server already holds,
      but a delete or a partial restore still uploads the new directory nodes on the path to the
      root. Directory nodes (type 3, visible in the object header) may therefore use a headroom
      above the quota, operator-set, default 1% of the quota and at least 64 MiB (conclusion).
      Deletes then succeed at a full quota as long as the headroom is free, and they are the way
      to free the quota.
    - A restore or a dedup hit makes retained bytes live again without an upload. The commit call
      therefore refuses a commit that raises the live bytes of chunks and file manifests above the
      quota, or all live bytes above the quota plus the headroom (conclusion). A commit that does
      not raise the live bytes is always accepted, so deletes are never blocked by it. Live bytes
      then never exceed the quota plus the headroom.
  - **Upload budgets (operator-set):** bytes made live per rolling 24 hours: new uploads,
    counted at upload, and retained bytes that a commit makes live again (a restore, or a dedup
    hit on a retained object), counted at the commit (conclusion). Bytes that are already live
    cost nothing, so moves, renames and dedup hits on live objects are free. Otherwise a device
    could keep any amount of dropped data stored, by making it live again and dropping it, one
    quota at a time, before each window ends. Both budgets are separate from the account quota.
    - **Per device:** stops only the device that exceeds it. Default: half the account budget
      (amendment "One device cannot lock out the others"), so one device never uses up the
      budget of the others.
    - **Per account:** the sum over all its devices. Default: the account quota, so a first full
      upload fits in one day. It is needed because a compromised device can add devices to the
      account log, each with its own device budget, so device budgets alone bound nothing
      (conclusion).
    - **Side commits count** (conclusion, server security review H1): objects a side commit
      adds that a commit declared before and that are not live are retained again for the
      window, so they count as revived at the commit, like the head's revived objects, and the
      pin restore allowance below applies to them in the same way. Before, a device could
      upload garbage once, declare it in a side commit, and declare it again in a new side
      commit just before each window ended, keeping it stored for ever while paying the budget
      only once; the disk bound under "Disk sizing" did not hold.
    - **Pin restore allowance** (conclusion): retained bytes that a commit makes live again and
      that lie in the tree of an admitted pin cost neither device budget nor account budget, up
      to an allowance of P (the pin cap, `Q + H`) per account in any rolling W days; beyond it
      they count against the budgets as usual. It applies to every commit, because a restore has
      no special path. A restore after ransomware then does not wait for the budget that the
      harmful device used up, and one pinned tree always fits, since it was live and is
      therefore at most `Q + H`.
      - **Not unlimited:** without a bound, a device could keep the garbage of every pinned tree
        stored for the pin's 90 days, outside every budget, by reviving and dropping it before
        each window ends.
      - **Not charged to the pin cap:** charging free revivals against P itself would let a device
        revive the garbage of its own pin and so push an older, honest pin out of the cap. A
        separate allowance never changes which pins are admitted.
      - **Longer retention:** an object revived free and dropped again stays for the window after
        the drop. The latest free revival is at the end of the pin, so the allowance keeps pinned
        bytes at most W days beyond the end of their pin, and at most P of them for any window.
        "Disk sizing" counts it as a term of its own.
      - **Residual:** a device that is not removed yet can use up the allowance by reviving
        pinned objects. The honest restore then counts against the budgets and waits at most a
        day, as without the allowance.
    - Within one window an account can then make at most its account budget times the window,
      plus one day of uploads made just before it, plus the pin restore allowance, live, however
      many devices it has. With the defaults that is 31 times the quota plus `Q + H` (the full
      bound is under Consequences, "Disk sizing"); where several accounts share a disk, the
      operator lowers the account budget (open point for the external review: the default).
  - **Operator warning:** when an account's retained bytes exceed its quota, or a device hits
    its budget, or an account its account budget, or the bytes held only by the minimum count
    reach their cap, or the bytes held only by pins reach the pin cap, or a pin lapses, the
    server warns the operator and sends a
    `notice` to every device of the account. Remedies: remove the device (its tokens end at
    once) and, if needed, an operator purge through the server CLI.
  - **Disk reserve:** below a configured free disk reserve the server refuses all new uploads
    and warns the operator. It is the only limit that blocks honest devices because of
    something outside their account, and it means the disk is too small for the configured
    quotas. Within an account, see the amendment "One device cannot lock out the others" for
    what a compromised device can still block and for how long. Bytes that uploads in flight have
    announced but not written count as used, the reserve is checked again before an upload is
    stored, and each account has at most a few uploads in flight (server security review M5).
  - **Records** (conclusion, server security review L3): the sealed account records of an
    account are capped at R bytes in all (operator-set, default 64 MiB), and the server checks
    each record's signature with the sender's key from the verified log before it stores it,
    so only bytes a current device of the account signed take that room.
- **Client guards:**
  - A root marker file: when it is missing, the folder pauses instead of deleting.
  - A prompt above 100 deletions in one run (Nextcloud's default; OneDrive uses 200).
  - These guards stop accidental deletions before they are propagated. Mass rewrites, such as
    ransomware encrypting files in place, pass them; against those the server's retention and
    anomaly pinning apply.
  - Deletes are propagated after a short delay.
- **Residual risk: withheld log entries** (conclusion, app shell security review): the server
  cannot forge or reorder device log entries, but it can withhold the ones after a point it
  chooses, for one device or for all. A device then keeps working on the log it verified: a
  device removed later still looks current to it, an epoch rotated later is not used, and a
  recovery or pairing joins at an older head. Nothing in version 1 proves to a device that it
  has seen the newest entry; the frontier rule and the safety numbers only show the
  inconsistency once two devices compare or the server lets the entries through (the freeze of
  section 4, "Versions"). The recovery computes the head after its own append itself and
  refuses a server that reports another one (security review I1), which closes the made-up
  anchor, not the withheld tail. Accepted for version 1; a signed log head with a timestamp
  that every device must see refreshed within a bound is the follow-up.

### 6. Transport and access

- **TLS 1.3:** at the server or at a reverse proxy. The client refuses plain HTTP except for
  `localhost`, and self-signed setups use an SPKI pin from the pairing offer. There is no switch
  to accept invalid certificates.
  - **Server URL check** (conclusion, finding M2): the URL is parsed with the WHATWG URL
    Standard parser (`url`, the one reqwest uses), so the host checked is the host the client
    connects to. Allowed are `https`, and `http` only with the host `localhost`, `127.0.0.1` or
    `::1`; a URL with a user name or password is refused (this closes forms such as
    `http://localhost:80@evil.example/`), as is any form other than `scheme://host` and any URL
    with a query or a fragment, since the client joins API paths onto it. Only the parsed URL is
    passed on, and an offer carries it in the parser's serialization.
- **Pin rotation** (conclusion; [[threat-model-and-crypto-design]], section 5, covers the pin
  only at pairing):
  - **Mismatch:** a device whose pin does not match the server's key ends the connection during
    the TLS handshake, before it sends a proof or token. It keeps working locally and tells the
    person that the server identifies itself differently than usual. It never learns a pin from
    the server itself, and there is no button to accept the new key.
  - **Only two sources for a new pin:**
    1. A new pairing offer from a device that already trusts the new key. A device that scans or
       pastes an offer of its own account (the same account ID and server ID, and a log head that
       its verified log contains or that it then verifies as an extension) takes only the server
       URL and the pin from it and does not pair, and only if the offer's signature verifies
       against the inviter's key in its verified log and the inviter is a current, regular device
       there (section 4, "Signed offer").
    2. A confirmed comparison with the server CLI. The device shows the server key number of the
       key it now sees, the operator runs a server CLI command that prints the number of the
       server's own key, and the person confirms that both rows match. The confirm button is
       disarmed for a moment, as for the safety number ([[threat-model-and-crypto-design]], R8).
       The first device after a key change can only take this path.
  - **Server key number:** 30 digits in six groups of five, the layout of the safety number,
    so the UI shows it as a row of numbers to compare and never calls it a fingerprint. Each
    group is five bytes of `SHA-256(field("hangar-drive/v1/server-key-number") || field(server
    id) || field(SHA-256 of the SPKI))`, read as a big-endian integer modulo 100000. Binding the
    server ID means a number from another server never matches.
  - **Never silent:** no trust on first use after a change, no automatic acceptance of any key.
    A certificate renewed with the same key keeps its SPKI and needs no rotation; the
    self-hosting guide tells operators to keep the key.
  - **Public CA:** a server with a certificate from a public CA, for example Let's Encrypt, needs
    no pin: the offer carries none, the device uses the platform verifier, and renewals change
    nothing. A pinned device moves to the platform verifier only through an offer without a pin
    from a device of its account, never because a certificate from a public CA appears.
  - **Not chosen:** a rotation message signed with the old key. It needs the old key to survive,
    which a broken or expired self-signed setup often lacks, and it would add a server signing
    role for transport only.
- **Accounts:** an account needs a single-use, expiring invite that the operator creates on the
  server.
- **Device sign-in:** an Ed25519 challenge proof bound to the server ID, the server URL, the
  account and the protocol version. Sessions use short-lived bearer tokens that the server stores
  only as hashes.
  - **Server URL** (conclusion, app shell security review, open point "session binding"): the
    server ID is public, so a recovery sheet or link with the real server ID and a foreign URL
    would let that host relay a device's sign-in to the real server and hold the session. The
    statement therefore carries the base URL the device connects to
    (`hangar_drive_crypto::session::base_url`, the parser's serialization ending in `/`), the
    proof request names it, and the server refuses a proof for any other address than
    `HANGAR_DRIVE_PUBLIC_URL`. That setting is required (conclusion after the end-to-end test):
    `serve` does not start without it and says how to set it, so the binding cannot be off by
    an omission; the admin commands run without it, and a proof is then refused. Test
    `the_server_does_not_start_without_its_public_url`. The SPKI is not bound: TLS ends at the
    reverse proxy, so the server does not
    know the key its clients see. Vector `session.proof`, test
    `a_proof_for_another_address_is_refused_by_a_server_with_a_public_url`.
  - **Stateless challenge** (conclusion, server security review M1): the 32 challenge bytes
    are `expiry (u64, ms) || nonce (8) || the first 16 bytes of HMAC-SHA-256(server secret,
    label || server || account || device || expiry || nonce)`. The server secret is 32 random
    bytes made at the first start in the data folder (`server.secret`). A challenge request
    writes nothing; the proof checks the tag and the expiry, and only a challenge whose proof
    verified is remembered until it expires, so it is accepted once. The device signs the 32
    bytes as before; the wire format is unchanged.
- **Sessions:** a token lives about one hour, is renewed by a new proof and is revoked at once
  when the device log removes the device. Tokens never appear in URLs or logs.
  - **Removed device** (conclusion, finding E2E-3): a removed device can no longer read the
    log that says so. A proof that verifies with the key the log last listed for a device the
    log removed is therefore answered with `DeviceRemoved` (403), the challenge used up, and
    not counted as a failed proof; any other bad proof stays `ProofInvalid`, so only a holder of
    that key learns of the removal. The proof names the length of the log the device verified
    (`ProofRequest::log_length`, a hint outside the signed statement), and the answer carries
    the log entries after it up to and including the removal, at most `MAX_LOG_PAGE`
    (`ErrorBody::removal_log`). The engine counts `DeviceRemoved` only as the answer to its own
    proof call; it forgets the account at once (security review L1, `account::forget`) and shows
    "removed by ..." when those entries continue its own verified log with a valid removal of
    itself (`AccountState::removal_in`), and otherwise stops syncing, shows the server's report
    and forgets only once the person confirms ("Follow-up check of the overall security
    review" below); `ProofInvalid` never does that. A recovery device answered so means "this
    code was used before" (E2E-5). `SessionError::Removed` in `hangar_drive_crypto::session`.
  - **Scope:** the server sets a session's scope at sign-in from the verified log. A regular
    device may make every call; a recovery device only the calls of the recovery session
    (section 4, "Recovery session").
- **Rate limits:** per IP and per account on the challenge, proof, invite, pairing and upload
  endpoints.
  - **Shape** (conclusion, server security review M1, M6): the limits are checked before a
    body is read. Each public endpoint is limited per address (IPv4, IPv6 /64) and, with four
    times the limit, per network (IPv4 /16, IPv6 /48). Sign-in is limited per account only by
    failed proofs, keyed by account and device and only for devices the log lists, so nobody
    can fill the table with invented accounts or lock an account out with challenges. A proof
    counts only after its check failed, and a valid proof always goes through, also over the
    counter (overall review M1). A full
    table evicts the entries whose window ended, oldest first. A public body must arrive
    within 10 seconds; connections per address are capped in the accept loop, except for
    trusted proxies, which limit per client themselves. Calls with a bearer token are limited
    per address and network before the token is looked up (overall review, info).
- **Client IPs:** taken from `X-Forwarded-For` only when the operator has marked the proxy as
  trusted. No proxy is trusted by default, and the self-hosting guide names the exact proxy
  address to trust, never a whole private range (server security review L1).
- **Docker defaults:** the image runs as non-root, and Compose binds to `127.0.0.1` by default,
  with a memory and a process limit (server security review M4, L7).
- **Admin commands** (conclusion, server security review L5, L6): `gc` and `purge` refuse
  while the server runs on the same data folder, which it holds locked (`server.lock`); a
  folder purge is confirmed by typing the folder ID.

### 7. Cross-platform name policy

- Names in the protocol are compared in NFC. The exact bytes from disk are kept.
- Case-only and normalization-only collisions become conflicts. A case-only rename is a rename.
  - **Case keys** (conclusion, finding M3): two names collide by case when any of three keys of
    their NFC forms is equal: the full lowercase, full Unicode case folding (which joins `ſ` with
    `s` and `ς` with `σ`, as APFS does) and the per-character simple uppercase (which joins `ı`
    with `i`, as the NTFS upcase table does). A false collision only makes a conflict copy, a
    missed one would put two names on one file, so the keys err towards collisions.
- Names that are invalid on Windows are marked "cannot sync on this device" and are never renamed
  silently. This covers reserved names even with an extension (`CON`, `PRN`, `AUX`, `NUL`,
  `CONIN$`, `CONOUT$`, and `COM` and `LPT` with a digit 0 to 9 or a superscript ¹ ² ³; conclusion,
  finding L4), `< > : " / \ | ? *`, control characters, a trailing dot or space, and names of
  more than 255 UTF-16 code units.
- **Display names** (conclusion, finding L3): device, folder and pairing names refuse control
  characters, format characters (General Category Cf, which holds every bidirectional control)
  and line and paragraph separators, so a name cannot reorder or hide the text of a prompt such
  as "Add device <name>?". File names keep their bytes; the app shows them isolated.
  - **Blank and padded names** (conclusion, finding N5): a display name also needs a visible
    character and must not start or end with white space. A name made only of white space, of
    the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0 (letters that render blank), or of a
    mix of both is refused, so a prompt cannot show an empty name or a name padded to look like
    another one. A padded name is refused rather than trimmed, because the name is signed and
    sealed as given; callers trim user input before they submit it. Fillers inside a name stay
    allowed, since Korean text may use them.
  - **Visible character and padded edges** (conclusion, overall security review N12): a visible
    character is a letter, number, punctuation or symbol (General Category L, N, P, S) that is
    no filler; the blank Braille pattern U+2800 joins the fillers. The combining grapheme joiner
    U+034F and the variation selectors are combining marks and never visible, and a name may not
    start or end with them or a filler, except a variation selector right after a visible
    character, which belongs to it (an emoji such as U+2764 U+FE0F). The rule is decided by what
    a character is not (white space, Cc, Cf, Zl, Zp, M, Co, a filler, a default ignorable code
    point), so any other unassigned code point counts as visible until the tables know it.
    Default ignorable code points
    (`Default_Ignorable_Code_Point`, reserved ones such as U+2065 included, `DEFAULT_IGNORABLE_RANGES`)
    render as nothing in any renderer, so they are never visible and pad an edge like a filler
    (follow-up check of the fixes: before, a name of U+2065 alone passed as not blank). Vector
    `name.display_names`.
- **8.3 short name aliases** (conclusion, overall security review N14): a name of the shape of
  a short name (a base of at most eight characters ending in `~` and digits, an optional
  extension of at most three) is marked "cannot sync on this device" on Windows
  (`WindowsNameProblem::ShortNameAlias`). Windows opens a path by its short name too, so such a
  name can address another entry: `HANGAR~1` at the root is usually `.hangar-drive`, and a write
  under it would land in the reserved directory past the ignore list. Which short names exist
  depends on the volume and the order of creation, so every name of that shape is refused, not
  only the reserved one; elsewhere such names sync as usual.
- **Shell junction names** (conclusion, follow-up review of the Windows handles, M1): a name
  that ends in a dot and a GUID in braces (`Bilder.{0AFACED1-E828-11D1-9187-B532F1E9575D}`) is
  marked "cannot sync on this device" on Windows (`WindowsNameProblem::ShellJunction`). The
  Explorer shell takes such a folder for the namespace extension the GUID names; with
  `CLSID_FolderShortcut` and a `target.lnk` inside, a shell path through it resolves to the
  link's target, which another device could otherwise sync into a root. Files of that form are
  refused too; elsewhere such names sync as usual.
- **Code points HFS+ ignores** (conclusion, overall security review N15): the case keys drop
  U+200C to U+200F, U+202A to U+202E, U+206A to U+206F and U+FEFF before they are computed, the
  code points HFS+ ignores when it compares names (Apple TN1150, not measured on a volume), so
  two names that differ only in them collide by case and become a conflict copy instead of two
  names on one file. The comparison key keeps them.
- Long paths: the app manifest declares `longPathAware`, and file system calls use `\\?\`
  paths, because the manifest alone works only when the `LongPathsEnabled` registry value is set.
- 8.3 short names from watcher events are resolved to long names before matching.
- **Reading a file** (overall security review N6): the open uses `FILE_OPEN_REPARSE_POINT` on
  Windows and `O_NOFOLLOW` on Unix and refuses a handle that is a reparse point, so a link put
  in place of the file is never read through. The directories above the file are opened by
  handles as well, each relative to the one above it (amendments "Directory handles on Unix" and
  "Directory handles on Windows", L1), so a directory swapped for a link or junction between the
  check and the open changes nothing: the engine reads the file in the directory it checked.
  Before the Windows amendment the directories were checked by path on Windows, and a program
  that may write in the sync root could swap one of them for a junction in between and make the
  engine read, and upload, a file from outside the root.
- Locked files (sharing violations from Office, antivirus, the indexer) are retried with backoff
  and never block the whole run.
- Downloads go to a temporary file and are renamed atomically.
- **File IDs on Unix** (conclusion, acceptance review): device and inode alone do not identify
  a file, because Linux gives a freed inode number to the next new file at once (9,998 of
  10,000 delete and create cycles on ext4 below overlayfs, [[unix-inode-reuse-measurement]]). A
  file another program deleted and created again with the same size and mtime would then pass
  the replace check (L3). The file ID on Linux and macOS therefore mixes the birth time
  (`stx_btime` from `statx`, `st_birthtime`) into device and inode; it is set once per inode and
  survives writes, renames, time and mode changes, so a move keeps its ID. `st_ctime` is not a
  fallback: it changes with every rename and every time or mode change (same measurement), so
  moves would lose their ID, a directory would get a new ID with every entry added to it, and
  the engine's own `set_meta` would read as a replace. Code:
  `crates/hangar-drive-sync/src/localfs/unix.rs` (`unix_id`, read through `statx` relative to a
  directory handle since the amendment "Directory handles on Unix", with the same values std's
  metadata gave on glibc and macOS).
  - **Residual risk:** where the file system reports no birth time (ext4 with 128 byte inodes,
    ext3, 9p, NFSv3, many FUSE file systems, and kernels before 4.11 without `statx`),
    the ID stays device and inode. There, a file another program deleted and created again
    with the same size and mtime (to the tolerance) on the same inode is taken for the expected
    one: an incoming replace overwrites the other program's file instead of keeping it as a
    conflict copy, and an incoming delete moves it to the trash. The same holds for two files that get the same inode
    within one timestamp tick on a file system with coarse timestamps. The inode generation
    (`FS_IOC_GETVERSION`) would close part of it, at the cost of opening every file during a
    scan; open point.
- mtime counts only together with a hash, with a 2 s tolerance on FAT and exFAT.
- Alternate data streams and atime are not synced.

#### What is synced

The reports say nothing about links, empty directories, permissions or ignored names beyond ADS
and atime. Everything in this subsection is a conclusion of this ADR.

| Entry | Version 1 |
| --- | --- |
| Regular files | synced: content, size, mtime and the execute flag |
| Directories, also empty ones | synced; an empty directory is a directory node with zero entries |
| Execute permission | one flag, bit 0 of the entry `flags`. Linux and macOS read it from the owner's execute bit and set or clear it when writing. Windows cannot see it: a Windows device keeps the flag from the synced tree when it changes a file, and files it adds have it cleared. Other mode bits and owners are not synced |
| Hidden files and dotfiles | synced like any file. The Windows hidden, read-only and archive attributes are not synced |
| Files with the Windows system attribute | not synced (managed by the OS, for example `desktop.ini`) |
| Symbolic links, all platforms | not synced and never followed |
| Junctions, mount points and other reparse points on Windows | not synced and never followed. This includes other providers' cloud placeholders, so a scan never starts their download |
| Hardlinks | every name is synced as an independent file; the link is not kept, and equal content dedups to the same objects. The local index groups names that share a file ID, so a change through one name rehashes all of them, and a second name is never taken for a move |
| FIFOs, sockets, device nodes | not synced |
| Built-in ignore list | never added to a tree: `desktop.ini`, `Thumbs.db`, `ehthumbs.db`, `.DS_Store`, names starting with `._`, `Icon\r`, `$RECYCLE.BIN`, `System Volume Information`, `.Trashes`, `.Spotlight-V100`, `.fseventsd`, Office owner files `~$*`, Office temporary files `~*.tmp`, LibreOffice lock files `.~lock.*#`, and `.hangar-drive` at the sync root |

- **Reserved directory:** `.hangar-drive` at the sync root holds the root marker and the
  temporary download files. It lies on the same volume as the files, so the final rename is
  atomic. It is never synced.
- **Part of the protocol:** the ignore list and the exclusion rules live in
  `hangar-drive-protocol` and change only with the protocol version, so every device decides
  the same and no device uploads what another ignores.
- **Entry kinds:** `kind` in a directory node entry is 1 for a file and 2 for a directory. A
  version 1 parser refuses every other value; links can come later as a new kind.
- **Sync root:** it must not be a reparse point and must not lie inside another provider's sync
  root. [[sync-prior-art-research]] (section 6) marks the second rule as an assessment.
- **Excluded or impossible locally:** a version 1 client never adds an excluded entry to a tree.
  If an incoming tree holds an entry this device cannot create, for example a name that is a
  symbolic link locally, the entry is marked "cannot sync on this device", as for invalid
  names, and the device never deletes it from the tree.

> [!question] Unverified
> - The exact names Office and LibreOffice use for owner, lock and temporary files on each
>   platform and version.
> - Whether reading a file behind another provider's cloud placeholder reparse point starts its
>   download, and which reparse tags such placeholders use.
> - Whether NTFS reports stale size and mtime for the other names of a hardlink until the file
>   is opened, which would make the file ID grouping above mandatory rather than an optimisation.

### 8. Dependencies decided here

- **`notify`:** the change watcher, CC0-1.0. CC0 is outside the MIT, Apache-2.0 and BSD policy.
  - It is accepted as a documented exception, as the sister app already does, because CC0 waives
    all rights and is more permissive than MIT.
  - The Linux backend's `inotify` (ISC, equivalent to MIT) needs no exception: ISC is on the
    license allowlist below.
  - The workspace MSRV goes to 1.91 together with the first change that adds `notify` 9.
- **`sqlx` (server metadata):** MIT or Apache-2.0, same stack as the sister relay server.
- **Not adopted:** `fastcdc` (no CDC in version 1) and `blake3` (HMAC-SHA-256 keeps the review
  surface at the primitives the sister app already uses).
- **`unicode-normalization` (NFC names):** `(MIT OR Apache-2.0) AND Unicode-3.0`. The Unicode
  data license is permissive.
- **License allowlist:** `deny.toml` in the project root enforces this section; the CI job
  `licenses` runs `cargo deny check licenses sources` on every push and pull request.
  - Allowed for every crate: MIT, Apache-2.0 (also `WITH LLVM-exception`), BSD-3-Clause, ISC,
    Zlib and Unicode-3.0. ISC and Zlib are permissive licenses equivalent to MIT; Unicode-3.0 is
    the data license above. This also covers `inotify` (ISC) and `ring` (`Apache-2.0 AND ISC`)
    without a crate exception.
  - Every other license is allowed only for the named crate, as an exception below.
  - Paths and licenses measured with `cargo tree -i <crate> --workspace` and `cargo deny list`
    against `Cargo.lock` of 2026-11-26.
- **`option-ext` 0.2 (MPL-2.0):** pulled only by `dirs-sys` 0.5 through `dirs` 7, which
  `hangar-drive-sync` uses directly and `tauri` and `tauri-build` use as well.
  - MPL-2.0 is a file-level copyleft: its obligations cover only the MPL files themselves. The
    crate is used unmodified from crates.io, so no project file falls under the MPL.
  - Shipping a binary keeps one duty: recipients must learn where the source of the MPL files is
    (MPL-2.0 section 3.2). The unmodified crates.io source satisfies it; the release's
    third-party notices name it.
  - Alternative: replacing `dirs` in `hangar-drive-sync` (for example with `etcetera`, MIT or
    Apache-2.0) would not remove the crate, because `tauri` pulls `dirs` anyway. Accepted.
  - The same reasoning applies to the MPL-2.0 crates Tauri pulls for HTML processing
    (`cssparser`, `cssparser-macros`, `dtoa-short`, `selectors`, through `dom_query` in
    `tauri-utils` and `wry`); they get the same exception. There is no alternative short of
    leaving Tauri.
- **`xxhash-rust` 0.8 (BSL-1.0):** pulled only by `notify` 9 (section 8, `notify`), not used by
  project code.
  - The Boost Software License 1.0 is permissive like MIT; it does not even require the notice in
    binary distributions, only in copies of the source.
  - Alternative: none short of replacing `notify` with own watchers per platform, which this
    section rejected. Accepted.
- **`webpki-root-certs` 1.0 (CDLA-Permissive-2.0):** the Mozilla root certificate data, pulled by
  `rustls-platform-verifier` in `hangar-drive-sync`. CDLA-Permissive-2.0 is a permissive data
  license (keep the license text, no copyleft). Accepted as an exception; the alternative would be
  dropping the platform verifier for TLS.
- **App shell** (conclusion, 2026-11-26): the desktop app (`src-tauri/Cargo.toml`, each with its
  reason there) adds the official Tauri plugins `dialog`, `notification`, `autostart`,
  `clipboard-manager`, `single-instance` (feature `deep-link`) and `deep-link` (MIT/Apache-2.0),
  `keyring` 4 with `keyring-core` for the OS keychain, as the sister app does, `qrcode` 0.15
  (MIT/Apache-2.0, without the `image` feature) for the pairing QR code, and `resvg` 0.50
  (Apache-2.0 OR MIT, without default features) as a build dependency that rasterizes the tray
  icons from `src/tray/icons/*.svg`. Four crates they pull need an exception, checked by
  `cargo deny`:
  - `clipboard-win` 5 and `error-code` 3 (BSL-1.0): the Windows clipboard of `arboard`, pulled by
    the clipboard plugin; BSL-1.0 is accepted on the same grounds as `xxhash-rust`, and the
    sister app ships the same crates.
  - `tiny-keccak` 2 (CC0-1.0): pulled by the deep link plugin through `rust-ini`,
    `ordered-multimap`, `dlv-list` and `const-random`; CC0 is accepted on the same grounds as
    `notify`.
  - `arrayref` 0.3 (BSD-2-Clause): pulled by `resvg` through `tiny-skia-path`, at build time only,
    so it is not part of the shipped app. BSD-2-Clause is BSD-3-Clause without the endorsement
    clause, so it is at least as permissive. Alternative: tray icons rasterized once and committed
    as PNGs, which drift from the SVGs the window generates and tests.
- **Signed updates** (conclusion, app shell security review): `tauri-plugin-updater` 2.14
  (Apache-2.0 OR MIT, without default features, with `rustls-tls` and `zip`) installs an update
  only when its minisign signature verifies against the public key in `tauri.conf.json`; it is
  registered only once that key and an endpoint are there, and the command `install_update`
  refuses until then. It adds `minisign-verify` (MIT); `reqwest`, `rustls` and `ring` are in the
  tree through the sync crate already. Key handling: [[0002-version-scheme]], "Signed updates".
- **Exceptions pinned to versions** (conclusion, security review I2): every license exception in
  `deny.toml` names the exact locked version (`notify@9.0.0`, ...), so a new version fails the
  check until its license was looked at again. `cargo deny --locked check advisories` runs in the
  job `licenses` too; the advisories it lists with a reason are the zbus 5 D-Bus crates merged
  into zbus 6 (RUSTSEC-2026-0370, -0371, -0372, Linux, through `keyring` and the notification
  and single instance plugins) and `proc-macro-error` (RUSTSEC-2024-0370) of Tauri's GTK 3
  stack. cargo-audit also warns about RUSTSEC-2024-0429 (glib 0.18 `VariantStrIter`, unsound,
  never called here) and RUSTSEC-2026-0543 (chrono, locked but in no build), which cargo-deny
  does not match against the graph.

## Consequences

- The data model and the crypto formats are fixed before any sync code exists, which is the
  cheapest moment to get them right.
- **Exact sizes:** the server cannot see them, because of Padmé padding. Small files cost one
  object each, and dedup is weaker than with CDC for files edited in the middle.
- **Visible metadata:** the server still sees object counts, object types and padded sizes,
  the padded sizes of records and sealed pairing names (overall security review N13; before,
  exact sizes, which told the number of folders, devices and generations),
  upload and commit times, which device wrote, the device log, the reference graph between commits and objects,
  merges, side commits and re-anchor commits, live and retained bytes, and upload volume per
  device. The README and
  the UI state this honestly.
- **One head:** a device publishes only while it reaches the server. Concurrent writers retry
  their merge, and the version that reached the server first keeps the name.
- **Commit bodies:** the bodies of heads are kept for the life of a folder, without server times
  or reference deltas once their trees expire. They hold no content, but show the server for as
  long which device wrote how many heads in which order; deleting the folder or an operator
  purge removes them. The commit table grows with the number of heads.
- **Disk sizing:** with quota Q, headroom H, account budget B per 24 hours, window W days,
  minimum count cap C, record cap R and pin cap `P = Q + H`, the objects and records one
  account can keep stored at a time T are bounded by `(Q + H) + B × (W + 1) + P + P + C + R`,
  that is `3 × (Q + H) + B × (W + 1) + C + R` (conclusion, from the rules of section 5; R and
  the side commit rules since the server security review, H1 and L3). Each stored object
  is in exactly one retention class (section 5, "Retention classes"), so the terms below never
  count a byte twice:
  - Classes 1 and 2, live or kept for the window at T: every such object was live at some time
    in the last W days, or was uploaded in them (side commits and uploads whose commit never
    came included). It was therefore live at the start of the window, at most `Q + H` because
    the upload and commit checks keep live bytes within the quota plus the headroom, or it
    became live later, in one of two ways. Either the budget counted it in the last W + 1 days, at
    most `B × (W + 1)`: a revived object at the commit that made it live, a new object at its
    upload. The extra day covers objects uploaded before the window and committed in it, which
    the commit does not count again; an upload without a commit is deleted after 24 hours, so
    none is older. A side commit retains only what it adds, for the window after its upload;
    each such object was uploaded then (counted at upload) or revived then (counted at the
    commit, H1), and a side commit never extends its base's tree, so side commits add no term. Or the pin restore allowance revived it free, at most P in the last W days.
    That allowance term is the longer retention of pinned bytes: at most P of them, for at most
    W days beyond the end of their pin.
  - Class 3, held only by admitted pins: at most P at every time, because the pin cap is checked
    in every garbage collection step, not only when a pin is made.
  - Class 4, held only by the minimum count: at most C.
  - Records: at most R per account, outside the object classes.
  - The bound holds after every garbage collection step; between two steps, objects that became
    deletable since the last one come on top.
  - With the defaults (B = Q, W = 30, C = Q, R = 64 MiB) that is `35 × Q + 3 × H + R`, plus the
    commit bodies, a few hundred bytes per head. The self-hosting guide explains this. The earlier bound,
    `34 × Q + H`, counted the pins as Q and had no allowance term; it also did not hold, because
    the pin cap was checked only when a pin was made.
  - **The pin attack, replayed** (section 5, "The attack it stops"): with the cap checked only
    at creation, 90 daily garbage pins of up to Q each could hold up to `90 × Q` in class 3 after
    their windows ended, far beyond the bound. With the lasting cap, the first garbage tree takes
    up to Q of P and every later one lapses when its window ends, so class 3 stays at most P.
    The garbage still in the window was paid from the budget and is inside `B × (W + 1)`.
    Reviving pinned garbage free to keep it stored is limited to P per window by the allowance.
- **Local plaintext:** synced files and the local sync index, which holds names, are plaintext
  on disk. Version 1 relies on OS disk encryption and says so.
- **Device trust:** one compromised device can read everything and lock out the others. Retention,
  anomaly pinning, removal notifications and the recovery code limit the damage, but it is
  inherent to devices with equal rights.
- **Server trust:** the backup protects against clients, not against the server or a lost disk.
  The documentation recommends a second copy (3-2-1), and a second backup target can come later.
- **Unreviewed protocol:** the protocol is built by hand from standard parts. An external
  cryptographic review and a penetration test of the server are **release blockers**. The review
  list is in [[threat-model-and-crypto-design]] (section 7.2); it also covers the conclusions of
  this ADR: the single head and its merge rules, the fork claim and the empty seen vector, the
  kept commit bodies, the change feed and record freshness, the quota, budget and pin rules,
  the minimum count cap and the disk bound, the lasting pin cap `Q + H` with admission in
  creation order and the retention classes, the pin restore allowance and its residual risk,
  the flow "burst, remove the device, reset the whole folder" without a quota exemption and the
  garbage pin a restore can set off, the re-anchor after an older server state with its
  residual risk, the republishing of account state and the re-anchor mark, the pin rotation and
  the server key number, the conflict link and the per-device dismissal of anomaly warnings.
- **Joint work with the sister project:** the shared crypto core needs a refactoring there.
  Until it lands, Drive's builds depend on a pinned commit of that repository.

## Evidence

- [[sync-prior-art-research]]: prior art table, Nucleus lessons, watcher limits per platform,
  placeholder APIs, storage and transport, Windows pitfalls, ransomware protections.
- [[threat-model-and-crypto-design]]: threat model per attacker, key hierarchy, formats,
  rollback and fork analysis, retention rules, reuse options, risks R1 to R12.

## Next steps

- [ ] `notify` spike on Windows: buffer overflow under bulk copies, rename pairing (measurement
      filed under `raw/`).
- [ ] Agree on the shared crypto core with the sister project.
- [ ] Protocol crate: item IDs, object and commit types (at most two parents, empty seen
      vector, commit `flags` with the re-anchor bit), directory entry kinds and flags with
      `conflict_of`, change feed entries, ignore list and name policy, with tests.
- [x] Server: accounts, invites, device sign-in, object store, commit log with compare-and-swap,
      change feed, retention with the minimum count cap, the pin cap checked in every garbage
      collection step and the retention classes, quota checked at upload and at commit,
      directory node headroom, device and account upload budgets that also count revived bytes,
      the pin restore allowance, the server key number in the CLI.
- [x] Self-hosting guide: check the reverse proxy defaults that affect 4 MiB chunk uploads and
      long-lived SSE connections (nginx `client_max_body_size`, `proxy_read_timeout`); explain
      disk sizing.
- [ ] Sync core with simulation tests (including the merge rules, the join of a non-empty local
      folder, long offline periods and the re-anchor),
      then the first end-to-end sync of one folder.

## Amendment 2026-11-26: own crypto crate first

- **Change:** `crates/hangar-drive-crypto` is built now as a standalone crate in this
  repository. It does not depend on the sister app's team crypto crate, neither as a git
  dependency pinned to a commit nor otherwise. This replaces, for now, the second point of
  "Code: option B" in section 4 and the matching point under Consequences ("Until it lands,
  Drive's builds depend on a pinned commit of that repository").
- **Why:** the labels of the sister crate are fixed to `hangar-team/v1/` in its code, so Drive
  cannot reuse its identity, log, epoch, record and recovery code under the `hangar-drive/v1/`
  labels this ADR requires ("Separate identities", section 4) without first changing that crate.
  A shared core can only be extracted after a refactoring there, which is agreed with the sister
  project before it starts. Waiting for it would block the protocol, the server and the sync
  core; a git dependency on today's crate would give Drive the wrong labels.
- **What stays the same:** the crate uses exactly the primitives, crates and versions of the
  sister crate (table in section 4, plus `hkdf`, `sha2`, `hmac`, `getrandom`, `zeroize` and
  `subtle`), so the review surface does not grow and the lock file holds no second copy of a
  crypto crate. Every label starts with `hangar-drive/v1/`. Code taken from the sister crate
  (MIT, same owner) carries a comment naming its origin.
- **Differences in substance** (conclusions, part of the external review): the account log has
  one member, no roles and its own entry kinds (create, add device, remove device, rotate
  epoch); while a rotation is due after a removal, it accepts only further removals and the
  rotation, and one added regular device from a recovery device. Records carry a version per record instead of a per-device counter; the replay guard
  refuses older versions and a different record under an accepted version. There is no history
  link, because folder key rings hold every generation.
- **Format changes after the security review of the crates** (2026-11-26, findings M1, M4, L1,
  L6; formats of version 1, nothing was stored before them, so the version bytes stay 1; the
  fixed vectors in `crates/hangar-drive-crypto/testdata/vectors.json` and `test_vectors.py`
  hold the new bytes):

  | Format | Change |
  | --- | --- |
  | Folder key ring | each entry is `generation (u32) \|\| created at log index (u64) \|\| FK (32)`; the index is at least 1, never decreases along the ring and is never above the log head index of the ring's record |
  | Pairing offer | the offer bytes are followed by the inviter's Ed25519 signature over `field("hangar-drive/v1/pairing-offer") \|\| offer`; the server URL is stored in the WHATWG serialization (for example `https://drive.example/`) |
  | Commit `flags` | bit 1 marks a side commit, in the signed body |
  | Log append call | `device_wrap`: the new device's wrapped key of the current epoch, with an add device entry; never together with rotation `wraps` |
  | Account record `device-names` | `0x01 \|\| count (u32) \|\| count x ( device id (16) \|\| field(name) )`, sorted by device ID; names follow the pairing name rule |

- **Rule changes from the same review** (conclusions): the log append call is one batch of
  removals with their rotation, or one added device, and leaves no rotation due (M5), with the
  one recovery exception of section 4; records and commits of removed devices need a current
  sender, the re-seal of every record and a barrier commit per folder (H1, sections 3 and 4);
  the recovery session scope (section 4); the side commit's generation and log head are not
  below its base's (L1); discarded re-anchor heads (L2).
- **Rule changes from the review of the sync engine** (2026-11-26, conclusions): the removal as
  a resumable job that any current device completes (N1, section 4, "A resumable job"); the
  check before a barrier needs a barrier permit of the last removal and reports the heads of
  removed devices it let in (N2); a name the file system reports as existing although the tree
  says it is free is marked "cannot sync on this device" (N3); device names in conflict copy
  names have `/ \ :` and the other characters Windows refuses replaced, and API paths are
  appended to the base URL's path instead of `Url::join` (N6).
- **Later:** the shared core stays the goal of option B. When it exists, Drive moves to it only if
  its formats produce the same bytes as `hangar-drive-crypto` under Drive's labels, checked
  against the fixed vectors in `crates/hangar-drive-crypto/testdata/vectors.json`; otherwise
  Drive keeps its own crate for the differing parts, because stored logs, records and commits
  must stay readable.

## Amendment 2026-11-26: app shell and the second engine review

Conclusions of wiring the desktop app to the sync engine and of the open points N1 to N5 of the
second sync engine review. Formats of version 1 that were never shipped change in place.

- **Recovery sheet, version 2 (N1, covers N6):** `0x02 || account ID (16) || server ID (16) ||
  genesis (32) || pin flag (0x00 or 0x01) || SPKI pin (32, with flag 0x01) || server URL`, in
  `hangar_drive_crypto::recovery::RecoverySheet`, with the vectors `recovery.sheet` and
  `recovery.sheet_unpinned` in `testdata/vectors.json`, recomputed by `test_vectors.py`.
  - **Genesis anchor:** the hash of the account's first device log entry. The first entry is made
    when the code is shown, before the invite is redeemed (`account::Genesis`), so the sheet can
    name it; nothing reaches the server before the typed check group, as before (ux-concept
    4.2.1).
  - **Recovery checks it twice:** the recovery session's verified log must start with the anchor
    (otherwise "unknown code"), and the new device joins with the anchor and the head of its own
    add device entry, so neither session can be handed another account's log or a made-up one.
  - **Pin:** a sheet printed for a self-signed server carries the pin this device trusts, so the
    recovery's first connection is pinned like a pairing's; a sheet for a public CA carries none.
  - Version 1 sheets (without anchor) are refused.
  - Superseded by version 3 (amendment "Recovery link bound to the code"): the anchor alone does
    not stop a forged account that lists the recovery device.
- **Log length (N4):** reading a device log refuses a server's page that claims more than
  `MAX_LOG_ENTRIES`, before any entry is read, and stops after at most that many pages
  (`recovery::fetch_log`, `Account::sync_log`).
- **Invite check (N3):** `checkInvite` answers the host in its ASCII (punycode) form, whether a
  label is punycode and whether the link pins a key, so the window can warn before anything is
  sent. A recovery checks the new device's name first and answers `blank` or `edgeWhitespace`.
- **Pairing confirmation (N2):** before a new device sends anything, `inspectLink` reads an
  invite, a pairing offer or a recovery sheet offline and names its host and account, so the
  person confirms them first; a pairing offer carries the account ID on both screens, and after
  joining `pairResult` carries the account's devices for the person to confirm as their own.
- **Re-seal without folders** (found while testing a renewed recovery code): a removal in an
  account without folders left the device names sealed under the old epoch, so a device added
  later could not read them. The re-seal is now due whenever an account record was sealed before
  the last removal, not only a folder key ring (`Account::reseal_due`).
- **Renewed recovery code (ux-concept 10.3):** `renewRecoveryCode` shows a new code; the typed
  check group adds its recovery device and then removes the old one with its rotation, so closing
  the dialog midway leaves the old code valid and a failure in between leaves both valid, never
  none.
- **Reserved directories (N5), mtime tolerance on Linux, invite link and `/join` page:** see the
  log entry of the same day; the server prints the whole invite link from
  `HANGAR_DRIVE_PUBLIC_URL`, with the pin only on request, and serves a static `/join` page under
  its own strict CSP whose first-party script builds the deep link in the browser, so the invite
  never reaches the server.
- **App shell:** the index and the shell's `settings.json` live in the platform's local config
  folder (`dirs::config_local_dir()/Hangar Drive`), which the root check refuses as a sync root;
  secrets only in the OS keychain (service `hangar-drive`, Windows persistence `Local`); one
  instance per user session in every build, because two instances on one index and one folder
  would fight over every file; autostart on by default, applied once in release builds.

## Amendment 2026-11-26: security review of the app shell

Fixes of the app shell's security review (M1 to M3, L1 to L7, I1 to I4), each with a test.

- **Clipboard (M1):** codes and pairing links are copied with `write_secret` of the clipboard
  plugin, which on Windows adds `ExcludeClipboardContentFromMonitorProcessing` (no history, no
  cloud clipboard) and elsewhere the clipboard managers' concealed hints, and cleared after a
  minute unless something else was copied (`src-tauri/src/clipboard.rs`). `readClipboardText`
  returns only a Hangar Drive link or a code, otherwise `""` (L2).
- **Recovery file (M2):** the save dialog starts in Downloads, and a place below OneDrive
  (`OneDrive`, `OneDriveConsumer`, `OneDriveCommercial`, registry), Dropbox, Google Drive,
  iCloud Drive, `~/Library/CloudStorage` or `~/Library/Mobile Documents`, or on a volume labelled
  "Google Drive", gives `SaveResult` `inCloudFolder`.
- **Print window (M3):** the sheet is served once from memory over the app's own scheme
  `hangar-print` under a random path, dropped and wiped when served, in an incognito WebView that
  may navigate nowhere else (L3); no `data:` URL any more.
- **Secrets on removal, reset and uninstall (L1):** a device that learns it was removed forgets
  the account at once (`device-identity`, `epoch-1` to the newest epoch plus a margin, the stored
  account and the folders' sync state; the files stay) and keeps the "removed" warning until it
  is set up again; `resetDevice` does the same without the warning; a join that fails after the
  identity was stored, or joins another account, leaves nothing behind. The NSIS uninstaller
  starts the app with `--uninstall-cleanup` (not on an update), which forgets the secrets and
  removes the index folder. Narrowed later to an uninstall with the "delete app data" box
  ticked, see the amendment "Installer upgrade keeps the device keys".
- **Defense in depth (L2):** accepting a pairing request and deleting a folder everywhere ask
  again in a native dialog that names the device and its safety number, or the folder. Folder
  places reach the backend only as tokens of `pickFolder`, `defaultFolderPlace` and
  `listAccountFolders`.
- **Navigation (L3), folder checks (L4), file manager (L5), bidi isolation (L7):** the main
  window is built in code with a navigation guard (own origin, the dev server only in a
  development build); a new root is checked before it is created
  (`roots::check_planned_root`); on Windows the file manager is driven through
  `SHOpenFolderAndSelectItems` and `ShellExecuteW` on a canonical path inside the folder; the
  backend's texts isolate names with RTL letters or bidi controls (FSI ... PDI) as the window's
  `isolateName` does.
- **Recovery head (I1):** see section 5, "Residual risk: withheld log entries".
- **Error report (I3):** paths in an engine error lose the user name (`~`, `<user>`).
- **Development builds (I4):** keychain service `hangar-drive-dev` and the index in
  `<local config>/Hangar Drive/dev/`.
- **Session binding:** section 6, "Server URL".

## Amendment 2026-11-26: end-to-end test against the real server

The end-to-end test `crates/hangar-drive-sync/tests/e2e_server.rs` (the real server with real
engines, file systems and HTTP clients) found six errors; each has its own test, and the core
flow runs without workarounds.

- **E2E-1, account creation:** the group check redeemed the invite without a session and then
  called endpoints that need one. It now has two steps: `Account::create_from` redeems the
  invite and stores identity and account at once, marked as not set up; `Account::finish_setup`
  signs in as the new device, reads what an earlier attempt got through and adds the first epoch
  and the device names. The engine carries an unfinished setup on at the next confirmation or
  tick, also after a restart, and the server answers a repeated creation (used invite, same
  account, the same entry 1 byte for byte) with the same success, so a lost answer does not
  strand the account.
- **E2E-2, first commit of a new folder:** section 3, "Unknown folder". The engine no longer
  swallows a failing folder round: after three failed rounds in a row the folder shows a banner
  (`refused`, or `quotaFull`, `serverDisk`, `updateRequired` by the error).
- **E2E-3 and E2E-5, removed devices:** section 6, "Removed device".
- **E2E-4, recovered device name:** the recovered device writes its name into the sealed device
  names, as pairing does; should that fail, `finish_recovery_cleanup` writes it after its
  re-seal.
- **E2E-6, device name on the server:** section 4, "Sealed name", and section 3, "Pairing
  slots".
- **Public URL required:** section 6, "Server URL".

## Amendment 2026-11-26: the window's last commands

The window called nine commands the app shell did not have yet (`disconnectThisDevice`, `undo`,
`restoreDeletedFolder`, `cancelRestore`, `redownloadFolder`, `getServerNumber`,
`confirmServerNumber`, `fixServerWithOffer`, `restoreRemoteDeleted`). They now run in the engine
(`crates/hangar-drive-sync/src/engine.rs`, `folder.rs`), with the shell as a thin layer; a test of
the shell (`every_command_the_window_calls_exists_with_its_arguments`) reads the window's bridge
and fails for a command the shell lacks or an argument name it does not read. Conclusions:

- **Disconnecting this device** (conclusion): after "these are not my devices" right after a
  join (security review N2) and from the device list, the device forgets the account at once, as
  a reset does (L1): its identity and every epoch secret leave the keychain, the account and the
  folders' sync state leave the index, and its session token, which lives only in memory, goes
  with the connection. It cannot take itself out of the account's log, since no device removes
  itself (section 4, the log rules), and the server has no call that ends a session; a token runs
  out on the server within the hour (`SESSION_SECS`). So the device stays in the log of that
  account until a device of that account removes it. That is harmless: the entry only names
  public keys, and the private keys that could use them are gone, so nobody can sign in as that
  device, open an epoch secret wrapped to it or sign anything in its name. A device the person
  pairs again later is a new device with new keys. Before any folder is chosen nothing of this
  device reached the other account. Tests `disconnecting_after_the_join_forgets_the_strangers_account`
  (engine) and `disconnecting_this_device_forgets_the_account` (shell).
- **Undo** (conclusion; section 5, "A restore is a commit"): "Keep this", a restored file, a
  folder reset and restored trash items answer with an undo token. The token names what the
  action changed in the remote tree, each item with its node before (`UndoState`), kept in memory
  for the last 20 actions. Undoing publishes the device's own pending changes first (a "keep
  this" lives on the disk until its round) and then a new commit that puts exactly those items
  back, so the history keeps both states and changes of other devices since stay. An item the
  server never held is left alone. Where no token can be drawn the window shows no "Undo".
- **Folders deleted everywhere** (section 3, "Folder list"): the sealed folder list carries no
  retired entries, so every device remembers the folders it saw in the list and keeps one that
  left it under "Gelöschte Ordner" for the retention window. Bringing one back undoes the retire
  call (`DELETE /api/v1/folders/{folder}/retire`, `ServerApi::bring_back`) and then names the
  folder in the list again; both steps may be repeated.
- **Restores that wait for the upload budget** (UX 9.1): a restore the server holds back with
  `budget_exceeded` is a stored job, tried again every 15 minutes and computed on the then
  current state; `cancelRestore` drops it, and a job that expired or no longer fits leaves the
  list.
- **Download again** (UX 8.2): only for a folder stopped because its marker is missing. The shell
  checks and creates the old place, and the folder forgets what it held on disk while it keeps
  its verified chain, marks and history, so its protection against an older state stays.
- **Pin rotation** (section 6): `getServerNumber` shows the server key number of the key the
  server presented in the aborted handshake (the HTTP client keeps its SPKI hash after a
  mismatch, `ServerApi::seen_pin`); `confirmServerNumber` takes exactly that key, after one more
  question in a native dialog that shows the number (security review L2, now three actions),
  and only while it is still the key of the number shown (`confirm_server_number(&pin)`, overall
  security review N7). An
  offer (`fixServerWithOffer`) gives only URL and pin, through
  `PairingOffer::server_address`; for an offer whose log head is newer than the verified log,
  the log is fetched through the offered address, verified from the anchor and the offer checked
  again, and the old address stays on any failure.
- **Files another device deleted** (UX 8.1): one activity entry per round and folder, with
  "Wiederherstellen", which restores every file of it that is still gone from the head before the
  round, in one commit; a file that came back meanwhile stays as it is.

## Amendment 2026-11-26: overall security review

Fixes of the overall security review of engine, crypto, protocol and server (H1, H2, M1 to M3,
N1 to N7, N12 to N15 and the info points), each with a test that replays the attack and fails
without the fix.

### Engine

Tests in `crates/hangar-drive-sync/tests/` unless named otherwise.

- **Pairing only without an account (H1):** `EngineCore::start_pairing` refuses while the device
  belongs to an account or a pairing is open, and `Account::join` refuses
  (`SyncError::AlreadySetUp`) before it writes anything when the keychain holds an identity or
  the index an account. The join stores its identity and epoch secrets under the same keychain
  names, so a compromised window could pair a set-up device into a stranger's account: its
  identity was replaced, the clean-up of a failed join deleted its epoch secrets, and the folders
  the person then added went to the stranger. A failed join now deletes exactly what it wrote
  (its identity, the epoch secrets it fetched, the account it saved), and a refused join ends
  the pairing instead of retrying. Test `pairing_guard.rs`, taken over from the review's proof of
  concept, and `a_join_over_a_stored_identity_touches_nothing`.
- **"Removed" from the server (H2):** `device_removed` counts only as the answer to the
  device's own proof (`NetError::DeviceRemoved`); on any other route it is a protocol error,
  since a token says nothing about which key made it. How the engine then decides was changed
  by the follow-up check (amendment "Follow-up check of the overall security review", H2): it
  forgets at once on a removal it verified in the log the server sends with the answer, and
  never by itself otherwise. Without such a removal it stops syncing, shows
  `Warning::RemovalReported`, signs in again once an hour with a fresh challenge and proof, and
  forgets the account (L1) only when the person confirms (`confirm_device_removed`, the
  shell's `confirmDeviceRemoved`); a proof the server accepts again ends the report. A clock
  set back since the last report makes the probe due at once (follow-up check of the fixes:
  before, the device stayed stopped until the clock caught up, also when the server accepted
  it again; `a_clock_set_back_does_not_stop_the_probes`).
  - **The trade-off against L1:** replaced by the follow-up check (H2 there): the automatic
    forgetting after three answers over a day is gone.
  - Tests `removal_report.rs` (`device_removed_on_the_feed_does_not_forget`, the confirmation,
    `a_bare_removal_answer_never_forgets_by_itself`, a server that accepts the device again),
    `removal_proof.rs`, `http.rs`
    (`device_removed_counts_only_as_the_answer_to_the_proof`) and the end-to-end flow.
- **Offers with a new server identity (M2):** `fix_server_with_offer` checks an offer whose log
  head is ahead of the verified log through a temporary connection to the offered address: the
  log goes into a fresh `AccountState`, which must contain the device's own verified head, and
  the offer's signature is checked against it. Nothing is stored and the account is not
  refreshed until the address is taken; before, the refresh through a forged offer's server
  stored its feed cursor (up to `u64::MAX`, a freeze) and records before the check. A feed
  sequence below the device's cursor is an older state: the cursor goes to 0, the whole account
  is read again and verified as always, and the window shows `ServerNotice::OlderAccountState`.
  Tests `older_feed.rs` (`a_forged_offer_touches_nothing_before_its_signature_is_checked`,
  `a_feed_sequence_pushed_to_the_maximum_does_not_freeze_the_device`).
- **Trees beyond the limits of a folder (M3):** decoding a server's tree stops at 512 levels and
  2^20 items before more objects are fetched (`codec::MAX_TREE_DEPTH`, `MAX_TREE_ITEMS`; 512
  levels is the deepest path macOS's `PATH_MAX` of 1024 bytes can hold, and 2^20 items keep the
  three trees of a folder below about a gigabyte), and `Tree::check` and the encoder's order
  walk the tree once, O(n), where the walk from every item to the root was O(n x depth). A head
  beyond the limits is taken into the verified chain and the history, but its tree never: the
  folder stops (`StopReason::TreeLimit`, `Warning::TreeLimit`), and "Undo a device" publishes on
  that head with the reference delta computed by `codec::reachable`, which lists a tree's
  objects without building it (bounded by `MAX_REACHABLE_OBJECTS`), then makes the folder
  active again. Measured (debug build, Windows): a chain of 40,000 directories is refused after
  513 directory nodes in about 40 ms, and `Tree::check` of it takes about 60 to 100 ms. Tests
  `tree_limits.rs`.
- **The confirmed server number (N7):** `confirm_server_number(expected_pin)` takes the key only
  if it is still the candidate of the number shown; `ServerNumberView::pin` (not serialized for
  the window) carries it to the shell. A number shown again for another key in between keeps
  the old pin. Test `the_server_number_confirmed_becomes_the_pin` (`commands.rs`).
- **No proxy for loopback (N5):** plain HTTP, allowed only to the loopback address, never goes
  through a proxy of the environment (`no_proxy`); for https the environment's proxy only
  tunnels the end-to-end checked TLS connection (`docs/self-hosting.md`, "Forward proxies on the
  devices"). Test `http_proxy.rs`.
- **Reading a file (N6):** section 7, "Reading a file", with its residual risk. Test
  `a_link_in_place_of_a_file_is_not_read` (`localfs.rs`); it needs the right to create symbolic
  links, which Windows grants only in developer mode, and skips without it.
- **Info:** the quarantine is cleaned with every hourly scan (`FileSystem::housekeeping`), not
  only when a root is opened (`the_quarantine_is_cleaned_while_the_root_stays_open`);
  `inspectLink` names a punycode host for a pairing offer and a recovery sheet as for an invite
  (`InspectedLink::*::punycode`, `inspect_link_names_a_punycode_host_of_an_offer_and_a_sheet`);
  the pin mismatch flag explains only a failure of the TLS handshake, so a timeout after a
  mismatch is "unreachable" (`a_later_timeout_is_not_reported_as_a_pin_mismatch`); release
  builds keep integer overflow checks (`[profile.release] overflow-checks = true` in the root
  manifest, with its reason).

### Crypto and protocol

- **Signature before the log (M2):** `PairingOffer::server_address` checks the signature first
  when the inviter is a current, regular device of the verified log, so a forged offer in a
  known device's name with a head far ahead is `Signature`, not `AheadOfLog`; only an inviter
  the log does not list yet makes the device fetch the log
  (`a_device_of_the_account_takes_url_and_pin_only_from_a_signed_offer`).
- **Display names (N12), short name aliases (N14), code points HFS+ ignores (N15):** section 7.
  Tests in `crates/hangar-drive-protocol/src/name.rs`, vector `name.display_names` (24 names).
- **Padmé for records and sealed names (N13):** formats of version 1 that hold no data yet
  change in place; the vectors and `test_vectors.py` hold the new bytes
  (`records_are_padded_with_padme`, `sealed_names_are_padded_with_padme`).

  | Format | Change |
  | --- | --- |
  | Sealed account record | the ciphertext seals `length (u64) \|\| plaintext \|\| zeros` to `padme(8 + len)`, checked strictly on opening (`OpenError::Padding`); the largest record is `MAX_RECORD_LEN`, the bound the server checks |
  | Sealed pairing name | the ciphertext seals `length (u64) \|\| name \|\| zeros` to `padme(8 + len)`; the server accepts 10 to 144 padded bytes (`SEALED_NAME_MIN_PADDED`, `SEALED_NAME_MAX_PADDED`) |
  | Pairing name key | HKDF info `field("hangar-drive/v1/pairing-name-key")`; the associated data keeps `pairing-name`, so no byte string serves as both |

- **Framing (info):** a field of 4 GiB or more panics as a documented invariant instead of
  saturating its length prefix, which gave two different field lists the same bytes
  (`framing::length_prefix`, also for the framed hash and MAC); every field is bounded far
  below that by the protocol limits before it is framed
  (`a_field_of_four_gib_is_refused_not_saturated`).
- **Keys only from the verified log (info):** `AccountKey::derive` and `RecordCipher::new` are
  crate-internal; outside the crate a record key comes only from `AccountKey::for_epoch` and
  `RecordCipher::for_epoch`, which check the secret against the epoch's commitment.
- **`MAX_GENERATIONS` (info):** a folder key ring holds at most 4096 generations
  (`folder_keys::MAX_GENERATIONS`); every device removal adds one to every ring, so the bound
  is far above any account's life, and a ring that claims more is refused before it is read,
  which bounds the work and memory of opening one.
- **Corrections of the design report** (info; the raw report stays as it was): Padmé pads every
  object, full chunks included, because the 8-byte length prefix makes a full chunk `4 MiB + 8`
  bytes, which pads to `4 MiB + 128 KiB` (about 3 %), not only a file's last chunk; and the
  pairing secret P is 128 bits (16 bytes, `recovery::ENTROPY_LEN`), as section 4 says, not 32
  bytes.
- **Fuzz targets (info):** `decode_sheet` (`RecoverySheet::decode`), `open_name` (sealed pairing
  names, `PairingSecret::open_name` is public for it) and `decode_api_json` (the JSON of the
  server API) in `crates/hangar-drive-crypto/fuzz`; they build with `cargo check`, a fuzz run
  needs nightly.

### Server

Tests in `server/tests/overall_review.rs` unless named otherwise.

- **Failed proofs (M1):** a proof is checked first; only a failed check counts against the
  device's failure counter, and only for a device the log lists, in the address branch (a proof
  signed for another URL) as in the signature branch. Over the limit a failing proof is answered
  `rate_limited`, but a valid proof always goes through. Anyone who knows the account and device
  IDs can send bad proofs in a device's name, so a counter that also refused the valid proof let
  a third party lock the device out; the counter guards nothing a valid Ed25519 proof needs.
  Tests `m1_a_third_party_does_not_lock_a_device_out` and the reversed
  `sign_in_invite_pairing_and_upload_are_rate_limited` (`flows.rs`).
- **Bring-back and the allowance (N1):** the pin restore allowance covers bringing back a
  retired folder once per pinned head. Migration `0003_overall_review.sql` adds
  `pins.brought_back_ms`; a bring-back takes the allowance only while no pin on that folder and
  head carries it, and sets it on all of them, so a pin of a later retirement of the same head
  does not reopen it. Otherwise a device could retire and bring back a pinned folder over and
  over for free, until the allowance it drained was missing for the restore it exists for. Test
  `n1_the_allowance_brings_a_pinned_folder_back_only_once`.
- **Folder removal after the collection (N2):** a folder the collection deletes gets a row in
  `folder_tombstones` in the same transaction, and the row goes only after the folder's
  directory was removed. While it exists, `find_or_create` refuses to make the folder ID again
  (`rate_limited`, retried by the device). Before, an upload between the collection's commit and
  the removal created the folder again, put its file into the old directory and lost it with
  the directory, while its row stayed: a committed object without a file. A tombstone left by a
  crash is finished by the next step of the account. Chosen over renaming the directory before
  the commit, which leaves objects without files when the transaction then fails or the process
  dies in between. Tests `n2_an_upload_while_a_deleted_folder_is_removed_is_not_lost` (the
  store stopped inside `delete_folder` through `Deps::store_layer`) and
  `n2_a_tombstone_left_by_a_crash_is_finished_by_the_next_step`.
- **Unlisted proxy (N3):** a request whose peer is a private, shared (RFC 6598), loopback or
  link-local address, sends `X-Forwarded-For` and is not a trusted proxy logs one `operator
  warning` per address (at most 64 addresses), since every client behind such a proxy shares its
  rate limits. The header stays ignored; a public peer with the header is an ordinary client and
  is not reported. A warning at start is not possible: the server learns its proxy only from
  the first request. Unit test
  `a_local_peer_with_a_forwarded_header_that_is_not_trusted_is_found_once` (`client_ip.rs`).
- **Memory of the largest commit (N4):** measured with a counting allocator
  (`server/tests/commit_memory.rs`, `#[ignore]`, release build): a commit with
  `MAX_REFERENCE_DELTA_IDS` (1,048,576) added IDs, a 67 MiB body, held 312 MiB of heap at its
  peak. Two causes: the IDs bound as one `Vec<String>` plus one JSON text (about 160 MiB), and the
  body buffer grown by doubling (a 128 MiB buffer and the copy from the 64 MiB one). The IDs
  now go to SQLite in pages of 4096, written straight into one reused text, and the body buffer
  is reserved at the announced `Content-Length` (within the limit). Peak after: 115 MiB, the body
  plus the parsed IDs. At the 80 MiB body limit, with a side delta, that is about 140 to 175 MiB
  per call, so `HANGAR_DRIVE_HEAVY_REQUESTS` stays at 4: about 0.7 GiB at most for four such
  calls, below the 1 GiB `mem_limit` of `docker-compose.yml`. SQLite allocates outside the Rust
  allocator; its share stays small, since each statement gets one page of IDs and its temporary
  tables spill to disk. The call with a million IDs takes about 45 s under the write lock, which
  is an open point for its own measurement.
- **Info:** `PRAGMA secure_delete=ON` on every connection, so deleted rows (token hashes,
  records, reference lists) do not linger in free pages of the database file or its copies
  (unit test `deleted_rows_are_overwritten`, `db.rs`); a server that terminates TLS itself sends
  `Strict-Transport-Security: max-age=31536000` without `includeSubDomains` or `preload`, which
  would bind hosts it does not serve, and a server behind a proxy sends none, since only the
  proxy knows whether every client reaches it over https (`tls_cli.rs`,
  `a_server_behind_a_proxy_sets_no_hsts`); calls with a bearer token are limited per address
  (3000 per minute) and network (12000) before the token is looked up, and the address limits
  of a route come before its token, the account limits after it, so a flood of made-up tokens
  costs no database read beyond the limit (`ratelimit::check_address`, `check_account`); the
  backup section of `docs/self-hosting.md` names the database file and `server.secret`.

## Amendment 2026-11-26: follow-up check of the overall security review

The last points of the follow-up check of the overall security review (N-1 to N-4), the
decision on H2 (a verifiable removal) and the skeleton check of device names. Each has a test
that fails without the fix.

- **Resetting a folder (N-1):** `reset_folder` changes the folder on every device, so the shell
  asks in the system's dialog every time, not only above a threshold, with the folder's name and
  the number of files that disappear: files of the folder's current state that the entry does
  not hold, counted by the engine before the question (`EngineCore::reset_folder_preview`,
  `ResetPreview`). Files that only change keep their history and are not counted. The window's
  own question is gone; "no" answers `null` and the window shows nothing (`resetFolder` answers
  `RestoreOutcome | null`). Tests `a_reset_preview_counts_the_files_that_disappear`
  (`crates/hangar-drive-sync/tests/commands.rs`), `a_folder_reset_runs_only_after_a_yes` and
  `destructive_commands_ask_natively_first` (`src-tauri/src/commands.rs`).
- **Removing devices after a recovery (N-2):** `finish_recovery_cleanup` asks in the system's
  dialog as soon as regular devices are to be removed and lists their names (isolated against
  bidirectional text); only devices the engine offered (`recovery_devices`) are passed on, so
  the engine never removes a device the question did not name. The used recovery device is
  removed without a question, as before. "No" answers `null` and the window stays at the step.
  Tests `the_recovery_cleanup_passes_on_only_offered_devices`,
  `destructive_commands_ask_natively_first`, and in the window "stays at the old devices after
  a no in the system's question".
- **Hiding warnings (N-3):** `dismiss_warning` (`dismissSuspect`) takes only the ID of a warning
  the engine shows at that moment; a made-up ID would otherwise hide a warning before it
  appears. Only "suspect device" (`Suspect`) is on the allowlist (`dismissible`), since it is
  the only kind with "That was me" in the window; every other kind is refused, and an old
  hidden entry of another kind no longer hides it. `RemovalReported` in particular can never
  be hidden, only confirmed. The list of hidden IDs keeps the newest `MAX_DISMISSED` (64); warning IDs
  are per folder and kind, so a device collects only a few, and the oldest fall out first. The
  question before turning autostart off stays. Tests `only_a_shown_warning_can_be_hidden`
  (`commands.rs`), `the_removal_report_cannot_be_dismissed` (`removal_report.rs`) and the unit
  tests in `crates/hangar-drive-sync/src/engine.rs`.
- **Limits of a folder on the disk (N-4):** `MAX_TREE_ITEMS` and `MAX_TREE_DEPTH` (section
  "Trees beyond the limits of a folder" of the overall review) also hold for the local scan
  and for the tree to publish (`FolderSettings::max_tree_items`, `max_tree_depth`, smaller in
  tests). The scan checks them while it walks, so a folder far beyond them is not read to its
  end, and the merged tree is checked before it is encoded, since disk and server can each be
  within the limits while their merge is not (`Tree::within`, O(n)). A folder beyond them stops
  with its own reason (`StopReason::LocalTooLarge`, `StopReasonApi::TooLarge`, "too large for a
  folder" in twelve languages) and publishes nothing: no other device would take such a tree
  in. It tries again with a full scan once the watcher reports a change in it (at most once a
  minute) or with the hourly scan. Tests `local_limits.rs` (too many items, too deep, a merged
  tree beyond the limit).
- **Verifiable removal (H2), decision of the main agent:** the server sends with `device_removed`,
  and only as the answer to the device's own proof, the signed end of the device log from the
  head the device names. The proof names it in the new optional field `log_length` of
  `ProofRequest` (not part of the signed statement; the session vector is unchanged), and the
  error body carries the entries in the new optional field `removal_log` (`ErrorBody`, a
  `LogPage`): the entries after that length up to and including the entry that removed the
  device, at most `MAX_LOG_PAGE`. The device checks them with the existing device log verifier
  from its own verified head (`AccountState::removal_in`: the first entry must be the one after
  the head and chain to its hash, every entry goes through `apply` on a copy). A valid removal of
  itself makes it forget at once and show who removed it; a bare code, a forged or missing
  entry, or a chain that does not start at its own head never makes it forget: the warning stays
  until the person confirms. The automatic forgetting after three answers over a day is gone.
  The HTTP client reads error bodies up to 1 MiB for this (`MAX_ERROR_BODY`).
  - **The trade-off against L1:** L1 forgets the secrets of a removed device so that a thief or
    the next owner finds nothing to open. The day without a confirmation kept L1 for a device
    nobody looks at, but it let any server, or anyone with a valid certificate for its name,
    wipe the keys of any device by saying "removed" for a day, which on the last device of an
    account without its recovery code lost the account. The log closes that gap from both
    sides: a real removal is signed by a device of the account, so a device that was really
    removed now forgets at once, sooner than after a day, which serves L1 better; and a server
    cannot forge a removal, since every entry must verify from the device's own head, so a
    false claim never wipes anything. What is left without the person is the case where the
    server will not or cannot show the removal: it withholds the log, the gap is longer than a
    page (more than 512 log entries since the device last synced), or the device's own head is
    no longer part of the server's log. Then the device stays stopped and shows the warning, and
    its keys stay until the person confirms. That is accepted: a server that withholds the log
    is not trusted with a wipe either, the keys of a removed device open only what the server
    still serves (it refuses the device's sign-in), and the device keeps reading its folders'
    plaintext from disk anyway.
  - **Privacy of the log end:** only a holder of the removed device's key gets the answer, the
    entries are the device log every device of the account reads anyway, and they stop at the
    removal, so the removed device learns nothing the account did after it.
  - Tests: `a_removal_counts_only_from_the_own_head` (`crates/hangar-drive-crypto/src/devicelog.rs`:
    the real removal, another device, no removal, a gap, a wrong first index, a broken signature,
    a removal signed by a key the log does not list); `removal_proof.rs` (a real removal entry
    forgets at once; a missing log, a log without the removal and a forged removal never forget;
    a chain said to start before or after the own head never forgets);
    `a_removed_device_loses_its_session_proof_and_commits_at_once` (`server/tests/flows.rs`: no
    log without a head, the log from the head up to the removal and not beyond it, verified by
    `removal_in`); `device_removed_counts_only_as_the_answer_to_the_proof` (`http.rs`: the proof
    carries `log_length`, the log reaches the engine); the end-to-end flows
    `a_removed_device_learns_that_it_was_removed` and `the_core_flow_works_against_the_real_server`
    now see the removal verified and forgotten without a confirmation, also for a device whose
    log end runs over a recovery device's entry.
- **Device names that look alike (skeleton check):** when a device is named or renamed and when
  a pairing request arrives, the engine compares the name with the names of the account's
  current regular devices (`EngineCore::similar_device_name`,
  `hangar_drive_protocol::name::looks_alike`): NFKC, default ignorable code points dropped, runs
  of white space as one space, full case folding, and a small homoglyph table
  (`name::HOMOGLYPHS`) for Latin, Cyrillic and Greek letters and the digits 0 and 1, taken from
  the single code point mappings of `confusables.txt` of Unicode Technical Standard #39
  (Unicode 16.0) [UNVERIFIED: the entries were chosen from the standard's table and common
  glyphs, not checked line by line against the file]. The table is applied once before and once
  after folding, since a capital look-alike (Cyrillic `В` for `B`) folds to a small letter that
  looks like nothing Latin; two names look alike when either skeleton is equal. False positives
  cost a hint and a question, a miss lets a stranger's device pass for one of the person's own,
  so the check errs on the side of "alike". A pairing request carries the name it looks like
  (`PairRequestView::similar_to`): the window says "There is already a device with this name"
  and the native question before the device is added names that device. A rename to a look-alike
  name is refused (`DeviceNameError::LooksLike`) unless the shell asked natively and the person
  said yes (`rename_device(.., allow_look_alike)`); "no" shows the reason at the field. The
  recovery name of a new installation is not checked: the old devices it resembles are usually
  the ones the cleanup removes. Tests `look_alike_device_names_are_found` and
  `the_homoglyph_table_maps_only_to_basic_latin_and_once` (`name.rs`),
  `a_pairing_request_names_a_device_that_looks_the_same` and
  `a_rename_to_a_look_alike_needs_the_confirmation` (`commands.rs`), the questions in
  `src-tauri/src/confirm.rs`, and the window tests in `src/devices/devices.test.tsx`.

| Wire change | Where | Compatibility |
| --- | --- | --- |
| `ProofRequest.log_length: Option<u64>` | request of `POST /session/proof` | optional and left out when empty; a server of an older build refuses it as an unknown field (no build is released yet) |
| `ErrorBody.removal_log: Option<LogPage>` | `device_removed` answer of the proof | optional; replies ignore unknown fields |

## Amendment 2026-11-26: installer upgrade keeps the device keys

Finding HIGH of an independent security review: a manual upgrade or downgrade on Windows forgot
the device's account. The pre-uninstall hook (`src-tauri/windows/hooks.nsh`) started
`--uninstall-cleanup` whenever `$UpdateMode` was not 1, but the Tauri NSIS template of tauri-cli
2.12.6 sets that only when the installer itself runs with `/UPDATE`, which only the updater does.
An interactive installer of a newer or older version preselects "uninstall before installing" and
runs the installed version's uninstaller without `/UPDATE`, so the cleanup removed
`device-identity`, every epoch secret, the index and `settings.json` on each manual upgrade
([[tauri-nsis-uninstall-code-reading]]). With the updater off until the owner adds its key (see
[[0002-version-scheme]]), that is the only way to update. No build had been released, so no
installed copy carries the old hook.

- **Decision:** the cleanup runs only after the person's explicit choice:
  `${If} $UpdateMode <> 1` `${AndIf} $DeleteAppDataCheckboxState = 1`. The template's "delete app
  data" box on the uninstaller's confirmation page is always shown, unchecked, and read in
  `un.ConfirmLeave` before the uninstall section runs; silent and passive uninstalls leave it
  empty ([[tauri-nsis-uninstall-code-reading]]). The box is reliable in the reinstall path too,
  because that path runs the same uninstaller with its pages, so no extra message box is needed.
  Keeping the keys is the safe default on an upgrade: a lost identity means setting the device up
  again, a kept one costs nothing there.
- **Wording:** custom language files (`src-tauri/windows/German.nsh`, `English.nsh`, entered in
  `bundle.windows.nsis.customLanguageFiles`) replace the CLI's built-in ones, identical except for
  `deleteAppData` ("App-Daten und Geräteschlüssel dieses PCs löschen" / "Delete app data and this
  PC's device keys") and `${PRODUCTNAME}` instead of the placeholder the bundler leaves unfilled.
  They have to be compared with the built-in files after every CLI update.
- **Trade-off against L1** (amendment "Security review of the app shell"): L1 made every
  uninstall forget the device's secrets so that the next user of the PC finds nothing to open.
  That stays available, but as a choice: an uninstall without the tick, and every upgrade or
  downgrade, now leaves the device identity and the epoch secrets in the user's Credential Manager
  and the index in `%LOCALAPPDATA%\Hangar Drive`. Both belong to the same Windows user, who could
  read them while the app was installed anyway (SECURITY.md, "Installation per user"); a person
  who gives the PC away ticks the box or uses "Dieses Gerät zurücksetzen" first. The device stays
  in the account's log either way until another device removes it.
- **Tests:** `cleanup::tests::the_uninstall_hook_runs_the_cleanup_only_when_the_person_ticked_it`
  interprets the hook's conditions for every combination of the two variables (it fails with the
  old hook), and `the_delete_box_names_the_device_keys_in_every_installer_language` checks the
  language files and their entries in `tauri.conf.json`. The hook and both language files were
  compiled and run with makensis 3.13 in a harness ([[tauri-nsis-uninstall-code-reading]]). The
  real installer flow is a manual check before every release ([[0002-version-scheme]]).

## Amendment 2026-11-26: recovery link bound to the code

Finding LOW of an independent security review, "recovery link as phishing into a foreign
account". The recovery sheet's link carries server URL, pin and genesis anchor, and a link can
come from anyone. Whoever knows an account's device log (the server's operator, a copy of its
database) can build an account of their own: the same account ID, their own entry 1 and device,
the code's recovery device listed in it (its public keys and its proof of possession are public in
the real log, and the proof binds only account ID, device ID and the recovery flag), an epoch
secret they hold wrapped to its KEM key, and a link to their server with their own genesis
anchor. The real code then passed every check there (the log starts with the link's anchor and
lists the recovery device, current, with exactly the derived keys), and the new device joined an
account whose epoch secret the attacker knows: what the person then put into it was readable by
the attacker.

**Decision: recovery sheet, version 3, with an anchor tag.**

```text
sheet      = 0x03 || account ID (16) || server ID (16) || genesis (32) || anchor tag (16)
             || pin flag (0x00 or 0x01) || SPKI pin (32, with flag 0x01) || server URL
anchor tag = HKDF-SHA256(salt none, ikm = the code's 128 bit entropy,
                         info = field("hangar-drive/v1/recovery-anchor") || field(account ID)
                                || field(genesis), 16 bytes)
```

- `RecoveryCode::anchor_tag`, `RecoverySheet::new` and `RecoverySheet::is_for` in
  `crates/hangar-drive-crypto/src/recovery.rs`. The recovering installation checks the tag right
  after the code is typed and before it connects anywhere (`EngineCore::recover_account`), and
  `recovery::add_device_with_code` checks it again before it reads the log, so every caller of the
  recovery step does. A sheet that fails answers the new window code `wrongSheet`
  (`RecoverError::WrongSheet`, `RecoveryError::WrongSheet`), with the text
  `error.recovery.wrongSheet` in all twelve languages: the link does not belong to the code, take
  the link or QR code from the same sheet as the code, and do not use a link somebody sent.
- **Why it holds against the attack:** the attacker knows the complete log, every public key and
  the server database, but not the code. HKDF-Expand is HMAC-SHA256 under a key extracted from
  the code's 128 bits, a PRF, so without the code nobody can make the tag for any (account,
  genesis) pair, and a tag seen on a real sheet covers only the real genesis. The attacker's
  account cannot reuse the real genesis either: entry 1 is signed by the creating device and
  every later entry by a device the log lists, so a log that starts with the real anchor continues
  only with entries real devices signed, and an epoch secret is accepted only against the
  commitment such an entry carries. Forging a tag by guessing succeeds with probability 2^-128 per
  link the person opens. The check also keeps the recovery device's sign-in away from a server the
  code was not made for.
- **Why not the key derivation:** feeding the genesis anchor into the recovery device's keys would
  bind as well, but entry 1 lists the first recovery device, so the anchor (the hash of entry 1)
  depends on that device's keys: circular. Moving the recovery device out of entry 1, or a signed
  commitment in a later log entry, would change the log, the account creation and the server's
  admission rules; the tag changes only the sheet, which was never shipped.
- **Bound and not bound:** account ID and genesis anchor are bound. Server URL, server ID and pin
  are not: a server may move, and a wrong server cannot produce a log that starts with the real
  anchor (N1), so they need no binding of their own.
- **Code renewal:** every new code (setup, `renewRecoveryCode`, the new code after a recovery in
  `finish_recovery_cleanup`) makes its own sheet with its own tag over the same account and
  anchor, so a renewed code's link differs from the old one in the tag only. An old sheet's link
  with a new code is refused as `wrongSheet`, which tells the person to keep code and link of one
  sheet together.
- **Printed sheet:** the tag is part of the link and its QR code only; the sheet prints no field
  for it, since the person pastes or scans the link and never types its parts. No safety number
  was added: the cryptographic binding needs no comparison by the person.
- Versions 1 and 2 are refused (`SheetError::Version`); no build with either was released.
- Vectors: `recovery.anchor_tag` is new, `recovery.sheet` and `recovery.sheet_unpinned` are
  version 3, recomputed independently by `crates/hangar-drive-crypto/test_vectors.py`.
- Tests: `a_sheet_is_only_for_the_code_it_was_made_with` (crypto: another genesis or account with
  the real tag fails, another code fails, server URL, server ID and pin are free);
  `a_forged_account_that_lists_the_recovery_device_cannot_take_the_code`
  (`crates/hangar-drive-sync/tests/engine.rs`: the attack built from public data only on a second
  in-memory server, refused as `wrongSheet` before a single call reaches that server, refused by
  `add_device_with_code` on its own, then the control that the same forged account with a tag only
  the code holder can make would pass every other check, and the good case with the real sheet);
  `a_sheet_with_another_genesis_is_refused` (another anchor with the real tag is `wrongSheet`,
  another anchor with a valid tag is still refused by the log check as `unknown`);
  `a_renewed_code_replaces_the_old_one_after_the_group_check` (same fields, new link, old link with
  the new code is `wrongSheet`); window tests for the text and the mock.

## Amendment 2026-11-26: directory handles on Unix (security review L1)

Finding L1 of the independent security review (low): on Unix the directories between the sync
root and a target were checked by path (`symlink_metadata`, file IDs against the index) and the
operation then resolved the path again. A local program with write access in the sync root could
swap a checked directory for a symbolic link in between, and a write, delete, rename, directory
creation, metadata change or read landed outside the root.

- **Decision:** on Linux and macOS every operation of `LocalFs` goes through directory handles
  (`crates/hangar-drive-sync/src/localfs/unix.rs`). The root is opened with `O_DIRECTORY |
  O_NOFOLLOW`, each directory on the way with `openat` relative to the one above it and `O_RDONLY
  | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`; a link or a file on the way fails that open (`ELOOP`,
  `ENOTDIR`, `EMLINK` on FreeBSD) and is `FsError::Changed`, and where the index knows a
  directory's file ID the ID of the open handle (`fstat`) must match. The operation is relative to
  the handle of the directory that holds the target: `openat` with `O_NOFOLLOW` (reads also with
  `O_NONBLOCK` and a regular file check, so a FIFO cannot block), `statx` or `fstatat` with
  `AT_SYMLINK_NOFOLLOW`, `mkdirat`, `unlinkat`, `linkat`, `renameat2` with `RENAME_NOREPLACE` and
  `RENAME_EXCHANGE` on Linux, `renameatx_np` with `RENAME_EXCL` and `RENAME_SWAP` on macOS (the
  fallbacks of L2 and L3 unchanged, now handle-relative), and listings through `fdopendir` on the
  handle. A path is never resolved twice: a directory swapped after the walk changes only what the
  path means, and the operation stays in the directory that was checked, inside the root.
- **Reserved directory and cleaning:** `.hangar-drive/` and its levels are created with `mkdirat`
  and opened with `O_NOFOLLOW` (N5 unchanged in effect); emptying `tmp` at start enters only plain
  directories through their handles, at most 16 levels deep.
- **Stats:** `std::fs::Metadata` has no handle-relative form, so the module reads stats itself
  (`statx` with `STATX_BTIME` on Linux, falling back to `fstatat` where `statx` is missing, and
  `fstatat` with `st_birthtime` on macOS). Device (`makedev` of the `statx` halves), inode, birth
  time and modification time are the values std read before, so the file IDs in existing indexes
  stay valid (test `handle_stats_match_std_metadata`). musl builds now get the birth time too.
- **Dependency:** `rustix` 1.1 (features `fs`, `std`) for the Unix target, section 8 policy:
  Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT, Bytecode Alliance, already in the lock file
  through tempfile and polling, so no crate was added; safe wrappers, so the module has no unsafe
  code. Alternatives: `libc` directly (about fifteen unsafe blocks and an own directory reader),
  `nix` (no wrapper of `renameatx_np`). `libc` stays for `statfs` and `getuid`. `cargo deny`
  green.
- **Windows unchanged:** the IDs of the directories on the way come from handles opened with
  `FILE_FLAG_OPEN_REPARSE_POINT`, then the operation uses the path. Between that check and the
  operation a directory can still be swapped for a junction there (section 7, "Reading a file",
  residual risk); closing it needs `NtCreateFile` relative to a directory handle and a
  handle-based rename (`SetFileInformationByHandle` with `FileRenameInfoEx`), an open point.
  Closed by the amendment "Directory handles on Windows".
- **Open point, platform trash:** an incoming delete first checks the file through the handles,
  then hands the path to the platform trash (`NSFileManager trashItemAtURL` on macOS, the
  freedesktop trash in `crates/hangar-drive-sync/src/trash.rs` on Linux), which resolve it again.
  A swap in that window moves a file of the same name from outside the root into the person's own
  trash (recoverable, not deleted). The quarantine fallback is handle-based. The quarantine
  cleaning (`trash::clean_quarantine`, `housekeeping`) still walks by path below a checked plain
  directory; same class of race, open point. The quarantine cleaning goes through handles since
  the amendment "Directory handles on Windows", on both platforms; the trash hand-over stays open
  on Linux and macOS.
- **Network and WSL drives** (measured on WSL 2 drvfs, 9p): an operation on a handle whose
  directory was renamed after the walk fails with `ENXIO` instead of landing in the moved
  directory. Nothing outside the root changes there either; the engine retries on the next run.
- **Tests** (`crates/hangar-drive-sync/src/localfs.rs`, `link_swap_tests`, `cfg(unix)`): a sync
  root with `a/f` and `a/sub/` next to a directory outside it. With the link already in place,
  every operation (new file, replace, delete, trash, rename out of and into `a`, create and remove
  directory, metadata, read, stat, list) is `Changed` and nothing outside changes. With the swap
  made by a test hook exactly between the check and the operation (`race::arm`, per thread), each
  operation changes nothing outside and acts on the checked directory (now `a.moved`). Also: a
  directory replaced by another directory with a different file ID is refused, and a link at
  `.hangar-drive` is never followed, neither by a write nor by the cleaning at start. Run on
  Linux (WSL 2, ext4, kernel 6.18): all pass; the ten race tests fail against the code before this
  change with the same hook, so they reproduce the finding. CI runs them on `ubuntu-latest` and
  `macos-latest` (`cargo test --workspace`).

## Amendment 2026-11-26: one device cannot lock out the others

Security review findings MEDIUM 3 (one device locks every other device of the account out for
24 hours) and LOW 2 (event stream slots can be used up). Section 5 ("Checked at upload and at
commit", "Per device", "Disk reserve") is updated in place.

**The attack (MEDIUM 3).** With the old defaults (device budget = account budget = quota) a
compromised device uploaded a quota of garbage it never committed. The upload check counted
every uncommitted upload of the account, so every honest device got `quota_exceeded`, and the
account budget was gone as well (`budget_exceeded`). Removing the device freed nothing: the
`objects` rows did not say who had uploaded them, and the collection deleted them only 24 hours
after their upload. The attack could be repeated every day. Section 5 claimed the disk reserve
was the only case in which honest devices are blocked; that was wrong.

**Decision.**

- **Uploader per object:** migration `0004_device_uploads.sql` adds `objects.uploader`, the
  session device of the upload. Rows from before the migration keep NULL: a declared object no
  longer needs it, and an uncommitted one counts against no device and goes with the
  collection within 24 hours, as before.
- **Upload check per device:** `PUT /objects/{id}` counts live bytes plus the uploading device's
  own uncommitted bytes (instead of the account's) against Q and Q + H. One device's uploads
  therefore never take quota from another device. The running counter per device is the table
  `device_pending`, kept by triggers on `objects` (insert, `declared` 0 to 1, delete), so the
  commit call needs no change, and rebuilt by `usage::recount_pending` at every collection step.
  Measured: a commit that declares 200,000 uploads took 5.38 s with the triggers against 5.01 s
  without them (release build, Windows 11, the `m4_measure_a_large_delta` setup with and without
  an uploader; about 7 %).
- **What still bounds the uncommitted bytes:** every upload pays the budgets, so all devices
  together leave at most about one account budget uncommitted, which "Disk sizing" already
  counts as the day of uploads before the window. The commit check still holds live bytes to Q +
  H: two devices may each upload close to the quota, but only commits that fit go through
  (test `another_devices_uncommitted_uploads_do_not_count_against_the_quota`).
- **Removal deletes the uploads:** the log append that removes a device deletes its uncommitted
  objects in the same transaction (`objects::drop_uploads_of`) and recounts the counters; the
  files follow after the commit in the background under each object's stripe lock, as in the
  collection's sweep, and a crash in between leaves files without rows for the orphan sweep.
  Uncommitted objects have no references, so no tree changes. Each deleted byte is also taken off
  the removed device's budget minute in which it was paid, so the account budget it spent on
  garbage is free again at once. Only deleted bytes are given back; what the device made live
  stays paid, so adding and removing devices never keeps anything stored beyond the budgets.
- **Device budget default: half the account budget** (`config::default_device_budget`). A single
  device leaves the others at least as much budget as it can take. Rejected: an account budget
  of 2 Q with the device budget at Q, which keeps a full first upload within one day but doubles
  the `B × (W + 1)` term of "Disk sizing". The cost of the choice: one device uploads at most half
  a quota per day by default, so a first upload of a full quota from one device takes two days;
  the operator can raise the account budget or set the device budget to the account budget
  (`docs/self-hosting.md`).
- **What remains (conclusion):** a compromised device can still add devices to the account log,
  each with its own device budget, and spend the whole account budget through them. Adding a
  device is visible in the device log and on every device, and removing the added devices deletes
  their uncommitted uploads and gives that budget back. A device can also commit garbage and so
  fill the quota with live bytes; that is the person's data as far as the server can tell,
  visible in the history, and deleting it (directory nodes use the headroom) frees the quota.
  Only the disk reserve blocks honest devices for reasons outside their account.

**Event streams (LOW 2).** `GET /account/events` was limited to 32 streams per account and
2048 on the server, so one device could take all 32 slots of its account, and 64 accounts all
slots of the server. Now a device holds at most two streams (`events::MAX_STREAMS_PER_DEVICE`);
a third stream of the same device closes the device's oldest one instead of being refused. The
newest connection is the one most likely alive, so a half-open connection the server has not yet
noticed never keeps an honest device from reconnecting, and a device can only close its own
streams. A closed slot stops counting at once. The limits per account (32, still needed because a
device can add devices) and per server (2048) stay. The endpoint stays as well: the client does
not use it yet and polls the feed every 5 seconds; connecting the client to the stream is an open
point.

**Tests.** `server/tests/device_uploads.rs`:
`removing_a_device_deletes_its_uncommitted_uploads_and_frees_the_budget_at_once` (device A uses
up the account budget with uploads and commits one of them, B is refused, B removes A, the four
uncommitted rows and their files are gone, the counters are zero, the committed object stays,
and B uploads exactly the four refunded chunks at once),
`with_the_default_budgets_one_device_cannot_lock_the_others_out` (with the defaults A stops at
half the account budget and B still uploads and commits its half),
`another_devices_uncommitted_uploads_do_not_count_against_the_quota` (A's uploads fill the
quota, B uploads and commits all the same, A's commit of its garbage is refused, the collection's
recount agrees with the triggers), `a_third_event_stream_of_a_device_closes_its_oldest` (over
HTTP). Unit tests: `a_device_holds_at_most_two_streams_and_a_third_closes_its_oldest`
(`events.rs`), `device_budget_defaults_to_half_the_account_budget` (`config.rs`). The migration
was also applied to a database at 0003 with old rows (NULL uploader, triggers checked by hand
with Python's SQLite 3.50.4).

## Amendment 2026-11-26: collisions in linear time and copy names within the limit

Security review findings HIGH 2 (collision handling of the merge and the executor quadratic to
cubic) and LOW 3 (a conflict copy name longer than 255 UTF-16 units). Section 3, "Conflict copy
name", is updated in place.

**The attack (HIGH 2).** The merge fixed one collision per round and then started again from the
root; each round compared every pair of names of a directory, each comparison computing NFC and
six case keys, and `record_rekey` walked all rekeys. The executor compared every target name with
every sibling. Measured before the fix (release build, Windows 11, the machine shared with other
builds): an unchanged folder of 1,000 files in one directory 2.8 s (the review measured 112 s for
8,000), 256 case variants of one name 46 s, a join of 400 identical files 175 s, writing 2,000
new files 5.7 s. A compromised device could stop every device of the account with a directory of
20,000 files or a few thousand case variants, well inside `MAX_DIRECTORY_ENTRIES` (2^18) and
`MAX_TREE_ITEMS` (2^20).

**Decision.** The rule itself is unchanged, and every device still reaches the same merge:

- **Merge** (`merge.rs`, module docs): `fix_collisions` takes the fixes the round by round search
  would take, in the same order, in one walk per directory. The case keys of an entry are
  computed once per walk and looked up in hash maps (key to the first kept entry); a walk goes on
  where the last fix left it, because a fix never changes the entries ahead of it or their order
  (a renamed loser collides with nothing any more, a removed one is gone). Only a merge of two
  directories adds entries to another directory; that directory is walked again from its start,
  before the current one goes on if it comes first in the order (root, then item ID), as the
  restart did. Rounds in which orphans or cycles still change fix one collision each, as before;
  once they are settled, all remaining collisions are fixed in one go, bounded by the same round
  limit. Fixing a collision never makes an orphan or a cycle. `record_rekey` keeps a backward map,
  and `fix_cycles` first checks with one walk from the root whether any item has no path.
- **Copy names** (`names::DirNames`): whether a candidate collides is a hash lookup in the
  directory's key counts. Searching ` 2`, ` 3` and so on stays the rule, but the index learns
  which numbered names are taken: every number with as many digits shares stem, label and
  extension, so the name with number n is `P + n + Q`, and each case key of it is
  `key(P) + n + key(Q)` (space, digits and `)` are stable in NFC, map to themselves under every
  case mapping and end the context of a final sigma; the index checks the split on every name it
  tries, and a property test checks it on random names with combining marks, sigma, long s, the
  Kelvin sign, dotted and dotless i and ignorable code points). Losers that share `key(P)` and
  `key(Q)` skip the numbers known to be taken; when such a key leaves the directory the number
  is forgotten, so the result is always the first free name.
- **Executor** (`apply.rs`): an index of the working tree by case key per directory, built when a
  directory is first asked about and kept in step with every change of the working tree during a
  run, answers what `Tree::colliding_children` answered.
- **Keys of ASCII names** (`names::case_keys`): NFC, the HFS+ ignorables and the three case
  mappings are the identity or the ASCII mappings for ASCII, so the keys are computed directly;
  a test checks them against `CaseKeys::of`.

Measured after the fix (same machine and benchmark): 1,000 unchanged files 1.3 ms, 8,000 10 ms,
50,000 88 ms, 262,144 (one full directory) 0.67 s; 256 case variants 1.7 ms, 1,024 7 ms, 4,096
33 ms, 262,144 3.4 s; a join of 400 identical files 1.3 ms, 5,000 27 ms, 50,000 0.34 s, 262,144
2.5 s; writing 2,000 new files 5 ms, 20,000 54 ms, 262,144 0.98 s. The copy name search costs a
few key computations per copy and digit of its number, so the work is about n log n.

**Copy names within the limit (LOW 3).** `labelled` shortened only the stem, and an extension of
more than about 225 units still made a name longer than 255 units. The stem is now shortened
first, down to its first character, then the extension, and the label only when it alone would
not fit; an extension cut short loses trailing dots and spaces. Cuts fall between characters, so
no surrogate pair is split. A copy of a name Windows can hold is one Windows can hold: the label
`(...)` keeps the part before the first dot from being a reserved name or an 8.3 alias. Names
that fit with at least one character of the stem stay exactly as before. The measurements are
filed in [[merge-collision-benchmark]].

**Tests.** `merge.rs`: `linear_collision_fixing_equals_the_reference` (4,000 random merges with
case, NFC, long s, sigma and Kelvin collisions, numbered copy names, joins, orphans and cycles,
compared field by field with the old round by round implementation, kept as a test module),
`nested_directory_merges_equal_the_reference` (joins with nested directories merging into remote
ones in both ID orders), `record_rekey_equals_the_reference`, and
`collisions_take_linear_work`, which counts key computations in a debug build without a clock:
an unchanged folder of 50,000 files, a join of 5,000 identical files and 2,048 case variants.
`names.rs`: `indexed_copy_names_equal_the_plain_search` (entries come and go, also ones that look
like numbered copies), `copy_names_for_many_variants_take_linear_work` (3,000 losers in case and
long s variants), `keys_split_at_the_number`, `fast_keys_equal_the_protocol_keys`,
`long_extensions_fit_windows` (a 250 unit extension, an extension cut at spaces, surrogate
pairs, a 400 character device name). `apply.rs`: `sibling_index_equals_the_pass_over_the_directory`,
`many_new_files_take_linear_work` (20,000 new files).

## Amendment 2026-11-26: server notices reach the window, downloads respect the disk

Follow-up to a security review of the engine (MEDIUM 1, MEDIUM 2, LOW 4).

**Anomaly pins reach every device (MEDIUM 1).** The engine dropped every feed notice except three,
so section 5's "all devices are told through a feed notice" did not hold. Now
(`crates/hangar-drive-sync/src/engine.rs`):

- `Notice::AnomalyPin` is stored per folder and commit in the engine's settings (`pins`, at most
  32, kept across restarts because the feed tells each pin only once) and shown in every snapshot
  as `Warning::Suspect` with the folder, the pinned commit as the timeline entry, the retention
  days, the pin's end (`until`) and `lapsed`.
- The suspect device is the writer of the first commit after the pinned one in this device's own
  verified timeline (`burst_writer`), never a device the server names; the notice carries no
  device. Narrowed by the amendment "Follow-up review of the delta binding" (MEDIUM 3): a device
  is named only when its own verified heads after the pin drop enough to set off a burst. A device that does not sync the folder, or has not pulled the burst yet, leaves the
  device empty and the window names the folder (UX 9.4).
- A pin the pin cap lets go comes again with its end set to the server's now. A pin notice that
  ends within an hour of the device's clock, or earlier than known, marks the pin as lapsed (the
  margin covers clock skew; a fresh pin lasts 90 days). A pin leaves the device once its end plus
  the retention window has passed. "Das war ich" stays per device ("No shared dismissal"); the
  suspect warning is still the only one that can be hidden.
- `QuotaWarning`, `AccountBudget` and `DiskReserve` become the quiet notices `quota` (with the
  numbers on the storage line), `budgetAccount` and `serverDisk`; `MinimumCountCap` now names the
  retention window instead of 0 days. Quiet notices appear once each instead of piling up while
  the app runs. They have no "cleared" signal from the server and stay until the app restarts
  (open point below).

**Downloads respect the disk (MEDIUM 2).** A manifest may name the same chunk up to its limit
(`MAX_FILE_SIZE` 4 TiB) while the quota counts only distinct objects, so one small upload could
fill the disks of all devices, and `FsDisk::write_file` fetched every repeated chunk again. Now
(`crates/hangar-drive-sync/src/folder.rs`):

- Before anything is fetched, the free space of the sync root's volume
  (`FileSystem::free_bytes`, `crates/hangar-drive-sync/src/space.rs`: `GetDiskFreeSpaceExW` or
  `statvfs`; replaceable in tests through `MemFs::set_free_bytes`) must hold the file plus a
  reserve of 256 MiB (`DISK_RESERVE_BYTES`; since the amendment "Follow-up review of the delta
  binding", LOW 4, 5 % of the volume, at least 256 MiB and at most 10 GiB). Otherwise the write fails with `DiskFull`, nothing is
  fetched or written, the item backs off from one minute doubling to 32 minutes, and the window
  shows the existing `diskFull` banner with the bytes the waiting files need until they are
  written or the folder is in sync.
- Within one write, a chunk ID that comes again is kept as plaintext until its last use, up to
  64 MiB (`CHUNK_CACHE_BYTES`); beyond that it is fetched again, so memory stays bounded.
- One apply run fetches at most 1 GiB (`ROUND_DOWNLOAD_BYTES`); the first file of a run always
  goes, the rest waits for the next round, which checks the free space again.

**Incoming mass deletion has no threshold (LOW 4, open point).** `planner.rs` holds only local
deletions above the threshold for a decision. A mass deletion another device commits is applied
here without a question. The threat model treats this as inherent: a device of the account may
delete, and every deleted file goes to the recycle bin or the quarantine and stays in the server's
history for the retention window, so it can be brought back. Whether incoming deletions should
also wait above a threshold is an open product decision (it would let a compromised device's
deletions sit undecided on every other device, and hold up honest reorganisations). Decided in
the amendment "incoming mass deletes" (2026-11-27): they wait above a threshold.

**Open points.**
- Quiet notices end only with a restart; a "condition cleared" feed notice would let them go when
  the server clears the condition.
- The disk reserve is a constant; a setting may follow if it proves too much for small disks
  (now 5 % of the volume within 256 MiB and 10 GiB, see LOW 4 of the follow-up review).

**Tests.** `crates/hangar-drive-sync/tests/server_warnings.rs`:
`a_burst_by_one_device_warns_every_device` (A replaces every file, the memory server sends the
pin, B and A show "suspect" naming "Laptop" with the pinned commit as a timeline entry, "Das war
ich" on B hides it only there, a lapse marks it on A),
`quota_budget_and_disk_notices_reach_the_window_once`,
`a_download_waits_for_space_and_fetches_a_repeated_chunk_once` (a file of three identical chunks
is not written with too little space, the banner names its size, and after space returns every
object is fetched at most once). Unit tests in `engine.rs`
(`pin_notices_are_kept_once_and_a_lapse_is_noticed`, `the_burst_writer_comes_from_the_timeline`),
`space.rs`, `src-tauri/src/notifications.rs`, the decoder shapes in `src-tauri/src/commands.rs`,
and the window (`src/problems/problems.test.tsx`, `src/main/MainWindow.test.tsx`).

## Amendment 2026-11-26: reference deltas bound to the tree

Security review finding HIGH: no one checked a reference delta against the tree. The server
checked a delta only against its own view of the deltas before it (`check_delta` in
`server/src/service/commits.rs`), never that the new root stayed live; the signed body held no
delta; the delta pull did not deliver it; honest devices computed their delta from their tree.
A compromised device that was not removed yet could (1) keep the tree and drop every object of
it, so devices saw no change while the collection deleted the folder after the window; (2) lock
the folder for every honest device for good, because each later honest diff then dropped an
object the server no longer held live and was refused as `commit_refused`, which the client did
not handle, and the re-anchor (all objects as added) was refused because they were live; (3)
declare garbage as added with the tree unchanged, live for ever against the quota. LOW 1 of the
same file: the burst share could be diluted by adding garbage first.

**Format** (no release yet, so the format changes in place; labels stay `hangar-drive/v1/`):

```text
body = ... || field(counter, u64) || field(flags, u32) || field(delta digest, 32) || field(seen)
flags bit 2 = full delta (never on a side commit)
delta digest = SHA-256( field("hangar-drive/v1/commit-delta") || field(mode, u8: 0 diff, 1 full)
               || field(added ids, ascending) || field(dropped ids, ascending) )
```

`ReferenceDelta::validate` requires both lists strictly ascending, so a delta has one spelling.
`crates/hangar-drive-crypto/src/commit.rs` (`DeltaDigest`, `SignedCommit::check_delta`); vector
`commit.side_delta_digest` and the four commit vectors recomputed in Rust and by
`test_vectors.py`.

**Delta per commit kind** (`R(c)` is the set of objects reachable from commit c's tree):

| Commit | Mode | Relative to |
| --- | --- | --- |
| First commit | diff | the empty set |
| Normal commit, restore, conflict copies of a merge | diff (full when the diff does not fit and the set does) | the first parent, the head the device verified |
| Merge commit | diff | its first parent, the current server head, never the side commit |
| Side commit | always diff (a full side commit is malformed) | its base, the head it was built on |
| Stage of a publish too large for one commit | diff | the previous stage |
| Re-anchor | full | none |
| Barrier | full when `R` fits one delta, else the empty diff | none |
| Repair after `delta_mismatch` | full, without the side commit | none |

A diff is exact: `added = R(c) \ R(parent)`, `dropped = R(parent) \ R(c)`. The client no longer
truncates the dropped list (`fit_delta` is gone): every device recomputes it, so a missing ID
would make an honest commit look forged. A commit whose diff and full set both exceed
`MAX_REFERENCE_DELTA_IDS` is split by the stages as before; one that only drops that much with a
tree that large stays refused (open point).

**Server** (`server/src/service/commits.rs`):
- The uploaded delta must match the signed digest and mode, else `commit_refused`.
- A diff: every added object held (`missing_objects`), none live; every dropped one live; and the
  new root live afterwards (added, or live and not dropped). A violation is the new code
  `delta_mismatch` (409) with up to 64 of the IDs that do not fit in `missing`, never
  `commit_refused`. The side commit's diff is checked against its base the same way.
- A full delta: every object held (`missing_objects` otherwise, so a device can upload objects the
  collection already deleted), the root in the list, and then the list replaces the live set:
  objects in it that are not live are added, live objects outside it are dropped
  (`split_full`). Quota, budgets, the burst signal and the retention intervals see exactly that
  change, like a diff.

**Devices** (`crates/hangar-drive-sync/src/folder.rs`, `verify_tree_deltas`): after a pull
verified the chain, every new head and side commit is checked: the digest of `R(tree)` against
`R(first parent)` (side commit: its base; full: `R(tree)` alone) must equal the signed digest.
The server applied exactly the signed delta, so this proves that the server's live set matches
the tree. A mismatch is refused like a bad signature
(`ChainError::Commit(CommitError::DeltaMismatch)`): the folder takes nothing in, publishes
nothing on top and shows the error until the person removes the device that wrote it.
Exceptions:
- A mismatching commit by a device the verified log has removed since passes, because it comes
  in only behind a barrier the removing device or the person accepted; the barrier's full delta
  already reset the live set.
- A commit whose trees can no longer be read (the parent's objects collected after the window, a
  tree beyond the limits) cannot be checked.

In both cases the device sets `full_next`, and its next commit carries a full delta.

**The delta pull does not deliver the delta** (deviation from the review's proposal, a
conclusion): with the digest in the signed body, the device recomputes the delta from the two
trees it decodes anyway and compares digests, and the server's check of the uploaded delta
against the same digest ties its live set to that delta. Delivering the lists would add nothing
to the proof and cost up to 32 MiB per commit, for every device on every pull, plus storing the
lists for as long as the window. The IDs a device would want for diagnosis are in the server's
`delta_mismatch` answer.

**Repair path, so that honest devices are never locked out:**
- A publish whose diff the server answers with `delta_mismatch` sets `full_next`, seals every
  directory node and manifest of the same tree again (`codec::encode_fresh`), uploads every
  object the server lacks, and sends the tree once more with a full delta and without the side
  commit. That rebuilds the live set from what the honest device declares and uploads, also
  after the collection deleted objects (state after attacks 1 and 2).
- The re-anchor sends a full delta (before, its all-added delta could never pass) and seals its
  tree fresh, since the server that showed an older state may lack objects the index lists as
  uploaded.
- The barrier after a removal sends a full delta when the tree fits; if the server lacks objects
  of it, the barrier falls back to the empty diff and the device's next publish carries the full
  delta with the objects uploaded again. Since the amendment "Follow-up review of the delta
  binding" (HIGH 1) such a barrier is followed by a repair commit at once.

**Burst signal (LOW 1):** every head commit records an event with the folder's file data before
the change, also one that drops nothing (migration `0005_delta_binding.sql`, column
`drop_events.live_before`). The share of dropped bytes counts against that data just before the
change and also against the data before the window's first change, whichever share is larger.
Adding garbage first and then dropping every real file within the hour now sets off the pin.

**Open points.**
- Garbage added more than an hour before the drop still dilutes the share; a longer lookback or
  an absolute byte threshold would close it at the price of more false alarms.
- Chunks hashed under an older generation and not yet uploaded when a rotation happens could not
  be sealed for upload until the file changed; a full repair that needed such a chunk waited the
  same way. Closed by the amendment "content hashed before a key rotation".
- Objects a repair re-adds count as revived bytes against the repairing device's budget (or the
  pin restore allowance), like any restore.
- A commit that drops more than `MAX_REFERENCE_DELTA_IDS` objects of a tree that itself holds
  more than that many cannot be published yet (no delete stages).

**Tests.** `server/tests/delta_binding.rs`:
`a_head_that_keeps_its_root_but_drops_it_is_refused` (attack 1 with the root: `delta_mismatch`
naming the root; a never live root; a full delta without its root),
`a_delta_the_commit_did_not_sign_is_refused` (garbage on top of the signed delta, another
digest, a flipped mode, a hidden drop),
`a_full_delta_rebuilds_a_broken_live_set_with_objects_uploaded_again` (attack 1 without the root,
the collection deletes the files, a diff naming them gets `delta_mismatch`, the full delta asks
for the deleted files, takes them, and diffs fit again),
`garbage_added_first_does_not_dilute_the_burst_signal` (20 chunks for 20 GB of real data, 80 of
garbage, then every real chunk dropped: the pin holds the head before the drop; the test fails
without the fix). `crates/hangar-drive-sync/tests/delta_binding.rs` (memory server, which now
keeps the live set like the real one):
`a_head_whose_delta_does_not_fit_its_tree_is_refused_until_its_device_is_removed` (B refuses C's
forged head and publishes nothing, A removes C, the barrier's full delta resets the live set, B
goes on), `an_honest_device_heals_a_broken_server_view_and_commits_again` (empty live set and
deleted objects: the device's diff gets `delta_mismatch`, the full delta uploads everything
again, B verifies it, and the next commit is a diff again). Unit tests:
`the_delta_digest_binds_mode_order_and_both_lists`, the flag rules, the protocol's order check.
The end to end test against the real server passes unchanged.

## Amendment 2026-11-26: content hashed before a key rotation

**Problem.** Chunk IDs are keyed per generation. A file hashed under generation 1 whose round
failed before the upload (at the pull, say) kept its generation 1 chunk IDs after a removal
rotated the ring to generation 2. `seal_chunk` seals under the writable generation and refuses a
chunk whose ID differs, and the scan does not hash a file again while its size and time are
unchanged, so every publish ended in `LocalChanged` and the file never went up. A full repair
after `delta_mismatch` that needed a generation 1 chunk the collection had deleted failed the
same way.

**Decision.** A chunk that does not seal to its ID marks its content for the next scan, which
hashes the file again under the newest generation even when size and time are unchanged
(`FolderSync::rehash`, in memory only). When the failing content's chunk list names an older
generation, every other content with chunks the server lacks and an older generation is marked
too, so a rotation costs one failed publish attempt, not one per pending file; a file that merely
changed marks only itself. The new chunk IDs give the file a new content key, which publishes
like any local change.

- **Not chosen:** sealing such chunks with the older generation's keys. A removed device knows
  them, so new data under them would be readable by it. Uploads use the writable generation only.
- **Not chosen:** hashing every unpublished file of an older generation in each scan. That needs
  the server's and the synced tree's contents as a set in every scan, while the failed upload
  already names exactly the affected contents.
- **Manifests and directory nodes** are not affected: `codec::encode` seals every object the
  object cache does not know as on the server under the writable generation in each encode, and
  the cache holds only uploaded or downloaded objects. An object the server lost after a rotation
  is sealed again under the writable generation by `codec::encode_fresh`.

**Tests.** `crates/hangar-drive-sync/tests/removal.rs`:
`content_hashed_before_a_rotation_but_not_uploaded_still_goes_up` (eight files hashed in a round
that fails at the pull, a removal rotates to generation 2, the next round publishes all of them;
it fails without the fix, and also when only the failing content is marked),
`a_repair_after_a_rotation_uploads_lost_old_chunks_under_the_new_generation` (the collection
deleted every object of a generation 1 tree after the rotation, the full repair uploads the file
again under generation 2; it fails without the fix).

## Amendment 2026-11-26: directory handles on Windows (security review L1)

The amendment "Directory handles on Unix" left the race of finding L1 open on Windows, the
first target platform: the IDs of the directories on the way were read from handles opened with
`FILE_FLAG_OPEN_REPARSE_POINT`, and the operation then resolved the path again. A local program
with write access in the sync root could swap a checked directory for a junction (or a directory
symbolic link) in between, and a write, delete, rename, directory creation, metadata change or
read landed outside the root.

- **Decision:** on Windows every operation of `LocalFs` goes through directory handles as well
  (`crates/hangar-drive-sync/src/localfs/windows.rs`, the same `plat::Spot` and `plat::Folder`
  interface as `localfs/unix.rs`). The root is opened with `CreateFileW` and
  `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, each directory on the way with
  `NtCreateFile` relative to the handle of the one above it (`OBJECT_ATTRIBUTES.RootDirectory`,
  the bare name as `ObjectName`, `OBJ_CASE_INSENSITIVE` as `CreateFileW` uses) and
  `FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT`. A junction, a directory symbolic link or
  another reparse point on the way opens as itself and is refused by `FILE_ATTRIBUTE_REPARSE_POINT`,
  a file on the way fails with `STATUS_NOT_A_DIRECTORY`; both are `FsError::Changed`, and where
  the index knows a directory's file ID the ID of the open handle must match. The operation is
  relative to the handle of the directory that holds the target: opens, creates and stats with
  `NtCreateFile` and `FILE_OPEN_REPARSE_POINT` (plus `FILE_NON_DIRECTORY_FILE` or
  `FILE_DIRECTORY_FILE` where the kind is known), deletes with `SetFileInformationByHandle` and
  `FileDispositionInfoEx` with `FILE_DISPOSITION_FLAG_POSIX_SEMANTICS` (the classic
  `FileDispositionInfo` where the file system refuses the extended class, FAT and exFAT;
  read-only files stay refused, as `DeleteFileW` refuses them), renames with
  `NtSetInformationFile` and `FileRenameInformation`, `RootDirectory` set to the handle of the
  target's directory and `ReplaceIfExists` false wherever the code expects "already exists"
  (L2), and listings with `GetFileInformationByHandleEx` and `FileFullDirectoryInfo` on the
  directory handle. The reserved directory and its levels are created or opened in one step
  (`FILE_OPEN_IF | FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT`, N5 unchanged in effect).
- **Names below the Win32 parser:** names reach `NtCreateFile` as they are, so the path as a
  whole has no `MAX_PATH` limit (each name keeps its 255 unit limit) and no device name mapping
  (`CON`, `NUL`; `name_problem` refuses them before any path is built, unchanged). The module
  refuses, as a second line, every name that is empty, `.` or `..` or holds `\`, `/`, `:` or a
  NUL, so no name can reach another directory or an alternate data stream.
- **Stats and IDs:** attributes, size and write time from `GetFileInformationByHandle`, the reparse
  tag from `FileAttributeTagInfo`, the file ID from `FileIdInfo` with the volume serial number,
  else the 64-bit file index: the same values as before, so the IDs in existing indexes stay
  valid (test `handle_stats_match_std_metadata` against std's metadata and a handle opened by
  path). Kinds as std's `FileType` decides them: a name surrogate reparse point (junction,
  symbolic link) is a link, any other reparse point `Reparse`.
- **Replace (L3):** Windows has no swap of two names by handle (`ReplaceFileW` takes paths), so
  the replace is two renames by handle, neither of which replaces: the old file moves into the
  reserved `tmp` directory under a random name (`FILE_NON_DIRECTORY_FILE`, so a directory put in
  its place is not moved), then the new file takes the freed name. Afterwards the old file is
  checked against the expectation and removed or kept as a conflict copy, as before. If someone
  takes the name in the moment between the two renames, the old file goes back, or, if that
  fails as well, next to it as a conflict copy, and the replace reports `Changed`; nothing is lost.
  The new file gets the old one's creation time and its hidden, archive and not content indexed
  attributes, as `ReplaceFileW` gave them (read-only left out). **Trade-off:** for that moment the
  name is free, so a program that opens it exactly then finds no file; `ReplaceFileW` swapped by
  path and had that race of L1 instead. The new file keeps the ACL it got in `tmp` (inherited
  from the root, as for every new file since L2), not the old file's explicit ACL.
- **Recycle bin (open point of the Unix amendment, closed on Windows):** the shell's
  `IFileOperation` takes a path and resolves it again. Before the hand-over the directories from
  the root down to the file's directory are walked again with handles that do not share delete
  (`windows::pin`), the pinned directory must have the file ID of the one checked before, and the
  file is checked again in it. While these handles are open, nobody can rename, move or delete
  any of these directories (an open for `DELETE` fails with a sharing violation; delete access
  covers delete and rename, CreateFileW documentation of `FILE_SHARE_DELETE`), so what the path
  means in the file system stays the one checked. That alone does not make the shell act on the
  checked file: the shell resolves paths through its own namespace, see "Shell namespace" in the
  amendment "Follow-up review of the Windows handles", which adds the check that closes it.
  Files inside a pinned directory stay free to go (measured,
  test `a_pinned_directory_cannot_be_renamed`), so the shell can still move the file into the
  recycle bin. A directory someone holds open for deleting at that moment fails the pin with a
  sharing violation (`Locked`, retried later). **Residual window:** the file itself is not pinned
  (the shell needs to move it); a program that swaps the file for another file of the same name in
  between makes the shell recycle that other file, which is inside the root and recoverable: the
  L3 class of race, unchanged. On Linux and macOS the open point of the Unix amendment stays.
- **Quarantine cleaning (both platforms):** `trash::clean_quarantine` walked by path below a
  checked directory. The cleaning at start and in `housekeeping` now goes through handles on
  both platforms (`clean_quarantine` in `localfs/windows.rs` and `localfs/unix.rs`): only plain
  directories are entered, each through its own handle, at most 16 levels deep, and a link or
  junction is removed as itself, never followed. The age rule stays in `trash::expired`.
- **Platform behaviour met on the way** (measured on Windows 11 Pro 10.0.26300, NTFS):
  `SetFileInformationByHandle` with `FileRenameInfo` refuses a `RootDirectory` with
  `ERROR_INVALID_PARAMETER`, so the native `NtSetInformationFile` is used, whose documentation
  defines `RootDirectory` as the target directory of a relative name; `FileRenameInformation`
  refuses a buffer shorter than the structure with `STATUS_INFO_LENGTH_MISMATCH`; a directory with
  an open handle below it cannot be renamed by others (documented in the remarks of
  `FILE_RENAME_INFORMATION`), so a user's rename of a folder can fail while an operation of the
  engine below it runs (milliseconds; the person retries, the engine never holds handles across
  runs).
- **Dependency:** none added. `windows-sys` 0.61 gains the features `Wdk_Foundation`,
  `Wdk_Storage_FileSystem` and `Win32_System_IO` (`NtCreateFile`, `NtSetInformationFile`,
  `OBJECT_ATTRIBUTES`, `IO_STATUS_BLOCK`); `ReplaceFileW`, `MoveFileExW` and the path-based Windows
  code in `localfs.rs` are gone. The unsafe code is in the module `nt` of `localfs/windows.rs`,
  each block with its `SAFETY` note. `cargo deny check` green.
- **Microsoft documentation:** `NtCreateFile` (winternl.h, ntdll; "If this value is non-NULL, the
  ObjectName member specifies a file name relative to this directory"; `FILE_OPEN_REPARSE_POINT`
  "bypass normal reparse point processing"), `FILE_RENAME_INFORMATION` (ntifs.h; `RootDirectory`
  "a handle for the root directory under which the file will reside after it is renamed",
  `ReplaceIfExists` false fails if the target exists), `FILE_DISPOSITION_INFORMATION_EX` (ntddk.h;
  POSIX semantics remove the name when the delete handle closes), `CreateFileW` (`FILE_SHARE_DELETE`:
  "Otherwise, no process can open the file or device if it requests delete access", "Delete
  access allows both delete and rename operations"). Retrieved 2026-11-26 from
  learn.microsoft.com.
- **Tests** (`crates/hangar-drive-sync/src/localfs.rs`, `link_swap_tests`, now on every
  platform): each test runs with every link kind the machine can make, a junction (made with
  `cmd /C mklink /J` as an argv array, no admin rights needed) and a directory symbolic link,
  which needs developer mode or elevation and is skipped with a note otherwise (skipped on the
  development machine). With the link already in place every operation is `Changed`; with the
  swap made by `race::arm` exactly between the check and the operation, nothing outside the root
  changes and the operation acts on the checked directory (now `a.moved`); the listing test now
  also compares a size, since the outside twin has the same names. New on Windows:
  `a_trash_after_the_swap_hands_the_shell_no_path_through_the_link` (the outside twin has the
  same size and time and the expectation no file ID, so only the pin stops the shell), and in
  `localfs/windows.rs` `handle_stats_match_std_metadata`,
  `names_that_are_not_single_names_are_refused_by_the_open`,
  `times_before_the_epoch_convert_like_std` and `a_pinned_directory_cannot_be_renamed`. In
  `tests/localfs.rs`, `the_quarantine_cleaning_never_follows_a_link` replaces the test that
  called the path-based cleaning. **Counter-check:** against the code before this change the ten
  race tests fail on Windows with the same hook (they reproduce the finding), and the trash test
  fails with the pin switched off (the shell recycled the outside file). Run on Windows 11 (NTFS):
  every test of `hangar-drive-sync` passes; on Linux (WSL 2, ext4) the `localfs` unit and
  integration tests pass with the new Unix quarantine cleaning.

## Amendment 2026-11-26: follow-up review of the delta binding

A read-only security review of the amendment "reference deltas bound to the tree" kept the
format, the digest and the server check, and found four gaps.

**HIGH 1: a check skipped behind an unreadable tree.** A device skipped the delta check of a
commit whose tree or parent tree it could not read (`readable_set` gave up on a missing object or
a tree beyond the limits) and only set `full_next`, which took effect at its next publish. A
compromised device commits X1, whose root names a manifest it never uploads, and right after X2
with the old tree and a forged delta; every device skipped both and took them in.
- `DeltaCommit` carries the server's unsigned time of the call, `server_ms`, absent once the
  commit expired. A missing object counts as "the collection took it" only for a commit older
  than `UNREADABLE_AFTER_MS` (one day, the shortest retention an operator can set) or without a
  time; for a younger commit of a current device it is a delta mismatch. A server decides
  retention anyway, so its time gives it nothing new (conclusion).
- A tree beyond the limits anywhere on the way stops the folder as `StopReason::TreeLimit` does,
  not only for the last head.
- A skipped check, a mismatch of a removed device behind a barrier, and a barrier that kept the
  empty diff now write a repair commit at once (`FolderSync::repair`): the remote tree again on
  the frontier with a full delta, nodes and manifests sealed again, missing objects uploaded,
  with no local change needed.

**MEDIUM 2: repair and barrier stuck on the upload budget.** Bytes a commit makes live again
count against the device budget, so after a removed device dropped more than a budget slowly
(below the burst signal), the full barrier was refused with `budget_exceeded` until the
collection had deleted the data.
- Server (`revived`): bytes whose last drop came from a head of a device the log has removed
  since go through the pin restore allowance, like bytes of a pinned tree. Not free: a device
  that can add and remove devices could otherwise keep garbage stored for nothing by dropping it
  from a device it then removes. Reviving bytes this account already paid for keeps costing
  budget in every other case, because that cost is what bounds keeping dropped data alive
  through revive and drop cycles (section 5, "Upload budgets").
- Client: the barrier also falls back to the empty diff on `budget_exceeded` and
  `quota_exceeded`, so the removal finishes, and the repair follows once it fits.

**MEDIUM 3: who is named suspect.** The window named the writer of the first commit after the
pinned one. A malicious server could place a pin right before any device's commit, and after a
removal the barrier that drops the removed device's garbage named the barrier's writer.
- Each verified head's timeline record holds the file objects its delta drops and the parent's
  file objects (`TimelineRec::dropped_files`, `files_before`), counted from the trees by the
  delta check; a full delta counts chunks only, so a barrier or repair that keeps the tree drops
  nothing.
- `burst_writer` names a device only if its verified heads after the pin, within the hour after
  the first of them, drop at least the server's default share (30 %) and count (20 to 500,
  at most all file objects of a small folder). Otherwise the warning names no device and the
  window offers the device list instead of "Gerät entfernen" (already in place). A pin on a
  commit outside this device's history names no device either.
- Open point: commits a device published itself have no counts, so on the device that wrote a
  burst the warning names no device.

**LOW 4: the disk reserve.** A download now leaves 5 % of the volume free, at least 256 MiB and
at most 10 GiB (5 % of a 4 TB disk would hold back 200 GB; 10 GiB covers a system feature update
and a swap file), checked per file against the free space read right before it
(`folder::room_for`). Unknown free space is no room: every supported platform reports it, so
`None` means the call failed, and the file waits as on a full disk. `ROUND_DOWNLOAD_BYTES` is
documented as a bound on traffic per round, not on the disk. `FileSystem::volume_bytes` is new
(`space::volume_bytes`: `GetDiskFreeSpaceExW` total, `statvfs` `f_blocks`).

**Test double.** The memory server keeps the live set after every head and checks a side
commit's diff against its base like the real server.

**Tests.** `crates/hangar-drive-sync/tests/delta_binding.rs`:
`a_forged_delta_behind_a_tree_nobody_can_read_is_refused` (X1 and X2 as above with a current
server time: B refuses with the mismatch; it failed without the time rule),
`an_unreadable_old_tree_is_skipped_and_repaired_at_once` (without a server time: B writes a full
repair commit at once and the live set is the tree again). `server/tests/delta_binding.rs`:
`bringing_back_what_a_removed_device_dropped_costs_no_budget` (device budget 20 kB, C drops
12.4 kB with a diff that sets off no pin, C is removed, A's full delta is accepted; it failed
with `budget_exceeded` before; A's own drop and revival still pays). `engine.rs`:
`a_pin_before_a_commit_that_drops_nothing_names_no_device`,
`a_barrier_after_a_pin_does_not_name_its_writer`, the burst writer test reworked.
`crates/hangar-drive-sync/tests/disk_reserve.rs`:
`twenty_files_of_one_gib_leave_five_percent_of_the_volume` (100 GiB volume, 10 GiB free, twenty
files of 1 GiB: 5 GiB stay free, 1 GiB before), checked on the policy function, since `MemFs`
would need the 20 GiB in memory.

## Amendment 2026-11-26: follow-up review of the Windows handles

A read-only security review of the amendment "Directory handles on Windows" found the handle
walk itself sound (reparse points on every level, alternate data streams, 8.3 names, case, the
FFI) and six points, all fixed with tests.

- **M1, shell namespace (medium):** the recycle bin hands the shell a path, and the shell
  resolves it through its own namespace, not the file system's. A folder named `x.{CLSID}`, or
  a plain folder with the read-only attribute and a `desktop.ini` that names a CLSID
  (`CLSID2=`, `Flags=2`), is a namespace junction there; with `CLSID_FolderShortcut`
  (`{0AFACED1-E828-11D1-9187-B532F1E9575D}`) and a `target.lnk`, the shell item of
  `root\x\victim.txt` is `outside\victim.txt`, and `DeleteItem` recycled the file outside the
  root (reproduced by the review; measured here with `SIGDN_FILESYSPATH` on Windows 11, without
  deleting anything). The pin of the directories does not help, since nothing in the file system
  changes. A peer that syncs the first form into a root makes the attack remote. Three layers:
  - `trash::to_recycle_bin` reads the file system path of the parsed item and of its parent
    (`IShellItem::GetDisplayName(SIGDN_FILESYSPATH)`, freed with `CoTaskMemFree`) and compares
    them with the checked path and its directory (`CompareStringOrdinal`, case ignored, as the
    file system compares names); any difference is a failure, and the file goes to the
    quarantine through the handles. The item's own path is the decisive one, since the copy engine
    deletes what the item is; the parent is compared as well because the copy engine works in the
    item's parent folder, so a namespace that reported the right item path under a foreign
    parent would still be refused. Conclusion, not measured beyond the two forms above.
  - `windows_problem` refuses names that end in `.{GUID}` (section 7, "Shell junction names"),
    so the first form never reaches a root from another device. The engine reports it as
    `NameReason::Reserved`, like `ShortNameAlias` (`engine::name_reason`), and the rename field
    of the window says "reserved on Windows" (`src/domain/windowsNames.ts`).
  - `trash_file`: when the platform reports success but the checked file is still in place and
    still matches, it recycled something else; the checked file goes to the quarantine and the
    result is `Quarantine`, never `RecycleBin`.
  Tests: `a_shell_junction_name_never_reaches_the_shell` (first form: the shell resolves outside,
  the engine refuses the name, nothing outside changes), `the_recycle_bin_refuses_a_path_the_shell_resolves_elsewhere`
  (second form with a plain name: the shell resolves outside, the result is `Quarantine`, nothing
  outside changes), `shell_junction_names_cannot_sync_on_windows` in the protocol crate. The
  counter-check without the resolution check was not run, since it would put the outside file
  into the person's real recycle bin; the shell's resolution to `outside\f`, asserted in both
  tests, shows what `DeleteItem` would have acted on.
- **L1, buffer length (soundness):** the length passed to `SetFileInformationByHandle` was
  raised to the size of `FILE_RENAME_INFORMATION` for every class, so the 4 byte
  `FILE_DISPOSITION_INFO_EX` and the 1 byte `FILE_DISPOSITION_INFO` were read past their end.
  The length is now passed as given; only the rename raises its own buffer to the structure's
  size, as `NtSetInformationFile` requires.
- **L2, listing parser:** the parser of `FILE_FULL_DIR_INFO` records read a whole record (72
  bytes) after checking only 68. It is now a safe function over a byte slice that reads each
  field by its offset, ends the chain at a record whose fixed part or name does not fit or whose
  `NextEntryOffset` points into the fixed part, and is tested with hand-built buffers
  (`the_listing_parser_stays_inside_the_buffer`, the last record at `bytes - 68`); the offsets are
  checked against windows-sys (`the_record_offsets_match_the_sdk`).
- **L3, backups across a crash:** the old file a replace pushed out waits in `tmp` until it is
  settled, and the cleaning at start deleted `tmp`, so a crash in between (or a failed
  `keep_as_conflict`) lost an edit the person made at the last moment. The old file now always
  waits under a name ending in `.bak` (on Linux and macOS the new file takes such a name before the
  exchange), and the cleaning at start moves such files through the handles into
  `.hangar-drive/trash/recovered/` instead of deleting them; that directory expires like every
  quarantine entry, 30 days after the last file moved in. Other leftovers (half-written downloads)
  are still removed. Tests: `a_backup_left_in_tmp_is_recovered_at_start` and
  `a_crash_after_the_swap_of_a_replace_loses_no_old_file` (a hook right after the swap panics),
  both failing before the fix (run on Windows) and passing after it on Windows and Linux.
- **L4, one entry without a stat:** an entry whose own open was refused (an ACL, a filter
  driver) failed the whole listing. It is now listed with the attributes, size and write time of
  its directory record and without a file ID; a reparse point stays `Reparse`. Listing it as
  `Other`, as the review proposed, would drop a known file from the next tree and send its delete
  to every device; without a file ID the scan matches it by path. Test
  `an_entry_without_a_stat_does_not_fail_the_listing` (`icacls` denies SYNCHRONIZE to everyone on
  a file in `tests/.tmp/` and resets it afterwards), failing before the fix.
- **L5, rename onto the same file:** a case-only rename (the target name holds the source
  itself) used a replacing rename, so a file put under the target name after the file ID check
  was replaced for good. On Windows the rename now never replaces: NTFS takes a case change of
  the same entry without `ReplaceIfExists` (measured), and a file put there meanwhile is "already
  exists". Test `a_rename_onto_the_same_file_never_replaces_another_one` (a second hard link of
  the file passes the ID check and is then swapped for another file), failing before the fix.
  Linux and macOS keep the plain rename: on a case-insensitive APFS volume `RENAME_EXCL` may refuse
  the case change of the same entry (not measured), and two names of one inode make `rename` a
  no-op; open point for macOS.
- **Not done (info):** remembering the root's file ID in `LocalFs::new` and comparing it in every
  open of the root would need the ID passed to every platform function; the root path itself is
  outside the threat model (amendment "Directory handles on Unix").
- **Dependency:** none added; `windows` 0.62 gains the feature `Win32_Globalization`
  (`CompareStringOrdinal`). `cargo deny check` green.

## Amendment 2026-11-27: security review of the crypto and protocol crates

A read-only security review of `crates/hangar-drive-crypto` and `crates/hangar-drive-protocol`
found one medium, one low and six informational points. All are fixed, with tests. The byte
formats of entries, records, objects, offers and commits do not change, so the fixed vectors
stay as they are (`test_vectors.py`: all 61 match). Two rules that server and clients share
change (device log, replay guard), and the app's stored guard marks gain the epoch.

**MEDIUM 1: the reserve of the device log could be used up.** The last 64 places of the log took
removals and rotate epoch entries, and a rotate epoch entry was accepted at any time. A
compromised current device could append about 8190 plain rotations, fill the log up to
`LogFull` and never be removed; with many devices added before, 64 places did not hold a removal
of each of them either.
- **No plain rotations** (conclusion): a rotate epoch entry is accepted only while a rotation is
  due after a removal, or for the account's first epoch (`LogError::NoRotationDue`). The app
  makes no other rotation (`finish_setup` makes the first epoch, every later rotation comes from
  `remove_devices`), and a rotation without a removal protects nothing a removal did not already
  ask for. A plain rotation "once something else was appended since the last one" was not
  chosen: it would keep an add and rotate cycle of two entries per call for nothing the app
  uses. The epochs of a log are now at most its removals plus one.
- **The reserve holds every device:** `RESERVED_LOG_ENTRIES = 2 * MAX_CURRENT_DEVICES + 2` (132;
  first set to `2 * MAX_DEVICES + 2` and raised with the follow-up below). In the reserve the log
  takes removals, the due rotation, and one regular device added by a recovery device per epoch;
  the very last place takes only the due rotation. The recovery add keeps a log in the reserve
  from getting stuck when the person has only the recovery device left. Bound (conclusion,
  checked by the tests below): an attacker with regular devices only uses at most two places per
  device it removes (it keeps itself and the recovery device), plus one for a rotation due when
  the reserve began; the person then needs one place to add a device through the recovery
  device, one per remaining device and one for the rotation. With `c` current devices at the
  start of the reserve and `d` (0 or 1) for a due rotation that is at most `2c + d` places.
  Corrected with the amendment "recovery in one piece": the person's part must fit in one piece
  (it is one batch now), and after every complete batch an account has at most `MAX_DEVICES`
  devices (the place above the limit is taken only inside a recovery batch), while a due rotation
  follows a removal, so `c + d <= MAX_DEVICES` and at most 128 places are needed; the earlier
  premise `c + d <= MAX_CURRENT_DEVICES` (130) was looser than needed.
- The server's `admit_batch` is unchanged; a plain rotation batch after the first epoch is now
  refused there by the same verifier (`NoRotationDue`). Throttling appends is the server's part.
- Tests (`devicelog.rs`): `only_the_first_rotation_needs_no_removal`;
  `the_last_places_are_reserved` (rewritten: a regular device adds nothing in the reserve, no
  plain rotation, one recovery add per epoch, the last place only for the due rotation);
  `after_the_worst_abuse_the_owner_still_removes_the_attacker` (64 devices, the attacker removes
  every device but the owner's, each with its rotation, and tries plain rotations and adds in
  between; the owner then removes it and rotates within the log);
  `after_the_worst_abuse_the_recovery_device_still_gets_the_account_back` (the same with a
  rotation due at the start of the reserve and only the recovery device left: it adds a device
  that removes the attacker and the recovery device and rotates);
  `the_reserve_holds_a_removal_of_every_device`. Both abuse tests fail with the old reserve of
  64 places. They move the log to the reserve without thousands of signed entries
  (`fast_forward`: the checks of the next entry read only the length and the newest hash).
- **Recovery over the device limit** (follow-up, conclusion): the device cap also bound the
  recovery device. A compromised regular device could remove the person's regular devices and
  fill the account up to `MAX_DEVICES` with devices of its own; the recovery device then could
  not add a device (`TooManyDevices`), so the recovery sheet never got back in.
  - A regular device added by a recovery device may exceed `MAX_DEVICES` by exactly one, up to
    `MAX_CURRENT_DEVICES = MAX_DEVICES + 1` (65). A regular device still adds nothing at 64 or
    more, so only the person's recovery device reaches the extra place, and a recovery device
    adds nothing at 65. The device it adds can then remove every other device.
  - Every bound that counts current devices follows: a rotation wraps to at most 65 devices, so
    `MAX_WRAPPED_KEYS` is 65; one append call removes every other device of a full account with
    its rotation (64 removals and the rotation, which is what the app's removal and recovery do
    in one call), so `MAX_APPEND_ENTRIES` rose from 16 to 65. The crypto crate checks both at
    compile time against `MAX_CURRENT_DEVICES`. The server's wrap check
    (`wraps_cover_current_devices`) compares with the log's current devices and needed no
    change; no other list is bounded by the device limit (device names allow 1024, the create
    entry 8). The reserve grew to `2 * MAX_CURRENT_DEVICES + 2` above.
  - Not chosen: exempting the recovery add from the cap altogether (a recovery code holder could
    then grow the account without bound and every rotation's recipients with it), and reserving
    a place below the cap for the recovery device (it would lower what the person can use, and
    an account with two recovery devices would need two).
  - Tests: `a_full_account_still_lets_the_recovery_device_in` and
    `the_reserve_holds_the_device_over_the_limit_too` (`devicelog.rs`: 65 devices before the
    reserve, the attacker's worst use of it, then the recovery path within the log), and
    `server/tests/recovery_cap.rs`, `a_full_account_still_lets_the_recovery_sheet_in_and_remove_everyone`
    (over the socket: the attacker removes the owner and fills the account to 64, a regular add is
    refused, the recovery session adds the new device as the 65th, and that device removes all 64
    others with one append call and one wrap).

**LOW 1: a huge record version blocked the re-seal.** The replay guard ordered records by version
only, and the re-seal after a removal writes the version plus one. A malicious server together
with a compromised current device could give a device a record at version `u64::MAX`; after that
device's removal the guard refused every re-sealed record of the new epoch for good.
- **Order `(epoch, version)`** (`RecordGuard::check`): a record under a newer epoch than the
  mark's is newer whatever its version; one under an older epoch is refused
  (`GuardError::StaleEpoch`); within one epoch the version rule stays (an older version is
  refused, a different record under the same version is equivocation). The guard only sees
  records that opened, whose sender is current in the verified log, so a record of a newer epoch
  always comes from a current device.
- **Marks hold the epoch:** `RecordMark { epoch: Option<Epoch>, version, digest }`. The app stores
  them as `marks` in its account value. An account stored by an older version has `guard` tuples
  without the epoch, read once (`resume_marks` in `crates/hangar-drive-sync`): a mark takes the
  epoch of the record kept for its key when that record's SHA-256 is the mark's digest and its
  version the mark's (`RecordMark::from_legacy`); otherwise the epoch stays unknown and the mark
  keeps the version-only rule until the next accepted record. The next save writes only `marks`.
- **Server rule:** unchanged. The server stores only the current epoch and only the stored
  version plus one, so what it stores never goes back in either order.
- Open point for the sync engine: `AccountRecords` documents its versions as the server's. A
  device that was shown a forged high version still re-seals at that version plus one; an honest
  server refuses that with `record_version`, and the record the device then fetches may be the
  removed device's, which no longer opens. Other current devices re-seal, and the device accepts
  their records under the new order; a device that is the only one left should re-seal at the
  version the server holds.
- Tests: `a_huge_version_of_a_removed_device_does_not_block_the_next_epoch` (the attack: b's
  record at `u64::MAX`, b removed, a's re-sealed record at version 4 of epoch 2 is accepted; the
  epoch 1 records are refused as stale, an older version or another record of epoch 2 as
  before), `a_mark_without_epoch_keeps_the_version_rule` and
  `a_legacy_mark_takes_the_epoch_of_its_own_record` (crypto), `old_guard_marks_are_migrated`
  (sync).

**Info.**
- `object::padme` returns `Option<u64>`, `None` where the rounded length would pass `u64::MAX`
  (lengths above `2^64 - 2^57`). The callers (objects, records, pairing names) add the length
  prefix with `checked_add` and refuse such lengths. Test `padme_does_not_overflow_near_the_top`.
- Pairing: the offer body is written into a buffer of its final size, signature included, so no
  grown buffer leaves copies of the pairing secret in freed memory. Test
  `offer_buffers_are_allocated_at_their_final_size`.
- Pairing: typing P as a code without the offer is documented as not supported. The code carries
  neither account ID nor log head hash, so a device that only typed it has no trust anchor. The
  app pairs only through the scanned offer; no feature changed.
- `FolderView::reanchor_base` finds the bases of side commits by map lookups (the kept chain
  through the view's positions, the segment through its own map) instead of a linear search per
  head, and the check for side commits without a head uses a set. Test
  `reanchor_finds_side_bases_on_the_kept_chain_and_in_the_segment` (bases on the kept chain and in
  the segment are found, one on the dropped part of the chain is refused, as before).
- `RecordKey` is deserialized through `try_from` with the rule of `RecordKey::new` (a folder
  exactly for per-folder kinds), so no JSON, feed entry or stored state yields a mismatched key.
  Test `record_keys_are_checked_when_read`.
- Fuzz target `verify_built_delta`: builds commits from the input's fields, signs them with the
  fixture's keys (one device current, one removed with its rotation) and runs `verify_delta`,
  `check_delta` and `reanchor_base`, so `step`, the removed signer rule and the re-anchor walk are
  reached behind the signature. It compiles (`cargo check` of the fuzz package); it was not run,
  since no nightly toolchain is installed here.

## Amendment 2026-11-27: security review of the sync server

A security review of `server/` found three medium and four low points and a few infos; each
was checked in the code first and is fixed with tests (`server/tests/server_review.rs`,
`server/tests/deploy_files.rs`, unit tests in the named modules). The device log throttle
below is the server side of the crypto review's log reserve (amendment "security review of the
crypto and protocol crates").

- **M1, address tables flooded without a session:** the authorization layer counts every call
  with a bearer token per address before the token lookup (`CallIp`, 3000/min, IPv6 per /64)
  and per network (`CallNet`, 12000/min, IPv6 per /48). Each request of one /48 with a new /64
  added a key, so a few networks filled the table of 100 000 keys within a minute, and from
  then on every new honest key got `rate_limited`. Now every address scope keeps at most
  `MAX_ADDRESSES_PER_NET` (256) keys of one network at a time; beyond that a new address is not
  tracked and only the network limit, counted first, applies to it. Ended windows are evicted
  on every new key, not only in a full table, so the per network counts hold only live keys.
  `CallIp` also fails open in a full table (about 400 networks at once): it only bounds token
  lookups, which `CallNet` still bounds. The sign-in scopes keep refusing new keys in a full
  table, so an online search for proofs or invites never gains from a flood. Code:
  `server/src/http/ratelimit.rs` (`hit_in`, `Table::groups`, `Scope::fails_open`).
- **M2, one account holding the global write lock:** the commit call took `BEGIN IMMEDIATE`
  first and then loaded up to 2^21 IDs into its temporary table and checked them, so commits
  full of IDs the server does not hold (refused with `missing_objects` only at the end) held
  the write lock of every account, and sign-ins, uploads and pairing of others ran into the
  10 s busy timeout. The call now has two phases on one pooled connection
  (`commits::commit_call`, `db::begin_write_on`). Without the lock it reads the account, the
  folder and the head (refusing `head_moved` early), decodes and verifies both commits, loads
  the IDs into `commit_ids` (writes to the temporary database only, which take no lock on the
  main one) and checks that every added object is held. Under `BEGIN IMMEDIATE` it reads the
  account again (and decodes again if the device log grew), then runs the unchanged checks:
  compare and swap, parents, counters, every rule that depends on the head, and the held checks
  once more. The collection deletes object rows in its own write transaction, so the second
  check sees every deletion before it and none can come before the commit is durable; the
  object locks order only file removal against uploads and are not involved. Option (a) was
  taken because it removes the cost the attack needs; (b) is added on top: `CommitAccount` (30
  commits per minute and account, before the body is read) and `CommitRefusedAccount` (20
  refused commits per 10 minutes, `head_moved` and the server's own failures not counted; once
  used up, every commit of the account is refused before its body is read for the rest of the
  window). Measured on Windows 11, debug build, the largest delta (1 048 576 IDs, none held)
  and an empty write transaction every 20 ms beside it
  (`m2_measure_a_refused_commit_with_the_largest_delta`, the same test run against the previous
  code in a temporary worktree): before, a write waited **1.64 s** for the lock (2 writes during
  a call of 5.5 s); after, the longest wait was **14.6 ms** (54 writes during a call of 3.7 s).
  Tests: a commit stopped by a test hook right before the lock (`Hooks::commit_prepared`) does
  not delay another account's sign-in; an object deleted while it waits makes it fail with
  `missing_objects` under the lock; a commit of phantom IDs never reaches the hook; refused
  commits brake only their own account.
- **M3, no writable temporary folder in the image:** confirmed in the code. The bundled SQLite
  (libsqlite3-sys 0.40) is built without `SQLITE_TEMP_STORE`, so temporary tables and sorts
  spill to files beyond the page cache; `unixTempFileDir` tries `SQLITE_TMPDIR`, `TMPDIR`,
  `/var/tmp`, `/usr/tmp`, `/tmp` and `.`, all on the read-only root file system of the
  container (`read_only: true`, no tmpfs), so a large commit could fail with an I/O error.
  Fixed without RAM: the image sets `SQLITE_TMPDIR=/data/tmp`, and the server creates
  `<data dir>/tmp` (0700 on Unix) at every start and empties it in `serve` under the data
  folder lock (an admin command beside the server must not remove its files). No environment
  variable is set at run time, which edition 2024 makes `unsafe`. Open: checked by reading the
  code and by `deploy_files.rs`; a large commit in the real container was not run (Docker was
  not available).
- **L1, connection slots per network:** the server limited connections per address only, so
  with TLS in the server 64 IPv4 addresses took all 4096 slots. `PeerConnections` now also
  counts per network (the rate limiter's network key): four times the address limit and at
  most a quarter of all slots (`Concurrency::connections_per_net`). The TLS handshake timeout
  went from 10 s to 5 s.
- **L2, trickling bodies in the heavy slots:** a commit or record body holds one of the four
  heavy slots while it arrives (the slot bounds the memory of these bodies, finding M4), and
  only an idle timeout of 30 s and a total of 120 s ended a slow one. Heavy bodies must now keep
  64 KiB/s on average after a grace of 5 s (`extract::HEAVY_PACE`, `read_paced`); a body that
  falls behind is answered 408 and frees its slot. Taking the slot after the body was rejected:
  it would give up the memory bound.
- **L3, trusted proxies with TLS in the server:** an operator who moved from a proxy to TLS in
  the server kept trusting `X-Forwarded-For` from the old proxy's addresses, which clients could
  then reach directly. The server now refuses to start when TLS in the server is configured and
  `HANGAR_DRIVE_TRUSTED_PROXIES` is not empty (`ConfigError::TlsWithTrustedProxies`).
- **L4, backup command:** the documented `tar` wrote the archive with `server.secret` world
  readable and used an unpinned image. It now runs with `umask 077`, gives the archive to the
  operator's user, and uses the Caddy image that `docker-compose.yml` already pins by digest;
  the guide says the archive is a secret.
- **Device log throttle (crypto follow-up):** a compromised current device could append
  rotations at the call rate until the log was full and it could no longer be removed. The log
  format now refuses rotations nothing made due; on the server, appends that add a device or
  rotate without a removal count against `LogAppendAccount` (30 per hour and account), and
  rotations without a removal also against `LogRotateAccount` (one per hour). A batch that
  removes devices, the rotation the log has due and the one append of a recovery session are
  never counted, so a stolen device always stays removable (`service::devicelog::Throttle`).
- **Infos done:** `SECURITY.md` names the self-hosted server's scope (sign-in bypass, access
  across accounts, denial of service without a session) and what is out of scope (operator
  misconfiguration). `HANGAR_DRIVE_BIND` sets the listen address: loopback by default outside
  the image, `0.0.0.0` in the image; the health check follows it. The proxy examples send HSTS
  without `includeSubDomains`, like the server. The nginx example gives `/api/v1/folders/` a
  read timeout of 300 s. The guide says a certificate change in the TLS mode needs a restart.
  The data folder is made 0700 at start on Unix (a process umask would need `unsafe`, and a
  private folder covers every file in it). An upload claims its staging bytes before the disk
  check, so two uploads cannot both pass on the same free space.
- **Not done:** a total time limit for `GET /objects` bodies. The body stream is polled only
  when the socket takes data, so a timer inside it does not fire for a client that stops
  reading; it needs a write timeout on the connection, which hyper's HTTP/1 server does not
  offer. Open point. The health check in the TLS mode still only connects (info 5): a real
  handshake needs a client configuration that accepts the server's own certificate.
- **Breaking changes:** outside the image the server now listens on `127.0.0.1` unless
  `HANGAR_DRIVE_BIND` is set; with TLS in the server and trusted proxies it does not start.
- **Dependency:** none added.

## Amendment 2026-11-27: security review of the sync engine

A security review of `crates/hangar-drive-sync` (threat model of section 4: the server is not
trusted, other devices of the account may be hostile) found work that grew with the square of a
directory or with the history, unbounded memory and storage, and gaps in the local mass delete
guard. Fixed with tests unless marked open; the complexity tests count operations, not time, so
they hold in a debug build.

**HIGH 1: the scan was quadratic in the size of a directory.** `Tree::lookup_exact` looked at
every entry of each directory on the path and fell back to the comparison key of every entry;
the scan asked once per entry found, in the walk of a partial scan and for the remote tree of a
new file. Measured by the review: 64,000 entries in one directory took 117 s per round, at
`MAX_DIRECTORY_ENTRIES` about 30 minutes, which a hostile device sets off with empty files and an
honest large folder meets as well.
- `tree::NameIndex`, built once per scan: the exact names per directory borrow from the tree, the
  comparison keys are computed once per node and only when a lookup first needs them; where
  several entries match, the smallest item ID wins, as before. The scan takes all its lookups
  through it (`folder.rs`, local index for the walk, the identification and unreadable
  directories, the remote index on first need).
- Tests: `name_index_equals_the_walk_over_the_children` (random trees with names equal by key
  but not by bytes, and duplicate names), `scan_lookups_take_linear_work` (50,000 entries in one
  directory, half found only by key: at most 6 units of work per entry; the walk over the
  children needs more than 10 per entry already for the first 200 lookups, 2.5 * 10^9 for all).

**HIGH 2: the delta check held every tree of a pull in memory.** `verify_tree_deltas` read the
reachable set of the tree and of the parent's tree of every commit and kept every set until the
end (`readable_set` with a cache without eviction); 200 commits over a tree of a million files
need an estimated 15 to 20 GB, and every device of the account fell into an out of memory loop.
- `codec::ReachState` holds one reachable set as reference counts (references from reachable
  directory nodes and manifests, repeats counted, the kind of each object). `goto(root)` first
  counts the references of objects of the new root that were not reachable, then takes away
  those of the old root's objects that lose their last one; a subtree both roots share is never
  read. The objects form an acyclic graph (an ID is the keyed hash of a plaintext naming its
  children), so `added` and `dropped` are exactly the set differences of the earlier walk
  (`reachable_typed`). A head's first parent is the head before it, so a pull reads the first
  tree once and then only what each commit changed, and holds one set.
- The check (`DeltaWalk`) keeps the roots found unreadable (gone or beyond the limits), as the
  cache did. A move also reads the dropped nodes of the old tree; when that fails, the target is
  read alone, and the old tree then counts as unreadable, as a full read of it would have found.
  A forged tree that names one ID as two kinds keeps the kind first reached; the counts stay
  consistent, only such a tree's set can differ from the earlier walk's (conclusion).
- Stricter in one case (conclusion): an object missing in a subtree both trees share no longer
  makes the check unreadable, since it is never read; the diff is then computed exactly, and a
  commit whose delta does not fit is refused, where before an old enough commit passed as
  unchecked. An honest commit always fits its diff.
- `take_outcome` (the removal job) uses the same check. `readable_set` stays only for the single
  tree of a barrier.
- Tests: `counted_transitions_equal_the_set_differences` (500 random graphs with chunks repeated
  within and across manifests, one manifest in many places, one directory node under many
  parents, roots that reuse subtrees of others; sequences of moves also back, to no root and to
  a subtree: `added`, `dropped`, the dropped manifests and chunks and the set itself equal the
  earlier walk's, kept as the test reference), `many_commits_over_a_large_tree_read_only_the_changes`
  (200 commits over 20,000 files in 100 directories: at most 20,101 + 6 * 200 node reads, about
  8 million before, and at most the tree plus four objects held). The integration tests of the
  delta binding pass unchanged.

**MEDIUM 1: the executor was quadratic for chains of renames.** Each pass tried every pending
item, and a chain of renames onto the name the next item gives up freed one name per pass
(measured by the review: 16,000 in 65 s).
- `apply.rs` registers a waiting operation under what it waits for (`Reason`: its parent's
  creation, a name of a directory by each of its case keys, the directory to empty, a move of a
  directory between it and its target, the return of a parked item) and wakes it on the
  matching `Event` of the working tree (an entry left a directory, an item arrived, an item
  moved, a parked item came back). Passes keep the ID order: an operation woken before the
  place the pass has reached runs in the next pass. A pass with nothing to run parks one item
  as before.
- One correction of the earlier passes: a move that leaves its content to the next pass counted
  as no progress, so as the last pending operation it ended blocked until the next round; it now
  finishes in the same run.
- Tests: `event_scheduling_equals_the_passes` (3,000 random runs with chains, swaps, cycles,
  moves below the item itself, late emptied directories and skipped items: working tree, synced
  tree, disk and report equal the earlier passes, kept as the test reference with the
  correction), `a_chain_of_renames_takes_linear_steps` (20,000 renames: at most 3 steps per
  item; about 2 * 10^8 before).

**MEDIUM 3: the local index grew without a bound.** The plaintexts, object IDs and chunk lists
of every object ever seen stayed until the folder was removed.
- `FolderSync::prune_cache`, with the hourly scan (`engine.rs`): kept are the object IDs of the
  remote and the local tree (found by encoding them against the cache, nothing is uploaded, so
  the next publish seals no unchanged node again), the plaintexts and IDs of everything
  reachable in the cache from the remote root, the last fully synced head and every commit of
  the timeline seen within `HISTORY_CACHE_MS` (30 days, the server's default retention), and the
  chunk lists of every file of the three trees. Everything else is a cache: a restore of an older
  commit fetches its nodes again, and its chunk lists come with its manifests. A tree that does
  not encode leaves everything as it is. New `Store::retain_cache`.
- Before a plaintext or a chunk list is written, the free space of the index volume is checked
  (`SpaceGuard`, again after 8 MiB or 2 s): without the reserve a download leaves
  (`folder::disk_reserve`), the write fails with `StoreError::DiskFull`, shown as "disk full"
  (`ErrorKind::DiskFull`), and the system drive is never filled. Unknown free space does not stop
  it.
- Tests: `the_cache_keeps_only_what_is_named`, `a_full_index_volume_stops_the_cache_with_its_own_error`
  (index), `the_cache_shrinks_and_syncing_and_restoring_go_on` (`tests/cache_prune.rs`: 30
  versions of 20 files, the plaintexts and chunk lists fall to below a quarter, a download, a
  publish and a restore of the first version work afterwards).

**MEDIUM 2: open point, `MAX_DELTA_TOTAL`.** (Closed for the pull and the removal job by the amendments "delta pages" and "delta pages in the engine"; the re-anchor stays open there.) A pull, a re-anchor (from cursor 0) and the removal
job read the whole delta after the cursor and refuse more than 200,000 commits as a protocol
error. A new device, a re-anchor and a device that was offline long are then locked out for
good, and a hostile device writes that many commits in about an hour. Not changed here: the
check of the chain (`FolderView::check_delta` in the crypto crate) takes the delta as a whole,
because heads of a removed device are let in only with a barrier later in the same delta, and a
prefix that ends before the barrier is refused. A fix that is not half needs the crypto crate.
Draft:
- The crypto crate verifies page by page into a scratch view: each page continues the chain of
  the one before; heads of a removed signer without a barrier yet are kept as compact pending
  metadata (commit ID, device, sequence, first parent, root, delta digest; about 200 bytes),
  settled by a later barrier or, after the last page, by the refusal and the takeover as now.
- The engine runs the tree check per page with the counted set above (it already reads only the
  changes), keeps the scratch view, the pending heads and the cursor in the store, so a pull
  resumes after a restart, and adopts the view, the timeline and the remote tree only after the
  last page. The barrier rule stays as it is; `MAX_DELTA_TOTAL` then bounds a page set in
  memory, not the history.
- The protocol does not change (the pages are the server's). Next step: a task for the crypto
  crate (`check_delta_page` with the pending set) and the engine part with tests over more than
  200,000 commits of the memory server.

**LOW 1: the local mass delete guard.**
- "Delete them" (`resolve_held(false)`) now approves exactly the held items
  (`FolderMeta::approved`, which replaces `approve_deletes`); a delete that came later goes
  through the guard again. Before, the flag let every local delete of the next round pass.
- While a question is open (`held` not empty), every further local delete is held as well. A held
  item that is back on the disk leaves the question.
- The threshold counts this device's local deletes of the last `DELETE_WINDOW_MS` (10 minutes,
  `FolderMeta::recent_deletes`, approved deletes not counted) together with those of the round,
  so 50 files every 10 seconds are held from the second batch on.
- Tests (`tests/mass_delete.rs`): `an_approval_lets_only_the_held_deletes_go`,
  `an_open_question_holds_every_further_delete`,
  `a_slow_delete_is_held_once_the_window_reaches_the_threshold`. The guard for incoming deletes
  is a task of its own (window and texts).

**LOW 2:** the activity list looked through the grouped deletes once per change
(`engine.rs`); it takes one set now.

**LOW 3:** `Merger::fix_cycles` asked `Tree::path` for every item, which walks up to n steps for
an item on a cycle. The items that reach the root are found by one walk down and the set grows
as fixes link items back (a fix moves only an item without a path, so no item loses its path).
Test `many_cycles_take_linear_work` (10,000 two-item cycles from local moves: at most 20 units of
work per pair, about 4 * 10^8 before); the random merge tests against the reference pass.

**LOW 4: the Linux trash.** `$topdir/.Trash-$uid`, `$topdir/.Trash/$uid`, the home trash and
their `files/` and `info/` were created with `create_dir_all` and used without a check, so a link
or a directory of another user on a shared volume took the file elsewhere. Each is now looked at
with lstat and used only as a plain directory of this user that nobody else may write to; a
missing one is created with mode 0700 and checked again. Anything else sends the file to the
quarantine. `$topdir/.Trash` must be a plain directory with the sticky bit, as before. The
decision is a pure function (`trash::xdg`), tested on every platform
(`trash_directories_must_be_plain_and_private`); the system calls compile and run only on Linux.
A swap of a checked directory by its owner between the check and the rename stays possible (the
owner is this user).

**Crypto review LOW 1, the open point of the sync engine.** A device that a malicious server and
a compromised device showed a forged high record version re-sealed after a removal at that
version plus one; an honest server refuses it with `record_version`, and as the last current
device it stayed in the old epoch for good. `Account::reseal_after_removal` now fetches the
refused record and, when it is not under the current epoch, seals it again under the current
epoch at the server's version plus one (`reseal_at_server_version`); the new epoch is newer than
every mark of the old one. A version at `u64::MAX` is sealed one below, refused, and goes the
same way. Test `the_last_device_reseals_at_the_server_version_after_a_forged_one`
(`tests/removal.rs`; fails without the fix).

**Info.**
- The watcher keeps at most `MAX_CHANGED_PATHS` (10,000) paths per drain and asks for a full scan
  beyond (`Changes::add_path`, test `many_changed_paths_become_a_full_scan`); so does
  `FolderSync::note_changes` for paths that pile up.
- A failing random generator gave every new item the ID `ff..ff`, so two new items could share
  one ID (the comment said "a hash of a counter"). `EntropyIds` now gives distinct IDs for the
  rest of the run and the run is refused with the generator's error (test
  `a_failing_generator_gives_distinct_ids_and_an_error`). The executor's placeholder for "no
  item" is the root's ID, which no item has.
- The client index sets `secure_delete`, so paths of a removed folder or a reset device do not
  stay in free pages of the file.
- Open (LOW 5): the timeline and the chain are written as JSON with the folder metadata on every
  save and grow with the history; a table of their own in the index is the follow-up.

**Public API:** `FolderMeta::approve_deletes` is replaced by `approved` and `recent_deletes`;
new `FolderSync::prune_cache`, `tree::NameIndex`, `codec::ReachState`, `codec::ObjectGraph`,
`codec::StoreGraph`, `codec::cached_reachable`, `Store::retain_cache`, `StoreError::DiskFull`,
`watch::MAX_CHANGED_PATHS`, `folder::DELETE_WINDOW_MS`, `folder::HISTORY_CACHE_MS`. Nothing of it
is used by the app shell. **Dependency:** none added.

## Amendment 2026-11-27: delta pages

The crypto part of the open point MEDIUM 2 of the amendment "security review of the sync engine"
(`MAX_DELTA_TOTAL`). The engine part (pulling, storing the state, adopting after the last page)
follows in the sync crate.

- **Page by page check without a format change** (conclusion): `FolderView::begin_check` (and
  `begin_check_before_barrier` for the removing device's check without the removed signer rule)
  returns a `DeltaVerifier`; `push_page(state, page)` checks the next page and returns a
  `DeltaPart` (the heads and side commits that passed so far and, before a barrier, the removed
  heads among them); `finish(state)` returns the verdict `check_delta` gives for the whole delta:
  `DeltaVerdict::Accepted { view, rest }` or `DeltaVerdict::RemovedSigner(refusal)`, or the
  error. `check_delta`, `verify_delta` and `verify_delta_before_barrier` are that check with the
  delta as one page. Nothing passed by a page is accepted before `finish`.
- **Why it needs no protocol change:** the removed signer rule asks of every head of a removed
  device that a later head of a current device names a log head at or after the removal. Read
  forward, that is one number: the highest removal index among the heads still waiting; a head of
  a current device that names a log head at or after it settles every waiting head at once,
  because a smaller index waiting is covered by the same head. The draft's pending metadata per
  head (about 200 bytes each) is not needed for the verdict.
- **Same refusals as the whole delta:** a commit that does not decode, verify or keep the order
  of sequences refuses at once (the whole delta reads all of them first); a refusal of the chain
  rules is kept and returned by `finish` only after the removed signer rule, as before. A head
  waits until its call is complete, because its side commit may start the next page: the open
  call holds at most a head and one side commit.
- **Memory:** per verified head the scratch view's chain entry (60 bytes stored,
  `VERIFIER_BYTES_PER_HEAD`) and its place in the view's index; besides that the open call, the
  marks per device and fixed fields. The commits themselves stay with the page.
- **Stored state:** `DeltaVerifier::encode` and `decode` (a strict local format of the crypto
  crate, version byte 1), so the engine can resume after a restart. A stored state is trusted
  like the rest of the local index; it resumes only with the device log the check began with
  (`ChainError::LogChanged` otherwise, and on any page with another log: begin again).
- **Not covered:** `FolderView::reanchor_base` still takes the server's commits after the base
  as a whole, because it walks back from the last head; a re-anchor across more than
  `MAX_DELTA_TOTAL` commits needs its own step (a first pass that keeps the first parent per
  head, then this check from the base).
- Tests (`commit.rs`): every delta any test of the crate verifies is also checked against the
  former whole delta check (kept for the tests as `verify_whole`), cut at four sets of random
  page boundaries with the state stored and resumed between pages, in both modes, and the removed
  heads before a barrier are compared; `pages_check_exactly_what_the_whole_delta_check_does` (240
  random deltas from an empty view and from a verified chain, with a removed signer and barriers,
  merges with side commits and mistakes of every kind; acceptance and the refusals
  `RemovedSigner`, `Counter`, `Sequence` and `SideUnexpected` are reached);
  `the_page_by_page_check_holds_a_fixed_size_per_head` (3000 heads in pages of 512: at most two
  commits held, the stored state grows by the chain entries only);
  `a_stored_delta_check_resumes_only_with_its_own_log` (strict decoding, another log refused).
  A deliberately wrong variant that closes the open call at the end of every page fails 8 of the
  tests.
- The formats on the wire and the fixed vectors do not change (`test_vectors.py`: all 61 match).

## Amendment 2026-11-27: incoming mass deletes

Decides the open point LOW 4 of the amendment "server notices reach the window, downloads
respect the disk" ("incoming mass deletion has no threshold"). A single compromised device, or a
slip on another device, removed the working copy of every device within seconds: incoming
deletes went to the recycle bin at once (`FolderSync::apply_plan`), the server is not trusted
(section 2), and the recycle bin is no reliable protection (it may be off, full or emptied, and a
quarantined file is gone after 30 days).

**Decision.** Deletes another device made wait on this device for the person's decision once
the incoming *file* deletes of a folder since the last decision, within a day
(`LONG_DELETE_WINDOW_MS`, 24 hours, which holds the local guard's 10 minute window), reach

- at least 1,000 (`INCOMING_DELETE_ALWAYS`), or
- at least 100 (`INCOMING_DELETE_MIN`) and at least 25 % (`INCOMING_DELETE_PERCENT`) of the
  folder's size, which is the fewest files the folder held over that day plus the deletes
  carried out within it (`FolderSync::files_before`).

A folder of fewer than 100 files never asks. Moves keep their item and are no delete;
directories are held with their files but not counted; files that came into the folder within
the day are not counted either (see "Follow-up review" below). The decision is the pure function
`planner::hold_deletes`; `FolderSync::guard_incoming` applies it after the plan. (The first
version of this amendment counted over the 10 minute window only and took the share of the
current file count; the follow-up review below changed both.)

**Reasons for the numbers.** 100 is the local guard's threshold (Nextcloud's default), so both
directions ask from the same size. The share keeps honest tidying up quiet: removing 100 old
files from a folder of 5,000 is 2 %, removing a quarter of a folder is what an attack or a slip
looks like. 1,000 asks regardless of the share, so a large folder cannot lose thousands of files
without a question. Over a day, many small commits (one device deleting 50 files every few
seconds, or 99 every 10 minutes) add up instead of slipping through one by one.

**Behavior.**
- An incoming delete is an item of the synced tree and of the disk that the server's tree and the
  plan no longer have. Held items go into the executor's skip set: they stay on the disk and in
  the synced tree, so the merge keeps seeing them as deleted remotely and everything else of the
  folder keeps syncing. Deleted directories above a held item are skipped as well.
- While a question is open, every further incoming delete is held too. A local change to a held
  file wins by the existing merge rules (modify against delete keeps the file), so it leaves the
  question and is published again.
- The state lives in `FolderMeta` (`incoming_held`, `incoming_revision`, `incoming_devices`,
  `incoming_approved`, `recent_incoming`, and since the follow-up review `file_minimums`,
  `fresh_files`, `long_deletes`), all `#[serde(default)]`, so metadata stored before loads
  unchanged and a question and the day's counts survive a restart.
- "Ja, hier löschen" approves exactly the held set, bound to `incoming_revision`, which grows
  whenever the set gains items; the app reads the revision before its native question and passes
  it on, so deletes that arrived during the question ask again. Approved deletes are not counted
  in the window, and either decision starts the day's count again.
- "Wiederherstellen" (the default) pulls, grafts every held file (and every held empty
  directory) from the synced tree onto the current server tree (`folder::graft`: old IDs, missing
  parents, a "restored" name on a clash) and publishes it as a new commit; the content comes from
  this disk. The files come back on every device.
- The question names the writing device when the non-side commits that arrived with the held
  deletes come from exactly one device of the verified timeline; otherwise "another device".
  Below the title it says since when that device is in the account (follow-up review, L5).
- What this device's own action removes (a restore, a folder reset, an undo, through
  `publish_tree`) is approved on this device; other devices ask.

**Interface.** `Warning::IncomingDelete { folder, device: Option<String>, device_added:
Option<Millis>, count, sample }`,
`EngineCore::list_incoming_delete`, `incoming_delete_revision`, `resolve_incoming_delete`; Tauri
commands `list_incoming_delete` and `resolve_incoming_delete` (native question before "delete
here", like `resolve_mass_delete`); a notification and the tray's "Braucht dich" like the local
guard; the window shows the local guard's dialog in an incoming variant (UX 8.1, keys
`incoming.*`).

**Consequences.** A compromised device can still delete on the server, but every other device
keeps its copy until a person decides there, and restoring from any device brings the files back
everywhere. An honest large reorganisation by deleting (not moving) asks once on each other
device. The re-anchor after an older server state is not approved automatically: a mass delete it
brings asks as well, which is the safe side when the server is in doubt.

**Tests.** `planner::tests::incoming_deletes_are_held_from_the_thresholds_on` (99/100, 24/25 %,
999/1000); `tests/incoming_delete.rs` (thresholds at the edges, the window over several commits,
moves not counted, holding, approval of only the shown state, restore back on the deleting
device, local change wins, restart keeps the question, own restore does not ask);
`folder::tests::metadata_without_the_incoming_guard_fields_loads`; engine commands in
`tests/commands.rs`; notification, native question and command checks in `src-tauri`; dialog,
banner and texts in the window's tests.

### Follow-up review of the incoming guard

An independent review of this amendment found two ways around the threshold, a gap next to it,
a spoofable name in the question and two smaller points.

**M3: diluted and paced deletes.** (a) A device added 3,500 empty files to a folder of 500, then
deleted the 500 real ones in one commit: 500 is below 1,000 and below 25 % of 4,000. (b) 99
deletes every 10 minutes never reached 100 in the window. Fixed:
- The share is taken of the fewest files the folder held over the day, kept as the fewest per
  hour (`file_minimums`), plus the deletes carried out within the day. Files added before a
  delete raise the count only after that day's minimum, so they cannot dilute it. The hourly
  minimum is kept only once the folder was fully synced (`sync_base`), so a first download or
  "download again" is no baseline.
- The deletes add up over the long window since the last decision (`recent_incoming` now keeps
  a day), so the pace of a slow delete does not matter within a day.
- Files that came into a fully synced folder within the day (`fresh_files`, at most
  `FRESH_FILES_CAP` = 20,000; past it the oldest are forgotten and count like any other file,
  which only asks sooner) are not counted as deletes: creating a project and removing part of
  it again does not ask. An old file cannot be made fresh: a move or a content change keeps its
  item ID, and a delete followed by a new file under the same name deletes the old ID (held) and
  brings a new one, which waits for the name until the decision.
- The **local** guard had the same pacing flank (100 per 10 minutes, so 99 per 10 minutes went
  out). It keeps its rule and adds the same long window for the old files this device deleted
  since the last decision (`long_deletes`), by the same share rule and never below the set
  threshold. Dilution did not apply there (no share).
- Bound: a device that waits a full day after adding the filler files dilutes the share again;
  1,000 deletes ask regardless.
- Tests: `tests/incoming_delete.rs` (`files_added_just_before_do_not_dilute_the_share`,
  `deletes_paced_below_the_short_window_add_up_over_the_day`,
  `deleting_part_of_a_new_project_does_not_ask`, `a_little_cleanup_every_day_does_not_ask`,
  `deleting_and_writing_again_under_the_same_names_is_held`,
  `the_long_window_survives_a_restart`); `tests/mass_delete.rs`
  (`deletes_paced_past_the_window_add_up_over_the_day`,
  `deleting_files_made_today_does_not_add_up`).

**M4: mass overwrites (open point, not built).** Emptying or encrypting the content of every file
is no delete: each device takes the new versions at once (the ransomware pattern), and the
server's history is no reliable protection, since the server is not trusted. Today the executor
replaces a file atomically (`LocalFs::write_atomic` with `replace`; on Windows two renames by
handle through `tmp`, on Unix an exchange), and `LocalFs::settle_old` removes the old file
afterwards, or keeps it as a conflict copy when it was not the expected one. Nothing keeps it.
The existing pieces are the quarantine `.hangar-drive/trash/<item ID>/` (30 days,
`trash::QUARANTINE_DAYS`, cleaned by age at start and hourly through handles,
`plat::clean_quarantine`), `trash/recovered` for backups left by a crash, and the disk reserve
of the download path (`folder::disk_reserve`, 5 % within 256 MiB and 10 GiB). The "suspect"
banner (UX 9.4) comes from the server's anomaly pin and names a timeline entry to restore, so it
cannot say that versions were kept on this disk. The design:
1. Count incoming content changes of old files from other devices (same item, new content, not
   fresh) in the same long window and by the same rule (`hold_deletes`); from the threshold on,
   the folder marks every further incoming replace of the window as "keep".
2. A new `FileSystem` method, defaulting to `write_atomic`, replaces with "keep": `settle_old`
   moves the old file by handle into `.hangar-drive/trash/kept/<time>-<item ID>/<name>`
   instead of removing it (the same rename as the quarantine of a delete).
3. Before keeping, the free space after the copy must stay above `disk_reserve`; if not, the
   oldest entries under `trash/kept` go first (never other quarantine entries), and if that is
   not enough the version is not kept. This needs a listing of `trash/kept` with sizes and an
   eviction through the same handle code as `clean_quarantine`, on Windows and Unix.
4. The 30 day cleaning covers `trash/kept` as it is.
5. Finding them again: the folder's `.hangar-drive/trash/kept/`, newest last; a later version of
   the window could list them in the restore dialog.
This touches the platform file code that the reviews L1 (handles on Unix and Windows) hardened,
adds a port method with a space-bounded eviction and needs real-file-system tests per platform,
so it is not a small change; built halfway it would promise a protection it does not give.
Recorded here as the next step instead.

**L5: a spoofable name in the question.** Any current device can rename any device in the
sealed device names (`Account::set_device_name`), so a hostile device can call itself "Laptop".
The question now has a quiet line below the title, "{device} ist seit {date} in deinem Konto."
(`incoming.deviceSince`), with the date the verified device log added the writing device
(`Account::device_added_ms`, the issuing device's clock), the date the device list shows next to
it. The engine sends it as `device_added`; without a named device there is no line. Tests:
`tests/commands.rs` (equal to the device list), the window's dialog and text tests.

**L1: record versions at the top.** `put_device_names` and `put_folder_list` took the held version
plus one unchecked, a panic with overflow checks once a version reached `u64::MAX`; both now
refuse with an error (`next_record_version`). The re-seal at the server's version
(`reseal_at_server_version`) took any number the server named: a malicious server naming
`u64::MAX - 1` made the device seal at `u64::MAX`, freezing the record. It now takes the
server's version only when it is below the version the server refused (this device holds a
forged higher one, the case it was made for) or when it is the version of the record this device
just opened and accepted. Starting low under a new epoch would avoid the problem, but the server
demands exactly its version plus one under any epoch (`server/src/service/records.rs`), so that
needs a server change: reported, not made. Tests: `account::tests::a_record_at_the_top_takes_no_further_version`,
`tests/removal.rs::a_bare_high_version_from_the_server_is_not_taken`.

**Info: the clipboard clearing.** A clearing thread that found its copy was the last one could
drop the next copy's secret from the held slot right after that copy set it; ending the app in
that minute left the new code on the clipboard. A copy and its clearing now each run under the
lock of the held slot, and a clearing only acts while the slot still holds its own text
(`src-tauri/src/clipboard.rs`, test `a_clearing_never_drops_the_next_copy`).

## Amendment 2026-11-27: delta pages in the engine

The engine part of the open point MEDIUM 2 of the amendment "security review of the sync
engine" (`MAX_DELTA_TOTAL`), on the page by page check of the amendment "delta pages".

- **Pull page by page** (`folder/pull.rs`, `FolderSync::pull_delta`): the pull of a round and the
  removal job ask for one page after the cursor, check it (`paging::check_page`: the page size,
  sequences above the cursor and rising, `more` only with an item, the server's sequence not
  below its items, the frontier not above the server's sequence) and hand it to
  `DeltaVerifier::push_page`. What a page lets through (`DeltaPart`) goes on at once: the
  heads' roots into the map of first parents, the check of every commit's reference delta
  against the trees (the counted set of the amendment "security review of the sync engine", now
  part by part: `TreeChecker`) and its timeline record with the drop counts. No list of raw
  commits is kept. A head the verifier holds back for its side commit comes out with the next
  page; its sequence and server time come from the last page's (`carry`), kept for that.
- **Nothing before `finish`:** the view, the remote tree, the timeline and `full_next` change
  only after `DeltaVerifier::finish` accepted the whole delta, as before. A refusal of the chain
  rules, of the tree check (a current device's delta that does not fit its tree), of paging or
  of the bound drops the stored state, so a refused delta is checked again from its start.
- **Stored state** (Check of the round only): after every page the index holds the verifier
  (`DeltaVerifier::encode`), the cursor, the frontier it began after, the last page's sequences
  and server times, the last head, the two flags of the tree check, and the page's timeline
  records under a key of their own (`pull/<folder>` and `pull/<folder>/<n>` in the account
  values; the records first, so a crash between the two writes only repeats a page). After a
  lost connection or a restart the next round goes on from there when the frontier is the same
  and the verifier decodes with the device log of this round; otherwise (another frontier,
  `ChainError::LogChanged`) it begins again. The counted set of the tree check is not stored: the
  first page after a restart reads the parent's tree once. Removing a folder removes its stored
  pull (`Store::delete_folder`).
- **Memory:** per head the verifier's chain entry (60 bytes), its timeline record and its root,
  about 200 bytes in all; of the commits only one page (at most 1,024 items of the protocol) and
  the open call. The timeline records are what the folder keeps afterwards anyway (LOW 5 of the
  review stays open: the timeline lives in the folder metadata).
- **Bound:** `MAX_PULL_COMMITS` (four million commits, `FolderSettings::max_pull_commits`)
  replaces `MAX_DELTA_TOTAL` for the pull and the removal job. Reason (conclusion): the server
  takes at most 30 commits per minute and account (amendment "security review of the sync
  server", M2), so a device that commits without a pause needs about 92 days to reach it, which
  the person and the operator see long before; the memory at the bound is below a gigabyte.
  Progress against endless pages stays: every page that announces more must hold an item and
  move the cursor, and only commits the devices really signed pass the check, so a server can
  only page forward over commits that exist.
- **Before the barrier:** the device that is refused by the removed signer rule reads the delta a
  second time page by page with `begin_check_before_barrier` and collects the removed heads; the
  removal job does the same for its permit, and its normal checks (another device wrote the
  barrier, the delta is already safe) use the same pull. These passes store no state; a removal
  job that stops is resumed by its own record and reads its delta again.
- **Incoming deletes:** the records are added to the timeline in one step after `finish`, as
  before, so the writers the incoming guard names (timeline records since the last apply) are
  the same. Within one page a part's side commits come before its heads, as for a whole delta
  before; over pages the records keep the server's order.
- **Re-anchor, open point:** `FolderView::reanchor_base` still takes the server's commits from
  cursor 0 as one list (bound `MAX_DELTA_TOTAL`, 200,000), because it walks back from the
  server's last head by first parents to the verified chain and checks that segment forward;
  it needs the whole delta and cannot be fed page by page without a change of the crypto crate.
  Draft of that change (not made here): a first page by page pass keeps per head only its ID
  and first parent (40 bytes, the map the walk back uses today) and the last head; the walk back
  gives the base and the segment's first sequence; a second page by page pass from the base
  checks the segment with the normal rules (a `DeltaVerifier` that starts from the base entry
  and the marks up to it, which `begin` does not offer yet) and collects the side commits.
  The engine part would then use the same stored state as the pull. Until then a re-anchor
  across more than 200,000 commits is refused as before, and only after the person confirmed
  "the server shows an older state".
- **Tests** (`tests/delta_pages.rs`, pages of four calls and a bound of 60 for the real sizes):
  `a_device_without_a_frontier_takes_a_long_delta_in_pages` (120 commits: beyond the bound
  refused with nothing taken in and nothing stored, within it every page, the folder equals the
  server's and the timeline A's), `a_pull_cut_off_midway_goes_on_from_its_stored_state` (cut after
  ten pages: nothing taken in, the stored state below 12 kB, the next round reads at most the
  remaining pages plus one, every commit once in the timeline),
  `a_changed_device_log_begins_the_pull_again` (a device added between the cut and the next
  round: the pull reads every page again and ends at the server's head),
  `a_rewound_server_after_a_cut_off_pull_stops_the_folder_and_keeps_nothing` (older state after a
  cut: the folder stops as `OlderState`, its frontier unchanged, the stored state gone),
  `a_device_joins_a_folder_with_more_commits_than_the_former_bound` (200,001 commits, ignored, run
  with `--ignored`). Every other test of the crate (delta binding, removal with removed signers
  and barriers, older states, the simulation, incoming deletes) passes unchanged on the paged
  pull. The memory server counts and cuts delta pages (`ServerState::delta_pages`,
  `delta_pages_left`).
- **Interface:** `FolderSync::fetch_delta` is gone; `take_outcome` takes the pulled delta and is
  crate internal; `write_barrier` takes the covered timeline records; new
  `FolderSettings::max_pull_commits`, `folder::MAX_PULL_COMMITS`, `paging::check_page`. Nothing
  of it is used by the app shell.

## Amendment 2026-11-27: follow-up check of the sync server fixes

An independent check of the amendment "security review of the sync server" found four points;
all are fixed with tests.

- **M2, address limits shared by every session behind one address (medium):** the token
  lookup limits (`CallIp`, `CallNet`) counted every call with a bearer token, so a compromised
  device in the same household (same public address) used them up, with made-up tokens or its
  own session, and the honest device got `rate_limited` for everything, also for removing it.
  A session token is now 16 random bytes and a 16 byte HMAC-SHA-256 tag over them under the
  server secret (`sessions::new_token`, label `hangar-drive/v1/session-token`). The
  authorization layer checks the tag in constant time (`sessions::issued_here`): a token with
  a valid tag counts against `CallToken` (per token, before the lookup) and, once
  `authenticate` admitted it, against `CallDevice` (per account and device); any other token
  counts against the address limits as before. The tag only picks the limit: whether the
  session exists, has not expired and belongs to a current device is still decided by
  `authenticate` alone, so a revoked token stays refused (test
  `a_token_the_server_issued_is_not_admitted_by_its_tag_alone`). It is no oracle: a valid tag
  needs the server secret, and it tells nothing a holder of the token does not know. Chosen over
  a cache of valid sessions, which would be empty after a restart, exactly when a flood would
  keep honest devices from being looked up once. Tokens issued before the change (at most one
  hour old) and after a lost `server.secret` carry no valid tag and only count as unknown.
  128 random bits stay out of reach of guessing. The upload address limit (`UploadIp`) is gone
  for the same reason; uploads count per account (`UploadAccount`) as before. Tests:
  `made_up_tokens_from_the_same_address_do_not_lock_out_a_session`,
  `a_flooding_device_does_not_keep_another_device_from_removing_it` (both from 127.0.0.1 with
  every limit divided by 30), `issued_tokens_and_sessions_never_touch_the_address_limits`.
- **L2, commit limits per account:** one device used up `CommitAccount` or set off the brake of
  `CommitRefusedAccount` for the whole account. Both count per device now (`CommitDevice` 30
  per minute, `CommitRefusedDevice` 20 per 10 minutes), with higher caps per account
  (`CommitAccount` 120 per minute, `CommitRefusedAccount` 60 per 10 minutes), so one device
  alone never reaches the account's caps, while the account as a whole still cannot keep the
  write lock busy. Tests: `one_device_uses_up_only_its_own_commits`,
  `refused_commits_brake_the_device_and_then_the_account`.
- **L3, the least pace cut off slow honest uplinks:** the 64 KiB/s pace of heavy bodies now
  applies only while another call waits for a heavy slot (`App::heavy_waiting`); without
  contention only the idle timeout (30 s) and the total timeout (120 s) apply, and the read
  looks again every 500 ms whether someone started to wait. A trickling body thus still frees
  its slot as soon as it holds someone up. Tests:
  `a_slow_body_passes_while_nobody_waits_and_is_cut_off_once_someone_does`,
  `a_heavy_body_below_the_pace_is_cut_off_after_the_grace`.
- **L4, connection cap per IPv4 /16:** one client of a provider or carrier NAT held the cap of
  its /16, and every other customer of it was locked out in the TLS mode. Connections now count
  per IPv4 /24 (IPv6 /48, `client_ip::connection_net_key`), and the network cap applies only
  while fewer than half of the 4096 slots are free; the counts are kept all the time, so the cap
  holds at once when the slots run short. Test
  `a_providers_network_is_capped_only_per_24_and_only_when_slots_run_short`.
- **Dependency:** none added (`hmac` was already used for the challenges).

## Amendment 2026-11-27: recovery in one piece, adds per day, delta check on a growing log

An independent follow-up check of the amendments "security review of the crypto and protocol
crates" and "delta pages" found three points; all are fixed with tests.

**H1 (high): a race in the recovery.** The recovery device added the person's new device F in
one call, and F removed the lost devices and rotated in a second call after signing in. A hostile
device that stayed online removed F with its rotation in between, as often as it liked; in the
reserve each round cost three places, so after about 44 rounds the log was full and the hostile
device stayed for good. And at the second-to-last place a recovery device could still add F,
which then could remove nobody.
- **One batch** (conclusion): a third batch shape, `BatchShape::Recovery`, in the recovery
  session's one append call: `[add device F (signed by the recovery device), remove device*
  (signed by F), rotate (signed by F)]`, the only batch with two signers, admitted only when the
  sender is a current recovery device. Rotation wraps go to every device current after the
  batch; `device_wrap` carries F's wrap of the epoch before it (so F opens the records it
  re-seals and can fetch that epoch later); the server stores both. `LogAppendRequest::validate`
  no longer refuses both kinds of wraps in one request; `append_wraps_fit` checks which kind
  fits which shape. `MAX_APPEND_ENTRIES` is 66 (the add, up to 64 removals, the rotation).
- **A log rule as well** (conclusion): after a recovery device's add, only F may write, and only
  removals and its rotation, until that rotation (`LogError::RecoveryOpen`), so every verifier
  sees that nothing came in between, not only the server. A recovery device adds only where the
  log still has room after the add: two places (a removal and the rotation), one when a rotation
  is already due; otherwise `Reserved`.
- **The two-step way is gone:** the add of a recovery device alone is no batch the server
  admits (`RecoveryOpen`), and the recovery session's scope check asks for at least two entries
  and the rotation's wraps. Keeping it would keep the race; the stuck-log exception (finding M5,
  section 4) needs nothing else, since F makes the due rotation in the same batch. Which devices
  the recovery removes is the app's choice; `epoch::recover` takes the list.
- **Reserve:** after every complete batch an account has at most `MAX_DEVICES` devices, and the
  person's part is one recovery batch of `1 + c' + 1` places; the bound of the amendment above
  is corrected there (at most 128 of the 132 places).
- Tests: `nobody_writes_between_a_recovery_and_its_rotation` (the attacker's removal of F, its
  other entries and a second add are refused while the recovery is open; the batch in parts or
  without its rotation is refused), `the_recovery_batch_cannot_be_used_by_a_regular_device` (a
  regular device's add with removals and rotation by the added device, a removal signed by
  another device, another sender), `a_recovery_fits_at_the_end_of_the_log` (no add at the
  second-to-last place, the batch at the last three places, with a due rotation at the last two,
  and after the worst use of the reserve), the reworked
  `a_recovery_device_may_add_one_device_while_a_rotation_is_due` and
  `a_full_account_still_lets_the_recovery_device_in` (`devicelog.rs`);
  `server/tests/recovery_cap.rs`: the full account recovered in one call over the socket, the
  attacker's session ends in the same call, the recovery session cannot add on its own, a
  regular session cannot send the recovery shape; `flows.rs`, the recovery session test.

**M1 (medium): add and remove cycles filled the log before the reserve.** Removals are free and
adds were limited to 30 an hour: a device that adds a throwaway device, removes it and rotates
appends three entries per add, about 90 an hour, and the reserve was reached in about four days.
- **Adds per day** (conclusion): every added device of a regular device also counts against
  `ADDS_PER_DAY` = 20 per account and day (`server/src/service/devicelog.rs`). Each cycle needs
  an add, so the log grows by at most 60 entries a day that way: about 134 days from an empty log
  to the reserve, and the reserve still keeps every device removable. Twenty new devices a day is
  far above any household's pairing; removals, the due rotation and the recovery are never
  counted.
- Not chosen: counting removals of devices the remover added "recently". The log has no time
  of its own, and every recency the log can express (same epoch, a few entries) the attacker
  controls, since its own removals advance it; a format rule cannot bound a rate. Counting
  removals at all would let an attacker use up the count that the person needs to remove it.
- The count lives in memory in the device log service until the rate limiter has a day scope of
  its own (a scope `LogAddDayAccount`, 20 per 86,400 s, is the clean place).
- Tests: `adds_are_bounded_per_day` and the reworked
  `one_plain_rotation_an_hour_and_removals_after_every_limit` (unit tests), the reworked
  `device_log_appends_are_throttled_and_removals_never` (`server_review.rs`: 20 adds, then
  refused, also an hour later; the removal of the thief passes; a day later adds pass again).

**M5 (medium): the delta check began again on every log change.** A hostile device changes the
log about once a minute, so a slow device with a long history never reached `finish`.
- **Pinned to the log it began with** (conclusion): `DeltaVerifier` applies every rule to the log
  as it was at `begin_check`; pages, `finish` and `decode` take a newer log that extends it
  (`ChainError::LogChanged` only for a log that does not hold the pinned head). The check stops
  instead (`DeltaVerifier::cut`) at the first call with a commit that names a log head beyond the
  pinned one, or whose signer the newer log has removed since; that call and everything after
  it is the next delta, checked from the accepted view against the newer log. `finish` refuses
  with `LogChanged` only when the newer log removed a device whose heads were already checked.
- **Why it is never weaker:** every accepted commit names a head of the pinned log, where the
  newer log vouches for the same signers and keys; no accepted head comes from a device the newer
  log removed after the pinned head, and so no head that would cover a removed signer under the
  pinned log is one the newer log would not count. The removed signer rule therefore reads the
  same under both logs, and the accepted part is exactly what `check_delta` against the newer log
  accepts for it, with the same view. A delta whose commits need the newer log is left to the
  next pull, never let through on the older one; with an unchanged log nothing changes.
- **Progress:** the commits written after the pin are at the end of the history, so the cut
  falls there and the long part before it is accepted; a restart is needed only when a device
  with heads already checked is removed during the check, which the removal itself bounds (and
  adds per day bound for throwaway devices).
- Tests: `a_growing_log_does_not_restart_the_check` (the newer log between pages: the check stops
  at the first commit naming it; the rest as the next delta gives the result of the whole delta
  against the newer log), `a_removal_in_the_newer_log_is_never_missed` (b removed during the
  check and the barrier left out: known from the first page, b's heads are left to the next
  delta, which the rule refuses; known only at the end or after a resume from storage,
  `LogChanged`), `a_stored_delta_check_resumes_with_its_own_log_or_a_longer_one`. Every delta of
  every test still runs against the whole delta check at random page boundaries.
- API changes for the engine: `DeltaVerifier::cut()` is new; `push_page`, `finish` and `decode`
  take a newer log; the stored state's format byte is 2 (states of format 1 are refused as
  `InvalidView`: begin again). `AccountState::last_removal_index_at` is new.

The formats on the wire and the fixed vectors do not change (`test_vectors.py`: all 61 match);
the shared rules change (recovery batch, the open recovery, the add's room at the end of the
log).

## Amendment 2026-11-27: the engine on the recovery in one piece and the growing log

The engine part of the amendment "recovery in one piece, adds per day, delta check on a growing
log" (H1 and M5).

**Recovery in one append** (`crates/hangar-drive-sync/src/recovery.rs`, `engine.rs`).
- `recovery::prepare` (steps 0 to 3): the sheet is checked against the code, the recovery
  session reads the verified log, checks the genesis anchor and the code's recovery device
  (current, a recovery device, the code's keys), and lists the current regular devices with
  the time their add entry was issued. It writes nothing.
- `recovery::recover_with_code` (step 4): reads the log again, unwraps the current epoch's
  secret, and sends one `LogAppendRequest` built by `epoch::recover`: the add of the new device
  (signed by the recovery device), the removal of the chosen devices that are still current
  regular devices and of every current recovery device, the used one included, and the
  rotation (signed by the new device), with the rotation's wraps and the new device's wrap of
  the epoch before (`device_wrap`). The log head after the batch is computed here and must be
  the server's answer (security review I1). The former `add_device_with_code` (the add alone) is
  gone, as the server no longer admits it.
- The engine keeps its three calls in their order. `recover_account` signs in as the recovery
  device and runs `prepare`; the session, the sheet, the code and the new device's keys wait in
  memory (`Recovering::before_join`). `recovery_devices` lists the devices from the verified log.
  `finish_recovery_cleanup` makes the one append with the chosen devices, signs in as the new
  device, joins at the head after the batch, and runs the removal job, whose append step finds
  the removals in the log already (`removal::resume`), so it re-seals and writes the barriers with
  the new device's own removal (`BarrierPermit::of_own_removal`); then the device name and the
  new code as before.
- **Records sealed before the batch:** the batch removes the devices that sealed the account's
  records, and a record opens only when its sender is current, so the new device could not open
  them against the whole log. At its join, and only for a device a recovery device added, a
  record that does not open is opened once more against the log right before the batch
  (`Account::recovery_base_of`), the state every current device held then; the guard checks it
  as always. Nothing a removed device seals after the batch is stored (the server takes records
  of the newest epoch only), and the new device seals everything again under the new epoch right
  after the join. Conclusion: the new device trusts the records the account held right before the
  recovery, as a device joining before the removal did in the two-step way.
- **Before the choice nothing is in the account:** an end of the app or a cancel between
  `recover_account` and `finish_recovery_cleanup` leaves the log as it was and the code unused
  (a code is "used" exactly when its recovery device is removed, which only the batch does). A
  failed append leaves the same; the person starts again.
- **Keeping every old device stays possible:** `epoch::recover` needs a removal unless a rotation
  is due, and the batch always removes the used recovery device (as the cleanup did before), so
  the list of chosen devices may be empty. No behavior change for the person there.
- **What changes for the person:** before the choice the recovery session cannot read the sealed
  device names (its scope is the log, its own wrapped keys and one append), so the devices come
  without names, with their ID and the date they were added. And a "code used" or "unknown code"
  now ends `finish_recovery_cleanup` as well, when another device removed the recovery device
  between the two calls.
- The memory server keeps a recovery's `device_wrap` under the epoch before the batch and
  announces the batch's epoch in the feed, as the server does.

**Delta check on a growing log** (`folder/pull.rs`).
- A stored check resumes with a longer log (`DeltaVerifier::decode` takes it). When it stops at the
  first call that needs the newer log (`DeltaVerifier::cut`), the pull finishes the part before
  it and, in the same round, checks the rest as the next delta from the accepted view against
  this round's log, with the cursor back at the accepted frontier. A check begun in this round
  is pinned to this round's log and is not cut.
- A page that names a log head beyond this round's log (`AheadOfLog`) or an unknown generation
  keeps the stored state: the round reads the log and goes on from the state stored before that
  page. `LogChanged` (a log without the pinned head, or a removal of a device whose heads were
  checked) and a stored state of format 1 (`InvalidView`) begin again.
- The stored state is written after a page only when an eighth more pages were read since the
  last write (at least one page), so writing stays linear in the delta, since each write holds
  every chain entry checked so far; the timeline records of every page are stored at once, and
  records after the last state are written again on the resume. Removing the stored pull also
  removes such records.
- Tests (`tests/delta_pages.rs`): `a_growing_log_goes_on_with_the_pull` (a device added between
  the cut and the next round, A's later commits naming the newer log head: the next round reads
  at most the remaining pages, the page of the cut again and one more, and ends at the server's
  head with the whole timeline) replaces `a_changed_device_log_begins_the_pull_again`;
  `a_stored_pull_without_its_pinned_log_head_begins_again` (the stored pinned head changed: every
  page again).

**Changes the app needs** (not made here; `src-tauri` and `src` build unchanged):
- Recovery dialog, device list (`recoveryDevices`): `Device.name` is empty before the join; show
  "Gerät, hinzugefügt am {date}" from `added` instead of a name, in every language.
- The step text: the new device is not in the account until "Fertig"; closing the dialog before
  ends the recovery without changes, and the code stays valid.
- `finishRecoveryCleanup` can now fail with the reasons `recoverAccount` had ("code used", "code
  unknown", "not reachable"); it reports them as `SyncError::Invalid` or `Net`. The app maps them
  to the recovery texts and lets the person start again.
- Keeping all old devices is allowed (an empty list); the used code always stops working.

## Amendment 2026-11-27: a recovery survives every failure after its append

A security review of the recovery in one piece found that every failure after the append made
the account unusable for good, and two smaller gaps. Fixed in `crates/hangar-drive-sync`; tests
in `tests/recovery_resume.rs`.

**HIGH 1: a failure after the append threw the only key away.** Once the batch is sent, the code
is spent and the chosen devices are gone, yet every later failure ran into "nothing happened,
start again": a head the server answered wrongly, an answer lost after the commit, the end of the
app before the join, a failed sign-in of the new device, or a failed join. The join deleted the
new identity, the engine dropped it, and a person who had removed every old device lost the
account. Without any hostile server, two cases led there as well: a record under an epoch older
than the current one (the new device only gets the wraps of the current epoch and the one after
the batch), and a record a hostile but current device left signed but unreadable (the server only
checks header and signature); the join's refresh stopped at either.
- **Pending recovery.** Right before the append goes out, the engine stores the new device's
  identity in the keychain (`recovery-identity`) and a marker in the local index
  (`recovery-pending`: account, device, name, server address, pin, server ID, genesis anchor, the
  head after the batch computed by this device, the removed devices). The marker holds nothing
  secret. It goes once the new device joined and wrote the barriers, or once the recovery
  device's own verified log shows that the batch is not in.
- **Resolution by the new device's own log.** Whatever the server answers to the append, the new
  device signs in and joins at the head this device computed (with the genesis anchor). A join
  that works proves the batch is in; a head the server made up is no reason to stop any more,
  since the join checks the computed head against its own verified log (I1 holds: the anchor is
  never the server's value). When the join fails while the recovery session is still open, the
  recovery device reads its log: while it still lists the recovery device (which the batch
  removes) and not the new device, the batch is not in, and the marker and the key go, the choice
  stays, and the same code works again (a server that hides a batch it took from the recovery
  device can make this device drop the key; such a server can withhold the whole account
  anyway, and the next attempt works on the log it shows). Otherwise everything stays: the engine tries again in its
  loop (every `POLL_INTERVAL_MS`), at a repeated `finishRecoveryCleanup`, after a restart, and
  when the person types the code again (`recoverAccount` first lets the pending device join; only
  a log that still lists the recovery device drops the earlier attempt). A marker of another
  account makes `recoverAccount` refuse; "reset this device" removes marker and key as every
  other secret.
- **A join cut short is completed.** The join stores the account before it writes the records it
  could not read anew; a restart in between finds the stored account with the marker and runs
  `Account::complete_recovery_join` (every record read again from cursor 0, the same leniency,
  then the writes), then the barriers.
- **Lenient join, only after the own recovery** (`Account::join_recovered`). A record that opens
  neither against the log nor against the log before the batch, or whose epoch secret the server
  does not hold for the new device (`not_found`), counts as missing; failures of the connection,
  the keychain or the local index still stop the join, so it is tried again. The leniency holds
  only for a device whose add a recovery device signed (`recovery_base_of`) and only during that
  join; `Account::join` for pairing is unchanged, and the replay guard checks every record the
  join does take. When the new device is the only regular device left, it writes the missing
  records anew under the new epoch at the server's version plus one: a folder list it could not
  open becomes an empty one, the device names list only itself, and a folder whose key ring it
  could not open leaves the folder list (no device holds that key any more; the folder's files
  are out of reach either way; replaced by LOW 2 of the "follow-up review of the recovery after
  its append" below: the folder stays and the `foldersUnreadable` warning names it). With other regular devices left it writes nothing; they re-seal
  under the new epoch (N1). A later device names or folder list write after a skipped record
  takes the server's version plus one as well.
- **What the person loses in the worst case:** with a hostile device that overwrote the folder
  list, the list of folders (their rings stay on the server, unnamed); never the account.
- Tests: `a_lost_answer_after_the_append_still_joins`,
  `a_recovery_cut_off_before_the_join_finishes_after_a_restart`,
  `typing_the_code_again_finishes_a_pending_recovery`,
  `a_record_under_an_older_epoch_does_not_stop_the_join`,
  `an_unreadable_record_of_another_device_does_not_stop_the_join`,
  `an_unreadable_folder_list_becomes_an_empty_one`,
  `a_join_cut_off_midway_is_tried_again` (an identity the cut off join left under the device
  identity's entry, with no stored account, is removed exactly when it is the pending one:
  `Account::drop_unfinished_join`),
  `an_append_that_did_not_go_through_starts_over_with_the_same_code`. The former test
  `a_recovery_refuses_a_head_the_server_made_up` becomes
  `a_recovery_joins_at_its_own_head_when_the_server_makes_one_up`. The memory server can lose an
  append's answer, drop an append, and go offline right after one.

**MEDIUM 1: a device added while the person chose survived.** The append read the log again and
removed only the chosen devices, so a device added between the list and the append stayed in the
account unseen. The list now keeps the head of the log it was read from (`RecoveryChoice::shown`);
`recovery::build_recovery` refuses with `RecoveryError::ListChanged` before anything is written
when the log moved on, the engine reads the list again and answers
`SyncError::RecoveryListChanged` (`ErrorKind::RecoveryListChanged`, `"recoveryListChanged"`), and
`recoveryDevices` returns the new list. Test:
`a_device_added_while_the_person_chooses_is_offered_too`.

**Typed refusals of the append.** "Code used" and "code unknown" at `finishRecoveryCleanup`
were `SyncError::Invalid` with a fixed text, which the app had to compare. They are
`SyncError::RecoveryCodeUsed` (`ErrorKind::RecoveryCodeUsed`, `"recoveryCodeUsed"`) and
`SyncError::RecoveryCodeUnknown` (`ErrorKind::RecoveryCodeUnknown`, `"recoveryCodeUnknown"`, also
for a sheet the code was not made for) now, both before anything is written. Test:
`a_code_used_in_between_is_its_own_error`.

**LOW 1: an account left without a recovery device went unnoticed.** The app could end after the
join and before the new code was added. The snapshot now carries the warning
`{"kind": "noRecoveryCode", "id": "noRecoveryCode"}` while the account is set up and its log has
no current recovery device; it cannot be hidden and goes once a new code is confirmed
(`renewRecoveryCode`, which also ends a recovery that joined but stopped before its code). While
a recovery is pending and this device has no account yet, the snapshot carries
`{"kind": "recoveryPending", "id": "recoveryPending"}`.

**Changes the app needs** (not made here):
- Decode and show the warnings `noRecoveryCode` (banner with "Neuen Wiederherstellungscode
  erstellen", calling `renewRecoveryCode`) and `recoveryPending` (the recovery is being completed;
  typing the code again also works), in every language.
- Map `ErrorKind::RecoveryCodeUsed` and `ErrorKind::RecoveryCodeUnknown` from
  `finishRecoveryCleanup` instead of comparing error texts.
- Map `ErrorKind::RecoveryListChanged` from `finishRecoveryCleanup`: tell the person that the
  account's devices changed, reload `recoveryDevices` and let them choose again.
- After a failed `finishRecoveryCleanup` keep the dialog: the call can be repeated (before the
  append the choice stays; after it the pending recovery is completed).

## Amendment 2026-11-27: follow-up review of the recovery after its append

A second security review of the previous amendment found one medium and several low points.
Fixed in `crates/hangar-drive-sync`; regression tests in `tests/recovery_resume.rs` (among them
the review's two probes with the expectation turned around) and one test against the real
server.

**M1: a retry after a refused append could keep a device unseen.** When the recovery's reads
missed a device added right before its append, the batch built on the shorter log was refused
(the real server refuses an append whose first entry does not chain to the log's head:
`a_recovery_built_on_a_stale_log_is_refused_by_the_real_server` in `tests/e2e_server.rs`).
`settle_unsent` then took the new log as the shown one and returned the send error, so a retry
with the same choice went through and left the added device in the account. Now `settle_unsent`
compares the recovery device's log with the one the person chose from: when it ends elsewhere,
the choice takes the new list and `finish_recovery_cleanup` answers
`SyncError::RecoveryListChanged`; only on the same log is the send error returned. Test:
`a_device_added_between_read_and_append_is_offered_before_the_retry`.

**LOW 2: too much counted as unreadable, and a folder left the list silently.**
- `unreadable` takes only failures to open: `not_found` for the epoch wrap, a wrap that does not
  open, a missing secret, the record header, and the opening errors of a record (malformed,
  format, sender, signature, decryption, padding). The replay guard, a version the server named
  wrongly, a record ahead of the log, an unknown epoch, the checks on what an opened record holds,
  the connection, the keychain and the local index stop the join as before (unit test
  `only_records_that_do_not_open_are_unreadable`).
- A folder whose key ring the join could not open stays in the folder list. Its ring is kept as
  unreadable in the stored account (`Account::unreadable_records`) and read again, leniently and
  against the log before the batch as well, at every refresh that fetches it, until it opens (the
  server shows it intact, or a remaining device re-seals it). Then the barriers of the recovery's
  removals are written for that folder (`Account::take_recovered_rings`,
  `Account::removed_by_own_recovery`), which it could not get while its ring was unreadable;
  without them it would stop at the removed devices' heads. That they are due is stored with the
  account (`rings_recovered`) and cleared only once they are written, so an end of the app in
  between writes them at the next start (test
  `barriers_for_a_ring_that_came_back_survive_a_restart`). The same holds for the folder list
  and the device names while another regular device is left to re-seal them. This is the only
  leniency after the join, and only for these keys.
- The window is told with one warning, `foldersUnreadable`, which names the folders whose key
  could not be read and says whether the folder list itself could not be read (the empty list the
  only device left had to start with). One warning is enough for the person: both cases mean
  "some folders are not reachable right now", and the folder names are what they can act on. It
  cannot be dismissed while it names a folder; with only the folder list it can, since nothing
  comes back by waiting. Test: `a_ring_the_server_damages_during_the_join_comes_back` (the
  review's probe `a_ring_the_server_damages_during_the_join_drops_the_folder_for_good` turned
  around).
- This replaces the rule of the previous amendment that dropped such a folder from the list.

**LOW 3: the marker was not protected.** The keychain entry of the pending recovery now holds a
format byte, the SHA-256 of the marker and the identity; a marker that does not match it, or one
without its key, is refused and nothing is acted on (the key and the warning `recoveryPending`
stay). A key without a marker (the app ended between the two writes, before the append) is
removed at the next start. Test: `a_changed_marker_is_refused`.

**LOW 4: the leniency could outlive the join.** The recovery counts as pending until its marker
is gone; a failure to remove it is returned. The stored account notes whether its join after the
recovery is still open (`recovery_join_open`), and `complete_recovery_join` does nothing once it
finished, so a marker left behind brings no leniency back. Test:
`a_marker_left_after_the_join_brings_no_leniency_back`.

**LOW 5: the device names of the new device alone.** While the new device could not read the
names and another regular device is left, it does not write a list of itself alone (that would
drop every other name); the remaining device re-seals the names under the new epoch, and the
loop adds the new device's name once the names are readable. Test:
`unreadable_names_wait_for_the_device_that_is_left`.

**LOW 7: a reset could destroy the only key.** `reset_device` refuses with
`SyncError::RecoveryPending` (`ErrorKind::RecoveryPending`, `"recoveryPending"`) while a recovery
is pending and this device has no account yet. `reset_device_discarding_recovery` resets anyway;
the app calls it only after the person confirmed that the account may then be lost. Test:
`a_reset_during_a_pending_recovery_needs_the_forced_reset`.

**LOW 6 (a server that forks), not changed:** `settle_unsent` drops the earlier attempt's key
when the recovery device's log still lists the recovery device. Keeping it as "superseded" until
a new join succeeds was considered and not done: the key helps only if the server later shows a
log with the first batch after all, and then the new attempt's device lives in the other fork,
so neither key gives one consistent account; keeping keys of abandoned forks with no way to use
them leaves secrets behind (security review L1). A server that forks controls what every device
sees and can withhold the account in any case. With M1 above, a log that moved on is shown to
the person instead of being acted on.

**Precision on the leniency:** `Account::join` (pairing) runs the strict refresh. The leniency
needs the log before a recovery batch (`recovery_base_of`), which exists only for a device whose
add a recovery device signed, and the writes in place of unreadable records need
`Account::join_recovered`; the engine joins a paired device through `Account::join` only, so
none of this applies to it.

**Changes the app needs** (not made here):
- Decode `{"kind": "foldersUnreadable", "id": "foldersUnreadable", "folders": [names],
  "folderList": bool}`: a banner naming the folders (they could not be opened after the
  recovery and come back by themselves once the server or another device provides them), and
  with `folderList` that the list of folders had to start empty. Dismissible only without
  folders.
- Map `ErrorKind::RecoveryPending` from `resetDevice`: explain that a recovery is not finished
  and that resetting may lose the account for good; offer "Reset anyway", which calls
  `resetDeviceDiscardingRecovery` after a native confirmation.

## Amendment 2026-11-28: the engine stays responsive during long work

**Finding (release 0.1.0, Windows, own server over HTTPS).** After the setup with two folders of
about 1,600 files the window stayed empty. The engine thread was inside one sync pass for
minutes (`FolderSync::round` -> `upload` -> `ServerApi::put_object`), while two
`EngineHandle::call(|core| core.snapshot())` waited for it. Cause: `Engine::spawn` ran
`EngineCore::tick`, and each tick ran a whole round per folder (scan with every hash, every
upload, the commit, every download) before it took the next command or sent a snapshot. The loop
also took only one command per pass and paused for the full tick interval even with work left.

**Decision: a work budget per pass.** `engine::WORK_BUDGET_MS` (1 s of `Clock` time) is shared by
the folders that run a round, each with at least 250 ms (`FolderSettings::work_budget_ms`, set by
the engine per pass; direct callers of `FolderSync::round` and the round inside `revert` run
without one). A round stops at a clean point once the budget is spent and reports
`RoundReport::more`; every phase still does at least one unit, and a phase that starts after the
budget is spent still gets a quarter of it, so a round whose scan and plan took the budget moves
the transfer on.
- **Hashing:** the scan hashes in batches of at most 32 files or 64 MiB and checks the budget
  between batches. Files left over wait for the next scan: a file the local tree knows keeps its
  known version (`recheck`); a new file stays out of the tree (`deferred`, path and size); the
  next scan lists both again, also a partial one. A file the synced tree knows by item is always
  hashed, since leaving it out would read as a local delete. A remote file at the path of a
  waiting new file does not keep it from waiting (see "Follow-up review" below). A large first
  scan therefore publishes in several commits, each a valid tree.
- **Uploads:** checked before each object but the first. A cut ends the publish with
  `PublishFailure::Yielded` before the commit: nothing half is committed, and the round saves
  and returns. A side commit is signed (and takes a counter value) before the head's upload, so
  a cut there skips one counter value, as a lost compare-and-swap already does; harmless, since
  counters only need to grow. The next round plans and encodes again (directory
  nodes and manifests have keyed IDs from their plaintext, so they get the same IDs) and asks
  the server what it lacks, so nothing is uploaded twice. Objects uploaded without a commit are
  kept by the server for 24 hours (`retention.rs`, "young uploads"), which covers a cut, an
  offline phase or an end of the app in between. Stages of a publish too large for one commit
  are whole commits each, as before.
- **Downloads:** checked before each file but the first, next to the existing bound of 1 GiB per
  round; a file is written atomically and is not split. *Superseded the same day:* a file of
  several chunks now arrives in parts across rounds (amendment "transfers that never hold the
  engine thread").
- **The loop:** when the last pass reports more work it does not pause, runs every waiting
  command (not one per pass) and starts the next pass. The thread sends the stored state as a
  first `BackendEvent::Snapshot` before the first pass (`EngineCore::first_snapshot`).

**Snapshot.** `sync.bytesLeft` was always 0 and now carries the bytes left: during an upload the
exact bytes of the objects the server still lacks (`FolderSync::upload_left`), otherwise the size
of the local files whose content the synced tree lacks, plus the size of the remote files whose
content is not on this disk, plus the new files that wait for their hash; renames and new times
count nothing. The upload count of a folder and `pendingFiles` include the new files that wait
for their hash, so a large first scan never reads as up to date. The upload count falls only with
a commit (the synced tree follows then), so during one upload `bytesLeft` is what moves from
snapshot to snapshot. `lastSync` is set only by a pass that was not cut and ends in sync. New
field `folders[].fileCount` (`Option<u64>`, JSON `"fileCount": number | null`): the files of the
folder on this disk, directories and the folder's marker not counted, plus the new files that
wait for their hash, so the number does not jump during a large first scan; `null` before the
first scan, like `bytes`, which now counts the waiting files' bytes as well.

**Network calls.** Every request of `HttpServer` has a connect timeout of 15 s and a request
timeout of 60 s (head and every read of the body; reqwest 0.13 blocking), with at most four
attempts and a bounded backoff; the event stream uses its own read timeout of 75 s. No single
call blocks without bound. *Superseded the same day:* connect timeout 10 s, no retry after a
timeout, pool idle limit 5 s (amendment "transfers that never hold the engine thread").

**Not split yet.** The pull of a folder's delta and of the head's tree (the tree check walks the
tree's objects; the plaintext cache makes a repeated walk cheap, but a cut needs the paged pull
state to keep it, which today only a lost connection does), re-anchoring after an older state,
and a person's restores (`publish_tree`) still run to their end within one pass. A single file of
several GiB is hashed, sealed or written whole. These are follow-up work. *Partly superseded the
same day:* hashing and downloading a large file are split (amendment "transfers that never hold
the engine thread"); pull, re-anchoring and restores are still whole.

**Follow-up review of the budget (security review, same day).**
- **H1 (high): a waiting new file and a server item at its path ended in "cannot sync" for good.**
  The scan decided against the remote tree before the pull (a new folder starts with an empty
  remote tree); the download then met the file on disk (`Exists`, nothing lost) and the item
  stayed in `cannot_sync`: on a join of a large non-empty folder files stayed unsynced for good,
  later changes did not arrive, and the folder still said in sync. Now `apply_plan` leaves every
  item of the plan at the path of a waiting new file (comparison key per name) alone in that
  round, with its subtree, and reports `more`; once the file is hashed the merge sees both, as
  without a budget. This holds after every pull of the round, also the one after a lost
  compare-and-swap, and keeps the budget during a join instead of hashing every overlapping file
  at once. Tests: `rounds::a_join_with_the_budget_leaves_no_file_unsynced`,
  `rounds::edits_after_a_join_with_the_budget_reach_both_devices`,
  `rounds::a_new_file_waiting_for_its_hash_meets_a_remote_file_of_its_name` (both versions kept,
  one as the conflict copy), control `rounds::a_join_without_the_budget_leaves_no_file_unsynced`.
- **L1: a cut round could report in sync.** `RoundReport::in_sync` is false while files wait for
  their hash or the round was cut; the engine sets `lastSync` only for a pass without a cut. Test:
  `rounds::a_round_with_files_waiting_for_their_hash_is_not_in_sync`.
- **L2: a server that keeps nothing drove the loop without a pause.** A server that answers
  `put_object` but keeps listing the objects as missing made every pass cut and ask for the next
  one at once. The upload remembers what it sent before a cut (`cut_sent`); when the next upload
  finds one of those missing again, its cut does not set `more`, so the loop keeps its pause.
  Test: `a_server_that_keeps_nothing_does_not_drive_the_loop_without_a_pause`
  (`ServerState::forget_puts`).

**Snapshots after commands and cheap snapshots.**
- After the waiting commands the loop sends a changed snapshot right away
  (`EngineCore::changed_snapshot`), before the pass, which may work for its whole budget, so a
  pause, a resume or a paused folder shows at once. Test:
  `a_command_shows_in_a_snapshot_before_the_next_pass`.
- A folder's numbers (upload and download counts, bytes left, files and bytes on disk) are kept
  with a `folder::SummaryKey` and computed again only when it changes: the editions of the local,
  synced and remote trees (`Tree::edition`, a process-wide unique number set by every insert and
  remove, equal for a tree and its unchanged clones), whether the local tree is known, the
  folder's state, the waiting files, the upload's bytes left and the cannot-sync list. A snapshot
  of an unchanged folder of 100,000 files walks no tree. Test:
  `a_snapshot_of_an_unchanged_folder_walks_no_tree` (`EngineCore::folder_sums_computed`), and
  `the_file_count_serializes_and_follows_the_disk`.

**Tests** (`tests/engine_budget.rs`, with the test hooks `memory::SharedClock`, `WorkCost`,
`ServerState::put_cost`, `get_cost`, `object_puts` and `MemFs::set_read_cost`):
`the_engine_answers_and_reports_progress_during_a_large_upload` (engine thread with the app's
5 s pause: commands answered within 1.5 s during the upload, progress snapshots with falling
`bytesLeft`, every object uploaded once),
`an_upload_cut_off_by_the_end_of_the_app_resumes_after_a_restart` (no commit after the first
pass, the restarted engine finishes, every object once, the server holds exactly the committed
tree), `a_large_first_scan_hashes_in_slices_and_commits_every_file` and
`a_large_download_writes_files_in_slices`. All four fail with the budget switched off.

**Second performance review: rounds that cost only what they do (same day).** An analysis found
that the budget made every cut round repeat the whole preamble of its upload, and that idle
rounds cost a pull, a scan and several saves per folder every 5 s. Changes (`folder.rs`,
`engine.rs`, `watch.rs`):
- **A: a cut upload goes on.** A round cut during its upload keeps the plan and its encoding
  (`PendingPublish`), valid while the editions of the three trees, the frontier, the remote root
  and the writable generation are unchanged and nothing was stored outside a round (a person's
  action drops it in `FolderSync::save`). Each upload keeps its queue across rounds
  (`UploadJob`, keyed by the encoded root and the writable generation): the next round asks the
  server only about what the last round sent (the L2 check, now one small query), and before the
  upload reports done the server is asked about every candidate again unless that ask was in this
  round, since it deletes uploads no commit names after a day. Objects found present or sent
  during the uploads under way (`known_present`) are not asked about again by an upload of a
  new plan; that ask before the commit covers them. A scan with no reported path and nothing
  waiting reads nothing. The upload phase ends at the round's budget, but never before a quarter
  of the folder's share and at least 250 ms (`UPLOAD_FLOOR_MS`) have passed in it, fixed once
  per round for all uploads of the round; the engine shares the pass budget only among the
  folders that run a round. Nothing is committed half: every upload and its final ask finish
  before `content()`, signing and sending. Measured in
  `a_cut_upload_goes_on_without_asking_about_every_object_again` (60 files, 121 objects, 13
  passes): 362 object IDs asked in 14 queries and one delta pull, against 1,694 IDs and a pull
  per pass before.
- **C: intermediate commits.** Once an upload sent `FolderSettings::stage_bytes` (256 MiB) or
  `stage_objects` (8,192 objects) since its last one, and at least `stage_interval_ms` (30 s,
  within the server's 30 commits per device and minute) after it, it commits the server's tree
  plus the files whose every chunk is on the server, with the directories they need
  (`stage_ready`, a single walk; a name that collides by any of its keys waits), through the
  existing `publish_stage`. A file still uploading never shows. This runs before the side commit
  and the final commit. When the disk held the head before fully, the sync base moves to the
  stage, so the final commit needs no side commit; a folder never fully synced keeps none. Other
  devices see a large first upload grow, and the 24 hour collection of uncommitted uploads no
  longer makes a first upload of more than a day start over. Tests:
  `rounds::a_large_upload_commits_as_it_goes_and_the_other_device_sees_a_part` (40 files, six
  commits, the other device saw 8, 16, 24 and 32 files) and
  `rounds::a_restart_after_an_intermediate_commit_goes_on` (no conflict copy, every object once).
- **F: idle folders are skipped.** With `FolderSettings::pull_on_demand` (set by the engine) a
  round pulls only when the change feed reported a head other than this device's frontier
  (`FolderSync::note_remote_head`, also a lower one, so an older state is noticed), at start,
  after a failed pass or round, after a feed read from its start or a changed log, and hourly
  with the full scan. `FolderSync::wants_round` skips a folder whose last round ended in sync with
  nothing reported, waiting or stored since; it still reads the root marker each pass, since no
  watcher reports its loss. `save()` writes nothing when no row and no metadata byte changed.
  Tests: `an_idle_folder_costs_only_the_feed` (20 idle passes: 20 calls, no pull, no save),
  `a_head_the_feed_reports_is_pulled_in_the_next_pass`,
  `a_head_the_feed_missed_is_pulled_within_the_hour`.
- **N: the watcher wakes the loop.** Every watcher event rings a `watch::Waker`; the engine thread
  runs a pass `WAKE_DEBOUNCE_MS` (400 ms) after the first event of a burst instead of after its
  5 s pause. A command still runs a pass at once. The watchers hold a sender of the loop's
  channel, so the last `EngineHandle` ends the thread with a stop message. Test:
  `a_change_on_disk_wakes_the_engine_before_its_pause` (synced after about 430 ms with a 120 s
  pause).
- **H: read order.** The queue holds chunks by path and chunk index, then sealed nodes and
  manifests; chunks the disk cannot produce come first, so a changed disk ends the upload early.
  Test: `rounds::chunks_go_up_in_path_and_chunk_order`.

Every new test except the feed pull fails with its change taken out (the feed pull is a guard
that also held when every round pulled). Not done: the store has no batch in its trait, so the
chunk list and cache writes are not grouped into one transaction yet (`SqliteStore::batch` is
generic and cannot be called through `dyn Store`).

**Security review of the client changes (same day).**
- **MEDIUM 1: a file rewritten every second drove the device into the server's commit limit.**
  With the watcher's wake-up every change made a commit; past 30 per device and minute the
  server refused and the client's wait held the engine thread for every folder. Now the commits
  of a folder's rounds are paced by a bucket of `PUBLISH_BURST` (3) that refills by one every
  `PUBLISH_INTERVAL_MS` (5 s, `FolderSettings::publish_interval_ms`): the first changes after a
  quiet spell go out at once, a stream of changes makes one commit per 5 s. Only the commit
  waits (`PublishFailure::Held`, after the upload and its last ask, before the side commit):
  the round keeps its plan, ends without `more` and not in sync, nothing of the plan reaches the
  disk, and the folder's rounds wait until `FolderSync::hold_until` unless a pull is due or
  files wait for their hash; the loop wakes for it (`EngineCore::next_due_in`). A bucket rather
  than a fixed gap, so a clock that stands still (tests) or a few quick actions are not held.
  All rounds of the device share
  `DEVICE_COMMITS_PER_MINUTE` (20) commit calls per minute, intermediate, side and repair commits
  and refused calls included (`FolderSettings::commit_allowance`, `FolderSync::round_commits`);
  an intermediate commit keeps one for the final commit. The person's actions (restores, undo)
  are not held. Files younger than a few seconds are not deferred: the interval already bounds
  the commits, and a deferral would need its own rules for files that never settle. Tests:
  `a_file_rewritten_all_the_time_makes_few_commits` (60 changes in 30 s: at most 9 commits, the
  first at once; 60 before, 20 with the device budget alone),
  `the_folders_of_a_device_share_one_commit_budget` (four folders, one minute: at most 20; 56
  with the folders' pacing alone).
- **LOW 2:** `codec::remember_uploaded` caches plaintexts best effort; the first failure (an
  index volume near its reserve) ends the caching for the call, the object IDs stay mandatory.
  Before, every round uploaded, failed there and started over. Test:
  `index::tests::a_full_index_volume_does_not_stop_remembering_an_upload`.
- **LOW 3:** files that wait for their hash (`deferred`, `recheck`) are hashed first, so a
  folder that keeps changing in front of them in path order cannot starve them, and the round
  leaves remote items at a waiting path alone with `more` only when its scan hashed something.
  Test: `rounds::files_waiting_for_their_hash_are_not_starved_by_constant_changes`.
- **INFO:** `SqliteStore::batch` was used only by its own test and an outer rollback after
  `save_folder` would have left `FolderSync`'s saved metadata and deltas out of step with the
  index; it is removed, and `save_folder`, `delete_folder` and `retain_cache` use plain
  transactions again (the savepoints were only for nesting in a batch).

## Amendment 2026-11-28: upload throughput of the server

A first sync of many small files was bound by the server, not by the network: every file is
at least two objects (manifest and chunk), and an analysis of the upload path found one hard
limit and several costs that ran under the database's global write lock. The changes below
raise the throughput without weakening any guarantee of the threat model: the server is not
trusted by the devices (end-to-end encryption, signed commits and logs), but protects itself
against abuse by an account or device (quota, budgets, disk reserve, rate limits) and keeps its
own integrity (a committed row always has its file, nothing confirmed is lost on power
failure). Code in `server/`; tests in `server/tests/upload_throughput.rs`,
`server/tests/deploy_files.rs` and unit tests in the named modules.

- **Upload rate configurable, exact `Retry-After`.** `Scope::UploadAccount` allowed 1200
  uploads per minute and account, so at most 10 small files a second. The operator now sets it
  with `HANGAR_DRIVE_UPLOADS_PER_MINUTE` (default 1200 unchanged, accepted 60 to 12000; the
  upper bound is about what one disk sustains at three flushes per stored object, more would
  only let one account queue work in front of the others). The per token and per device call
  limits (`CallToken`, `CallDevice`) become `max(3000, uploads + 1800)`, so one device can use
  the configured rate and still make its other calls; with the default this is the 3000 they
  always had. The limits for unknown tokens (`CallIp`, `CallNet`) and every sign-in limit are
  unchanged. A refused call now carries the seconds until the refusing fixed window ends
  (`ratelimit::Denied`, `RateLimiter::check` and `blocked`; a key refused by a full table waits
  for the oldest window of that table) in `Retry-After`, instead of a flat 60, also for failed
  proofs and device log appends (the day budget of adds included). Refusals that clear within
  moments ask for a short wait: a busy upload slot 1 s, a folder whose directory is still being
  removed and an upload that raced a folder removal 2 s (`error::RETRY_SOON_S`). Refusals
  without a window that ends (a busy heavy slot, a session route called without a session) keep
  60. Security: the counters, keys and order of the checks are the same; only the number in the
  header is now true, which tells an attacker nothing he could not measure. High values of the
  upload rate only make sense with few trusted accounts, since every upload goes through the one
  database write path and one account at a high rate slows the others (`docs/self-hosting.md`).
- **The file goes in place outside the write lock** (`service::objects::store`). Before, the
  upload took `BEGIN IMMEDIATE`, checked, inserted the row, renamed the staged file into place
  and flushed the directory, and only then committed: every upload of the server waited behind
  one directory flush, and on Linux the flush of a directory is a full journal commit. Now,
  under the object's stripe lock: (1) read-only checks (first the account's count of folder
  removals, then folder retired, folder being removed by a tombstone, the object already has a
  row, the quota has room), where the held check is mandatory, since otherwise an upload could
  rename a file over the file of an object that has a row; (2) the disk reserve, then the
  rename and the directory flush, outside any database transaction; (3) one write transaction
  that repeats every check (removals, retired, held, quota, budget, disk reserve) and inserts
  the row. Any refusal or error in (3), and a failed install, removes the file again before the
  stripe lock is released. Steps (1) to (3) run in a task of their own (`store_locked` under
  `tokio::spawn`) that owns the stripe guard: a request whose connection drops cannot release
  the stripe while a file is being put in place or removed (follow-up review LOW 3). The task
  also owns the account's upload slot (`app::OwnedUploadSlot`), so a dropped request cannot let
  more than `HANGAR_DRIVE_UPLOADS_PER_ACCOUNT` uploads of one account into this step.
  - *Invariant "a committed row has its file":* the file is durable before the row commits, as
    before. The garbage collection (`remove_object_files`) and the orphan sweep
    (`sweep_orphan_files`) remove a file only under the same stripe lock and only when no row
    exists, so they wait for an upload in flight and then see its row. Object rows are inserted
    only by this function, under the stripe, so no row can appear between (1) and (3); should
    one appear anyway, the file is left to it (`Recorded::Held`).
  - *A folder deleted whole between (1) and (3)* (follow-up review MEDIUM 1): folder
    directories are removed without stripe locks (garbage collection of a retired or
    never-committed folder, `purge retained`, the operator's `purge folder`), which could take
    the new file with them. The first version compared only the folder row (1) saw; a folder
    that did not exist in (1), was made by another upload and was then purged was missed, and
    (3) made it again and committed a row whose file was gone (reproduced by the review). Now:
    every transaction that deletes folders of an account raises `accounts.folder_removals`
    (migration 0006, `usage::count_folder_removal`) and leaves a tombstone that goes only after
    the directory is removed (`purge folder` now writes one too, in the same commit; a tombstone
    of a failed removal is cleared by the garbage collection's next try). (1) reads the count
    before it looks at the folder; (3) reads it again. A removal committed after that first read
    changes the count and (3) refuses (`removal_raced`); a removal committed before it either
    still has its tombstone, which (1) and the folder creation in (3) refuse, or removed its
    directory before this file went in place. `purge account` deletes the account row, which
    (3) sees as a missing count. A per-folder lock in memory was considered (the review's first
    suggestion) but not chosen: the database counter needs no lock across the garbage
    collection's transaction and its later file removal, and it also holds should a removal
    ever run in another process.
  - *How (3) refuses after a changed count* (follow-up LOW 2): the folder (1) saw is still the
    same row (key and creation time; SQLite may hand a deleted folder's key to a new row, both
    are equal only if the clock went back by more than the folder's age): the upload goes on, a
    removal of another folder costs nothing. Tombstone present, another row with the ID, (1) saw
    no folder, or the account gone: `rate_limited` with `Retry-After: 2`, the device tries
    again. The folder (1) saw is gone without a tombstone: if it had a head (only an operator
    purge removes such a folder), `folder_retired`, so the device stops instead of making the
    operator's deleted folder again; if it never had a head, `rate_limited` with 2 s, because
    the garbage collection also deletes a never-committed folder without objects a day after
    it was made (a device that uploaded without committing and slept), and the device's retry
    makes the folder again (acceptance review). `folder_identity` reads `head_pk IS NOT NULL`
    for this; the equality check stays on key and creation time.
  - *Crash between (2) and the commit:* a file without a row, removed by the orphan sweep once
    it is an hour old, as before for a crash between file and row. A file is never removed when
    the commit's outcome is unknown. A dropped connection no longer interrupts the steps.
  - *Cost of a refusal:* a refusal in (3) now costs a rename, a directory flush and a delete;
    the read-only checks in (1) refuse the common cases (held, retired, over quota) before
    that, and uploads stay rate limited. The budget is charged only in (3), as before.
  - Tests: `an_upload_refused_after_its_file_went_in_place_leaves_no_file` (budget),
    `a_disk_that_fills_while_the_file_goes_in_place_refuses_and_removes_it`,
    `a_second_upload_of_an_object_never_replaces_its_file` (a second upload with other bytes
    waits at the stripe and never installs), `concurrent_uploads_of_one_object_store_it_once`,
    `the_orphan_sweep_waits_for_an_upload_in_flight`,
    `a_folder_deleted_while_the_file_goes_in_place_refuses_the_upload` (a committed folder:
    `folder_retired`, the folder not made again),
    `a_never_committed_folder_collected_during_the_upload_asks_to_retry`, `a_folder_made_after_the_check_and_purged_refuses_the_upload`,
    `a_folder_made_after_the_check_and_collected_refuses_the_upload` (`purge retained`),
    `a_folder_still_being_removed_refuses_for_a_moment`,
    `a_removal_of_another_folder_does_not_stop_an_upload`,
    `a_busy_upload_slot_asks_to_retry_in_a_second`,
    `an_upload_finishes_after_its_connection_dropped`. Removing the held check in (1), the
    removal count check in (3), the task around the steps or the committed distinction makes
    the respective tests fail (checked by mutation).
  - **Not done: `synchronous=NORMAL` for the upload transaction.** In WAL mode it would keep
    the database consistent (frames are written in order, so a later durable `FULL` commit
    makes every earlier one durable), but a confirmed upload could be lost on power failure,
    and the device would only learn of it at its next commit (`missing_objects`). The pragma
    is per connection, so it would have to be switched on a pooled connection and back. With
    the rename and the directory flush out of the write lock, the WAL flush of the commit is
    the one flush left under it; its saving does not outweigh a weaker promise.
- **`objects/missing` in one statement.** It ran one `SELECT` per ID (up to 4096 per call).
  Now the IDs travel as one JSON array of hex strings into `json_each`, as in the commit call,
  and the statement returns the positions of those without a row (`NOT EXISTS` on the unique
  index `(folder_pk, object_id)`), sorted, so the answer keeps the request's order. The text is
  static, nothing of the request becomes SQL. Test:
  `missing_answers_a_full_list_in_request_order` (4096 IDs, held ones spread over the list).
- **SQLite pragmas** (`db.rs`): `cache_size` 16 MiB per connection (`-16384`, SQLite's default
  is 2 MiB), so the object and reference indexes of a large account stay in memory; at most 8
  connections make 128 MiB, which `mem_limit: 1g` holds beside the four heavy slots' bodies
  (comment in `docker-compose.yml`). `journal_size_limit` 64 MiB, so one large commit no longer
  leaves a WAL of its largest size on disk for good. `synchronous=FULL` and `secure_delete`
  stay. Test: `every_connection_has_the_cache_and_wal_limits`.
- **First orphan sweep an hour after the start** (`retention::sweep_due`,
  `FIRST_SWEEP_DELAY_MS`): it walked every object directory right at the start, competing for
  the disk with the first uploads of a new server; now it runs an hour after the start and then
  daily, by the server's clock (a clock that steps back delays it). Files without a row stay at
  most an hour longer, which costs only disk space. Tests:
  `the_first_sweep_waits_an_hour_and_then_runs_daily`,
  `the_first_file_sweep_runs_an_hour_after_the_start` (with the manual clock).
- **New object directories flushed into their parents** (`store::FsStore::install`). The rename
  was flushed in its directory, but a directory created for it (account, folder, the two fan-out
  levels) was not flushed into its parent, so after a power failure the directory entry, and
  with it a confirmed object, could be missing. Now every directory the install creates is
  flushed into its parent once, when it is made, under a store-wide lock that also makes an
  install which finds its directory present wait until its creator has flushed it. Existing
  directories cost nothing extra; a new fan-out directory costs one flush, at most 65,792 per
  folder over its life. Windows skips directory flushes (NTFS journals the metadata). Test:
  `new_directories_are_flushed_into_their_parents_once` (counts the flushes, so it runs on
  every platform).
- **Smaller points.** The staging file is written through a 256 KiB buffer instead of one write
  per body frame (`STAGING_BUFFER` in `http/handlers.rs`); limits and timeouts are unchanged,
  and the flush and `sync_all` still happen before any lock. 256 KiB rather than 1 MiB because
  every upload in flight holds one (8 per account by default) inside the container's memory
  limit. `docker-compose.yml` sets the new variable and rotates the logs (`json-file`, 10 MB,
  5 files). `docs/self-hosting.md` gains a section for Nginx Proxy Manager (the server's network
  with one fixed address, the advanced configuration with `proxy_request_buffering off`,
  `client_max_body_size 100m`, timeouts and the event stream location, finding the address to
  trust from the `operator warning`, diagnosis with the `ms` of the upload route, the data
  folder on an SSD).

**Expected effect** (not measured on a Linux host yet; the development machine is Windows,
where directory flushes are skipped and the main gain does not show): uploads of different
objects no longer queue behind each other's directory flush, so the write lock is held for the
checks, the insert and the WAL flush only, and with SSDs the server reaches the configured rate
instead of about one directory flush per upload. The `missing` call costs one statement instead
of up to 4096. A measurement on Linux (uploads per second with 1, 4 and 8 parallel uploads,
before and after) is open.

### Parallel uploads on the device

The device sent one object at a time (`FolderSync::run_job`): every object waited for the round
trip and the server's flushes of the one before, so a first sync of many small files left the
line idle although the server takes `HANGAR_DRIVE_UPLOADS_PER_ACCOUNT` (default 8) uploads of an
account at once. Code in `crates/hangar-drive-sync/src/upload.rs` and `folder.rs`; tests in
`crates/hangar-drive-sync/tests/parallel_uploads.rs`, the HTTP side in `tests/http.rs`.

- **Design.** `ServerApi::uploader` hands out an `ObjectUploader` (`Send + Sync`) for worker
  threads beside the `&mut ServerApi` of the engine thread. The upload loop is split into
  dispatch and booking (`FolderSync::dispatch`, `fill`, `collect`, `finish`): the engine thread
  pops objects in the queue's read order (path, chunk index, so the disk is still read mostly
  from front to back), draws each chunk's nonce from the round's entropy source and hands the
  object to a `Lane`; the workers (scoped threads) read the chunk, seal it and send it. Results
  are booked on the engine thread exactly as before (`sent`, `sent_round`, `known_present`, bytes
  left, stage counters), and the loop returns only once nothing is in flight, so the next
  round's check of what was sent, the final missing query before the commit and the
  intermediate commits work as before. *Superseded the same day* (amendment "transfers that
  never hold the engine thread"): the sending workers are no longer scoped to the round, and
  the loop returns at its deadline or for a waiting command with objects still in flight; they
  stay in the job's lane and are booked by the next round. A commit (final or intermediate)
  still happens only once nothing of its upload is in flight. Without an uploader (test doubles, `upload_workers` 1,
  a queue of one object) the same loop runs inline through `ServerApi::put_object`.
- **Cap.** `FolderSettings::upload_workers`, default `UPLOAD_WORKERS` = 4, clamped to
  `MAX_UPLOAD_WORKERS` = 8 (the server's default per account): 4 keep the line busy across
  the round trip and leave slots for another device of the account. Folders run one after the
  other in a pass, so parallelism lives at one level; in addition `HttpServer` holds
  `UploadSlots` (a semaphore, `ServerConfig::upload_slots`, default 4) shared by every uploader
  it hands out, so uploads of several folders can never exceed the cap together.
- **Stops.** The deadline of the round's upload phase, a stage that is due and the first
  failure stop dispatching; objects in flight finish and are booked, then the loop reports
  `Yielded`, `StageDue` or the error as before. A chunk that no longer seals marks its content
  for a new hash (`mark_rehash`) as before. Engine commands wait at most for the objects in
  flight (bounded by the request timeout), not for the rest of the queue. *Superseded the same
  day:* commands no longer wait for objects in flight at all (amendment "transfers that never
  hold the engine thread").
- **Busy slots and sessions.** The HTTP client retries `429` with `Retry-After` inside the
  request (at most `RetryPolicy::max`, 8 s; the server says 1 s for a busy slot), on the worker
  thread only. Still refused, the object is queued again and the upload goes on with one object
  less at once; only one object at a time that is still refused ends the round as before
  (reported as offline, no 60 s stall of the pass). Workers never sign in: a `401` comes back
  as `unauthorized` and the engine thread sends that object again through `put_object`, which
  signs in and renews the token the uploaders share (`SharedToken`).
- **Copies and traffic.** Request bodies are `bytes::Bytes` (already in the lock file through
  reqwest): a sealed chunk moves into the request without a copy and a retry sends the same
  buffer. The uploaders count on the client's shared `TrafficCounter` (atomics), so the traffic
  line sees parallel uploads as before.
- **Randomness.** Nonces are drawn in dispatch order on the engine thread
  (`object::NONCE_LEN`, now public), so the entropy source is never shared between threads
  and seeded tests stay reproducible. The in-memory server offers an uploader only after
  `ServerState::enable_parallel_uploads`; the seeded simulation and the tests that watch the
  order of uploads keep one thread.
- **Measured** (`parallel_uploads_take_less_wall_time`, debug build, Windows, in-memory
  server with 5 ms per upload, 126 objects, whole round including scan and hashing): one at a
  time 3.4 s, four workers 1.4 s. Not measured against a real server over a network yet.

## Amendment 2026-11-28: transfers that never hold the engine thread

**Goal (owner).** The app works smoothly under any load: no hang, no stutter, no frozen window.
The work budget of the amendment "the engine stays responsive during long work" bounded a pass
to about a second, but within that second the engine thread still waited for the server: for
every object in flight before a round could end, for `Retry-After` and backoff waits, for a
renewed sign-in, for one download at a time, and for a whole large file to be hashed or
written. A command sent during such a wait sat behind it. Code in
`crates/hangar-drive-sync/src/` (`interrupt.rs`, `download.rs`, `progress.rs`, `upload.rs`,
`folder.rs`, `chunker.rs`, `http.rs`, `localfs.rs`, `engine.rs`); tests in
`tests/engine_budget.rs`, `tests/large_transfers.rs`, `tests/http.rs` and unit tests in the
named modules. Measurements in [[transfer-responsiveness-measurement]].

### Lanes detached from the round, commands interrupt

- **Waiting commands.** `interrupt::Interrupt` counts the commands sent to the engine thread
  and not started yet (`EngineHandle::call` raises it until the command runs; dropping the last
  handle raises it for the stop). A round with a budget treats a waiting command like a spent
  budget (`FolderSync::spent`, `FsDisk::spent`): it stops at its next clean point (between hash
  batches and chunks of a large file, between downloaded files and chunks, between uploaded
  objects), and the pass breaks off before the next folder's round. A round without a budget (a
  person's action, tests that expect whole rounds) never looks at it.
- **Upload lanes outlive the round.** The sending workers of `upload::Lane` are plain threads
  that own what they send; only the sealing threads (`Sealers`, which borrow the disk and the
  keys) are scoped to the round. `FolderSync::dispatch` waits for answers in slices of 50 ms
  (`UPLOAD_WAIT_SLICE`) and returns at its deadline or for a waiting command with objects still
  in flight; they stay in the job's lane (`UploadJob::flight`) and the next round books them
  first. Nothing is committed while objects of the upload are in flight: `finish` reports
  `Done` or `StageDue` only once the lane is empty (`Next::Empty`); a deadline while answers are
  out turns either into `Yielded`. A dropped lane (job evicted, folder gone, sign-out) sets a
  flag, so its workers send nothing they still find queued, and its answers are never booked.
- **No idle threads.** A folder that does not run a round (paused, stopped, nothing to do) and
  a paused engine close their lanes (`FolderSync::release_transfers`): the workers end once
  their request is answered, the answers stay for the next round. Uploads of other plans of the
  same folder are closed while another one runs (review fix), so at most one lane per folder
  keeps threads waiting. A paused folder starts no new upload; what was in flight finishes.
- **Feed reads during long work.** A pass that only carries on the last one's work
  (`EngineCore::note_continuation`: no command, no change on disk) reads the account's feed
  only every `CONTINUATION_REFRESH_MS` (5 s), not once per one-second slice; a command, a wake
  or a pull asked for after an error reads it at once.
- **Calls that yield.** `HttpServer` gets the engine's interrupt (`ServerApi::set_interrupt`):
  waits for `Retry-After` and backoff run in slices of 50 ms, and a sign-in after an expired
  session is not started while a command waits. Such a call ends with `NetError::Interrupted`
  (transient); the pass then asks for the next pass without the full pull of a lost connection.
  Worker threads never see the interrupt: they are not on the engine thread.

### Parallel downloads in parts, checked before they land

- **Lanes.** `download::FetchLane`: up to `DOWNLOAD_WORKERS` (4, at most 8) threads per folder
  fetch sealed chunks through `ServerApi::fetcher` (`HttpFetcher`: the client's pool, token and
  traffic counter, 4 fetch slots per account connection), ahead of the executor in the order it
  writes the files (item ID), while the round's thread opens each chunk and writes the files one
  at a time as before. The plan for the lane names at most four windows of chunks. A worker
  never signs in; a chunk fetched with an expired token is fetched again on the round's thread.
  A `rate_limited` answer narrows the lane by one. A failure belongs to the run that asked: a
  new plan asks again (review fix).
- **Memory.** One lane holds at most `FETCH_WINDOW_BYTES` ahead (8 chunks, 32 MiB), counted by
  the expected size of every object in flight or fetched and not taken; all lanes of one engine
  share one `FetchBudget` (`FETCH_ACCOUNT_BYTES`, 64 MiB). The chunk the executor needs now is
  fetched beyond both, so a lane never waits for room that only it could free. A new plan drops
  what it no longer names. A cut run keeps its lane for the next round; a finished one drops it.
- **Large files in parts.** A file of more than one chunk (4 MiB) is written chunk by chunk into
  a part file `dl-<content key in hex>.dl` in the root's reserved `tmp` directory
  (`FileSystem::partial_write`), and a round stops between two chunks at its budget or for a
  waiting command; the next round goes on from there. An append is refused unless the part file
  is the one created then (file ID, one link, length equal to the offset). At most two part
  files per folder (`MAX_PARTIAL_DOWNLOADS`); the free space check counts only what is left.
- **Check before it lands (security review M1).** `partial_finish` opens the part file, checks
  file ID and link count, reads the whole content back through that handle and compares the
  SHA-256 of every chunk with what was written, then syncs that same handle, sets time and
  execute flag and puts it in place by one rename (the same end as `write_atomic`). A changed
  part file never lands; the download starts over. Only a waiting command stops the check, not
  the budget (a large file would always outlast it); it runs again in full next time.
- **Plaintext does not stay behind (security review N1).** Part files of contents the plan no
  longer brings in go at the next apply; a stopped or removed folder, a new root and a sign-out
  remove all of a folder's part files; opening a root empties its `tmp` directory.
- **Fixed in the review:** the link count on Windows was not checked (`single_link` returned
  true); it now reads `nNumberOfLinks` of the handle as Unix reads `st_nlink`, with a test that
  fails on the old behavior (`localfs::tests::a_part_file_with_another_name_is_refused`).

### Hashing large files in steps (security review M3)

A pausable hash (a file the scan may leave for later) stops between two chunks once the stop
condition holds and comes back as `ChunkError::Paused` with the chunk IDs so far
(`chunker::PartialHash`); the next scan goes on from there only while the file is provably the
same: same size, modification time and file ID, the same change stamp
(`FileSystem::change_stamp`: `ctime` on Unix, NTFS `ChangeTime` on Windows, both moved by a
write that keeps size and modification time), the same generation, and within `RESUME_WITHIN`
(10 minutes). A file without a file ID or a change stamp is hashed from the start; a folder that
stops running drops its partial hashes. The change stamp is read only for files of more than one
chunk, so a scan of many small files pays no extra open per file (review fix).

### Live progress

`progress::Live` turns the bytes a round moves (an object the server confirmed, a chunk written
to the disk) into snapshots between passes, at most one per `LIVE_EVERY` (200 ms, five per
second), whose `sync.bytesLeft` counts down from the snapshot the window shows. The app forwards
them like any snapshot (`src-tauri/src/events.rs`, `events::forward`, cache `shell.snapshot`).
Review fix: the base is renewed with every snapshot sent (after commands, at start, at the end
of a pass), so progress reported by a command outside a pass never sends an older snapshot whose
warnings would come back for a moment and notify again.

### HTTP client

- Connect timeout 10 s (`http::CONNECT_TIMEOUT`, was 15 s; the operating system's own limit on
  Windows is about 21 s, as stated in the code).
- A request that timed out is not sent again: every retry would hold the calling thread for
  another full limit; the next pass tries again. Other transient failures keep their bounded
  retries.
- Idle connections leave the pool after 5 s (`http::POOL_IDLE_TIMEOUT`; reqwest keeps one 90 s
  by default), below the server's idle limit (10 s) and the proxy's, so no request goes out on a
  connection the other side closed meanwhile.
- Upload bodies are streamed from the shared buffer (`SentBody`) and count their bytes for the
  traffic line as they go out.
- HTTP/2 is not active: reqwest 0.13 is built with `blocking`, `json` and `rustls-no-provider`
  only, and `h2` is not in the lock file, so the client speaks HTTP/1.1 with a keep-alive pool;
  parallelism comes from the lanes' threads and their connections.
- The app does not wait for detached workers on exit: it never joins the engine's threads, and
  they end with the process.

### Server: writer queue, bounded threads and proxy connections, image

Committed in `9e7a405` and `54e92f4`; code in `server/src/db.rs`, `config.rs`, `lib.rs`,
`main.rs` and `server/Dockerfile`, guide in `docs/self-hosting.md`.

- **Writers take turns.** SQLite lets a waiting writer sleep and retry (1, 2, 5, 10 up to
  100 ms between tries), so with several uploads at once a writer often slept on after the lock
  was free; the code records single uploads of over a second at the tail on a fast disk. Writers
  of one database now queue in arrival order inside the process before `BEGIN IMMEDIATE`
  (`db::begin_write`), taking the turn before a pool connection, with a fallback to SQLite's own
  lock after 10 s (`BUSY_TIMEOUT`), so nested write transactions cannot wait for themselves.
- **Commits hold connections.** A commit waits for its turn with its connection, so heavy
  requests are capped at half the pool (`MAX_HEAVY_REQUESTS` = 4 of 8 connections).
- **Threads.** Tokio's blocking pool is capped at 64 threads (`MAX_BLOCKING_THREADS`), below the
  Compose process limit (`pids_limit: 256`).
- **Proxy connection limit.** A trusted proxy gets half of the 4,096 connection slots
  (`TRUSTED_PROXY_CONNECTIONS` = 2,048), not all of them: behind a published port every process
  of the host arrives from the trusted gateway address.
- **Image.** Cross-compiled with `tonistiigi/xx` 1.9.0 from `rust:1.100.0-alpine` instead of
  emulated (the Dockerfile states minutes instead of about an hour for arm64; not measured
  here), dependencies in their own layer, full LTO with one codegen unit (7 % smaller than thin
  LTO, as stated there), remapped paths, OCI labels, distroless `static-debian13:nonroot` base.
- **Not measured yet:** the load test `server/tests/load.rs` (ignored, runs against a running
  image) has no recorded result in this wiki; uploads per second against a real server over a
  network remain open, as in the amendment "upload throughput of the server".

### Evidence

- Windows 11, debug build: `cargo test --workspace` green; the three integration test files
  above three times in a row without a failure. Linux: `cargo clippy -p hangar-drive-sync
  --all-targets -- -D warnings` and `cargo test -p hangar-drive-sync` green in `rust:1.100.0`
  (Debian), with `tests/.tmp` on a Linux file system ([[transfer-responsiveness-measurement]]).
- Tests that pin the behavior: `a_command_is_taken_at_once_while_uploads_hang_on_a_slow_server`,
  `a_pass_yields_to_a_waiting_command_before_a_round`,
  `passes_that_carry_on_an_upload_read_the_feed_only_now_and_then`,
  `progress_arrives_several_times_per_second_within_a_round` (`tests/engine_budget.rs`);
  `many_small_files_download_in_parallel`, `a_large_download_goes_on_where_it_stopped`,
  `a_stopped_download_run_ends_at_once` (`tests/large_transfers.rs`); the timeout,
  `Retry-After` and pool tests in `tests/http.rs`; `download::tests`, `chunker::tests`,
  `interrupt::tests` and the part file tests in `localfs::tests`.
- The timing bounds of the tests are about ten times what a desktop measured, so a slow CI
  runner passes while the old behavior (a command behind a one-second upload) still fails.
