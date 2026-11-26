---
title: "ADR 0001: Foundation: scope, sync model, server and encryption"
type: decision
tags: [scope, sync, server, backup, e2e, crypto, architecture, merge, restore, quota]
sources: ["[[sync-prior-art-research]]", "[[threat-model-and-crypto-design]]", "[[unix-inode-reuse-measurement]]"]
status: accepted
superseded_by:
created: 2026-11-26
updated: 2026-11-26
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
    section 4.1).
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
  nothing.
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
    `P_name = HKDF-SHA256(P, field("hangar-drive/v1/pairing-name"), 32)`, `sealed_name = nonce
    (24) || XChaCha20-Poly1305(P_name, nonce, name, aad = field(label) || field(account) ||
    field(new device))`, and the request tag covers `sealed_name` instead of the name. Only who
    holds P opens it; the server checks only its size. Vectors `pairing.sealed_name` and
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
    (base64url of the sheet bytes, version 2 since the second engine review: account ID, server
    ID, the genesis anchor, the optional SPKI pin and the server URL; see the amendment "App
    shell and the second engine review"); the link never carries the code, which is always
    typed. The server ID is learnt before the code is shown, through the
    session challenge, which the server answers for any account and which writes nothing.
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
    fewer files could never set off a pin. An operator count below 20 is taken as set.
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
    - `PUT /objects/{id}` is refused when the live bytes plus uncommitted uploads plus the new
      object would exceed the quota. A commit only references objects the server already holds,
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
    - **Per device:** stops only the device that exceeds it. Default: the account budget.
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
    and warns the operator. This is the only case in which honest devices are blocked, and it
    means the disk is too small for the configured quotas. Bytes that uploads in flight have
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
    that key learns of the removal. The engine then forgets the account as for a removal it read
    in the log (security review L1, `account::forget`) and shows "this device was removed"
    without a name; `ProofInvalid` never does that. A recovery device answered so means "this
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
    can fill the table with invented accounts or lock an account out with challenges. A full
    table evicts the entries whose window ended, oldest first. A public body must arrive
    within 10 seconds; connections per address are capped in the accept loop, except for
    trusted proxies, which limit per client themselves.
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
- Long paths: the app manifest declares `longPathAware`, and file system calls use `\\?\`
  paths, because the manifest alone works only when the `LongPathsEnabled` registry value is set.
- 8.3 short names from watcher events are resolved to long names before matching.
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
  the engine's own `set_meta` would read as a replace. Code: `crates/hangar-drive-sync/src/localfs.rs`
  (`unix_id`).
  - **Residual risk:** where the file system reports no birth time (ext4 with 128 byte inodes,
    ext3, 9p, NFSv3, many FUSE file systems, and musl builds, whose std does not call `statx`),
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
  removes the index folder.
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
  question in a native dialog that shows the number (security review L2, now three actions). An
  offer (`fixServerWithOffer`) gives only URL and pin, through
  `PairingOffer::server_address`; for an offer whose log head is newer than the verified log,
  the log is fetched through the offered address, verified from the anchor and the offer checked
  again, and the old address stays on any failure.
- **Files another device deleted** (UX 8.1): one activity entry per round and folder, with
  "Wiederherstellen", which restores every file of it that is still gone from the head before the
  round, in one commit; a file that came back meanwhile stays as it is.
