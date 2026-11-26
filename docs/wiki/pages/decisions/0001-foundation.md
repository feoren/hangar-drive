---
title: "ADR 0001: Foundation: scope, sync model, server and encryption"
type: decision
tags: [scope, sync, server, backup, e2e, crypto, architecture, merge, restore, quota]
sources: ["[[sync-prior-art-research]]", "[[threat-model-and-crypto-design]]"]
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
    - An account change feed returns every account level change after an account cursor,
      using a monotonic sequence per account ("Change feed" below).
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
  - Each commit's height is one more than the highest height of its parents.
  - Along the first-parent chain, nothing goes back: a new head names a key generation and an
    account log head at least those its first parent names (conclusion). Without the log rule, a
    removed device whose key leaked could sign commits that name a log head from before its
    removal; without the generation rule, a device could keep writing under a generation the
    removed device holds.
  - As before: signature, signer valid at the named log head, per device counter above the
    server's mark for that device, every object in a reference delta held.
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
  - `folders`: an old version only hides a new folder or shows a retired one, whose commits the
    server refuses. That is a loss of availability, like a freeze.
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
         goes to its sequence.
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
        and the signature cover it. Bit 0 marks the commit of step 4 as a re-anchor. Version 1
        knows no other bit; server and devices refuse unknown bits, and bit 0 on a first commit,
        a side commit or a merge commit. Every other commit writes 0.
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
- **Recovery:** a 128 bit recovery code with a printed recovery sheet. There is no password
  recovery.
- **Removing a device:** triggers an immediate epoch rotation and a new folder key generation.
  Re-encrypting old content is an option and off by default.
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
    that uploads it; the last head of a retired folder is superseded at retirement. The newest
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
    means the disk is too small for the configured quotas.
- **Client guards:**
  - A root marker file: when it is missing, the folder pauses instead of deleting.
  - A prompt above 100 deletions in one run (Nextcloud's default; OneDrive uses 200).
  - These guards stop accidental deletions before they are propagated. Mass rewrites, such as
    ransomware encrypting files in place, pass them; against those the server's retention and
    anomaly pinning apply.
  - Deletes are propagated after a short delay.

### 6. Transport and access

- **TLS 1.3:** at the server or at a reverse proxy. The client refuses plain HTTP except for
  `localhost`, and self-signed setups use an SPKI pin from the pairing offer. There is no switch
  to accept invalid certificates.
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
       URL and the pin from it and does not pair.
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
- **Device sign-in:** an Ed25519 challenge proof bound to the server ID, the account and the
  protocol version. Sessions use short-lived bearer tokens that the server stores only as hashes.
- **Sessions:** a token lives about one hour, is renewed by a new proof and is revoked at once
  when the device log removes the device. Tokens never appear in URLs or logs.
- **Rate limits:** per IP and per account on the challenge, proof, invite, pairing and upload
  endpoints.
- **Client IPs:** taken from `X-Forwarded-For` only when the operator has marked the proxy as
  trusted.
- **Docker defaults:** the image runs as non-root, and Compose binds to `127.0.0.1` by default.

### 7. Cross-platform name policy

- Names in the protocol are compared in NFC. The exact bytes from disk are kept.
- Case-only and normalization-only collisions become conflicts. A case-only rename is a rename.
- Names that are invalid on Windows are marked "cannot sync on this device" and are never renamed
  silently. This covers reserved names even with an extension, `< > : " / \ | ? *`, control
  characters and a trailing dot or space.
- Long paths: the app manifest declares `longPathAware`, and file system calls use `\\?\`
  paths, because the manifest alone works only when the `LongPathsEnabled` registry value is set.
- 8.3 short names from watcher events are resolved to long names before matching.
- Locked files (sharing violations from Office, antivirus, the indexer) are retried with backoff
  and never block the whole run.
- Downloads go to a temporary file and are renamed atomically.
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
  - The Linux backend's `inotify` (ISC, equivalent to MIT) gets the same exception when Linux
    ships.
  - The workspace MSRV goes to 1.91 together with the first change that adds `notify` 9.
- **`sqlx` (server metadata):** MIT or Apache-2.0, same stack as the sister relay server.
- **Not adopted:** `fastcdc` (no CDC in version 1) and `blake3` (HMAC-SHA-256 keeps the review
  surface at the primitives the sister app already uses).
- **`unicode-normalization` (NFC names):** `(MIT OR Apache-2.0) AND Unicode-3.0`. The Unicode
  data license is permissive.

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
- **Disk sizing:** with quota Q, headroom H, account budget B per 24 hours, window W days and
  minimum count cap C, and pin cap `P = Q + H`, the objects one account can keep stored at a
  time T are bounded by `(Q + H) + B × (W + 1) + P + P + C`, that is
  `3 × (Q + H) + B × (W + 1) + C` (conclusion, from the rules of section 5). Each stored object
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
    none is older. Or the pin restore allowance revived it free, at most P in the last W days.
    That allowance term is the longer retention of pinned bytes: at most P of them, for at most
    W days beyond the end of their pin.
  - Class 3, held only by admitted pins: at most P at every time, because the pin cap is checked
    in every garbage collection step, not only when a pin is made.
  - Class 4, held only by the minimum count: at most C.
  - The bound holds after every garbage collection step; between two steps, objects that became
    deletable since the last one come on top.
  - With the defaults (B = Q, W = 30, C = Q) that is `35 × Q + 3 × H`, plus the commit bodies, a
    few hundred bytes per head. The self-hosting guide explains this. The earlier bound,
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
- [ ] Server: accounts, invites, device sign-in, object store, commit log with compare-and-swap,
      change feed, retention with the minimum count cap, the pin cap checked in every garbage
      collection step and the retention classes, quota checked at upload and at commit,
      directory node headroom, device and account upload budgets that also count revived bytes,
      the pin restore allowance, the server key number in the CLI.
- [ ] Self-hosting guide: check the reverse proxy defaults that affect 4 MiB chunk uploads and
      long-lived SSE connections (nginx `client_max_body_size`, `proxy_read_timeout`); explain
      disk sizing.
- [ ] Sync core with simulation tests (including the merge rules, the join of a non-empty local
      folder, long offline periods and the re-anchor),
      then the first end-to-end sync of one folder.
