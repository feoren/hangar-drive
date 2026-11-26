# Hangar Drive: threat model and cryptographic design for version 1

- Date: 2026-11-26
- Kind: raw source for ADR 0001 (security review and design proposal, no code)
- Author role: application security review (`hangar-security`)
- Status: proposal; nothing here is decided until ADR 0001 accepts it
- Read for this report: the Hangar Drive repository as of commit `fdc2c8b` (skeleton: health endpoint only, no sync, no crypto), the sibling Hangar repository's `crates/hangar-team-crypto` and `crates/hangar-team-protocol` (module docs, formats, limits, dependency manifest and lock file) and its wiki page `concepts/team-crypto.md` (updated 2026-11-25).
- Verified in this session: the external sources in section 10 (fetched or searched on 2026-11-26) and crate versions on crates.io. Statements marked `[UNVERIFIED]` were not checked in this session.

## 0. Short answer

Build version 1 as "a team of one": reuse Hangar's device identity, signed device log, HPKE epochs and recovery code for the account, and add a new, small file layer on top: random folder keys in a key ring, encrypted content addressed objects with keyed IDs (no convergent encryption), an encrypted tree so the server never sees names or paths, and a signed, hash chained commit DAG per folder that clients check against a stored frontier, which stops rollback and makes forks detectable. Backups survive a compromised client only through a server side retention rule that no client API can shorten. The biggest risks are that the whole protocol is hand built and unreviewed (high), that one compromised device has full read and sign power over the account (high, inherent), and that a server can still freeze or withhold state without an out of band check (medium).

## 1. Threat model

### 1.1 Assets

| Asset | Why it matters |
| --- | --- |
| File contents | the primary secret |
| File and folder names, paths, tree shape | often as sensitive as content (names of people, clients, diagnoses) |
| Integrity and authenticity of files and versions | a server must not inject, alter, reorder, truncate, roll back or mix files |
| Version history and trash (the backup) | must survive deletion and garbage uploads by a compromised client |
| Device private keys, epoch secrets, folder keys | whoever holds them reads everything |
| Recovery code | equivalent to full account access |
| Session tokens, invite tokens | server access, quota, availability |
| Metadata: sizes, counts, times, device list, IP addresses | traffic and behaviour analysis |

### 1.2 The version 1 assumption, questioned

"One person, several own devices" is the right scope for version 1, with three corrections:

1. **Operator and user are not always the same person.** Self hosting often means one person runs the server for a family or a small office. The curious operator is therefore a real attacker in version 1, not only later.
2. **"Sharing later without a break" is only true if the formats already carry it.** Every object must name its folder and its folder key generation, folder keys must be independent of the account's epoch keys, and every write must be signed per device. Otherwise sharing a folder later means re-encrypting it.
3. **A compromised client is in scope for version 1.** Hangar's team crypto lists "a compromised device" as out of scope (`concepts/team-crypto.md`, threat model in short). For a backup product that cannot hold: confidentiality against a compromised device is impossible, but the integrity of the history against it is a core promise (section 4).

### 1.3 Per attacker

Severity rates the impact if the design fails against that attacker.

| Attacker | Must be protected | Can still do / stays visible | Severity if broken |
| --- | --- | --- | --- |
| **Curious server operator** (honest, but reads everything on disk and in logs) | contents, names, paths, tree, exact sizes, keys | account and device count, device public keys and log (plaintext by design), number of objects and their padded sizes, upload and commit times, which device uploaded, IP addresses, total volume, dedup hits inside one folder, the reference graph between commits and objects (needed for retention) | Critical |
| **Compromised or malicious server** (active) | all of the above plus integrity: no injected, altered, swapped, reordered or truncated files; no rollback to an old state; no substituted device keys; no foreign epoch secret; no invented account log for a new device | delete or withhold data (availability is not protected against the server); freeze a client on an old but consistent state until devices compare state out of band; fork devices (detected once their histories meet, section 3.4); drop or delay pushes; replay old ciphertext (refused by the frontier check) | Critical |
| **Network attacker** (on path, possibly with a misissued or user accepted certificate) | everything the server must not see, plus tokens and invite codes | with broken TLS, the same as an active server; without, traffic volume and timing | High (TLS is the only layer for tokens and metadata) |
| **Stolen or lost device, locked** | keys (OS keychain), local files (OS disk encryption) | nothing beyond what the device's disk encryption allows | High |
| **Stolen or lost device, unlocked or with a live app session** | after removal from another device: no new content, no further server access | everything already synced and every key on the device; inherent, bounded only by fast removal | High (inherent) |
| **Compromised client (ransomware, malware)** | the history on the server: old versions and the trash must survive mass deletion, mass rewrite and garbage uploads; other devices must notice | read everything the device can read; sign valid commits that delete or replace files; remove the other devices from the account log and rotate keys (lock out); exhaust the quota | Critical for the backup promise |
| **Malicious member (later, sharing)** | folders not shared with it; other members' identities (no writing in their name); content written after its removal | keeps everything it saw and every key it held; writes signed garbage into shared folders while a member (attributable, recoverable through retention) | High |
| **Removed device or former member** | new content after the rotation and the new folder key generation | old content and old keys; server access ends at once (tokens and proofs refused) | Medium |

### 1.4 Metadata, explicitly

| Item | Visible to the server in this design | How it is reduced |
| --- | --- | --- |
| File contents | no | AEAD |
| Names, paths, tree shape | no names or paths; object count and sizes give a rough shape | names live only inside encrypted, padded directory nodes |
| File size | number of full chunks (4 MiB granularity) plus a padded last chunk | Padmé padding of every object (section 3.1) |
| Number of files | approximately (number of manifest sized objects) | no packing of small files in version 1; later option |
| Times | upload, commit and session times; client clock times stay encrypted | none in version 1 (no cover traffic) |
| Which device wrote | yes (authenticated session, signed commit) | accepted |
| Account devices, their keys, epochs | yes (the device log is signed plaintext, as in Hangar) | accepted: the server needs it to authenticate devices |
| Equal content | only inside one folder and one key generation (same object ID) | keyed IDs instead of convergent encryption |
| Reference graph | which objects a commit adds or drops | needed for retention; accepted |
| Folder count | roughly (size of the sealed key ring record, number of commit logs) | accepted |

## 2. Key hierarchy

### 2.1 Layers

```text
Device identity (per device, OS keychain)
  Ed25519 sign key, X25519 KEM key                         [hangar identity]
        |
Account device log (signed, hash chained, plaintext)       [hangar memberlog, one member]
        |
Account epoch secret S_e (random 256 bit, per epoch)       [hangar epoch, HPKE wrapped to every
        |                                                    device incl. the recovery device]
Account seal key K_acct,e = HKDF(S_e, ...)                 [like hangar EpochKeys]
        |
Folder key ring per folder (sealed record under K_acct,e)  [like hangar notes KeyRing]
  FK_f,g: random 256 bit per folder f and generation g
        |
Per generation keys: K_obj (object AEAD), K_id (object IDs)
        |
Objects: chunks, file manifests, directory nodes           [new]
Commits: signed by the writing device                      [new]
```

Why folder keys are random and not derived from the epoch: an epoch rotation then re-seals one small key ring record per folder and re-encrypts no content; a folder can later move into a shared space by wrapping its ring for that space; and a removed sharee is locked out of new content by adding a generation. This is the same mechanism as Hangar's notes key ring (ADR 0006 there).

Why no per file key: with keyed object IDs, the object key is per folder and generation and the AEAD uses random 192 bit nonces. A per file key adds nothing against the server and would break deduplication. Key separation per object comes from the associated data, which binds folder, generation, type and ID.

### 2.2 A new device (pairing)

Primary path: a QR code (or a copied text block) shown on an existing device A:

```text
offer = server URL, server SPKI pin (optional), server id, account id, A's device id,
        account log head (index, hash), pairing secret P (32 random bytes), expiry
```

1. The new device B generates its identity and sends to the server's pairing endpoint: its public keys, its proof of possession, a device name, and `tag = HMAC-SHA-256(HKDF(P, "hangar-drive/v1/pairing-mac"), request)`. The server routes it by `pairing id = HKDF(P, "hangar-drive/v1/pairing-id")`. It learns neither P nor anything that lets it forge the tag.
2. A verifies the tag, asks the person "Add device <name>?" and shows B's safety number (Hangar's 30 digit format). On confirmation A appends an add device entry (endorsed by A itself, same member) and wraps the current epoch secret to B.
3. B fetches the log and accepts it only if it extends the head from the offer and contains its own entry. This closes Hangar's open question 10 for Drive: the trust anchor (the head) came out of band, so a server cannot show a new device an invented log.
4. The offer is single use, expires after 10 minutes, and the endpoint is rate limited.

Fallback without a camera: the person types the offer's 128 bit secret (26 base32 characters), or both devices show both safety numbers and the person confirms they match. A short code (6 to 8 characters) must **never** be used as P without a PAKE: the server sees the tag and can brute force a short code offline (high severity if done wrong). A PAKE (CPace, SPAKE2) for short codes is a later option; no mature, reviewed Rust crate was checked for this report `[UNVERIFIED]`.

### 2.3 Recovery when all devices are gone

Reuse Hangar's recovery code with the same structure: 128 random bits, Crockford base32 with a checksum. HKDF derives an offline recovery device that sits in the account log with `recovery: true` and receives every epoch wrap. Drive specific additions:

- Print a recovery sheet with the code plus, in the clear, the server URL, server id and account id (the code alone does not name the account). At setup the person types one group back.
- Flow:
  1. Enter the sheet on a new installation.
  2. Authenticate to the server as the recovery device and fetch its wrapped epoch secrets.
  3. Add the new installation as a device (the one entry a recovery device may write).
  4. From the new device, remove the lost devices and the used recovery device.
  5. Rotate, add a folder key generation, print a new code.
- No password based recovery: a chosen password would let the server attack the wrapped keys it stores offline. The code is machine drawn, so it needs no password hashing (Hangar's reasoning in `recovery.rs` applies).
- Consequences to state in the UI:
  - the code plus the server's data is full access;
  - without the code and without any device, the data is gone by design;
  - if the server is gone too, only a second backup target helps.

### 2.4 Removing a device

From any remaining device of the person:

1. Write a remove device entry to the account log (Hangar's `device.remove` semantics). The server applies it at once: it revokes that device's tokens and refuses its proofs.
2. Rotate the account epoch to the remaining devices and the recovery device. Drive needs no history link: the folder key rings are re-sealed under the new epoch and always contain all generations.
3. Add a new generation to every folder key ring. New objects use it; existing objects keep their generation (the removed device had those keys anyway).
4. Optional, off by default: "re-encrypt folder" rewrites all objects under the new generation. It only helps against a removed device that held the keys but had not downloaded the data.

In version 1 all devices belong to the owner and can rotate. Hangar's deferred and urgent rotation logic therefore collapses to "rotate immediately after every removal".

## 3. Content encryption

### 3.1 Chunks, AEAD and deduplication

**Recommendation: no convergent encryption. Deduplicate only inside one folder and one key generation, with an object ID that is a keyed hash of the plaintext.**

- **No convergent encryption.** With convergent encryption (key = hash of content), anyone who can guess a file can confirm it is stored, and can recover low entropy fields of a known template by trying candidates (confirmation and "learn the remaining information" attacks). In a self hosted product the saving across users is small and the leak is permanent. Severity of allowing it: high.
- **Keyed IDs:** `id = HMAC-SHA-256(K_id, field(type) || field(plaintext))`. The server sees equal IDs only for equal content in the same folder and generation, and cannot test a guessed file without `K_id`.
- **Fixed 4 MiB chunks in version 1, no content defined chunking (CDC).**
  - CDC chunk boundaries leak information about the content. Truong et al. (2025) show practical key recovery against the keyed CDC of Borg, restic, Tarsnap, Bupstash and Duplicacy, which breaks their protection against fingerprinting.
  - The same paper gives a provably secure keyed CDC. That is a later option, once Drive needs better dedup for files edited in the middle.
- **Padding:** every object is padded with Padmé before encryption (Nikitin et al., PETS 2019: leakage of O(log log M) bits, at most 12% overhead). With fixed chunks only a file's last chunk varies, so only it pays for the padding.
- **AEAD:** XChaCha20-Poly1305 with a random 192 bit nonce under `K_obj`. The associated data binds folder, generation, type and ID. Random nonces under one key are safe for far more objects than a folder will ever hold.
- **Key commitment:** Poly1305 based AEADs do not commit to their key (Len, Grubbs, Ristenpart, USENIX Security 2021). After decryption the opener recomputes the keyed ID from the plaintext and refuses a mismatch. That binds a ciphertext to exactly one plaintext under one key and closes partitioning style tricks. Severity if omitted: medium.
- **STREAM is not needed for chunks:**
  - A chunk is at most 4 MiB and is encrypted and verified as one AEAD message in memory.
  - The order, the count and the end of a file are authenticated by the manifest (section 3.3). One of the providers Hofmann and Truong studied (CCS 2024) lacked exactly this, so a malicious server could drop and reorder chunks.
  - Use an age style STREAM (C2SP age spec: 64 KiB segments, 11 byte big endian counter, last segment flag) only for objects that cannot be bounded, for example an export archive.

### 3.2 Names and paths

**Recommendation: the server sees no tree at all.** Names live inside encrypted directory nodes, as in a Git or restic tree, not as encrypted file names on the server.

- Cryptomator encrypts names with AES-SIV, using the parent directory ID as associated data, and flattens directories. Keeping names inside nodes instead hides name lengths and avoids deterministic name encryption entirely; equal names in different folders do not show.
- Directory node plaintext: entries sorted by comparison key, each with:
  - the name as the exact UTF-8 bytes from disk,
  - a normalized comparison key in NFC,
  - kind, child object ID, size, modification time, flags.
- The comparison key exists because macOS, Windows and Linux disagree on normalization and case. That is an integrity and conflict topic rather than a crypto one, but it must be in the format from the start.
- Nodes are objects like chunks: keyed ID, padded, sealed. A changed file rewrites its manifest and the nodes on its path to the root, as in any Merkle tree.

### 3.3 Manifests and versions

- **File manifest** (object type 2): format version, file size, flags, modification time, and the ordered list of chunk IDs (capped at 2^20 chunks, 4 TiB). The manifest's ID is a keyed hash over all of it, so chunk order, count and the end of the file are authenticated through the tree.
- **Directory node** (type 3): see section 3.2.
- **Commit** (signed, not encrypted): names the folder, the parents, the root directory node ID, the key generation, the writing device, the account log head the device verified, a per device counter and a height. It is signed with the device's Ed25519 key under a Drive only label. The root ID is a keyed hash, so the commit reveals nothing about content.
- **Integrity chain:** the commit's signature is verified first. Then every object reached from the root is checked by recomputing its keyed ID. One signature per commit, not per chunk.
- **Commit validity:** the signer must be a non recovery device the account log lists at the named head, with a key period covering it (Hangar's `key_periods` logic), and the generation must exist in the folder ring. Commits a removed device makes after its removal are refused.

### 3.4 Rollback and forks by the server

- **Commit DAG per folder,** hash chained through parent commit hashes, like Git. Concurrent edits on offline devices legitimately produce several heads; a device merges them with a merge commit (conflict copies for real conflicts).
- **Frontier check (rollback):**
  - Every device stores, per folder, its verified frontier: the set of head hashes it has accepted, with their heights.
  - For every stored head, the server's answer must contain a head that descends from it. Otherwise the device refuses and reports "the server shows an older state".
  - Old commits the server replays fail the same check.
- **Per device counter:** each device's commits carry a strictly increasing counter (Hangar's `SendCounter`/`ReplayGuard` pattern with the clock floor), so a server cannot present an older commit of a device as its newest.
- **Forks:** a server that hides device X's commits from device Y can keep the two views apart only as long as X and Y never see each other's later commits (fork consistency, SUNDR, OSDI 2004). In Drive every merge brings them together, so a fork is detected at the first merge. Each commit can also list the newest commit it saw from each other device (a small version vector), which makes a hidden commit visible as soon as one later commit crosses.
- **Freeze (withholding everything new):** cannot be detected cryptographically without a second channel. Severity: medium, accepted for version 1. Mitigations:
  - a "folder safety number" over the current frontier that two devices can compare,
  - a warning when a device has seen nothing from its siblings for a long time,
  - later, a LAN peer check.
- **Account log forks:** Hangar binds the rotate entry's log hash into the epoch keys, and that carries over. The two sides of a forked account log derive different seal keys and cannot read each other's key rings.

## 4. Backup despite end to end encryption

### 4.1 Versions and trash without seeing content

- Every commit is a version of the whole folder. Old versions and the trash are simply older commits and the objects they reach. The server stores opaque objects and signed commits and never needs a key.
- A client's "delete" is a new commit without the entry. A client's "empty trash" only asks for earlier collection, which the server ignores until the retention window has passed.
- For garbage collection, each commit upload carries in the clear the object IDs it adds and drops relative to its first parent (a reference delta). The server computes reachability from those deltas. This reveals the reference graph, not content.

### 4.2 Protection against a compromised client

| Measure | Effect | Severity if missing |
| --- | --- | --- |
| **Server side retention, set only by the operator** (server config, for example `HANGAR_DRIVE_RETENTION_DAYS`, default 30, plus a minimum number of retained commits per folder; a per file minimum is impossible because the server cannot see files). No client API deletes commits or objects. | mass deletion and mass rewrite stay recoverable for the window | Critical |
| **Collection rule:** an object may be deleted only if no retained commit declared it reachable and the newest commit that declared it is older than the window. Commits themselves are kept for the window after they stop being heads. | a lying client that declares nothing reachable cannot shorten the window, because older honest commits still declare the objects | Critical |
| **Anomaly pinning:** the server watches metadata only (share of a folder's objects replaced or dropped per hour, upload volume). Above a threshold it pins the last commit before the burst beyond the normal window (for example 90 days) and tells all devices. | ransomware that rewrites everything is caught by its own volume, without reading content | High |
| **Quota and rate limits per account and per device** | garbage uploads cannot fill the disk or push out other accounts | High |
| **Signed commits** | every version names the device that wrote it; the restore UI offers the last commit before the suspect device's first commit | Medium |
| **Device removal notifications** | a device that removes all others (lock out) is visible on every device and on the server; the recovery code restores access, retention keeps the data | High |
| **Immediate purge only through the operator** (server CLI) | data protection erasure stays possible without giving clients a delete button | Medium |

Limits:

- Retention protects against clients, not against the server. A malicious or broken server, or a lost disk, takes the backup with it.
- Document the 3-2-1 rule, and support a second target later (for example S3 compatible storage with object lock, `[UNVERIFIED]` for the exact API).
- Collection runs on server time, so the operator must trust the server clock.

## 5. Transport and authentication

- **TLS 1.3** at the server (rustls) or at a reverse proxy.
  - The client refuses plain HTTP except for `localhost` and uses the platform verifier.
  - For self signed certificates it accepts an SPKI pin delivered in the pairing offer. There is no "accept invalid certificates" switch.
  - TLS protects tokens and metadata; the content does not depend on it.
- **Account creation** needs a single use, expiring invite token that the operator creates with a server CLI (128 bit, stored hashed). Without it, anyone who finds the server can fill its disk.
- **Device sign in by proof of possession,** after the pattern of Hangar's `possession.rs`:
  - The server sends a fresh 32 byte challenge. The device signs `field("hangar-drive/v1/session-proof") || field(server id) || field(account) || field(device) || field(sign public key) || field(challenge) || field(protocol version)`.
  - The server checks the signature against the key the account log lists now. It runs the same log verifier as the clients, as Hangar's relay does.
  - `server id` is a random ID the server makes on first start and the client pins at pairing, so a proof is valid for one server only.
  - No TLS channel binding (RFC 9266), because a reverse proxy terminates TLS.
- **Session token:**
  - 256 random bits, stored on the server only as SHA-256, bound to the device.
  - Lifetime about one hour, renewed by a new proof; revoked at once when the log removes the device.
  - Never in URLs and never in logs, including the proxy's access log.
- **Rate limits** per IP and per account on the challenge, proof, invite, pairing and upload endpoints. Client IPs come from `X-Forwarded-For` only when the operator has configured the proxy as trusted. Otherwise an attacker sets the header and rotates it to dodge every limit.
- **Self hosting pitfalls** (for the sysadmin role to document and test):
  - nginx's default `client_max_body_size` (1 MiB) rejects 4 MiB chunks, and the default `proxy_read_timeout` (60 s) drops idle push connections, so the client must ping more often `[UNVERIFIED in this session; nginx defaults from memory]`.
  - WebSocket or SSE needs the proxy's upgrade headers and no response buffering.
  - Docker published ports can bypass host firewalls such as ufw `[UNVERIFIED]`. The Compose file already binds to `127.0.0.1`, which should stay the default.
  - TLS terminated at a proxy on another host means plaintext HTTP, tokens included, on the LAN. Recommend proxy and server on one host, or TLS on both legs.
  - Let's Encrypt needs public DNS; LAN only setups need the pinning path above.

## 6. Reuse

### 6.1 What in `hangar-team-crypto` fits

| Module | Fit for Drive | Notes |
| --- | --- | --- |
| `identity` (Ed25519 + X25519, keychain format, proof, endorsement, safety numbers) | direct | labels are hard coded `hangar-team/v1/...` (22 places across the two crates); Drive needs its own domain (section 6.3) |
| `memberlog` (signed log, rules, key periods, verifier for client and server) | direct, as the account device log with one member | roles and member entries stay unused in version 1 but are the path to sharing; the relay side `ticket_role` parameter has no Drive equivalent (the Drive server passes the owner role for the account's own devices) |
| `epoch`, `rotation` (HPKE base mode, commitment in the log, wrap to all) | direct | static KEM keys mean no forward secrecy; acceptable for stored data, which is long lived anyway |
| `record` (sealed and signed records, replay guard) | partly | good for small account records (folder key rings, device names, settings); `RecordKind` is a closed enum of Hangar kinds and the size limits are Hangar's; not for chunks |
| `recovery` | direct | add the recovery sheet; separate label or version byte for Drive |
| `possession` | as a pattern | the statement must name the Drive server and account |
| `notes::KeyRing` | close to the folder key ring | ring of (key id, 32 byte key), at most 255; generalize or copy |
| `relay`, `decision`, task and claim parts | no | Hangar specific |

Observation (low, maintainability): two public constants share the name `MAX_LOG_ENTRIES` with different meanings: `hangar-team-protocol/src/limits.rs:43` (256, entries per `memberlog.entries` page) and `hangar-team-crypto/src/memberlog.rs:131` (8192, the log cap). Worth renaming before a second product depends on both.

### 6.2 What is missing for files

- Object format with keyed IDs, Padmé padding and the key commitment check.
- File manifest and directory node formats, including name normalization keys.
- Folder commit DAG: commit format, signature, frontier and rollback check, version vector, merge.
- Folder key ring with generations as a first class type.
- Pairing protocol (section 2.2) and its anchor check.
- Session proof and token for the Drive server.
- Retention and collection semantics (server side and not crypto, but part of the security claim).
- A bounded STREAM, for exports only. `aead-stream` 0.6.0 (RustCrypto, MIT or Apache-2.0) exists and should belong to the same `aead` generation as `chacha20poly1305` 0.11 `[UNVERIFIED that they share aead 0.6]`.
- Local protection of the sync index, which holds names in plaintext on disk: rely on OS disk encryption in version 1 and say so.

### 6.3 Options

| Option | Advantage | Disadvantage | Fit |
| --- | --- | --- | --- |
| A. Use `hangar-team-crypto` directly and add Drive modules to it | one crate, one review | couples two products' release cycles; carries Hangar specific kinds, limits and labels; the crate is `publish = false` in its own workspace inside another repository, so Drive's public CI cannot use a local path | weak |
| **B. Extract a shared core and build `hangar-drive-crypto` in the Drive repository** | the shared parts (framing, identity, log, epoch, rotation, recovery, generic record, key ring) get a domain parameter for labels; file specific code lives where it is used; one external review of the core covers both products | one refactoring in Hangar; until then, a git dependency on the public Hangar repository pinned to a commit | **recommended** |
| C. age (`age` crate 0.12.1, MIT or Apache-2.0, labelled "[BETA]" on crates.io; format specified by C2SP) | well designed file format, STREAM payload, simple | one header per file with recipient stanzas, so adding a device means rewriting every file's header; no device log, no dedup, no versions, no rollback protection | only for exports |
| D. Cryptomator (`cryptolib`, Java, AGPLv3 or a commercial license; Cure53 audit of 1.1.5 in 2017) | mature, documented vault format (AES-GCM chunks of 32 KiB with chunk number and header nonce as associated data; AES-SIV names with the directory ID as associated data) | wrong language; AGPLv3 does not fit an MIT product; designed for one password and untrusted storage: no device keys, no signatures, no rollback protection, sizes and name lengths visible | ideas only |
| E. MLS (RFC 9420, for example OpenMLS) for later sharing | standard group key agreement with forward secrecy and post compromise security | far more complex; does not solve storage, dedup or rollback | evaluate when teams come (Hangar's question 10 of the hardening round asks the same) |

Option B needs domain separation (severity medium if skipped). If one device identity were ever used by both Hangar and Drive with the same labels, a signature made in one product could verify in the other. Use separate identities per product and the label prefix `hangar-drive/v1/` for every Drive signature, MAC, KDF and AEAD context.

## 7. Open risks and external review

### 7.1 Risks

| # | Risk | Severity | Handling |
| --- | --- | --- | --- |
| R1 | Hand built protocol from standard parts; neither the Hangar crate nor the Drive layer is externally reviewed | High | release blocker: external review (7.2) |
| R2 | One compromised device reads everything and can lock out the others (all devices are owner equal) | High, inherent | retention, anomaly pinning, removal notifications, recovery code; later optional "removal needs a second device" |
| R3 | Server freeze or withholding is not detectable without a second channel | Medium | frontier, version vectors, folder safety number, staleness warning |
| R4 | Metadata: sizes to chunk granularity, counts, times, reference graph, device list | Medium | padding; document honestly in the README and UI |
| R5 | Local plaintext files and the sync index on disk; unlocked stolen device | Medium | OS disk encryption, fast remote removal; not solvable in the protocol |
| R6 | The recovery code is full access; lost code plus lost devices means lost data | Medium | recovery sheet, typed back check, UI text |
| R7 | The backup is only as strong as the server; a malicious operator can delete everything | Medium | 3-2-1 guidance, second target later |
| R8 | The pairing fallback by comparing numbers relies on people actually comparing | Medium | QR path first; confirm button disarmed for a moment, as in Hangar |
| R9 | Name normalization and case conflicts across platforms corrupt or shadow files | Medium | normalized comparison key in the node format from version 1 |
| R10 | Collection depends on the server clock | Low | operator responsibility; also never collect before the minimum commit count |
| R11 | Dependency maturity: `ed25519-dalek` 3.0.0, `hpke` 0.15.1, `chacha20poly1305` 0.11.0 on `aead` 0.6.1 are a recent generation | Low to medium | independent audits of these crates not checked `[UNVERIFIED]`; pin versions, `cargo audit` in CI |
| R12 | Lessons from broken systems: key substitution and file injection by a malicious server (Nextcloud, Albrecht et al. 2024), unauthenticated chunk order (Hofmann and Truong 2024), malleable key handling (MEGA, Backendal et al. 2023 `[UNVERIFIED citation details]`) | context | each is addressed by a section above and must be a test case in the review |

### 7.2 What must be reviewed externally before a first release

1. The shared core: the open questions already listed in `concepts/team-crypto.md` (ten from the internal review, ten from the hardening round, one for the decision seal), restricted to the parts Drive uses.
2. The object format: keyed IDs, padding, nonce handling, the key commitment check, associated data.
3. The deduplication decision and the leakage of keyed IDs inside a folder.
4. The commit DAG: rollback and fork claims, the frontier rule, behaviour after device removal and re-admission.
5. Pairing: the anchor check, the MAC with the pairing secret, the fallback, replay and expiry.
6. The recovery flow end to end.
7. Retention and collection rules against a compromised client (a design review, then a test on a running server).
8. Server authentication: challenge, proof, token storage, revocation, rate limits behind a proxy.
9. Implementation: parsing strictness, zeroization, constant time comparisons, error messages that leak nothing, test vectors with an independent second implementation (the approach of Hangar's `test_vectors.py`).
10. A penetration test of the server and the Docker image; optionally a symbolic model (Tamarin or ProVerif) of pairing and the account log.

## 8. Cryptographic design for version 1

### 8.1 Primitives

| Purpose | Primitive | Crate (license) |
| --- | --- | --- |
| Signatures (log, commits, proofs) | Ed25519, strict verification | `ed25519-dalek` 3 (BSD-3-Clause) |
| Key wrap to devices | HPKE base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 | `hpke` 0.15 (MIT or Apache-2.0) |
| Object and record AEAD | XChaCha20-Poly1305, random 192 bit nonce | `chacha20poly1305` 0.11 (MIT or Apache-2.0) |
| KDF | HKDF-SHA256 | `hkdf` 0.13 |
| Keyed IDs, pairing MAC | HMAC-SHA-256 | `hmac` (already in the tree through `hkdf`) |
| Hashes (commit IDs, log) | SHA-256 | `sha2` 0.11 |
| Randomness | OS generator, fallible | `getrandom` 0.4 |
| Hygiene | `zeroize`, `subtle` | as in Hangar |

No new primitive compared with Hangar. BLAKE3 would be faster for keyed IDs on CPUs without SHA extensions; deferred to keep the review surface small.

Framing: `field(x) = u32 big endian length || x`, as in Hangar. All integers are big endian. All labels start with `hangar-drive/v1/`.

### 8.2 Identifiers

- Account id, device id, folder id: 16 random bytes chosen by the client; the server refuses duplicates.
- Server id: 16 random bytes made on the server's first start.

### 8.3 Key derivation

```text
K_acct,e = HKDF-SHA256(ikm = S_e,
             info = field("hangar-drive/v1/account-seal") || field(account) || field(e, u32)
                    || field(rotation log hash))
FK_f,g   = 32 random bytes, kept in the ring of folder f under generation g (u32, from 1)
K_obj    = HKDF-SHA256(ikm = FK_f,g, info = field("hangar-drive/v1/object-key") || field(f) || field(g))
K_id     = HKDF-SHA256(ikm = FK_f,g, info = field("hangar-drive/v1/object-id")  || field(f) || field(g))
P_mac    = HKDF-SHA256(ikm = P, info = field("hangar-drive/v1/pairing-mac"))
P_id     = HKDF-SHA256(ikm = P, info = field("hangar-drive/v1/pairing-id"))
recovery identity = HKDF-SHA256(ikm = code entropy, info = field("hangar-drive/v1/recovery-identity"), 64 bytes)
```

### 8.4 Formats in outline

```text
folder key ring record (sealed and signed with the record format, kind "folder-keys",
record id = folder id, under K_acct,e):
  0x01 || folder id || count (u16) || count x ( generation (u32) || FK (32) ), oldest first

object (types: 1 chunk, 2 file manifest, 3 directory node):
  id     = HMAC-SHA-256(K_id, field(type) || field(plaintext))
  padded = length (u64) || plaintext || zeros, to the Padme length of 8 + len(plaintext)
  aad    = field("hangar-drive/v1/object") || field(0x01) || field(account) || field(f)
           || field(g, u32) || field(type) || field(id)
  blob   = 0x01 || g (u32) || type (u8) || nonce (24) || XChaCha20-Poly1305(K_obj, nonce, padded, aad)
  open   = decrypt, check zero padding, recompute id, refuse on mismatch
  stored by the server under (account, f, id)

file manifest plaintext:
  0x01 || size (u64) || mtime (i64 ms) || flags (u32) || count (u32) || count x chunk id (32)
  chunks are 4 MiB of plaintext; only the last may be shorter

directory node plaintext:
  0x01 || count (u32) || entries sorted by comparison key:
  field(name bytes) || field(NFC comparison key) || kind (u8) || child id (32)
  || size (u64) || mtime (i64 ms) || flags (u32)

commit:
  body = field("hangar-drive/v1/commit") || field(0x01) || field(account) || field(f)
         || field(height, u64) || field(parents: count u8 (1..=8, 0 only for the first)
         || commit ids) || field(root node id) || field(g, u32) || field(device)
         || field(log head index, u64) || field(log head hash) || field(counter, u64)
         || field(seen: count u8 || (device || commit id) ...)
  commit id = SHA-256(field("hangar-drive/v1/commit-id") || body)
  wire      = body || Ed25519 signature of the device over field("hangar-drive/v1/commit-sig") || body
  sent with: reference delta (object ids added, object ids dropped), in the clear

session proof:
  field("hangar-drive/v1/session-proof") || field(server id) || field(account) || field(device)
  || field(sign public key) || field(challenge, 32) || field(protocol version, u16)

pairing request tag:
  HMAC-SHA-256(P_mac, field("hangar-drive/v1/pairing-request") || field(account) || field(new device id)
               || field(sign key) || field(kem key) || field(proof) || field(name))
```

The account log, epochs, wrapped keys, records and the recovery code keep Hangar's byte formats, re-labelled for Drive.

### 8.5 Client checks in order

1. Account log: verified from entry 1 against the pinned anchor (the pairing head or the device's own history).
2. Epoch secret: accepted only if it matches the log's commitment.
3. Folder ring: opened with `K_acct,e`; the signer must be a current non recovery device.
4. Commit: signature, signer valid at the named head, counter above the device's mark, generation in the ring, frontier rule.
5. Objects: AEAD, padding, recomputed ID equal to the referenced ID.

## 9. Decisions for ADR 0001

1. Version 1 scope: one person, several devices. The operator may be a different person. A compromised client is in scope for history integrity and out of scope for confidentiality.
2. Account model: the account is a Hangar style log with one member; member entries are reserved for sharing.
3. Crypto code: extract a shared core from `hangar-team-crypto` (option B) with a label domain parameter, and put Drive's file layer in a new `hangar-drive-crypto` crate. Until the extraction, use a git dependency pinned to a commit.
4. Separate device identities per product; the label prefix `hangar-drive/v1/` everywhere.
5. Folder keys are random, in a generational key ring sealed under the account epoch, and independent of epochs.
6. No convergent encryption; dedup only inside a folder and generation, via HMAC-SHA-256 keyed IDs.
7. Fixed 4 MiB chunks; no content defined chunking in version 1; keyed CDC only after its own review.
8. Padmé padding for every object.
9. XChaCha20-Poly1305 with random nonces, plus the recomputed keyed ID as a key commitment check.
10. No server visible tree: names only inside encrypted directory nodes, with an NFC comparison key.
11. A signed commit DAG per folder with frontier based rollback protection, per device counters and a seen vector. Freeze attacks are accepted and surfaced through a folder safety number.
12. Server side retention set only by the operator; reference deltas in the clear; the collection rule of section 4.2; anomaly pinning; no client delete API.
13. Pairing by a QR offer with a 128 bit secret and the log head as anchor; fallback by a full entropy code or safety number comparison; no short codes without a PAKE.
14. Recovery by Hangar's 128 bit recovery code with a recovery sheet; no password recovery.
15. Every device removal triggers an immediate rotation and a new folder key generation; full re-encryption is optional.
16. Transport: TLS 1.3, SPKI pinning for self signed setups, invite only account creation, Ed25519 challenge proof, hashed short lived bearer tokens, trusted proxy configuration for client IPs.
17. An external cryptographic review and a server penetration test are release blockers.
18. Exports, if any, use the age format; neither Cryptomator nor age is the core.

## 10. Sources

Retrieved or searched on 2026-11-26 unless noted.

- C2SP, "age" specification (payload: STREAM, 64 KiB chunks, nonce layout, header MAC): https://github.com/C2SP/C2SP/blob/main/age.md
- `age` crate on crates.io (0.12.1, description "[BETA]", repository str4d/rage): https://crates.io/crates/age ; license MIT or Apache-2.0: https://github.com/str4d/rage
- `aead-stream` crate on crates.io (0.6.0, "Generic implementation of the STREAM online authenticated encryption construction", MIT or Apache-2.0): https://crates.io/crates/aead-stream , https://docs.rs/aead-stream
- Hoang, Reyhanitabar, Rogaway, Vizár, "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance" (STREAM), referenced by the age spec: https://eprint.iacr.org/2015/189
- Cryptomator `cryptolib` (AGPLv3 or commercial license, Cure53 audit of 1.1.5, 2017): https://github.com/cryptomator/cryptolib
- Cryptomator security architecture and vault format (file header, AES-GCM 32 KiB chunks, AAD with chunk number and header nonce, AES-SIV names with directory ID): https://docs.cryptomator.org/security/architecture/ , https://docs.cryptomator.org/security/vault/
- Hofmann, Truong, "End-to-End Encrypted Cloud Storage in the Wild: A Broken Ecosystem", ACM CCS 2024: https://eprint.iacr.org/2024/1616
- Albrecht, Backendal, Coppola, Paterson, "Share with Care: Breaking E2EE in Nextcloud", IEEE EuroS&P 2024: https://eprint.iacr.org/2024/546
- Truong, Merz, Scarlata, Günther, Paterson, "Breaking and Fixing Content-Defined Chunking": https://eprint.iacr.org/2025/558 ; Borg chunker notes: https://borgbackup.readthedocs.io/en/master/internals/chunker.html
- Nikitin, Barman, Lueks, Underwood, Hubaux, Ford, "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs" (Padmé), PoPETs 2019(4): https://petsymposium.org/popets/2019/popets-2019-0056.php
- Li, Krohn, Mazières, Shasha, "Secure Untrusted Data Repository (SUNDR)", OSDI 2004 (fork consistency): https://www.usenix.org/legacy/event/osdi04/tech/li_j.html
- Len, Grubbs, Ristenpart, "Partitioning Oracle Attacks", USENIX Security 2021: https://eprint.iacr.org/2020/1491
- Not re-checked in this session: Backendal, Haller, Paterson, "MEGA: Malleable Encryption Goes Awry", IEEE S&P 2023; RFC 9180 (HPKE); RFC 9420 (MLS); RFC 9266 (TLS exporter channel binding); nginx documentation for `client_max_body_size` and `proxy_read_timeout`.
- Internal: Hangar repository, `crates/hangar-team-crypto` (README, module docs of `identity`, `memberlog`, `epoch`, `rotation`, `record`, `recovery`, `possession`, `notes`; `Cargo.toml`, `Cargo.lock`), `crates/hangar-team-protocol` (`hash.rs`, `limits.rs`), wiki page `concepts/team-crypto.md` (updated 2026-11-25). Hangar Drive repository at commit `fdc2c8b`.
