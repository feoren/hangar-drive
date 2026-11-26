-- Hangar Drive server metadata (ADR 0001, sections 3 to 6). The server stores only what it
-- needs and nothing it could read: IDs are opaque, objects, records and wrapped keys are
-- encrypted, log entries and commits are signed plaintext without content.
-- Times are Unix milliseconds (UTC). IDs are raw bytes (16 or 32). Secrets (session and invite
-- tokens) are stored only as SHA-256.

-- One row per key: the server ID (16 random bytes, made at the first start).
CREATE TABLE server_meta (
    key         TEXT    PRIMARY KEY,
    value       BLOB    NOT NULL
) STRICT, WITHOUT ROWID;

-- Single-use, expiring invites created by the admin CLI.
CREATE TABLE invites (
    token_hash  BLOB    PRIMARY KEY,
    created_ms  INTEGER NOT NULL,
    expires_ms  INTEGER NOT NULL,
    used_ms     INTEGER
) STRICT, WITHOUT ROWID;

-- warn_state: bit set of operator warnings already raised (see retention.rs), so a warning is
-- logged and announced once per transition and not in every garbage collection step.
CREATE TABLE accounts (
    pk              INTEGER PRIMARY KEY,
    id              BLOB    NOT NULL UNIQUE,
    created_ms      INTEGER NOT NULL,
    log_length      INTEGER NOT NULL DEFAULT 0 CHECK (log_length >= 0),
    feed_seq        INTEGER NOT NULL DEFAULT 0 CHECK (feed_seq >= 0),
    live_data_bytes INTEGER NOT NULL DEFAULT 0,
    live_dir_bytes  INTEGER NOT NULL DEFAULT 0,
    warn_state      INTEGER NOT NULL DEFAULT 0
) STRICT;

-- The device log, verified by the same code as on the devices before every append.
CREATE TABLE log_entries (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    idx         INTEGER NOT NULL CHECK (idx >= 1),
    entry       BLOB    NOT NULL,
    PRIMARY KEY (account_pk, idx)
) STRICT, WITHOUT ROWID;

-- HPKE-wrapped epoch secrets, one per epoch and recipient device.
CREATE TABLE epoch_keys (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    epoch       INTEGER NOT NULL CHECK (epoch >= 1),
    device      BLOB    NOT NULL,
    data        BLOB    NOT NULL,
    PRIMARY KEY (account_pk, epoch, device)
) STRICT, WITHOUT ROWID;

-- Sign-in challenges: single use, a minute long. Not tied to an existing account, so an
-- unknown account looks like a known one.
CREATE TABLE challenges (
    challenge   BLOB    PRIMARY KEY,
    account_id  BLOB    NOT NULL,
    device_id   BLOB    NOT NULL,
    expires_ms  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX challenges_expiry ON challenges (expires_ms);

-- Bearer sessions. recovery and appended carry the SessionScope; appended is set in the same
-- transaction that stores a recovery session's one append.
CREATE TABLE sessions (
    token_hash  BLOB    PRIMARY KEY,
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    device      BLOB    NOT NULL,
    recovery    INTEGER NOT NULL CHECK (recovery IN (0, 1)),
    appended    INTEGER NOT NULL DEFAULT 0 CHECK (appended IN (0, 1)),
    expires_ms  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
-- Revoking a removed device's sessions in its account.
CREATE INDEX sessions_device ON sessions (account_pk, device);
CREATE INDEX sessions_expiry ON sessions (expires_ms);

-- Sealed account records. folder is empty for kinds without a folder.
CREATE TABLE records (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    kind        TEXT    NOT NULL CHECK (kind IN ('folder-keys', 'folders', 'device-names')),
    folder      BLOB    NOT NULL,
    version     INTEGER NOT NULL CHECK (version >= 1),
    data        BLOB    NOT NULL,
    PRIMARY KEY (account_pk, kind, folder)
) STRICT, WITHOUT ROWID;

-- The account change feed. coalesce_key is unique per account: a newer entry of the same kind
-- and key replaces the older one, so the feed stays bounded and returns the newest per key.
CREATE TABLE feed (
    account_pk   INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    seq          INTEGER NOT NULL,
    coalesce_key TEXT    NOT NULL,
    change       TEXT    NOT NULL,
    PRIMARY KEY (account_pk, seq),
    UNIQUE (account_pk, coalesce_key)
) STRICT, WITHOUT ROWID;

-- A new device's pairing request, routed by the pairing ID (derived from the pairing secret).
CREATE TABLE pairing (
    id          BLOB    PRIMARY KEY,
    request     TEXT    NOT NULL,
    expires_ms  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX pairing_expiry ON pairing (expires_ms);

-- Folders of an account. A folder row exists from the first upload; head_pk and seq come with
-- the first commit. retired_ms: retired, restorable within the window.
CREATE TABLE folders (
    pk              INTEGER PRIMARY KEY,
    account_pk      INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    id              BLOB    NOT NULL,
    created_ms      INTEGER NOT NULL,
    seq             INTEGER NOT NULL DEFAULT 0 CHECK (seq >= 0),
    head_pk         INTEGER,
    retired_ms      INTEGER,
    live_data_bytes INTEGER NOT NULL DEFAULT 0,
    live_dir_bytes  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account_pk, id)
) STRICT;

-- Commits. role 'head': was the folder's head after its call (seq); 'side': uploaded with the
-- merge commit of the same seq, base_seq is the seq of its parent head. server_ms and
-- superseded_ms are dropped when the commit's tree expires (data minimization, ADR 5); a head's
-- body stays for the life of the folder, a side commit's row goes with its tree.
CREATE TABLE commits (
    pk              INTEGER PRIMARY KEY,
    folder_pk       INTEGER NOT NULL REFERENCES folders (pk) ON DELETE CASCADE,
    commit_id       BLOB    NOT NULL,
    seq             INTEGER NOT NULL CHECK (seq >= 1),
    role            TEXT    NOT NULL CHECK (role IN ('head', 'side')),
    body            BLOB    NOT NULL,
    height          INTEGER NOT NULL,
    device          BLOB    NOT NULL,
    generation      INTEGER NOT NULL,
    log_index       INTEGER NOT NULL,
    base_seq        INTEGER,
    server_ms       INTEGER,
    superseded_ms   INTEGER,
    expired         INTEGER NOT NULL DEFAULT 0 CHECK (expired IN (0, 1)),
    UNIQUE (folder_pk, commit_id)
) STRICT;
-- Delta pull by folder sequence, and the window range of the garbage collection.
CREATE INDEX commits_seq ON commits (folder_pk, seq, role);

-- The highest commit counter the server accepted per folder and device.
CREATE TABLE device_marks (
    folder_pk   INTEGER NOT NULL REFERENCES folders (pk) ON DELETE CASCADE,
    device      BLOB    NOT NULL,
    counter     INTEGER NOT NULL,
    PRIMARY KEY (folder_pk, device)
) STRICT, WITHOUT ROWID;

-- Stored objects, per folder (their IDs are keyed per folder). kind is the type byte of the
-- clear header (1 chunk, 2 file manifest, 3 directory node); size the padded blob length.
-- declared: some commit has named it in a reference delta; until then it is an upload that
-- counts as uncommitted and is deleted 24 hours after its upload.
CREATE TABLE objects (
    pk          INTEGER PRIMARY KEY,
    folder_pk   INTEGER NOT NULL REFERENCES folders (pk) ON DELETE CASCADE,
    object_id   BLOB    NOT NULL,
    kind        INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
    size        INTEGER NOT NULL CHECK (size > 0),
    uploaded_ms INTEGER NOT NULL,
    declared    INTEGER NOT NULL DEFAULT 0 CHECK (declared IN (0, 1)),
    UNIQUE (folder_pk, object_id)
) STRICT;
-- Uncommitted uploads of a folder (quota and the 24 hour rule).
CREATE INDEX objects_pending ON objects (folder_pk, declared, uploaded_ms);

-- Reachability as intervals over the folder sequence: the object is in the tree of every head
-- with added_seq <= seq < dropped_seq (dropped_seq NULL: still live). Built from the reference
-- deltas, so the tree of any head is one range query and no delta has to be kept as such.
CREATE TABLE refs (
    folder_pk   INTEGER NOT NULL REFERENCES folders (pk) ON DELETE CASCADE,
    object_pk   INTEGER NOT NULL REFERENCES objects (pk) ON DELETE CASCADE,
    added_seq   INTEGER NOT NULL,
    dropped_seq INTEGER,
    PRIMARY KEY (object_pk, added_seq)
) STRICT, WITHOUT ROWID;
-- Live set of a folder and the interval scans of the garbage collection.
CREATE INDEX refs_folder ON refs (folder_pk, dropped_seq, added_seq);

-- Objects a side commit adds to its base tree.
CREATE TABLE side_refs (
    commit_pk   INTEGER NOT NULL REFERENCES commits (pk) ON DELETE CASCADE,
    object_pk   INTEGER NOT NULL REFERENCES objects (pk) ON DELETE CASCADE,
    PRIMARY KEY (commit_pk, object_pk)
) STRICT, WITHOUT ROWID;
CREATE INDEX side_refs_object ON side_refs (object_pk);

-- Anomaly pins: the tree of commit seq of the folder is held until until_ms, unless the pin
-- lapses under the pin cap (lapsed_ms, for good) or the operator lifts it (row deleted).
CREATE TABLE pins (
    pk          INTEGER PRIMARY KEY,
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    folder_pk   INTEGER NOT NULL REFERENCES folders (pk) ON DELETE CASCADE,
    commit_id   BLOB    NOT NULL,
    seq         INTEGER NOT NULL,
    created_ms  INTEGER NOT NULL,
    until_ms    INTEGER NOT NULL,
    lapsed_ms   INTEGER
) STRICT;
CREATE INDEX pins_account ON pins (account_pk, created_ms);

-- Bytes made live per device (rolling 24 hours, upload budgets).
CREATE TABLE budget_events (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    device      BLOB    NOT NULL,
    at_ms       INTEGER NOT NULL,
    bytes       INTEGER NOT NULL
) STRICT;
CREATE INDEX budget_events_account ON budget_events (account_pk, at_ms);

-- Devices that hit their upload budget and were announced; cleared by the garbage collection
-- once their rolling usage is below the budget again, so the warning is not repeated per upload.
CREATE TABLE device_warnings (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    device      BLOB    NOT NULL,
    PRIMARY KEY (account_pk, device)
) STRICT, WITHOUT ROWID;

-- Retained bytes revived free from the tree of an admitted pin (rolling window W).
CREATE TABLE allowance_events (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    at_ms       INTEGER NOT NULL,
    bytes       INTEGER NOT NULL
) STRICT;
CREATE INDEX allowance_events_account ON allowance_events (account_pk, at_ms);

-- Replaced or dropped file data per head commit (rolling hour, anomaly signal). parent_seq is
-- the seq of the head the commit replaced: the last commit before the burst is the oldest one.
CREATE TABLE drop_events (
    folder_pk   INTEGER NOT NULL REFERENCES folders (pk) ON DELETE CASCADE,
    at_ms       INTEGER NOT NULL,
    parent_seq  INTEGER NOT NULL,
    objects     INTEGER NOT NULL,
    bytes       INTEGER NOT NULL
) STRICT;
CREATE INDEX drop_events_folder ON drop_events (folder_pk, at_ms);
