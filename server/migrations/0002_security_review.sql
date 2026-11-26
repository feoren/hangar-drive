-- Fixes of the server security review (2026-11-26). Each statement can run on a database of
-- 0001 exactly once (sqlx records applied migrations); IF EXISTS and IF NOT EXISTS keep the
-- table rebuilds safe if a statement before them is ever split off.

-- M1: challenges are stateless (an HMAC under the server secret). Only challenges whose proof
-- verified are remembered, until they expire, so none is accepted twice.
DROP TABLE IF EXISTS challenges;
CREATE TABLE IF NOT EXISTS used_challenges (
    challenge   BLOB    PRIMARY KEY,
    expires_ms  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS used_challenges_expiry ON used_challenges (expires_ms);

-- M2: the inviting device reserves a slot with its session; the new device can fill only a
-- reserved, empty slot, once. Slots live ten minutes, so the old ones are simply dropped.
DROP TABLE IF EXISTS pairing;
CREATE TABLE IF NOT EXISTS pairing (
    id          BLOB    PRIMARY KEY,
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    request     TEXT,
    expires_ms  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS pairing_expiry ON pairing (expires_ms);
-- Open slots per account.
CREATE INDEX IF NOT EXISTS pairing_account ON pairing (account_pk, expires_ms);

-- M3: a pin no longer goes with its folder. A folder with an admitted pin is deleted only after
-- the pin ended (retention.rs); the foreign key without ON DELETE makes deleting a folder that
-- still has a pin row fail instead of dropping the pin silently. Deleting the account still
-- removes both, in one statement.
CREATE TABLE IF NOT EXISTS pins_new (
    pk          INTEGER PRIMARY KEY,
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    folder_pk   INTEGER NOT NULL REFERENCES folders (pk),
    commit_id   BLOB    NOT NULL,
    seq         INTEGER NOT NULL,
    created_ms  INTEGER NOT NULL,
    until_ms    INTEGER NOT NULL,
    lapsed_ms   INTEGER
) STRICT;
INSERT INTO pins_new (pk, account_pk, folder_pk, commit_id, seq, created_ms, until_ms, lapsed_ms)
    SELECT pk, account_pk, folder_pk, commit_id, seq, created_ms, until_ms, lapsed_ms FROM pins;
DROP TABLE pins;
ALTER TABLE pins_new RENAME TO pins;
CREATE INDEX IF NOT EXISTS pins_account ON pins (account_pk, created_ms);
CREATE INDEX IF NOT EXISTS pins_folder ON pins (folder_pk);

-- M4: running counters instead of a SUM over every upload. Budgets and the pin restore
-- allowance are kept per minute: one row per account, device and minute, so the rolling sums
-- read at most 1440 rows per device and day, however many uploads there were.
CREATE TABLE IF NOT EXISTS budget_minutes (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    device      BLOB    NOT NULL,
    minute_ms   INTEGER NOT NULL,
    bytes       INTEGER NOT NULL,
    PRIMARY KEY (account_pk, minute_ms, device)
) STRICT, WITHOUT ROWID;
INSERT INTO budget_minutes (account_pk, device, minute_ms, bytes)
    SELECT account_pk, device, (at_ms / 60000) * 60000, SUM(bytes) FROM budget_events
    GROUP BY account_pk, device, (at_ms / 60000) * 60000;
DROP TABLE IF EXISTS budget_events;

CREATE TABLE IF NOT EXISTS allowance_minutes (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    minute_ms   INTEGER NOT NULL,
    bytes       INTEGER NOT NULL,
    PRIMARY KEY (account_pk, minute_ms)
) STRICT, WITHOUT ROWID;
INSERT INTO allowance_minutes (account_pk, minute_ms, bytes)
    SELECT account_pk, (at_ms / 60000) * 60000, SUM(bytes) FROM allowance_events
    GROUP BY account_pk, (at_ms / 60000) * 60000;
DROP TABLE IF EXISTS allowance_events;

-- Uncommitted uploads per account (M4), sealed record bytes per account (L3).
ALTER TABLE accounts ADD COLUMN pending_data_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN pending_dir_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN record_bytes INTEGER NOT NULL DEFAULT 0;
UPDATE accounts SET
    pending_data_bytes = (SELECT COALESCE(SUM(o.size), 0) FROM objects o JOIN folders f ON f.pk = o.folder_pk
                          WHERE f.account_pk = accounts.pk AND o.declared = 0 AND o.kind <> 3),
    pending_dir_bytes = (SELECT COALESCE(SUM(o.size), 0) FROM objects o JOIN folders f ON f.pk = o.folder_pk
                         WHERE f.account_pk = accounts.pk AND o.declared = 0 AND o.kind = 3),
    record_bytes = (SELECT COALESCE(SUM(LENGTH(r.data)), 0) FROM records r WHERE r.account_pk = accounts.pk);

-- L4: the burst threshold is a share of the folder's file objects (chunks and manifests).
ALTER TABLE folders ADD COLUMN live_file_objects INTEGER NOT NULL DEFAULT 0;
UPDATE folders SET live_file_objects = (
    SELECT COUNT(*) FROM refs r JOIN objects o ON o.pk = r.object_pk
    WHERE r.folder_pk = folders.pk AND r.dropped_seq IS NULL AND o.kind <> 3);
