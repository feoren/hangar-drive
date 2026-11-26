-- Fixes of the overall security review (2026-11-26). sqlx records applied migrations, so this
-- file runs once per database; SQLite has no ADD COLUMN IF NOT EXISTS, as in 0002.

-- N1: bringing back a retired folder takes the pin restore allowance only once per pinned
-- head. Without the mark, retiring and bringing back the same pinned folder again and again
-- revived its tree for free each time, outside every budget, until the allowance ran out for
-- the restores it is meant for. The time a pin's head was first brought back with the
-- allowance; NULL while it never was.
ALTER TABLE pins ADD COLUMN brought_back_ms INTEGER;

-- N2: a folder the garbage collection deleted keeps a tombstone until its object files are
-- removed. The rows go in the collection's transaction, the files only after it; without the
-- tombstone an upload in between created the folder again, installed its file into the old
-- directory, and the removal of that directory took the new file with it while its row stayed.
-- While the tombstone exists, the folder ID cannot be created again (the upload is answered
-- `rate_limited` and retried); a tombstone a crash left behind is finished by the next step.
CREATE TABLE IF NOT EXISTS folder_tombstones (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    folder_id   BLOB    NOT NULL,
    created_ms  INTEGER NOT NULL,
    PRIMARY KEY (account_pk, folder_id)
) STRICT, WITHOUT ROWID;
