-- Uploads per device (security review 2026-11-26, finding MEDIUM 3). sqlx records applied
-- migrations, so this file runs once per database; SQLite has no ADD COLUMN IF NOT EXISTS, as
-- in 0002 and 0003.
--
-- Before, the upload check counted every uncommitted upload of the account against the quota,
-- and no row said which device had sent it. One compromised device could upload a quota of
-- garbage it never committed and lock every honest device out until the collection deleted it
-- 24 hours later; removing the device freed nothing. Now each upload names its device, the
-- upload check counts only the uploading device's own uncommitted bytes, and removing a device
-- deletes its uncommitted uploads at once (service/objects.rs, `drop_uploads_of`).

-- The device that uploaded the object. NULL for rows from before this migration: a declared
-- object no longer needs it, and an uncommitted one then counts against no device's share and
-- is deleted by the collection within 24 hours of its upload, as before.
ALTER TABLE objects ADD COLUMN uploader BLOB;

-- Uncommitted bytes per device, the running counter the upload check reads (finding M4: no
-- request sums over every upload of a day). Kept by the triggers below, so every path that
-- inserts, declares or deletes an object keeps it right without knowing about it, and rebuilt
-- from the objects by `usage::recount_pending` at every collection step, which repairs any drift
-- (for example rows a folder's ON DELETE CASCADE removed after the folder row was gone).
CREATE TABLE IF NOT EXISTS device_pending (
    account_pk  INTEGER NOT NULL REFERENCES accounts (pk) ON DELETE CASCADE,
    device      BLOB    NOT NULL,
    data_bytes  INTEGER NOT NULL DEFAULT 0,
    dir_bytes   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_pk, device)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS objects_pending_insert AFTER INSERT ON objects
WHEN NEW.declared = 0 AND NEW.uploader IS NOT NULL
BEGIN
    INSERT INTO device_pending (account_pk, device, data_bytes, dir_bytes)
        SELECT f.account_pk, NEW.uploader,
               CASE WHEN NEW.kind <> 3 THEN NEW.size ELSE 0 END,
               CASE WHEN NEW.kind = 3 THEN NEW.size ELSE 0 END
        FROM folders f WHERE f.pk = NEW.folder_pk
    ON CONFLICT (account_pk, device) DO UPDATE SET
        data_bytes = data_bytes + excluded.data_bytes,
        dir_bytes = dir_bytes + excluded.dir_bytes;
END;

CREATE TRIGGER IF NOT EXISTS objects_pending_declare AFTER UPDATE OF declared ON objects
WHEN OLD.declared = 0 AND NEW.declared = 1 AND OLD.uploader IS NOT NULL
BEGIN
    UPDATE device_pending SET
        data_bytes = MAX(0, data_bytes - CASE WHEN OLD.kind <> 3 THEN OLD.size ELSE 0 END),
        dir_bytes = MAX(0, dir_bytes - CASE WHEN OLD.kind = 3 THEN OLD.size ELSE 0 END)
    WHERE account_pk = (SELECT account_pk FROM folders WHERE pk = OLD.folder_pk)
      AND device = OLD.uploader;
END;

CREATE TRIGGER IF NOT EXISTS objects_pending_delete AFTER DELETE ON objects
WHEN OLD.declared = 0 AND OLD.uploader IS NOT NULL
BEGIN
    UPDATE device_pending SET
        data_bytes = MAX(0, data_bytes - CASE WHEN OLD.kind <> 3 THEN OLD.size ELSE 0 END),
        dir_bytes = MAX(0, dir_bytes - CASE WHEN OLD.kind = 3 THEN OLD.size ELSE 0 END)
    WHERE account_pk = (SELECT account_pk FROM folders WHERE pk = OLD.folder_pk)
      AND device = OLD.uploader;
END;
