-- Folder removals per account (upload throughput review 2026-11-28, follow-up MEDIUM 1). sqlx
-- records applied migrations, so this file runs once per database; SQLite has no ADD COLUMN IF
-- NOT EXISTS, as in 0002 to 0005.
--
-- An upload puts its file in place before its write transaction. A folder directory is removed
-- without the object stripe locks (garbage collection, `purge folder`), so a folder that was
-- deleted between those two steps may have taken the new file with it. Every transaction that
-- deletes folders of an account raises this counter; an upload reads it before its file goes in
-- place and refuses in its transaction when it changed (service/objects.rs, `store`).
ALTER TABLE accounts ADD COLUMN folder_removals INTEGER NOT NULL DEFAULT 0;
