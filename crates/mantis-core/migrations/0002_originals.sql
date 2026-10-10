-- Messages as captured before match-and-replace rules or manual edits, kept
-- beside the bytes actually sent (NULL when nothing changed), and whether the
-- user dropped the exchange from the intercept queue.
ALTER TABLE exchanges ADD COLUMN request_original  BLOB;
ALTER TABLE exchanges ADD COLUMN response_original BLOB;
ALTER TABLE exchanges ADD COLUMN dropped INTEGER NOT NULL DEFAULT 0;
