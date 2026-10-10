-- Raw request/response bytes are the source of truth. The other columns are
-- derived at insert time and exist only for lookup.
CREATE TABLE exchanges (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,          -- unix microseconds, UTC
    source   TEXT    NOT NULL,
    host     TEXT    NOT NULL,
    port     INTEGER NOT NULL,
    tls      INTEGER NOT NULL,
    method   TEXT,
    path     TEXT,
    status   INTEGER,
    request  BLOB    NOT NULL,
    response BLOB
);
CREATE INDEX idx_exchanges_host   ON exchanges (host);
CREATE INDEX idx_exchanges_method ON exchanges (method);
CREATE INDEX idx_exchanges_status ON exchanges (status);
CREATE INDEX idx_exchanges_ts     ON exchanges (ts);
