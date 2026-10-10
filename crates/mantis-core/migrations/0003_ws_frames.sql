-- WebSocket frames seen inside an upgraded exchange. `raw` holds the frame
-- exactly as on the wire (possibly cut short when `truncated`); the other
-- columns are derived from its header for lookup.
CREATE TABLE ws_frames (
    id          INTEGER PRIMARY KEY,
    exchange_id INTEGER NOT NULL REFERENCES exchanges (id),
    ts          INTEGER NOT NULL,        -- unix microseconds, UTC
    to_server   INTEGER NOT NULL,        -- 1 client->server, 0 server->client
    opcode      INTEGER NOT NULL,
    fin         INTEGER NOT NULL,
    compressed  INTEGER NOT NULL,        -- RSV1 (permessage-deflate)
    payload_len INTEGER NOT NULL,        -- real length, even when raw is truncated
    truncated   INTEGER NOT NULL,
    raw         BLOB    NOT NULL
);
CREATE INDEX idx_ws_frames_exchange ON ws_frames (exchange_id, id);
