# WebSocket capture

When an in-scope exchange upgrades to WebSocket (`101` with `Upgrade: websocket`), over `ws://` or
through an intercepted `wss://` tunnel, the proxy keeps forwarding bytes exactly as they arrive and
records each frame on the side.

- **What is stored:** one `ws_frames` row per frame, linked to the upgrade exchange. `raw` holds the
  frame as on the wire, still masked when the client sent it masked. Opcode, FIN, compressed (RSV1)
  and the real payload length are derived from the header for lookup. Fragmented messages stay as
  separate frames; reassembly is up to the viewer or exporter.
- **Compression:** `permessage-deflate` is not stripped from the handshake, so such frames are stored
  as compressed and flagged. Decompression for display comes later.
- **Limits:** at most 1 MiB of payload is stored per frame (`truncated` is set, the real length is
  kept) and 64 MiB per connection and direction. Forwarding is never affected.
- **Invalid framing:** if a stream stops looking like WebSocket, capture stops for that connection
  with a warning and bytes keep flowing.
- **Not captured:** out-of-scope upgrades (relayed untouched), non-WebSocket upgrades, and edits or
  interception of frames (not implemented).
- **Using it:** `mantis-cli proxy` prints `ws #<exchange> -> text 12B` lines. Library users call
  `ProxyHandle::subscribe_ws()` and `Store::ws_frames(exchange_id)`.
