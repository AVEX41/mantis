# ADR 0002: HTTP/2 is downgraded to HTTP/1.1

Status: Accepted

## Context
The proxy, the raw wire reader/writer and the stored message model are HTTP/1.1: a message is one
contiguous byte string that is forwarded and stored exactly as seen (ARCHITECTURE decisions 1 and 2).
HTTP/2 has no such form. Messages are split into binary frames, multiplexed on one connection, with
HPACK-compressed headers that are not byte-for-byte reproducible. Supporting it means a second
message model, a frame-level proxy and a way to show and edit requests that never existed as text.

ROADMAP Phase 2 allows either "HTTP/2 support or documented downgrade".

## Decision
Downgrade. During TLS interception both sides are offered ALPN `http/1.1` only, so browsers and most
HTTP clients fall back to HTTP/1.1 on their own. No HTTP/2 code is written now.

## Consequences
- Browsers, curl and most libraries work unchanged. Cleartext HTTP/2 (`h2c`) is not recognised: an
  `Upgrade: h2c` that an origin accepts becomes an uncaptured byte tunnel.
- Clients that require HTTP/2 fail the TLS handshake (`no_application_protocol`), notably gRPC
  clients and a few APIs. The proxy logs a warning saying so and keeps serving other clients.
  Such traffic can still be tested by pointing the client at the origin directly.
- Servers that behave differently over HTTP/2 (smuggling via downgrade, h2-specific features) are not
  reachable through Mantis. That is a real gap for a security tool.
- Revisit when HTTP/2 testing is needed. A separate frame-level capture path, with its own stored
  representation, is the likely shape; it must not replace the raw HTTP/1.1 message model.
