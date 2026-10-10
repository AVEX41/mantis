# HTTPS interception

Mantis terminates TLS with a local CA, reads the plaintext, and re-encrypts to the origin.

## Setup
1. Run `mantis-cli proxy`. On first start it creates the CA in the user data directory
   (`mantis-cli ca path` shows where) and prints the certificate's SHA-256 fingerprint.
2. Export the certificate: `mantis-cli ca export --out mantis-ca.pem` (or `--format der` for Windows).
   Only the certificate is exported; the private key never leaves `ca.key`.
3. Import `mantis-ca.pem` into the browser or OS trust store, and check the fingerprint matches.
4. Point the client at the proxy (default `127.0.0.1:8080`).

Quick check without a browser: `curl --proxy http://127.0.0.1:8080 --cacert mantis-ca.pem https://example.org/`.

## What gets intercepted
- With no scope configured, every `CONNECT` target is intercepted and logged (`tls = true`).
- With a scope, only targets whose host and port may be in scope are intercepted. Everything else is
  relayed as an untouched byte tunnel: no certificate is minted and nothing is logged.
  Path rules are applied per request inside the tunnel.
- HTTP/2 is not implemented. Both sides are offered `http/1.1` only, so clients downgrade; clients that
  require HTTP/2 (such as gRPC) cannot be proxied. See `docs/adr/0002-http2-downgrade.md`.

## Origin certificates
Origin certificates are verified against the OS trust store. For lab targets with self-signed
certificates use `--insecure-upstream` (library: `Config::insecure_upstream`). This disables
verification entirely, so keep it off for anything else. Frontends must expose the same option.

## Key handling
- `ca.key` is created with mode `0600` in a `0700` directory (Unix). Mantis refuses to load a key that
  group or others can read. On Windows it relies on the per-user profile ACL; no stronger protection.
- The CA is valid for 3 years, is limited to signing certificates (`pathlen 0`), and issues leaves valid
  for 365 days. Anyone holding `ca.key` can impersonate any site to a client that trusts the CA:
  only import it into profiles used for testing, and remove it when finished.
- To rotate: delete `ca.pem` and `ca.key` (both), restart, and re-import.

## Known limits
- Clients that pin certificates (many mobile apps) will refuse the interception.
- Large uploads from clients sending `Expect: 100-continue` wait about a second.
- Origin connections are reused only within one intercepted tunnel.
