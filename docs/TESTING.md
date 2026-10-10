# Testing strategy

## Levels
- Unit tests per crate.
- Property tests (proptest) for parsers and the raw wire reader/writer.
- Fuzz targets (cargo-fuzz) for HTTP parsing.
- Integration tests: spawn proxy plus a local test server, assert on stored messages.
- Golden-file tests for reports.
- UI: keep logic in view-models so it is testable without rendering.

## Local lab targets (run in Docker on an isolated network)
- OWASP Juice Shop
- DVWA
- OWASP WebGoat
- Your own homelab VLAN targets

## Scanner quality
Track per-check results in `docs/scan-results.md`: true positives, false positives, missed cases.
A check is not "done" until it has a documented result on at least two targets.

## CI
Matrix: windows-latest, ubuntu-latest, macos-latest. Steps: fmt, clippy, test, cargo audit.
