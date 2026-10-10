# Product Requirements

## Problem
Security testers need a fast, native, scriptable web testing toolkit that runs on all desktop OSes
without a browser engine or JVM, with a modern UI and a headless mode.

## Users
Students, pentesters, bug bounty hunters, and appsec engineers on Windows, Linux, and macOS.

## Functional requirements
| ID | Module | Requirement |
|----|--------|-------------|
| F1 | Proxy | HTTP/1.1, HTTP/2, WebSocket interception over TLS with a generated local CA |
| F2 | Proxy | Intercept queue: forward, drop, edit; scope-based filtering |
| F3 | Proxy | Match-and-replace rules on requests and responses |
| F4 | History | Searchable, filterable traffic log; smooth at 100k+ entries |
| F5 | Replay | Resend and edit any message; per-tab history; raw byte fidelity |
| F6 | Fuzzer | Attack modes: single-position, parallel same payload, parallel zip, cartesian product |
| F7 | Fuzzer | Payload sources, processors, grep-match/extract, rate limiting |
| F8 | Entropy | Token collection and statistical randomness analysis |
| F9 | Scanner | Crawler, passive checks, active checks, issue model with severity and confidence |
| F10 | OOB | Self-hostable DNS/HTTP/SMTP interaction server plus client polling |
| F11 | Codec | Encode/decode/hash chains; hex view |
| F12 | Diff | Compare two messages (text and bytes) |
| F13 | Browser | Launch an external Chromium with proxy and CA preconfigured; control via DevTools Protocol |
| F14 | Extensions | WASM plugin API for checks, payload generators, and message handlers |
| F15 | Projects | Save/load projects (SQLite), export reports (HTML, JSON) |
| F16 | CLI | Headless proxy, replay, scan, and report generation |

## Non-functional requirements
- Native binaries for Windows, Linux (x86_64, aarch64), macOS (Apple Silicon, x86_64).
- No Electron, no webview, no JVM, no OpenSSL.
- Startup under 1 s. History view stays responsive at 100k rows.
- Proxy overhead under 5 ms median per request on localhost.

## Non-goals
- Any AI/LLM features.
- Embedded browser engine.
- Compatibility with other tools' extension formats.
- Cloud-hosted multi-tenant scanning.
