# Desktop UI

`cargo run --release -p mantis-ui -- [PROJECT.db]` opens the window (egui, per ADR 0001). Without a
path, type one into the Project box and press "Open / create".

## Layout
- **History** (centre): every stored exchange, newest first, virtualized. The filter box matches host,
  method, path or status as a case-insensitive substring. The list polls for new rows once a second.
- **Viewer** (bottom, resizable): the selected exchange's raw request and response. Tabs add
  "as captured" / "as received" copies when rewrite rules or edits changed what was sent. Text and Hex
  views, search and Next. Control characters show as escapes (`\r`, `\x00`) and very long lines are
  continued on the next row, so nothing needs horizontal scrolling to be found.

## Proxy page
Start and stop the proxy from the window; it runs in the same process on a background runtime, so the
UI never waits on it. Settings are locked while it runs.
- **Listen address** (default `127.0.0.1:8080`) and **CA directory** (default: the user data directory).
- **Allow network access** is required to listen beyond loopback and shows a warning when ticked.
- **Skip origin certificate verification (insecure)** is the GUI form of `--insecure-upstream`. A red
  banner stays at the top of the window while it is ticked or active. It is off at every launch.
- **Export PEM / DER** writes the CA certificate (never the key) for importing into a browser; it
  refuses to overwrite a file. The CA fingerprint is shown once the proxy has started.
- A project must be open first; the proxy logs into it, and the history list updates as rows arrive.

## Scope page
A table of include/exclude rules (host, ports, path regex) with inline validation, the same model as
`mantis-cli proxy --scope`, and load/save of that TOML file. Turn the checkbox on to restrict logging,
interception and rewriting to the rules; turn it off to put everything in scope. "Apply to running proxy"
takes effect immediately; exchanges already in flight keep the verdict they started with.

## Remembered between runs
Last project, listen address, CA directory and the scope rules. Not remembered: the insecure and
network-access switches, and whether the proxy was running.

## Trying it with a lot of data
```
cargo run --release -p mantis-ui --example seed_db -- /tmp/big.db 100000   # newest row has a 5 MB body
cargo run --release -p mantis-ui -- /tmp/big.db
```

## Benchmark
`mantis-ui PROJECT.db --bench` scripts one scroll through the whole history and then through the 5 MB
body in Text and Hex, prints frame-interval percentiles and memory, and exits. Numbers depend on the
machine and display; the acceptance bar is no frame over 20 ms in the scripted run.

## How it is built
The window draws; the models decide. `HistoryModel` pages rows on demand through a reader thread that
owns a read-only database connection, so the UI thread never touches SQLite. `RawView` indexes a
message into display rows. Both are unit tested without rendering.
