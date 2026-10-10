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
