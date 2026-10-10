# ADR 0001: GUI framework

Status: Accepted (egui/eframe)

## Context
ARCHITECTURE decision 6 defers the GUI choice to an editor-widget spike. The
acceptance criteria (ROADMAP phase 0) are: a 5 MB body viewer, hex view and
search; smooth scroll; non-UTF-8 bytes render. Candidates: iced 0.14, Slint 1.18,
egui/eframe 0.36. Spikes live in `spikes/gui-{iced,slint,egui}/` (throwaway,
standalone packages outside the workspace; shared body generator and bench
harness in `spikes/common.rs`).

## What was built
Each spike generates the same deterministic 5 MiB body (50k+ lines, lines up to
~210 chars, non-ASCII text, and invalid UTF-8 bytes `FF FE 80 C3 00` every 997th
line). It has Text and Hex tabs (offset, 16 bytes/row, ASCII gutter), a search
box (`memchr::memmem`, match count, Next jumps to the match in the active view),
and virtualised rows: egui `ScrollArea::show_rows`, Slint `ListView` over a lazy
`Model`, iced a hand-rolled 80-row window inside a `scrollable` with spacers
(iced has no built-in virtual list).

## Measurement
`--bench` scripts one pass over the whole body: 600 frames in Text (about 90
rows per frame), then 600 in Hex (about 550 rows per frame), after 30 warm-up
frames, and records frame-to-frame intervals. Release builds, Apple M5, 16 GB,
macOS 27.0.1, 60 Hz pacing (p50 of about 16.6 ms is vsync). Three runs each.
RSS from `ps` after load and after the scroll, peak from `/usr/bin/time -l`.

| | egui | iced | Slint |
|---|---|---|---|
| Frame p95, text / hex (ms) | 17.2-17.3 / 17.2 | 17.0-17.1 / 17.1 | 18.1-19.8 / 17.7-21.2 |
| Frame p99, text / hex (ms) | 17.6 / 17.4-17.5 | 17.2-17.5 / 17.2-17.7 | 18.4-21.4 / 18.0-21.4 |
| Max frame, text (ms) | 28-34 | 20-37 | 49 (all runs) |
| Frames >20 ms, text / hex | 3-6 / 0 | 0-3 / 0 | 2-25 / 2-142 |
| RSS after load / after scroll (MB) | 116 / 120-121 | 104 / 108 | 110 / 115 |
| Peak RSS (MB) | 121 | 108 | 115 |
| CPU time for the 20 s run (user+sys, s) | 4.3 | **18.8** | 3.1-5.5 |
| Release binary (MB) | 13.2 | 10.7 | 15.6 |

Peak RSS is `maximum resident set size` converted from bytes. Baseline: the 5 MiB
body plus the line index is about 6 MiB, so nearly all RSS is framework and GPU
overhead, and memory does not separate the candidates.

Reading the numbers:
- All three hold 60 fps on the paced intervals; none dropped frames in a way a
  user would see at p99. The interval metric is capped by vsync, so it hides
  headroom. CPU time is the better indicator of headroom.
- **iced** used about 15 ms of CPU per frame (18 s over 1230 frames) in this
  stress test, nearly the whole frame budget. Idle CPU is 0%. Every frame
  replaces all 80 rows with fresh text, so cosmic-text shaping is the likely
  cost. Not profiled, and the spike's hand-rolled windowing may contribute.
  Real scrolling changes a few rows per frame, so this overstates the cost,
  but it leaves little headroom.
- **Slint** had a few more >20 ms frames in Hex (run 1 had 2, runs 2-3 had
  82-142) and a consistent 49 ms hitch in the text phase. Cause not
  investigated (a first-frame or model-reset cost is plausible).
- **egui** was steady, with a handful of 28-34 ms frames early in the text phase.

## Not measured (be careful relying on this)
- Real trackpad/wheel feel. Scripted jumps of a screen or more per frame are a
  stress test, not a smoothness judgment.
- Search is not benchmarked. The `memmem` scan over 5 MiB is identical across
  spikes. The UI wiring (typing, Next, jump) was written but not exercised by
  the automated run.
- Only macOS and one display refresh rate. The CI matrix covers Windows and Linux
  builds, but no spike was built or run there.
- Editor-grade features (selection, copy, in-place editing of a request, syntax
  highlighting). The spikes only display. Widget capabilities below come from
  general knowledge of each toolkit, not from testing.

## Comparison beyond the numbers
- **egui**: immediate mode, least code (about 90 lines for the spike). Virtual
  rows are one call. Editing a request needs `TextEdit`, which lays out the
  whole string each frame, so a 5 MB editable buffer would need a custom
  widget; read-only views are fine. API churn is high: 0.36 moved `App::update`
  to `ui` and renamed panels, so expect upgrade work. Accessibility is weaker.
- **iced**: Elm-style, clean for message-driven channel architecture (fits the
  tokio-channels rule). No virtual list in the box. Has a `text_editor` built on
  cosmic-text, but its cost at megabyte sizes was not tested. The CPU result
  above is the main concern.
- **Slint**: declarative `.slint` DSL plus build step, so UI code is split across
  two languages, and a lazy `Model` is needed for large lists. `ListView`
  virtualises natively. Licensing needs checking: Slint is offered under
  GPLv3, a royalty-free tier, and commercial terms, and this project is MIT.
  Verify the current terms before choosing it.

## Recommendation
Choose **egui** (eframe). Accepted by the maintainer.

Why: lowest CPU headroom risk after Slint, steady frame times, least code, no
licensing question, and a pure-Rust API that keeps the UI thread simple with
`mpsc` channels. Its main weakness is large editable text, which we can address
with a custom virtualised editor widget for message bodies, since raw `Bytes`
rather than `String` is the source of truth anyway.

Runner-up: Slint if its license is acceptable and the Hex 20 ms+ frames turn out
to be a spike artifact. iced is the least attractive on this evidence.

Before accepting, a follow-up check is worth doing: an interactive
trackpad pass on all three, and a quick build and run of the egui spike on
Windows and Linux.

## Consequences
Add `mantis-ui` dependencies on `eframe` in a separate change,
keep `mantis-core` free of any GUI dependency (unchanged), and delete
`spikes/` or leave it for reference. Open follow-ups: an interactive trackpad pass and a run of the egui spike on
Windows and Linux.
