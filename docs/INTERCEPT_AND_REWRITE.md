# Intercept queue and match-and-replace

Both only touch **in-scope** traffic (everything, when no scope is configured). Out-of-scope requests
are forwarded untouched, never held, and never logged.

Order for each message: rewrite rules, then the intercept queue, then forwarding. The queue shows
the already-rewritten message.

## Intercept queue
- `mantis-cli proxy --intercept` holds requests and `--intercept-responses` also holds responses.
  Each held message prints with control characters escaped; answer `f` (forward) or `d` (drop) on stdin.
  If stdin closes, interception turns off so nothing stays stuck. Editing is for the GUI.
- Library: `ProxyHandle::intercept()` gives `set_enabled(Dir, bool)`, `subscribe()` (a `Held` event
  per message), `pending()` and `decide(id, Forward | Edited(bytes) | Drop)`. Turning a direction off
  forwards everything held in it.
- Edited bytes are sent exactly as given: no `Content-Length` fix-up, no normalisation. The target
  host and port stay those of the original request, whatever the edit says.
- Drop discards the message and closes the client connection with no reply.
- A connection error from the client releases its held entry. A clean end of the client's stream is
  treated as a half-close (some clients still wait for the answer), so that entry stays until decided.
- The store keeps what was sent in `request`/`response` and the capture in
  `request_original`/`response_original` (only when they differ), plus a `dropped` flag.

## Match-and-replace
`mantis-cli proxy --rules rules.toml`:

```toml
[[rules]]
direction = "request"        # request | response | both
target = "header"            # request_line | header | body | message
header = "User-Agent"        # only with target = "header"; case-insensitive
pattern = "curl"             # literal text, or a regex when regex = true
replace = "Mantis"           # with regex = true, $1 expands
regex = false
# fix_content_length = true  # default on for body/message rules, off otherwise
# enabled = false
```

- Rules apply in file order, each to the output of the previous one. Unknown keys are errors.
- After a body change, `Content-Length` is shifted by the length difference, so a deliberately wrong
  value stays wrong by the same amount.
- Messages with a chunked body are not rewritten by body or message rules (a match could straddle
  chunk framing, and re-encoding would change bytes the rule never named); a warning is logged.
  Header and request-line rules still apply.
- `ProxyHandle::rewriter().set_rules(..)` replaces the rules while the proxy runs; an invalid set is
  rejected and the old rules stay.
- Replacement text comes from TOML, so it is UTF-8; arbitrary bytes need the library API later.

## Known limits
- There are no upstream read timeouts yet: a request the origin never answers keeps its connection.
- Edited requests cannot change where the request goes.
