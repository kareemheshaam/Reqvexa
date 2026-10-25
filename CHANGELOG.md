# Changelog

All notable changes to Reqvexa are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0a1] - 2026-10-25

### Added

- Python request-flow generation from the Analysis tab. Each planned request
  can be selected or unselected, and the generated `tls_client` code supports
  synchronous and asynchronous execution. Ordered headers, cookies, bodies,
  HTTP/1 settings, and HTTP/2 pseudo-header normalization are included; the
  preview supports copy and `.py` save.
- Standalone single-request generation for exactly one selected request. The
  exported script uses a direct `tls_client` method call, preserves captured
  header order and raw request bodies, and supports synchronous and asynchronous
  output without including the surrounding flow.
- Request-search criteria to limit matching to selected request and response
  areas, including query parameters, post data, headers, and response content.
- Flow generation follows captured response dependencies: response cookies use
  the session cookie jar, response-header values are read from their producer,
  and response-body values are exposed as manual placeholders. Encoding and
  decoding needed to match captured values is included in generated flow code.
- Optional one-level analysis: the GUI "Recursive" switch (on by default)
  turns off the backward expansion through found requests. With it off,
  `ProvenanceEngine.analyze(..., recursive=False)` scopes the capture to
  the target and the first request whose response held each of its values,
  `plan_flow`/`safe_report` (which inherit the analysis depth) include only
  those direct first producers, and traces stop at one level - a long
  session-cookie echo no longer pulls every prior consumer into the plan.
  The Analysis tab labels each result "recursive" or "one level".
- Manual analysis tab: clicking a value in the traffic or analysis
  inspector (header, cookie, query parameter, or a JSON body
  string/number) searches the capture for the first strictly-earlier
  request that holds the exact same literal, ignoring names entirely -
  a cookie value clicked on one request is found anywhere any other
  header, cookie, form field, or body path holds it. The app switches to
  the dedicated Manual tab, where every found request is appended as a
  card to the trace chain (origin first, then one card per hop with the
  masked value and where it was found) and opened in a Manual-tab
  inspector so the next value can be picked from it; the process repeats
  by hand, one hop records per click and nothing is searched recursively
  from the found request. Chain cards open their request on click, the
  chain/inspector panes resize with a slider, and dead ends ("first
  appearance is this request itself") are recorded as muted cards with
  the status line explaining them. The Clear button or a capture reload
  resets the tab. The search parses entries on demand (lazy captures
  stay low-memory): tracing JSESSIONID from request #552 to request #16
  of the reference capture runs instantly, and a full not-found scan of
  all earlier entries takes ~0.2s. Trace values stay masked unless
  "Show sensitive values" is on.
- Optional one-level value sweep on the Manual tab: instead of clicking
  values one by one, pressing "Sweep values" searches the first earlier
  appearance of every traceable value on the open or traffic-selected
  request in one pass - header, cookie, and query values, urlencoded
  form field values, and JSON body scalars (the same exact-literal,
  name-agnostic search a click runs, with every sweep hit equal to the
  per-value manual search result, verified by test). Still one level
  deep by design: found requests land on the chain but their values are
  never searched automatically, so recursion remains a user decision;
  dead ends are recorded as their own cards. The sweep parses each
  earlier entry once for all remaining values (body texts decode once)
  instead of one pass per value, streams progress into the status line,
  switches to the Manual tab, opens the swept request in its inspector,
  and reports "N values traced, M dead ends, K earlier entries checked".
  On the reference capture it sweeps request #552 (64 values, 62 traced)
  in 0.19s. Clear/capture-reload invalidate an in-flight sweep, repeated
  sweeps deduplicate against hops already on the chain, and values stay
  masked unless "Show sensitive values" is on.
- `reqvexa requests` subcommand that lists request IDs, methods, and redacted
  paths so `--request` values can be discovered from the CLI.
- `--request` selectors: accept a request ID, an entry index (including
  negative indices such as `-1`), or a URL substring; ambiguous substrings
  report the matching IDs.
- Headless GUI automation tests covering the Flet viewer: a fake-page harness
  drives capture loading, request selection, analysis streaming and tabs,
  dialog saves, reveal-switch masking, stop/cancel/error handling, and stale
  job isolation, with the GUI module back under the coverage gate.
- `trace --output FILE`, matching `plan` and `report`.
- `report --format mermaid` renders the request flow as a deterministic
  Mermaid flowchart with target and unresolved styling.
- `--version` CLI flag.
- `--unsafe-raw` flags for `trace` and `requests` for explicit unredacted
  output.
- HAR ingestion now accepts documents with a UTF-8 BOM, describes the reason
  for invalid shapes, and transparently decompresses gzip response bodies
  (base64-encoded or raw magic bytes).
- Coverage tooling: `pytest --cov` with a 90% gate (currently 93% with the GUI
  module included); CI runs tests on Linux and Windows plus a quality
  job for compileall, ruff, mypy, and coverage; tag pushes build sdist/wheel
  artifacts and attach them to the GitHub release.
- Packaging metadata: project URLs, keywords, OS/Topic classifiers.
- Capture-wide value ignoring: `ProvenanceEngine.analyze` accepts
  `ignored_value_names`, which drops whole logical-value buckets whose
  canonical name forms (request keys, `X-*` response headers,
  cookie./CSRF/Bearer aliases) match a checked name, so a value selected
  on one request can no longer reappear under a different name shape
  elsewhere. The Analysis Control dialog lists only fields on the selected
  target request (response values are producers, not target inputs), with
  selections persisting across request switches and prior exclusions shown
  in an "Also excluded" note.
- Analysis Control groups target fields into Cookies, Headers, Payload, and
  Parameters. Checked fields are included in tracing; select-all and
  unselect-all update the persistent selections. The control opens in a dialog
  from either the Analysis tab or the pre-analysis confirmation dialog, which
  also holds the Recursive, Show sensitive values, and Ignore file responses
  options.
- HTTP/2 pseudo-headers are shown separately in request previews and excluded
  from ordinary-header extraction and analysis controls.
- Optional "Ignore file responses" analysis filter excludes static assets and
  downloadable responses from producer matching without removing request-side
  observations.
- New analysis results are focused when complete; request previews in Analysis
  now include value-copy controls. Manual result cards open the full captured
  request/response, and entries without a status code are labeled as unavailable
  instead of misleadingly displaying HTTP 0.
- Lazy HAR loading in the GUI: a file load builds a byte-offset index
  over `log.entries` and keeps only request/response metadata resident
  (methods, URLs, statuses beside the request list); the full content of
  one entry is parsed from the file when it is selected in the traffic or
  analysis-flow list, with a bounded LRU re-parse cache. Provenance
  analysis materializes the whole capture for the run and releases it
  afterwards, including on failure or cancel. Byte offsets are exact with
  BOMs and multi-byte characters; invalid files and source files changed
  mid-session surface as notifications instead of crashes. On the
  557-entry reference capture the idle resident footprint drops from
  ~98 MB to ~28 MB before analysis and the engine finds identical results
  (178 logical values) either way.

### Changed

- GUI body previews no longer truncate: request and response bodies render
  in full text since only one entry is parsed at a time on selection
  (largest reference-capture body ≈498 KB renders fine). Bodies above
  ~500 KB still show complete, but skip JSON syntax highlighting to avoid a
  multi-second pause while coloring hundreds of spans; the note says so.

- `trace` output now redacts the target query string by default, aligning it
  with the safe report privacy contract.
- Analysis-time performance: request lookup, version lookup, response lookup,
  observation request bucketing, and cross-field value matching are now
  indexed; a 1,200-entry capture analyzes roughly 4x faster. Producer
  inference additionally memoizes Bearer-stripping, URL-decoding and
  Base64-candidate checks, precomputes per-request host origins, and scans
  prior responses via sorted sequence bounds with origin bucketing - a
  557-entry capture with 4565 value versions analyzed 3.5x faster with
  bit-identical provenance output.
- Ruff linting extended to import sorting (`I`), pyupgrade (`UP`), bugbear
  (`B`), and RUF rules; mypy moved to `disallow_untyped_defs`.
- Planning performance: `plan_flow` scans each request's observations exactly
  once via a worklist closure, resolves version matches for every observation
  through one precomputed raw/stripped-string version index (a capture where
  one logical value has ~4500 versions stalled for minutes in per-observation
  bucket scans), skips per-flow-version trace walks that re-descended cyclic
  producer chains, and `safe_report` reuses the target trace and pre-indexed
  producer edge methods. On a 557-entry capture (71976 state observations,
  4565 versions, 178 logical values) the full analyze + plan + report path
  runs in ~3.3s instead of hanging indefinitely, with old-vs-new planning
  byte-identical on a shared subset and trace-node collection switched to
  version-id keys to avoid exponential dataclass hashing of shared subtrees.
- Trace nodes are memoized analysis-wide (`trace_version`) so repeated target
  tracing is incremental; verified byte-identical to fresh per-root walks on
  captures where both complete.

### Removed

- Dead code: unreachable cross-field candidate pass in `_infer_producers`,
  unused `_candidate_transformed_sources`, unused `MatchEvidence` model,
  and unused local confidence assignments.

### Fixed

- Clickable inspector values no longer start a text selection instead of
  tracing: selectable text swallows pointer events in Flet, so traceable
  header/cookie/query values and JSON body values render non-selectable
  and clicking them behaves as the trace action. Copying is preserved
  through a small copy-icon button next to every value (and next to the
  "Body" label for whole bodies), which puts the exact raw value on the
  clipboard via the new app copy handler.
- Cancelled analyses no longer silently skip candidate sources during
  producer inference and return degraded partial results instead of raising.
- GUI observation streaming no longer builds a control chain per observation
  when a scope floods: under 1,200 streamed observations rows render as
  before; beyond the cap a single live counter replaces further rows, so a
  71,976-observation capture no longer stalls the UI thread after the final
  extraction tick.

## [0.1.0-alpha] - 2026-08-29

- HAR 1.2 parsing, value extraction, temporal versions, provenance inference,
  CLI (`analyze`, `trace`, `graph`, `plan`, `report`) and Flet GUI.
