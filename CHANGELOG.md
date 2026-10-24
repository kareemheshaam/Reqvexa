# Changelog

All notable changes to Reqvexa are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Manual value tracing in the GUI: clicking a value in the traffic or
  analysis inspector (header, cookie, query parameter, or a JSON body
  string/number) searches the capture for the first strictly-earlier
  request that holds the exact same literal, ignoring names entirely -
  a cookie value clicked on one request is found anywhere any other
  header, cookie, form field, or body path holds it. The found request is
  appended to a "Manual trace" strip and opened in the inspector, so the
  next value can be picked from it and the process repeated by hand; one
  hop records per click and nothing is searched recursively from the
  found request. Dead ends ("first appearance is this request itself")
  are reported in place, the strip stays visible between steps, and the
  Clear button or a capture reload resets it. The search parses entries
  on demand (lazy captures stay low-memory): tracing JSESSIONID from
  request #552 to request #16 of the reference capture runs instantly,
  and a full not-found scan of all earlier entries takes ~0.2s. Trace
  values stay masked unless "Show sensitive values" is on.
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
  elsewhere. The GUI ignore panel now also lists the target response's
  header and Set-Cookie names (the raw Set-Cookie header name is skipped,
  parsed cookie names are selectable instead), selections persist across
  request switches, and persisted picks from other requests surface in an
  "Also ignoring (N from other requests)" footer line.
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

- Cancelled analyses no longer silently skip candidate sources during
  producer inference and return degraded partial results instead of raising.
- GUI observation streaming no longer builds a control chain per observation
  when a scope floods: under 1,200 streamed observations rows render as
  before; beyond the cap a single live counter replaces further rows, so a
  71,976-observation capture no longer stalls the UI thread after the final
  extraction tick.

## [0.1.0-alpha] - Initial release

- HAR 1.2 parsing, value extraction, temporal versions, provenance inference,
  CLI (`analyze`, `trace`, `graph`, `plan`, `report`) and Flet GUI.
