# Changelog

All notable changes to Reqvexa are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

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

### Changed

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

### Removed

- Dead code: unreachable cross-field candidate pass in `_infer_producers`,
  unused `_candidate_transformed_sources`, unused `MatchEvidence` model,
  and unused local confidence assignments.

### Fixed

- Cancelled analyses no longer silently skip candidate sources during
  producer inference and return degraded partial results instead of raising.

## [0.1.0-alpha] - Initial release

- HAR 1.2 parsing, value extraction, temporal versions, provenance inference,
  CLI (`analyze`, `trace`, `graph`, `plan`, `report`) and Flet GUI.
