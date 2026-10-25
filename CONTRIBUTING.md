# Contributing

Thanks for improving Reqvexa. This project analyzes captures that contain
private data, so keep real captures and generated reports out of commits.
Use the synthetic fixtures under `fixtures/` for tests and examples.

## Setup

```text
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
python -m pip install -e ".[dev,gui]"
```

## Before you commit

Every change must pass:

```text
python -m pytest -q             # tests (uses the local source tree)
python -m pytest --cov          # same, with the 90% coverage gate
python -m compileall -q src tests
python -m ruff check src tests
python -m mypy src
```

The deterministic benchmark is a regression gate for provenance accuracy:

```text
python -c "from tests.benchmark.runner import run_benchmark; print(run_benchmark())"
```

It must stay at 16/16 with `trace_accuracy` at 1.0. New provenance features
should come with a new benchmark case in `tests/benchmark/cases/__init__.py`.

## Design rules

- Determinism first: same capture, same output. No wall-clock, no random
  ordering; sort before rendering anything.
- Observations are facts, hypotheses are not. Never upgrade a `CANDIDATE`
  inference to `SUPPORTED` without exact-value evidence.
- Mask by default. Raw values only appear when the user passes an explicit
  `--unsafe-raw` style flag. Query strings are redacted from human output.
- No network I/O. The analysis must remain read-only over the capture.

## Style

- Ruff config lives in `pyproject.toml` (`pytest` pythonpath, ruff, mypy,
  pytest-cov). Line length is 100.
- Public API additions require type hints and an export from
  `reqvexa/__init__.py` when part of the Python API.
- Commits follow Conventional Commits-ish prefixes observed in history:
  `add ...`, `fix ...`, `docs: ...`.

## Releasing

Update `CHANGELOG.md`, the project version in `pyproject.toml`, and the README
version badge in the release commit. Tag the matching PEP 440 version with a
`v` prefix (for example, `v0.2.0a1` for an alpha). The `release.yml` workflow
builds the sdist and wheel and attaches them to the matching GitHub release.
