from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from reqvexa.capture import HarProvider
from reqvexa.models import Capture


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    capture: Capture
    target_request_id: str
    expected_logical_values: frozenset[str]
    expected_versions: frozenset[str]
    expected_supported_producers: frozenset[str]
    expected_unsupported_producers: frozenset[str]
    expected_roots: frozenset[str]
    expected_unresolved: frozenset[str]


def _entry(method: str, url: str, *, headers=None, response=None, body=None,
           mime="application/json", cookies=None, response_cookies=None, started=None):
    request: dict[str, Any] = {
        "method": method, "url": url, "headers": headers or [], "cookies": cookies or [],
    }
    if body is not None:
        request["postData"] = {"mimeType": mime, "text": body}
    value: dict[str, Any] = {
        "status": 200, "headers": [], "cookies": response_cookies or [],
        "content": {"mimeType": mime},
    }
    if response is not None:
        value["content"]["text"] = response
    return {
        "startedDateTime": started or "2026-08-29T00:00:00Z",
        "time": 1, "timings": {"wait": 1}, "request": request, "response": value,
    }


def _case(case_id: str, entries: list[dict[str, Any]], target_sequence: int,
          values: set[str], versions: set[str], supported: set[str] | None = None,
          unsupported: set[str] | None = None, roots: set[str] | None = None,
          unresolved: set[str] | None = None) -> BenchmarkCase:
    capture = HarProvider().load_json({"log": {"version": "1.2", "entries": entries}})
    return BenchmarkCase(
        case_id, capture, capture.requests[target_sequence].id, frozenset(values),
        frozenset(versions), frozenset(supported or ()), frozenset(unsupported or ()),
        frozenset(roots or ()), frozenset(unresolved or ()),
    )


def all_cases() -> tuple[BenchmarkCase, ...]:
    encoded = base64.b64encode(b"plain-token").decode()
    return (
        _case("duplicate-set-cookie", [
            _entry("GET", "https://t.test/start", response="", response_cookies=[{"name": "session", "value": "A"}]),
            _entry("GET", "https://t.test/target", headers=[{"name": "Cookie", "value": "session=A"}]),
        ], 1, {"cookie.session"}, {"A"}, {"cookie.session:A"}),
        _case("unrelated-token-response", [
            _entry("GET", "https://t.test/unrelated", response='{"token":"A"}'),
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Other", "value": "B"}]),
        ], 1, {"other"}, {"B"}, unresolved={"B"}),
        _case("transformed-token", [
            _entry("GET", "https://t.test/source", response=json.dumps({"token": encoded})),
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Token", "value": "plain-token"}]),
        ], 1, {"token"}, {"plain-token"}, unsupported={"token:plain-token"},
               unresolved={"plain-token"}),
        _case("mutation-reversion", [
            _entry("GET", "https://t.test/a", response="", response_cookies=[{"name": "s", "value": "A"}]),
            _entry("GET", "https://t.test/b", headers=[{"name": "Cookie", "value": "s=A"}]),
            _entry("GET", "https://t.test/c", response="", response_cookies=[{"name": "s", "value": "B"}]),
            _entry("GET", "https://t.test/d", headers=[{"name": "Cookie", "value": "s=A"}]),
        ], 3, {"cookie.s"}, {"A"}, unresolved=set()),
        _case("multiple-producers", [
            _entry("GET", "https://t.test/a", response='{"token":"A"}'),
            _entry("GET", "https://t.test/b", response='{"token":"A"}'),
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Token", "value": "A"}]),
        ], 2, {"token"}, {"A"}, {"token:A"}),
        _case("delayed-producer", [
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Token", "value": "A"}]),
            _entry("GET", "https://t.test/source", response='{"token":"A"}'),
        ], 0, {"token"}, {"A"}, unresolved={"A"}),
        _case("unconsumed-response", [
            _entry("GET", "https://t.test/source", response='{"unused":"A"}'),
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Token", "value": "B"}]),
        ], 1, {"token"}, {"B"}, unresolved={"B"}),
        _case("outside-capture-producer", [
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Token", "value": "external"}]),
        ], 0, {"token"}, {"external"}, roots={"UNKNOWN"}, unresolved={"external"}),
        _case("semantic-name-collision", [
            _entry("GET", "https://t.test/source", response='{"id":"123"}'),
            _entry("POST", "https://t.test/target", body='{"product_id":"123"}'),
        ], 1, {"product_id"}, {"123"}, unsupported={"product_id:123"}, unresolved={"123"}),
        _case("identical-value-different-state", [
            _entry("GET", "https://a.test/source", response='{"token":"same"}'),
            _entry("GET", "https://b.test/target", headers=[{"name": "X-Token", "value": "same"}]),
        ], 1, {"token"}, {"same"}, unresolved={"same"}),
        _case("same-logical-transformation", [
            _entry("GET", "https://t.test/source", response=json.dumps({"csrf": "A%2B"})),
            _entry("GET", "https://t.test/target", headers=[{"name": "X-CSRF", "value": "A+"}]),
        ], 1, {"csrf"}, {"A+"}, unsupported={"csrf:A+"}),
        _case("analytics-noise", [
            _entry("GET", "https://t.test/session", response="", response_cookies=[{"name": "s", "value": "A"}]),
            _entry("POST", "https://t.test/analytics", body='{"event":"view"}'),
            _entry("GET", "https://t.test/target", headers=[{"name": "Cookie", "value": "s=A"}]),
        ], 2, {"cookie.s"}, {"A"}, {"cookie.s:A"}),
        _case("static-noise", [
            _entry("GET", "https://t.test/app.js", response="const x=1", mime="application/javascript"),
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Token", "value": "A"}]),
        ], 1, {"token"}, {"A"}, unresolved={"A"}),
        _case("redirect-chain", [
            _entry("GET", "https://t.test/start", response=""),
            _entry("GET", "https://t.test/login", response='{"token":"A"}'),
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Token", "value": "A"}]),
        ], 2, {"token"}, {"A"}, {"token:A"}),
        _case("parallel-timestamp-order", [
            _entry("GET", "https://t.test/one", response='{"token":"A"}'),
            _entry("GET", "https://t.test/two", response='{"token":"B"}'),
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Token", "value": "B"}]),
        ], 2, {"token"}, {"B"}, {"token:B"}),
        _case("ambiguous-producer", [
            _entry("GET", "https://t.test/one", response='{"token":"A"}'),
            _entry("GET", "https://t.test/two", response='{"token":"A"}'),
            _entry("GET", "https://t.test/three", response='{"token":"A"}'),
            _entry("GET", "https://t.test/target", headers=[{"name": "X-Token", "value": "A"}]),
        ], 3, {"token"}, {"A"}, {"token:A"}),
    )
