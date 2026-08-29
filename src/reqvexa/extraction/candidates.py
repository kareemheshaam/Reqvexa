from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from reqvexa.cancellation import AnalysisCancelled
from reqvexa.models import Capture, Cookie, Header, SourceLocation, ValueObservation, stable_id

TOKEN_HEADERS = {"authorization", "x-api-key", "x-auth-token", "x-csrf-token",
                 "x-csrf", "x-access-token", "x-signature"}
SENSITIVE_HINTS = ("token", "secret", "password", "authorization", "cookie", "key", "signature")


@dataclass(frozen=True)
class ExtractionConfig:
    max_body_bytes: int = 1_000_000
    max_json_depth: int = 12
    max_json_nodes: int = 10_000


def extract_observations(capture: Capture,
                         config: ExtractionConfig | None = None,
                         progress_callback: Any | None = None,
                         cancel_event: Any | None = None,
                         observation_callback: Any | None = None,
                         max_sequence: int | None = None) -> tuple[ValueObservation, ...]:
    config = config or ExtractionConfig()
    observations: list[ValueObservation] = []
    responses = {response.id: response for response in capture.responses}
    requests = [
        request for request in capture.requests
        if max_sequence is None or request.sequence <= max_sequence
    ]
    total = len(requests)
    for index, request in enumerate(requests, start=1):
        if cancel_event is not None and cancel_event.is_set():
            raise AnalysisCancelled()
        if progress_callback is not None:
            progress_callback(
                "extract",
                index - 1,
                total,
                f"Scanning request {request.sequence}: {request.method}",
            )
        before_count = len(observations)
        observations.extend(_request_observations(request, config, cancel_event))
        if request.response_id and request.response_id in responses:
            observations.extend(_response_observations(
                request, responses[request.response_id], config, cancel_event
            ))
        if observation_callback is not None:
            observation_callback(
                request.id,
                request.sequence,
                tuple(observations[before_count:]),
            )
        if progress_callback is not None:
            request_observations = observations[before_count:]
            hints = sorted({
                hint for item in request_observations for hint in item.semantic_hints
                if hint
            })
            found = ", ".join(hints[:5]) if hints else "no named state"
            if len(hints) > 5:
                found += ", ..."
            progress_callback("extract", index, total,
                              f"Request {request.sequence}: found {found}")
        if cancel_event is not None and cancel_event.is_set():
            raise AnalysisCancelled()
    merged: dict[str, ValueObservation] = {}
    for observation in observations:
        previous = merged.get(observation.observation_id)
        if previous is None:
            merged[observation.observation_id] = observation
        else:
            merged[observation.observation_id] = ValueObservation(
                observation_id=previous.observation_id,
                location=previous.location,
                raw_value=previous.raw_value,
                normalized_value=previous.normalized_value,
                timestamp=previous.timestamp,
                sequence=previous.sequence,
                semantic_hints=tuple(sorted(set(previous.semantic_hints + observation.semantic_hints))),
                representation_ids=tuple(sorted(set(previous.representation_ids + observation.representation_ids))),
                transformation=previous.transformation or observation.transformation,
            )
    return tuple(sorted(merged.values(), key=lambda item: item.observation_id))


def _request_observations(request: Any, config: ExtractionConfig,
                          cancel_event: Any | None = None) -> list[ValueObservation]:
    result: list[ValueObservation] = []
    header_cookies: set[tuple[str, str]] = set()
    for header in request.headers:
        if cancel_event is not None and cancel_event.is_set():
            raise AnalysisCancelled()
        name = header.name.lower()
        value = header.value
        if name == "cookie":
            for cookie_name, cookie_value in _parse_cookie_header(value):
                header_cookies.add((cookie_name.lower(), cookie_value))
                result.append(_observation(
                    request.id, None, request.sequence, request.timestamp, "request.cookie",
                    f"{cookie_name}@", cookie_value, f"cookie.{cookie_name}", request.id))
        elif (name in TOKEN_HEADERS or name.startswith("x-")
              or "token" in name or "auth" in name or "signature" in name):
            result.extend(_header_value_observations(
                request.id, None, request.sequence, request.timestamp,
                "request.header", name, value, name, request.id
            ))
        else:
            result.append(_observation(
                request.id, None, request.sequence, request.timestamp, "request.header",
                name, value, None, request.id))
    for cookie in request.cookies:
        if (cookie.name.lower(), cookie.value) in header_cookies:
            continue
        result.append(_cookie_observation(cookie, request.id, None, request.sequence, request.timestamp,
                                          "request.cookies"))
    split = urlsplit(request.url)
    for key, value in parse_qsl(split.query, keep_blank_values=True):
        result.append(_observation(request.id, None, request.sequence, request.timestamp,
                                   "request.query", key, value,
                                   key, request.id))
    if request.body:
        result.extend(_body_observations(request.id, None, request.sequence,
                                          request.timestamp, request.body, request.headers, config,
                                          "request.body"))
    for segment in PurePosixPath(split.path).parts:
        if segment not in ("/", "") and len(segment) > 2:
            result.append(_observation(request.id, None, request.sequence, request.timestamp, "request.path",
                                       segment, segment, None, request.id))
    return result


def _response_observations(request: Any, response: Any,
                           config: ExtractionConfig,
                           cancel_event: Any | None = None) -> list[ValueObservation]:
    result: list[ValueObservation] = []
    header_cookies: set[tuple[str, str]] = set()
    for header in response.headers:
        if cancel_event is not None and cancel_event.is_set():
            raise AnalysisCancelled()
        name = header.name.lower()
        if name == "set-cookie":
            cookie = _parse_set_cookie(header.value)
            if cookie:
                header_cookies.add((cookie.name.lower(), cookie.value))
                result.append(_cookie_observation(cookie, request.id, response.id, request.sequence,
                                                  request.timestamp, "response.set_cookie"))
        else:
            result.extend(_header_value_observations(
                request.id, response.id, request.sequence, request.timestamp,
                "response.header", name, header.value, name, request.id
            ))
    for cookie in response.cookies:
        if (cookie.name.lower(), cookie.value) in header_cookies:
            continue
        result.append(_cookie_observation(cookie, request.id, response.id, request.sequence,
                                          request.timestamp,
                                          "response.cookies"))
    if response.body:
        result.extend(_body_observations(
            request.id, response.id, request.sequence, request.timestamp,
            response.body, response.headers, config, "response.body", cancel_event
        ))
        mime = (response.mime_type or "").lower()
        if "html" in mime:
            result.extend(_html_observations(request.id, response.id, request.sequence,
                                             request.timestamp, response.body))
    return result


def _body_observations(request_id: str, response_id: str | None, sequence: int,
                       timestamp: Any, body: bytes, headers: tuple[Header, ...],
                       config: ExtractionConfig, container: str,
                       cancel_event: Any | None = None) -> list[ValueObservation]:
    if cancel_event is not None and cancel_event.is_set():
        raise AnalysisCancelled()
    if len(body) > config.max_body_bytes:
        return []
    text = body.decode("utf-8", errors="replace")
    content_type = _header(headers, "content-type") or ""
    result: list[ValueObservation] = []
    json_candidate = text.lstrip("\ufeff \t\r\n")
    is_xssi_json = json_candidate.startswith(")]}'")
    if "json" in content_type or json_candidate.startswith(("{", "[")) or is_xssi_json:
        parsed = _parse_json_text(text)
        if parsed is not None and response_id is not None:
            result.append(_observation(
                request_id, response_id, sequence, timestamp, container, "$",
                json.dumps(parsed, ensure_ascii=False, separators=(",", ":")),
                "json_document", request_id,
            ))
        result.extend(_json_observations(
            request_id, response_id, timestamp, parsed, container,
            sequence, config=config, cancel_event=cancel_event
        ))
    if "form-urlencoded" in content_type or (
        "=" in text
        and not text.lstrip().startswith(("{", "["))
        and "javascript" not in content_type
        and _looks_like_form_body(text)
    ):
        for key, value in parse_qsl(text, keep_blank_values=True):
            result.append(_observation(request_id, response_id, sequence, timestamp, container,
                                       key, value, key, request_id))
    return result


def _parse_json_text(text: str) -> Any | None:
    """Parse JSON responses that use Google's anti-XSSI preamble."""
    candidate = text.lstrip("\ufeff \t\r\n")
    if candidate.startswith(")]}'"):
        _, separator, candidate = candidate.partition("\n")
        if not separator:
            return None
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def _looks_like_form_body(text: str) -> bool:
    """Reject JavaScript/source blobs before treating text as query pairs."""
    parts = [part for part in text.split("&") if part]
    if not parts:
        return False
    key_pattern = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,80}$")
    return all(
        "=" in part and key_pattern.fullmatch(part.split("=", 1)[0].strip()) is not None
        for part in parts
    )


def _header_value_observations(request_id: str, response_id: str | None,
                               sequence: int, timestamp: Any, container: str,
                               path: str, value: str, semantic_hint: str | None,
                               source_id: str) -> list[ValueObservation]:
    # Keep the wire representation single and let provenance compare Bearer
    # headers with their prefix-stripped equivalent.
    return [_observation(
        request_id, response_id, sequence, timestamp, container,
        path, value, semantic_hint, source_id
    )]


def _json_observations(request_id: str, response_id: str | None, timestamp: Any, value: Any,
                       container: str, sequence: int = 0, depth: int = 0,
                       config: ExtractionConfig | None = None,
                       path: str = "$", cancel_event: Any | None = None) -> list[ValueObservation]:
    config = config or ExtractionConfig()
    if cancel_event is not None and cancel_event.is_set():
        raise AnalysisCancelled()
    if depth > config.max_json_depth:
        return []
    result: list[ValueObservation] = []
    if isinstance(value, dict):
        for key in sorted(value):
            if len(result) >= config.max_json_nodes:
                break
            child_path = f"{path}.{key}"
            child = value[key]
            if isinstance(child, (str, int, float, bool)) or child is None:
                result.append(_observation(request_id, response_id, sequence, timestamp, container, child_path,
                                           "" if child is None else str(child), key, request_id))
            else:
                result.extend(_json_observations(request_id, response_id, timestamp, child, container,
                                                 sequence, depth + 1, config, child_path,
                                                 cancel_event))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if len(result) >= config.max_json_nodes:
                break
            result.extend(_json_observations(request_id, response_id, timestamp, child, container,
                                             sequence, depth + 1, config, f"{path}[{index}]",
                                             cancel_event))
    elif isinstance(value, (str, int, float, bool)) or value is None:
        result.append(_observation(
            request_id, response_id, sequence, timestamp, container, path,
            "" if value is None else str(value), _json_path_leaf(path), request_id
        ))
    return result


def _json_path_leaf(path: str) -> str | None:
    leaf = path.rsplit(".", 1)[-1]
    if leaf.startswith("$["):
        return None
    return leaf.split("[", 1)[0] or None


class _StateHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.items: list[tuple[str, str, str]] = []
        self._hidden_name: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        if tag == "input" and data.get("name") is not None:
            name = data["name"]
            assert name is not None
            self.items.append((name, data.get("value", "") or "", "input"))
        for key, value in attrs:
            if value and key.lower() in {"data-token", "data-csrf", "data-state"}:
                self.items.append((key, value, "attribute"))


def _html_observations(request_id: str, response_id: str, sequence: int, timestamp: Any,
                       body: bytes) -> list[ValueObservation]:
    parser = _StateHTMLParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    return [
        _observation(request_id, response_id, sequence, timestamp, f"response.html.{kind}", name,
                     value, name, request_id)
        for name, value, kind in parser.items
    ]


def _cookie_observation(cookie: Cookie, request_id: str, response_id: str | None, sequence: int,
                        timestamp: Any, container: str) -> ValueObservation:
    scope = "|".join(str(part or "") for part in
                     (cookie.domain, cookie.path, cookie.secure, cookie.host_only,
                      cookie.partition_key))
    observation_id = stable_id("cookie-observation", request_id, response_id, sequence,
                               cookie.identity_scope(), cookie.value)
    representation_id = stable_id("cookie-representation", container, request_id, response_id,
                                  sequence, cookie.identity_scope(), cookie.value)
    normalized, transformation = normalize_value(cookie.value)
    return ValueObservation(
        observation_id=observation_id,
        location=SourceLocation(container, f"{cookie.name}@{scope}", request_id, response_id),
        raw_value=cookie.value,
        normalized_value=normalized,
        semantic_hints=(f"cookie.{cookie.name}",),
        sequence=sequence,
        timestamp=timestamp,
        representation_ids=(representation_id,),
        transformation=transformation,
    )


def _observation(request_id: str, response_id: str | None, sequence: int, timestamp: Any,
                 container: str,
                 path: str, value: str, semantic_hint: str | None,
                 source_id: str) -> ValueObservation:
    normalized, transformation = normalize_value(value)
    return ValueObservation(
        observation_id=stable_id("observation", source_id, container, path, value),
        location=SourceLocation(container, path, request_id, response_id),
        raw_value=value, normalized_value=normalized,
        semantic_hints=(semantic_hint,) if semantic_hint else (),
        sequence=sequence,
        timestamp=timestamp,
        transformation=transformation,
    )


def normalize_value(value: str) -> tuple[str, str | None]:
    transformations: list[str] = []
    normalized = " ".join(value.strip().split())
    if normalized != value:
        transformations.append("WHITESPACE_NORMALIZED")
    decoded = unquote(normalized)
    if decoded != normalized:
        normalized = decoded
        transformations.append("URL_DECODED")
    return normalized, "+".join(transformations) or None


def decode_base64_candidate(value: str) -> str | None:
    if len(value) < 4 or not re.fullmatch(r"[A-Za-z0-9+/_=-]+", value):
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        text = decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return text if text and all(char.isprintable() or char.isspace() for char in text) else None


def _parse_cookie_header(value: str) -> Iterable[tuple[str, str]]:
    for item in value.split(";"):
        if "=" in item:
            name, cookie_value = item.strip().split("=", 1)
            yield name, cookie_value


def _parse_set_cookie(value: str) -> Cookie | None:
    first = value.split(";", 1)[0]
    if "=" not in first:
        return None
    name, cookie_value = first.split("=", 1)
    return Cookie(name.strip(), cookie_value.strip())


def _header(headers: tuple[Header, ...], name: str) -> str | None:
    for header in headers:
        if header.name.lower() == name.lower():
            return header.value
    return None
