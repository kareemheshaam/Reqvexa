from __future__ import annotations

import base64
import binascii
import gzip
import json
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from reqvexa.models import Capture, Cookie, Header, HttpRequest, HttpResponse, stable_id

UTF8_BOM = b"\xef\xbb\xbf"
GZIP_MAGIC = b"\x1f\x8b"


class HarFormatError(ValueError):
    """Raised when a HAR is structurally invalid."""


class HarProvider:
    """Read HAR 1.2 while preserving raw source fields and header ordering."""

    def load_file(self, path: str | Path, lazy: bool = False) -> Capture:
        """Load a HAR capture.

        With ``lazy=True`` only request/response metadata is kept resident; a
        byte-offset index re-parses each entry's full content from the file
        on demand instead of holding it in memory.
        """
        data = Path(path).read_bytes()
        byte_base = 0
        if data.startswith(UTF8_BOM):
            data = data[len(UTF8_BOM):]
            byte_base = len(UTF8_BOM)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise HarFormatError(f"Capture is not valid UTF-8 JSON: {error}") from error
        if not lazy:
            try:
                document = json.loads(text)
            except json.JSONDecodeError as error:
                raise HarFormatError(f"Capture is not valid UTF-8 JSON: {error}") from error
            return self.load_json(document)
        return self._build_lazy_capture(Path(path), text, byte_base)

    def load_json(self, document: dict[str, Any]) -> Capture:
        if not isinstance(document, dict):
            raise HarFormatError("HAR document must be a JSON object")
        log_value = document.get("log")
        if not isinstance(log_value, dict):
            raise HarFormatError("HAR document must contain a log object")
        if log_value.get("version") not in (None, "1.2"):
            found = log_value.get("version")
            raise HarFormatError(f"Only HAR 1.2 is supported (found version={found!r})")
        entries = log_value.get("entries")
        if not isinstance(entries, list):
            raise HarFormatError("HAR log.entries must be a list")

        requests: list[HttpRequest] = []
        responses: list[HttpResponse] = []
        for sequence, entry in enumerate(entries):
            if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
                raise HarFormatError(f"Entry {sequence} has no request object")
            request_raw: dict[str, Any] = entry["request"]
            response_value = entry.get("response")
            response_raw: dict[str, Any] | None = (
                response_value if isinstance(response_value, dict) else None
            )
            entry_id = stable_id("entry", sequence, request_raw.get("method"), request_raw.get("url"))
            request_id = stable_id("request", entry_id)
            response_id = stable_id("response", entry_id) if response_raw is not None else None
            requests.append(self._request(request_raw, entry, sequence, entry_id, response_id))
            if response_raw is not None:
                assert response_id is not None
                responses.append(self._response(response_raw, entry, request_id, entry_id, response_id))
        return Capture(tuple(requests), tuple(responses))

    def _request(self, raw: dict[str, Any], entry: dict[str, Any], sequence: int,
                 entry_id: str, response_id: str | None) -> HttpRequest:
        url = str(raw.get("url", ""))
        headers = tuple(Header(str(h.get("name", "")), str(h.get("value", "")), i)
                        for i, h in enumerate(raw.get("headers") or []) if isinstance(h, dict))
        cookies = tuple(self._cookie(c) for c in raw.get("cookies") or [] if isinstance(c, dict))
        post_data_value = raw.get("postData")
        post_data: dict[str, Any] = (
            post_data_value if isinstance(post_data_value, dict) else {}
        )
        body = self._decode_content(post_data.get("text"), post_data.get("encoding"))
        timestamp = self._timestamp(entry.get("startedDateTime"))
        return HttpRequest(
            id=stable_id("request", entry_id), sequence=sequence, timestamp=timestamp,
            method=str(raw.get("method", "")), url=url,
            query=tuple((str(k), str(v)) for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)),
            headers=headers, cookies=cookies, body=body, body_encoding=post_data.get("encoding"),
            initiator=self._initiator(entry), response_id=response_id,
            source_entry_id=entry_id, timing=entry.get("timings") or {},
            raw=raw,
        )

    def _response(self, raw: dict[str, Any], entry: dict[str, Any], request_id: str,
                  entry_id: str, response_id: str) -> HttpResponse:
        headers = tuple(Header(str(h.get("name", "")), str(h.get("value", "")), i)
                        for i, h in enumerate(raw.get("headers") or []) if isinstance(h, dict))
        cookies = tuple(self._cookie(c) for c in raw.get("cookies") or [] if isinstance(c, dict))
        content_value = raw.get("content")
        content: dict[str, Any] = content_value if isinstance(content_value, dict) else {}
        body = self._decode_content(content.get("text"), content.get("encoding"))
        mime = content.get("mimeType") or self._header(headers, "content-type")
        return HttpResponse(
            id=response_id, request_id=request_id, status=int(raw.get("status", 0)),
            headers=headers, cookies=cookies, body=body, mime_type=mime,
            timing=entry.get("timings") or {}, source_entry_id=entry_id, raw=raw,
        )

    @staticmethod
    def _initiator(entry: dict[str, Any]) -> str | None:
        initiator = entry.get("_initiator")
        if initiator is None:
            field_value = entry.get("initiator")
            if isinstance(field_value, dict):
                initiator = field_value.get("type")
        return str(initiator) if initiator is not None else None

    @staticmethod
    def _timestamp(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value))
        except ValueError:
            return None

    @staticmethod
    def _header(headers: tuple[Header, ...], name: str) -> str | None:
        for header in headers:
            if header.name.lower() == name.lower():
                return header.value
        return None

    @staticmethod
    def _decode_content(text: Any, encoding: Any) -> bytes | None:
        if text is None:
            return None
        if isinstance(text, bytes):
            data = text
        else:
            data = str(text).encode("utf-8")
        if encoding == "base64":
            try:
                data = base64.b64decode(data)
            except (binascii.Error, ValueError):
                return data
        if data.startswith(GZIP_MAGIC):
            try:
                data = gzip.decompress(data)
            except (OSError, EOFError):
                return data
        return data

    @staticmethod
    def _cookie(raw: dict[str, Any]) -> Cookie:
        return Cookie(
            name=str(raw.get("name", "")),
            value=str(raw.get("value", "")),
            domain=raw.get("domain"),
            path=raw.get("path"),
            secure=raw.get("secure"),
            host_only=raw.get("hostOnly"),
            partition_key=raw.get("partitionKey"),
        )

    def _build_lazy_capture(self, path: Path, text: str, byte_base: int) -> Capture:
        """Index a HAR file without keeping entry content resident.

        Locates the top-level ``log.entries`` array, parses each entry once
        to extract request/response metadata plus its byte range, then
        discards the parsed document. Re-parsing later goes straight to the
        recorded byte range, so resident memory holds only metadata.
        """
        decoder = json.JSONDecoder()
        entries_pos, marker = self._locate_entries_marker(text)
        version_pos = text.find('"version"', 0, entries_pos)
        if version_pos != -1:
            colon = text.find(":", version_pos + len('"version"'))
            if colon != -1:
                version = self._peek_json_value(decoder, text, colon + 1)
                if version is not None and version != "1.2":
                    raise HarFormatError(
                        f"Only HAR 1.2 is supported (found version={version!r})"
                    )

        scan = entries_pos + len(marker) + 1
        scan = _skip_blank(text, scan)
        if scan >= len(text) or text[scan] != "[":
            raise HarFormatError("HAR log.entries must be a list")
        scan = _skip_blank(text, scan + 1)

        metas: list[_EntryMeta] = []
        proxy_requests: list[HttpRequest] = []
        proxy_responses: list[HttpResponse] = []
        # Byte position of the FIRST entry: everything before it (the log
        # header) is on disk too, and may contain multi-byte characters.
        byte_cursor = byte_base + len(text[:scan].encode("utf-8"))
        sequence = 0
        while True:
            scan = _skip_blank(text, scan)
            if scan >= len(text) or text[scan] == "]":
                break
            if text[scan] != "{":
                raise HarFormatError(
                    f"Capture has invalid entry structure at char offset {scan}"
                )
            try:
                entry, end = decoder.raw_decode(text, scan)
            except json.JSONDecodeError as error:
                raise HarFormatError(
                    f"Capture is not valid UTF-8 JSON: {error}"
                ) from error
            if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
                raise HarFormatError(f"Entry {sequence} has no request object")
            request_raw: dict[str, Any] = entry["request"]
            response_value = entry.get("response")
            response_raw: dict[str, Any] | None = (
                response_value if isinstance(response_value, dict) else None
            )
            method = str(request_raw.get("method", ""))
            url = str(request_raw.get("url", ""))
            entry_id = stable_id("entry", sequence, method, url)
            request_id = stable_id("request", entry_id)
            response_id = (
                stable_id("response", entry_id) if response_raw is not None else None
            )
            timestamp = self._timestamp(entry.get("startedDateTime"))
            timings = entry.get("timings") or {}
            mime: str | None = None
            status: int | None = None
            if response_raw is not None:
                status = int(response_raw.get("status", 0))
                content_value = response_raw.get("content")
                content = content_value if isinstance(content_value, dict) else {}
                response_headers = tuple(
                    Header(str(item.get("name", "")), str(item.get("value", "")), index)
                    for index, item in enumerate(response_raw.get("headers") or [])
                    if isinstance(item, dict)
                )
                mime = content.get("mimeType") or self._header(response_headers, "content-type")
            byte_end = byte_cursor + len(text[scan:end].encode("utf-8"))
            metas.append(_EntryMeta(
                sequence=sequence, byte_start=byte_cursor, byte_end=byte_end,
                entry_id=entry_id, request_id=request_id, response_id=response_id,
                method=method, url=url, timestamp=timestamp, timings=timings,
                status=status, mime=mime,
            ))
            proxy_requests.append(HttpRequest(
                id=request_id, sequence=sequence, timestamp=timestamp,
                method=method, url=url,
                query=tuple((str(key), str(value)) for key, value
                            in parse_qsl(urlsplit(url).query, keep_blank_values=True)),
                headers=(), cookies=(), body=None, body_encoding=None,
                initiator=None, response_id=response_id,
                source_entry_id=entry_id, timing=timings, raw={},
            ))
            if response_raw is not None and response_id is not None:
                proxy_responses.append(HttpResponse(
                    id=response_id, request_id=request_id,
                    status=int(status or 0), headers=(), cookies=(), body=None,
                    mime_type=mime, timing=timings, source_entry_id=entry_id, raw={},
                ))
            byte_cursor = byte_end
            sequence += 1
            next_scan = _skip_comma_blank(text, end)
            # Separator bytes (commas, whitespace) belong to the file too;
            # without them the next entry's offset drifts.
            byte_cursor += len(text[end:next_scan].encode("utf-8"))
            scan = next_scan

        metas_tuple = tuple(metas)
        store = LazyEntryStore(
            path, self, metas_tuple,
            (tuple(proxy_requests), tuple(proxy_responses)),
        )
        return Capture(
            tuple(proxy_requests), tuple(proxy_responses), entry_store=store
        )

    @staticmethod
    def _locate_entries_marker(text: str) -> tuple[int, str]:
        marker = '"entries"'
        position = text.find(marker)
        while position != -1:
            escaped_before = position > 0 and text[position - 1] == "\\"
            has_colon = (
                position + len(marker) < len(text) and text[position + len(marker)] == ":"
            )
            if not escaped_before and has_colon:
                return position, marker
            position = text.find(marker, position + 1)
        raise HarFormatError("HAR log.entries must be a list")

    def _peek_json_value(self, decoder: json.JSONDecoder, text: str,
                         start: int) -> Any:
        try:
            value, _ = decoder.raw_decode(text, _skip_blank(text, start))
        except (json.JSONDecodeError, ValueError) as error:
            raise HarFormatError(
                f"Capture is not valid UTF-8 JSON: {error}"
            ) from error
        return value


def _skip_blank(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t\r\n":
        index += 1
    return index


def _skip_comma_blank(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t\r\n,":
        index += 1
    return index


@dataclass(frozen=True)
class _EntryMeta:
    """Resident per-entry header info; content stays on disk."""

    sequence: int
    byte_start: int
    byte_end: int
    entry_id: str
    request_id: str
    response_id: str | None
    method: str
    url: str
    timestamp: datetime | None
    timings: dict[str, Any]
    status: int | None
    mime: str | None


class LazyEntryStore:
    """Byte-offset index over a HAR file; parses one entry on demand.

    Resident memory holds per-entry metadata and metadata-only proxies, so
    request/response content (headers, cookies, bodies) stays on disk until
    a specific entry is inspected. A small LRU cache bounds re-parses.
    """

    CACHE_LIMIT = 12

    def __init__(self, path: Path, provider: HarProvider,
                 metas: tuple[_EntryMeta, ...],
                 proxies: tuple[tuple[HttpRequest, ...],
                                tuple[HttpResponse, ...]]) -> None:
        self.path = Path(path)
        self._provider = provider
        self._metas = metas
        self._proxy_requests, self._proxy_responses = proxies
        self._meta_by_request_id = {meta.request_id: meta for meta in metas}
        self._cache: OrderedDict[int, tuple[HttpRequest, HttpResponse | None]] = (
            OrderedDict()
        )
        self._lock = threading.Lock()
        self.materialized = False

    @property
    def proxies(self) -> tuple[tuple[HttpRequest, ...],
                               tuple[HttpResponse, ...]]:
        """Metadata-only request/response proxies installed on the capture."""
        return (self._proxy_requests, self._proxy_responses)

    def view(self, request_id: str) -> tuple[HttpRequest, HttpResponse | None]:
        """Full request/response for one entry, parsed from the file."""
        meta = self._meta_by_request_id.get(request_id)
        if meta is None:
            raise KeyError(f"Unknown request: {request_id}")
        with self._lock:
            cached = self._cache.get(meta.sequence)
            if cached is not None:
                self._cache.move_to_end(meta.sequence)
                return cached
        parsed = self._parse(meta)
        with self._lock:
            self._cache[meta.sequence] = parsed
            while len(self._cache) > self.CACHE_LIMIT:
                self._cache.popitem(last=False)
        return parsed

    def materialize_capture(self) -> tuple[list[HttpRequest], list[HttpResponse]]:
        """Parse every entry in capture order (provenance analysis path)."""
        requests: list[HttpRequest] = []
        responses: list[HttpResponse] = []
        for meta in self._metas:
            request, response = self._parse(meta)
            requests.append(request)
            if response is not None:
                responses.append(response)
        return requests, responses

    def _parse(self, meta: _EntryMeta) -> tuple[HttpRequest, HttpResponse | None]:
        try:
            with self.path.open("rb") as handle:
                handle.seek(meta.byte_start)
                chunk = handle.read(meta.byte_end - meta.byte_start)
            entry = json.loads(chunk.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise HarFormatError(
                f"Capture is not valid UTF-8 JSON: {error}"
            ) from error
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            raise HarFormatError(f"Entry {meta.sequence} has no request object")
        request_raw: dict[str, Any] = entry["request"]
        response_value = entry.get("response")
        response_raw: dict[str, Any] | None = (
            response_value if isinstance(response_value, dict) else None
        )
        request = self._provider._request(
            request_raw, entry, meta.sequence, meta.entry_id, meta.response_id
        )
        if request.id != meta.request_id:
            raise HarFormatError(f"Entry {meta.sequence} changed since load")
        if response_raw is None or meta.response_id is None:
            return request, None
        response = self._provider._response(
            response_raw, entry, meta.request_id, meta.entry_id, meta.response_id
        )
        if response.id != meta.response_id or response.status != meta.status:
            raise HarFormatError(f"Entry {meta.sequence} changed since load")
        return request, response
