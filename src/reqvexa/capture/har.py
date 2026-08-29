from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from reqvexa.models import Capture, Cookie, Header, HttpRequest, HttpResponse, stable_id


class HarFormatError(ValueError):
    """Raised when a HAR is structurally invalid."""


class HarProvider:
    """Read HAR 1.2 while preserving raw source fields and header ordering."""

    def load_file(self, path: str | Path) -> Capture:
        return self.load_json(json.loads(Path(path).read_text(encoding="utf-8")))

    def load_json(self, document: dict[str, Any]) -> Capture:
        if document.get("log", {}).get("version") not in (None, "1.2"):
            raise HarFormatError("Only HAR 1.2 is supported")
        entries = document.get("log", {}).get("entries")
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
            initiator=entry.get("_initiator") or entry.get("initiator", {}).get("type")
            if isinstance(entry.get("initiator"), dict) else entry.get("_initiator"),
            response_id=response_id, source_entry_id=entry_id, timing=entry.get("timings") or {},
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
        data = str(text).encode("utf-8")
        if encoding == "base64":
            try:
                data = base64.b64decode(data)
            except binascii.Error:
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
