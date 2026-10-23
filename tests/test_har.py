from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path

import pytest

from reqvexa.capture import HarFormatError, HarProvider
from reqvexa.provenance import ProvenanceEngine


def entry(method: str, url: str, *, headers=None, response=None):
    request = {
        "method": method, "url": url, "httpVersion": "HTTP/1.1",
        "headers": headers or [], "cookies": [],
    }
    return {"startedDateTime": "2026-08-29T00:00:00Z", "time": 1,
            "timings": {"wait": 1}, "request": request,
            **({"response": response} if response is not None else {})}


def response(status=200, headers=None, text=None, mime="application/json"):
    content = {"size": len(text or ""), "mimeType": mime}
    if text is not None:
        content["text"] = text
    return {"status": status, "headers": headers or [], "cookies": [],
            "content": content}


def write_har(tmp_path: Path, entries: list, *, raw: bytes | None = None,
              bom: bool = False) -> Path:
    if raw is None:
        document = {"log": {"version": "1.2", "creator": {"name": "test"},
                            "entries": entries}}
        raw_bytes = json.dumps(document).encode("utf-8")
    else:
        raw_bytes = raw
    path = tmp_path / "capture.har"
    path.write_bytes(b"\xef\xbb\xbf" + raw_bytes if bom else raw_bytes)
    return path


def test_load_file_accepts_utf8_bom(tmp_path):
    capture = write_har(tmp_path, [
        entry("GET", "https://example.test/"),
    ], bom=True)
    loaded = HarProvider().load_file(capture)
    assert len(loaded.requests) == 1


def test_load_file_rejects_non_object_document(tmp_path):
    path = write_har(tmp_path, [], raw=b"[]")
    with pytest.raises(HarFormatError, match="JSON object"):
        HarProvider().load_file(path)


def test_load_file_rejects_malformed_json(tmp_path):
    path = write_har(tmp_path, [], raw=b"{not json")
    with pytest.raises(HarFormatError, match="not valid UTF-8 JSON"):
        HarProvider().load_file(path)


def test_load_file_rejects_missing_log(tmp_path):
    path = write_har(tmp_path, [], raw=b'{"creator": {}}')
    with pytest.raises(HarFormatError, match="log object"):
        HarProvider().load_file(path)


def test_load_file_rejects_bad_har_version(tmp_path):
    path = write_har(tmp_path, [], raw=b'{"log": {"version": "2.0"}}')
    with pytest.raises(HarFormatError, match=r"HAR 1\.2"):
        HarProvider().load_file(path)


def test_load_json_rejects_missing_entries():
    with pytest.raises(HarFormatError, match=r"log\.entries"):
        HarProvider().load_json({"log": {"version": "1.2"}})


def test_gzip_base64_response_body_is_decoded():
    body = json.dumps({"token": "gz-token"}).encode("utf-8")
    document = {"log": {"version": "1.2", "entries": [
        entry("GET", "https://example.test/source", response={
            "status": 200, "headers": [], "cookies": [],
            "content": {
                "mimeType": "application/json",
                "encoding": "base64",
                "text": base64.b64encode(gzip.compress(body)).decode(),
            },
        }),
        entry("GET", "https://example.test/target",
              headers=[{"name": "X-Token", "value": "gz-token"}]),
    ]}}
    capture = HarProvider().load_json(document)
    analysis = ProvenanceEngine().analyze(
        capture, target_request_id=capture.requests[1].id
    )
    producers = [
        hypothesis
        for version in analysis.versions.values()
        if version.raw_value == "gz-token"
        for hypothesis in analysis.target_producers.get(version.version_id, ())
    ]
    assert producers


def test_gzip_magic_bytes_are_detected_without_base64():
    compressed = gzip.compress(b'{"token":"raw-gz"}')
    decoded = HarProvider._decode_content(compressed, None)
    assert decoded is not None and decoded.startswith(b'{"token"')


def test_invalid_base64_returned_as_is():
    decoded = HarProvider._decode_content("not-base64!!!", "base64")
    assert decoded == b"not-base64!!!"
