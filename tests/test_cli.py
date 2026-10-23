from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from reqvexa.cli import main


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


def write_har(tmp_path: Path, entries: list, *, bom: bool = False) -> Path:
    document = {"log": {"version": "1.2", "creator": {"name": "test"}, "entries": entries}}
    path = tmp_path / "capture.har"
    raw = json.dumps(document).encode("utf-8")
    path.write_bytes(b"\xef\xbb\xbf" + raw if bom else raw)
    return path


def run_cli(argv: list[str], capsys: pytest.CaptureFixture) -> tuple[int, str, str]:
    exit_code = main(argv)
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


# ------------------------------------------------------------------ errors ---


def test_unknown_request_returns_exit_code_2_with_message(tmp_path, capsys):
    capture = write_har(tmp_path, [entry("GET", "https://example.test/")])
    code, out, err = run_cli(["trace", str(capture), "--request", "nop"], capsys)
    assert code == 2
    assert "reqvexa requests" in err
    assert "Traceback" not in err
    assert out == ""


def test_malformed_capture_returns_exit_code_2_with_message(tmp_path, capsys):
    bad = tmp_path / "bad.har"
    bad.write_text('{"log": {"version": "1.2"}}', encoding="utf-8")
    code, _out, err = run_cli(["analyze", str(bad)], capsys)
    assert code == 2
    assert "cannot read HAR capture" in err
    assert "Traceback" not in err


def test_missing_gui_extra_prints_install_hint(capsys, monkeypatch):
    monkeypatch.setitem(sys.modules, "reqvexa.gui", None)
    code, _, err = run_cli(["gui"], capsys)
    assert code == 2
    assert 'install "reqvexa[gui]"' in err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "reqvexa" in capsys.readouterr().out


# --------------------------------------------------------------- discovery ---


def test_requests_command_lists_ids_and_redacts_query(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://reqvexa.local/"),
        entry("GET", "https://reqvexa.local/api/products?token=secret-value"),
    ])
    code, out, err = run_cli(["requests", str(capture)], capsys)
    assert code == 0
    assert "secret-value" not in out
    assert "/api/products" in out
    assert out.splitlines()[0].split()[2].startswith("request_")
    assert "Traceback" not in err


def test_requests_command_json_and_unsafe_raw(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://reqvexa.local/api/products?token=secret-value"),
    ])
    code, json_out, _ = run_cli(["requests", str(capture), "--json"], capsys)
    assert code == 0
    payload = json.loads(json_out)
    assert payload[0]["path"] == "/api/products"
    assert "url" not in payload[0]
    code, raw_out, _ = run_cli(["requests", str(capture), "--json", "--unsafe-raw"], capsys)
    assert code == 0
    assert "?token=secret-value" in raw_out


# ----------------------------------------------------------- trace privacy ---


def test_trace_redacts_query_by_default(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://reqvexa.local/source", response=response(text="{\"token\":\"TICKET-1\"}")),
        entry("GET", "https://reqvexa.local/target?ticket=TICKET-1"),
    ])
    code, out, _ = run_cli(["trace", str(capture), "--request", "/target"], capsys)
    assert code == 0
    assert "?ticket=TICKET-1" not in out
    assert "/target" in out


def test_trace_unsafe_raw_shows_query(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://reqvexa.local/target?ticket=TICKET-1"),
    ])
    code, out, _ = run_cli(
        ["trace", str(capture), "--request", "/target", "--unsafe-raw"], capsys)
    assert code == 0
    assert "?ticket=TICKET-1" in out


def test_trace_writes_output_file(tmp_path, capsys):
    capture = write_har(tmp_path, [entry("GET", "https://reqvexa.local/target")])
    output = tmp_path / "trace.txt"
    code, _, _err = run_cli(
        ["trace", str(capture), "--request", "-1", "--output", str(output)], capsys)
    assert code == 0
    assert output.read_text(encoding="utf-8").startswith("Target:")


# ----------------------------------------------------------- the selectors ---


def test_request_selector_negative_index(tmp_path, capsys):
    entries = [
        entry("GET", "https://reqvexa.local/first"),
        entry("GET", "https://reqvexa.local/third"),
    ]
    capture = write_har(tmp_path, entries)
    code, out, _ = run_cli(["trace", str(capture), "--request", "-1"], capsys)
    assert code == 0
    assert "Target:\nGET /third" in out


def test_request_selector_url_substring(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://reqvexa.local/first"),
        entry("GET", "https://reqvexa.local/products/detail"),
        entry("GET", "https://reqvexa.local/third"),
    ])
    code, out, _ = run_cli(["trace", str(capture), "--request", "products"], capsys)
    assert code == 0
    assert "/products/detail" in out


def test_ambiguous_selector_reports_choices(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://reqvexa.local/api/one"),
        entry("GET", "https://reqvexa.local/api/two"),
    ])
    code, _out, err = run_cli(["trace", str(capture), "--request", "/api"], capsys)
    assert code == 2
    assert "matches 2 requests" in err
    assert "/api/one" in err


def test_out_of_range_index_error(tmp_path, capsys):
    capture = write_har(tmp_path, [entry("GET", "https://reqvexa.local/only")])
    code, _out, err = run_cli(["trace", str(capture), "--request", "5"], capsys)
    assert code == 2
    assert "outside the capture" in err


# ----------------------------------------------------------------- reports ---


def test_report_mermaid_renders_flowchart_with_target(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://reqvexa.local/login", response=response(
            text='{"session_token":"TICKET-1"}')),
        entry("GET", "https://reqvexa.local/products",
              headers=[{"name": "Authorization", "value": "Bearer TICKET-1"}]),
    ])
    code, out, _ = run_cli(
        ["report", str(capture), "--request", "-1", "--format", "mermaid"], capsys)
    assert code == 0
    assert out.startswith("flowchart LR")
    assert "classDef target" in out
    assert "(target)" in out
    assert "authorization" in out
    assert "TICKET-1" not in out  # values never leak into diagram labels


def test_report_mermaid_marks_unresolved(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://reqvexa.local/target",
              headers=[{"name": "X-Signature", "value": "never-seen"}]),
    ])
    code, out, _ = run_cli(
        ["report", str(capture), "--request", "-1", "--format", "mermaid"], capsys)
    assert code == 0
    assert "unresolved" in out
    assert "classDef unresolved" in out


# --------------------------------------------------------------- ingestion ---



def test_raw_text_match_finds_token_in_html_prose(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://reqvexa.local/page",
              response=response(text="<div>state token plain-raw-token end</div>",
                                mime="text/html")),
        entry("GET", "https://reqvexa.local/target",
              headers=[{"name": "X-Token", "value": "plain-raw-token"}]),
    ])
    code, out, _ = run_cli(["trace", str(capture), "--request", "/target"], capsys)
    assert code == 0
    assert "producer: response_" in out  # structured scans miss; raw text hit


def test_graph_command_dumps_graph(tmp_path, capsys):
    capture = write_har(tmp_path, [
        entry("GET", "https://jqvexa.local/a", response=response(text="{\"token\":\"v\"}")),
        entry("GET", "https://jqvexa.local/b", headers=[{"name": "X-Token", "value": "v"}]),
    ])
    code, out, _ = run_cli(["graph", str(capture)], capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["nodes"]
    assert all(node["type"] in {"REQUEST", "RESPONSE", "VALUE", "VALUE_VERSION"}
               for node in payload["nodes"])
    assert all(edge["evidence_ids"] for edge in payload["edges"])
