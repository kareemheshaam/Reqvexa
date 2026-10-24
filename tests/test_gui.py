"""Headless tests for the Flet GUI.

Flet 0.28 ships no testing module, so the app is driven against a minimal
fake page: real event handlers run, control trees carry the assertions, and
``_poll_events`` runs as a cancellable task so worker-thread events are
processed exactly like in production.

Everything here is deterministic: workers are real threads, events go
through the production queue, and no timers or sleeps gate the assertions
beyond the polling drain helper.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import flet as ft
import pytest

from reqvexa.gui import (
    AMBER,
    DEFAULT_IGNORED_HINTS,
    RED,
    ReqvexaApp,
    _badge,
    _body_view,
    _header_value,
    _json_keys,
    _json_spans,
    _method_color,
    _observation_name,
    _request_hints,
    _safe_path,
    _status_color,
    _ui_path,
)

TOKEN = "tok-0123456789abcdef"  # display-masks to "tok-" + 16 asterisks


# ------------------------------------------------------------ harness ---


class FakePage:
    """Implements the page surface ReqvexaApp relies on."""

    def __init__(self) -> None:
        self.controls: list[ft.Control] = []
        self.dialog: ft.AlertDialog | None = None
        self.update_count = 0
        self.handler: Callable[..., Any] | None = None
        self.tasks: list[Any] = []  # one created-but-unstarted coroutine
        for attribute in ("bgcolor", "padding", "theme", "dark_theme",
                          "theme_mode", "window_min_width", "window_min_height"):
            setattr(self, attribute, None)

    def add(self, *controls: ft.Control) -> None:
        self.controls.extend(controls)

    def update(self) -> None:
        self.update_count += 1

    def run_task(self, handler: Callable[..., Any], *args: Any) -> None:
        """Record refresh scheduling without starting the event loop."""
        self.handler = handler
        self.tasks.append(handler(*args))


@pytest.fixture
def page() -> Iterator[FakePage]:
    fake = FakePage()
    yield fake
    for task in fake.tasks:
        with contextlib.suppress(RuntimeError, AttributeError):
            task.close()
    fake.tasks.clear()


@pytest.fixture
def app(page: FakePage) -> ReqvexaApp:
    return ReqvexaApp(page, capture_path=None, request_id=None)


def walk(control: Any) -> Iterator[Any]:
    """Depth-first walk of a Flet control tree."""
    if control is None:
        return
    yield control
    for attribute in ("controls", "tabs", "actions"):
        for child in getattr(control, attribute, None) or []:
            yield from walk(child)
    for attribute in ("content", "title", "subtitle", "leading", "trailing"):
        yield from walk(getattr(control, attribute, None))


def texts(control: Any) -> list[str]:
    holder: list[str] = []
    for node in walk(control):
        if isinstance(node, ft.Text) and isinstance(node.value, str):
            holder.append(node.value)
    return holder


def has_text(control: Any, needle: str) -> bool:
    return any(needle in value for value in texts(control))


def wait_for(app: ReqvexaApp, condition: Callable[[], bool], timeout: float = 10.0) -> None:
    """Run _poll_events as a task until the condition holds, then cancel it."""

    async def runner() -> None:
        task = asyncio.ensure_future(app.page.handler())
        try:
            async with asyncio.timeout(timeout):
                while not condition():
                    await asyncio.sleep(0.01)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    asyncio.run(runner())


def run_poll(app: ReqvexaApp, seconds: float = 0.25) -> None:
    """Let _poll_events run for a bounded interval without a goal condition."""

    async def runner() -> None:
        task = asyncio.ensure_future(app.page.handler())
        try:
            await asyncio.sleep(seconds)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    asyncio.run(runner())


# ------------------------------------------------------------ builders ---


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


def har(entries):
    return {"log": {"version": "1.2", "creator": {"name": "test"}, "entries": entries}}


def write_har(tmp_path: Path, entries) -> str:
    path = tmp_path / "capture.har"
    path.write_text(json.dumps(har(entries)), encoding="utf-8")
    return str(path)


def standard_entries() -> list:
    """Login sets a cookie, products consumes it, /dead has no response."""
    return [
        entry("GET", "https://example.test/login", headers=[
            {"name": "User-Agent", "value": "reqvexa-tests"},
        ], response=response(
            headers=[{"name": "Set-Cookie", "value": f"session={TOKEN}"}],
            text='{"csrf":"' + TOKEN + '"}',
        )),
        entry("GET", "https://example.test/api/products", headers=[
            {"name": "Cookie", "value": f"session={TOKEN}"},
        ], response=response(status=200, text="[]")),
        entry("GET", "https://other-site.org/dead",
              headers=[{"name": "X-Signature", "value": TOKEN}]),
    ]


def load_capture(app: ReqvexaApp, path: str) -> None:
    app.path_field.value = path
    app._load_capture()
    wait_for(app, lambda: app.status_text.value == "Capture loaded")


def run_analysis(app: ReqvexaApp) -> None:
    app._analyze()
    wait_for(app, lambda: app.latest_analysis_tab_index is not None)


# ---------------------------------------------------- helper unit tests ---


def test_ui_path_redacts_query_and_masks_long_segments():
    url = "https://example.test/a/b?token=secret-value"
    assert _ui_path(url) == "/a/b"
    assert _ui_path(url, unsafe_raw=True) == "/a/b"  # query stays hidden
    long_segment = "x" * 60
    assert _safe_path(f"https://example.test/{long_segment}") == "/<redacted>"


def test_method_color_changes_for_known_and_unknown_methods():
    assert _method_color("GET") != _method_color("POST")
    assert _method_color("DELETE") == _method_color("delete")
    assert all(_method_color(name) for name in ("GET", "PUT", "PATCH", "TRACE"))


def test_status_color_bins_ok_unknown_and_failed():
    assert _status_color("200") == _status_color("SUPPORTED")
    assert _status_color("CANDIDATE") == _status_color("UNKNOWN")
    assert _status_color("500") == RED


def test_badge_renders_label_on_background():
    badge = _badge("SUPPORTED", AMBER)
    assert isinstance(badge, ft.Container)
    assert any(value == "SUPPORTED" for value in texts(badge))


def test_observation_name_prefers_semantic_hint_then_path_leaf():
    hinted = SimpleNamespace(semantic_hints=("cookie.session",), location=SimpleNamespace(path="$"))
    assert _observation_name(hinted) == "session"

    located = SimpleNamespace(semantic_hints=(), location=SimpleNamespace(path="$.csrf_token"))
    assert _observation_name(located) == "csrf_token"

    unnamed = SimpleNamespace(semantic_hints=(), location=SimpleNamespace(path="$"))
    assert _observation_name(unnamed) == "unnamed"


def test_request_hints_collect_headers_cookies_query_and_json_keys():
    request = SimpleNamespace(
        headers=[SimpleNamespace(name="X-Api-Key", value="v")],
        cookies=[SimpleNamespace(name="Session", value="v")],
        query=[("Page", "2")],
        body=b'{"csrf":"1","nested":{"trace_id":"2"},"items":[{"weight":"3"}]}',
    )
    hints = _request_hints(request)  # type: ignore[arg-type]
    assert hints == sorted({
        "x-api-key", "session", "page", "csrf",
        "trace_id", "weight", "items", "nested",
    })


def test_request_hints_ignore_oversized_or_broken_bodies():
    assert _request_hints(SimpleNamespace(  # type: ignore[arg-type]
        headers=(), cookies=(), query=(), body=b'{"csrf":"1" ' + b"x" * 50_001,
    )) == []
    assert "csrf" not in _request_hints(SimpleNamespace(  # type: ignore[arg-type]
        headers=(), cookies=(), query=(), body=b"not json {",
    ))


def test_json_keys_recurses_through_dicts_lists():
    assert _json_keys({"A": {"b": [{"C": 1}]}, "list": [2, {"d": 3}]}) == {"a", "b", "c", "list", "d"}
    assert _json_keys([1, "text", None]) == set()


def test_json_spans_preserve_text_and_color_syntax():
    text = '{"key":[true,42,null,"value"]}'
    spans = _json_spans(text)
    assert "".join(span.text or "" for span in spans) == text
    colors = {span.style.color for span in spans if span.style is not None}
    assert {"#A78BFA", "#67E8F9", "#F59E0B", "#FBBF24"} <= colors


def test_header_value_matches_case_insensitively_or_none():
    headers = [SimpleNamespace(name="Content-Type", value="text/plain")]
    assert _header_value(headers, "content-type") == "text/plain"
    assert _header_value(headers, "Accept") is None


def test_body_view_renders_json_grid_plain_text_and_truncates():
    from reqvexa.gui import MAX_BODY_PREVIEW_CHARS

    rendered = _body_view('{"k":1}', "application/json")
    assert isinstance(rendered, ft.Container)
    assert _body_view('{"k":1', "application/json") is not None  # invalid JSON
    assert isinstance(_body_view("<html>", "text/html"), ft.Text)
    large = _body_view("x" * (MAX_BODY_PREVIEW_CHARS + 1), "application/json")
    assert "truncated" in " ".join(texts(large))


def test_default_ignored_hints_are_transport_metadata_only():
    assert "user-agent" in DEFAULT_IGNORED_HINTS
    assert "sec-fetch-site" in DEFAULT_IGNORED_HINTS
    assert "authorization" not in DEFAULT_IGNORED_HINTS
    assert "cookie" not in DEFAULT_IGNORED_HINTS


# ------------------------------------------------------- app level tests ---


def test_app_builds_expected_initial_layout(app: ReqvexaApp, page: FakePage):
    assert len(page.controls) == 3
    assert [tab.text for tab in app.main_tabs.tabs] == ["Traffic", "Logs", "Analysis"]
    assert app.analysis_tabs.tabs == []
    assert app.request_list.controls == []
    assert app.stop_button.disabled is True
    assert app.progress.visible is False
    assert app.status_text.value == "Ready"
    assert has_text(app.detail_panel, "Select a request to inspect it.")

    event = SimpleNamespace(control=SimpleNamespace(value=45))
    app._resize_vertical_split(event, app.traffic_list_container,
                               app.traffic_detail_container)
    assert app.traffic_list_container.expand == 45
    assert app.traffic_detail_container.expand == 55

    app._refresh_sensitive_views()  # no analysis yet: views stay, no notify
    assert app.status_text.value == "Ready"


def test_load_capture_populates_list_summary_and_candidates(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))

    assert app._summary.value == "3 requests  /  2 responses"
    tiles = app.request_list.controls
    assert [texts(tile)[0] for tile in tiles] == ["GET /login", "GET /api/products", "GET /dead"]
    assert ["#0  200", "#1  200", "#2  -"] == [texts(tile)[1] for tile in tiles]

    selected = [tile for tile in tiles if tile.selected]
    assert len(selected) == 1
    assert texts(selected[0])[0] == "GET /dead"  # default target is the last request

    # The unresponsive target shows its banner instead of a response pane.
    assert has_text(app.detail_panel, "No captured response.")


def test_select_request_moves_target_and_ignore_options(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    products = app.capture.requests[1]

    app._select_request(products.id)
    assert app.target_id == products.id
    assert list(app.ignore_boxes) == ["cookie"]
    checkbox = app.ignore_boxes["cookie"]
    assert isinstance(checkbox, ft.Checkbox)
    assert checkbox.value is False  # cookies are state, never transport noise
    assert has_text(app.detail_panel, "HTTP 200")

    selected = [tile for tile in app.request_list.controls if tile.selected]
    assert len(selected) == 1 and texts(selected[0])[0] == "GET /api/products"


def test_ignore_selections_persist_across_request_switches(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    login = app.capture.requests[0]
    dead = app.capture.requests[2]

    app._select_request(login.id)
    assert app.ignore_boxes["user-agent"].value is True  # transport default
    app.ignore_boxes["user-agent"].value = False
    app._ignore_toggled(None)
    assert app.ignored_names["user-agent"] is False

    app._select_request(dead.id)
    assert list(app.ignore_boxes) == ["x-signature"]
    app.ignore_boxes["x-signature"].value = True
    app._ignore_toggled(None)
    assert app.ignored_names["x-signature"] is True

    app._select_request(login.id)
    assert app.ignore_boxes["user-agent"].value is False  # restored from storage

    merged = app._ignored_selection()
    assert "x-signature" in merged
    assert "user-agent" not in merged


def test_ignore_options_include_response_side_names(app: ReqvexaApp, tmp_path):
    entries = standard_entries()
    login = entries[0]
    assert login["response"] is not None
    login["response"]["headers"].append({"name": "X-Frame-Options", "value": "deny"})
    load_capture(app, write_har(tmp_path, entries))
    app._select_request(app.capture.requests[0].id)
    assert "user-agent" in app.ignore_boxes  # request side, unchanged
    assert "x-frame-options" in app.ignore_boxes  # response side selectable
    assert app.ignore_boxes["x-frame-options"].value is False  # opt-in, not a default
    assert "set-cookie" not in app.ignore_boxes  # zombie name, cookie names instead


def test_loaded_capture_keeps_metadata_only_proxies(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    assert app.capture.is_lazy
    assert app.capture.requests[0].headers == ()  # resident proxies hold none

    app._select_request(app.capture.requests[0].id)
    assert list(app.ignore_boxes) == ["user-agent"]  # full view hints
    assert has_text(app.detail_panel, "User-Agent")  # parsed on demand for view
    assert app.capture.requests[0].headers == ()  # proxies stay metadata-only

    run_analysis(app)
    assert len(app.analysis_tabs.tabs) == 1
    assert app.capture.requests[0].headers == ()  # engine released after analyze


def test_ignore_options_list_persisted_names_from_other_requests(
        app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    app.ignored_names.clear()  # isolate persistence from transport defaults
    app.ignored_names["x-signature"] = True
    app._select_request(app.capture.requests[0].id)
    assert has_text(app.ignore_panel, "Also ignoring (1 from other requests)")
    assert has_text(app.ignore_panel, "x-signature")


def test_search_field_filters_request_list(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    app.search_field.value = "api"
    app._render_request_list()
    assert [texts(tile)[0] for tile in app.request_list.controls] == ["GET /api/products"]

    app.search_field.value = "no-match-here"
    app._render_request_list()
    assert app.request_list.controls == []


def test_capture_load_errors_are_reported_then_recovered(app: ReqvexaApp, tmp_path):
    app.path_field.value = ""
    app._load_capture()
    assert app.status_text.value == "Choose a HAR file first."
    assert app.page.update_count > 0

    app.path_field.value = str(tmp_path / "missing.har")
    app._load_capture()
    wait_for(app, lambda: app.load_button.disabled is False)
    assert "No such file" in app.status_text.value

    app.path_field.value = write_har(tmp_path, standard_entries())
    app._load_capture()
    wait_for(app, lambda: app.status_text.value == "Capture loaded")
    assert app._summary.value == "3 requests  /  2 responses"


def test_analyze_completes_tab_with_plan_and_summary(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    app._select_request(app.capture.requests[1].id)

    assert app.analysis_tabs.tabs == []  # no tab before analysis starts
    run_analysis(app)

    index = app.latest_analysis_tab_index
    tab = app.analysis_tabs.tabs[index]
    assert tab.text == "Analysis 01 - #1"  # ordinal and target sequence
    content = tab.content
    assert has_text(content, "2 requests required for this flow")
    assert has_text(content, "session")  # consumed value is traced
    assert has_text(content, "SUPPORTED")
    assert TOKEN not in texts(content)  # masked mode hides the raw token
    assert app._summary.value == "2 planned steps  /  1 traced values  /  0 unresolved"


def test_reveal_switch_toggles_masked_display_values(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    run_analysis(app)
    tab = app.analysis_tabs.tabs[app.latest_analysis_tab_index]

    assert TOKEN not in texts(tab)
    app.reveal_switch.value = True
    app._refresh_sensitive_views()
    assert TOKEN in texts(app.analysis_tabs.tabs[app.latest_analysis_tab_index])
    assert app.status_text.value == "Sensitive values shown."

    app.reveal_switch.value = False
    app._refresh_sensitive_views()
    assert TOKEN not in texts(app.analysis_tabs.tabs[app.latest_analysis_tab_index])
    assert app.status_text.value == "Sensitive values masked."


def test_show_analysis_request_replaces_flow_placeholder(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    run_analysis(app)
    tab = app.analysis_tabs.tabs[app.latest_analysis_tab_index]

    placeholder = next(
        node for node in walk(tab.content)
        if isinstance(node, ft.Container)
        and getattr(node, "content", None) is not None
        and texts(node.content) == ["Select a flow request to inspect it."]
    )
    app._show_analysis_request(placeholder, app.capture.requests[0].id)
    assert isinstance(placeholder.content, ft.Row)
    assert has_text(placeholder, "Request")


def test_save_without_analysis_prompts_instead_of_dialog(app: ReqvexaApp):
    app._save_json()
    assert app.page.dialog is None
    assert app.status_text.value == "Analyze a target first."
    app._save_markdown()
    assert app.page.dialog is None


def test_save_json_writes_file_and_forces_suffix(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    run_analysis(app)
    app._save_json()

    dialog = app.page.dialog
    assert dialog is not None and dialog.open is True
    assert dialog.title.value == "Save JSON report"
    target = tmp_path / "nested" / "report.weird"
    dialog.content.value = str(target)

    dialog.actions[1].on_click(None)  # Save action
    assert dialog.open is False
    written = tmp_path / "nested" / "report.json"
    assert written.exists()
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["plan"]["steps"]
    assert "Saved" in app.status_text.value


def test_save_cancel_keeps_dialog_state_consistent(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    run_analysis(app)
    app._save_markdown()

    dialog = app.page.dialog
    assert dialog.title.value == "Save Markdown report"
    dialog.content.value = str(tmp_path / "unused.md")
    dialog.actions[0].on_click(None)  # Cancel action
    assert dialog.open is False
    assert not (tmp_path / "unused.md").exists()


def test_save_markdown_writes_report(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    run_analysis(app)
    app._save_markdown()

    dialog = app.page.dialog
    output = tmp_path / "report.md"
    dialog.content.value = str(output)
    dialog.actions[1].on_click(None)
    assert output.read_text(encoding="utf-8").startswith("# Reqvexa Safe Report")


def test_stop_requests_cancellation_and_disables_button(app: ReqvexaApp):
    app._begin("Analyzing target")
    assert app.stop_button.disabled is False
    app._stop()

    assert app.cancel_event.is_set()
    assert app.stop_button.disabled is True
    assert any("Stop requested" in value for value in texts(app.live_log))


def test_begin_disables_buttons_until_finished(app: ReqvexaApp):
    job = app._begin("Loading capture")
    assert job == 1
    assert app.load_button.disabled is True
    assert app.analyze_button.disabled is True
    assert app.stop_button.disabled is False
    assert app.progress.visible is True
    assert app.progress.value == 0

    app._finish("Capture loaded")
    assert app.load_button.disabled is False
    assert app.analyze_button.disabled is False
    assert app.stop_button.disabled is True
    assert app.progress.visible is False
    assert app.status_text.value == "Capture loaded"


def test_cancelled_event_finishes_job(app: ReqvexaApp):
    app._begin("Loading capture")
    app.events.put(("cancelled", app.active_job_id))
    wait_for(app, lambda: app.load_button.disabled is False
             and app.status_text.value == "Analysis stopped")
    assert any("stopped by user" in value.lower() for value in texts(app.live_log))
    assert app.progress.visible is False


def test_error_event_finishes_job_with_message(app: ReqvexaApp):
    app._begin("Analyzing target")
    app.events.put(("error", (app.active_job_id, RuntimeError("worker boom"))))
    wait_for(app, lambda: app.load_button.disabled is False)
    assert "worker boom" in app.status_text.value
    assert app.progress.visible is False


def test_stale_job_events_are_ignored(app: ReqvexaApp):
    first = app._begin("First job")
    app._begin("Second job")  # new job supersedes the stale one
    received: list[str] = []
    app.events.put(("result", (first, received.append, "payload")))
    run_poll(app)

    assert received == []  # callback from a stale job is never invoked

    app.events.put(("result", (app.active_job_id, received.append, "payload")))
    wait_for(app, lambda: received == ["payload"])


def test_live_log_caps_at_300_rows(app: ReqvexaApp):
    for index in range(305):
        app._log(f"row {index}")
    values = texts(app.live_log)
    assert len(values) == 300
    assert values[0] == "row 5"
    assert values[-1] == "row 304"


def test_observation_stream_rows_render_masked_values(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    app._begin("Analyzing target")
    job = app.active_job_id
    app._create_streaming_analysis_tab(job, app.target_id)

    observations = (
        SimpleNamespace(semantic_hints=("cookie.session",),
                        normalized_value=TOKEN,
                        location=SimpleNamespace(container="request.cookies",
                                                 path="$.session")),
        SimpleNamespace(semantic_hints=(),
                        normalized_value="X",
                        location=SimpleNamespace(container="response.raw_text",
                                                 path="$$")),
    )
    app.events.put(("observations", (job, "unused", 7, observations)))
    wait_for(app, lambda: len(app.streaming_lists[job].controls) == 2)

    stream = app.streaming_lists[job]
    values = texts(stream)
    assert "0007" in values
    assert "session" in values
    assert TOKEN not in values  # masked display only
    assert any("*" in value for value in values if value != "0007")


def test_observation_stream_switches_to_summary_when_flooded(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    app._begin("Analyzing target")
    job = app.active_job_id
    app._create_streaming_analysis_tab(job, app.target_id)

    observations = tuple(
        SimpleNamespace(semantic_hints=(f"hint.{index}",),
                        normalized_value=f"value-{index}",
                        location=SimpleNamespace(container="response.body",
                                                 path="$.field"))
        for index in range(50)
    )
    for sequence in range(29):
        app.events.put(("observations", (job, "unused", sequence, observations)))
    wait_for(app, lambda: app.stream_totals.get(job) == 1450)

    stream = app.streaming_lists[job]
    values = texts(stream)
    # Row previews covered the pre-flood window; the flood itself is one
    # summary row instead of another control chains.
    assert any("1,450 observations scanned" in value for value in values)
    assert any("(row previews capped at 1,200)" in value for value in values)
    assert len(stream.controls) == 1
    assert app.stream_summaries[job] is stream.controls[0]
