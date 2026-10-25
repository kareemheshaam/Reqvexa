"""Headless tests for the Flet GUI.

The app is driven against a minimal fake page: real event handlers run,
control trees carry the assertions, and
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
    MANUAL_TAB_INDEX,
    RED,
    ReqvexaApp,
    SweepResult,
    _badge,
    _body_view,
    _entry_candidate_values,
    _first_earlier_occurrence,
    _header_value,
    _json_keys,
    _json_spans,
    _key_value_section,
    _method_color,
    _observation_name,
    _request_hints,
    _request_ignore_groups,
    _safe_path,
    _status_color,
    _sweep_request_values,
    _ui_path,
)

TOKEN = "tok-0123456789abcdef"  # display-masks to "tok-" + 16 asterisks


# ------------------------------------------------------------ harness ---


class FakePage:
    """Implements the page surface ReqvexaApp relies on."""

    def __init__(self) -> None:
        self.controls: list[ft.Control] = []
        self.active_dialog: ft.AlertDialog | None = None
        self.opened_dialogs: list[ft.AlertDialog] = []
        self.closed_dialogs: list[ft.AlertDialog] = []
        self.update_count = 0
        self.handler: Callable[..., Any] | None = None
        self.tasks: list[Any] = []  # one created-but-unstarted coroutine
        self.clipboard: str | None = None
        self.window = SimpleNamespace(min_width=None, min_height=None)
        for attribute in ("bgcolor", "padding", "theme", "dark_theme", "theme_mode"):
            setattr(self, attribute, None)

    def add(self, *controls: ft.Control) -> None:
        self.controls.extend(controls)

    def update(self) -> None:
        self.update_count += 1

    def show_dialog(self, control: ft.AlertDialog) -> None:
        control.open = True
        self.opened_dialogs.append(control)
        self.active_dialog = control

    def pop_dialog(self) -> ft.AlertDialog | None:
        control = next(
            (dialog for dialog in reversed(self.opened_dialogs) if dialog.open),
            None,
        )
        if control is None:
            return None
        control.open = False
        self.closed_dialogs.append(control)
        if self.active_dialog is control:
            self.active_dialog = next(
                (dialog for dialog in reversed(self.opened_dialogs) if dialog.open),
                None,
            )
        return control

    def make_clipboard(self):
        page = self

        class FakeClipboard:
            async def set(self, value: str) -> None:
                page.clipboard = value

        return FakeClipboard()

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
    instance = ReqvexaApp(page, capture_path=None, request_id=None)
    instance.clipboard = page.make_clipboard()
    return instance


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


def first_appearance_entries() -> list:
    """Two-hop chain: bootstrap -> middle -> target."""
    return [
        entry("GET", "https://example.test/bootstrap",
              response=response(text='{"token":"A"}')),
        entry("GET", "https://example.test/middle", headers=[
            {"name": "X-Token", "value": "A"},
        ], response=response(text='{"session":"B"}')),
        entry("GET", "https://example.test/target", headers=[
            {"name": "X-Session", "value": "B"},
        ]),
    ]


def load_capture(app: ReqvexaApp, path: str) -> None:
    app.path_field.value = path
    app._load_capture()
    wait_for(app, lambda: app.status_text.value == "Capture loaded")


def run_analysis(app: ReqvexaApp) -> None:
    # Analysis behavior tests opt into their target fields explicitly. The UI
    # now starts with every Analysis Control checkbox unchecked.
    app._set_all_trace_values(True)
    app._analyze()
    wait_for(app, lambda: app.latest_analysis_tab_index is not None)


def body_entry(method: str, url: str, body_text: str, mime: str,
               headers=None) -> dict:
    """A bare entry whose request carries a body and no response."""
    return {
        "startedDateTime": "2026-08-29T00:00:00Z", "time": 1,
        "timings": {"wait": 1},
        "request": {"method": method, "url": url, "httpVersion": "HTTP/1.1",
                    "headers": headers or [], "cookies": [],
                    "postData": {"mimeType": mime, "text": body_text}},
    }


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


def test_body_view_renders_full_json_grid_plain_text_without_highlight():
    from reqvexa.gui import BODY_HIGHLIGHT_MAX_CHARS

    rendered = _body_view('{"k":1}', "application/json")
    assert isinstance(rendered, ft.Container)
    assert _body_view('{"k":1', "application/json") is not None  # invalid JSON
    assert isinstance(_body_view("<html>", "text/html"), ft.Text)
    # Huge bodies are not truncated: they render fully, just unhighlighted.
    huge = "x" * (BODY_HIGHLIGHT_MAX_CHARS + 1)
    big = _body_view(huge, "application/json")
    assert "without syntax highlighting" in " ".join(texts(big))
    assert huge in " ".join(texts(big))
    assert "truncated" not in " ".join(texts(big))



def test_default_ignored_hints_are_transport_metadata_only():
    assert "user-agent" in DEFAULT_IGNORED_HINTS
    assert "sec-fetch-site" in DEFAULT_IGNORED_HINTS
    assert "authorization" not in DEFAULT_IGNORED_HINTS
    assert "cookie" not in DEFAULT_IGNORED_HINTS


# ------------------------------------------------------- app level tests ---


def test_app_builds_expected_initial_layout(app: ReqvexaApp, page: FakePage):
    assert len(page.controls) == 3
    assert isinstance(app.main_tabs.control, ft.Tabs)
    assert isinstance(app.main_tabs.tab_bar, ft.TabBar)
    assert isinstance(app.main_tabs.tab_bar_view, ft.TabBarView)
    assert app.main_tabs.control.length == 4
    assert app.analysis_tabs.control.length == 1  # Flet 1 requires a valid visible tab.
    assert [tab.text for tab in app.main_tabs.tabs] == [
        "Traffic", "Manual", "Logs", "Analysis"]
    assert app.analysis_tabs.tabs == []
    assert app.request_list.controls == []
    assert app.stop_button.disabled is True
    assert app.progress.visible is False
    assert app.status_text.value == "Ready"
    assert app.recursive_switch.value is True
    assert app.reveal_switch.value is True
    assert app.ignore_file_responses_switch.value is True
    assert has_text(app.detail_panel, "Select a request to inspect it.")
    # The manual tab starts empty with its guidance placeholder.
    assert app.manual_flow_list.controls == []
    assert has_text(app.manual_detail, "Pick a request in Traffic")

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
    assert list(app.ignore_boxes) == ["session"]
    checkbox = app.ignore_boxes["session"]
    assert isinstance(checkbox, ft.Checkbox)
    assert checkbox.value is False  # fields are opt-in and start unchecked
    assert has_text(app.detail_panel, "HTTP 200")

    selected = [tile for tile in app.request_list.controls if tile.selected]
    assert len(selected) == 1 and texts(selected[0])[0] == "GET /api/products"


def test_ignore_selections_persist_across_request_switches(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    login = app.capture.requests[0]
    dead = app.capture.requests[2]

    app._select_request(login.id)
    assert app.ignore_boxes["user-agent"].value is False  # transport default is excluded
    app.ignore_boxes["user-agent"].value = True
    app._ignore_toggled(None)
    assert app.ignored_names["user-agent"] is False  # checked means not ignored

    app._select_request(dead.id)
    assert list(app.ignore_boxes) == ["x-signature"]
    assert app.ignore_boxes["x-signature"].value is False
    app.ignore_boxes["x-signature"].value = False
    app._ignore_toggled(None)
    assert app.ignored_names["x-signature"] is True

    app._select_request(login.id)
    assert app.ignore_boxes["user-agent"].value is True  # restored from storage

    merged = app._ignored_selection()
    assert "x-signature" in merged
    assert "user-agent" not in merged


def test_ignore_options_exclude_response_side_names(app: ReqvexaApp, tmp_path):
    entries = standard_entries()
    login = entries[0]
    assert login["response"] is not None
    login["response"]["headers"].append({"name": "X-Frame-Options", "value": "deny"})
    load_capture(app, write_har(tmp_path, entries))
    app._select_request(app.capture.requests[0].id)
    assert "user-agent" in app.ignore_boxes  # request side, unchanged
    assert "x-frame-options" not in app.ignore_boxes  # response side is not traced
    assert "session" not in app.ignore_boxes  # response cookie is not a request value
    assert "csrf" not in app.ignore_boxes  # response body is not traced as target input
    assert "set-cookie" not in app.ignore_boxes  # zombie name, cookie names instead


def test_ignore_options_are_grouped_for_target_request_only(
        app: ReqvexaApp, tmp_path):
    target = entry(
        "POST", "https://example.test/submit?page=3",
        headers=[{"name": "X-Trace", "value": "trace-value"}],
        response=response(
            headers=[
                {
                    "name": "Set-Cookie",
                    "value": "server_session=sess-123; Path=/; HttpOnly; SameSite=Lax",
                },
                {"name": "X-Frame-Options", "value": "deny"},
            ],
            text='{"response_csrf":"resp-csrf-value"}',
        ),
    )
    target["request"]["cookies"] = [
        {"name": "request_session", "value": "req-session-value"},
    ]
    target["request"]["postData"] = {
        "mimeType": "application/x-www-form-urlencoded",
        "text": "payload_key=payload-value",
    }
    load_capture(app, write_har(tmp_path, [target]))
    request, response_value = app.capture.view_entry(app.capture.requests[0].id)

    assert response_value is not None
    assert _request_ignore_groups(request) == {
        "Cookies": ["request_session"],
        "Headers": ["x-trace"],
        "Payload": ["payload_key"],
        "Parameters": ["page"],
    }
    assert app.ignore_groups == {
        "Cookies": ("request_session",),
        "Headers": ("x-trace",),
        "Payload": ("payload_key",),
        "Parameters": ("page",),
    }
    assert all(not checkbox.value for checkbox in app.ignore_boxes.values())
    assert not {"server_session", "x-frame-options", "response_csrf"} & set(app.ignore_boxes)
    assert not {"path", "samesite"} & set(app.ignore_boxes)
    assert has_text(app.ignore_panel, "Cookies")
    assert has_text(app.ignore_panel, "Payload")

    app._set_all_trace_values(True)
    assert all(box.value for box in app.ignore_boxes.values())
    app._set_all_trace_values(False)
    assert all(not box.value for box in app.ignore_boxes.values())
    assert {"request_session", "x-trace", "payload_key", "page"} <= (
        app._ignored_selection()
    )


def test_analysis_confirmation_and_separate_analysis_control_dialog(
        app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    app._select_request(app.capture.requests[1].id)

    app.analyze_button.on_click(None)
    confirmation = app.page.active_dialog
    assert isinstance(confirmation, ft.AlertDialog)
    assert confirmation in app.page.opened_dialogs
    assert confirmation.open is True
    assert has_text(confirmation, "Confirm analysis")
    assert app.recursive_switch in list(walk(confirmation))
    assert app.reveal_switch in list(walk(confirmation))
    assert app.ignore_file_responses_switch in list(walk(confirmation))
    assert app.recursive_switch.value is True
    assert app.reveal_switch.value is True
    assert app.ignore_file_responses_switch.value is True
    assert all(not checkbox.value for checkbox in app.ignore_boxes.values())
    assert app.analysis_tabs.tabs == []  # confirmation does not start work

    control_button = next(
        node for node in walk(confirmation)
        if isinstance(node, ft.OutlinedButton)
        and node.content == "Analysis Control"
    )
    control_button.on_click(None)
    control = app.page.active_dialog
    assert isinstance(control, ft.AlertDialog)
    assert control.open is True
    assert has_text(control, "Checked fields are included in tracing")
    assert has_text(control, "Cookies")
    assert app.ignore_boxes["session"].value is False

    next(
        node for node in walk(control)
        if isinstance(node, ft.TextButton) and node.content == "Unselect all"
    ).on_click(None)
    assert all(not box.value for box in app.ignore_boxes.values())
    next(
        node for node in walk(control)
        if isinstance(node, ft.TextButton) and node.content == "Select all"
    ).on_click(None)
    assert all(box.value for box in app.ignore_boxes.values())

    control.actions[0].on_click(None)  # Done returns to confirmation.
    assert app.page.active_dialog is app.confirmation_dialog
    assert app.page.active_dialog.open is True
    app.page.active_dialog.actions[1].on_click(None)  # Analyze target
    wait_for(app, lambda: app.analysis_count == 1)
    assert app.confirmation_dialog.open is False
    assert app.latest_analysis_tab_index == 0
    assert app.page.opened_dialogs[0] is confirmation


def test_analysis_tab_opens_standalone_analysis_control_dialog(
        app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    analysis_control = next(
        node for node in walk(app.main_tabs.tabs[3].content)
        if isinstance(node, ft.TextButton) and node.content == "Analysis Control"
    )
    analysis_control.on_click(None)
    assert isinstance(app.page.active_dialog, ft.AlertDialog)
    assert app.page.active_dialog.title.value == "Analysis Control"
    assert app.page.active_dialog.open is True
    control_dialog = app.page.active_dialog
    control_dialog.actions[0].on_click(None)
    assert control_dialog.open is False
    assert app.page.active_dialog is None


def test_analysis_request_selection_generates_sync_or_async_code(
        app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, first_appearance_entries()))
    run_analysis(app)

    result_tab = app.analysis_tabs.tabs[app.latest_analysis_tab_index].content
    request_boxes = [
        node for node in walk(result_tab) if isinstance(node, ft.Checkbox)
    ]
    assert len(request_boxes) == len(app.plan.steps)
    assert all(box.value for box in request_boxes)
    selection_buttons = {
        node.content: node for node in walk(result_tab)
        if isinstance(node, ft.TextButton)
        and node.content in {"Select all", "Unselect all"}
    }
    selection_buttons["Unselect all"].on_click(None)
    assert not any(box.value for box in request_boxes)
    selection_buttons["Select all"].on_click(None)
    assert all(box.value for box in request_boxes)

    generate_button = next(
        node for node in walk(result_tab)
        if isinstance(node, ft.FilledButton) and node.content == "Generate Python"
    )
    selection_buttons["Unselect all"].on_click(None)
    generate_button.on_click(None)
    assert app.code_dialog is None
    selection_buttons["Select all"].on_click(None)

    first_step = app.plan.steps[0]
    request_boxes[0].value = False
    request_boxes[0].on_change(SimpleNamespace(control=request_boxes[0]))

    generate_button.on_click(None)

    assert app.code_dialog is app.page.active_dialog
    assert app.code_preview is not None
    assert first_step.path not in app.code_preview.value
    assert "tls_client.Session()" in app.code_preview.value
    assert "captured headers, cookies" in " ".join(texts(app.code_dialog))

    assert app.code_async_switch is not None
    app.code_async_switch.value = True
    app.code_async_switch.on_change(None)
    assert "async def run()" in app.code_preview.value
    assert "tls_client.AsyncSession()" in app.code_preview.value

    asyncio.run(app._copy_generated_code())
    assert app.page.clipboard == app.code_preview.value

    app._save_generated_code()
    save_dialog = app.page.active_dialog
    output_path = tmp_path / "generated-flow.py"
    save_dialog.content.value = str(output_path)
    save_dialog.actions[1].on_click(None)
    assert output_path.read_text(encoding="utf-8") == app.code_preview.value
    assert app.page.active_dialog is app.code_dialog


def test_analysis_can_generate_one_selected_request(
        app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, first_appearance_entries()))
    run_analysis(app)

    result_tab = app.analysis_tabs.tabs[app.latest_analysis_tab_index].content
    request_boxes = [
        node for node in walk(result_tab) if isinstance(node, ft.Checkbox)
    ]
    assert len(request_boxes) == len(app.plan.steps)

    generate_button = next(
        node for node in walk(result_tab)
        if isinstance(node, ft.OutlinedButton)
        and node.content == "Generate Single Request"
    )
    generate_button.on_click(None)
    assert app.code_dialog is None
    assert "exactly one request" in app.status_text.value

    for checkbox in request_boxes[:-1]:
        checkbox.value = False
        checkbox.on_change(SimpleNamespace(control=checkbox))
    generate_button.on_click(None)

    assert app.code_dialog is app.page.active_dialog
    assert app.code_dialog.title.value == "Generated Python single request"
    assert app.code_single_request is True
    assert len(app.code_requests) == 1
    assert app.code_requests[0].url == "https://example.test/target"
    assert "url = 'https://example.test/target'" in app.code_preview.value
    assert "headers =" in app.code_preview.value
    assert "response = session.get(url, headers=headers, cookies=cookies)" in (
        app.code_preview.value
    )
    assert "REQUESTS" not in app.code_preview.value
    assert "REPLACE_ME" not in app.code_preview.value

    assert app.code_async_switch is not None
    app.code_async_switch.value = True
    app.code_async_switch.on_change(None)
    assert "async def run()" in app.code_preview.value
    assert "tls_client.AsyncSession()" in app.code_preview.value


def test_http2_pseudo_headers_are_not_analysis_control_fields(
        app: ReqvexaApp, tmp_path):
    pseudo_request = entry(
        "GET", "https://example.test/path",
        headers=[
            {"name": ":method", "value": "GET"},
            {"name": ":authority", "value": "example.test"},
            {"name": ":path", "value": "/path"},
            {"name": "X-Session", "value": "session-123"},
        ],
        response=response(
            headers=[{"name": ":status", "value": "200"}],
            text='{"token":"response-token"}',
        ),
    )
    load_capture(app, write_har(tmp_path, [pseudo_request]))
    request = app.capture.requests[0]
    app._select_request(request.id)

    assert set(app.ignore_boxes) == {"x-session"}
    assert has_text(app.detail_panel, "HTTP/2 pseudo-headers")
    assert has_text(app.detail_panel, ":authority")
    assert has_text(app.detail_panel, "Headers")


def test_loaded_capture_keeps_metadata_only_proxies(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    assert app.capture.is_lazy
    assert app.capture.requests[0].headers == ()  # resident proxies hold none

    app._select_request(app.capture.requests[0].id)
    assert set(app.ignore_boxes) == {"user-agent"}
    assert app.ignore_groups == {
        "Headers": ("user-agent",),
    }
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
    assert has_text(app.ignore_panel, "Also excluded (1 from other requests)")
    assert has_text(app.ignore_panel, "x-signature")


def test_search_field_filters_request_list(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    app.search_field.value = "api"
    app._render_request_list()
    assert [texts(tile)[0] for tile in app.request_list.controls] == ["GET /api/products"]

    app.search_field.value = "no-match-here"
    app._render_request_list()
    assert app.request_list.controls == []


def test_search_criteria_dialog_selects_and_clears_fields(
        app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))

    assert all(box.value for box in app.search_criteria_boxes.values())
    app.search_criteria_button.on_click(None)
    dialog = app.page.active_dialog
    assert dialog is app.search_criteria_dialog and dialog.open is True
    criteria_labels = {
        node.label for node in walk(dialog) if isinstance(node, ft.Checkbox)
    }
    assert "Request body / POST data" in criteria_labels
    assert "Response content" in criteria_labels

    next(
        node for node in walk(dialog)
        if isinstance(node, ft.TextButton) and node.content == "Unselect all"
    ).on_click(None)
    assert all(not box.value for box in app.search_criteria_boxes.values())

    next(
        node for node in walk(dialog)
        if isinstance(node, ft.TextButton) and node.content == "Select all"
    ).on_click(None)
    assert all(box.value for box in app.search_criteria_boxes.values())

    dialog.actions[0].on_click(None)
    assert dialog.open is False


def test_search_filters_by_selected_request_and_response_fields(
        app: ReqvexaApp, tmp_path):
    target = entry(
        "METASEARCH",
        "https://example.test/url-only-token?query_key=query-only-token",
        headers=[{"name": "X-Search", "value": "header-only-token"}],
        response=response(
            status=299,
            headers=[{"name": "X-Response-Search", "value": "response-header-token"}],
            text='{"result":"response-content-token"}',
        ),
    )
    target["request"]["cookies"] = [
        {"name": "request_cookie", "value": "request-cookie-token"},
    ]
    target["request"]["postData"] = {
        "mimeType": "application/x-www-form-urlencoded",
        "text": "payload=post-data-token",
    }
    target["response"]["cookies"] = [
        {"name": "response_cookie", "value": "response-cookie-token"},
    ]
    entries = [
        entry("GET", "https://example.test/unrelated"),
        target,
    ]
    load_capture(app, write_har(tmp_path, entries))
    assert app.capture.is_lazy

    target_label = "METASEARCH /url-only-token"
    criteria_cases = {
        "request_metadata": "metasearch",
        "request_url": "url-only-token",
        "query_parameters": "query-only-token",
        "request_headers": "header-only-token",
        "request_cookies": "request-cookie-token",
        "request_body": "post-data-token",
        "response_status": "299",
        "response_headers": "response-header-token",
        "response_cookies": "response-cookie-token",
        "response_content": "response-content-token",
    }
    for criterion, needle in criteria_cases.items():
        app._set_all_search_criteria(False)
        app.search_criteria_boxes[criterion].value = True
        app.search_field.value = needle
        app._render_request_list()
        assert [texts(tile)[0] for tile in app.request_list.controls] == [
            target_label,
        ], f"criterion {criterion!r} did not match {needle!r}"


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
    assert TOKEN in texts(content)  # sensitive values are shown by default
    assert app._summary.value == "2 planned steps  /  1 traced values  /  0 unresolved"


def test_ignore_file_responses_switch_filters_asset_producers(
        app: ReqvexaApp, tmp_path):
    entries = [
        entry(
            "GET", "https://example.test/assets/bundle.js",
            response=response(
                text='{"token":"FILE-ONLY-TOKEN"}',
                mime="application/javascript",
            ),
        ),
        entry("GET", "https://example.test/target", headers=[
            {"name": "X-Token", "value": "FILE-ONLY-TOKEN"},
        ]),
    ]
    load_capture(app, write_har(tmp_path, entries))
    app.ignore_file_responses_switch.value = True
    run_analysis(app)

    target = app.capture.requests[1]
    target_observation = next(
        item for item in app.analysis.observations
        if item.request_id == target.id
        and item.response_id is None
        and item.normalized_value == "FILE-ONLY-TOKEN"
    )
    version = app.analysis._version_for_observation(
        target_observation, target.sequence,
    )
    assert version is not None
    assert version.version_id not in app.analysis.target_producers
    assert app.analysis_ignores_file_responses is True
    assert has_text(
        app.analysis_tabs.tabs[app.latest_analysis_tab_index].content,
        "file responses ignored",
    )


def test_recursive_switch_controls_analysis_depth(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, first_appearance_entries()))
    app._select_request(app.capture.requests[2].id)
    assert app.recursive_switch.value is True
    app._set_all_trace_values(True)

    app._analyze()
    wait_for(app, lambda: app.analysis_count == 1)
    assert [step.sequence for step in app.plan.steps] == [0, 1, 2]
    assert app.main_tabs.selected_index == 3
    assert app.analysis_tabs.selected_index == app.latest_analysis_tab_index
    assert app.analysis_recursive is True
    assert has_text(
        app.analysis_tabs.tabs[app.latest_analysis_tab_index].content, "recursive",
    )

    app.recursive_switch.value = False
    app._analyze()
    # Simulate the user switching back to the old result while the new tab is
    # still showing progress. Completion must restore focus to the new tab.
    app.analysis_tabs.selected_index = 0
    wait_for(app, lambda: app.analysis_count == 2)
    assert [step.sequence for step in app.plan.steps] == [1, 2]
    assert app.main_tabs.selected_index == 3
    assert app.analysis_tabs.selected_index == app.latest_analysis_tab_index
    assert app.analysis_recursive is False
    tab = app.analysis_tabs.tabs[app.latest_analysis_tab_index]
    assert has_text(tab.content, "one level")
    assert has_text(tab.content, "2 requests required for this flow")

    # Re-rendering for the sensitive-values switch must keep the depth.
    app.reveal_switch.value = True
    app._refresh_sensitive_views()
    assert [step.sequence for step in app.plan.steps] == [1, 2]


def test_reveal_switch_toggles_masked_display_values(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    run_analysis(app)
    tab = app.analysis_tabs.tabs[app.latest_analysis_tab_index]

    assert TOKEN in texts(tab)  # reveal is enabled by default
    app.reveal_switch.value = False
    app._refresh_sensitive_views()
    assert TOKEN not in texts(app.analysis_tabs.tabs[app.latest_analysis_tab_index])
    assert app.status_text.value == "Sensitive values masked."

    app.reveal_switch.value = True
    app._refresh_sensitive_views()
    assert TOKEN in texts(app.analysis_tabs.tabs[app.latest_analysis_tab_index])
    assert app.status_text.value == "Sensitive values shown."


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
    copy_buttons = [
        node for node in walk(placeholder.content)
        if isinstance(node, ft.IconButton)
    ]
    assert copy_buttons
    asyncio.run(copy_buttons[0].on_click(None))
    assert app.page.clipboard == "reqvexa-tests"


def test_save_without_analysis_prompts_instead_of_dialog(app: ReqvexaApp):
    app._save_json()
    assert app.page.active_dialog is None
    assert app.status_text.value == "Analyze a target first."
    app._save_markdown()
    assert app.page.active_dialog is None


def test_save_json_writes_file_and_forces_suffix(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    run_analysis(app)
    app._save_json()

    dialog = app.page.active_dialog
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

    dialog = app.page.active_dialog
    assert dialog.title.value == "Save Markdown report"
    dialog.content.value = str(tmp_path / "unused.md")
    dialog.actions[0].on_click(None)  # Cancel action
    assert dialog.open is False
    assert not (tmp_path / "unused.md").exists()


def test_save_markdown_writes_report(app: ReqvexaApp, tmp_path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    run_analysis(app)
    app._save_markdown()

    dialog = app.page.active_dialog
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
    app.reveal_switch.value = False  # exercise the masked-display setting
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


# ------------------------------------------------------- manual trace ---


def clickable_controls(control: Any) -> list[Any]:
    return [
        node for node in walk(control)
        if isinstance(node, ft.Container) and getattr(node, "on_click", None) is not None
    ]


def test_key_value_rows_report_exact_raw_values():
    captured: list[tuple[str, str, str]] = []
    section = _key_value_section(
        "Headers", [("auth", "Bearer abc-123"), ("x-other", "row-value-2")],
        kind="header",
        on_value=lambda kind, name, value: captured.append((kind, name, value)),
        on_copy=lambda kind, name, value: captured.append(("copy-" + kind, name, value)),
    )
    clickable = clickable_controls(section)
    assert len(clickable) == 2
    clickable[0].on_click(None)
    assert captured == [("header", "auth", "Bearer abc-123")]
    # The copy icon sits next to the value because selectable text swallows
    # the trace click; it copies the exact raw value.
    copies = [node for node in walk(section) if isinstance(node, ft.IconButton)]
    assert len(copies) == 2
    copies[0].on_click(None)
    assert captured[-1] == ("copy-header", "auth", "Bearer abc-123")
    # Traceable value text itself is not selectable (that stole the click).
    traceable = [node for node in walk(clickable[0])
                 if isinstance(node, ft.Text)]
    assert traceable and all(not node.selectable for node in traceable)


def test_plain_sections_without_trace_callback_stay_selectable():
    section = _key_value_section("Headers", [("auth", "x")], kind="header")
    assert not clickable_controls(section)
    value = next(
        node for node in walk(section)
        if isinstance(node, ft.Text) and node.value == "x"
    )
    assert value.selectable


def test_json_spans_make_values_clickable_but_not_keys_or_literals():
    captured: list[str] = []
    spans = _json_spans(
        '{"keep":"val-1","n":42,"flag":true,"other":"val-2"}',
        on_value=lambda kind, name, value: captured.append(value),
    )
    handlers = [span.on_click for span in spans if span.on_click is not None]
    assert len(handlers) == 3  # val-1, 42, val-2 - keys/bools/null not clickable
    for handler in handlers:
        handler(None)
    assert captured == ["val-1", "42", "val-2"]


def test_clickable_json_body_disables_selection_but_plain_bodies_keep_it():
    spanned = _body_view('{"k":"val-1"}', "application/json",
                         on_value=lambda kind, name, value: None)
    spanned_text = next(
        node for node in walk(spanned)
        if isinstance(node, ft.Text) and node.spans
    )
    assert not spanned_text.selectable  # selectable text eats span taps

    dead = _body_view('{"k":"val-1"}', "application/json")
    dead_text = next(
        node for node in walk(dead)
        if isinstance(node, ft.Text) and getattr(node, "spans", None)
    )
    assert dead_text.selectable is True

    plain = _body_view("hello world", "text/plain",
                       on_value=lambda kind, name, value: None)
    plain_text = next(
        node for node in walk(plain) if isinstance(node, ft.Text)
    )
    assert plain_text.selectable  # untraced bodies still allow text selection


def test_copy_button_copies_exact_value(app: ReqvexaApp, tmp_path: Path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    login = app.capture.requests[0]
    asyncio.run(app._copy_inspector_value(login.id, "cookie", "session", TOKEN))
    assert app.page.clipboard == TOKEN
    assert "Copied" in app.status_text.value


def test_inspector_rows_are_clickable_with_copy_icons(app: ReqvexaApp,
                                                      tmp_path: Path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    app._select_request(app.capture.requests[0].id)
    clickable = [
        node for node in walk(app.detail_panel.content)
        if isinstance(node, ft.Container) and getattr(node, "on_click", None) is not None
    ]
    copies = [
        node for node in walk(app.detail_panel.content)
        if isinstance(node, ft.IconButton)
    ]
    assert clickable and copies


def test_manual_trace_finds_first_request_holding_the_value(app: ReqvexaApp,
                                                            tmp_path: Path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    products = app.capture.requests[1]
    app._select_request(products.id)

    app._trace_inspector_value(products.id, "cookie", "session", TOKEN)
    wait_for(app, lambda: len(app.manual_hops) == 1)

    hop = app.manual_hops[0]
    assert hop.value == TOKEN
    assert hop.from_request.id == products.id
    assert hop.found_request is not None and hop.found_request.sequence == 0
    assert "response body field 'csrf'" in hop.locations
    assert len(app.manual_flow_list.controls) == 2  # origin card + one hop
    # The hop surfaced the Manual tab and opened the found request there.
    assert app.main_tabs.selected_index == MANUAL_TAB_INDEX
    assert has_text(app.manual_detail, "/login")
    assert has_text(app.manual_detail, "HTTP 200")
    preview_text = "".join(
        span.text or "" for node in walk(app.manual_detail)
        if isinstance(node, ft.Text)
        for span in (node.spans or [])
    )
    assert "csrf" in preview_text
    run_poll(app, 0.25)  # one hop per click: nothing searched further
    assert len(app.manual_hops) == 1


def test_manual_result_card_reopens_full_captured_response(
        app: ReqvexaApp, tmp_path: Path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    products = app.capture.requests[1]
    app._trace_inspector_value(products.id, "cookie", "session", TOKEN)
    wait_for(app, lambda: len(app.manual_hops) == 1)

    result_card = app.manual_flow_list.controls[1]
    assert result_card.on_click is not None
    result_card.on_click(None)
    assert has_text(app.manual_detail, "HTTP 200")
    preview_text = "".join(
        span.text or "" for node in walk(app.manual_detail)
        if isinstance(node, ft.Text)
        for span in (node.spans or [])
    )
    assert TOKEN in preview_text  # full captured response body
    assert "csrf" in preview_text


def test_manual_preview_does_not_mistake_missing_status_for_http_zero(
        app: ReqvexaApp, tmp_path: Path):
    entry_without_status = entry(
        "GET", "https://example.test/no-status",
        response={"headers": [], "cookies": [], "content": {}},
    )
    load_capture(app, write_har(tmp_path, [entry_without_status]))

    app._select_manual_request(app.capture.requests[0].id)

    assert has_text(app.manual_detail, "HTTP status unavailable")
    assert has_text(app.manual_detail, "No response content was captured")
    assert not has_text(app.manual_detail, "HTTP 0")


def test_manual_trace_dead_end_reports_no_earlier_appearance(app: ReqvexaApp,
                                                             tmp_path: Path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    login = app.capture.requests[0]
    app._select_request(login.id)

    app._trace_inspector_value(login.id, "json", "csrf", TOKEN)
    wait_for(app, lambda: len(app.manual_hops) == 1)

    hop = app.manual_hops[0]
    assert hop.found_request is None and not hop.locations
    assert "first appearance is request #0" in app.status_text.value
    assert any("no earlier appearance" in value for value in texts(app.manual_flow_list))
    # No auto-open on a dead end: the manual inspector keeps its placeholder.
    assert has_text(app.manual_detail, "Pick a request in Traffic")
    assert has_text(app.detail_panel, "/login")  # traffic inspector unchanged


def test_manual_trace_ignores_names_and_hits_first_appearance_first(app: ReqvexaApp,
                                                                    tmp_path: Path):
    entries = [
        body_entry("POST", "https://example.test/intro",
                   '{"weird_key":"svc-9821"}', "application/json"),
        body_entry("POST", "https://example.test/form-bearer",
                   "pad=x&csrf_token=frm-77", "application/x-www-form-urlencoded"),
        entry("GET", "https://example.test/kit", headers=[
            {"name": "X-Different-Name", "value": "svc-9821"},
        ]),
    ]
    load_capture(app, write_har(tmp_path, entries))
    kit = app.capture.requests[2]

    app._trace_inspector_value(kit.id, "header", "x-different-name", "svc-9821")
    wait_for(app, lambda: len(app.manual_hops) == 1)
    first = app.manual_hops[0]
    assert first.found_request is not None and first.found_request.sequence == 0
    assert first.locations == ("request body field 'weird_key'",)

    app._trace_inspector_value(kit.id, "header", "x-different-name", "frm-77")
    wait_for(app, lambda: len(app.manual_hops) == 2)
    second = app.manual_hops[1]
    assert second.found_request is not None and second.found_request.sequence == 1
    assert second.locations == ("request body field 'csrf_token'",)


def test_manual_flow_respects_sensitive_values_switch(app: ReqvexaApp, tmp_path: Path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    products = app.capture.requests[1]
    app._trace_inspector_value(products.id, "cookie", "session", TOKEN)
    wait_for(app, lambda: len(app.manual_hops) == 1)

    shown = texts(app.manual_flow_list)
    assert any(TOKEN in value for value in shown)  # shown by default
    app.reveal_switch.value = False
    app._refresh_sensitive_views()
    shown = texts(app.manual_flow_list)
    assert not any(TOKEN in value for value in shown)
    assert any(value.count("*") == 16 for value in shown)
    app.reveal_switch.value = True
    app._refresh_sensitive_views()
    assert any(TOKEN in value for value in texts(app.manual_flow_list))


def test_manual_trace_clear_and_capture_reload_reset(app: ReqvexaApp,
                                                     tmp_path: Path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    products = app.capture.requests[1]
    app._trace_inspector_value(products.id, "cookie", "session", TOKEN)
    wait_for(app, lambda: len(app.manual_hops) == 1)

    app._clear_manual_trace()
    assert len(app.manual_hops) == 0 and app.manual_origin is None
    assert len(app.manual_flow_list.controls) == 0
    assert has_text(app.manual_detail, "Pick a request in Traffic")

    app._trace_inspector_value(products.id, "cookie", "session", TOKEN)
    wait_for(app, lambda: len(app.manual_hops) == 1)
    second = tmp_path / "second.har"
    second.write_text(json.dumps(har(standard_entries())), encoding="utf-8")
    load_capture(app, str(second))
    assert len(app.manual_hops) == 0 and app.manual_origin is None
    assert len(app.manual_flow_list.controls) == 0
    assert has_text(app.manual_detail, "Pick a request in Traffic")


def test_manual_trace_rejects_values_too_short(app: ReqvexaApp, tmp_path: Path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    kit = app.capture.requests[2]
    app._trace_inspector_value(kit.id, "header", "x-short", "9")
    run_poll(app, 0.2)
    assert len(app.manual_hops) == 0
    assert len(app.manual_flow_list.controls) == 0


def test_manual_trace_stops_when_nothing_is_traced(app: ReqvexaApp,
                                                   tmp_path: Path):
    load_capture(app, write_har(tmp_path, standard_entries()))
    kit = app.capture.requests[2]
    app._trace_inspector_value(kit.id, "header", "x-signature", "not-there-99")
    wait_for(app, lambda: len(app.manual_hops) == 1)
    hop = app.manual_hops[0]
    assert hop.found_request is None and not hop.locations


# ------------------------------------------------------- optional sweep ---


def sweep_entries() -> list:
    """Five entries whose values spread across headers, form fields, JSON
    scalars, a query and a server-set cookie, with earlier requests that
    hold some of them (and later ones that must be ignored by first-hit)."""
    zero = body_entry("POST", "https://example.test/intro",
                      '{"weird_key":"svc-9821","n":7712}', "application/json")
    form = body_entry("POST", "https://example.test/form-bearer",
                      "pad=x&csrf_token=frm-77", "application/x-www-form-urlencoded")
    holder = entry("GET", "https://example.test/kit", headers=[
        {"name": "X-Different-Name", "value": "svc-9821"},
    ])
    plain = body_entry("GET", "https://other-site.org/plain",
                       "plain body text without discrete values", "text/plain")
    final_resp = response(
        status=200, text='{"mirror":"svc-9821","k":"extra-fluff"}',
    )
    final_resp["cookies"] = [{"name": "sess", "value": "resp-only-token"}]
    final = entry("POST", "https://example.test/final?ref=lonely-42", headers=[
        {"name": "X-Token", "value": "svc-9821"},
        {"name": "X-Form", "value": "frm-77"},
        {"name": "X-Short", "value": "x"},
    ], response=final_resp)
    final["request"]["postData"] = {
        "mimeType": "application/json", "text": '{"n":7712}',
    }
    return [zero, form, holder, plain, final]


def test_entry_candidate_values_collect_traceable_literals(app: ReqvexaApp,
                                                           tmp_path: Path):
    load_capture(app, write_har(tmp_path, sweep_entries()))
    capture = app.capture
    zero_body = _entry_candidate_values(*capture.view_entry(capture.requests[0].id))
    assert zero_body == ["svc-9821", "7712"]  # JSON scalars, numbers as str()
    form_body = _entry_candidate_values(*capture.view_entry(capture.requests[1].id))
    assert form_body == ["frm-77"]  # urlencoded field values count; pad=x is short
    plain_body = _entry_candidate_values(*capture.view_entry(capture.requests[3].id))
    assert plain_body == []  # plain text bodies carry no discrete values
    final = capture.requests[4]
    values = _entry_candidate_values(*capture.view_entry(final.id))
    assert values == [
        "svc-9821",  # request header, deduped against the response body copy
        "frm-77",
        "lonely-42",  # query value
        "7712",
        "resp-only-token",  # server-set response cookie
        "extra-fluff",
    ]
    assert "x" not in values  # shorter than MANUAL_VALUE_MIN_CHARS


def test_sweep_hits_match_single_value_search_exactly(app: ReqvexaApp,
                                                      tmp_path: Path):
    """Every sweep hit must equal the one-value manual search for the same
    value (same winner, same location labels) - the sweep is the same
    search repeated, not a different heuristic."""
    load_capture(app, write_har(tmp_path, sweep_entries()))
    capture = app.capture
    final = capture.requests[4]
    result = _sweep_request_values(capture, final.id, capture.view_entry)
    assert result.checked == 4  # dead-end values force the full earlier scan
    assert result.source_request_id == final.id
    assert [hit[0] for hit in result.hits] == ["svc-9821", "frm-77", "7712"]
    assert result.missing == ("lonely-42", "resp-only-token", "extra-fluff")
    for value, found_id, locations in result.hits:
        single = _first_earlier_occurrence(
            capture, final.id, value, capture.view_entry,
        )
        assert single == (found_id, locations)


def test_sweep_finds_first_appearance_for_every_value(app: ReqvexaApp,
                                                      tmp_path: Path):
    load_capture(app, write_har(tmp_path, sweep_entries()))
    capture = app.capture
    final = capture.requests[4]
    result = _sweep_request_values(capture, final.id, capture.view_entry)
    found = {hit[0]: hit for hit in result.hits}
    # First appearance wins even though request #2 holds svc-9821 too.
    assert found["svc-9821"][1] == capture.requests[0].id
    assert found["svc-9821"][2] == ("request body field 'weird_key'",)
    # Cross-surface hop: a header value first held by a urlencoded form
    # field in an earlier request.
    assert found["frm-77"][1] == capture.requests[1].id
    assert found["frm-77"][2] == ("request body field 'csrf_token'",)
    assert found["7712"][1] == capture.requests[0].id
    assert found["7712"][2] == ("request body field 'n'",)


def test_sweep_records_every_value_without_recursing(app: ReqvexaApp,
                                                     tmp_path: Path):
    load_capture(app, write_har(tmp_path, sweep_entries()))
    final = app.capture.requests[4]
    app._select_request(final.id)
    app._start_value_sweep()
    wait_for(app, lambda: not app.sweep_running)

    assert app.main_tabs.selected_index == MANUAL_TAB_INDEX
    assert app.manual_origin.id == final.id
    assert len(app.manual_hops) == 6  # 3 traced + 3 dead ends
    assert [hop.value for hop in app.manual_hops] == [
        "svc-9821", "frm-77", "7712", "lonely-42", "resp-only-token",
        "extra-fluff",
    ]
    assert app.manual_hops[0].found_request.sequence == 0
    assert app.manual_hops[1].found_request.sequence == 1
    assert app.manual_hops[2].found_request.sequence == 0
    assert all(hop.found_request is None for hop in app.manual_hops[3:])
    assert "3 values traced" in app.status_text.value
    assert "3 dead ends" in app.status_text.value
    assert "4 earlier entries checked" in app.status_text.value
    assert "nothing further searched" in app.status_text.value
    # The swept request opened in the manual inspector for the next manual hop.
    assert has_text(app.manual_detail, "/final")
    assert any("no earlier appearance" in value
               for value in texts(app.manual_flow_list))
    # One level, by design: the found requests are never swept automatically.
    run_poll(app, 0.35)
    assert len(app.manual_hops) == 6 and not app.sweep_running
    # Re-sweeping dedupes instead of duplicating the chain.
    app._start_value_sweep()
    wait_for(app, lambda: not app.sweep_running)
    assert len(app.manual_hops) == 6
    assert "already on the chain" in app.status_text.value


def test_stale_and_guarded_sweeps_never_touch_the_chain(app: ReqvexaApp,
                                                        tmp_path: Path):
    app._start_value_sweep()
    assert "Load a capture first" in app.status_text.value

    load_capture(app, write_har(tmp_path, sweep_entries()))
    final = app.capture.requests[4]
    holder = app.capture.requests[1]
    result = SweepResult(
        final.id, (("frm-77", holder.id, ("request body field 'csrf_token'",)),), 1,
        ("lonely-42",),
    )
    app.sweep_token += 1
    app._sweep_done((app.sweep_token - 1, result))  # invalidated stale result
    assert len(app.manual_hops) == 0

    app._sweep_done((app.sweep_token, result))
    assert [hop.value for hop in app.manual_hops] == ["frm-77", "lonely-42"]
    assert app.manual_hops[0].found_request is not None
    assert app.manual_hops[1].found_request is None

    app._clear_manual_trace()  # bumps the token: a mid-sweep result is stale
    app._sweep_done((app.sweep_token - 1, result))
    assert len(app.manual_hops) == 0

    app.sweep_running = True
    app._start_value_sweep()
    assert "already running" in app.status_text.value
    app.sweep_running = False
    run_poll(app, 0.2)
    assert len(app.manual_hops) == 0  # guardrails never searched anything
