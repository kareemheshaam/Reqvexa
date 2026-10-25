from __future__ import annotations

import asyncio
import json
import queue
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import flet as ft

from reqvexa.cancellation import AnalysisCancelled
from reqvexa.capture import HarFormatError, HarProvider
from reqvexa.codegen import generate_python
from reqvexa.models import (
    Capture,
    HttpRequest,
    HttpResponse,
    SecretDisplayPolicy,
    ValueObservation,
)
from reqvexa.planning import FlowPlan, plan_flow, report_markdown, safe_report
from reqvexa.provenance import Analysis, ProvenanceEngine

BG = "#0B1120"
SURFACE = "#111827"
SURFACE_2 = "#172033"
BORDER = "#263449"
TEXT = "#E5E7EB"
MUTED = "#94A3B8"
ACCENT = "#38BDF8"
GREEN = "#34D399"
AMBER = "#FBBF24"
RED = "#FB7185"
NAME_COLOR = "#A78BFA"
VALUE_COLOR = "#67E8F9"
# Cap for JSON-key collection when building analysis-control options; body
# display never truncates since entries load one at a time on selection.
MAX_BODY_PREVIEW_CHARS = 50_000
# Bodies larger than this still render fully, but skip JSON syntax
# highlighting because constructing colored spans over them is slow.
BODY_HIGHLIGHT_MAX_CHARS = 500_000
# Short values match practically everything, so manual tracing refuses them.
MANUAL_VALUE_MIN_CHARS = 2
# Main-tab order in ReqvexaApp._build: Traffic, Manual, Logs, Analysis.
MANUAL_TAB_INDEX = 1
ANALYSIS_TAB_INDEX = 3
SEARCH_CRITERIA = (
    ("Request metadata", "request_metadata"),
    ("Request URL", "request_url"),
    ("Query parameters", "query_parameters"),
    ("Request headers", "request_headers"),
    ("Request cookies", "request_cookies"),
    ("Request body / POST data", "request_body"),
    ("Response status", "response_status"),
    ("Response headers", "response_headers"),
    ("Response cookies", "response_cookies"),
    ("Response content", "response_content"),
)

# (request_id, kind, name, exact raw value) from an inspector value click.
ValueClickHandler = Callable[[str, str, str, str], Any]


@dataclass(frozen=True)
class ManualHop:
    """One manual-trace step: a value clicked in one request and the
    earliest strictly-earlier request that holds the exact same value.

    Requests are metadata-only proxies in lazy captures, so hops never hold
    request/response content.
    """

    value: str
    from_request: HttpRequest
    found_request: HttpRequest | None
    locations: tuple[str, ...] = ()


SweepHit = tuple[str, str, tuple[str, ...]]  # (value, found request id, labels)


@dataclass(frozen=True)
class SweepResult:
    """Outcome of the optional one-level value sweep of one request.

    ``hits`` follows the source entry's value order (request side first);
    ``missing`` lists values with no earlier appearance (dead ends).
    """

    source_request_id: str
    hits: tuple[SweepHit, ...]
    checked: int
    missing: tuple[str, ...]


@dataclass(frozen=True)
class TabItem:
    """A tab label/content pair rendered by Flet 1's split tab controls."""

    text: str
    content: ft.Control


class TabbedView:
    """Manage Flet 1's TabBar + TabBarView composition as one tab set."""

    def __init__(
        self,
        tabs: list[TabItem],
        *,
        selected_index: int = 0,
        scrollable: bool = False,
        expand: bool = True,
        divider_color: str | None = None,
        indicator_color: str | None = None,
        label_color: str | None = None,
        unselected_label_color: str | None = None,
        empty_label: str = "No tabs yet",
        empty_content: ft.Control | None = None,
    ) -> None:
        self.tabs = tabs
        self._empty_tab = TabItem(
            empty_label,
            empty_content or ft.Text("No content to display.", color=MUTED),
        )
        self.tab_bar = ft.TabBar(
            tabs=[],
            scrollable=scrollable,
            divider_color=divider_color,
            indicator_color=indicator_color,
            label_color=label_color,
            unselected_label_color=unselected_label_color,
        )
        self.tab_bar_view = ft.TabBarView(controls=[], expand=True)
        self.control = ft.Tabs(
            length=1,
            content=ft.Column(
                controls=[self.tab_bar, self.tab_bar_view],
                expand=True,
                spacing=0,
            ),
            selected_index=selected_index,
            expand=expand,
        )
        self._sync()

    @property
    def selected_index(self) -> int:
        return self.control.selected_index

    @selected_index.setter
    def selected_index(self, value: int) -> None:
        self.control.selected_index = value

    def append(self, tab: TabItem) -> None:
        self.tabs.append(tab)
        self._sync()

    def replace(self, index: int, tab: TabItem) -> None:
        self.tabs[index] = tab
        self._sync()

    def _sync(self) -> None:
        visible_tabs = self.tabs or [self._empty_tab]
        self.tab_bar.tabs = [ft.Tab(label=tab.text) for tab in visible_tabs]
        self.tab_bar_view.controls = [tab.content for tab in visible_tabs]
        self.control.length = len(visible_tabs)
        if self.control.selected_index >= self.control.length:
            self.control.selected_index = 0


# Individual streaming rows stop at this size; bigger scopes fall back to a
# summarized counter so a 70,000-observation capture cannot flood the UI.
MAX_OBSERVED_STREAM_ROWS = 1200

# Browser transport metadata is useful for request inspection but normally is
# not application state produced by a prior response.
DEFAULT_IGNORED_HINTS = frozenset({
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "host",
    "pragma",
    "priority",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "user-agent",
})


def launch_gui(capture_path: str | Path | None = None,
               request_id: str | None = None) -> None:
    ft.run(
        lambda page: ReqvexaApp(page, capture_path, request_id),
        name="Reqvexa",
    )


class ReqvexaApp:
    def __init__(self, page: ft.Page, capture_path: str | Path | None,
                 request_id: str | None) -> None:
        self.page = page
        self.capture: Capture | None = None
        self.analysis: Analysis | None = None
        self.plan: FlowPlan | None = None
        self.report: dict[str, Any] | None = None
        # Depth of the most recent completed analysis, reused when the
        # sensitive-values switch re-renders its report.
        self.analysis_recursive: bool = True
        self.analysis_ignores_file_responses: bool = False
        self.target_id: str | None = request_id
        self.analysis_count = 0
        self.job_counter = 0
        self.active_job_id = 0
        self.analysis_tab_by_job: dict[int, int] = {}
        self.streaming_lists: dict[int, ft.ListView] = {}
        self.stream_totals: dict[int, int] = {}
        self.stream_summaries: dict[int, ft.Text] = {}
        self.latest_analysis_tab_index: int | None = None
        self.analysis_request_selections: dict[int, set[str]] = {}
        self.ignore_boxes: dict[str, ft.Checkbox] = {}
        self.ignore_groups: dict[str, tuple[str, ...]] = {}
        self.search_criteria_boxes: dict[str, ft.Checkbox] = {}
        self.search_criteria_dialog: ft.AlertDialog | None = None
        self.confirmation_dialog: ft.AlertDialog | None = None
        self.analysis_control_dialog: ft.AlertDialog | None = None
        self.code_dialog: ft.AlertDialog | None = None
        self.code_preview: ft.TextField | None = None
        self.code_async_switch: ft.Switch | None = None
        self.code_requests: tuple[HttpRequest, ...] = ()
        self.code_analysis: Analysis | None = None
        self.code_single_request = False
        self.save_dialog: ft.AlertDialog | None = None
        self.clipboard = ft.Clipboard()
        self._return_to_confirmation = False
        # Manual trace state: the request tracing started from and every hop
        # the user has recorded (one hop per value click, no automations).
        self.manual_hops: list[ManualHop] = []
        self.manual_origin: HttpRequest | None = None
        self.manual_open_id: str | None = None
        self.sweep_running: bool = False
        self.sweep_token: int = 0  # bumped to invalidate an in-flight sweep
        self.manual_flow_list: ft.ListView
        self.manual_detail: ft.Container
        # Ignore selections persist across target switches so a value chosen
        # on one request stays ignored for the capture and later requests.
        self.ignored_names: dict[str, bool] = {
            hint: True for hint in DEFAULT_IGNORED_HINTS
        }
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.cancel_event = threading.Event()
        self.traffic_detail_container: ft.Container
        self.traffic_list_container: ft.Container
        self._build()
        self.page.run_task(self._poll_events)
        if capture_path:
            self.path_field.value = str(capture_path)
            self._load_capture()

    def _build(self) -> None:
        page = self.page
        page.bgcolor = BG
        page.padding = 0
        page.theme = ft.Theme(color_scheme_seed=ACCENT)
        page.dark_theme = ft.Theme(color_scheme_seed=ACCENT)
        page.theme_mode = ft.ThemeMode.DARK
        page.window.min_width = 1080
        page.window.min_height = 700

        self.path_field = ft.TextField(
            hint_text="Path to HAR file", dense=True, filled=True,
            bgcolor=SURFACE_2, border_color=BORDER, expand=True,
            on_submit=lambda _: self._load_capture(),
        )
        self.search_field = ft.TextField(
            hint_text="Filter requests", prefix_icon=ft.Icons.SEARCH,
            dense=True, filled=True, bgcolor=SURFACE_2, border_color=BORDER,
            on_change=lambda _: self._render_request_list(),
        )
        self.search_criteria_boxes = {
            key: ft.Checkbox(
                label=label,
                value=True,
                on_change=lambda _: self._search_criteria_changed(),
            )
            for label, key in SEARCH_CRITERIA
        }
        self.search_criteria_button = ft.OutlinedButton(
            "Search criteria",
            icon=ft.Icons.FILTER_LIST,
            tooltip="Choose which request and response fields the filter searches.",
            on_click=lambda _: self._open_search_criteria(),
        )
        self.search_criteria_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Search criteria"),
            content=ft.Column([
                ft.Text(
                    "Case-insensitive search across the selected fields.",
                    color=MUTED,
                ),
                ft.Row([
                    ft.TextButton(
                        "Select all",
                        on_click=lambda _: self._set_all_search_criteria(True),
                    ),
                    ft.TextButton(
                        "Unselect all",
                        on_click=lambda _: self._set_all_search_criteria(False),
                    ),
                ]),
                ft.Text("Request", color=ACCENT, weight=ft.FontWeight.BOLD),
                ft.Column(
                    controls=[
                        self.search_criteria_boxes[key]
                        for _label, key in SEARCH_CRITERIA[:6]
                    ],
                    spacing=0,
                    tight=True,
                ),
                ft.Text("Response", color=ACCENT, weight=ft.FontWeight.BOLD),
                ft.Column(
                    controls=[
                        self.search_criteria_boxes[key]
                        for _label, key in SEARCH_CRITERIA[6:]
                    ],
                    spacing=0,
                    tight=True,
                ),
            ], tight=True, spacing=6, width=480, scroll=ft.ScrollMode.AUTO),
            actions=[
                ft.TextButton(
                    "Close", on_click=lambda _: self._close_search_criteria(),
                ),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        self.load_button = ft.FilledButton(
            "Load capture", icon=ft.Icons.FOLDER_OPEN, on_click=lambda _: self._load_capture()
        )
        self.analyze_button = ft.FilledButton(
            "Analyze target",
            icon=ft.Icons.PLAY_ARROW,
            on_click=lambda _: self._show_analysis_confirmation(),
        )
        self.recursive_switch = ft.Switch(
            label="Recursive", value=True,
            tooltip=(
                "On: follow every found value through the requests that "
                "produced it. Off: one level only - stop at the first "
                "response each value appeared in."
            ),
        )
        self.stop_button = ft.OutlinedButton(
            "Stop", icon=ft.Icons.STOP_CIRCLE, disabled=True, on_click=lambda _: self._stop()
        )
        self.reveal_switch = ft.Switch(
            label="Show sensitive values",
            value=True,
            on_change=lambda _: self._refresh_sensitive_views(),
        )
        self.ignore_file_responses_switch = ft.Switch(
            label="Ignore file responses",
            value=True,
            tooltip=(
                "Exclude static assets and downloadable-file responses from "
                "value matching; request-side values are still analyzed."
            ),
        )
        self.progress = ft.ProgressBar(value=0, color=ACCENT, bgcolor=BORDER, visible=False)
        self.status_text = ft.Text("Ready", size=12, color=MUTED)
        self.live_log = ft.ListView(
            expand=True, spacing=2, auto_scroll=True,
        )
        self.request_list = ft.ListView(
            expand=True, spacing=2, padding=0,
        )
        self.detail_panel = ft.Container(
            content=ft.Text("Select a request to inspect it.", color=MUTED),
            expand=True, padding=20,
        )
        self.ignore_panel = ft.Column(
            height=320,
            scroll=ft.ScrollMode.AUTO,
            spacing=6,
        )
        self._summary = ft.Text("No capture loaded", color=MUTED, size=12)

        header = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Text("Reqvexa", size=24, weight=ft.FontWeight.BOLD, color=TEXT),
                    ft.Container(expand=True),
                    ft.Text("Local traffic provenance", color=MUTED, size=12),
                ]),
                ft.Row([self.path_field, self.load_button]),
            ], spacing=10),
            padding=ft.Padding.only(left=22, right=22, top=18, bottom=14),
            border=ft.Border.only(bottom=ft.BorderSide(1, BORDER)),
        )
        controls = ft.Container(
            content=ft.Column([
                self.progress,
                ft.Row([self._summary, ft.Container(expand=True), self.status_text]),
            ], spacing=8),
            padding=ft.Padding.symmetric(horizontal=22, vertical=12),
            bgcolor=SURFACE,
        )
        self.main_tabs = TabbedView(
            [
                TabItem("Traffic", self._traffic_view()),
                TabItem("Manual", self._manual_view()),
                TabItem("Logs", self.live_log),
                TabItem("Analysis", self._analysis_view()),
            ],
            selected_index=0, expand=True, scrollable=True, divider_color=BORDER,
            indicator_color=ACCENT, label_color=TEXT, unselected_label_color=MUTED,
        )
        page.add(header, controls, self.main_tabs.control)

    def _traffic_view(self) -> ft.Control:
        self.traffic_detail = ft.Container(
            content=self.detail_panel,
            expand=True,
            padding=0,
            bgcolor=SURFACE,
        )
        self.traffic_list_container = ft.Container(
            content=self.request_list,
            expand=4,
            padding=ft.Padding.all(10),
            bgcolor="#0E1626",
            border=ft.Border.only(bottom=ft.BorderSide(1, BORDER)),
        )
        self.traffic_detail_container = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Text("Request / Response", color=ACCENT,
                            weight=ft.FontWeight.BOLD),
                    ft.Container(expand=True),
                    ft.Text("List height", color=MUTED, size=11),
                    ft.Slider(
                        min=20,
                        max=70,
                        value=40,
                        divisions=10,
                        width=150,
                        label="{value}%",
                        on_change=lambda event: self._resize_vertical_split(
                            event, self.traffic_list_container,
                            self.traffic_detail_container,
                        ),
                    ),
                    self.analyze_button,
                    self.stop_button,
                ]),
                self.traffic_detail,
            ], expand=True, spacing=8),
            expand=6,
            padding=ft.Padding.all(14),
            bgcolor=SURFACE,
        )
        return ft.Column([
            ft.Container(
                content=ft.Row([
                    ft.Text("Captured traffic", size=13, weight=ft.FontWeight.BOLD, color=TEXT),
                    ft.Container(expand=True),
                    ft.Text("Select a request to inspect it", color=MUTED, size=11),
                ]),
                padding=ft.Padding.only(left=16, right=16, top=12, bottom=8),
            ),
            ft.Container(
                content=ft.Row([
                    self.search_field,
                    self.search_criteria_button,
                ], spacing=8),
                padding=ft.Padding.symmetric(horizontal=16),
            ),
            self.traffic_list_container,
            self.traffic_detail_container,
        ], expand=True, spacing=0)

    def _manual_view(self) -> ft.Control:
        """The dedicated manual-analysis tab: the trace chain plus an
        inspector for the currently open trace request."""
        self.manual_flow_list = ft.ListView(expand=True, spacing=4)
        self.manual_detail = ft.Container(
            content=ft.Text(
                "Pick a request in Traffic, click one of its values, and the "
                "first request holding it appears here.",
                color=MUTED,
            ),
            expand=True,
            padding=20,
            bgcolor=SURFACE,
        )
        self.manual_list_container = ft.Container(
            content=self.manual_flow_list,
            expand=4,
            padding=ft.Padding.all(10),
            bgcolor="#0E1626",
            border=ft.Border.only(bottom=ft.BorderSide(1, BORDER)),
        )
        self.manual_detail_container = ft.Container(
            content=ft.Column([
                ft.Text("Traced request / Response", color=ACCENT,
                        weight=ft.FontWeight.BOLD),
                self.manual_detail,
            ], expand=True, spacing=8),
            expand=6,
            padding=ft.Padding.all(14),
            bgcolor=SURFACE,
        )
        sweep_button = ft.TextButton(
            "Sweep values",
            on_click=lambda _: self._start_value_sweep(),
        )
        sweep_button.tooltip = (
            "Trace every value on this request to the first earlier request "
            "holding it; found requests are appended to the chain, never "
            "searched further"
        )
        return ft.Column([
            ft.Container(
                content=ft.Row([
                    ft.Text("Manual trace", size=13, weight=ft.FontWeight.BOLD, color=TEXT),
                    ft.Container(expand=True),
                    ft.Text("Click a value to trace it - the copy icon copies it",
                            color=MUTED, size=11),
                    sweep_button,
                    ft.Text("Chain height", color=MUTED, size=11),
                    ft.Slider(
                        min=20,
                        max=70,
                        value=40,
                        divisions=10,
                        width=150,
                        label="{value}%",
                        on_change=lambda event: self._resize_vertical_split(
                            event, self.manual_list_container,
                            self.manual_detail_container,
                        ),
                    ),
                    ft.TextButton("Clear", on_click=lambda _: self._clear_manual_trace()),
                ], spacing=10),
                padding=ft.Padding.only(left=16, right=16, top=12, bottom=8),
            ),
            self.manual_list_container,
            self.manual_detail_container,
        ], expand=True, spacing=0)

    def _analysis_view(self) -> ft.Control:
        self.analysis_tabs = TabbedView(
            [],
            selected_index=0,
            scrollable=True,
            expand=True,
            divider_color=BORDER,
            indicator_color=ACCENT,
            label_color=TEXT,
            unselected_label_color=MUTED,
            empty_label="No analyses yet",
            empty_content=ft.Text(
                "Analyze a target request to see results here.", color=MUTED,
            ),
        )
        return ft.Column([
            ft.Container(
                content=ft.Row([
                    ft.Text("Analysis results", weight=ft.FontWeight.BOLD, color=TEXT),
                    ft.Container(expand=True),
                    ft.TextButton(
                        "Analysis Control",
                        icon=ft.Icons.FILTER_ALT,
                        on_click=lambda _: self._open_analysis_control(),
                    ),
                    ft.FilledButton(
                        "Analyze again",
                        icon=ft.Icons.PLAY_ARROW,
                        on_click=lambda _: self._show_analysis_confirmation(),
                    ),
                ]),
                padding=ft.Padding.only(left=16, right=16, top=14),
            ),
            self.analysis_tabs.control,
        ], expand=True, spacing=0)

    def _load_capture(self) -> None:
        path = (self.path_field.value or "").strip()
        if not path:
            self._notify("Choose a HAR file first.", RED)
            return
        job_id = self._begin("Loading capture")
        self._run_worker(
            lambda: HarProvider().load_file(path, lazy=True), self._capture_loaded, job_id
        )

    def _capture_loaded(self, capture: Any) -> None:
        self.capture = capture
        self.analysis = self.plan = self.report = None
        # Hop ids/values belong to the previous capture; start a clean trace.
        self.sweep_token += 1
        self.manual_hops.clear()
        self.manual_origin = None
        self.manual_open_id = None
        self.sweep_running = False
        self.manual_detail.content = self._manual_placeholder()
        self._render_manual_flow()
        ids = {request.id for request in capture.requests}
        self.target_id = self.target_id if self.target_id in ids else (
            capture.requests[-1].id if capture.requests else None
        )
        self._render_request_list()
        if self.target_id:
            self._show_request(self.target_id)
            self._build_ignore_options()
        self._summary.value = f"{len(capture.requests)} requests  /  {len(capture.responses)} responses"
        self._finish("Capture loaded")

    def _render_request_list(self) -> None:
        if self.capture is None:
            return
        needle = (self.search_field.value or "").casefold().strip()
        criteria = {
            key for key, checkbox in self.search_criteria_boxes.items()
            if checkbox.value
        }
        self.request_list.controls.clear()
        for request in self.capture.requests:
            label = f"{request.method} {_ui_path(request.url, self._show_sensitive())}"
            if needle and not self._request_matches_search(request, needle, criteria):
                continue
            response = _response_for(self.capture.responses, request.response_id)
            status = str(response.status) if response else "-"
            self.request_list.controls.append(ft.ListTile(
                title=ft.Text(label, size=12, color=TEXT, max_lines=1,
                              overflow=ft.TextOverflow.ELLIPSIS),
                subtitle=ft.Text(f"#{request.sequence}  {status}", size=11, color=MUTED),
                leading=ft.Container(
                    content=ft.Text(request.method[:3], size=10, weight=ft.FontWeight.BOLD,
                                    color=BG, text_align=ft.TextAlign.CENTER),
                    bgcolor=_method_color(request.method), width=38, height=24,
                    alignment=ft.Alignment(0, 0), border_radius=4,
                ),
                dense=True, selected=request.id == self.target_id,
                selected_tile_color="#1E3A5F",
                on_click=lambda _, request_id=request.id: self._select_request(request_id),
            ))
        self.page.update()

    def _request_matches_search(
        self,
        request: HttpRequest,
        needle: str,
        criteria: set[str],
    ) -> bool:
        """Search selected request/response fields without materializing a lazy capture."""
        def contains(value: Any) -> bool:
            if value is None:
                return False
            if isinstance(value, bytes):
                text = value.decode("utf-8", errors="replace")
            elif isinstance(value, (dict, list, tuple)):
                text = json.dumps(value, ensure_ascii=False, default=str)
            else:
                text = str(value)
            return needle in text.casefold()

        if "request_metadata" in criteria and contains((
            request.sequence, request.method, request.id,
            request.timestamp.isoformat() if request.timestamp else "",
        )):
            return True

        if "request_url" in criteria:
            parts = urlsplit(request.url)
            url_without_query = (
                f"{parts.scheme}://{parts.netloc}{parts.path}{parts.fragment}"
            )
            if contains(url_without_query):
                return True

        if "query_parameters" in criteria:
            query_values = [request.query, urlsplit(request.url).query]
            if contains(query_values):
                return True

        content_criteria = {
            "request_headers",
            "request_cookies",
            "request_body",
            "response_status",
            "response_headers",
            "response_cookies",
            "response_content",
        }
        if not (criteria & content_criteria) or self.capture is None:
            return False
        try:
            full_request, response = self.capture.view_entry(request.id)
        except (HarFormatError, OSError, KeyError, ValueError):
            return False

        if "request_headers" in criteria and contains([
            (header.name, header.value) for header in full_request.headers
        ]):
            return True

        if "request_cookies" in criteria and contains([
            (cookie.name, cookie.value, cookie.domain, cookie.path)
            for cookie in full_request.cookies
        ]):
            return True

        if "request_body" in criteria and (
            contains(full_request.body)
            or contains(full_request.raw.get("postData"))
        ):
            return True

        if response is None:
            return False

        if "response_status" in criteria and contains(response.status):
            return True

        if "response_headers" in criteria and contains([
            (header.name, header.value) for header in response.headers
        ]):
            return True

        if "response_cookies" in criteria and contains([
            (cookie.name, cookie.value, cookie.domain, cookie.path)
            for cookie in response.cookies
        ]):
            return True

        return "response_content" in criteria and (
            contains(response.body)
            or contains(response.raw.get("content"))
        )

    def _open_search_criteria(self) -> None:
        if self.search_criteria_dialog is not None:
            self.page.show_dialog(self.search_criteria_dialog)

    def _close_search_criteria(self) -> None:
        if self.search_criteria_dialog is not None:
            self.page.pop_dialog()

    def _search_criteria_changed(self) -> None:
        self._render_request_list()

    def _set_all_search_criteria(self, selected: bool) -> None:
        for checkbox in self.search_criteria_boxes.values():
            checkbox.value = selected
        self._render_request_list()

    def _select_request(self, request_id: str) -> None:
        self.target_id = request_id
        self._show_request(request_id)
        self._build_ignore_options()
        self._render_request_list()
        self.page.update()

    def _view_entry(self, request_id: str) -> tuple[HttpRequest, HttpResponse | None] | None:
        """Parse one entry for viewing; survives unreadable source files."""
        if self.capture is None:
            return None
        try:
            return self.capture.view_entry(request_id)
        except (HarFormatError, OSError) as error:
            self._notify(f"Cannot load entry content: {error}", RED)
            return None

    # --------------------------------------------------------- manual trace

    def _trace_inspector_value(self, request_id: str, kind: str, name: str,
                               value: str) -> None:
        """Manual trace: find the first request holding this exact value.

        Names are ignored deliberately; the click passes the raw value, the
        search compares literals only, and every hop is a single step the
        user chose - nothing recurses on the found request.
        """
        capture = self.capture
        if capture is None or len(value) < MANUAL_VALUE_MIN_CHARS:
            return
        try:
            origin = capture.request(request_id)
        except KeyError:
            return
        if self.manual_origin is None:
            self.manual_origin = origin
            self._render_manual_flow()
        display = SecretDisplayPolicy(unsafe_raw=self._show_sensitive()).display(value)
        origin_note = f" ({kind} '{name}')" if name else f" ({kind})"
        self._notify(
            f"Tracing {display!r}{origin_note} from request "
            f"#{origin.sequence}...", ACCENT,
        )

        def worker() -> None:
            try:
                result = _first_earlier_occurrence(
                    capture, request_id, value, capture.view_entry,
                )
            except Exception as error:  # surface worker failures in the UI
                self.events.put(("manual_error", (request_id, value, error)))
                return
            self.events.put(("manual_result", (request_id, value, result)))

        threading.Thread(target=worker, daemon=True, name="manual-trace").start()

    async def _copy_inspector_value(self, request_id: str, kind: str, name: str,
                                    value: str) -> None:
        """Put the exact raw value on the clipboard (copy icon clicks)."""
        try:
            await self.clipboard.set(value)
        except Exception as error:  # clipboard can be unavailable on some hosts
            self._notify(f"Copy failed: {error}", RED)
            return
        self._notify(
            f"Copied a {len(value):,}-character value to the clipboard.", MUTED,
        )

    def _start_value_sweep(self) -> None:
        """Optional batch mode of the manual trace: automatically search the
        first earlier appearance of EVERY traceable value on the currently
        open/selected request. Found requests are appended to the chain and
        nothing else - the sweep is one level deep, recursion stays manual."""
        capture = self.capture
        if capture is None:
            self._notify("Load a capture first.", AMBER)
            return
        if self.sweep_running:
            self._notify("A value sweep is already running.", AMBER)
            return
        request_id = self.manual_open_id or self.target_id
        if not request_id:
            self._notify("Select a request in Traffic to sweep it.", AMBER)
            return
        try:
            origin = capture.request(request_id)
        except KeyError:
            self._notify("Select a request in Traffic to sweep it.", AMBER)
            return
        self.sweep_running = True
        self.sweep_token += 1
        token = self.sweep_token

        def progress(done: int, total: int) -> None:
            self.events.put(("sweep_progress", (token, request_id, done, total)))

        def worker() -> None:
            try:
                result = _sweep_request_values(
                    capture, request_id, capture.view_entry, progress,
                )
            except Exception as error:  # surface worker failures in the UI
                self.events.put(("sweep_error", (token, error)))
                return
            self.events.put(("sweep_done", (token, result)))

        threading.Thread(target=worker, daemon=True, name="value-sweep").start()
        self._notify(
            f"Sweeping every value on request #{origin.sequence} to its "
            f"first appearance (one level)...", ACCENT,
        )

    def _sweep_done(self, payload: tuple[int, SweepResult]) -> None:
        """Record the sweep outcome: one hop per value, dead ends included."""
        token, result = payload
        if token != self.sweep_token:  # cleared or reloaded mid-sweep
            return
        self.sweep_running = False
        capture = self.capture
        if capture is None:
            return
        try:
            origin = capture.request(result.source_request_id)
        except KeyError:
            self._notify("Sweep source no longer exists (capture reloaded).",
                         AMBER)
            return
        if not result.hits and not result.missing:
            self._notify(
                f"Request #{origin.sequence} has no traceable values to sweep.",
                AMBER,
            )
            return
        existing = {(hop.from_request.id, hop.value) for hop in self.manual_hops}
        if self.manual_origin is None:
            self.manual_origin = origin
        additions: list[ManualHop] = []
        traced = dead = 0
        for value, found_id, locations in result.hits:
            if (origin.id, value) in existing:
                continue
            existing.add((origin.id, value))
            try:
                found_request = capture.request(found_id)
            except KeyError:
                continue
            additions.append(ManualHop(
                value=value, from_request=origin,
                found_request=found_request, locations=locations,
            ))
            traced += 1
        for value in result.missing:
            if (origin.id, value) in existing:
                continue
            existing.add((origin.id, value))
            additions.append(ManualHop(
                value=value, from_request=origin, found_request=None,
            ))
            dead += 1
        if not additions:
            self._notify(
                f"Every traceable value on request #{origin.sequence} is "
                f"already on the chain.", AMBER,
            )
            return
        self.manual_hops.extend(additions)
        self._render_manual_flow()
        # The swept request becomes the next manual-inspection surface: its
        # chain is complete (one level), and deeper hops can be picked by hand.
        self.main_tabs.selected_index = MANUAL_TAB_INDEX
        self._select_manual_request(origin.id)
        summary = (
            f"Sweep of request #{origin.sequence}: {traced} value"
            f"{'s' if traced != 1 else ''} traced to first appearance, "
            f"{dead} dead end{'s' if dead != 1 else ''} "
            f"({result.checked:,} earlier entries checked; one level, "
            f"nothing further searched)."
        )
        self._notify(summary, GREEN if traced else AMBER)

    def _manual_trace_done(self, payload: tuple[str, str,
                                               tuple[str, tuple[str, ...]] | None]) -> None:
        request_id, value, result = payload
        capture = self.capture
        if capture is None:
            return
        try:
            from_request = capture.request(request_id)
            found_request = capture.request(result[0]) if result is not None else None
        except KeyError:
            self._notify("Manual trace target no longer exists (capture reloaded).", AMBER)
            return
        locations = tuple(result[1]) if result is not None else ()
        self.manual_hops.append(ManualHop(
            value=value, from_request=from_request,
            found_request=found_request, locations=locations,
        ))
        self._render_manual_flow()
        masked = SecretDisplayPolicy(unsafe_raw=self._show_sensitive()).display(value)
        if found_request is None or result is None:
            self._notify(
                f"No earlier request holds {masked!r}; its first appearance is "
                f"request #{from_request.sequence} itself.", AMBER,
            )
            return
        self._notify(
            f"Value {masked!r} first appeared in request "
            f"#{found_request.sequence} ({locations[0]}).", GREEN,
        )
        # Surface the Manual tab and open the found request in its inspector
        # so the user can pick the next value from it.
        self.main_tabs.selected_index = MANUAL_TAB_INDEX
        self._select_manual_request(found_request.id)

    def _manual_placeholder(self) -> ft.Text:
        return ft.Text(
            "Pick a request in Traffic, click one of its values, and the "
            "first request holding it appears here.",
            color=MUTED,
        )

    def _select_manual_request(self, request_id: str) -> None:
        """Open one request in the Manual tab's inspector; its values stay
        clickable so the trace continues from there."""
        self.manual_open_id = request_id
        pair = self._view_entry(request_id)
        if pair is None:
            self.manual_detail.content = ft.Text(
                "This entry's content could not be re-read from the capture file.",
                color=RED,
            )
            self.page.update()
            return
        request, response = pair
        self.manual_detail.content = _traffic_detail(
            request, response, unsafe_raw=self._show_sensitive(),
            on_value=self._trace_inspector_value,
            on_copy=self._copy_inspector_value,
        )
        self.page.update()

    def _render_manual_flow(self) -> None:
        """Rebuild the Manual tab chain: origin card, one card per hop."""
        unsafe_raw = self._show_sensitive()
        controls: list[ft.Control] = []
        origin = self.manual_origin
        if origin is not None:
            controls.append(self._manual_card(
                origin,
                headline=f"#{origin.sequence} {origin.method} "
                         f"{_ui_path(origin.url, unsafe_raw)}",
                note="trace origin",
                openable=True,
            ))
            for hop in self.manual_hops:
                display = SecretDisplayPolicy(unsafe_raw=unsafe_raw).display(hop.value)
                if hop.found_request is None:
                    controls.append(self._manual_card(
                        hop.from_request,
                        headline=f"{display}",
                        note=f"#{hop.from_request.sequence} dead end - "
                             f"no earlier appearance",
                        openable=False,
                    ))
                else:
                    controls.append(self._manual_card(
                        hop.found_request,
                        headline=f"#{hop.found_request.sequence} "
                                 f"{hop.found_request.method} "
                                 f"{_ui_path(hop.found_request.url, unsafe_raw)}",
                        note=f"first held {display} ({hop.locations[0]})",
                        openable=True,
                    ))
        self.manual_flow_list.controls = controls
        self.page.update()

    def _manual_card(self, request: HttpRequest, headline: str, note: str,
                     openable: bool) -> ft.Container:
        """A chain card in the Manual tab; openable cards open their request
        in the manual inspector so the next value can be picked from it."""
        card = ft.Container(
            content=ft.Column([
                ft.Text(note, color=MUTED, size=10,
                        max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                ft.Text(headline, color=TEXT, size=11, max_lines=2,
                        overflow=ft.TextOverflow.ELLIPSIS,
                        font_family="Cascadia Mono"),
            ], spacing=3),
            padding=10,
            bgcolor=SURFACE,
            border=ft.Border.all(1, BORDER if openable else "#3A2A2A"),
            border_radius=6,
            on_click=(lambda _, request_id=request.id:
                      self._select_manual_request(request_id))
            if openable else None,
        )
        if openable:
            card.tooltip = "Open this result to preview its captured request and response."
        return card

    def _clear_manual_trace(self) -> None:
        self.sweep_token += 1  # an in-flight sweep must not repopulate
        self.sweep_running = False
        self.manual_hops.clear()
        self.manual_origin = None
        self.manual_open_id = None
        self.manual_detail.content = self._manual_placeholder()
        self._render_manual_flow()

    def _show_request(self, request_id: str) -> None:
        pair = self._view_entry(request_id)
        if pair is None:
            self.detail_panel.content = ft.Text(
                "This entry's content could not be re-read from the capture file.",
                color=RED,
            )
            self.page.update()
            return
        request, response = pair
        self.detail_panel.content = _traffic_detail(
            request, response, unsafe_raw=self._show_sensitive(),
            on_value=self._trace_inspector_value,
            on_copy=self._copy_inspector_value,
        )
        self.page.update()

    def _build_ignore_options(self) -> None:
        if self.capture is None or self.target_id is None:
            return
        pair = self._view_entry(self.target_id)
        if pair is None:
            return
        request, _response = pair
        available_groups = _request_ignore_groups(request)
        visible_groups: dict[str, tuple[str, ...]] = {}
        self.ignore_boxes = {}
        option_limit = 200
        for section, names in available_groups.items():
            visible: list[str] = []
            for name in names:
                if name in self.ignore_boxes:
                    continue
                if len(self.ignore_boxes) >= option_limit:
                    break
                checkbox = ft.Checkbox(
                    label=name,
                    # The control is an include-list: checked means this
                    # target field participates in tracing. New fields start
                    # unchecked until the user opts them in.
                    value=not self.ignored_names.get(
                        name, True,
                    ),
                    on_change=self._ignore_toggled,
                )
                self.ignore_boxes[name] = checkbox
                visible.append(name)
            if visible:
                visible_groups[section] = tuple(visible)
        self.ignore_groups = visible_groups
        persistent_only = [
            name for name, checked in sorted(self.ignored_names.items())
            if checked and name not in self.ignore_boxes
        ]
        sections: list[ft.Control] = []
        for section, names in visible_groups.items():
            sections.append(ft.Text(
                section, color=ACCENT, size=11, weight=ft.FontWeight.BOLD,
            ))
            sections.append(ft.GridView(
                controls=[
                    ft.Container(
                        content=self.ignore_boxes[name],
                        height=28,
                        padding=0,
                        alignment=ft.Alignment(0, 0),
                    )
                    for name in names
                ],
                runs_count=4,
                height=min(4, (len(names) + 3) // 4) * 30,
                spacing=0,
                run_spacing=0,
                child_aspect_ratio=9.0,
                padding=0,
            ))
        if not sections:
            sections.append(ft.Text(
                "No named values detected in this request.",
                color=MUTED, size=12,
            ))
        if persistent_only:
            sections.append(ft.Text(
                f"Also excluded ({len(persistent_only)} from other requests): "
                + ", ".join(persistent_only[:12]),
                color=MUTED, size=11,
                overflow=ft.TextOverflow.ELLIPSIS,
            ))
        if sum(map(len, available_groups.values())) > option_limit:
            sections.append(ft.Text(
                f"Showing the first {option_limit} names; narrow the target "
                "request to see other names.",
                color=MUTED, size=10,
            ))
        self.ignore_panel.controls = sections
        self.page.update()

    def _ignore_toggled(self, event: ft.ControlEvent | None) -> None:
        """Persist include-checkbox state as the engine's ignore set."""
        for hint, checkbox in self.ignore_boxes.items():
            self.ignored_names[hint] = not bool(checkbox.value)

    def _set_all_trace_values(self, selected: bool) -> None:
        """Include or exclude every known field, then refresh its sections."""
        self._ignore_toggled(None)
        known_names = set(self.ignored_names) | set(self.ignore_boxes)
        for name in known_names:
            self.ignored_names[name] = not selected
        for checkbox in self.ignore_boxes.values():
            checkbox.value = selected
        self._build_ignore_options()

    def _set_all_ignored(self, selected: bool) -> None:
        """Compatibility wrapper; ``selected`` now means include for tracing."""
        self._set_all_trace_values(selected)

    def _ignored_selection(self) -> set[str]:
        """Every excluded name: current panel checks plus persisted ones."""
        self._ignore_toggled(None)
        return {name for name, checked in self.ignored_names.items() if checked}

    def _show_analysis_confirmation(self) -> None:
        """Open the run-options dialog before starting a new analysis."""
        if self.capture is None or self.target_id is None:
            self._notify("Load a capture and select a target request.", RED)
            return
        self._ignore_toggled(None)
        self._build_ignore_options()
        self._display_analysis_confirmation()

    def _display_analysis_confirmation(self) -> None:
        self.confirmation_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Confirm analysis"),
            content=ft.Column([
                ft.Text(
                    "Review the analysis options, then choose which target "
                    "request fields to trace.",
                    color=MUTED,
                ),
                self.recursive_switch,
                self.reveal_switch,
                self.ignore_file_responses_switch,
                ft.OutlinedButton(
                    "Analysis Control",
                    icon=ft.Icons.FILTER_ALT,
                    on_click=lambda _: self._open_analysis_control(),
                ),
            ], tight=True, spacing=12, width=520),
            actions=[
                ft.TextButton(
                    "Cancel", on_click=lambda _: self._close_analysis_confirmation(),
                ),
                ft.FilledButton(
                    "Analyze target",
                    icon=ft.Icons.PLAY_ARROW,
                    on_click=lambda _: self._confirm_analysis(),
                ),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        self.page.show_dialog(self.confirmation_dialog)

    def _open_analysis_control(self) -> None:
        """Show the grouped include-list in its own modal window."""
        if self.capture is None or self.target_id is None:
            self._notify("Load a capture and select a target request first.", RED)
            return
        self._ignore_toggled(None)
        self._build_ignore_options()
        self._return_to_confirmation = bool(
            self.confirmation_dialog is not None
            and self.confirmation_dialog.open
        )
        if self._return_to_confirmation and self.confirmation_dialog is not None:
            self.page.pop_dialog()
        self.analysis_control_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Analysis Control"),
            content=ft.Column([
                ft.Text(
                    "Checked fields are included in tracing. Uncheck fields "
                    "you do not want to trace.",
                    color=MUTED,
                ),
                ft.Row([
                    ft.TextButton(
                        "Select all",
                        on_click=lambda _: self._set_all_trace_values(True),
                    ),
                    ft.TextButton(
                        "Unselect all",
                        on_click=lambda _: self._set_all_trace_values(False),
                    ),
                ]),
                self.ignore_panel,
            ], tight=True, spacing=8, width=640),
            actions=[
                ft.FilledButton(
                    "Done", on_click=lambda _: self._close_analysis_control(),
                ),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        self.page.show_dialog(self.analysis_control_dialog)

    def _close_analysis_control(self) -> None:
        if self.analysis_control_dialog is not None:
            self.page.pop_dialog()
        return_to_confirmation = self._return_to_confirmation
        self._return_to_confirmation = False
        if return_to_confirmation:
            self._display_analysis_confirmation()

    def _close_analysis_confirmation(self) -> None:
        if self.confirmation_dialog is not None:
            self.page.pop_dialog()

    def _confirm_analysis(self) -> None:
        self._close_analysis_confirmation()
        self._analyze()

    def _analyze(self) -> None:
        if self.capture is None or self.target_id is None:
            self._notify("Load a capture and select a target request.", RED)
            return
        ignored = self._ignored_selection()
        recursive = bool(self.recursive_switch.value)
        ignore_file_responses = bool(self.ignore_file_responses_switch.value)
        job_id = self._begin("Analyzing target")
        self._create_streaming_analysis_tab(job_id, self.target_id)
        self._run_worker(
            lambda: ProvenanceEngine().analyze(
                self.capture, target_request_id=self.target_id, ignored_hints=ignored,
                ignored_value_names=ignored, recursive=recursive,
                ignore_file_responses=ignore_file_responses,
                progress_callback=lambda stage, current, total, message:
                    self._progress(job_id, stage, current, total, message),
                observation_callback=lambda request_id, sequence, observations:
                    self._observations_progress(job_id, request_id, sequence, observations),
                cancel_event=self.cancel_event,
            ),
            lambda analysis: self._analysis_ready(
                job_id, analysis, recursive, ignore_file_responses,
            ),
            job_id,
        )

    def _analysis_ready(self, job_id: int, analysis: Analysis,
                        recursive: bool,
                        ignore_file_responses: bool = False) -> None:
        if job_id != self.active_job_id:
            return
        if self.target_id is None:
            return
        self.analysis = analysis
        self.analysis_recursive = recursive
        self.analysis_ignores_file_responses = ignore_file_responses
        self.plan = plan_flow(analysis, self.target_id, recursive=recursive)
        self.report = safe_report(
            analysis,
            self.target_id,
            unsafe_raw=bool(self.reveal_switch.value),
            recursive=recursive,
        )
        self.analysis_count += 1
        self._complete_analysis_tab(
            job_id,
            self.analysis_count,
            self.target_id,
            self.plan,
            self.report,
            analysis,
        )
        self._summary.value = (
            f"{len(self.plan.steps)} planned steps  /  "
            f"{len(self.report['values'])} traced values  /  "
            f"{len(self.plan.unresolved_values)} unresolved"
        )
        self._finish("Analysis complete")

    def _create_streaming_analysis_tab(self, job_id: int, target_id: str) -> None:
        capture = self.capture
        if capture is None:
            return
        target = capture.request(target_id)
        stream = ft.ListView(expand=True, spacing=4)
        self.streaming_lists[job_id] = stream
        self.stream_totals[job_id] = 0
        self.stream_summaries.pop(job_id, None)
        self.analysis_tabs.append(TabItem(
            text=f"Analysis {self.analysis_count + 1:02d} - running",
            content=ft.Column([
                ft.Container(
                    content=ft.Text(
                        f"Scanning capture for dependencies of request #{target.sequence}...",
                        color=ACCENT,
                    ),
                    padding=ft.Padding.all(14),
                ),
                stream,
            ], expand=True, spacing=0),
        ))
        self.analysis_tab_by_job[job_id] = len(self.analysis_tabs.tabs) - 1
        self.analysis_tabs.selected_index = len(self.analysis_tabs.tabs) - 1
        self.main_tabs.selected_index = ANALYSIS_TAB_INDEX
        self.page.update()

    def _complete_analysis_tab(self, job_id: int, ordinal: int, target_id: str,
                               plan: FlowPlan, report: dict[str, Any],
                               analysis: Analysis | None = None) -> None:
        capture = self.capture
        if capture is None:
            return
        target = capture.request(target_id)
        tab_index = self.analysis_tab_by_job[job_id]
        self.analysis_tabs.replace(
            tab_index,
            TabItem(
                text=f"Analysis {ordinal:02d} - #{target.sequence}",
                content=self._analysis_result_view(
                    plan, report, tab_index=tab_index, analysis=analysis,
                ),
            ),
        )
        self.analysis_tabs.selected_index = tab_index
        self.latest_analysis_tab_index = tab_index
        # Flet can retain the previously selected inner tab when a new result
        # replaces its running placeholder, so explicitly focus the new result
        # at both tab levels.
        self.main_tabs.selected_index = ANALYSIS_TAB_INDEX
        self.analysis_tabs.selected_index = tab_index
        self.streaming_lists.pop(job_id, None)
        self.stream_totals.pop(job_id, None)
        self.stream_summaries.pop(job_id, None)
        self.analysis_tab_by_job.pop(job_id, None)
        self.page.update()

    def _analysis_result_view(
        self,
        plan: FlowPlan,
        report: dict[str, Any],
        *,
        tab_index: int | None = None,
        analysis: Analysis | None = None,
    ) -> ft.Control:
        capture = self.capture
        if capture is None:
            return ft.Text("Capture is no longer available.", color=RED)
        if analysis is None:
            analysis = self.analysis
        step_ids = {step.request_id for step in plan.steps}
        if tab_index is None:
            selected_request_ids = set(step_ids)
        else:
            selected_request_ids = self.analysis_request_selections.setdefault(
                tab_index, set(step_ids),
            )
            selected_request_ids.intersection_update(step_ids)

        flow_list = ft.ListView(
            expand=True, spacing=4,
        )
        selection_count = ft.Text(color=MUTED, size=11)
        request_selection_boxes: dict[str, ft.Checkbox] = {}
        value_grid = ft.GridView(
            runs_count=3,
            expand=True,
            spacing=8,
            run_spacing=8,
            child_aspect_ratio=3.1,
        )
        analysis_detail = ft.Container(
            content=ft.Text("Select a flow request to inspect it.", color=MUTED),
            expand=True,
            bgcolor=SURFACE,
        )
        flow_container = ft.Container(
            content=flow_list,
            expand=4,
            padding=ft.Padding.all(10),
        )
        detail_container = ft.Container(
            content=ft.Column([
                ft.Text("Request / Response", color=ACCENT,
                        weight=ft.FontWeight.BOLD),
                analysis_detail,
            ], expand=True, spacing=8),
            expand=6,
            padding=ft.Padding.all(14),
            bgcolor=SURFACE,
        )
        split_slider = ft.Slider(
            min=20,
            max=70,
            value=40,
            divisions=10,
            width=150,
            label="{value}%",
            on_change=lambda event: self._resize_vertical_split(
                event, flow_container, detail_container
            ),
        )

        def refresh_request_selection() -> None:
            selection_count.value = (
                f"{len(selected_request_ids)} of {len(plan.steps)} requests selected"
            )
            self.page.update()

        def select_requests(selected: bool) -> None:
            selected_request_ids.clear()
            if selected:
                selected_request_ids.update(step_ids)
            for checkbox in request_selection_boxes.values():
                checkbox.value = selected
            refresh_request_selection()

        def request_selection_changed(event: Any, request_id: str) -> None:
            if event.control.value:
                selected_request_ids.add(request_id)
            else:
                selected_request_ids.discard(request_id)
            refresh_request_selection()

        def generate_selected_requests(_: Any = None) -> None:
            selected_ids = set(selected_request_ids)
            if not selected_ids:
                self._notify("Select at least one request to generate code.", AMBER)
                return
            selected_requests: list[HttpRequest] = []
            try:
                for step in plan.steps:
                    if step.request_id in selected_ids:
                        request, _response = capture.view_entry(step.request_id)
                        selected_requests.append(request)
            except (HarFormatError, OSError, KeyError) as error:
                self._notify(f"Cannot load request for code generation: {error}", RED)
                return
            self._open_code_generation(tuple(selected_requests), analysis=analysis)

        def generate_single_request(_: Any = None) -> None:
            selected_ids = set(selected_request_ids)
            if len(selected_ids) != 1:
                self._notify(
                    "Select exactly one request to generate a standalone request.",
                    AMBER,
                )
                return
            request_id = next(iter(selected_ids))
            try:
                request, _response = capture.view_entry(request_id)
            except (HarFormatError, OSError, KeyError) as error:
                self._notify(f"Cannot load request for code generation: {error}", RED)
                return
            self._open_code_generation(
                (request,), analysis=analysis, single_request=True,
            )

        for step in plan.steps:
            checkbox = ft.Checkbox(
                value=step.request_id in selected_request_ids,
                tooltip="Include this request in generated code",
                on_change=lambda event, request_id=step.request_id:
                    request_selection_changed(event, request_id),
            )
            request_selection_boxes[step.request_id] = checkbox
            flow_list.controls.append(ft.Row([
                checkbox,
                ft.Container(
                    content=ft.Row([
                        ft.Text(f"{step.sequence:04d}", width=55, color=MUTED, size=12),
                        _badge(step.role, GREEN if step.role == "target" else ACCENT),
                        ft.Text(step.method, width=58, color=_method_color(step.method),
                                weight=ft.FontWeight.BOLD),
                        ft.Text(
                            _ui_path(
                                capture.request(step.request_id).url,
                                self._show_sensitive(),
                            ),
                            expand=True, color=TEXT, max_lines=1,
                            overflow=ft.TextOverflow.ELLIPSIS,
                        ),
                        ft.Text(
                            "-> " + ", ".join(step.produces) if step.produces else "",
                            width=180, color=VALUE_COLOR, size=11,
                        ),
                    ], spacing=8),
                    expand=True,
                    padding=ft.Padding.symmetric(horizontal=12, vertical=9),
                    bgcolor=SURFACE_2,
                    border_radius=6,
                    on_click=lambda _, request_id=step.request_id:
                        self._show_analysis_request(analysis_detail, request_id),
                ),
            ], spacing=4))
        refresh_request_selection()

        request_selection_toolbar = ft.Row([
            ft.Text("Requests to generate", color=TEXT, weight=ft.FontWeight.BOLD),
            selection_count,
            ft.Container(expand=True),
            ft.TextButton(
                "Select all", on_click=lambda _: select_requests(True),
            ),
            ft.TextButton(
                "Unselect all", on_click=lambda _: select_requests(False),
            ),
            ft.FilledButton(
                "Generate Python",
                icon=ft.Icons.CODE,
                on_click=generate_selected_requests,
            ),
            ft.OutlinedButton(
                "Generate Single Request",
                icon=ft.Icons.CODE,
                on_click=generate_single_request,
            ),
        ], spacing=8)
        value_grid.controls = [
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Text(value["name"], color=NAME_COLOR, weight=ft.FontWeight.BOLD),
                        _badge(value["status"], _status_color(value["status"])),
                        ft.Container(expand=True),
                        ft.Text(value["display_value"], color=VALUE_COLOR, size=12),
                    ]),
                    ft.Text(
                        f"version {value['version_id']}  |  digest {value['value_digest']}",
                        color=MUTED, size=10,
                    ),
                ], spacing=5),
                padding=ft.Padding.all(10),
                bgcolor="#123126" if value["producers"] else SURFACE_2,
                border=ft.Border.all(1, GREEN if value["producers"] else BORDER),
                border_radius=6,
            )
            for value in report["values"]
        ]
        unresolved = plan.unresolved_values
        values_panel: list[ft.Control] = [
            ft.Text(f"{len(report['values'])} traced values", color=MUTED, size=12),
            ft.Container(content=value_grid, expand=True),
        ]
        if unresolved:
            values_panel.insert(1, ft.Container(
                content=ft.Text(
                    "Unresolved: " + ", ".join(unresolved),
                    color=AMBER, size=11, selectable=True,
                ),
                bgcolor="#3B2F14",
                padding=ft.Padding.all(10),
                border_radius=6,
            ))
        return ft.Column([
            ft.Container(
                content=ft.Row([
                    ft.Text(
                        f"{len(plan.steps)} requests required for this flow",
                        color=TEXT, weight=ft.FontWeight.BOLD,
                    ),
                    _badge(
                        "recursive" if self.analysis_recursive else "one level",
                        ACCENT if self.analysis_recursive else AMBER,
                    ),
                    *(
                        [_badge("file responses ignored", AMBER)]
                        if self.analysis_ignores_file_responses else []
                    ),
                    ft.Container(expand=True),
                    ft.Text("List height", color=MUTED, size=11),
                    split_slider,
                    ft.Text(
                        "Observational plan - no requests are sent",
                        color=MUTED, size=11,
                    ),
                ]),
                padding=ft.Padding.all(14),
            ),
            TabbedView(
                [
                    TabItem("Required requests", ft.Column([
                        request_selection_toolbar,
                        flow_container,
                        detail_container,
                    ], expand=True, spacing=0)),
                    TabItem("Values", ft.Column(values_panel, expand=True)),
                ],
                selected_index=0,
                expand=True,
            ).control,
        ], expand=True, spacing=0)

    def _show_analysis_request(self, detail: ft.Container, request_id: str) -> None:
        pair = self._view_entry(request_id)
        if pair is None:
            detail.content = ft.Text(
                "This entry's content could not be re-read from the capture file.",
                color=RED,
            )
            self.page.update()
            return
        request, response = pair
        detail.content = _traffic_detail(
            request, response, unsafe_raw=self._show_sensitive(),
            on_value=self._trace_inspector_value,
            on_copy=self._copy_inspector_value,
        )
        self.page.update()

    def _open_code_generation(
        self,
        requests: tuple[HttpRequest, ...],
        *,
        analysis: Analysis | None = None,
        single_request: bool = False,
    ) -> None:
        self.code_requests = requests
        self.code_analysis = None if single_request else analysis
        self.code_single_request = single_request
        self.code_async_switch = ft.Switch(
            label="Asynchronous (asyncio)",
            value=False,
            on_change=lambda _: self._refresh_generated_code(),
        )
        self.code_preview = ft.TextField(
            value=generate_python(
                requests,
                analysis=self.code_analysis,
                single_request=single_request,
            ),
            multiline=True,
            read_only=True,
            expand=True,
            text_size=11,
            bgcolor="#0B1120",
            border_color=BORDER,
        )
        self.code_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text(
                "Generated Python single request"
                if single_request else "Generated Python request flow"
            ),
            content=ft.Column([
                ft.Text(
                    (
                        "Standalone replay of this captured request. Captured "
                        "values are kept as-is rather than linked to earlier "
                        "responses. Review credentials before sharing."
                        if single_request else
                        f"{len(requests)} captured request(s). This code includes "
                        "captured headers, cookies, query values, and payloads; "
                        "review it before sharing."
                    ),
                    color=AMBER,
                    size=12,
                ),
                self.code_async_switch,
                ft.Container(
                    content=self.code_preview,
                    width=900,
                    height=520,
                ),
            ], width=920, height=590, spacing=10),
            actions=[
                ft.TextButton(
                    "Close", on_click=lambda _: self._close_code_generation(),
                ),
                ft.TextButton(
                    "Save .py", on_click=lambda _: self._save_generated_code(),
                ),
                ft.FilledButton(
                    "Copy code",
                    icon=ft.Icons.CONTENT_COPY,
                    on_click=lambda _: self._copy_generated_code(),
                ),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        self.page.show_dialog(self.code_dialog)

    def _refresh_generated_code(self) -> None:
        if self.code_preview is None or self.code_async_switch is None:
            return
        self.code_preview.value = generate_python(
            self.code_requests,
            analysis=self.code_analysis,
            asynchronous=bool(self.code_async_switch.value),
            single_request=self.code_single_request,
        )
        self.page.update()

    async def _copy_generated_code(self) -> None:
        if self.code_preview is None or not self.code_preview.value:
            return
        try:
            await self.clipboard.set(self.code_preview.value)
        except Exception as error:
            self._notify(f"Copy failed: {error}", RED)
            return
        self._notify("Generated Python code copied to the clipboard.", GREEN)

    def _save_generated_code(self) -> None:
        if self.code_preview is None or not self.code_preview.value:
            return
        self._save_dialog(".py", "Python code", self.code_preview.value)

    def _close_code_generation(self) -> None:
        if self.code_dialog is not None and self.code_dialog.open:
            self.page.pop_dialog()

    def _resize_vertical_split(self, event: Any, upper: ft.Container,
                               lower: ft.Container) -> None:
        upper_ratio = max(20, min(70, round(event.control.value)))
        upper.expand = upper_ratio
        lower.expand = 100 - upper_ratio
        self.page.update()

    def _refresh_sensitive_views(self) -> None:
        if self.report is not None and self.target_id is not None and self.analysis is not None:
            self.report = safe_report(
                self.analysis,
                self.target_id,
                unsafe_raw=bool(self.reveal_switch.value),
                recursive=self.analysis_recursive,
            )
            self._notify(
                "Sensitive values shown." if self.reveal_switch.value
                else "Sensitive values masked.",
                AMBER if self.reveal_switch.value else GREEN,
            )
        if self.capture is not None and self.target_id is not None:
            self._render_request_list()
            self._show_request(self.target_id)
            self._render_manual_flow()
            if self.manual_open_id is not None:
                self._select_manual_request(self.manual_open_id)
        if self.analysis is not None and self.plan is not None and self.target_id is not None:
            self.report = safe_report(
                self.analysis,
                self.target_id,
                unsafe_raw=bool(self.reveal_switch.value),
                recursive=self.analysis_recursive,
            )
            if self.latest_analysis_tab_index is not None:
                self.analysis_tabs.replace(
                    self.latest_analysis_tab_index,
                    TabItem(
                        text=f"Analysis {self.analysis_count:02d}",
                        content=self._analysis_result_view(
                            self.plan,
                            self.report,
                            tab_index=self.latest_analysis_tab_index,
                            analysis=self.analysis,
                        ),
                    ),
                )
        self.page.update()

    def _show_sensitive(self) -> bool:
        return bool(self.reveal_switch.value)

    def _save_json(self) -> None:
        if self.report is None:
            self._notify("Analyze a target first.", AMBER)
            return
        self._save_dialog(".json", "JSON report",
                          json.dumps(self.report, indent=2, sort_keys=True) + "\n")

    def _save_markdown(self) -> None:
        if self.report is None:
            self._notify("Analyze a target first.", AMBER)
            return
        self._save_dialog(".md", "Markdown report", report_markdown(self.report))

    def _save_dialog(self, extension: str, label: str, payload: str) -> None:
        field = ft.TextField(label="Output path", autofocus=True)
        self.save_dialog = ft.AlertDialog(
            modal=True, title=ft.Text(f"Save {label}"), content=field,
            actions=[
                ft.TextButton("Cancel", on_click=lambda _: self._close_dialog()),
                ft.FilledButton(
                    "Save",
                    on_click=lambda _: self._write_dialog(field.value, payload, extension),
                ),
            ],
        )
        self.page.show_dialog(self.save_dialog)

    def _write_dialog(self, path: str | None, payload: str, extension: str) -> None:
        if not path:
            return
        output = Path(path)
        if output.suffix.lower() != extension:
            output = output.with_suffix(extension)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
        self._close_dialog()
        self._notify(f"Saved {output}", GREEN)

    def _close_dialog(self) -> None:
        if self.save_dialog is not None and self.save_dialog.open:
            self.page.pop_dialog()

    def _stop(self) -> None:
        self.cancel_event.set()
        self.stop_button.disabled = True
        self._log("Stop requested; finishing the current extraction unit...", AMBER)
        self.page.update()

    def _begin(self, label: str) -> int:
        self.job_counter += 1
        self.active_job_id = self.job_counter
        self.cancel_event = threading.Event()
        self.progress.visible = True
        self.progress.value = 0
        self.load_button.disabled = True
        self.analyze_button.disabled = True
        self.stop_button.disabled = False
        self._log(label, ACCENT)
        self.page.update()
        return self.active_job_id

    def _finish(self, label: str) -> None:
        self.progress.visible = False
        self.load_button.disabled = False
        self.analyze_button.disabled = False
        self.stop_button.disabled = True
        self.status_text.value = label
        self.page.update()

    def _progress(self, job_id: int, stage: str, current: int,
                  total: int, message: str) -> None:
        self.events.put(("progress", (job_id, stage, current, total, message)))

    def _observations_progress(self, job_id: int, request_id: str, sequence: int,
                               observations: tuple[ValueObservation, ...]) -> None:
        self.events.put(("observations", (job_id, request_id, sequence, observations)))

    def _run_worker(self, operation: Any, callback: Any, job_id: int) -> None:
        def worker() -> None:
            try:
                self.events.put(("progress", (job_id, "start", 0, 1, "Worker started")))
                self.events.put(("result", (job_id, callback, operation())))
            except AnalysisCancelled:
                self.events.put(("cancelled", job_id))
            except Exception as error:  # surface worker failures in the UI
                self.events.put(("error", (job_id, error)))
        threading.Thread(target=worker, daemon=True).start()

    async def _poll_events(self) -> None:
        while True:
            handled = 0
            dirty = False
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.1)
                continue
            while True:
                if kind == "progress":
                    job_id, stage, current, total, message = payload
                    if job_id == self.active_job_id:
                        self.progress.value = min(1.0, current / total) if total else None
                        self.status_text.value = f"{stage}: {message}"
                        if stage in {"extract", "scope", "versions", "graph", "complete"}:
                            self._log(message, MUTED)
                        dirty = True
                elif kind == "observations":
                    job_id, _request_id, sequence, observations = payload
                    if job_id == self.active_job_id:
                        stream = self.streaming_lists.get(job_id)
                        if stream is not None:
                            total = self.stream_totals.get(job_id, 0) + len(observations)
                            self.stream_totals[job_id] = total
                            summary = self.stream_summaries.get(job_id)
                            if total <= MAX_OBSERVED_STREAM_ROWS:
                                for observation in observations:
                                    name = _observation_name(observation)
                                    display = SecretDisplayPolicy(
                                        unsafe_raw=bool(self.reveal_switch.value)
                                    ).display(observation.normalized_value)
                                    stream.controls.append(ft.Container(
                                        content=ft.Row([
                                            ft.Text(f"{sequence:04d}", width=55, color=MUTED, size=11),
                                            ft.Text(name, color=NAME_COLOR, size=11,
                                                    weight=ft.FontWeight.BOLD),
                                            ft.Text(display, color=VALUE_COLOR, size=11,
                                                    selectable=True, expand=True),
                                            ft.Text(observation.location.container, color=MUTED, size=10),
                                        ], spacing=8),
            padding=ft.Padding.symmetric(horizontal=10, vertical=7),
                                        bgcolor=SURFACE_2,
                                        border_radius=6,
                                    ))
                            else:
                                # Flooded scope: stop building per-row controls
                                # and keep one live counter so the UI thread
                                # stays responsive on huge captures.
                                if summary is None:
                                    summary = ft.Text(
                                        f"{MAX_OBSERVED_STREAM_ROWS:,} observations scanned",
                                        color=MUTED, size=11, selectable=True,
                                    )
                                    self.stream_summaries[job_id] = summary
                                    stream.controls = [summary]
                                summary.value = (
                                    f"{total:,} observations scanned"
                                    f" (row previews capped at "
                                    f"{MAX_OBSERVED_STREAM_ROWS:,})"
                                )
                            dirty = True
                elif kind == "result":
                    job_id, callback, result = payload
                    if job_id == self.active_job_id:
                        callback(result)
                        dirty = True
                elif kind == "cancelled":
                    if payload == self.active_job_id:
                        self._finish("Analysis stopped")
                        self._log("Analysis stopped by user.", AMBER)
                        # A stopped lazy analysis leaves its materialized
                        # content behind; release it so idle memory stays low.
                        if self.capture is not None:
                            self.capture.dematerialize()
                        dirty = True
                elif kind == "error":
                    job_id, error = payload
                    if job_id == self.active_job_id:
                        self._finish("Operation failed")
                        self._notify(str(error), RED)
                        if self.capture is not None:
                            self.capture.dematerialize()
                        dirty = True
                elif kind == "manual_result":
                    self._manual_trace_done(payload)
                    dirty = True
                elif kind == "manual_error":
                    _request_id, _value, error = payload
                    self._notify(f"Manual trace failed: {error}", RED)
                    dirty = True
                elif kind == "sweep_progress":
                    token, request_id, done, total = payload
                    if token == self.sweep_token:
                        sequence = "?"
                        if self.capture is not None:
                            try:
                                sequence = self.capture.request(request_id).sequence
                            except KeyError:
                                pass
                        self.status_text.value = (
                            f"Sweeping request #{sequence}: "
                            f"{done:,}/{total:,} earlier entries checked..."
                        )
                        dirty = True
                elif kind == "sweep_done":
                    self._sweep_done(payload)
                    dirty = True
                elif kind == "sweep_error":
                    token, error = payload
                    if token == self.sweep_token:
                        self.sweep_running = False
                        self._notify(f"Value sweep failed: {error}", RED)
                        dirty = True
                handled += 1
                if handled >= 25:
                    break
                try:
                    kind, payload = self.events.get_nowait()
                except queue.Empty:
                    break
            if dirty:
                self.page.update()
            # Yield to Flet so the batch is painted before the next batch is
            # drained from a busy analysis queue.
            await asyncio.sleep(0.025 if dirty else 0.075)

    def _log(self, message: str, color: str = MUTED) -> None:
        # Keep logs ASCII-safe on Windows without destroying non-ASCII content.
        message = message.encode("ascii", errors="backslashreplace").decode("ascii")
        self.live_log.controls.append(ft.Text(
            message,
            size=11,
            color=color,
            selectable=True,
            font_family="Cascadia Mono",
        ))
        if len(self.live_log.controls) > 300:
            self.live_log.controls.pop(0)

    def _notify(self, message: str, color: str) -> None:
        self.status_text.value = message
        self._log(message, color)
        self.page.update()


def _traffic_detail(request: HttpRequest, response: HttpResponse | None,
                    unsafe_raw: bool = False,
                    on_value: ValueClickHandler | None = None,
                    on_copy: ValueClickHandler | None = None) -> ft.Control:
    click: Callable[[str, str, str], None] | None = None
    if on_value is not None:
        def click(kind: str, name: str, value: str) -> None:
            on_value(request.id, kind, name, value)
    copy_value: Callable[[str, str, str], Any] | None = None
    if on_copy is not None:
        def copy_value(kind: str, name: str, value: str) -> Any:
            return on_copy(request.id, kind, name, value)
    request_view = _message_view(
        f"{request.method} {_ui_path(request.url, unsafe_raw)}",
        request.headers, request.body, request.cookies, request.query,
        mime_type=_header_value(request.headers, "content-type"),
        on_value=click, on_copy=copy_value, side="request",
    )
    if response is None:
        response_view = ft.Text("No captured response.", color=MUTED)
    else:
        status_label = (
            f"HTTP {response.status}" if response.status > 0
            else "HTTP status unavailable"
        )
        response_content = _message_view(
            "", response.headers, response.body, response.cookies, (),
            mime_type=response.mime_type,
            on_value=click, on_copy=copy_value, side="response",
        )
        if (
            response.status <= 0 and not response.headers and not response.cookies
            and not response.body
        ):
            response_content = ft.Text(
                "No response content was captured for this entry.",
                color=MUTED,
            )
        response_view = ft.Column([
            ft.Row([
                ft.Text(status_label, color=(
                    _status_color(str(response.status))
                    if response.status > 0 else MUTED
                ),
                        weight=ft.FontWeight.BOLD),
                ft.Text(response.mime_type or "unknown", color=MUTED, size=12),
            ]),
            response_content,
        ], expand=True, spacing=10)
    return ft.Row(
        controls=[
            ft.Container(
                content=ft.Column([
                    ft.Text("Request", color=ACCENT, weight=ft.FontWeight.BOLD),
                    request_view,
                ], expand=True, spacing=10),
                expand=True,
                padding=16,
                bgcolor=SURFACE,
            ),
            ft.Container(width=1, bgcolor=BORDER),
            ft.Container(
                content=ft.Column([
                    ft.Text("Response", color=GREEN, weight=ft.FontWeight.BOLD),
                    response_view,
                ], expand=True, spacing=10),
                expand=True,
                padding=16,
                bgcolor=SURFACE,
            ),
        ],
        expand=True,
        spacing=0,
    )


def _message_view(title: str, headers: Any, body: bytes | None,
                  cookies: Any, query: Any,
                  mime_type: str | None = None,
                  on_value: Callable[[str, str, str], None] | None = None,
                  on_copy: Callable[[str, str, str], Any] | None = None,
                  side: str = "request") -> ft.Control:
    sections: list[ft.Control] = []
    if title:
        sections.append(ft.Text(title, color=ACCENT, weight=ft.FontWeight.BOLD, selectable=True))
    if query:
        sections.append(_key_value_section("Query parameters", list(query),
                                           kind="query", on_value=on_value,
                                           on_copy=on_copy))
    if headers:
        # Cookies have their own structured section; showing the raw transport
        # header as well makes the same value appear twice in the inspector.
        hidden_cookie_headers = {"cookie", "set-cookie"} if cookies else set()
        pseudo_headers = [
            header for header in headers if header.name.startswith(":")
        ]
        visible_headers = [
            header for header in headers
            if header.name.lower() not in hidden_cookie_headers
            and not header.name.startswith(":")
        ]
        if pseudo_headers:
            sections.append(_key_value_section(
                "HTTP/2 pseudo-headers",
                [(header.name, header.value) for header in pseudo_headers],
                kind="pseudo-header", on_copy=on_copy,
            ))
        if visible_headers:
            sections.append(_key_value_section(
                "Headers", [(header.name, header.value) for header in visible_headers],
                kind="header", on_value=on_value, on_copy=on_copy,
            ))
    if cookies:
        sections.append(_key_value_section("Cookies", [(cookie.name, cookie.value)
                                                        for cookie in cookies],
                                           kind="cookie", on_value=on_value,
                                           on_copy=on_copy))
    if body:
        text = body.decode("utf-8", errors="replace")
        body_label: ft.Control = ft.Text("Body", color=MUTED, size=12)
        if on_copy is not None:
            body_label = ft.Row([
                ft.Text("Body", color=MUTED, size=12),
                ft.Container(expand=True),
                ft.IconButton(
                    icon=ft.Icons.CONTENT_COPY, icon_size=13,
                    on_click=lambda _, body_text=text: on_copy(
                        f"{side}-body", "", body_text,
                    ),
                ),
            ])
        sections.extend([
            body_label,
            _body_view(text, mime_type, on_value=on_value),
        ])
    return ft.ListView(
        controls=sections,
        expand=True,
        spacing=10,
        padding=0,
    )


def _body_view(text: str, mime_type: str | None = None,
               on_value: Callable[[str, str, str], None] | None = None) -> ft.Control:
    plain = ft.Text(
        text,
        font_family="Cascadia Mono",
        size=11,
        color=VALUE_COLOR,
        selectable=True,
    )
    if mime_type and "json" not in mime_type.lower():
        return plain
    if len(text) > BODY_HIGHLIGHT_MAX_CHARS:
        # Building colored spans over a huge body takes noticeably longer
        # than rendering the text, so those bodies stay plain but complete.
        return ft.Column([
            ft.Text(
                f"Body shown fully without syntax highlighting "
                f"({len(text):,} characters).",
                color=MUTED, size=11,
            ),
            plain,
        ], spacing=8)
    try:
        json.loads(text)
    except json.JSONDecodeError:
        return plain
    return ft.Container(
        content=ft.Text(
            spans=_json_spans(text, on_value),
            font_family="Cascadia Mono",
            size=11,
            # Selectable text swallows span taps, so bodies with traceable
            # values render non-selectable; copying large bodies goes through
            # the copy icon next to the "Body" label.
            selectable=on_value is None,
        ),
        bgcolor="#0A0F1C",
        padding=ft.Padding.all(10),
        border_radius=6,
    )


def _json_spans(text: str,
                on_value: Callable[[str, str, str], None] | None = None) -> list[ft.TextSpan]:
    token_pattern = re.compile(
        r'"(?:\\.|[^"\\])*"|true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],:]|\s+|.'
    )
    tokens = list(token_pattern.finditer(text))
    spans: list[ft.TextSpan] = []
    for index, match in enumerate(tokens):
        token = match.group(0)
        if token.isspace():
            spans.append(ft.TextSpan(token, style=ft.TextStyle(color=MUTED)))
            continue
        if token.startswith('"'):
            next_token = next(
                (item.group(0) for item in tokens[index + 1:] if not item.group(0).isspace()),
                "",
            )
            color = NAME_COLOR if next_token == ":" else VALUE_COLOR
        elif token in "{}[]":
            color = "#F59E0B"
        elif token in ",:":
            color = MUTED
        elif token in {"true", "false", "null"}:
            color = AMBER
        elif token[0].isdigit() or token[0] == "-":
            color = GREEN
        else:
            color = TEXT
        if on_value is not None and color in {VALUE_COLOR, GREEN}:
            spans.append(ft.TextSpan(
                token,
                style=ft.TextStyle(color=color),
                on_click=_span_click(token, on_value),
            ))
        else:
            spans.append(ft.TextSpan(token, style=ft.TextStyle(color=color)))
    return spans


def _span_click(token: str,
                on_value: Callable[[str, str, str], None]) -> Callable[[Any], None]:
    """Clicking a JSON string or number passes its exact literal value back."""
    def handler(_event: Any) -> None:
        if token.startswith('"'):
            try:
                decoded: Any = json.loads(token)
            except json.JSONDecodeError:
                decoded = token.strip('"')
        else:
            decoded = token
        if isinstance(decoded, bool) or not isinstance(decoded, (str, int, float)):
            return
        if isinstance(decoded, str) and len(decoded) < MANUAL_VALUE_MIN_CHARS:
            return
        on_value("json", "", str(decoded))
    return handler


def _key_value_section(title: str, items: list[tuple[str, str]],
                       kind: str = "header",
                       on_value: Callable[[str, str, str], None] | None = None,
                       on_copy: Callable[[str, str, str], Any] | None = None) -> ft.Control:
    rows: list[ft.Control] = []
    for name, value in items:
        row: list[ft.Control] = [
            ft.Text(str(name), color=NAME_COLOR, weight=ft.FontWeight.BOLD, size=11),
            ft.Text(":", color=MUTED),
        ]
        if on_copy is not None:
            copy_button = ft.IconButton(
                icon=ft.Icons.CONTENT_COPY, icon_size=13,
                on_click=lambda _, raw=str(value), item_name=str(name): on_copy(
                    kind, item_name, raw,
                ),
            )
            copy_button.tooltip = "Copy value"
            row.append(copy_button)
        if on_value is not None:
            # Selectable text swallows the pointer in Flet, so a value that
            # can be traced cannot also start a text selection; copying goes
            # through the copy icon instead.
            value_control: ft.Control = ft.Container(
                content=ft.Text(str(value), color=VALUE_COLOR, size=11, expand=True),
                on_click=lambda _, raw=str(value), item_name=str(name): on_value(
                    kind, item_name, raw,
                ),
            )
            value_control.tooltip = "Click to find the first earlier request holding this value"
        else:
            value_control = ft.Text(
                str(value), color=VALUE_COLOR, size=11,
                selectable=True, expand=True,
            )
        row.append(value_control)
        rows.append(ft.Row(row, spacing=3))
    return ft.Column([
        ft.Text(title, color=MUTED, size=12),
        ft.Column(rows, spacing=3),
    ], spacing=4)


def _first_earlier_occurrence(
    capture: Capture,
    exclude_request_id: str,
    value: str,
    view: Callable[[str], tuple[HttpRequest, HttpResponse | None]],
) -> tuple[str, tuple[str, ...]] | None:
    """Search for the exact literal value backwards through the capture.

    Requests are compared in capture order; the clicked request itself is
    skipped, and the earliest strictly-earlier request whose content holds
    the identical string wins. Names (header/cookie/key) are ignored on
    purpose - only the value text matters. Single one-step search: no
    recursion from the found request.
    """
    requests = capture.requests
    clicked_index = next(
        (index for index, request in enumerate(requests)
         if request.id == exclude_request_id), None,
    )
    if clicked_index is None:
        return None
    for candidate in requests[:clicked_index]:
        pair = view(candidate.id)
        if pair is None:
            continue
        locations = _value_locations(pair[0], pair[1], value)
        if locations:
            return candidate.id, tuple(locations)
    return None


def _entry_holds(request: HttpRequest, response: HttpResponse | None,
                 value: str, request_text: str, response_text: str) -> bool:
    """Whether the exact literal value appears anywhere in one entry.

    Same conditions as ``_value_locations`` in boolean form, so a sweep
    hit is exactly what a single-value manual search would have found.
    """
    if any(header.value == value for header in request.headers):
        return True
    if any(cookie.value == value for cookie in request.cookies):
        return True
    if any(entry == value for _key, entry in request.query):
        return True
    if request.body is not None and value in request_text:
        return True
    if response is None:
        return False
    if any(header.value == value for header in response.headers):
        return True
    if any(cookie.value == value for cookie in response.cookies):
        return True
    return response.body is not None and value in response_text


def _json_scalar_values(item: Any, values: list[str], depth: int = 0) -> None:
    """Collect a JSON body's string/number scalars - exactly the leaves the
    inspector renders as clickable value spans (keys/bools/null excluded)."""
    if depth > 30:
        return
    if isinstance(item, dict):
        for child in item.values():
            _json_scalar_values(child, values, depth + 1)
    elif isinstance(item, list):
        for child in item:
            _json_scalar_values(child, values, depth + 1)
    elif isinstance(item, bool):
        return
    elif isinstance(item, (int, float)):
        values.append(str(item))
    elif isinstance(item, str):
        values.append(item)


def _body_candidate_values(body: bytes | None) -> list[str]:
    """Values a request/response body carries: JSON scalars, or urlencoded
    form field values when it is not JSON (classic session carriers often
    arrive as form posts). Plain text bodies carry no discrete values."""
    if not body:
        return []
    text = body.decode("utf-8", errors="replace")
    try:
        parsed: Any = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError):
        parsed = None
    if parsed is not None:
        scalars: list[str] = []
        try:
            _json_scalar_values(parsed, scalars)
        except RecursionError:
            return []
        return scalars
    if len(text) <= MAX_BODY_PREVIEW_CHARS:
        return [entry for _key, entry in parse_qsl(text, keep_blank_values=True)]
    return []


def _entry_candidate_values(request: HttpRequest,
                            response: HttpResponse | None) -> list[str]:
    """Every traceable literal on one entry, deduplicated in inspector
    order (request side first). Short values are skipped because they
    match practically everything (same rule as manual clicks)."""
    values: list[str] = []
    values.extend(header.value for header in request.headers)
    values.extend(cookie.value for cookie in request.cookies)
    values.extend(entry for _key, entry in request.query)
    values.extend(_body_candidate_values(request.body))
    if response is not None:
        values.extend(header.value for header in response.headers)
        values.extend(cookie.value for cookie in response.cookies)
        values.extend(_body_candidate_values(response.body))
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if len(value) < MANUAL_VALUE_MIN_CHARS or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _sweep_request_values(
    capture: Capture,
    request_id: str,
    view: Callable[[str], tuple[HttpRequest, HttpResponse | None]],
    progress: Callable[[int, int], None] | None = None,
) -> SweepResult:
    """Trace EVERY traceable value on one request to its first appearance.

    The optional batch form of the manual trace: the same exact-literal,
    name-agnostic search that runs for a single click, run for all values
    at once. One pass parses each strictly-earlier entry once and checks
    every not-yet-found value against it (instead of one pass per value),
    and the earliest entry holding a value wins, identical to what a
    manual click on that value reports. Deep by exactly one level: found
    requests land on the chain but their values are never searched from
    here - recursion stays a user decision.
    """
    requests = capture.requests
    clicked_index = next(
        (index for index, request in enumerate(requests)
         if request.id == request_id), None,
    )
    if clicked_index is None:
        raise KeyError(f"request {request_id!r} is not part of this capture")
    try:
        source_pair = view(request_id)
    except (HarFormatError, OSError):
        source_pair = None
    if source_pair is None:
        return SweepResult(request_id, (), 0, ())
    values = _entry_candidate_values(source_pair[0], source_pair[1])
    if not values:
        return SweepResult(request_id, (), 0, ())
    pending = set(values)
    hits: dict[str, SweepHit] = {}
    checked = 0
    for index in range(clicked_index):  # earliest first: the first hit wins
        if not pending:
            break
        if progress is not None and (index % 25 == 0 or index == clicked_index - 1):
            progress(index, clicked_index)
        try:
            pair = view(requests[index].id)
        except (HarFormatError, OSError):
            continue
        checked += 1
        request, response = pair
        request_text = (request.body.decode("utf-8", errors="replace")
                        if request.body is not None else "")
        response_text = (response.body.decode("utf-8", errors="replace")
                         if response is not None and response.body is not None
                         else "")
        found_now = [value for value in pending
                     if _entry_holds(request, response, value,
                                     request_text, response_text)]
        for value in found_now:
            pending.remove(value)
            hits[value] = (value, requests[index].id, tuple(
                _value_locations_with_bodies(
                    request, response, value, request_text, response_text,
                ),
            ))
    if progress is not None:
        progress(clicked_index, clicked_index)
    dead_ends = tuple(value for value in values if value not in hits)
    return SweepResult(
        request_id,
        tuple(hits[value] for value in values if value in hits),
        checked,
        dead_ends,
    )


def _value_locations(request: HttpRequest, response: HttpResponse | None,
                     value: str) -> list[str]:
    """Where the exact value appears in one entry, as display labels."""
    return _value_locations_with_bodies(
        request, response, value,
        (request.body.decode("utf-8", errors="replace")
         if request.body is not None else ""),
        ((response.body.decode("utf-8", errors="replace"))
         if response is not None and response.body is not None else ""),
    )


def _value_locations_with_bodies(request: HttpRequest,
                                 response: HttpResponse | None,
                                 value: str, request_text: str,
                                 response_text: str) -> list[str]:
    """``_value_locations`` with body texts passed in (sweep decodes once)."""
    locations = [
        f"request header '{header.name}'"
        for header in request.headers if header.value == value
    ]
    locations.extend(
        f"request cookie '{cookie.name}'"
        for cookie in request.cookies if cookie.value == value
    )
    locations.extend(
        f"query '{key}'" for key, entry in request.query if entry == value
    )
    if request.body is not None:
        locations.extend(_body_locations_text(request_text, "request", value))
    if response is not None:
        locations.extend(
            f"response header '{header.name}'"
            for header in response.headers if header.value == value
        )
        locations.extend(
            f"response cookie '{cookie.name}'"
            for cookie in response.cookies if cookie.value == value
        )
        if response.body is not None:
            locations.extend(_body_locations_text(response_text, "response", value))
    return locations[:4]


def _body_locations(raw: bytes, side: str, value: str) -> list[str]:
    return _body_locations_text(raw.decode("utf-8", errors="replace"), side, value)


def _body_locations_text(text: str, side: str, value: str) -> list[str]:
    if value not in text:
        return []
    fields = _body_value_fields(text, value)
    return [f"{side} body field '{field}'" for field in fields] or [f"{side} body"]


def _body_value_fields(text: str, value: str) -> list[str]:
    """Name the form field or JSON path holding the value, when cheap."""
    if len(text) > MAX_BODY_PREVIEW_CHARS:
        return []
    hits: list[str] = []
    if text.lstrip()[:1] not in {"{", "["}:
        for key, entry in parse_qsl(text, keep_blank_values=True):
            if entry == value:
                hits.append(key)
                if len(hits) >= 2:
                    return hits
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return hits
    _json_value_fields(parsed, value, "", hits)
    return hits[:2]


def _json_value_fields(item: Any, value: str, path: str, hits: list[str],
                       depth: int = 0) -> None:
    """Collect JSON paths whose string or number scalar equals the value."""
    if len(hits) >= 2 or depth > 30:
        return
    if isinstance(item, dict):
        for key, child in item.items():
            _json_value_fields(child, value, f"{path}.{key}" if path else str(key),
                               hits, depth + 1)
    elif isinstance(item, list):
        for index, child in enumerate(item):
            _json_value_fields(child, value, f"{path}.{index}" if path else str(index),
                               hits, depth + 1)
    elif isinstance(item, bool):
        return
    elif isinstance(item, (int, float)) and str(item) == value and path:
        hits.append(path)
    elif isinstance(item, str) and item == value and path:
        hits.append(path)


class _IgnoreHintHTMLParser(HTMLParser):
    """Collect field names from HTML responses that extraction can observe."""

    def __init__(self) -> None:
        super().__init__()
        self.names: set[str] = set()

    def handle_starttag(self, _tag: str,
                        attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value for key, value in attrs}
        name = values.get("name")
        if name:
            self.names.add(name.lower())
        self.names.update(
            key.lower() for key, value in attrs
            if value and key.lower() in {"data-token", "data-csrf", "data-state"}
        )


def _cookie_hint_names(value: str) -> set[str]:
    names: set[str] = set()
    for item in value.split(";"):
        name, separator, _cookie_value = item.strip().partition("=")
        if separator and name.strip():
            names.add(name.strip().lower())
    return names


def _set_cookie_hint_name(value: str) -> str | None:
    pair = value.split(";", 1)[0].strip()
    name, separator, _cookie_value = pair.partition("=")
    return name.strip().lower() if separator and name.strip() else None


def _body_hint_names(body: bytes | None, mime_type: str | None = None) -> set[str]:
    """Return payload field names supported by the observation extractor."""
    if not body or len(body) > MAX_BODY_PREVIEW_CHARS:
        return set()
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return set()
    candidate = text.lstrip("\ufeff \t\r\n")
    if candidate.startswith(")]}'"):
        _preamble, separator, remainder = candidate.partition("\n")
        if separator:
            candidate = remainder.lstrip()
    mime = (mime_type or "").lower()
    if "json" in mime or candidate.startswith(("{", "[")):
        try:
            return _json_keys(json.loads(candidate))
        except (json.JSONDecodeError, RecursionError, ValueError):
            return set()
    if "html" in mime or candidate.startswith("<"):
        parser = _IgnoreHintHTMLParser()
        try:
            parser.feed(candidate)
        except (ValueError, RecursionError):
            return set()
        return parser.names
    if "form-urlencoded" in mime or _looks_like_form_body(candidate):
        return {
            key.lower() for key, _value in parse_qsl(candidate, keep_blank_values=True)
            if key
        }
    return set()


def _looks_like_form_body(text: str) -> bool:
    if "=" not in text or text.lstrip().startswith(("{", "[", "<")):
        return False
    parts = [part for part in text.split("&") if part]
    return bool(parts) and all(
        "=" in part
        and re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_.-]{0,80}", part.split("=", 1)[0].strip(),
        ) is not None
        for part in parts
    )


def _request_ignore_groups(request: HttpRequest) -> dict[str, list[str]]:
    """Group selectable field names found on the target request."""
    groups: dict[str, set[str]] = {
        "Cookies": set(),
        "Headers": set(),
        "Payload": set(),
        "Parameters": set(),
    }

    def collect_headers(headers: Any) -> None:
        for header in headers:
            name = header.name.lower().strip()
            if name.startswith(":"):
                # Pseudo-headers mirror request/response metadata and are not
                # selectable application state.
                continue
            if name == "set-cookie":
                cookie_name = _set_cookie_hint_name(header.value)
                if cookie_name:
                    groups["Cookies"].add(cookie_name)
            elif name == "cookie":
                groups["Cookies"].update(_cookie_hint_names(header.value))
            elif name:
                groups["Headers"].add(name)

    collect_headers(request.headers)
    groups["Cookies"].update(cookie.name.lower() for cookie in request.cookies)
    groups["Parameters"].update(
        key.lower() for key, _value in request.query if key
    )
    groups["Payload"].update(_body_hint_names(
        request.body, _header_value(request.headers, "content-type"),
    ))
    return {
        section: sorted(name for name in names if name)
        for section, names in groups.items() if names
    }


def _request_hints(request: HttpRequest) -> list[str]:
    """Flat, unique compatibility view of the categorized ignore options."""
    return sorted({
        hint for names in _request_ignore_groups(request).values()
        for hint in names
    })


def _json_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return {str(key).lower() for key in value} | {
            child for item in value.values() for child in _json_keys(item)
        }
    if isinstance(value, list):
        return {child for item in value for child in _json_keys(item)}
    return set()


def _response_for(responses: Any, response_id: str | None) -> HttpResponse | None:
    return next((response for response in responses if response.id == response_id), None)


def _observation_name(observation: ValueObservation) -> str:
    if observation.semantic_hints:
        hint = observation.semantic_hints[0]
        return hint.removeprefix("cookie.") if hint.startswith("cookie.") else hint
    path = observation.location.path or ""
    leaf = path.rsplit(".", 1)[-1].rsplit("/", 1)[-1].split("[", 1)[0]
    return leaf if leaf and leaf != "$" else "unnamed"


def _header_value(headers: Any, name: str) -> str | None:
    return next(
        (header.value for header in headers if header.name.lower() == name.lower()),
        None,
    )


def _badge(label: str, color: str) -> ft.Control:
    return ft.Container(
        content=ft.Text(label, size=10, color=BG, weight=ft.FontWeight.BOLD),
        bgcolor=color, padding=ft.Padding.symmetric(horizontal=7, vertical=3),
        border_radius=12,
    )


def _method_color(method: str) -> str:
    return {"GET": "#60A5FA", "POST": "#FBBF24", "PUT": "#C084FC",
            "PATCH": "#FB923C", "DELETE": "#FB7185"}.get(method.upper(), MUTED)


def _status_color(status: str) -> str:
    if status in {"200", "201", "204", "SUPPORTED"}:
        return GREEN
    if status in {"UNKNOWN", "CANDIDATE", "HYPOTHETICAL"}:
        return AMBER
    return RED


def _safe_path(url: str) -> str:
    path = urlsplit(url).path or "/"
    return "/".join("<redacted>" if len(segment) > 48 else segment
                    for segment in path.split("/"))


def _ui_path(url: str, unsafe_raw: bool = False) -> str:
    if unsafe_raw:
        return urlsplit(url).path or "/"
    return _safe_path(url)
