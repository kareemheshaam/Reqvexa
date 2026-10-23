from __future__ import annotations

import asyncio
import json
import queue
import re
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import flet as ft

from reqvexa.cancellation import AnalysisCancelled
from reqvexa.capture import HarProvider
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
MAX_BODY_PREVIEW_CHARS = 50_000

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
    ft.app(
        target=lambda page: ReqvexaApp(page, capture_path, request_id),
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
        self.target_id: str | None = request_id
        self.analysis_count = 0
        self.job_counter = 0
        self.active_job_id = 0
        self.analysis_tab_by_job: dict[int, int] = {}
        self.streaming_lists: dict[int, ft.ListView] = {}
        self.latest_analysis_tab_index: int | None = None
        self.ignore_boxes: dict[str, ft.Checkbox] = {}
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
        page.window_min_width = 1080
        page.window_min_height = 700

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
        self.load_button = ft.FilledButton(
            "Load capture", icon=ft.Icons.FOLDER_OPEN, on_click=lambda _: self._load_capture()
        )
        self.analyze_button = ft.FilledButton(
            "Analyze target", icon=ft.Icons.PLAY_ARROW, on_click=lambda _: self._analyze()
        )
        self.stop_button = ft.OutlinedButton(
            "Stop", icon=ft.Icons.STOP_CIRCLE, disabled=True, on_click=lambda _: self._stop()
        )
        self.reveal_switch = ft.Switch(
            label="Show sensitive values",
            value=False,
            on_change=lambda _: self._refresh_sensitive_views(),
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
        self.ignore_panel = ft.GridView(
            runs_count=3,
            height=40,
            spacing=0,
            run_spacing=0,
            child_aspect_ratio=12.0,
            padding=0,
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
            padding=ft.padding.only(left=22, right=22, top=18, bottom=14),
            border=ft.border.only(bottom=ft.BorderSide(1, BORDER)),
        )
        controls = ft.Container(
            content=ft.Column([
                self.progress,
                ft.Row([self._summary, ft.Container(expand=True), self.status_text]),
            ], spacing=8),
            padding=ft.padding.symmetric(horizontal=22, vertical=12),
            bgcolor=SURFACE,
        )
        self.main_tabs = ft.Tabs(
            tabs=[
                ft.Tab(text="Traffic", content=self._traffic_view()),
                ft.Tab(text="Logs", content=self.live_log),
                ft.Tab(text="Analysis", content=self._analysis_view()),
            ],
            selected_index=0, expand=True, scrollable=True, divider_color=BORDER,
            indicator_color=ACCENT, label_color=TEXT, unselected_label_color=MUTED,
        )
        page.add(header, controls, self.main_tabs)

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
            padding=ft.padding.all(10),
            bgcolor="#0E1626",
            border=ft.border.only(bottom=ft.BorderSide(1, BORDER)),
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
            padding=ft.padding.all(14),
            bgcolor=SURFACE,
        )
        return ft.Column([
            ft.Container(
                content=ft.Row([
                    ft.Text("Captured traffic", size=13, weight=ft.FontWeight.BOLD, color=TEXT),
                    ft.Container(expand=True),
                    ft.Text("Select a request to inspect it", color=MUTED, size=11),
                ]),
                padding=ft.padding.only(left=16, right=16, top=12, bottom=8),
            ),
            ft.Container(content=self.search_field, padding=ft.padding.symmetric(horizontal=16)),
            self.traffic_list_container,
            self.traffic_detail_container,
        ], expand=True, spacing=0)

    def _analysis_view(self) -> ft.Control:
        self.analysis_tabs = ft.Tabs(
            tabs=[],
            selected_index=0,
            scrollable=True,
            expand=True,
            divider_color=BORDER,
            indicator_color=ACCENT,
            label_color=TEXT,
            unselected_label_color=MUTED,
        )
        return ft.Column([
            ft.Container(
                content=ft.Row([
                    ft.Text("Analysis controls", weight=ft.FontWeight.BOLD, color=TEXT),
                    ft.Container(expand=True),
                    self.reveal_switch,
                    ft.TextButton(
                        "Re-run with selected values ignored",
                        icon=ft.Icons.FILTER_ALT, on_click=lambda _: self._analyze(),
                    ),
                ]),
                padding=ft.padding.only(left=16, right=16, top=14),
            ),
            ft.Container(
                content=ft.Column([
                    ft.Text("Values to ignore", color=MUTED, size=12),
                    self.ignore_panel,
                ], spacing=6),
                padding=ft.padding.symmetric(horizontal=16, vertical=8),
                bgcolor=SURFACE_2,
            ),
            self.analysis_tabs,
        ], expand=True, spacing=0)

    def _load_capture(self) -> None:
        path = (self.path_field.value or "").strip()
        if not path:
            self._notify("Choose a HAR file first.", RED)
            return
        job_id = self._begin("Loading capture")
        self._run_worker(lambda: HarProvider().load_file(path), self._capture_loaded, job_id)

    def _capture_loaded(self, capture: Any) -> None:
        self.capture = capture
        self.analysis = self.plan = self.report = None
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
        needle = (self.search_field.value or "").lower().strip()
        self.request_list.controls.clear()
        for request in self.capture.requests:
            label = f"{request.method} {_ui_path(request.url, self._show_sensitive())}"
            if needle and needle not in f"{request.sequence} {label} {request.id}".lower():
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

    def _select_request(self, request_id: str) -> None:
        self.target_id = request_id
        self._show_request(request_id)
        self._build_ignore_options()
        self._render_request_list()
        self.page.update()

    def _show_request(self, request_id: str) -> None:
        if self.capture is None:
            return
        request = self.capture.request(request_id)
        response = _response_for(self.capture.responses, request.response_id)
        self.detail_panel.content = _traffic_detail(
            request, response, unsafe_raw=self._show_sensitive()
        )
        self.page.update()

    def _build_ignore_options(self) -> None:
        if self.capture is None or self.target_id is None:
            return
        hints = _request_hints(self.capture.request(self.target_id))
        self.ignore_boxes = {
            hint: ft.Checkbox(
                label=hint,
                value=hint in DEFAULT_IGNORED_HINTS,
            )
            for hint in hints[:80]
        }
        self.ignore_panel.controls = [
            ft.Container(
                content=checkbox,
                height=28,
                padding=0,
                alignment=ft.Alignment(0, 0),
            )
            for checkbox in self.ignore_boxes.values()
        ] or [
            ft.Text("No named state values detected.", color=MUTED, size=12)
        ]
        rows = max(1, (len(self.ignore_panel.controls) + 2) // 3)
        self.ignore_panel.height = min(8, rows) * 29 + 4
        self.page.update()

    def _analyze(self) -> None:
        if self.capture is None or self.target_id is None:
            self._notify("Load a capture and select a target request.", RED)
            return
        ignored = {hint for hint, checkbox in self.ignore_boxes.items() if checkbox.value}
        job_id = self._begin("Analyzing target")
        self._create_streaming_analysis_tab(job_id, self.target_id)
        self._run_worker(
            lambda: ProvenanceEngine().analyze(
                self.capture, target_request_id=self.target_id, ignored_hints=ignored,
                progress_callback=lambda stage, current, total, message:
                    self._progress(job_id, stage, current, total, message),
                observation_callback=lambda request_id, sequence, observations:
                    self._observations_progress(job_id, request_id, sequence, observations),
                cancel_event=self.cancel_event,
            ),
            lambda analysis: self._analysis_ready(job_id, analysis),
            job_id,
        )

    def _analysis_ready(self, job_id: int, analysis: Analysis) -> None:
        if job_id != self.active_job_id:
            return
        if self.target_id is None:
            return
        self.analysis = analysis
        self.plan = plan_flow(analysis, self.target_id)
        self.report = safe_report(
            analysis,
            self.target_id,
            unsafe_raw=bool(self.reveal_switch.value),
        )
        self.analysis_count += 1
        self._complete_analysis_tab(
            job_id, self.analysis_count, self.target_id, self.plan, self.report
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
        self.analysis_tabs.tabs.append(ft.Tab(
            text=f"Analysis {self.analysis_count + 1:02d} - running",
            content=ft.Column([
                ft.Container(
                    content=ft.Text(
                        f"Scanning capture for dependencies of request #{target.sequence}...",
                        color=ACCENT,
                    ),
                    padding=ft.padding.all(14),
                ),
                stream,
            ], expand=True, spacing=0),
        ))
        self.analysis_tab_by_job[job_id] = len(self.analysis_tabs.tabs) - 1
        self.analysis_tabs.selected_index = len(self.analysis_tabs.tabs) - 1
        self.main_tabs.selected_index = 2
        self.page.update()

    def _complete_analysis_tab(self, job_id: int, ordinal: int, target_id: str,
                               plan: FlowPlan, report: dict[str, Any]) -> None:
        capture = self.capture
        if capture is None:
            return
        target = capture.request(target_id)
        tab_index = self.analysis_tab_by_job[job_id]
        self.analysis_tabs.tabs[tab_index] = ft.Tab(
            text=f"Analysis {ordinal:02d} - #{target.sequence}",
            content=self._analysis_result_view(plan, report),
        )
        self.analysis_tabs.selected_index = tab_index
        self.latest_analysis_tab_index = tab_index
        self.streaming_lists.pop(job_id, None)
        self.analysis_tab_by_job.pop(job_id, None)
        self.page.update()

    def _analysis_result_view(self, plan: FlowPlan, report: dict[str, Any]) -> ft.Control:
        capture = self.capture
        if capture is None:
            return ft.Text("Capture is no longer available.", color=RED)
        flow_list = ft.ListView(
            expand=True, spacing=4,
        )
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
            padding=ft.padding.all(10),
        )
        detail_container = ft.Container(
            content=ft.Column([
                ft.Text("Request / Response", color=ACCENT,
                        weight=ft.FontWeight.BOLD),
                analysis_detail,
            ], expand=True, spacing=8),
            expand=6,
            padding=ft.padding.all(14),
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
        for step in plan.steps:
            flow_list.controls.append(ft.Container(
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
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text("-> " + ", ".join(step.produces) if step.produces else "",
                            width=180, color=VALUE_COLOR, size=11),
                ], spacing=8),
                padding=ft.padding.symmetric(horizontal=12, vertical=9),
                bgcolor=SURFACE_2, border_radius=6,
                on_click=lambda _, request_id=step.request_id: self._show_analysis_request(
                    analysis_detail, request_id
                ),
            ))
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
                padding=ft.padding.all(10),
                bgcolor="#123126" if value["producers"] else SURFACE_2,
                border=ft.border.all(1, GREEN if value["producers"] else BORDER),
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
                padding=ft.padding.all(10),
                border_radius=6,
            ))
        return ft.Column([
            ft.Container(
                content=ft.Row([
                    ft.Text(
                        f"{len(plan.steps)} requests required for this flow",
                        color=TEXT, weight=ft.FontWeight.BOLD,
                    ),
                    ft.Container(expand=True),
                    ft.Text("List height", color=MUTED, size=11),
                    split_slider,
                    ft.Text(
                        "Observational plan - no requests are sent",
                        color=MUTED, size=11,
                    ),
                ]),
                padding=ft.padding.all(14),
            ),
            ft.Tabs(
                tabs=[
                    ft.Tab(text="Required requests", content=ft.Column([
                        flow_container,
                        detail_container,
                    ], expand=True, spacing=0)),
                    ft.Tab(text="Values", content=ft.Column(values_panel, expand=True)),
                ],
                selected_index=0,
                expand=True,
            ),
        ], expand=True, spacing=0)

    def _show_analysis_request(self, detail: ft.Container, request_id: str) -> None:
        if self.capture is None:
            return
        request = self.capture.request(request_id)
        response = _response_for(self.capture.responses, request.response_id)
        detail.content = _traffic_detail(
            request, response, unsafe_raw=self._show_sensitive()
        )
        self.page.update()

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
            )
            self._notify(
                "Sensitive values shown." if self.reveal_switch.value
                else "Sensitive values masked.",
                AMBER if self.reveal_switch.value else GREEN,
            )
        if self.capture is not None and self.target_id is not None:
            self._render_request_list()
            self._show_request(self.target_id)
        if self.analysis is not None and self.plan is not None and self.target_id is not None:
            self.report = safe_report(
                self.analysis,
                self.target_id,
                unsafe_raw=bool(self.reveal_switch.value),
            )
            if self.latest_analysis_tab_index is not None:
                self.analysis_tabs.tabs[self.latest_analysis_tab_index] = ft.Tab(
                    text=f"Analysis {self.analysis_count:02d}",
                    content=self._analysis_result_view(self.plan, self.report),
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
        self.page.dialog = ft.AlertDialog(
            modal=True, title=ft.Text(f"Save {label}"), content=field,
            actions=[
                ft.TextButton("Cancel", on_click=lambda _: self._close_dialog()),
                ft.FilledButton(
                    "Save",
                    on_click=lambda _: self._write_dialog(field.value, payload, extension),
                ),
            ],
        )
        self.page.dialog.open = True
        self.page.update()

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
        if self.page.dialog:
            self.page.dialog.open = False
            self.page.update()

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
                                    padding=ft.padding.symmetric(horizontal=10, vertical=7),
                                    bgcolor=SURFACE_2,
                                    border_radius=6,
                                ))
                            if len(stream.controls) > 1200:
                                del stream.controls[:-1200]
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
                        dirty = True
                elif kind == "error":
                    job_id, error = payload
                    if job_id == self.active_job_id:
                        self._finish("Operation failed")
                        self._notify(str(error), RED)
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
                    unsafe_raw: bool = False) -> ft.Control:
    request_view = _message_view(
        f"{request.method} {_ui_path(request.url, unsafe_raw)}",
        request.headers, request.body, request.cookies, request.query,
        mime_type=_header_value(request.headers, "content-type"),
    )
    if response is None:
        response_view = ft.Text("No captured response.", color=MUTED)
    else:
        response_view = ft.Column([
            ft.Row([
                ft.Text(f"HTTP {response.status}", color=_status_color(str(response.status)),
                        weight=ft.FontWeight.BOLD),
                ft.Text(response.mime_type or "unknown", color=MUTED, size=12),
            ]),
            _message_view(
                "", response.headers, response.body, response.cookies, (),
                mime_type=response.mime_type,
            ),
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
                  mime_type: str | None = None) -> ft.Control:
    sections: list[ft.Control] = []
    if title:
        sections.append(ft.Text(title, color=ACCENT, weight=ft.FontWeight.BOLD, selectable=True))
    if query:
        sections.append(_key_value_section("Query parameters", list(query)))
    if headers:
        # Cookies have their own structured section; showing the raw transport
        # header as well makes the same value appear twice in the inspector.
        hidden_cookie_headers = {"cookie", "set-cookie"} if cookies else set()
        visible_headers = [
            header for header in headers
            if header.name.lower() not in hidden_cookie_headers
        ]
        if visible_headers:
            sections.append(_key_value_section(
                "Headers", [(header.name, header.value) for header in visible_headers]
            ))
    if cookies:
        sections.append(_key_value_section("Cookies", [(cookie.name, cookie.value)
                                                        for cookie in cookies]))
    if body:
        text = body.decode("utf-8", errors="replace")
        sections.extend([
            ft.Text("Body", color=MUTED, size=12),
            _body_view(text, mime_type),
        ])
    return ft.ListView(
        controls=sections,
        expand=True,
        spacing=10,
        padding=0,
    )


def _body_view(text: str, mime_type: str | None = None) -> ft.Control:
    if len(text) > MAX_BODY_PREVIEW_CHARS:
        preview = text[:MAX_BODY_PREVIEW_CHARS]
        return ft.Column([
            ft.Text(
                f"Large body truncated for UI safety ({len(text):,} characters).",
                color=AMBER, size=11,
            ),
            ft.Text(
                preview,
                font_family="Cascadia Mono",
                size=11,
                color=VALUE_COLOR,
                selectable=True,
            ),
        ], spacing=8)
    if mime_type and "json" not in mime_type.lower():
        return ft.Text(
            text,
            font_family="Cascadia Mono",
            size=11,
            color=VALUE_COLOR,
            selectable=True,
        )
    try:
        json.loads(text)
    except json.JSONDecodeError:
        return ft.Text(text, font_family="Cascadia Mono", size=11,
                       color=VALUE_COLOR, selectable=True)
    return ft.Container(
        content=ft.Text(
            spans=_json_spans(text),
            font_family="Cascadia Mono",
            size=11,
            selectable=True,
        ),
        bgcolor="#0A0F1C",
        padding=ft.padding.all(10),
        border_radius=6,
    )


def _json_spans(text: str) -> list[ft.TextSpan]:
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
        spans.append(ft.TextSpan(token, style=ft.TextStyle(color=color)))
    return spans


def _key_value_section(title: str, items: list[tuple[str, str]]) -> ft.Control:
    return ft.Column([
        ft.Text(title, color=MUTED, size=12),
        ft.Column([
            ft.Row([
                ft.Text(str(name), color=NAME_COLOR, weight=ft.FontWeight.BOLD, size=11),
                ft.Text(":", color=MUTED),
                ft.Text(str(value), color=VALUE_COLOR, size=11, selectable=True, expand=True),
            ], spacing=3)
            for name, value in items
        ], spacing=3),
    ], spacing=4)


def _request_hints(request: HttpRequest) -> list[str]:
    hints = {header.name.lower() for header in request.headers}
    hints.update(cookie.name.lower() for cookie in request.cookies)
    hints.update(key.lower() for key, _ in request.query)
    if request.body and len(request.body) <= MAX_BODY_PREVIEW_CHARS:
        try:
            parsed = json.loads(request.body.decode("utf-8"))
            hints.update(_json_keys(parsed))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return sorted(hints)


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
        bgcolor=color, padding=ft.padding.symmetric(horizontal=7, vertical=3),
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
