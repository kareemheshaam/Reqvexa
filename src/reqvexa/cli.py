from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reqvexa.capture import HarFormatError, HarProvider
from reqvexa.models import Capture
from reqvexa.planning import plan_flow, report_markdown, report_mermaid, safe_path, safe_report
from reqvexa.provenance import Analysis, ProvenanceEngine, TraceNode

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _package_version
except ImportError:  # pragma: no cover - Python 3.12+ always provides it
    _package_version = None  # type: ignore[assignment]

if _package_version is not None:
    try:
        __version__ = _package_version("reqvexa")
    except PackageNotFoundError:
        __version__ = "0.0.0+unknown"
else:  # pragma: no cover
    __version__ = "0.0.0+unknown"

TARGET_COMMANDS = {"trace", "plan", "report"}


def _analysis(capture: Capture, request_id: str | None) -> Analysis:
    return ProvenanceEngine().analyze(capture, target_request_id=request_id)


def _target_id(request_id: str | None) -> str:
    """Narrow the request ID for commands that require a target."""
    if request_id is None:  # pragma: no cover - guarded by TARGET_COMMANDS
        raise RuntimeError("target request is required for this command")
    return request_id


class _CliError(Exception):
    """A user-facing CLI failure; the message prints without a traceback."""


def _resolve_request_id(capture: Capture, selector: str) -> str:
    if selector in capture.requests_by_id:
        return selector
    try:
        index = int(selector)
    except ValueError:
        index = None
    if index is not None:
        position = index if index >= 0 else len(capture.requests) + index
        if 0 <= position < len(capture.requests):
            return capture.requests[position].id
        raise _CliError(
            f"Request index {index} is outside the capture "
            f"(0 to {len(capture.requests) - 1})."
        )
    matches = [
        request.id for request in capture.requests
        if selector.lower() in request.url.lower()
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise _CliError(
            "Unknown request; run 'reqvexa requests <capture>' to list request IDs, "
            "or use an index such as --request -1."
        )
    shown = "\n".join(
        f"  {sequence}: {capture.requests_by_id[request_id].method} {safe_path(capture.requests_by_id[request_id].url)}"
        for sequence, request_id in enumerate(matches[:5])
    )
    raise _CliError(f"Selector '{selector}' matches {len(matches)} requests; "
                    "use one of these IDs instead:\n" + shown)


def _trace_lines(analysis: Analysis, request_id: str, unsafe_raw: bool) -> list[str]:
    request = analysis.capture.request(request_id)
    target = request.url if unsafe_raw else safe_path(request.url)
    lines = [f"Target:\n{request.method} {target}", "", "State dependencies:"]
    for node in analysis.trace(request_id):
        lines.extend(_trace_node_lines(analysis, node, 0))
    return lines


def _trace_node_lines(analysis: Analysis, node: TraceNode, depth: int) -> list[str]:
    version = analysis.versions[node.version_id]
    prefix = "  " * depth
    lines = [
        f"{prefix}{node.value_id}",
        f"{prefix}version: {node.version_id}",
        f"{prefix}status: {node.status}",
        f"{prefix}value: {version.display_value}",
    ]
    if node.producer_ids:
        lines.append(f"{prefix}producer: {', '.join(node.producer_ids)}")
    if node.note:
        lines.append(f"{prefix}note: {node.note}")
    for child in node.children:
        lines.extend(_trace_node_lines(analysis, child, depth + 1))
    return lines


def _requests_lines(capture: Capture, unsafe_raw: bool) -> list[str]:
    lines = []
    for request in capture.requests:
        location = request.url if unsafe_raw else safe_path(request.url)
        lines.append(f"{request.sequence:>4}  {request.method:<7} {request.id}  {location}")
    return lines


def _requests_json(capture: Capture, unsafe_raw: bool) -> str:
    payload = []
    for request in capture.requests:
        item = {
            "id": request.id,
            "sequence": request.sequence,
            "method": request.method,
            "path": safe_path(request.url),
        }
        if unsafe_raw:
            item["url"] = request.url
        payload.append(item)
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reqvexa",
        description="Trace the state behind a captured HTTP request.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Summarize a capture")
    analyze.add_argument("capture", type=Path)

    requests = subparsers.add_parser(
        "requests", help="List request IDs for use with --request"
    )
    requests.add_argument("capture", type=Path)
    requests.add_argument("--json", action="store_true", help="Emit JSON")
    requests.add_argument(
        "--unsafe-raw", action="store_true",
        help="Include full URLs and query strings (may contain secrets)",
    )

    trace = subparsers.add_parser("trace", help="Show state dependencies for one request")
    trace.add_argument("capture", type=Path)
    trace.add_argument(
        "--request", required=True,
        help="Request ID, entry index (e.g. -1), or URL substring",
    )
    trace.add_argument("--output", type=Path)
    trace.add_argument(
        "--unsafe-raw", action="store_true",
        help="Print the unredacted target URL (may contain secrets)",
    )

    graph = subparsers.add_parser("graph", help="Dump the provenance graph as JSON")
    graph.add_argument("capture", type=Path)

    plan = subparsers.add_parser("plan", help="Show the required request flow")
    plan.add_argument("capture", type=Path)
    plan.add_argument(
        "--request", required=True,
        help="Request ID, entry index (e.g. -1), or URL substring",
    )
    plan.add_argument("--output", type=Path)

    report = subparsers.add_parser("report", help="Write a masked safe report")
    report.add_argument("capture", type=Path)
    report.add_argument(
        "--request", required=True,
        help="Request ID, entry index (e.g. -1), or URL substring",
    )
    report.add_argument("--output", type=Path)
    report.add_argument(
        "--format", choices=("json", "markdown", "mermaid"), default="json"
    )

    gui = subparsers.add_parser("gui", help="Open the desktop viewer")
    gui.add_argument("capture", type=Path, nargs="?")
    gui.add_argument("--request")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "gui":
        try:
            from reqvexa.gui import launch_gui
        except ImportError:
            print(
                'error: the GUI extra is not installed. Run: '
                'python -m pip install "reqvexa[gui]"',
                file=sys.stderr,
            )
            return 2
        launch_gui(args.capture, args.request)
        return 0

    try:
        capture = HarProvider().load_file(args.capture)
    except (HarFormatError, OSError) as error:
        print(f"error: cannot read HAR capture: {error}", file=sys.stderr)
        return 2

    request_id: str | None = None
    if args.command in TARGET_COMMANDS:
        try:
            request_id = _resolve_request_id(capture, args.request)
        except _CliError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2

    analysis = _analysis(capture, request_id)
    if args.command == "analyze":
        print(json.dumps({
            "requests": len(analysis.capture.requests),
            "responses": len(analysis.capture.responses),
            "observations": len(analysis.observations),
            "value_versions": len(analysis.versions),
            "nodes": len(analysis.graph.nodes),
            "edges": len(analysis.graph.edges),
        }, indent=2, sort_keys=True))
    elif args.command == "requests":
        if args.json:
            _emit(_requests_json(capture, args.unsafe_raw), None)
        else:
            print("\n".join(_requests_lines(capture, args.unsafe_raw)))
    elif args.command == "graph":
        print(json.dumps(analysis.graph_dict(), indent=2, sort_keys=True))
    elif args.command == "plan":
        payload = json.dumps(plan_flow(analysis, _target_id(request_id)).to_dict(),
                             indent=2, sort_keys=True) + "\n"
        _emit(payload, args.output)
    elif args.command == "report":
        report_payload = safe_report(analysis, _target_id(request_id))
        if args.format == "markdown":
            payload = report_markdown(report_payload)
        elif args.format == "mermaid":
            payload = report_mermaid(report_payload)
        else:
            payload = json.dumps(report_payload, indent=2, sort_keys=True) + "\n"
        _emit(payload, args.output)
    else:
        payload = "\n".join(_trace_lines(analysis, _target_id(request_id), args.unsafe_raw)) + "\n"
        _emit(payload, args.output)
    return 0


def _emit(payload: str, output: Path | None) -> None:
    if output is None:
        print(payload, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())

