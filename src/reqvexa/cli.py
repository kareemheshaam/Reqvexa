from __future__ import annotations

import argparse
import json
from pathlib import Path

from reqvexa.capture import HarProvider
from reqvexa.planning import plan_flow, report_markdown, safe_report
from reqvexa.provenance import Analysis, ProvenanceEngine, TraceNode


def _analysis(path: str) -> Analysis:
    return ProvenanceEngine().analyze(HarProvider().load_file(path))


def _trace_lines(analysis: Analysis, request_id: str) -> list[str]:
    request = analysis.capture.request(request_id)
    lines = [f"Target:\n{request.method} {request.url}", "", "State dependencies:"]
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reqvexa")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("capture", type=Path)
    trace = subparsers.add_parser("trace")
    trace.add_argument("capture", type=Path)
    trace.add_argument("--request", required=True)
    graph = subparsers.add_parser("graph")
    graph.add_argument("capture", type=Path)
    plan = subparsers.add_parser("plan")
    plan.add_argument("capture", type=Path)
    plan.add_argument("--request", required=True)
    plan.add_argument("--output", type=Path)
    report = subparsers.add_parser("report")
    report.add_argument("capture", type=Path)
    report.add_argument("--request", required=True)
    report.add_argument("--output", type=Path)
    report.add_argument("--format", choices=("json", "markdown"), default="json")
    gui = subparsers.add_parser("gui")
    gui.add_argument("capture", type=Path, nargs="?")
    gui.add_argument("--request")

    args = parser.parse_args(argv)
    if args.command == "gui":
        from reqvexa.gui import launch_gui
        launch_gui(args.capture, args.request)
        return 0
    if args.command in {"trace", "plan", "report"}:
        analysis = ProvenanceEngine().analyze(
            HarProvider().load_file(args.capture), target_request_id=args.request
        )
    else:
        analysis = _analysis(str(args.capture))
    if args.command == "analyze":
        print(json.dumps({
            "requests": len(analysis.capture.requests),
            "responses": len(analysis.capture.responses),
            "observations": len(analysis.observations),
            "value_versions": len(analysis.versions),
            "nodes": len(analysis.graph.nodes),
            "edges": len(analysis.graph.edges),
        }, indent=2, sort_keys=True))
    elif args.command == "graph":
        print(json.dumps(analysis.graph_dict(), indent=2, sort_keys=True))
    elif args.command == "plan":
        payload = json.dumps(plan_flow(analysis, args.request).to_dict(),
                             indent=2, sort_keys=True) + "\n"
        _emit(payload, args.output)
    elif args.command == "report":
        report_payload = safe_report(analysis, args.request)
        if args.format == "markdown":
            payload = report_markdown(report_payload)
        else:
            payload = json.dumps(report_payload, indent=2, sort_keys=True) + "\n"
        _emit(payload, args.output)
    else:
        print("\n".join(_trace_lines(analysis, args.request)))
    return 0


def _emit(payload: str, output: Path | None) -> None:
    if output is None:
        print(payload, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
