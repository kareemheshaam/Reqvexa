from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from reqvexa.models import EdgeType
from reqvexa.provenance import Analysis, TraceNode


@dataclass(frozen=True)
class FlowStep:
    request_id: str
    sequence: int
    method: str
    path: str
    role: str
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()


@dataclass(frozen=True)
class FlowPlan:
    target_request_id: str
    steps: tuple[FlowStep, ...]
    unresolved_values: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_request_id": self.target_request_id,
            "steps": [
                {
                    "request_id": step.request_id,
                    "sequence": step.sequence,
                    "method": step.method,
                    "path": step.path,
                    "role": step.role,
                    "consumes": list(step.consumes),
                    "produces": list(step.produces),
                }
                for step in self.steps
            ],
            "unresolved_values": list(self.unresolved_values),
            "warnings": list(self.warnings),
        }


def plan_flow(analysis: Analysis, target_request_id: str) -> FlowPlan:
    trace = analysis.trace(target_request_id)
    required_versions = _trace_versions(trace)
    request_ids: set[str] = {target_request_id}

    # Walk every state value in each selected request, not only values that
    # were roots of the original target trace. This exposes unresolved
    # client-generated inputs in prerequisite requests as well.
    changed = True
    while changed:
        changed = False
        for request_id in tuple(sorted(request_ids)):
            for observation_id in analysis.request_observation_ids.get(request_id, ()):
                request = analysis.capture.request(request_id)
                version = _version_for_observation(analysis, observation_id, request.sequence)
                if version is None:
                    continue
                for hypothesis in analysis.target_producers.get(version.version_id, ()):
                    producer_request_id = _producer_request_id(analysis, hypothesis.producer)
                    if producer_request_id not in request_ids:
                        request_ids.add(producer_request_id)
                        changed = True

    steps: list[FlowStep] = []
    for request_id in sorted(request_ids,
                             key=lambda item: (analysis.capture.request(item).sequence, item)):
        request = analysis.capture.request(request_id)
        consumed = sorted({
            value_name(analysis, analysis.versions[version_id].value_id)
            for observation_id in analysis.request_observation_ids.get(request_id, ())
            for version_id, version in analysis.versions.items()
            if observation_id in analysis.value_observation_ids.get(version.value_id, ())
            and _observation_version_matches(analysis, observation_id, version_id, request.sequence)
        })
        produced = sorted({
            value_name(analysis, analysis.versions[version_id].value_id)
            for version_id in required_versions
            for hypothesis in analysis.target_producers.get(version_id, ())
            if _producer_request_id(analysis, hypothesis.producer) == request_id
        })
        role = "target" if request_id == target_request_id else "producer"
        steps.append(FlowStep(
            request_id=request_id,
            sequence=request.sequence,
            method=request.method,
            path=_safe_path(request.url),
            role=role,
            consumes=tuple(consumed),
            produces=tuple(produced),
        ))

    flow_version_ids = _flow_version_ids(analysis, tuple(steps))
    flow_nodes = {
        node.version_id: node
        for version_id in flow_version_ids
        for node in [analysis._trace_version(version_id, {}, set())]
    }
    unresolved = tuple(sorted({
        value_name(analysis, node.value_id)
        for node in flow_nodes.values()
        if node.status == "UNKNOWN"
    }))
    warnings = [
        "Plan is observational only; it does not execute or replay requests.",
    ]
    if unresolved:
        warnings.append("Some target values have no compatible prior response observation.")
    if any(node.status == "HYPOTHETICAL" for node in trace):
        warnings.append("Some dependencies are hypotheses and require verification.")
    return FlowPlan(target_request_id, tuple(steps), unresolved, tuple(warnings))


def safe_report(analysis: Analysis, target_request_id: str,
                unsafe_raw: bool = False) -> dict[str, Any]:
    plan = plan_flow(analysis, target_request_id)
    trace = analysis.trace(target_request_id)
    trace_nodes = {node.version_id: node for node in _trace_nodes(trace)}
    for version_id in _flow_version_ids(analysis, plan.steps):
        trace_nodes.setdefault(
            version_id, analysis._trace_version(version_id, {}, set())
        )
    values: list[dict[str, Any]] = []
    for node in sorted(trace_nodes.values(), key=lambda item: (item.value_id, item.version_id)):
        version = analysis.versions[node.version_id]
        producers = []
        for hypothesis in analysis.target_producers.get(node.version_id, ()):
            producer_request_id = _producer_request_id(analysis, hypothesis.producer)
            producer_request = analysis.capture.request(producer_request_id)
            producers.append({
                "request_id": producer_request_id,
                "sequence": producer_request.sequence,
                "method": producer_request.method,
                "path": _safe_path(producer_request.url),
                "confidence": hypothesis.confidence,
                "status": hypothesis.status,
                "category": hypothesis.category.value,
                "match_methods": _edge_methods(analysis, hypothesis.producer, node.version_id),
            })
        values.append({
            "value_id": node.value_id,
            "name": value_name(analysis, node.value_id),
            "version_id": node.version_id,
            "status": node.status,
            "display_value": (
                version.raw_value
                if unsafe_raw else version.display_value
            ),
            "value_digest": version.value_digest,
            "valid_from": version.valid_from,
            "valid_until": version.valid_until,
            "producers": producers,
            "note": node.note,
        })
    target = analysis.capture.request(target_request_id)
    return {
        "schema_version": 1,
        "target": {
            "request_id": target.id,
            "sequence": target.sequence,
            "method": target.method,
            "path": _safe_path(target.url),
        },
        "capture": {
            "requests": len(analysis.capture.requests),
            "responses": len(analysis.capture.responses),
            "observations": len(analysis.observations),
            "value_versions": len(analysis.versions),
        },
        "plan": plan.to_dict(),
        "values": values,
    }


def value_name(analysis: Analysis, value_id: str) -> str:
    """Return a stable human-readable semantic name for a logical value."""
    observation_ids = analysis.value_observation_ids.get(value_id, ())
    observations = [
        analysis.observations_by_id[item]
        for item in observation_ids
        if item in analysis.observations_by_id
    ]
    hints = sorted({
        hint for observation in observations for hint in observation.semantic_hints
        if hint
    })
    if hints:
        hint = hints[0]
        return hint.removeprefix("cookie.") if hint.startswith("cookie.") else hint
    for observation in observations:
        path = observation.location.path or ""
        leaf = path.rsplit(".", 1)[-1].rsplit("/", 1)[-1].split("[", 1)[0]
        if leaf and leaf != "$":
            return leaf
    return value_id.replace("value_", "value:")


def report_markdown(report: dict[str, Any]) -> str:
    target = report["target"]
    capture = report["capture"]
    plan = report["plan"]
    lines = [
        "# Reqvexa Safe Report",
        "",
        "## Target",
        "",
        f"- Request: `{target['request_id']}`",
        f"- Sequence: `{target['sequence']}`",
        f"- Method: `{target['method']}`",
        f"- Path: `{target['path']}`",
        "",
        "## Capture",
        "",
        f"- Requests: `{capture['requests']}`",
        f"- Responses: `{capture['responses']}`",
        f"- Observations: `{capture['observations']}`",
        f"- Value versions: `{capture['value_versions']}`",
        "",
        "## Planned Steps",
        "",
        "| Sequence | Role | Method | Path | Consumes | Produces |",
        "|---:|---|---|---|---|---|",
    ]
    for step in plan["steps"]:
        consumes = ", ".join(f"`{value}`" for value in step["consumes"]) or "-"
        produces = ", ".join(f"`{value}`" for value in step["produces"]) or "-"
        lines.append(
            f"| {step['sequence']} | {step['role']} | `{step['method']}` | "
            f"`{step['path']}` | {consumes} | {produces} |"
        )
    lines.extend(["", "## Values", "", "| Value | Version | Status | Display | Confidence |",
                  "|---|---|---|---|---:|"])
    for value in report["values"]:
        confidences = [
            producer["confidence"] for producer in value["producers"]
            if producer["confidence"] is not None
        ]
        confidence = max(confidences, default=0.0)
        lines.append(
            f"| `{value['name']}` | `{value['version_id']}` | "
            f"`{value['status']}` | `{value['display_value']}` | {confidence:.3f} |"
        )
    lines.extend(["", "## Unresolved Values", ""])
    if plan["unresolved_values"]:
        lines.extend(f"- `{value}`" for value in plan["unresolved_values"])
    else:
        lines.append("- None")
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {warning}" for warning in plan["warnings"])
    lines.append("")
    return "\n".join(lines)


def _trace_versions(nodes: tuple[TraceNode, ...]) -> set[str]:
    return {node.version_id for node in _trace_nodes(nodes)}


def _trace_nodes(nodes: tuple[TraceNode, ...]) -> set[TraceNode]:
    result: set[TraceNode] = set()
    stack = list(nodes)
    while stack:
        node = stack.pop()
        if node in result:
            continue
        result.add(node)
        stack.extend(node.children)
    return result


def _producer_request_id(analysis: Analysis, producer_id: str) -> str:
    if producer_id.startswith("response_"):
        response_id = producer_id.removeprefix("response_")
        return analysis.graph.nodes[response_id].payload["request_id"]
    return producer_id


def _observation_version_matches(analysis: Analysis, observation_id: str,
                                 version_id: str, sequence: int) -> bool:
    observation = analysis.observations_by_id[observation_id]
    version = analysis.versions[version_id]
    return (
        version.value_id == _value_id_for_observation(analysis, observation_id)
        and _values_match(version.raw_value, observation.normalized_value)
        and version.valid_from <= sequence
        and (version.valid_until is None or sequence < version.valid_until)
    )


def _value_id_for_observation(analysis: Analysis, observation_id: str) -> str:
    for value_id, ids in analysis.value_observation_ids.items():
        if observation_id in ids:
            return value_id
    return ""


def _flow_version_ids(analysis: Analysis, steps: tuple[FlowStep, ...]) -> set[str]:
    result: set[str] = set()
    for step in steps:
        request = analysis.capture.request(step.request_id)
        for observation_id in analysis.request_observation_ids.get(step.request_id, ()):
            version = _version_for_observation(analysis, observation_id, request.sequence)
            if version is not None:
                result.add(version.version_id)
    return result


def _version_for_observation(analysis: Analysis, observation_id: str,
                             sequence: int) -> Any | None:
    observation = analysis.observations_by_id[observation_id]
    candidates = [
        version for version in analysis.versions.values()
        if version.value_id == _value_id_for_observation(analysis, observation_id)
        and version.valid_from <= sequence
        and (version.valid_until is None or sequence < version.valid_until)
        and _values_match(version.raw_value, observation.normalized_value)
    ]
    return max(candidates, key=lambda version: version.valid_from, default=None)


def _values_match(left: str, right: str) -> bool:
    if left == right:
        return True
    left_parts = left.split(None, 1)
    right_parts = right.split(None, 1)
    if left_parts and left_parts[0].lower() == "bearer":
        left = left_parts[1] if len(left_parts) == 2 else ""
    if right_parts and right_parts[0].lower() == "bearer":
        right = right_parts[1] if len(right_parts) == 2 else ""
    return left == right


def _edge_methods(analysis: Analysis, producer: str, version_id: str) -> list[str]:
    return sorted({
        edge.inference_method
        for edge in analysis.graph.edges.values()
        if edge.type == EdgeType.PRODUCES
        and edge.source == producer
        and edge.target == version_id
    })


def _safe_path(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    safe_segments = [
        "<redacted>" if len(segment) > 48 else segment
        for segment in path.split("/")
    ]
    return "/".join(safe_segments)
