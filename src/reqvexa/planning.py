from __future__ import annotations

import re
from collections import deque
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


def plan_flow(analysis: Analysis, target_request_id: str,
              trace: tuple[TraceNode, ...] | None = None,
              recursive: bool | None = None) -> FlowPlan:
    """Plan the requests needed for one target.

    ``recursive=False`` keeps only the target and the first request each of
    its values appeared in; ``None`` inherits the analysis depth.
    """
    if recursive is None:
        recursive = analysis.recursive
    if trace is None:
        trace = analysis.trace(target_request_id, recursive=recursive)
    required_versions = _trace_versions(trace)
    request_ids: set[str] = {target_request_id}
    matching = _observation_versions(analysis)

    def _chosen_version(observation_id: str) -> Any | None:
        return max(
            matching.get(observation_id, ()),
            key=lambda version: version.valid_from, default=None,
        )

    # Walk every state value in each selected request, not only values that
    # were roots of the original target trace. This exposes unresolved
    # client-generated inputs in prerequisite requests as well. The worklist
    # reaches the identical monotone closure while scanning every request's
    # observations exactly once (the previous fixed-point loop re-scanned all
    # observations for every round that discovered a new request).
    queue: deque[str] = deque([target_request_id])
    while queue:
        request_id = queue.popleft()
        for observation_id in analysis.request_observation_ids.get(request_id, ()):
            version = _chosen_version(observation_id)
            if version is None:
                continue
            for hypothesis in analysis.target_producers.get(version.version_id, ()):
                producer_request_id = _producer_request_id(analysis, hypothesis.producer)
                if producer_request_id not in request_ids:
                    request_ids.add(producer_request_id)
                    if recursive:
                        queue.append(producer_request_id)

    # Logical-value names repeat across steps; resolve each one once.
    names: dict[str, str] = {}

    def _resolved(value_id: str) -> str:
        cached = names.get(value_id)
        if cached is None:
            cached = value_name(analysis, value_id)
            names[value_id] = cached
        return cached

    # Producer request -> produced value names, built once so no step has to
    # re-filter every traced version against its own request id.
    produced_names: dict[str, set[str]] = {}
    for version_id in required_versions:
        for hypothesis in analysis.target_producers.get(version_id, ()):
            produced_names.setdefault(
                _producer_request_id(analysis, hypothesis.producer), set(),
            ).add(_resolved(analysis.versions[version_id].value_id))

    steps: list[FlowStep] = []
    for request_id in sorted(request_ids,
                             key=lambda item: (analysis.capture.request(item).sequence, item)):
        request = analysis.capture.request(request_id)
        # Matched versions per observation are precomputed by the sweep, so
        # matching no longer scans a value's full version bucket per
        # observation (the admitted pairs are exactly the earlier scan's).
        consumed = sorted({
            _resolved(version.value_id)
            for observation_id in analysis.request_observation_ids.get(request_id, ())
            for version in matching.get(observation_id, ())
        })
        produced = sorted(produced_names.get(request_id, set()))
        role = "target" if request_id == target_request_id else "producer"
        steps.append(FlowStep(
            request_id=request_id,
            sequence=request.sequence,
            method=request.method,
            path=safe_path(request.url),
            role=role,
            consumes=tuple(consumed),
            produces=tuple(produced),
        ))

    # One-level plans care only about the target's own values; recursive
    # plans include everything the prerequisite requests consume too.
    flow_version_ids = (
        _flow_version_ids(analysis, tuple(steps)) if recursive
        else required_versions
    )
    # ``status == "UNKNOWN"`` holds for a flow version exactly when it has no
    # producer hypotheses (every other root status derives from them), so the
    # unresolved set needs no per-version trace walk: walking each flow
    # version re-descended unbounded cycle portions of the producer graph.
    unresolved = tuple(sorted({
        value_name(analysis, analysis.versions[version_id].value_id)
        for version_id in flow_version_ids
        if not analysis.target_producers.get(version_id, ())
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
                unsafe_raw: bool = False,
                recursive: bool | None = None) -> dict[str, Any]:
    if recursive is None:
        recursive = analysis.recursive
    # The trace feeds both the plan and the value table; compute it once and
    # let plan_flow reuse it instead of retracing the identical graph.
    trace = analysis.trace(target_request_id, recursive=recursive)
    plan = plan_flow(
        analysis, target_request_id, trace=trace, recursive=recursive,
    )
    trace_nodes = dict(_trace_nodes(trace))
    if recursive:
        # Producer requests in the plan consume their own values too; include
        # them for a complete report. One-level reports stay limited to the
        # target's values.
        for version_id in _flow_version_ids(analysis, plan.steps):
            trace_nodes.setdefault(version_id, analysis.trace_version(version_id))
    values: list[dict[str, Any]] = []
    edge_methods = _index_edge_methods(analysis.graph.edges)
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
                "path": safe_path(producer_request.url),
                "confidence": hypothesis.confidence,
                "status": hypothesis.status,
                "category": hypothesis.category.value,
                "match_methods": list(edge_methods.get(
                    (hypothesis.producer, node.version_id), ())),
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
            "path": safe_path(target.url),
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
    return set(_trace_nodes(nodes).keys())


def _trace_nodes(nodes: tuple[TraceNode, ...]) -> dict[str, TraceNode]:
    """Reachable trace nodes keyed by version id.

    Collects by version-id keys rather than hashing node values: dataclass
    hashing recurses through children tuples and explodes exponentially once
    memoized nodes are shared by reference across parents.
    """
    by_id: dict[str, TraceNode] = {}
    stack = list(nodes)
    while stack:
        node = stack.pop()
        if node.version_id in by_id:
            continue
        by_id[node.version_id] = node
        stack.extend(node.children)
    return by_id


def _producer_request_id(analysis: Analysis, producer_id: str) -> str:
    if producer_id.startswith("response_"):
        response_id = producer_id.removeprefix("response_")
        return analysis.graph.nodes[response_id].payload["request_id"]
    return producer_id


def _match_key(value: str) -> str:
    """Bearer-insensitive representation mirroring planning._values_match."""
    parts = value.split(None, 1)
    if parts and parts[0].lower() == "bearer":
        return parts[1] if len(parts) == 2 else ""
    return value


def _observation_versions(analysis: Analysis) -> dict[str, tuple[Any, ...]]:
    """Value- and window-matching versions for every state observation.

    A match set depends only on the owning request's sequence, so it is
    computed once per observation. ``_values_match(left, right)`` is exactly
    "equal raw or equal Bearer-stripped raw", so per logical value the
    versions are indexed by both representations; each observation does O(1)
    lookups under its own raw and stripped value and window-filters only the
    few hits. Candidate order is the original bucket position order, which
    preserves the previous max(valid_from) tie-breaking.
    """
    sequences = {request.id: request.sequence for request in analysis.capture.requests}
    by_id = analysis.observations_by_id
    results: dict[str, tuple[Any, ...]] = {}
    for value_id, observation_ids in analysis.value_observation_ids.items():
        bucket = analysis.versions_by_value.get(value_id, ())
        index: dict[str, list[tuple[int, Any]]] = {}
        for position, version in enumerate(bucket):
            index.setdefault(version.raw_value, []).append((position, version))
            stripped_key = _match_key(version.raw_value)
            if stripped_key != version.raw_value:
                index.setdefault(stripped_key, []).append((position, version))
        for observation_id in sorted(
            observation_ids,
            key=lambda item: (sequences.get(by_id[item].request_id or "", -1), item),
        ):
            observation = by_id[observation_id]
            sequence = sequences.get(observation.request_id or "", -1)
            candidates: dict[int, Any] = {}
            normalized_key = _match_key(observation.normalized_value)
            for key in (observation.normalized_value, normalized_key):
                for position, version in index.get(key, ()):
                    if (version.valid_from <= sequence
                            and (version.valid_until is None or sequence < version.valid_until)):
                        candidates[position] = version
            results[observation_id] = tuple(
                version for _, version in sorted(candidates.items())
            )
    return results


def _flow_version_ids(analysis: Analysis, steps: tuple[FlowStep, ...]) -> set[str]:
    matching = _observation_versions(analysis)
    result: set[str] = set()
    for step in steps:
        for observation_id in analysis.request_observation_ids.get(step.request_id, ()):
            version = max(
                matching.get(observation_id, ()),
                key=lambda item: item.valid_from, default=None,
            )
            if version is not None:
                result.add(version.version_id)
    return result


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


def _index_edge_methods(edges: dict[str, Any]) -> dict[tuple[str, str], tuple[str, ...]]:
    """Group PRODUCES edge inference methods by (producer, version) pair."""
    grouped: dict[tuple[str, str], set[str]] = {}
    for edge in edges.values():
        if edge.type == EdgeType.PRODUCES:
            grouped.setdefault(
                (edge.source, edge.target), set(),
            ).add(edge.inference_method)
    return {pair: tuple(sorted(methods)) for pair, methods in grouped.items()}


def safe_path(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    safe_segments = [
        "<redacted>" if len(segment) > 48 else segment
        for segment in path.split("/")
    ]
    return "/".join(safe_segments)


def _mermaid_label(text: str) -> str:
    return text.replace("\\", "").replace('"', "#quot;").replace("\n", " ")


def report_mermaid(report: dict[str, Any]) -> str:
    """Render the safe report plan as a deterministic Mermaid flowchart."""
    plan = report["plan"]
    unresolved = set(plan["unresolved_values"])
    assigned: dict[str, str] = {}
    used: set[str] = set()
    step_lines: list[str] = []
    state_lines: list[str] = []
    edges: list[str] = []
    target_ids: list[str] = []

    def node_id(logical_key: str) -> str:
        if logical_key in assigned:
            return assigned[logical_key]
        candidate = re.sub(r"[^A-Za-z0-9_]", "_", logical_key.split(":", 1)[-1]) or "node"
        unique: str = candidate
        suffix = 0
        while unique in used:
            suffix += 1
            unique = f"{candidate}{suffix}"
        used.add(unique)
        assigned[logical_key] = unique
        return unique

    for step in plan["steps"]:
        step_node = node_id(f"step:{step['sequence']}:{step['method']}:{step['path']}")
        label = _mermaid_label(f"{step['method']} {step['path']}")
        if step["role"] == "target":
            label = f"{label} (target)"
        step_lines.append(f'    {step_node}["{label}"]')
        if step["role"] == "target":
            target_ids.append(step_node)
        for value in step["produces"]:
            value_node = node_id(f"value:{value}")
            value_label = _mermaid_label(value)
            state_lines.append(f'    {value_node}(("{value_label}"))')
            edges.append(f'    {step_node} -- "{value_label}" --> {value_node}')
        for value in step["consumes"]:
            if value in step["produces"]:
                continue
            value_node = node_id(f"value:{value}")
            value_label = _mermaid_label(value)
            state_lines.append(f'    {value_node}(("{value_label}"))')
            if value in unresolved:
                edges.append(f'    {value_node} -. "unresolved {value_label}" .-> {step_node}')
            else:
                edges.append(f'    {value_node} -- "{value_label}" --> {step_node}')

    lines: list[str] = ["flowchart LR", *step_lines,
                        *dict.fromkeys(state_lines), *edges]
    if target_ids:
        lines.extend((
            "    classDef target stroke:#22c55e,stroke-width:3px;",
            f"    class {','.join(target_ids)} target;",
        ))
    unresolved_nodes = sorted({
        node_id(f"value:{value}") for value in unresolved
        if f"value:{value}" in assigned
    })
    if unresolved_nodes:
        lines.extend((
            "    classDef unresolved stroke:#f59e0b,stroke-dasharray:4 3;",
            f"    class {','.join(unresolved_nodes)} unresolved;",
        ))
    lines.append("")
    return "\n".join(lines)

