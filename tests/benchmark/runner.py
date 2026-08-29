from __future__ import annotations

import json
from typing import Any

from reqvexa.provenance import ProvenanceEngine

from .cases import BenchmarkCase, all_cases
from .metrics import f1, false_dependency_rate, set_metrics


def _target_observations(analysis: Any, case: BenchmarkCase) -> list[Any]:
    return [
        item for item in analysis.observations
        if item.request_id == case.target_request_id and item.response_id is None
        and item.location.container != "request.path"
    ]


def evaluate_case(case: BenchmarkCase) -> dict[str, Any]:
    analysis = ProvenanceEngine().analyze(case.capture)
    target = _target_observations(analysis, case)
    actual_values = {
        _label(item.semantic_hint or item.location.path or "")
        for item in target
    }
    actual_versions = {item.normalized_value for item in target}
    actual_producers = {
        f"{_label(item.semantic_hint or item.location.path)}:{analysis.versions[version_id].raw_value}"
        for item in target
        for version_id, version in analysis.versions.items()
        if version.value_id in analysis.value_observation_ids
        and item.observation_id in analysis.value_observation_ids[version.value_id]
        for hypothesis in analysis.target_producers.get(version_id, ())
        if hypothesis.status == "SUPPORTED"
    }
    actual_unresolved = {
        item.normalized_value for item in target
        if not any(
            hypothesis.status == "SUPPORTED"
            for version_id, version in analysis.versions.items()
            if version.raw_value == item.normalized_value
            for hypothesis in analysis.target_producers.get(version_id, ())
        )
    }
    value_metrics = set_metrics(case.expected_logical_values, actual_values)
    version_metrics = set_metrics(case.expected_versions, actual_versions)
    producer_metrics = set_metrics(case.expected_supported_producers, actual_producers)
    return {
        "case_id": case.case_id,
        "extraction": _metric_dict(value_metrics),
        "identity": _metric_dict(version_metrics),
        "version_resolution_accuracy": version_metrics.recall,
        "producer": {
            **_metric_dict(producer_metrics),
            "f1": f1(producer_metrics.precision, producer_metrics.recall),
        },
        "false_dependency_rate": false_dependency_rate(
            case.expected_unsupported_producers, actual_producers),
        "unresolved_value_rate": (
            len(actual_unresolved & set(case.expected_unresolved)) / len(case.expected_unresolved)
            if case.expected_unresolved else (1.0 if not actual_unresolved else 0.0)
        ),
        "trace_accuracy": 1.0 if actual_unresolved == set(case.expected_unresolved) else 0.0,
        "actual": {
            "logical_values": sorted(actual_values),
            "versions": sorted(actual_versions),
            "supported_producers": sorted(actual_producers),
            "unresolved": sorted(actual_unresolved),
        },
    }


def _label(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith("cookie."):
        return lowered
    lowered = lowered.removeprefix("x-")
    aliases = {
        "csrf": "csrf",
        "csrf-token": "csrf",
        "x-csrf": "csrf",
        "token": "token",
    }
    return aliases.get(lowered, lowered)


def run_benchmark(cases: tuple[BenchmarkCase, ...] | None = None,
                  *, fail_on_mismatch: bool = True) -> dict[str, Any]:
    selected = cases or all_cases()
    results = [evaluate_case(case) for case in selected]
    failures = [result for result in results if result["trace_accuracy"] != 1.0]
    aggregate = {
        "extraction_precision": _mean(result["extraction"]["precision"] for result in results),
        "extraction_recall": _mean(result["extraction"]["recall"] for result in results),
        "identity_precision": _mean(result["identity"]["precision"] for result in results),
        "identity_recall": _mean(result["identity"]["recall"] for result in results),
        "version_resolution_accuracy": _mean(result["version_resolution_accuracy"] for result in results),
        "producer_precision": _mean(result["producer"]["precision"] for result in results),
        "producer_recall": _mean(result["producer"]["recall"] for result in results),
        "producer_f1": _mean(result["producer"]["f1"] for result in results),
        "false_dependency_rate": _mean(result["false_dependency_rate"] for result in results),
        "unresolved_value_rate": _mean(result["unresolved_value_rate"] for result in results),
        "trace_accuracy": _mean(result["trace_accuracy"] for result in results),
    }
    report = {
        "case_count": len(results),
        "failed_cases": [result["case_id"] for result in failures],
        "aggregate": aggregate,
        "results": results,
    }
    if failures and fail_on_mismatch:
        raise AssertionError(json.dumps(report, indent=2, sort_keys=True))
    return report


def _mean(values: Any) -> float:
    values = list(values)
    return round(sum(values) / len(values), 6) if values else 1.0


def _metric_dict(metrics: Any) -> dict[str, Any]:
    return {
        "true_positives": metrics.true_positives,
        "false_positives": metrics.false_positives,
        "false_negatives": metrics.false_negatives,
        "precision": metrics.precision,
        "recall": metrics.recall,
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(fail_on_mismatch=False), indent=2, sort_keys=True))
