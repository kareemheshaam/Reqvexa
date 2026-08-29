from __future__ import annotations

from tests.benchmark.cases import all_cases
from tests.benchmark.metrics import f1, precision, recall, set_metrics


def test_benchmark_has_sixteen_adversarial_cases():
    cases = all_cases()
    assert len(cases) == 16
    assert len({case.case_id for case in cases}) == 16


def test_metric_formulas():
    metrics = set_metrics({"a", "b"}, {"b", "c"})
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert precision(1, 1) == 0.5
    assert recall(1, 1) == 0.5
    assert f1(0.5, 0.5) == 0.5
