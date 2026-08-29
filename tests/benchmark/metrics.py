from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


def precision(true_positives: int, false_positives: int) -> float:
    denominator = true_positives + false_positives
    return true_positives / denominator if denominator else 1.0


def recall(true_positives: int, false_negatives: int) -> float:
    denominator = true_positives + false_negatives
    return true_positives / denominator if denominator else 1.0


def f1(precision_value: float, recall_value: float) -> float:
    denominator = precision_value + recall_value
    return 2 * precision_value * recall_value / denominator if denominator else 0.0


@dataclass(frozen=True)
class SetMetrics:
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        return precision(self.true_positives, self.false_positives)

    @property
    def recall(self) -> float:
        return recall(self.true_positives, self.false_negatives)

    @property
    def f1(self) -> float:
        return f1(self.precision, self.recall)


def set_metrics(expected: Iterable[str], actual: Iterable[str]) -> SetMetrics:
    expected_set = set(expected)
    actual_set = set(actual)
    return SetMetrics(
        true_positives=len(expected_set & actual_set),
        false_positives=len(actual_set - expected_set),
        false_negatives=len(expected_set - actual_set),
    )


def false_dependency_rate(expected_unsupported: Iterable[str],
                          actual_supported: Iterable[str]) -> float:
    unsupported = set(expected_unsupported)
    if not unsupported:
        return 0.0
    return len(unsupported & set(actual_supported)) / len(unsupported)


def unresolved_value_rate(expected_unresolved: Iterable[str],
                          actual_unresolved: Iterable[str]) -> float:
    expected = set(expected_unresolved)
    actual = set(actual_unresolved)
    return len(actual & expected) / len(expected) if expected else (1.0 if not actual else 0.0)
