from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PairwiseCorrelationMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float


def pairwise_correlation_metrics(
    expected_group_by_event: Mapping[str, str],
    predicted_group_by_event: Mapping[str, str],
) -> PairwiseCorrelationMetrics:
    event_ids = sorted(set(expected_group_by_event) & set(predicted_group_by_event))
    tp = fp = fn = 0
    for index, left in enumerate(event_ids):
        for right in event_ids[index + 1 :]:
            expected = expected_group_by_event[left] == expected_group_by_event[right]
            predicted = predicted_group_by_event[left] == predicted_group_by_event[right]
            if expected and predicted:
                tp += 1
            elif predicted:
                fp += 1
            elif expected:
                fn += 1
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return PairwiseCorrelationMetrics(tp, fp, fn, precision, recall)


def connected_groups(keys_by_event: Mapping[str, Sequence[str]]) -> dict[str, str]:
    """Order-independent connected components for events sharing any candidate key."""
    parent = {event_id: event_id for event_id in keys_by_event}

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left: str, right: str) -> None:
        a, b = find(left), find(right)
        if a != b:
            low, high = sorted((a, b))
            parent[high] = low

    owner_by_key: dict[str, str] = {}
    for event_id in sorted(keys_by_event):
        for key in keys_by_event[event_id]:
            owner = owner_by_key.setdefault(key, event_id)
            union(event_id, owner)
    return {event_id: find(event_id) for event_id in keys_by_event}
