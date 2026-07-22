from __future__ import annotations

import itertools
from pathlib import Path

from scripts.eval_correlation import evaluate

from takt.domain.engines.correlation_quality import connected_groups

FIXTURE = Path(__file__).parent / "fixtures" / "pt_techlab" / "correlation" / "scenarios.json"


def test_correlation_quality_baseline() -> None:
    result = evaluate(FIXTURE)
    assert result["events"] == 7
    assert result["pairwise_precision"] == 1.0
    assert result["pairwise_recall"] == 1.0


def test_connected_grouping_is_independent_of_event_order() -> None:
    items = [("a", ["host:1"]), ("b", ["host:1", "hash:x"]), ("c", ["hash:x"]), ("d", ["host:2"])]
    expected_partition = {frozenset({"a", "b", "c"}), frozenset({"d"})}
    for permutation in itertools.permutations(items):
        groups = connected_groups(dict(permutation))
        partition = {frozenset(event for event, group in groups.items() if group == value) for value in set(groups.values())}
        assert partition == expected_partition
