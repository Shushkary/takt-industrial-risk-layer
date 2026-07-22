"""
Регрессия для протокола true positive / false positive (`scripts/eval_detection.py`,
`docs/detection_quality.md`): по каждому инварианту в объёме корпуса
`tests/fixtures/detection_eval/scenarios.py` TPR должен оставаться 1.0,
а FPR — 0.0. Падение теста означает, что предикат перестал ловить эталонную
атаку или начал ложно срабатывать на легитимный сценарий из корпуса.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "detection_eval"
sys.path.insert(0, str(_FIXTURES_DIR))

from eval_core import evaluate  # noqa: E402
from scenarios import IN_SCOPE_INVARIANT_IDS, all_scenarios  # noqa: E402


def test_detection_eval_corpus_has_both_classes_per_invariant() -> None:
    scenarios = all_scenarios()
    for iid in IN_SCOPE_INVARIANT_IDS:
        attacks = [s for s in scenarios if iid in s.expected_hits]
        assert attacks, f"no attack scenario labelled for {iid}"
    benign = [s for s in scenarios if not s.expected_hits]
    assert len(benign) >= len(IN_SCOPE_INVARIANT_IDS)


@pytest.mark.parametrize("invariant_id", sorted(IN_SCOPE_INVARIANT_IDS))
def test_in_scope_invariant_has_perfect_tpr_and_zero_fpr(invariant_id: str) -> None:
    matrix = evaluate()
    c = matrix[invariant_id]
    assert c.tpr == 1.0, f"{invariant_id}: TPR={c.tpr} (missed a labelled attack scenario)"
    assert c.fpr == 0.0, f"{invariant_id}: FPR={c.fpr} (fired on a labelled benign scenario)"
