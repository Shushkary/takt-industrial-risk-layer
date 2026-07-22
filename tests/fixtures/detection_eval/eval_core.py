"""Общая логика подсчёта TPR/FPR, используется скриптом `scripts/eval_detection.py`
и регрессионным тестом `tests/test_detection_quality.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

from takt.domain.invariants.evaluator import collect_extended_invariants

from scenarios import IN_SCOPE_INVARIANT_IDS, EvalScenario, all_scenarios  # noqa: F401


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def tpr(self) -> float | None:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def fpr(self) -> float | None:
        denom = self.fp + self.tn
        return self.fp / denom if denom else None


def run_scenario(sc: EvalScenario) -> frozenset[str]:
    return frozenset(collect_extended_invariants(sc.event, sc.recent, sc.ctx))


def evaluate() -> dict[str, Confusion]:
    scenarios = all_scenarios()
    matrix: dict[str, Confusion] = {iid: Confusion() for iid in sorted(IN_SCOPE_INVARIANT_IDS)}
    for sc in scenarios:
        actual = run_scenario(sc)
        for iid in IN_SCOPE_INVARIANT_IDS:
            expected = iid in sc.expected_hits
            got = iid in actual
            c = matrix[iid]
            if expected and got:
                c.tp += 1
            elif expected and not got:
                c.fn += 1
            elif not expected and got:
                c.fp += 1
            else:
                c.tn += 1
    return matrix
