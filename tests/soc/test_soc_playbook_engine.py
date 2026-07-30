"""Тесты детерминированного движка подсказок ``PlaybookEngine``."""

from __future__ import annotations

from pathlib import Path

from takt.application.soc.playbook_engine import CaseState, PlaybookEngine

_PLAYBOOK = Path(__file__).resolve().parents[2] / "playbooks" / "default.yaml"


def _engine() -> PlaybookEngine:
    return PlaybookEngine.from_yaml(_PLAYBOOK)


def test_playbook_loads_at_least_five_rules() -> None:
    eng = _engine()
    # Прогоняем состояние, покрывающее несколько правил, — движок читается без ошибок.
    hints = eng.get_hints(CaseState(severity="high", status="new"))
    assert len(hints) >= 2


def test_high_severity_and_new_status_hints_sorted() -> None:
    eng = _engine()
    hints = eng.get_hints(CaseState(severity="high", status="new"))
    ids = [h.rule_id for h in hints]
    assert "high-severity-escalate" in ids
    assert "new-case-triage" in ids
    # Детерминированная сортировка: приоритет по убыванию.
    priorities = [h.priority for h in hints]
    assert priorities == sorted(priorities, reverse=True)


def test_membership_condition_matches() -> None:
    eng = _engine()
    hints = eng.get_hints(CaseState(severity="low", status="open", invariant_hits=("brute_force",)))
    assert any(h.rule_id == "brute-force-lock-review" for h in hints)


def test_degraded_sources_hint() -> None:
    eng = _engine()
    hints = eng.get_hints(CaseState(severity="low", status="open", degraded_sources=True))
    assert any(h.rule_id == "degraded-sources-verify" for h in hints)


def test_no_match_returns_empty() -> None:
    eng = _engine()
    hints = eng.get_hints(CaseState(severity="none", status="closed"))
    assert hints == []


def test_determinism_repeated_calls() -> None:
    eng = _engine()
    state = CaseState(severity="high", status="new", invariant_hits=("lateral_movement",), source_classes=("ot",))
    assert eng.get_hints(state) == eng.get_hints(state)
