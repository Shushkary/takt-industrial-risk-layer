"""Движок подсказок ``PlaybookEngine`` — детерминированный, без LLM.

Читает декларативные правила (``playbooks/default.yaml``) и по состоянию кейса
возвращает отсортированный список подсказок. Никакой рандомизации и обращений к
внешним сервисам: при одинаковом входе всегда один и тот же выход.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class CaseState:
    """Снимок состояния кейса для подбора подсказок."""

    severity: str
    status: str
    invariant_hits: tuple[str, ...] = ()
    source_classes: tuple[str, ...] = ()
    degraded_sources: bool = False


@dataclass(frozen=True, slots=True)
class Hint:
    """Подсказка плейбука: рекомендация и приоритет."""

    rule_id: str
    recommendation: str
    priority: int


@dataclass(frozen=True, slots=True)
class PlaybookRule:
    """Правило плейбука: условие → рекомендация с приоритетом."""

    rule_id: str
    condition: dict[str, Any]
    recommendation: str
    priority: int


class PlaybookEngine:
    """Сопоставляет состояние кейса с правилами и выдаёт подсказки."""

    def __init__(self, rules: list[PlaybookRule]) -> None:
        self._rules = list(rules)

    @classmethod
    def from_yaml(cls, path: str | Path) -> PlaybookEngine:
        """Загрузить правила из YAML-файла (``playbooks/default.yaml``)."""
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules_raw = raw.get("rules", []) if isinstance(raw, dict) else []
        rules: list[PlaybookRule] = []
        for i, item in enumerate(rules_raw):
            rules.append(
                PlaybookRule(
                    rule_id=str(item.get("id", f"rule-{i + 1}")),
                    condition=dict(item.get("condition", {})),
                    recommendation=str(item.get("recommendation", "")),
                    priority=int(item.get("priority", 0)),
                )
            )
        return cls(rules)

    def get_hints(self, case_state: CaseState) -> list[Hint]:
        """Детерминированный набор подсказок для состояния кейса."""
        matched: list[Hint] = []
        for rule in self._rules:
            if self._matches(rule.condition, case_state):
                matched.append(
                    Hint(rule_id=rule.rule_id, recommendation=rule.recommendation, priority=rule.priority)
                )
        # Детерминированная сортировка: приоритет по убыванию, затем rule_id.
        matched.sort(key=lambda h: (-h.priority, h.rule_id))
        return matched

    @staticmethod
    def _matches(condition: dict[str, Any], state: CaseState) -> bool:
        for field_name, expected in condition.items():
            actual = getattr(state, field_name, None)
            if isinstance(actual, tuple):
                # Для перечислений (invariant_hits, source_classes): вхождение значения.
                if expected not in actual:
                    return False
            else:
                if actual != expected:
                    return False
        return True
