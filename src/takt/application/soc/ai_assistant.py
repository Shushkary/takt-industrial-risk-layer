"""Изолированный порт AI-ассистента (заглушка для спринта 7).

Модуль намеренно вынесен отдельно и не используется движком подсказок: подсказки
итерации 1 полностью детерминированы и не зависят от LLM. Порт задаёт границу,
за которой в будущем появится генеративный помощник, не затрагивая ядро.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class AssistantSuggestion:
    """Подсказка AI-ассистента (будущий спринт)."""

    text: str
    confidence: float
    rationale: str


@runtime_checkable
class AIAssistantPort(Protocol):
    """Порт генеративного ассистента (реализация — спринт 7)."""

    def suggest(self, context: dict[str, Any]) -> list[AssistantSuggestion]: ...


class NullAIAssistant:
    """Заглушка: ничего не предлагает (детерминированный no-op)."""

    def suggest(self, context: dict[str, Any]) -> list[AssistantSuggestion]:
        return []
