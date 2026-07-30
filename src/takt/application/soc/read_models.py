"""Read models (CQRS, сторона чтения).

Read-модели читают денормализованные проекции, а не доменные агрегаты. Это
отделяет тяжёлую запись/пересчёт от быстрого чтения UI (карточки, поиск, цепочки).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from takt.application.soc.ports import (
    AttackChainProjectionPort,
    CaseProjectionPort,
    EventSearchProjectionPort,
)


@dataclass(frozen=True, slots=True)
class SearchPage:
    """Страница курсорной пагинации результатов поиска событий."""

    items: list[dict[str, Any]]
    next_cursor: int | None
    total_count: int


class GetCaseCard:
    """Прочитать денормализованную карточку кейса из проекции."""

    def __init__(self, projection: CaseProjectionPort) -> None:
        self._projection = projection

    def execute(self, case_id: str) -> dict[str, Any] | None:
        return self._projection.get_case_card(case_id)


class SearchEvents:
    """Поиск событий по проекции полнотекстового индекса (курсорная пагинация)."""

    MAX_LIMIT = 200

    def __init__(self, projection: EventSearchProjectionPort) -> None:
        self._projection = projection

    def execute(
        self, *, query: str | None = None, after_seq: int | None = None, limit: int = 50
    ) -> SearchPage:
        bounded = max(1, min(int(limit), self.MAX_LIMIT))
        items, next_cursor, total = self._projection.search(
            query=query, after_seq=after_seq, limit=bounded
        )
        return SearchPage(items=items, next_cursor=next_cursor, total_count=total)


class GetAttackChain:
    """Прочитать реконструкцию цепочки атаки из проекции."""

    def __init__(self, projection: AttackChainProjectionPort) -> None:
        self._projection = projection

    def execute(self, case_id: str) -> list[dict[str, Any]]:
        return self._projection.get_chain(case_id)
