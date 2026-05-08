from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ExpectedBehaviorPort(Protocol):
    """HITL: пары (актив, операция), помеченные оператором как ожидаемое поведение."""

    def mark_expected(self, asset_id: str, operation: str) -> None: ...

    def is_expected(self, asset_id: str, operation: str) -> bool: ...
