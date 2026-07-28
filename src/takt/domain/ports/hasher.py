from __future__ import annotations

from abc import abstractmethod
from typing import Protocol


class HasherPort(Protocol):
    """Порт для вычисления хешей."""

    @abstractmethod
    def hash_bytes(self, data: bytes) -> str:
        """Вычисляет хеш от массива байтов и возвращает его строковое представление."""
        raise NotImplementedError
