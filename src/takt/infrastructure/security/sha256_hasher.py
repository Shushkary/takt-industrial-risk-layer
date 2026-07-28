from __future__ import annotations

import hashlib

from takt.domain.ports.hasher import HasherPort


class Sha256HasherAdapter(HasherPort):
    """Реализация порта HasherPort, использующая SHA256 из hashlib."""

    def hash_bytes(self, data: bytes) -> str:
        """Вычисляет SHA256 хеш от массива байтов и возвращает его строковое представление."""
        return hashlib.sha256(data).hexdigest()
