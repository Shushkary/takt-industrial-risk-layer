"""Единая нормализованная модель события L1 (``NormalizedEvent``).

Сущность — ``@dataclass(frozen=True)``; инварианты проверяются в ``__post_init__``
(а не в импортёрах L4), поэтому невозможно сконструировать заведомо невалидное
событие. ``content_hash`` вычисляется детерминированно в ``__post_init__``.

Важно (гард чистоты домена ``tests/test_domain_pure.py``): домен не импортирует
криптобиблиотеки (``hashlib`` и т.п.). Хеширование делегируется порту
``HasherPort`` (реализация — в инфраструктуре, ``Sha256HasherAdapter``), а домен
формирует только каноническое байтовое представление ``canonical_payload``.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from datetime import datetime
from enum import StrEnum

from takt.domain.ports.hasher import HasherPort


class SourceClass(StrEnum):
    """Допустимый перечень классов источников (см. ``docs/pt_techlab/data_contract.md``)."""

    EDR = "edr"
    SIEM = "siem"
    NDR = "ndr"
    OT = "ot"


# Публичный перечень допустимых значений (для валидации в инвариантах L1).
ALLOWED_SOURCE_CLASSES: frozenset[str] = frozenset(item.value for item in SourceClass)

# Нижняя граница «здравого» времени: защита от ``timestamp=0`` и эпохи Unix.
_MIN_SANE_TS_ISO = "2000-01-01T00:00:00+00:00"


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """Нормализованное событие второго аналитического эшелона.

    Поля:
        source_class: класс источника из допустимого перечня (``SourceClass``).
        host_id: узел (nullable).
        user_id: учётная запись (nullable).
        process: процесс/технологическая точка (nullable).
        address: сетевой адрес (nullable).
        artifact: артефакт — хеш/файл/домен (nullable).
        ts: время наблюдения, обязательно в UTC.
        raw_ref: ссылка на исходную (сырую) запись, не пустая.
        content_hash: sha256 основных полей, вычисляется в ``__post_init__``.
    """

    source_class: str
    host_id: str | None
    user_id: str | None
    process: str | None
    address: str | None
    artifact: str | None
    ts: datetime
    raw_ref: str
    content_hash: str = field(default="", compare=False)
    # Порт хеширования инъектируется только на время конструирования (InitVar):
    # в объекте не хранится, чтобы домен оставался свободным от инфраструктуры.
    hasher: InitVar[HasherPort | None] = None

    def __post_init__(self, hasher: HasherPort | None) -> None:
        # --- Инварианты конструктора (детерминированные, без обращения к времени) ---
        if self.ts.tzinfo is None or self.ts.utcoffset() is None:
            raise ValueError("NormalizedEvent.ts должен быть timezone-aware (UTC)")
        if self.ts.utcoffset().total_seconds() != 0:  # type: ignore[union-attr]
            raise ValueError("NormalizedEvent.ts должен быть в UTC (utcoffset == 0)")
        if not self.raw_ref or not self.raw_ref.strip():
            raise ValueError("NormalizedEvent.raw_ref не может быть пустым")
        if self.source_class not in ALLOWED_SOURCE_CLASSES:
            raise ValueError(
                f"NormalizedEvent.source_class {self.source_class!r} вне допустимого перечня "
                f"{sorted(ALLOWED_SOURCE_CLASSES)}"
            )
        # content_hash: либо вычисляется инъектированным hasher, либо принимается
        # уже посчитанным (например, при восстановлении из хранилища).
        if hasher is not None:
            computed = hasher.hash_bytes(self.canonical_payload())
            object.__setattr__(self, "content_hash", computed)
        elif not self.content_hash:
            raise ValueError(
                "NormalizedEvent требует hasher (HasherPort) для вычисления content_hash "
                "либо уже вычисленный content_hash"
            )

    def canonical_payload(self) -> bytes:
        """Каноническое байтовое представление основных полей (без ``raw_ref``).

        ``raw_ref`` не участвует в содержимом: два события с одинаковым составом,
        но разными ссылками на сырые данные считаются дублями (идемпотентный ingest).
        Функция чистая (без криптографии) — из неё инфраструктура получает sha256.
        """
        parts = [
            self.source_class,
            self.host_id or "",
            self.user_id or "",
            self.process or "",
            self.address or "",
            self.artifact or "",
            self.ts.astimezone(self.ts.tzinfo).isoformat(),
        ]
        return "\x1f".join(parts).encode("utf-8")

    def shared_entities(self) -> dict[str, str]:
        """Непустые общие сущности события для корреляции (ключ → значение)."""
        candidates = {
            "host_id": self.host_id,
            "user_id": self.user_id,
            "process": self.process,
            "address": self.address,
            "artifact": self.artifact,
        }
        return {key: value for key, value in candidates.items() if value}
