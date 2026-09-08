"""Идентичность процесса: чем один процесс отличается от другого.

Источники называют процесс по-разному. EDR и SIEM отдают GUID запуска, когда он есть в
событии; при его отсутствии SIEM-адаптер откатывается на ``subject.process.id`` — на PID.
PID уникален в пределах узла и переиспользуется операционной системой после завершения
процесса, поэтому сам по себе ключом не является: один и тот же PID на двух узлах — это два
разных процесса, и сведение их в одну карточку даёт ложные связи (аудит «След смены», D04:
52 события с ``host-a`` и ``host-b`` в одной истории).

Здесь задаётся ключ сущности — то, по чему процесс собирается в реестре и в карточке. Ключ
отделён от того, что показывается аналитику: показывается значение из данных источника
(``process_id``), ключ остаётся внутренним.

Чего этот контракт не умеет: различить **повторные запуски** с одним PID на одном узле. Для
этого нужен идентификатор или время запуска процесса в схеме источника; поле согласуется с
заказчиком, и до согласования такая идентичность помечается как «в пределах узла», а не
выдаётся за точную. Придумать признак запуска здесь нельзя — он был бы догадкой в
доказательном материале.
"""

from __future__ import annotations

import re

_GUID = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)

GUID_IDENTITY = "guid"
"""Глобально уникальный идентификатор запуска: сходится из разных источников."""

HOST_PID_IDENTITY = "host_pid"
"""Узел и PID: разводит узлы, но не различает повторные запуски на одном узле."""

UNDETERMINED_IDENTITY = "undetermined"
"""Узел неизвестен: процесс не сливается ни с одним другим."""

_HOST_PID_PREFIX = "pid"
_UNKNOWN_HOST = "?"


def is_process_guid(process_id: str | None) -> bool:
    value = (process_id or "").strip()
    return bool(value) and _GUID.match(value) is not None


def process_identity_kind(process_id: str | None, host_id: str | None) -> str:
    """Чем опознан процесс. Показывается в карточке: «в пределах узла» — не факт, а граница."""
    value = (process_id or "").strip()
    if not value:
        return UNDETERMINED_IDENTITY
    if is_process_guid(value):
        return GUID_IDENTITY
    return HOST_PID_IDENTITY if (host_id or "").strip() else UNDETERMINED_IDENTITY


def process_entity_key(process_id: str | None, host_id: str | None) -> str:
    """Ключ процесса как сущности реестра.

    GUID уникален сам по себе и остаётся ключом без изменений — так один процесс, увиденный
    EDR и SIEM, остаётся одним. PID получает область действия узла. Без узла ключ помечается
    неизвестным узлом: он не совпадёт ни с ключом того же PID на конкретном узле, ни с чужим
    PID, — то есть неопределённость не превращается в слияние.
    """
    value = (process_id or "").strip()
    if not value:
        return ""
    if is_process_guid(value):
        return value
    host = (host_id or "").strip() or _UNKNOWN_HOST
    return f"{_HOST_PID_PREFIX}:{host}|{value}"
