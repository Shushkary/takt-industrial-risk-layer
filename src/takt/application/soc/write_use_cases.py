"""Write use cases (CQRS, командная сторона).

Каждый сценарий — отдельный класс с методом ``execute()``. Изменения состояния,
меняющие вердикт/состав кейса, фиксируются в append-only hash-chain журнале.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from takt.application.soc.ports import AuditJournalPort, JournalEntry
from takt.domain.soc.normalized_event import NormalizedEvent
from takt.domain.soc.ports import Clock, EventRepository, IdGenerator


@dataclass(frozen=True, slots=True)
class ProcessEventResult:
    """Результат идемпотентного ingest."""

    case_id: str
    created: bool
    content_hash: str


class ProcessEvent:
    """Идемпотентный ingest события.

    Проверяет ``content_hash`` через ``EventRepository.exists_by_hash``: если событие
    уже обрабатывалось — возвращает существующий ``case_id`` без создания дубля.
    """

    def __init__(
        self,
        repo: EventRepository,
        id_generator: IdGenerator,
    ) -> None:
        self._repo = repo
        self._ids = id_generator

    def execute(self, event: NormalizedEvent) -> ProcessEventResult:
        content_hash = event.content_hash
        if self._repo.exists_by_hash(content_hash):
            existing = self._repo.case_id_for_hash(content_hash)
            return ProcessEventResult(case_id=existing or "", created=False, content_hash=content_hash)
        case_id = self._ids.generate()
        self._repo.save(event, case_id=case_id)
        return ProcessEventResult(case_id=case_id, created=True, content_hash=content_hash)


class RecordCaseDecision:
    """Зафиксировать решение аналитика по кейсу (пишет в hash-chain журнал)."""

    def __init__(self, journal: AuditJournalPort, clock: Clock) -> None:
        self._journal = journal
        self._clock = clock

    def execute(self, *, case_id: str, decision: str, actor: str, note: str = "") -> JournalEntry:
        payload: dict[str, Any] = {
            "case_id": case_id,
            "decision": decision,
            "actor": actor,
            "note": note,
            "ts": self._clock.now().isoformat(),
        }
        return self._journal.append(action="case_decision", payload=payload)


class AddFinding:
    """Добавить находку в кейс (пишет в hash-chain журнал)."""

    def __init__(self, journal: AuditJournalPort, clock: Clock, id_generator: IdGenerator) -> None:
        self._journal = journal
        self._clock = clock
        self._ids = id_generator

    def execute(self, *, case_id: str, artifact: str, actor: str) -> JournalEntry:
        payload: dict[str, Any] = {
            "finding_id": self._ids.generate(),
            "case_id": case_id,
            "artifact": artifact,
            "actor": actor,
            "ts": self._clock.now().isoformat(),
        }
        return self._journal.append(action="add_finding", payload=payload)


class ManualGroupOverride:
    """Ручное переопределение группировки (attach/detach/merge/split).

    Все ручные вмешательства в корреляцию фиксируются в hash-chain журнале —
    это критично для аудита (human-in-the-loop) и последующей верификации.
    """

    _ACTIONS = frozenset({"attach", "detach", "merge", "split"})

    def __init__(self, journal: AuditJournalPort, clock: Clock) -> None:
        self._journal = journal
        self._clock = clock

    def execute(
        self, *, case_id: str, action: str, event_refs: list[str], actor: str
    ) -> JournalEntry:
        if action not in self._ACTIONS:
            raise ValueError(f"недопустимое действие группировки: {action!r}")
        payload: dict[str, Any] = {
            "case_id": case_id,
            "action": action,
            "event_refs": list(event_refs),
            "actor": actor,
            "ts": self._clock.now().isoformat(),
        }
        return self._journal.append(action="manual_group_override", payload=payload)
