from __future__ import annotations

from datetime import UTC, datetime

import pytest

from takt.application.use_cases.assess_risk import AssessRiskUseCase
from takt.application.use_cases.process_event import ProcessEventUseCase
from takt.domain.entities.case import CaseStatus
from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)
from takt.infrastructure.stores.memory import InMemoryCaseStore
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore

WEIGHTS = {
    "rhythm": 0.22,
    "graph": 0.22,
    "context": 0.18,
    "user": 0.18,
    "data_quality": 0.20,
    "correlation": {
        "mode": "generalized",
        "keys": [
            {"name": "host", "fields": ["host_id"], "bucket_sec": 600, "priority": 10},
            {"name": "hash", "fields": ["artifact:hash"], "priority": 20},
        ],
    },
}


def _event(event_id: str, source: EventSource, *, host: str, hash_value: str) -> NormalizedEvent:
    # `asset_id` в payload задан намеренно: без него ключ подавления шума вырождается в
    # `_|OBSERVED|бакет`, одинаковый у всех событий набора, и проверялась бы не корреляция,
    # а слияние по общему пустому активу.
    return NormalizedEvent(
        event_id=event_id,
        observed_at=datetime(2026, 6, 1, 9, 1, tzinfo=UTC),
        source=source,
        protocol="test",
        operation="OBSERVED",
        payload_size=1,
        payload={"asset_id": host},
        entities=EventEntities(host_id=host),
        artifacts=(EventArtifact(ArtifactType.HASH, hash_value),),
    )


def _execute(process: ProcessEventUseCase, event: NormalizedEvent):
    return process.execute(
        event,
        recent_events=[],
        tickets=[],
        graph_edges=[],
        polling_intervals_us=[],
        clock=datetime(2026, 6, 1, 9, 2, tzinfo=UTC),
    )


def test_edr_and_ndr_merge_by_host_with_typed_evidence() -> None:
    repo = InMemoryCaseStore()
    process = ProcessEventUseCase(AssessRiskUseCase(WEIGHTS), repo)
    first = _execute(process, _event("edr-1", EventSource.EDR, host="ws-17", hash_value="aaa"))
    second = _execute(process, _event("ndr-1", EventSource.NDR, host="WS-17", hash_value="bbb"))

    assert second.merged_into_existing is True
    assert second.case.case_id == first.case.case_id
    assert {item.source for item in second.case.observations} == {"edr", "ndr"}
    assert second.case.correlation_evidence[-1].rule == "host"
    assert second.case.correlation_evidence[-1].event_id == "ndr-1"


def test_same_hash_merges_independently_of_host() -> None:
    repo = InMemoryCaseStore()
    process = ProcessEventUseCase(AssessRiskUseCase(WEIGHTS), repo)
    first = _execute(process, _event("edr-1", EventSource.EDR, host="ws-a", hash_value="ABC"))
    second = _execute(process, _event("siem-1", EventSource.SIEM, host="ws-b", hash_value="abc"))

    assert second.merged_into_existing is True
    assert second.case.case_id == first.case.case_id
    assert second.case.correlation_evidence[-1].rule == "hash"
    assert second.case.risk_score == pytest.approx(first.case.risk_score)


def test_sqlite_persists_candidates_and_evidence_across_restart(tmp_path) -> None:
    path = tmp_path / "cases.sqlite3"
    first_store = SqliteCaseStore(path)
    first_process = ProcessEventUseCase(AssessRiskUseCase(WEIGHTS), first_store)
    first = _execute(first_process, _event("edr-1", EventSource.EDR, host="ws-a", hash_value="abc"))
    first_store.close()

    second_store = SqliteCaseStore(path)
    try:
        second_process = ProcessEventUseCase(AssessRiskUseCase(WEIGHTS), second_store)
        second = _execute(second_process, _event("siem-1", EventSource.SIEM, host="ws-b", hash_value="ABC"))
        persisted = second_store.get(first.case.case_id)
        assert second.merged_into_existing is True
        assert persisted is not None
        assert persisted.correlation_evidence[-1].rule == "hash"
        assert persisted.normalized_event_ids == ["edr-1", "siem-1"]
    finally:
        second_store.close()


def test_priority_selects_survivor_and_absorbs_the_other_case() -> None:
    """Пересечение по нескольким ключам собирает дела в одно, а не проставляет ссылку.

    Раньше здесь проверялось обратное: событие уходило в дело правила с высшим приоритетом,
    а пересечение фиксировалось ссылкой `related_cases`. Ссылка не собирает инцидент —
    аналитик всё равно видел отдельные дела и сводил их руками. Правило старшинства при этом
    не изменилось: выживает дело правила с высшим приоритетом, ссылки в обе стороны остаются.
    """
    repo = InMemoryCaseStore()
    process = ProcessEventUseCase(AssessRiskUseCase(WEIGHTS), repo)
    host_case = _execute(process, _event("host-1", EventSource.EDR, host="ws-priority", hash_value="host-only"))
    hash_case = _execute(process, _event("hash-1", EventSource.EDR, host="other", hash_value="shared"))

    overlap = _execute(process, _event("both-1", EventSource.SIEM, host="ws-priority", hash_value="shared"))

    assert overlap.case.case_id == host_case.case.case_id
    assert overlap.case.related_cases == [hash_case.case.case_id]
    assert set(overlap.case.normalized_event_ids) == {"host-1", "hash-1", "both-1"}
    persisted_other = repo.get(hash_case.case.case_id)
    assert persisted_other is not None
    assert persisted_other.status is CaseStatus.MERGED
    assert persisted_other.related_cases == [host_case.case.case_id]
    open_cases = [case for case in repo.list_all() if case.status in (CaseStatus.NEW, CaseStatus.TRIAGE)]
    assert len(open_cases) == 1
