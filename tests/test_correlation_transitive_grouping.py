"""Группировка после приёма: транзитивность и сложение двух ключей.

Два дефекта, найденные по замечанию «27 связанных событий дали 21 отдельное дело»:

1. Событие, совпавшее сразу с несколькими открытыми делами, попадало только в первое из них,
   а остальные получали ссылку `related_cases`. Ссылка не собирает инцидент: аналитик всё
   равно видел отдельные дела.
2. Первый ключ корреляции затирал `burst_fingerprint`, поэтому включение SOC-корреляции
   выключало подавление шума — два механизма группировки исключали друг друга.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

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

T0 = datetime(2026, 8, 17, 6, 0, tzinfo=UTC)

WEIGHTS = {
    "rhythm": 0.22, "graph": 0.22, "context": 0.18, "user": 0.18, "data_quality": 0.20,
    "alert_fatigue": {"mode": "bucketed", "bucket_sec": 300},
    "correlation": {
        "mode": "generalized",
        "keys": [
            {"name": "host", "fields": ["host_id"], "bucket_sec": 600, "priority": 10},
            {"name": "hash", "fields": ["artifact:hash"], "priority": 20},
        ],
    },
}


def _event(event_id: str, *, host: str, hash_value: str | None = None,
           minute: int = 0, operation: str = "OBSERVED",
           source: EventSource = EventSource.EDR) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=T0 + timedelta(minutes=minute),
        source=source,
        protocol="test",
        operation=operation,
        payload_size=1,
        payload={"asset_id": host},
        entities=EventEntities(host_id=host),
        artifacts=(EventArtifact(ArtifactType.HASH, hash_value),) if hash_value else (),
    )


def _process(repo, weights=None) -> ProcessEventUseCase:
    return ProcessEventUseCase(AssessRiskUseCase(weights or WEIGHTS), repo)


def _run(process: ProcessEventUseCase, event: NormalizedEvent):
    return process.execute(
        event, recent_events=[], tickets=[], graph_edges=[],
        polling_intervals_us=[], clock=event.observed_at,
    )


def _open(repo):
    return [case for case in repo.list_all() if case.status in (CaseStatus.NEW, CaseStatus.TRIAGE)]


def test_event_matching_two_open_cases_merges_them_into_one() -> None:
    """Связывающее событие уже принято — значит, дела описывают одну цепочку."""
    repo = InMemoryCaseStore()
    process = _process(repo)
    by_host = _run(process, _event("a-1", host="ws-17", hash_value="aaa"))
    by_hash = _run(process, _event("b-1", host="srv-42", hash_value="shared"))

    bridge = _run(process, _event("c-1", host="ws-17", hash_value="shared", minute=1))

    assert bridge.case.case_id == by_host.case.case_id
    assert set(bridge.case.normalized_event_ids) == {"a-1", "b-1", "c-1"}
    absorbed = repo.get(by_hash.case.case_id)
    assert absorbed is not None
    assert absorbed.status is CaseStatus.MERGED
    assert absorbed.related_cases == [by_host.case.case_id]
    assert len(_open(repo)) == 1


def test_absorbed_case_keeps_a_trail_in_both_directions() -> None:
    """Состав дела прослеживается: у обеих карточек в журнале названо, что с чем слито."""
    repo = InMemoryCaseStore()
    process = _process(repo)
    survivor = _run(process, _event("a-1", host="ws-17", hash_value="aaa"))
    other = _run(process, _event("b-1", host="srv-42", hash_value="shared"))
    _run(process, _event("c-1", host="ws-17", hash_value="shared", minute=1))

    merged = repo.get(survivor.case.case_id)
    absorbed = repo.get(other.case.case_id)
    assert any("absorbed correlated case" in line for line in merged.audit_log)
    assert any("merged into correlated case" in line for line in absorbed.audit_log)
    assert absorbed.case_id in merged.related_cases


def test_absorbed_case_no_longer_catches_new_events() -> None:
    """Поглощённое дело выходит из поиска по ключам, иначе события ушли бы в тупик."""
    repo = InMemoryCaseStore()
    process = _process(repo)
    survivor = _run(process, _event("a-1", host="ws-17", hash_value="aaa"))
    _run(process, _event("b-1", host="srv-42", hash_value="shared"))
    _run(process, _event("c-1", host="ws-17", hash_value="shared", minute=1))

    later = _run(process, _event("d-1", host="srv-42", hash_value="shared", minute=2))
    assert later.case.case_id == survivor.case.case_id
    assert len(_open(repo)) == 1


def test_absorption_survives_a_restart_on_sqlite(tmp_path) -> None:
    repo = SqliteCaseStore(tmp_path / "cases.sqlite3")
    try:
        process = _process(repo)
        survivor = _run(process, _event("a-1", host="ws-17", hash_value="aaa"))
        other = _run(process, _event("b-1", host="srv-42", hash_value="shared"))
        _run(process, _event("c-1", host="ws-17", hash_value="shared", minute=1))
    finally:
        repo.close()

    reopened = SqliteCaseStore(tmp_path / "cases.sqlite3")
    try:
        assert reopened.get(other.case.case_id).status is CaseStatus.MERGED
        assert set(reopened.get(survivor.case.case_id).normalized_event_ids) == {"a-1", "b-1", "c-1"}
        assert len(_open(reopened)) == 1
    finally:
        reopened.close()


def test_correlation_does_not_switch_off_noise_suppression() -> None:
    """Повтор одной операции на одном активе сливается и при включённой корреляции.

    Раньше первый ключ корреляции затирал `burst_fingerprint`: на корпусе INC-002 включение
    корреляции давало 223 дела вместо 121.
    """
    repo = InMemoryCaseStore()
    process = _process(repo)
    first = _run(process, _event("p-1", host="plc-01", operation="WRITE", source=EventSource.OT))
    # Второе событие того же актива и операции, но за границей окна правила `host`
    # (600 с) — совпадает только по ключу подавления шума.
    second = _run(
        process,
        _event("p-2", host="plc-01", operation="WRITE", minute=0, source=EventSource.OT),
    )
    assert second.case.case_id == first.case.case_id
    assert len(_open(repo)) == 1


def test_burst_fingerprint_is_not_a_correlation_key() -> None:
    """Ключ подавления шума остаётся ключом подавления шума, а не первым ключом корреляции."""
    repo = InMemoryCaseStore()
    outcome = _run(_process(repo), _event("a-1", host="ws-17", hash_value="aaa"))
    assert not outcome.case.burst_fingerprint.startswith("corr:")
    assert outcome.case.correlation_fingerprints
