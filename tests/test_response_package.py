"""Состав пакета реагирования: что попадает в рекомендации и с каким происхождением.

Замечание, с которого начата работа (аудит «След смены», разрыв D03): у дела `f4f5a0ac` в
составе были seed-хеш и домен, а таблица реагирования предлагала только три учётные записи,
адрес и заморозку конвейера. Пакет собирался в браузере из артефактов с `source=pivot-seed` и
знал ровно три типа — узел, учётную запись и адрес. Дело, собранное не пивотом, оставляло
панель пустой; у учётной записи и адреса поле узла было пустым молча.

Последствие: пункт ТЗ о пакете с типами и привязкой к узлам выполнялся для части объектов, а
остальное аналитик дополнял вручную — то есть за пределами доказательного контура.

Контракт: состав кандидатов считает продукт, а не браузер. Каждый кандидат несёт тип,
значение, узел (и признак того, что узел неизвестен), происхождение, события-основания,
класс источника и статус проверки. Узел не подставляется догадкой: неизвестный узел
показывается как неизвестный и по умолчанию не отмечается — решение остаётся за аналитиком.

ТАКТ этих действий не выполняет: пакет — перечень рекомендаций, исполняет их внешняя система
после подтверждения аналитика (`docs/product_boundary.md`).
"""

from __future__ import annotations

from datetime import UTC, datetime

from takt.application.use_cases.response_package import build_response_package
from takt.domain.entities.case import Case, CaseArtifact, CaseStatus, Finding
from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)

NOW = datetime(2026, 9, 8, 10, 0, tzinfo=UTC)


def _event(event_id: str, *, host: str | None = None, user: str | None = None,
           artifacts: tuple[EventArtifact, ...] = (), source: EventSource = EventSource.EDR) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=NOW,
        source=source,
        protocol="test",
        operation="OBSERVED",
        payload_size=1,
        payload={},
        entities=EventEntities(host_id=host, user_id=user),
        artifacts=artifacts,
        ingest_trust=1.0,
    )


def _case(*, artifacts: tuple[CaseArtifact, ...] = (), findings: tuple[Finding, ...] = ()) -> Case:
    return Case(
        case_id="c-1",
        status=CaseStatus.TRIAGE,
        title="дело",
        risk_class="HIGH",
        risk_score=0.8,
        created_at=NOW,
        artifacts=list(artifacts),
        findings=list(findings),
    )


def _by_value(package) -> dict[str, object]:
    return {item.value: item for item in package.candidates}


def test_hash_and_file_reach_the_package(tmp_path=None) -> None:
    """То самое воспроизведение: хеш и домен были в составе, а в таблице их не было."""
    events = [
        _event(
            "e-1",
            host="eng-ws-04",
            artifacts=(
                EventArtifact(ArtifactType.HASH, "abc123"),
                EventArtifact(ArtifactType.DOMAIN, "cdn-updates.example.net"),
                EventArtifact(ArtifactType.FILE, "C:/ProgramData/upd_agent.exe"),
            ),
        )
    ]

    package = build_response_package(_case(), events)
    found = _by_value(package)

    assert {"abc123", "cdn-updates.example.net", "C:/ProgramData/upd_agent.exe"} <= set(found)
    assert found["abc123"].type == "hash"
    assert found["abc123"].host_id == "eng-ws-04"
    assert found["abc123"].event_ids == ("e-1",)
    assert found["abc123"].action, "рекомендация обязана быть названа"


def test_a_case_without_a_pivot_still_forms_a_package() -> None:
    """Без артефактов пивота панель реагирования была пустой."""
    events = [_event("e-1", host="ws-1", user="ivanov")]

    package = build_response_package(_case(), events)

    assert {item.type for item in package.candidates} >= {"host", "account"}


def test_the_same_object_on_two_hosts_stays_two_rows() -> None:
    """Хеш на двух узлах — два решения: изолировать надо оба, и это видно построчно."""
    events = [
        _event("e-1", host="host-a", artifacts=(EventArtifact(ArtifactType.HASH, "abc123"),)),
        _event("e-2", host="host-b", artifacts=(EventArtifact(ArtifactType.HASH, "abc123"),)),
    ]

    package = build_response_package(_case(), events)
    hashes = [item for item in package.candidates if item.type == "hash"]

    assert sorted(item.host_id for item in hashes) == ["host-a", "host-b"]


def test_an_unknown_host_is_named_and_not_selected_by_default() -> None:
    """Пустое поле узла молчало; теперь неизвестный узел требует решения аналитика."""
    events = [_event("e-1", artifacts=(EventArtifact(ArtifactType.HASH, "abc123"),))]

    package = build_response_package(_case(), events)
    candidate = _by_value(package)["abc123"]

    assert candidate.host_id == ""
    assert candidate.host_known is False
    assert candidate.selected_by_default is False


def test_manual_artifacts_join_the_package_with_their_provenance() -> None:
    """Ручной артефакт — такое же основание, как событийный, и он тоже уходит в пакет."""
    case = _case(
        artifacts=(
            CaseArtifact(type="hash", value="manual-hash", host_id="ws-9", verification_status="confirmed", source="manual"),
        )
    )

    package = build_response_package(case, [])
    candidate = _by_value(package)["manual-hash"]

    assert candidate.origin == "manual"
    assert candidate.verification_status == "confirmed"
    assert candidate.host_id == "ws-9"


def test_pivot_seed_stays_the_core_and_expansion_stays_apart() -> None:
    """Узел, добранный расширением, — не отличительная сущность: он в другой группе."""
    case = _case(
        artifacts=(CaseArtifact(type="host", value="eng-ws-04", host_id="eng-ws-04", source="pivot-seed"),)
    )
    events = [_event("e-1", host="eng-ws-04")]

    package = build_response_package(case, events, expanded_hosts=("ws-neighbour",))
    rows = {item.value: item for item in package.candidates}

    assert rows["eng-ws-04"].group == "core"
    assert rows["eng-ws-04"].selected_by_default is True
    assert rows["ws-neighbour"].group == "expanded"
    assert rows["ws-neighbour"].selected_by_default is False


def test_the_package_is_versioned_by_confirmations_already_recorded() -> None:
    """Отбор сохраняется как версия пакета: подтверждений может быть несколько."""
    confirmed = Finding(
        finding_id="f-1", text="Пакет реагирования (версия 1): ...", author="alice", created_at=NOW
    )

    first = build_response_package(_case(), [])
    second = build_response_package(_case(findings=(confirmed,)), [])

    assert first.version == 1
    assert second.version == 2


def test_candidates_are_deterministic() -> None:
    """Повторный расчёт на тех же данных обязан дать тот же порядок и состав."""
    events = [
        _event("e-2", host="host-b", artifacts=(EventArtifact(ArtifactType.HASH, "b"),)),
        _event("e-1", host="host-a", artifacts=(EventArtifact(ArtifactType.HASH, "a"),)),
    ]

    first = build_response_package(_case(), events)
    second = build_response_package(_case(), events)

    assert [(item.type, item.value, item.host_id) for item in first.candidates] == [
        (item.type, item.value, item.host_id) for item in second.candidates
    ]


def test_the_package_states_that_takt_does_not_execute_it() -> None:
    """Граница продукта не выводится из интерфейса: она приходит вместе с пакетом."""
    package = build_response_package(_case(), [])

    assert "не выполняет" in package.boundary_note
