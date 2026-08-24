"""Сборка инцидента пивотом: прикладной слой и HTTP-контур.

Проверяется то, ради чего use case появился: штатный конвейер приёма дробит цепочку атаки
по burst-фингерпринтам, а сборка по отличительным сущностям возвращает её одним кейсом.
Отдельно проверяется, что расширение до уровня узла — осознанный шаг, а не поведение
по умолчанию, и что риск не выдумывается, а берётся из уже оценённых кейсов.

Смежное: `tests/test_pt_techlab_inc_002.py` (сам движок на полной фикстуре).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from takt.application.use_cases.assemble_incident import (
    AssembleIncidentUseCase,
    IncidentSeed,
)
from takt.domain.entities.case import Case, CaseStatus
from takt.domain.entities.event import (
    ArtifactType,
    EventArtifact,
    EventEntities,
    EventSource,
    NormalizedEvent,
)
from takt.infrastructure.stores.memory import InMemoryCaseStore

_START = datetime(2026, 8, 17, 6, 0, tzinfo=UTC)


def _event(
    event_id: str,
    *,
    minutes: int,
    host: str = "",
    user: str = "",
    dst: str = "",
    domain: str = "",
    source: EventSource = EventSource.EDR,
    operation: str = "PROCESS_START",
) -> NormalizedEvent:
    artifacts = (EventArtifact(type=ArtifactType.DOMAIN, value=domain),) if domain else ()
    return NormalizedEvent(
        event_id=event_id,
        observed_at=_START + timedelta(minutes=minutes),
        source=source,
        protocol="endpoint",
        operation=operation,
        payload_size=100,
        payload={},
        entities=EventEntities(host_id=host, user_id=user, dst_address=dst),
        artifacts=artifacts,
    )


class _FakeEventStore:
    """Хранилище событий с поиском по тем же критериям, что и SQLite-реализация."""

    def __init__(self, events: list[NormalizedEvent]) -> None:
        self.events = events
        self.calls = 0

    def search_events(self, **criteria):
        self.calls += 1
        offset = int(criteria.pop("offset", 0))
        limit = int(criteria.pop("limit", 100))
        selected = [event for event in self.events if self._matches(event, criteria)]
        selected.sort(key=lambda event: (event.observed_at, event.event_id))
        return selected[offset : offset + limit], len(selected)

    @staticmethod
    def _matches(event: NormalizedEvent, criteria: dict) -> bool:
        entities = event.entities
        if (host := criteria.get("host_id")) and (entities is None or entities.host_id != host):
            return False
        if (user := criteria.get("user_id")) and (entities is None or entities.user_id != user):
            return False
        if address := criteria.get("address"):
            addresses = {entities.src_address, entities.dst_address} if entities else set()
            if address not in addresses:
                return False
        if artifact_type := criteria.get("artifact_type"):
            value = criteria.get("artifact_value", "")
            if not any(item.type.value == artifact_type and item.value == value for item in event.artifacts):
                return False
        if (start := criteria.get("observed_from")) and event.observed_at < start:
            return False
        if (end := criteria.get("observed_to")) and event.observed_at > end:
            return False
        return True


def _chain_and_background() -> list[NormalizedEvent]:
    """Три события цепочки с отличительными сущностями и фон тех же узлов."""
    return [
        _event("chain-1", minutes=0, host="ws-17", user="smirnov"),
        _event("chain-2", minutes=1, host="ws-17", user="smirnov", dst="185.220.101.34"),
        _event("chain-3", minutes=2, host="build-srv-01", user="svc_build", domain="c2.example"),
        # Фон: те же узлы, но без отличительных сущностей.
        _event("bg-1", minutes=1, host="ws-17", user="orlova"),
        _event("bg-2", minutes=2, host="build-srv-01", user="backup"),
        # Фон вне окна инцидента.
        _event("bg-3", minutes=90, host="ws-17", user="orlova"),
        # Посторонний узел.
        _event("bg-4", minutes=1, host="ws-99", user="ivanov"),
    ]


def _use_case(events: list[NormalizedEvent], repo: InMemoryCaseStore | None = None) -> AssembleIncidentUseCase:
    return AssembleIncidentUseCase(events=_FakeEventStore(events), repo=repo or InMemoryCaseStore())


def test_core_takes_only_distinctive_entities() -> None:
    """Ядро собирается по отличительным сущностям и не тянет фон тех же узлов."""
    use_case = _use_case(_chain_and_background())
    result = use_case.execute(
        case_id="INC-TEST",
        seeds=[IncidentSeed.parse("user:smirnov"), IncidentSeed.parse("user:svc_build")],
    )
    assert set(result.core_event_ids) == {"chain-1", "chain-2", "chain-3"}
    assert result.expanded_event_ids == ()


def test_expansion_to_hosts_is_explicit_and_window_bound() -> None:
    """Расширение добирает фон тех же узлов только в окне ядра и только по запросу."""
    use_case = _use_case(_chain_and_background())
    result = use_case.execute(
        case_id="INC-TEST",
        seeds=[IncidentSeed.parse("user:smirnov"), IncidentSeed.parse("user:svc_build")],
        expand_hosts=("ws-17", "build-srv-01"),
    )
    assert set(result.expanded_event_ids) == {"bg-1", "bg-2"}
    assert "bg-3" not in result.case.normalized_event_ids, "событие вне окна инцидента не добирается"
    assert "bg-4" not in result.case.normalized_event_ids, "посторонний узел не добирается"


def test_address_seed_matches_both_directions() -> None:
    """Адрес ищется и как источник, и как назначение."""
    use_case = _use_case(_chain_and_background())
    result = use_case.execute(case_id="INC-TEST", seeds=[IncidentSeed.parse("address:185.220.101.34")])
    assert set(result.core_event_ids) == {"chain-2"}


def test_artifact_seed_matches_by_type_and_value() -> None:
    use_case = _use_case(_chain_and_background())
    result = use_case.execute(
        case_id="INC-TEST",
        seeds=[IncidentSeed.parse("artifact:domain:c2.example")],
    )
    assert set(result.core_event_ids) == {"chain-3"}


def test_risk_is_aggregated_from_assessed_cases_not_invented() -> None:
    """Риск собранного инцидента берётся из кейсов конвейера, а не вычисляется заново."""
    repo = InMemoryCaseStore()
    repo.save(
        Case(
            case_id="pipeline-1",
            status=CaseStatus.NEW,
            title="Risk HIGH",
            risk_class="HIGH",
            risk_score=0.81,
            created_at=_START,
            normalized_event_ids=["chain-2"],
            invariant_hits=["c2_beacon"],
        )
    )
    repo.save(
        Case(
            case_id="pipeline-2",
            status=CaseStatus.NEW,
            title="Risk LOW",
            risk_class="LOW",
            risk_score=0.21,
            created_at=_START,
            normalized_event_ids=["chain-1"],
            invariant_hits=["new_node_airgap"],
        )
    )
    result = _use_case(_chain_and_background(), repo).execute(
        case_id="INC-TEST",
        seeds=[IncidentSeed.parse("user:smirnov")],
    )
    assert result.case.risk_score == pytest.approx(0.81)
    assert result.case.risk_class == "HIGH"
    assert result.case.invariant_hits == ["c2_beacon", "new_node_airgap"]
    assert set(result.source_case_ids) == {"pipeline-1", "pipeline-2"}


def test_assembled_case_is_persisted_with_audit_trail() -> None:
    """Кейс сохраняется, а в журнале остаётся, чем именно он собран."""
    repo = InMemoryCaseStore()
    result = _use_case(_chain_and_background(), repo).execute(
        case_id="INC-TEST",
        seeds=[IncidentSeed.parse("user:smirnov")],
        actor="demo.loader",
    )
    stored = repo.get("INC-TEST")
    assert stored is not None
    assert stored.status is CaseStatus.TRIAGE, "сборка не выносит вердикт"
    assert any("incident assembled by pivot" in line for line in stored.audit_log)
    assert any("actor=demo.loader" in line for line in stored.audit_log)
    assert result.case.observations, "состав по источникам заполнен"


def test_unknown_entities_are_reported_as_lookup_error() -> None:
    use_case = _use_case(_chain_and_background())
    with pytest.raises(LookupError):
        use_case.execute(case_id="INC-TEST", seeds=[IncidentSeed.parse("user:никого-нет")])


@pytest.mark.parametrize(
    "raw",
    ["", "ws-17", "host:", "artifact:domain", "unknown:value"],
)
def test_seed_parsing_rejects_malformed_input(raw: str) -> None:
    with pytest.raises(ValueError):
        IncidentSeed.parse(raw)


def test_seed_parsing_accepts_documented_forms() -> None:
    assert IncidentSeed.parse("host:ws-17").search_criteria() == {"host_id": "ws-17"}
    assert IncidentSeed.parse("user:smirnov").search_criteria() == {"user_id": "smirnov"}
    assert IncidentSeed.parse("address:10.0.0.1").search_criteria() == {"address": "10.0.0.1"}
    assert IncidentSeed.parse("artifact:domain:c2.example").search_criteria() == {
        "artifact_type": "domain",
        "artifact_value": "c2.example",
    }
    # Значение узла само содержит двоеточие — разбирается как единое значение.
    assert IncidentSeed.parse("host:pipeline:release-prod").search_criteria() == {
        "host_id": "pipeline:release-prod"
    }


def test_paging_reads_every_matching_event() -> None:
    """Выдача больше страницы читается целиком, а не первой страницей."""
    events = [_event(f"chain-{index}", minutes=index, host="ws-17", user="smirnov") for index in range(25)]
    use_case = AssembleIncidentUseCase(events=_FakeEventStore(events), repo=InMemoryCaseStore(), page_size=10)
    result = use_case.execute(case_id="INC-TEST", seeds=[IncidentSeed.parse("user:smirnov")])
    assert len(result.core_event_ids) == 25


def test_previously_assembled_case_is_not_a_risk_source() -> None:
    """Повторная сборка не агрегирует риск с кейса, собранного этим же use case."""
    repo = InMemoryCaseStore()
    events = _chain_and_background()
    first = _use_case(events, repo).execute(
        case_id="INC-FIRST",
        seeds=[IncidentSeed.parse("user:smirnov")],
    )
    assert repo.get("INC-FIRST") is not None

    second = _use_case(events, repo).execute(
        case_id="INC-SECOND",
        seeds=[IncidentSeed.parse("user:smirnov")],
    )
    assert "INC-FIRST" not in second.source_case_ids
    assert "INC-SECOND" not in second.source_case_ids
    assert first.case.case_id not in second.case.related_cases


_WEIGHTS = {
    "rhythm": 0.22,
    "graph": 0.22,
    "context": 0.18,
    "user": 0.18,
    "data_quality": 0.20,
    "risk_class_thresholds": {"critical": 0.85, "high": 0.65, "medium": 0.4},
    "eps_soft_cap": 100_000,
    "mandelbrot_entropy_cap": 2.5,
}


def _pipeline_case(case_id: str, hits: list[str], score: float, risk_class: str) -> Case:
    return Case(
        case_id=case_id,
        status=CaseStatus.NEW,
        title=f"Risk {risk_class}",
        risk_class=risk_class,
        risk_score=score,
        created_at=_START,
        normalized_event_ids=["chain-1"],
        invariant_hits=hits,
    )


def test_incident_risk_uses_union_of_invariants_when_weights_available() -> None:
    """С весами инцидент оценивается по объединению срабатываний, а не по одному событию.

    Оба вошедших кейса по отдельности слабые; вместе они дают и внешний управляющий канал
    (`c2_external_dns` -> вектор графа 0.9), и работу вне окна (`out_of_shift_access` ->
    пользовательский вектор 0.7). Взвешенная сумма 0.324 — заметно больше, чем даёт любое
    из событий по отдельности.
    """
    repo = InMemoryCaseStore()
    repo.save(_pipeline_case("pipeline-1", ["c2_external_dns"], 0.05, "LOW"))
    repo.save(_pipeline_case("pipeline-2", ["out_of_shift_access"], 0.04, "LOW"))
    use_case = AssembleIncidentUseCase(
        events=_FakeEventStore(_chain_and_background()),
        repo=repo,
        weights=_WEIGHTS,
    )
    result = use_case.execute(case_id="INC-TEST", seeds=[IncidentSeed.parse("user:smirnov")])
    assert set(result.case.invariant_hits) == {"c2_external_dns", "out_of_shift_access"}
    assert result.case.risk_score > 0.05, "объединение срабатываний весомее любого отдельного кейса"


def test_incident_score_is_not_capped_by_eps_calibration() -> None:
    """Полнота признаков доходит до балла: прежний потолок 0.5 снят.

    До правки множитель `(0.5 + 0.5 * burst)` в `combine_risk` резал балл вдвое на любой
    реальной частоте потока, и инцидент с полным набором признаков не мог выйти даже за
    0.5. Теперь набор ниже даёт векторы 0.65 / 0.9 / 0.6 / 0.7 и балл около 0.575.
    Решение и разбор — `docs/risk_scale_calibration.md`.
    """
    repo = InMemoryCaseStore()
    every_marker = [
        "c2_external_dns",
        "out_of_shift_access",
        "lateral_movement",
        "expert_dissonance",
        "trust_index_drop",
        "request_reply_dissonance",
        "physical_invariant_breach",
    ]
    repo.save(_pipeline_case("pipeline-1", every_marker, 0.0, "LOW"))
    use_case = AssembleIncidentUseCase(
        events=_FakeEventStore(_chain_and_background()),
        repo=repo,
        weights=_WEIGHTS,
    )
    result = use_case.execute(case_id="INC-TEST", seeds=[IncidentSeed.parse("user:smirnov")])
    assert result.case.risk_score > 0.5, "прежний потолок шкалы снят"
    assert result.case.risk_score == pytest.approx(0.575, abs=0.01)
    assert result.case.risk_class == "MEDIUM"


def test_incident_risk_never_below_worst_contributing_case() -> None:
    """Инцидент не бывает безопаснее худшей своей части."""
    repo = InMemoryCaseStore()
    repo.save(_pipeline_case("pipeline-1", ["new_node_airgap"], 0.94, "CRITICAL"))
    use_case = AssembleIncidentUseCase(
        events=_FakeEventStore(_chain_and_background()),
        repo=repo,
        weights=_WEIGHTS,
    )
    result = use_case.execute(case_id="INC-TEST", seeds=[IncidentSeed.parse("user:smirnov")])
    assert result.case.risk_score == pytest.approx(0.94)
    assert result.case.risk_class == "CRITICAL"


def test_incident_risk_without_weights_falls_back_to_worst_case() -> None:
    """Без весов веса не выдумываются — берётся худший из вошедших кейсов."""
    repo = InMemoryCaseStore()
    repo.save(_pipeline_case("pipeline-1", ["c2_external_dns"], 0.33, "LOW"))
    result = _use_case(_chain_and_background(), repo).execute(
        case_id="INC-TEST",
        seeds=[IncidentSeed.parse("user:smirnov")],
    )
    assert result.case.risk_score == pytest.approx(0.33)


def test_incident_inherits_measured_vectors_of_its_parts() -> None:
    """Сборка не теряет измеренную основу вошедших дел.

    Ритм и организационный контекст меряются по событиям, а не выводятся из срабатываний:
    в наборе маркеров ритма и контекста нет ни одного SOC-инварианта. Пока сборка считала
    объединение с нулевого ритма и контекста, инцидент выходил слабее собственных частей и
    держался только страховкой «не ниже худшего вошедшего дела» — то есть сборка не
    добавляла к оценке ничего, хотя её смысл ровно обратный.
    """
    measured = {"rhythm": 0.75, "graph": 0.9, "context": 0.45, "user": 0.1, "data_quality": 0.0}
    weak = _pipeline_case("pipeline-1", ["c2_external_dns"], 0.05, "LOW")
    weak.risk_vectors = dict(measured)
    shift = _pipeline_case("pipeline-2", ["out_of_shift_access"], 0.04, "LOW")

    repo = InMemoryCaseStore()
    repo.save(weak)
    repo.save(shift)
    use_case = AssembleIncidentUseCase(
        events=_FakeEventStore(_chain_and_background()),
        repo=repo,
        weights=_WEIGHTS,
    )
    result = use_case.execute(case_id="INC-VECTORS", seeds=[IncidentSeed.parse("user:smirnov")])

    vectors = result.case.risk_vectors
    assert vectors["rhythm"] == pytest.approx(0.75), "измеренный ритм вошедшего дела потерян"
    assert vectors["context"] == pytest.approx(0.45), "измеренный контекст вошедшего дела потерян"
    # Пользовательский вектор поднят объединением: 0.1 у части, 0.7 по out_of_shift_access.
    assert vectors["user"] == pytest.approx(0.7)


def test_assembled_case_stores_its_own_vectors() -> None:
    """Иначе повторная сборка поверх собранного дела снова считала бы с нуля."""
    repo = InMemoryCaseStore()
    repo.save(_pipeline_case("pipeline-1", ["c2_external_dns"], 0.05, "LOW"))
    use_case = AssembleIncidentUseCase(
        events=_FakeEventStore(_chain_and_background()),
        repo=repo,
        weights=_WEIGHTS,
    )
    result = use_case.execute(case_id="INC-STORED", seeds=[IncidentSeed.parse("user:smirnov")])

    assert set(result.case.risk_vectors) == {"rhythm", "graph", "context", "user", "data_quality"}
