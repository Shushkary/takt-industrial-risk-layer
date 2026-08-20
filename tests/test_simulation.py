"""Хронология инцидента с объяснением отбора: домен, use case и HTTP-контур.

Проверяется то, ради чего вкладка симуляции появилась: аналитик должен видеть не только
состав кейса, но и почему продукт отобрал каждое событие. Отдельно закреплено, что фазы
цепочки не вычисляются продуктом — они приходят с разметкой источника, и неразмеченное
событие в хронологию не попадает, а его наличие видно в счётчике.

Смежное: `tests/test_assemble_incident.py` (откуда берутся объяснения отбора),
`tests/test_eval_baseline_inc002.py` (счётчики трудоёмкости).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from takt.application.use_cases.simulate_incident import SimulateIncidentUseCase
from takt.domain.entities.case import (
    Case,
    CaseArtifact,
    CaseStatus,
    CorrelationEvidence,
    InvariantHitRecord,
    Observation,
)
from takt.domain.entities.event import EventEntities, EventSource, NormalizedEvent
from takt.domain.entities.kill_chain import (
    KillChainPhase,
    parse_phase,
    parse_technique,
    phase_index,
    phase_title_ru,
)

_T0 = datetime(2026, 8, 17, 6, 0, tzinfo=UTC)


# --- Домен: разметка фаз ---------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("c2", KillChainPhase.C2),
        ("  Lateral_Movement  ", KillChainPhase.LATERAL_MOVEMENT),
        ("", None),
        (None, None),
        ("выдуманная-фаза", None),
    ],
)
def test_phase_parsing_is_forgiving_but_strict(raw, expected) -> None:
    """Неизвестная фаза не роняет разбор инцидента, но и не принимается за настоящую."""
    assert parse_phase(raw) is expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("T1558.003", "T1558.003"), ("t1047", "T1047"), ("1558", None), ("", None), ("T15580031", None)],
)
def test_technique_parsing(raw, expected) -> None:
    assert parse_technique(raw) == expected


def test_phase_order_follows_attack_development() -> None:
    assert phase_index(KillChainPhase.INITIAL_ACCESS) < phase_index(KillChainPhase.C2)
    assert phase_index(KillChainPhase.C2) < phase_index(KillChainPhase.IMPACT)
    # Неразмеченное событие уходит в конец, а не притворяется первой фазой.
    assert phase_index(None) > phase_index(KillChainPhase.IMPACT)


def test_phase_titles_are_russian() -> None:
    assert phase_title_ru(KillChainPhase.LATERAL_MOVEMENT) == "Горизонтальное перемещение"
    assert phase_title_ru(None) == "не размечено"


# --- Use case --------------------------------------------------------------


def _event(event_id: str, *, minutes: int, phase: str = "", technique: str = "", host: str = "ws-17"):
    payload = {"attack_phase": phase, "mitre_technique": technique}
    return NormalizedEvent(
        event_id=event_id,
        observed_at=_T0 + timedelta(minutes=minutes),
        source=EventSource.EDR,
        protocol="endpoint",
        operation="PROCESS_START",
        payload_size=10,
        payload=payload,
        entities=EventEntities(host_id=host, user_id="smirnov"),
    )


class _Store:
    def __init__(self, events):
        self._by_id = {event.event_id: event for event in events}

    def events_by_ids(self, event_ids):
        return [self._by_id[item] for item in event_ids if item in self._by_id]


def _case(event_ids: list[str], *, evidence=(), records=()) -> Case:
    return Case(
        case_id="INC-TEST",
        status=CaseStatus.TRIAGE,
        title="Тестовый инцидент",
        risk_class="MEDIUM",
        risk_score=0.47,
        created_at=_T0,
        normalized_event_ids=event_ids,
        observations=[Observation(source="edr", ingest_trust=1.0, event_ids=event_ids)],
        artifacts=[CaseArtifact(type="user", value="smirnov", source="pivot-seed")],
        correlation_evidence=list(evidence),
        invariant_hit_records=list(records),
        invariant_hits=["c2_external_dns"],
        audit_log=[f"{_T0.isoformat()} | finding appended | actor=analyst.01"],
    )


def test_unlabelled_events_stay_out_of_the_chain() -> None:
    """Событие без фазы не попадает в хронологию, но и не исчезает из счётчиков."""
    events = [
        _event("e-1", minutes=0, phase="initial_access", technique="T1566.001"),
        _event("e-2", minutes=1),
        _event("e-3", minutes=2, phase="c2", technique="T1071.004"),
    ]
    result = SimulateIncidentUseCase(events=_Store(events)).execute(_case(["e-1", "e-2", "e-3"]))
    assert result["chain_length"] == 2
    assert result["events_without_phase"] == 1
    assert result["events_total"] == 3
    assert [step["event_id"] for step in result["steps"]] == ["e-1", "e-3"]


def test_steps_are_ordered_by_time_and_numbered() -> None:
    events = [
        _event("e-late", minutes=5, phase="impact"),
        _event("e-early", minutes=0, phase="initial_access"),
    ]
    result = SimulateIncidentUseCase(events=_Store(events)).execute(_case(["e-late", "e-early"]))
    assert [step["event_id"] for step in result["steps"]] == ["e-early", "e-late"]
    assert [step["order"] for step in result["steps"]] == [1, 2]


def test_detection_explanation_names_selector_and_invariant() -> None:
    """Для каждого шага видно, чем он выделен и на каком основании."""
    events = [_event("e-1", minutes=0, phase="c2", technique="T1071.004")]
    evidence = [
        CorrelationEvidence(
            event_id="e-1",
            fingerprint="",
            rule="pivot",
            fields=["user:smirnov"],
            reason="совпала отличительная сущность инцидента: user:smirnov",
        )
    ]
    records = [
        InvariantHitRecord(
            invariant_id="c2_external_dns",
            event_ref="e-1",
            ts=_T0,
            score_contribution=0.9,
            dq_score=1.0,
            dq_partial=False,
        )
    ]
    result = SimulateIncidentUseCase(events=_Store(events)).execute(
        _case(["e-1"], evidence=evidence, records=records)
    )
    detection = result["steps"][0]["detection_explanation"]
    assert detection["selected_by"] == "pivot"
    assert detection["selected_by_title_ru"] == "пивот по отличительной сущности"
    assert detection["matched_entities"] == ["user:smirnov"]
    assert detection["invariants"] == ["c2_external_dns"]


def test_expansion_is_distinguishable_from_pivot() -> None:
    """Добранное расширением событие помечено иначе — его аналитик обязан отсеять сам."""
    events = [_event("e-2", minutes=1, phase="execution")]
    evidence = [
        CorrelationEvidence(
            event_id="e-2",
            fingerprint="",
            rule="host-expansion",
            fields=["host_id"],
            reason="добрано расширением до уровня узла ws-17 в окне инцидента",
        )
    ]
    result = SimulateIncidentUseCase(events=_Store(events)).execute(_case(["e-2"], evidence=evidence))
    detection = result["steps"][0]["detection_explanation"]
    assert detection["selected_by"] == "host-expansion"
    assert "расширением до уровня узла" in detection["reason"]


def test_phase_summary_follows_attack_order() -> None:
    events = [
        _event("e-1", minutes=3, phase="impact"),
        _event("e-2", minutes=0, phase="initial_access"),
        _event("e-3", minutes=1, phase="c2"),
        _event("e-4", minutes=2, phase="c2"),
    ]
    result = SimulateIncidentUseCase(events=_Store(events)).execute(
        _case(["e-1", "e-2", "e-3", "e-4"])
    )
    assert [item["phase"] for item in result["phases"]] == ["initial_access", "c2", "impact"]
    assert [item["events"] for item in result["phases"]] == [1, 2, 1]


def test_time_appears_only_with_explicit_coefficient() -> None:
    """Коэффициента «секунд на действие» в методике нет — по умолчанию времени не будет."""
    events = [_event("e-1", minutes=0, phase="c2")]
    use_case = SimulateIncidentUseCase(events=_Store(events))
    without = use_case.execute(_case(["e-1"]))["effort"]
    assert without["time_is_modelled"] is False
    assert without["modelled_takt_seconds"] is None

    with_coefficient = use_case.execute(_case(["e-1"]), seconds_per_action=20)["effort"]
    assert with_coefficient["time_is_modelled"] is True
    assert with_coefficient["modelled_takt_seconds"] == pytest.approx(20 * with_coefficient["takt_actions"])


def test_response_options_use_only_distinctive_entities() -> None:
    """Рекомендации строятся по отличительным сущностям, а не по всем сущностям кейса."""
    events = [_event("e-1", minutes=0, phase="c2", host="ws-99")]
    result = SimulateIncidentUseCase(events=_Store(events)).execute(_case(["e-1"]))
    kinds = {option["kind"] for option in result["response_options"]}
    assert kinds == {"reset_account"}
    assert all("ws-99" not in option["objects"] for option in result["response_options"])
