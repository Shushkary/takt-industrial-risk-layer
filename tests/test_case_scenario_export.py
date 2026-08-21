"""Закрытое дело как проверенный сценарий регресса.

Разрыв G-6 из [`docs/customer_value_map.md`](../docs/customer_value_map.md): этап 7 пути
клиента — «нет накопления проверенных знаний». Закрытое дело с подтверждённым вердиктом —
самый дорогой актив заказчика: за ним стоит работа аналитика и решение человека. Но
переиспользовать его нельзя: следующий релиз может тихо перестать ловить тот же сценарий.

Экспорт превращает такое дело в фикстуру, которую прогоняет
[`tests/test_case_scenarios.py`](test_case_scenarios.py). С этого момента накопленные случаи
заказчика работают сторожем от регрессий.

Главное ограничение проверяется здесь же: **сценарием становится только закрытое дело с
подтверждённым человеком вердиктом**. Неразобранное дело — это гипотеза, а не знание;
закрепив его как эталон, мы бы зафиксировали в регрессе собственную ошибку.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from takt.application.use_cases.case_scenario import (
    SCENARIO_SCHEMA_VERSION,
    build_case_scenario,
    event_from_dict,
    event_to_dict,
)
from takt.domain.entities.case import (
    Case,
    CaseStatus,
    FormalVerdictRecord,
    ManualPermit,
    VerdictCounterfactual,
)
from takt.domain.entities.event import ArtifactType, EventArtifact, EventEntities, EventSource, NormalizedEvent

_TS = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)


def _event(event_id: str = "e-1") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=_TS,
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="WRITE_REGISTER",
        payload_size=64,
        payload={"asset_id": "PLC-01", "function_code": 6},
        operator_id="op-1",
        entities=EventEntities(host_id="PLC-01", user_id="op-1"),
        artifacts=(EventArtifact(ArtifactType.HOST, "PLC-01"),),
        ingest_trust=0.9,
    )


def _confirmed_case(**overrides: object) -> Case:
    case = Case(
        case_id="c-77",
        status=CaseStatus.CONFIRMED,
        title="Запись в регистр ПЛК вне окна работ",
        risk_class="HIGH",
        risk_score=0.82,
        created_at=_TS,
        normalized_event_ids=["e-1"],
        primary_asset_id="PLC-01",
        trigger_operation="WRITE_REGISTER",
        invariant_hits=["out_of_shift_access", "blind_command"],
        formal_verdict_records=[
            FormalVerdictRecord(
                ts=_TS,
                actor="analyst",
                prev="неопределённое",
                next="нелегитимное",
                score=0.9,
                source="operator_confirmation",
                reason="подтверждено дежурным",
            )
        ],
    )
    for key, value in overrides.items():
        setattr(case, key, value)
    return case


def test_event_codec_round_trips_every_field() -> None:
    """Фикстура хранит событие целиком: потеря поля тихо изменила бы сценарий."""
    event = _event()

    restored = event_from_dict(event_to_dict(event))

    assert restored == event


def test_event_codec_output_is_json_stable() -> None:
    payload = event_to_dict(_event())

    assert payload["observed_at"] == _TS.isoformat()
    assert payload["source"] == "plc_polling"
    assert payload["artifacts"] == [{"type": "host", "value": "PLC-01"}]
    assert payload["entities"]["host_id"] == "PLC-01"


def test_scenario_records_the_expected_outcome() -> None:
    scenario = build_case_scenario(_confirmed_case(), [_event()])

    assert scenario["schema_version"] == SCENARIO_SCHEMA_VERSION
    assert scenario["source_case_id"] == "c-77"
    assert scenario["expected"]["verdict"] == "ILLEG"
    assert scenario["expected"]["risk_class"] == "HIGH"
    assert scenario["expected"]["invariant_hits"] == ["blind_command", "out_of_shift_access"]
    assert scenario["confirmed_by"] == "analyst"
    assert len(scenario["events"]) == 1


def test_invariant_hits_are_sorted_for_stable_diffs() -> None:
    """Фикстура ложится в git: порядок обязан быть каноническим, иначе diff — шум."""
    case = _confirmed_case(invariant_hits=["z_last", "a_first"])

    assert build_case_scenario(case, [_event()])["expected"]["invariant_hits"] == ["a_first", "z_last"]


def test_open_case_cannot_become_a_scenario() -> None:
    """Неразобранное дело — гипотеза. Закрепив его эталоном, мы зафиксируем свою ошибку."""
    case = _confirmed_case(status=CaseStatus.TRIAGE)

    with pytest.raises(ValueError, match="closed"):
        build_case_scenario(case, [_event()])


def test_case_without_operator_confirmation_cannot_become_a_scenario() -> None:
    case = _confirmed_case(formal_verdict_records=[])

    with pytest.raises(ValueError, match="confirm"):
        build_case_scenario(case, [_event()])


def test_case_confirmed_as_undetermined_cannot_become_a_scenario() -> None:
    """Подтверждённая неопределённость — честный вердикт, но не эталон для регресса."""
    case = _confirmed_case(
        formal_verdict_records=[
            FormalVerdictRecord(
                ts=_TS,
                actor="analyst",
                prev="неопределённое",
                next="неопределённое",
                score=0.5,
                source="operator_confirmation",
                reason="контекст не найден",
            )
        ]
    )

    with pytest.raises(ValueError, match="undetermined"):
        build_case_scenario(case, [_event()])


def test_case_without_events_cannot_become_a_scenario() -> None:
    with pytest.raises(ValueError, match="events"):
        build_case_scenario(_confirmed_case(), [])


def test_events_are_ordered_by_observation_time() -> None:
    """Прогон зависит от порядка событий — он фиксируется в фикстуре, а не в вызывающем коде."""
    later = NormalizedEvent(
        event_id="e-2",
        observed_at=datetime(2026, 8, 21, 10, 0, tzinfo=UTC),
        source=EventSource.PLC_POLLING,
        protocol="TCP",
        operation="POLL",
        payload_size=8,
        payload={"asset_id": "PLC-01"},
    )
    case = _confirmed_case(normalized_event_ids=["e-1", "e-2"])

    scenario = build_case_scenario(case, [later, _event()])

    assert [item["event_id"] for item in scenario["events"]] == ["e-1", "e-2"]


def test_context_events_carry_the_window_the_engine_saw() -> None:
    """Оконные инварианты без предыстории не воспроизводятся — фикстура несёт её отдельно."""
    earlier = NormalizedEvent(
        event_id="ctx-1",
        observed_at=datetime(2026, 8, 21, 8, 55, tzinfo=UTC),
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="AUTH_FAIL",
        payload_size=8,
        payload={"asset_id": "PLC-01"},
    )
    scenario = build_case_scenario(_confirmed_case(), [_event()], context_events=[earlier])

    assert [item["event_id"] for item in scenario["context_events"]] == ["ctx-1"]
    assert [item["event_id"] for item in scenario["events"]] == ["e-1"]


def test_context_events_exclude_the_case_own_events_and_the_future() -> None:
    """Предыстория — только то, что было до последнего события дела, и без дублей."""
    later = NormalizedEvent(
        event_id="future-1",
        observed_at=datetime(2026, 8, 21, 12, 0, tzinfo=UTC),
        source=EventSource.AUTH_LOGS,
        protocol="SSH",
        operation="LOGIN",
        payload_size=8,
        payload={"asset_id": "PLC-01"},
    )
    scenario = build_case_scenario(_confirmed_case(), [_event()], context_events=[later, _event()])

    assert scenario["context_events"] == []


def test_organizational_context_is_carried_without_secrets() -> None:
    """Контекст нужен для воспроизведения вердикта; в фикстуру идёт контрольная сумма."""
    permit = ManualPermit(
        permit_id="p-1",
        case_id="c-77",
        work_order_number="НР-42",
        actor="analyst",
        created_at=_TS,
        asset_id="PLC-01",
        operation="WRITE_REGISTER",
        verdict="illegitimate",
        confidence=0.9,
        rationale="",
        counterfactual="",
        counterfactual_struct=VerdictCounterfactual(verdict="illegitimate").to_dict(),
        organizational_context_sha256="a" * 64,
    )
    scenario = build_case_scenario(_confirmed_case(manual_permits=[permit]), [_event()])

    assert scenario["organizational_context"] == [
        {
            "work_order_number": "НР-42",
            "verdict": "illegitimate",
            "organizational_context_sha256": "a" * 64,
        }
    ]


def test_scenario_is_deterministic() -> None:
    case = _confirmed_case()

    assert build_case_scenario(case, [_event()]) == build_case_scenario(case, [_event()])


def test_api_exports_scenario_and_refuses_unresolved_case(tmp_path, monkeypatch) -> None:
    """Сквозная проверка на sqlite: события дела хранятся только там.

    В конфигурации без хранилища событий воспроизвести прогон нечем, и endpoint честно
    отвечает 501 — см. `test_api_scenario_export_needs_an_event_store`.
    """
    from fastapi.testclient import TestClient

    from takt.infrastructure.config.weights_loader import load_risk_weights
    from takt.interface_adapters.api.main import create_app

    def fake_load(path):
        weights = load_risk_weights(path)
        weights["storage"] = {"backend": "sqlite", "sqlite_path": str(tmp_path / "scenario.sqlite")}
        return weights

    monkeypatch.setattr("takt.interface_adapters.api.main.load_risk_weights", fake_load)

    with TestClient(create_app()) as client:
        case_id = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T21:00:00+00:00",
                "operation": "WRITE_REGISTER",
                "asset_id": "plc-scenario",
            },
        ).json()["case_id"]

        # Дело ещё не разобрано — экспорт обязан отказать, а не отдать гипотезу.
        assert client.get(f"/cases/{case_id}/scenario.json").status_code == 409

        client.post(
            f"/cases/{case_id}/formal-verdict/confirmation",
            json={"verdict": "нелегитимное", "confidence": 0.9, "reason": "подтверждено дежурным"},
        )
        client.post(f"/cases/{case_id}/decision", json={"status": "CONFIRMED", "reason": "подтверждено"})

        exported = client.get(f"/cases/{case_id}/scenario.json")
        assert exported.status_code == 200
        payload = exported.json()
        assert payload["source_case_id"] == case_id
        assert payload["expected"]["verdict"] == "ILLEG"

        assert client.get("/cases/no-such-case/scenario.json").status_code == 404


def test_api_scenario_export_needs_an_event_store() -> None:
    """Без хранилища событий прогон невоспроизводим — отказ, а не пустая фикстура."""
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    with TestClient(create_app()) as client:
        case_id = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T21:00:00+00:00",
                "operation": "WRITE_REGISTER",
                "asset_id": "plc-no-store",
            },
        ).json()["case_id"]

        assert client.get(f"/cases/{case_id}/scenario.json").status_code == 501
