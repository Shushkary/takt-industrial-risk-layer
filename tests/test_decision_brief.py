"""Сводка для лица, принимающего решение.

Разрыв G-5 из [`docs/customer_value_map.md`](../docs/customer_value_map.md): этап 6 пути
клиента — тот, где решение принимает руководитель, а не аналитик. Он несёт цену ошибки, но
разбирать карточку аналитика не будет. Сводка отвечает на четыре его вопроса и ни на один
чужой: что произошло, насколько выводу можно верить, чем это подтверждено, чего не хватает.

Границу продукта сводка не двигает: меры остаются рекомендациями, исполняет их внешняя
система после подтверждения человека (`docs/product_boundary.md`, «Активное управление»).
Проверка этого — часть тестов ниже, а не только договорённость.
"""

from __future__ import annotations

from datetime import UTC, datetime

from takt.domain.entities.case import (
    Case,
    CaseDecisionRecord,
    CaseStatus,
    ManualPermit,
    Observation,
    RawEvidenceRef,
    RemediationAttempt,
    VerdictCounterfactual,
)
from takt.domain.services.decision_brief import ACTIVE_CONTROL_DISCLAIMER, decision_brief

_TS = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)


def _case(**overrides: object) -> Case:
    case = Case(
        case_id="c-77",
        status=CaseStatus.TRIAGE,
        title="Запись в регистр ПЛК вне окна работ",
        risk_class="HIGH",
        risk_score=0.82,
        created_at=_TS,
        normalized_event_ids=["e-1", "e-2"],
        primary_asset_id="PLC-01",
        trigger_operation="WRITE_REGISTER",
        invariant_hits=["out_of_shift_access"],
        observations=[Observation(source="ndr", ingest_trust=0.9, event_ids=["e-1", "e-2"])],
        xai_summary="Запись в регистр вне разрешённого окна работ.",
        dq_score=1.0,
        dq_partial=False,
    )
    for key, value in overrides.items():
        setattr(case, key, value)
    return case


def _permit(verdict: str, counterfactual: VerdictCounterfactual) -> ManualPermit:
    return ManualPermit(
        permit_id="p-1",
        case_id="c-77",
        work_order_number="НР-42",
        actor="analyst",
        created_at=_TS,
        asset_id="PLC-01",
        operation="WRITE_REGISTER",
        verdict=verdict,
        confidence=0.9,
        rationale="",
        counterfactual="",
        counterfactual_struct=counterfactual.to_dict(),
        organizational_context_sha256="a" * 64,
    )


def test_brief_answers_the_four_questions_of_a_decision_maker() -> None:
    brief = decision_brief(_case())

    assert brief.case_id == "c-77"
    assert brief.risk_class == "HIGH"
    assert brief.verdict == "UNDET"
    assert brief.confidence_grade
    assert brief.missing != ()
    assert brief.explanation == "Запись в регистр вне разрешённого окна работ."


def test_invariants_are_named_in_russian() -> None:
    """Руководитель читает названия, а не идентификаторы инвариантов."""
    brief = decision_brief(_case())

    assert brief.invariants
    assert all(title != "out_of_shift_access" for title in brief.invariants)


def test_evidence_summary_counts_what_is_actually_attached() -> None:
    case = _case(
        raw_evidence_refs=[
            RawEvidenceRef(
                evidence_id="r-1",
                source="ndr",
                media_type="application/json",
                captured_at=_TS,
                payload_b64="e30=",
                sha256="b" * 64,
                size_bytes=2,
            )
        ],
        manual_permits=[_permit("legitimate", VerdictCounterfactual(verdict="legitimate"))],
    )
    case.append_audit("forensic bundle generated root_hash=c00 signature_status=mvp", _TS, actor="analyst")

    brief = decision_brief(case)

    assert brief.evidence.raw_evidence_count == 1
    assert brief.evidence.organizational_documents == 1
    assert brief.evidence.forensic_bundle_exported is True
    assert brief.evidence.audit_entries >= 1


def test_forensic_bundle_flag_is_false_until_bundle_is_built() -> None:
    """Не выдавать несобранный пакет за подтверждение: это прямая цена ошибки решения."""
    case = _case()
    case.append_audit("pdf exported sha256=deadbeef", _TS, actor="analyst")

    assert decision_brief(case).evidence.forensic_bundle_exported is False


def test_missing_route_leads_the_brief_when_verdict_is_undetermined() -> None:
    counterfactual = VerdictCounterfactual(
        verdict="undetermined",
        unmet_conditions=("утверждающий",),
        required_document="НР-42",
    )
    brief = decision_brief(_case(manual_permits=[_permit("undetermined", counterfactual)]))

    assert brief.verdict == "UNDET"
    assert [item.text for item in brief.missing] == ["утверждающий"]
    assert brief.missing[0].required_document == "НР-42"


def test_determined_verdict_has_no_missing_route() -> None:
    brief = decision_brief(_case(manual_permits=[_permit("legitimate", VerdictCounterfactual(verdict="legitimate"))]))

    assert brief.verdict == "LEG"
    assert brief.missing == ()


def test_last_decision_is_shown_with_actor_and_reason() -> None:
    case = _case(
        decision_records=[
            CaseDecisionRecord(
                ts=_TS,
                actor="head-of-soc",
                prev_status="NEW",
                next_status="TRIAGE",
                reason="передано в разбор",
            )
        ]
    )

    brief = decision_brief(case)

    assert brief.last_decision is not None
    assert brief.last_decision.actor == "head-of-soc"
    assert brief.last_decision.reason == "передано в разбор"


def test_brief_without_decisions_says_so_instead_of_guessing() -> None:
    assert decision_brief(_case()).last_decision is None


def test_recommended_measures_are_recorded_attempts_only() -> None:
    """Сводка показывает зафиксированные меры, а не изобретает новые."""
    case = _case(
        remediation_attempts=[
            RemediationAttempt(
                attempt_id="a-1",
                case_id="c-77",
                kind="access_review",
                status="planned",
                actor="analyst",
                created_at=_TS,
                action="проверить маршрут доступа",
                result="",
            )
        ]
    )

    brief = decision_brief(case)

    assert [measure.kind for measure in brief.measures] == ["access_review"]
    assert brief.measures[0].status == "planned"


def test_brief_states_the_product_boundary() -> None:
    """Граница продукта печатается в самой сводке, а не подразумевается.

    Сводка уходит человеку, который вправе распорядиться остановкой процесса. Он должен
    видеть, что ТАКТ мер не исполняет, прямо в документе, по которому решает.
    """
    brief = decision_brief(_case())

    assert brief.boundary_note == ACTIVE_CONTROL_DISCLAIMER
    assert "не выполняет" in brief.boundary_note


def test_api_serves_brief_and_one_page_pdf() -> None:
    """Сквозная проверка: сводка доступна и как JSON, и как лист PDF."""
    from fastapi.testclient import TestClient

    from takt.interface_adapters.api.main import create_app

    with TestClient(create_app()) as client:
        case_id = client.post(
            "/assess",
            json={
                "observed_at": "2026-04-30T21:00:00+00:00",
                "operation": "WRITE_REGISTER",
                "asset_id": "plc-brief",
            },
        ).json()["case_id"]

        brief = client.get(f"/cases/{case_id}/decision-brief")
        assert brief.status_code == 200
        payload = brief.json()
        assert payload["case_id"] == case_id
        assert payload["verdict"] in ("LEG", "ILLEG", "UNDET")
        assert payload["boundary_note"] == ACTIVE_CONTROL_DISCLAIMER
        assert payload["missing"], "дело без наряда обязано нести маршрут добора"

        pdf = client.get(f"/cases/{case_id}/decision-brief.pdf")
        assert pdf.status_code == 200
        assert pdf.headers["content-type"] == "application/pdf"
        assert pdf.content[:4] == b"%PDF"

        # Производный документ: выгрузка сводки не является событием жизненного цикла дела,
        # поэтому журнал после неё не растёт — в отличие от паспорта инцидента.
        audit_before = client.get(f"/cases/{case_id}").json()["audit_log"]
        assert client.get(f"/cases/{case_id}/decision-brief.pdf").status_code == 200
        assert client.get(f"/cases/{case_id}").json()["audit_log"] == audit_before

        assert client.get("/cases/no-such-case/decision-brief").status_code == 404


def test_brief_is_deterministic() -> None:
    """Сводка идёт руководителю и регулятору: повторный вызов обязан совпасть."""
    case = _case(
        manual_permits=[
            _permit(
                "undetermined",
                VerdictCounterfactual(verdict="undetermined", unmet_conditions=("окно работ", "утверждающий")),
            )
        ]
    )

    assert decision_brief(case) == decision_brief(case)
    assert decision_brief(case).to_dict() == decision_brief(case).to_dict()
