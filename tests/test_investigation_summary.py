"""Итоговое описание расследования: шаблон, редакции, утверждение и границы.

Часть разрыва D07 аудита «След смены»: связного итога — что произошло, чем подтверждено, что
осталось неясным — в продукте не было, и аналитик собирал его заново вне контура.

Проверяется не «поле сохраняется», а то, что описание остаётся текстом человека и не
превращается ни в вывод продукта, ни в переписываемый задним числом документ:

- расчёты дела (риск, вердикт, качество данных) от описания не меняются;
- шаблон заполняется тем, что продукт уже посчитал, и не пишет выводов за аналитика;
- правка добавляет редакцию, а не переписывает прошлую;
- у редакции своё контрольное значение канонической формы, воспроизводимое при повторе;
- утверждение отделено от сохранения: в пакет идёт утверждённая редакция.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from takt.application.use_cases.investigation_summary import (
    DRAFT_MARKER,
    MAX_SECTION_LENGTH,
    SECTION_KEYS,
    InvestigationSummaryUseCase,
    build_summary_template,
    summary_checksum,
)
from takt.domain.entities.case import Case, CaseDecisionRecord, CaseStatus, Finding
from takt.domain.entities.event import EventEntities, EventSource, NormalizedEvent
from takt.infrastructure.stores.memory import InMemoryCaseStore

NOW = datetime(2026, 9, 9, 10, 0, tzinfo=UTC)


def _event(event_id: str, *, minute: int = 0, host: str = "eng-ws-04", user: str = "eng.petrov") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        observed_at=NOW + timedelta(minutes=minute),
        source=EventSource.EDR,
        protocol="test",
        operation="PROCESS_START",
        payload_size=1,
        payload={},
        entities=EventEntities(host_id=host, user_id=user),
        ingest_trust=1.0,
    )


def _case(**kwargs) -> Case:
    base = {
        "case_id": "c-1",
        "status": CaseStatus.TRIAGE,
        "title": "Захват инженерной станции",
        "risk_class": "HIGH",
        "risk_score": 0.81,
        "created_at": NOW,
        "normalized_event_ids": ["e-1", "e-2"],
        "invariant_hits": ["INV-OT-01"],
        "xai_summary": "объяснение продукта",
    }
    base.update(kwargs)
    return Case(**base)


def _sections(**overrides) -> dict[str, str]:
    sections = dict.fromkeys(SECTION_KEYS, "")
    sections["executive_summary"] = "Инженерная станция захвачена, линия розлива остановлена."
    sections.update(overrides)
    return sections


def _use_case(case: Case) -> tuple[InvestigationSummaryUseCase, InMemoryCaseStore]:
    repo = InMemoryCaseStore()
    repo.save(case)
    return InvestigationSummaryUseCase(repo), repo


# --- шаблон ----------------------------------------------------------------


def test_the_template_offers_every_section_of_the_practice() -> None:
    """Состав разделов взят из практики отчётности, а не придуман: он должен быть полным."""
    template = build_summary_template(_case(), [])

    assert [section.key for section in template.sections] == list(SECTION_KEYS)
    assert all(section.title and section.prompt for section in template.sections)
    # Ограничения идут до рекомендаций, а не после: иначе читающий принимает решение раньше,
    # чем узнаёт, чего в деле не хватает.
    keys = list(SECTION_KEYS)
    assert keys.index("open_questions") > keys.index("assessment")
    assert keys.index("lessons") == len(keys) - 1


def test_the_template_is_prefilled_from_what_the_product_already_knows() -> None:
    """Идентификаторы не переносятся руками: там и появлялись ошибки."""
    case = _case(findings=[Finding("f-1", "powershell.exe скачал upd_agent.exe", "alice", NOW)])
    events = [_event("e-1"), _event("e-2", minute=5, host="jump-01")]

    template = build_summary_template(case, events)

    assert template.facts["case_id"] == "c-1"
    assert template.facts["hosts"] == ["eng-ws-04", "jump-01"]
    assert template.facts["sources"] == ["edr"]
    assert "eng-ws-04" in template.draft["impact"]
    assert "INV-OT-01" in template.draft["how_detected"]


def test_the_template_leaves_the_analysts_own_conclusions_empty() -> None:
    """Краткое изложение и уроки — выводы человека: подписывать их его именем продукт не вправе."""
    template = build_summary_template(_case(), [_event("e-1")])

    assert template.draft["executive_summary"] == ""
    assert template.draft["lessons"] == ""


def test_the_assessment_draft_is_the_product_explanation_and_says_so() -> None:
    """Черновик оценки допустим, но он обязан называться черновиком.

    В поле «Оценка аналитика» кладётся то, что продукт посчитал сам: объяснение оценки риска
    и сработавшие инварианты. Без пометки этот текст ушёл бы в доказательный пакет как слова
    человека, подписанные его именем.
    """
    case = _case()
    template = build_summary_template(case, [_event("e-1")])
    draft = template.draft["assessment"]

    assert draft.startswith(f"- {DRAFT_MARKER}")
    assert case.xai_summary in draft
    assert "INV-OT-01" in draft
    assert case.risk_class in draft


def test_the_assessment_draft_holds_without_a_product_explanation() -> None:
    """У дела может не быть объяснения риска — заготовка не должна на этом ломаться."""
    template = build_summary_template(_case(xai_summary="", invariant_hits=[]), [])
    draft = template.draft["assessment"]

    assert draft.startswith(f"- {DRAFT_MARKER}")
    assert "Класс риска" in draft


def test_the_template_names_the_gaps_it_knows_about() -> None:
    """Нерешённые вопросы продукт знает сам: неполнота данных и отсутствие наряда."""
    case = _case(dq_partial=True, dq_reasons=["stale_data"])

    template = build_summary_template(case, [_event("e-1")])

    assert "stale_data" in template.draft["open_questions"]
    assert "организационный документ" in template.draft["open_questions"]


def test_the_template_is_deterministic() -> None:
    """Заготовка входит в доказательный контур делом, а не собой: повтор обязан совпасть."""
    case = _case()
    events = [_event("e-2", minute=5), _event("e-1")]

    assert build_summary_template(case, events) == build_summary_template(case, events)


# --- редакции --------------------------------------------------------------


def test_editing_adds_a_version_instead_of_rewriting_the_previous_one() -> None:
    """Описание уходит в пакет: подменённый задним числом текст обесценил бы пакет."""
    case = _case()
    use_case, repo = _use_case(case)

    first = use_case.save("c-1", _sections(), confidence="moderate", actor="alice", clock=NOW)
    second = use_case.save(
        "c-1", _sections(executive_summary="Уточнено: остановка линии подтверждена."),
        confidence="high", actor="bob", clock=NOW + timedelta(hours=1),
    )

    stored = repo.get("c-1")
    assert stored is not None
    assert [item.version for item in stored.investigation_summaries] == [1, 2]
    assert stored.investigation_summaries[0].sections == first.sections
    assert second.version == 2 and second.author == "bob"


def test_a_repeated_save_of_the_same_text_does_not_create_a_version() -> None:
    """Журнал только дополняется: лишняя редакция останется в нём навсегда."""
    use_case, repo = _use_case(_case())

    use_case.save("c-1", _sections(), confidence="moderate", actor="alice", clock=NOW)
    use_case.save("c-1", _sections(), confidence="moderate", actor="alice", clock=NOW + timedelta(hours=1))

    stored = repo.get("c-1")
    assert stored is not None and len(stored.investigation_summaries) == 1


def test_a_version_carries_a_reproducible_checksum() -> None:
    """Без воспроизводимого значения сверка редакции в пакете ничего не проверяет."""
    use_case, _ = _use_case(_case())

    record = use_case.save("c-1", _sections(), confidence="moderate", actor="alice", clock=NOW)

    assert record.checksum == summary_checksum(record.sections, record.confidence)
    assert record.checksum == summary_checksum(dict(reversed(list(record.sections.items()))), "moderate")


def test_an_empty_summary_is_refused() -> None:
    """Пустой итог хуже отсутствующего: он занимает место ответа, не будучи им."""
    use_case, _ = _use_case(_case())

    with pytest.raises(ValueError, match="empty"):
        use_case.save("c-1", dict.fromkeys(SECTION_KEYS, ""), confidence="moderate", actor="alice", clock=NOW)


def test_an_unknown_confidence_is_refused() -> None:
    """Уверенность — обозначение со словарём, а не свободная строка."""
    use_case, _ = _use_case(_case())

    with pytest.raises(ValueError, match="confidence"):
        use_case.save("c-1", _sections(), confidence="уверен", actor="alice", clock=NOW)


def test_an_unknown_section_is_dropped_not_stored() -> None:
    """Состав описания в пакете обязан совпадать с каталогом разделов."""
    use_case, _ = _use_case(_case())

    record = use_case.save(
        "c-1", {**_sections(), "выдуманный_раздел": "текст"},
        confidence="moderate", actor="alice", clock=NOW,
    )

    assert set(record.sections) == set(SECTION_KEYS)


def test_a_section_longer_than_the_limit_is_refused() -> None:
    """Итог — связный текст, а не выгрузка: для содержимого в пакете есть свои файлы."""
    use_case, _ = _use_case(_case())

    with pytest.raises(ValueError, match="too long"):
        use_case.save(
            "c-1", _sections(what_happened="x" * (MAX_SECTION_LENGTH + 1)),
            confidence="moderate", actor="alice", clock=NOW,
        )


# --- утверждение -----------------------------------------------------------


def test_the_current_summary_is_the_approved_one() -> None:
    """В пакет идёт утверждённая редакция, а не последняя черновая."""
    use_case, _ = _use_case(_case())
    use_case.save("c-1", _sections(), confidence="moderate", actor="alice", clock=NOW)
    use_case.approve("c-1", 1, actor="bob", clock=NOW + timedelta(minutes=5))
    use_case.save(
        "c-1", _sections(executive_summary="черновик следующей редакции"),
        confidence="low", actor="alice", clock=NOW + timedelta(hours=1),
    )

    current = use_case.current("c-1")

    assert current is not None
    assert (current.version, current.approved, current.approved_by) == (1, True, "bob")


def test_approving_names_the_version_and_not_just_the_latest() -> None:
    """Между чтением и нажатием состав мог смениться: утвердить вслепую чужую правку нельзя."""
    use_case, _ = _use_case(_case())
    use_case.save("c-1", _sections(), confidence="moderate", actor="alice", clock=NOW)

    with pytest.raises(ValueError, match="unknown summary version"):
        use_case.approve("c-1", 7, actor="bob", clock=NOW)


def test_approval_is_recorded_in_the_case_journal() -> None:
    """Утверждение — действие человека над доказательным материалом, и оно журналируется."""
    use_case, repo = _use_case(_case())
    use_case.save("c-1", _sections(), confidence="moderate", actor="alice", clock=NOW)
    use_case.approve("c-1", 1, actor="bob", clock=NOW + timedelta(minutes=5))

    stored = repo.get("c-1")
    assert stored is not None
    assert any("case.summary.version 1" in line for line in stored.audit_log)
    assert any("case.summary.approved version 1" in line and "bob" in line for line in stored.audit_log)


# --- границы ---------------------------------------------------------------


def test_the_summary_changes_no_computed_value_of_the_case() -> None:
    """Это текст человека, а не вывод продукта: расчёты дела он не трогает."""
    case = _case()
    use_case, repo = _use_case(case)
    before = repo.get("c-1")
    assert before is not None

    use_case.save("c-1", _sections(), confidence="high", actor="alice", clock=NOW)
    use_case.approve("c-1", 1, actor="bob", clock=NOW)
    after = repo.get("c-1")

    assert after is not None
    assert (after.risk_score, after.risk_class, after.status) == (before.risk_score, before.risk_class, before.status)
    assert (after.dq_score, after.dq_partial, after.invariant_hits) == (
        before.dq_score, before.dq_partial, before.invariant_hits
    )
    assert after.normalized_event_ids == before.normalized_event_ids


def test_the_template_does_not_depend_on_a_language_model() -> None:
    """«Без обязательного LLM» — это свойство кода, а не обещание в документации."""
    from pathlib import Path

    module = Path(__file__).resolve().parents[1] / "src" / "takt" / "application" / "use_cases"
    lowered = (module / "investigation_summary.py").read_text(encoding="utf-8").lower()

    for marker in ("openai", "anthropic", "httpx", "requests.post", "llm(", "generate_text"):
        assert marker not in lowered, marker


def test_decisions_and_findings_reach_the_template_facts() -> None:
    """Аналитик не должен переписывать в итог то, что дело уже содержит."""
    case = _case(
        findings=[Finding("f-1", "powershell.exe скачал upd_agent.exe", "alice", NOW)],
        decision_records=[
            CaseDecisionRecord(ts=NOW, actor="alice", prev_status="TRIAGE", next_status="CONFIRMED",
                               reason="подтверждён захват станции")
        ],
    )

    template = build_summary_template(case, [_event("e-1")])

    assert template.facts["findings"] == ["powershell.exe скачал upd_agent.exe"]
    assert template.facts["decisions"] == ["TRIAGE -> CONFIRMED: подтверждён захват станции"]
