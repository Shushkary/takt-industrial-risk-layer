"""Итоговое описание расследования: шаблон, редакции и их утверждение.

Аудит «След смены» (разрыв D07) назвал пробел: паспорт инцидента отвечал, что находка была
добавлена, но не что в ней написано, и связного итога — что произошло, чем это подтверждено,
что осталось неясным — в продукте не было вовсе. Аналитик собирал его заново вне контура.

Здесь этот итог появляется как **текст аналитика по шаблону**. Три границы, которые модуль
держит:

1. **Это не вывод продукта.** Описание не участвует в расчёте риска, вердикта и качества
   данных и ничего в них не меняет. Модель языка не вызывается: контур вердикта защищён от
   таких вызовов (`tests/test_verdict_determinism_guard.py`), а шаблон и без неё заполняется
   тем, что продукт уже посчитал.
2. **Редакции неизменяемы.** Правка добавляет новую редакцию, а не переписывает прошлую:
   описание уходит в доказательный пакет, и подменённый задним числом текст обесценил бы
   пакет целиком. У каждой редакции своё контрольное значение канонической формы.
3. **Утверждение отделено от сохранения.** В доказательный пакет идёт утверждённая редакция;
   неутверждённая помечается черновиком. Читающий должен видеть разницу между рабочей записью
   и итогом, который аналитик предъявляет.

Состав разделов взят из устоявшейся практики отчётности об инцидентах, а не придуман здесь:

- **NIST SP 800-61r2** (Computer Security Incident Handling Guide), §3.2.5 и приложение с
  составом записи об инциденте: краткое изложение, хронология, воздействие, предпринятые
  действия;
- **ISO/IEC 27035-2** — состав отчёта об инциденте и его рассмотрение перед выпуском;
- **SANS Incident Handler's Handbook** — шестой шаг «Lessons Learned» как обязательная часть
  разбора, а не необязательное дополнение;
- **ICD 203 (Analytic Standards)** — оценка отделяется от установленного факта и
  сопровождается выраженной уверенностью со ссылкой на основания;
- **NIST SP 800-86** (Guide to Integrating Forensic Techniques) — в отчёте называются
  ограничения и пробелы, а не только результат.

Порядок разделов фиксирован: читающий должен получать ответ на вопрос «что случилось» раньше,
чем аргументацию, а ограничения — до рекомендаций, а не после них.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from takt.domain.entities.case import Case, InvestigationSummary
from takt.domain.entities.event import NormalizedEvent
from takt.domain.ports.case_repository import CaseRepositoryPort

HIGH_CONFIDENCE = "high"
MODERATE_CONFIDENCE = "moderate"
LOW_CONFIDENCE = "low"
CONFIDENCE_LEVELS = (HIGH_CONFIDENCE, MODERATE_CONFIDENCE, LOW_CONFIDENCE)

MAX_SECTION_LENGTH = 8000
"""Предел одного раздела. Итог — связный текст, а не выгрузка: без предела в него уходит
содержимое, для которого в пакете уже есть свои файлы."""


@dataclass(frozen=True, slots=True)
class SummarySection:
    """Раздел итогового описания: ключ, заголовок и вопрос, на который он отвечает."""

    key: str
    title: str
    prompt: str
    """Что аналитику написать. Подсказка остаётся в интерфейсе и не попадает в текст."""


SECTIONS: tuple[SummarySection, ...] = (
    SummarySection(
        "executive_summary",
        "Краткое изложение",
        "Три-четыре предложения для того, кто принимает решение: что произошло, чем это грозит,"
        " что сделано.",
    ),
    SummarySection(
        "what_happened",
        "Что произошло",
        "Установленные факты в хронологии, со ссылками на события и находки. Только то, что"
        " подтверждено данными; предположения — в разделе оценки.",
    ),
    SummarySection(
        "how_detected",
        "Как обнаружено",
        "Что и в каком источнике сработало, почему события связаны в один инцидент.",
    ),
    SummarySection(
        "impact",
        "Затронутое и воздействие",
        "Узлы, учётные записи, процессы и данные: что затронуто, что проверено, что не"
        " проверялось.",
    ),
    SummarySection(
        "assessment",
        "Оценка аналитика",
        "Интерпретация фактов и её основания. Гипотезы называть гипотезами; уверенность"
        " указывается отдельным полем.",
    ),
    SummarySection(
        "response",
        "Предпринятое и рекомендованное",
        "Что уже сделано и кем, что рекомендовано пакетом реагирования. ТАКТ этих действий"
        " не выполняет — исполняет внешняя система после подтверждения.",
    ),
    SummarySection(
        "open_questions",
        "Нерешённые вопросы и ограничения",
        "Чего не хватило: недоступные источники, пробелы истории, неполученные документы."
        " Ограничения называются здесь, а не подразумеваются.",
    ),
    SummarySection(
        "lessons",
        "Извлечённые уроки",
        "Что изменить в правилах, наблюдаемости или порядке работ, чтобы разбор в следующий"
        " раз был короче.",
    ),
)

SECTION_KEYS: tuple[str, ...] = tuple(section.key for section in SECTIONS)


@dataclass(frozen=True, slots=True)
class SummaryTemplate:
    """Заготовка описания: подсказки разделов и то, что продукт уже знает о деле."""

    sections: tuple[SummarySection, ...]
    draft: dict[str, str]
    confidence: str
    facts: dict[str, object]
    """Опорные значения дела для заполнения: аналитик их проверяет, а не переписывает вручную."""


def summary_checksum(sections: dict[str, str], confidence: str) -> str:
    """Контрольное значение канонической формы редакции.

    Каноническая форма — отсортированные ключи, разделители без пробелов, UTF-8 без
    экранирования: та же редакция обязана давать то же значение при повторном расчёте, иначе
    сверка редакции в пакете ничего не проверяет.
    """
    payload = {"confidence": confidence, "sections": {key: sections.get(key, "") for key in SECTION_KEYS}}
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _clean(sections: dict[str, str] | None) -> dict[str, str]:
    """Только известные разделы и только в пределах длины.

    Неизвестный ключ отбрасывается, а не сохраняется молча: иначе состав описания в пакете
    разошёлся бы с каталогом разделов, и читающий не понял бы, что видит.
    """
    given = sections or {}
    cleaned: dict[str, str] = {}
    for key in SECTION_KEYS:
        value = str(given.get(key, "") or "").strip()
        if len(value) > MAX_SECTION_LENGTH:
            raise ValueError(f"section is too long: {key}")
        cleaned[key] = value
    return cleaned


def build_summary_template(
    case: Case,
    events: Sequence[NormalizedEvent] = (),
    *,
    response_actions: Sequence[str] = (),
) -> SummaryTemplate:
    """Заготовка, собранная из уже посчитанного продуктом.

    Заготовка намеренно не пишет за аналитика выводов: она подставляет то, что и так есть в
    деле — состав, источники, находки, решения, — чтобы он не переносил это руками и не
    ошибался в идентификаторах. Строки-выводы («вероятно, это атака») здесь не появляются:
    такой текст был бы утверждением продукта, выданным за слова человека.
    """
    ordered = sorted(events, key=lambda item: (item.observed_at, item.event_id))
    sources = sorted({event.source.value for event in ordered})
    hosts = sorted({event.entities.host_id for event in ordered if event.entities and event.entities.host_id})
    accounts = sorted({event.entities.user_id for event in ordered if event.entities and event.entities.user_id})
    findings = [item.text for item in case.findings if not item.historical]
    decisions = [
        f"{record.prev_status} -> {record.next_status}: {record.reason}".strip()
        for record in case.decision_records
    ]
    gaps: list[str] = []
    if case.dq_partial or case.dq_reasons:
        gaps.append("качество данных неполное: " + (", ".join(case.dq_reasons) or "наблюдение частичное"))
    if not case.manual_permits:
        gaps.append("организационный документ к делу не приложен")
    if not ordered:
        gaps.append("состав событий недоступен в этом окне")

    facts: dict[str, object] = {
        "case_id": case.case_id,
        "title": case.title,
        "status": case.status.value,
        "risk_class": case.risk_class,
        "events": len(case.normalized_event_ids),
        "period_from": ordered[0].observed_at.isoformat() if ordered else "",
        "period_to": ordered[-1].observed_at.isoformat() if ordered else "",
        "sources": sources,
        "hosts": hosts,
        "accounts": accounts,
        "invariant_hits": list(case.invariant_hits),
        "findings": findings,
        "decisions": decisions,
        "response_actions": list(response_actions),
        "gaps": gaps,
        "xai_summary": case.xai_summary,
    }

    period = (
        f"{facts['period_from']} — {facts['period_to']}" if ordered else "период недоступен"
    )
    draft = {
        "executive_summary": "",
        "what_happened": _bullets(
            [f"Дело {case.case_id}: {case.title}", f"Период событий: {period}", f"Событий в составе: {len(case.normalized_event_ids)}"]
        ),
        "how_detected": _bullets(
            [f"Источники: {', '.join(sources) or 'не определены'}",
             f"Сработавшие инварианты: {', '.join(case.invariant_hits) or 'нет'}"]
        ),
        "impact": _bullets(
            [f"Узлы: {', '.join(hosts) or 'не определены'}",
             f"Учётные записи: {', '.join(accounts) or 'не определены'}"]
        ),
        "assessment": "",
        "response": _bullets(list(response_actions)) if response_actions else "",
        "open_questions": _bullets(gaps) if gaps else "",
        "lessons": "",
    }
    # Уверенность не угадывается: аналитик выбирает её сам. Средняя стоит как значение,
    # которое придётся подтвердить осознанно, а не как оценка продукта.
    return SummaryTemplate(sections=SECTIONS, draft=draft, confidence=MODERATE_CONFIDENCE, facts=facts)


def _bullets(lines: Sequence[str]) -> str:
    return "\n".join(f"- {line}" for line in lines if line)


class InvestigationSummaryUseCase:
    """Сохранение и утверждение редакций итогового описания."""

    def __init__(self, repo: CaseRepositoryPort) -> None:
        self._repo = repo

    def _case(self, case_id: str) -> Case:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError(f"unknown case: {case_id}")
        return case

    def current(self, case_id: str) -> InvestigationSummary | None:
        """Редакция, которую показывает продукт: последняя утверждённая, иначе последняя."""
        case = self._case(case_id)
        approved = [item for item in case.investigation_summaries if item.approved]
        if approved:
            return approved[-1]
        return case.investigation_summaries[-1] if case.investigation_summaries else None

    def save(
        self,
        case_id: str,
        sections: dict[str, str],
        *,
        confidence: str,
        actor: str,
        clock: datetime,
    ) -> InvestigationSummary:
        case = self._case(case_id)
        cleaned = _clean(sections)
        if not any(cleaned.values()):
            raise ValueError("investigation summary is empty")
        level = (confidence or "").strip().lower()
        if level not in CONFIDENCE_LEVELS:
            raise ValueError(f"unknown confidence: {confidence}")
        checksum = summary_checksum(cleaned, level)
        # Повтор того же текста новой редакции не создаёт: журнал только дополняется, и
        # лишняя редакция в нём остаётся навсегда.
        if case.investigation_summaries and case.investigation_summaries[-1].checksum == checksum:
            return case.investigation_summaries[-1]
        record = InvestigationSummary(
            version=len(case.investigation_summaries) + 1,
            sections=cleaned,
            confidence=level,
            author=actor,
            created_at=clock,
            checksum=checksum,
        )
        case.investigation_summaries.append(record)
        case.append_audit(
            f"case.summary.version {record.version} sha256={checksum[:16]}", clock, actor=actor
        )
        self._repo.save(case)
        self._record_operation(case, action="case.summary.save", actor=actor, clock=clock,
                               payload={"version": record.version, "checksum": checksum})
        return record

    def approve(self, case_id: str, version: int, *, actor: str, clock: datetime) -> InvestigationSummary:
        """Утверждение редакции: в доказательный пакет идёт именно она.

        Утверждается конкретный номер, а не «последнее»: между чтением и нажатием состав мог
        смениться, и утвердить вслепую чужую правку нельзя.
        """
        case = self._case(case_id)
        record = next((item for item in case.investigation_summaries if item.version == version), None)
        if record is None:
            raise ValueError(f"unknown summary version: {version}")
        if record.approved:
            return record
        record.approved = True
        record.approved_by = actor
        record.approved_at = clock
        case.append_audit(f"case.summary.approved version {version}", clock, actor=actor)
        self._repo.save(case)
        self._record_operation(case, action="case.summary.approve", actor=actor, clock=clock,
                               payload={"version": version, "checksum": record.checksum})
        return record

    def _record_operation(self, case: Case, *, action: str, actor: str, clock: datetime, payload: dict) -> None:
        record = getattr(self._repo, "record_operation_event", None)
        if callable(record):
            record(
                operation_type=action, entity_id=case.case_id, actor=actor,
                payload_json=json.dumps(payload, ensure_ascii=False), created_at=clock.isoformat(),
            )
