"""Содержание паспорта инцидента: находки, артефакты и основания решений.

Замечание, с которого начата работа (аудит «След смены», разрыв D07): в сохранённом деле были
находка `FORENSIC_FINDING_MARKER` и артефакт `HASH_MARKER`; сгенерированный PDF не содержал ни
одного из этих значений, зато содержал строку журнала `case.finding.add appended`. Получатель
паспорта видел факт добавления находки, но не её содержание — связный итог приходилось
собирать заново из выгрузок.

Forensic bundle эти данные отдаёт отдельными файлами, поэтому проблема именно в основном
читаемом выходе: паспорт — то, что берут в руки, и он обязан отвечать, что нашли и на каком
основании закрыли дело.

Здесь проверяется присутствие содержания, а не вёрстка: PDF читается как поток текста, и
проверка ищет в нём контрольные значения. Отсутствие такой проверки и было причиной того, что
пробел дожил до аудита при зелёном `test_pdf_export`.
"""

from __future__ import annotations

import contextlib
import re
import zlib
from datetime import UTC, datetime

from takt.domain.entities.case import (
    Case,
    CaseArtifact,
    CaseDecisionRecord,
    CaseStatus,
    Finding,
)
from takt.infrastructure.export.case_pdf import render_case_pdf

NOW = datetime(2026, 9, 8, 11, 0, tzinfo=UTC)


def _pdf_text(payload: bytes) -> str:
    """Видимый текст PDF: содержимое потоков распаковывается, из него берутся строки.

    Точная вёрстка здесь не проверяется — важно, дошло ли значение до документа вообще.
    """
    chunks: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", payload, re.DOTALL):
        raw = match.group(1)
        # Поток может быть и несжатым: тогда распаковка не нужна, а не ошибочна.
        with contextlib.suppress(zlib.error):
            raw = zlib.decompress(raw)
        chunks.append(raw.decode("latin-1", errors="ignore"))
    body = "".join(chunks) + payload.decode("latin-1", errors="ignore")
    return body


def _contains(text: str, value: str) -> bool:
    """Есть ли значение в документе.

    Длинные значения намеренно разбиваются переносом (`_break_long_tokens`), иначе они уходят
    за поле страницы: контрольные суммы и пути длиннее шестнадцати знаков. Поэтому сравнение
    идёт без пробелов — проверяется присутствие значения, а не его вёрстка.
    """
    squeezed = "".join(text.split())
    return "".join(value.split()) in squeezed


def _case() -> Case:
    case = Case(
        case_id="c-1",
        status=CaseStatus.CONFIRMED,
        title="Case with evidence",
        risk_class="HIGH",
        risk_score=0.81,
        created_at=NOW,
        normalized_event_ids=["ev-1", "ev-2"],
        xai_summary="summary",
        artifacts=[
            CaseArtifact(
                type="hash", value="HASH_MARKER", host_id="HOST_MARKER",
                verification_status="confirmed", source="manual", added_by="alice", created_at=NOW,
            )
        ],
        findings=[
            Finding(
                finding_id="f-1",
                text="FORENSIC_FINDING_MARKER",
                author="alice",
                created_at=NOW,
                event_ids=["ev-1"],
                artifacts=[CaseArtifact(type="file", value="FILE_MARKER", host_id="HOST_MARKER")],
            )
        ],
        decision_records=[
            CaseDecisionRecord(
                ts=NOW, actor="alice",
                prev_status=CaseStatus.TRIAGE.value, next_status=CaseStatus.CONFIRMED.value,
                reason="REASON_MARKER",
            )
        ],
    )
    case.append_audit("case.finding.add appended", NOW, actor="alice")
    return case


def test_findings_reach_the_passport() -> None:
    """То самое воспроизведение: в PDF был факт добавления находки, но не её текст."""
    text = _pdf_text(render_case_pdf(_case(), generated_at=NOW))

    assert _contains(text, "FORENSIC_FINDING_MARKER")
    assert "case.finding.add" in text, "журнал остаётся: он и раньше был единственным следом"


def test_artifacts_reach_the_passport_together_with_their_hosts() -> None:
    """Артефакт без узла — объект без привязки: получателю нечего с ним делать."""
    text = _pdf_text(render_case_pdf(_case(), generated_at=NOW))

    assert _contains(text, "HASH_MARKER")
    assert _contains(text, "HOST_MARKER")
    assert _contains(text, "FILE_MARKER"), "артефакт находки терялся вместе с её содержанием"


def test_decision_grounds_reach_the_passport() -> None:
    """Паспорт обязан отвечать, на каком основании дело закрыли."""
    text = _pdf_text(render_case_pdf(_case(), generated_at=NOW))

    assert _contains(text, "REASON_MARKER")
    assert "TRIAGE" in text and "CONFIRMED" in text


def test_an_empty_case_says_so_instead_of_dropping_the_section() -> None:
    """Пустой раздел лучше отсутствующего: читающий должен видеть, что находок нет."""
    case = Case(
        case_id="c-2", status=CaseStatus.NEW, title="empty", risk_class="LOW",
        risk_score=0.1, created_at=NOW,
    )

    text = _pdf_text(render_case_pdf(case, generated_at=NOW))

    assert "Findings" in text
    assert "Artifacts" in text
    assert "Decisions" in text


def test_the_passport_names_what_it_truncates() -> None:
    """Усечение обязано быть названо: молча обрезанный итог выглядит полным."""
    case = _case()
    case.audit_log.extend(f"строка журнала {index}" for index in range(120))
    case.findings.extend(
        Finding(finding_id=f"f-{index}", text=f"находка {index}", author="alice", created_at=NOW)
        for index in range(60)
    )

    text = _pdf_text(render_case_pdf(case, generated_at=NOW))

    assert "truncated" in text.lower()
