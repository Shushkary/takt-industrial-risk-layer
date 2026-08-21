"""Генерация PDF «паспорт инцидента» (спринт 11 ТЗ). Требует extra: pip install '.[export]'

Здесь же — одностраничная сводка для лица, принимающего решение (разрыв G-5,
``docs/customer_value_map.md``). Паспорт и сводка различаются не оформлением, а адресатом:
паспорт даёт аналитику весь состав дела, сводка даёт руководителю ровно то, по чему он решает.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from takt.domain.entities.case import Case
from takt.domain.services.decision_brief import decision_brief
from takt.domain.services.verdict_confidence import MissingContextItem

_PROJECT_ROOT = Path(__file__).resolve().parents[4]


def _latin1_safe(text: str) -> str:
    """Fallback для Helvetica — только latin-1."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _break_long_tokens(text: str, *, max_token_len: int = 16) -> str:
    parts: list[str] = []
    for token in text.split(" "):
        if len(token) <= max_token_len:
            parts.append(token)
            continue
        chunks = [token[i : i + max_token_len] for i in range(0, len(token), max_token_len)]
        parts.append(" ".join(chunks))
    return " ".join(parts)


def _pdf_visible_audit_log(case: Case) -> list[str]:
    return [entry for entry in case.audit_log if "pdf exported sha256=" not in entry]


def _open_document(ts: datetime, unicode_font_path: str | None) -> tuple[Any, str | None, str]:
    """Пустой документ с подключённым шрифтом. Общая часть паспорта и сводки."""
    try:
        from fpdf import FPDF
    except ImportError as e:
        raise RuntimeError(
            "Для PDF установите зависимость: pip install 'takt-industrial-risk-layer[export]'"
        ) from e

    pdf = FPDF()
    if hasattr(pdf, "set_creation_date"):
        pdf.set_creation_date(ts)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    font_file: str | None = None
    if unicode_font_path:
        candidate = Path(unicode_font_path).expanduser()
        if not candidate.is_absolute():
            candidate = _PROJECT_ROOT / candidate
        p = candidate.resolve()
        try:
            p.relative_to(_PROJECT_ROOT.resolve())
        except ValueError:
            p = _PROJECT_ROOT / "__outside_project_font_is_not_allowed__"
        if p.is_file():
            font_file = str(p)
            pdf.add_font("TaktUni", "", font_file)

    return pdf, font_file, ("TaktUni" if font_file else "Helvetica")


def _document_bytes(pdf: Any) -> bytes:
    out = pdf.output()
    if isinstance(out, str):
        return out.encode("latin-1")
    return bytes(out)


def render_case_pdf(
    case: Case,
    *,
    generated_at: datetime | None = None,
    unicode_font_path: str | None = None,
) -> bytes:
    ts = generated_at or datetime.now()
    pdf, font_file, body_font = _open_document(ts, unicode_font_path)

    pdf.set_font(body_font, "", 16)
    pdf.cell(0, 10, "TAKT Industrial Risk Layer", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(body_font, "", 11)
    pdf.cell(0, 8, f"Incident passport / Case {case.case_id}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    def T(s: str) -> str:
        return s if font_file else _latin1_safe(s)

    lines = [
        f"Generated (UTC): {ts.isoformat(timespec='seconds')}",
        f"Status: {case.status.value}",
        f"Risk class: {case.risk_class}",
        f"Risk score: {case.risk_score:.4f}",
        f"Data quality: {case.dq_score:.4f} (partial={case.dq_partial})",
        f"DQ reasons: {', '.join(case.dq_reasons) if case.dq_reasons else '-'}",
        f"Title: {T(case.title)}",
        f"Primary asset: {case.primary_asset_id or '-'}",
        f"Last event source: {case.last_event_source or '-'}",
        f"Trigger operation: {case.trigger_operation or '-'}",
        f"Fingerprint: {case.burst_fingerprint or '-'}",
        "",
        "Invariant hits:",
        ", ".join(case.invariant_hits) if case.invariant_hits else "-",
        "",
        "XAI summary:",
        T(case.xai_summary[:4000]),
        "",
        "Normalized event IDs:",
        ", ".join(case.normalized_event_ids) or "-",
        "",
        "Audit trail:",
        "\n".join(T(x) for x in _pdf_visible_audit_log(case)[-50:]) if _pdf_visible_audit_log(case) else "-",
    ]

    pdf.set_font(body_font, "", 10)

    def write_paragraph(paragraph: str) -> None:
        if hasattr(pdf, "set_x") and hasattr(pdf, "l_margin"):
            pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _break_long_tokens(paragraph))

    for block in lines:
        for paragraph in block.split("\n"):
            write_paragraph(T(paragraph))
        pdf.ln(1)

    return _document_bytes(pdf)


def render_decision_brief_pdf(
    case: Case,
    *,
    generated_at: datetime | None = None,
    unicode_font_path: str | None = None,
) -> bytes:
    """Один лист для того, кто принимает решение.

    Порядок блоков — порядок вопросов руководителя: вывод и обоснованность, потом чего не
    хватает, потом чем подтверждено, и только затем подробности. Маршрут добора идёт выше
    доказательств намеренно: если вердикт неопределённый, читать остальное незачем, пока
    документ не добран.
    """
    ts = generated_at or datetime.now()
    brief = decision_brief(case)
    pdf, font_file, body_font = _open_document(ts, unicode_font_path)

    def T(s: str) -> str:
        return s if font_file else _latin1_safe(s)

    pdf.set_font(body_font, "", 16)
    pdf.cell(0, 10, T("ТАКТ — сводка для принятия решения"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(body_font, "", 11)
    pdf.cell(0, 8, T(f"Дело {brief.case_id} · {brief.status}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    missing_block = (
        "\n".join(f"- {_missing_line(item)}" for item in brief.missing)
        if brief.missing
        else "- контекста достаточно, вердикт определён"
    )
    measures_block = (
        "\n".join(f"- {m.kind} [{m.status}] {m.action}".rstrip() for m in brief.measures)
        if brief.measures
        else "- меры в деле не зафиксированы"
    )
    decision = brief.last_decision
    decision_line = (
        f"{decision.ts.isoformat(timespec='seconds')} · {decision.actor} · "
        f"{decision.prev_status} -> {decision.next_status} · {decision.reason or '-'}"
        if decision is not None
        else "решение по делу не зафиксировано"
    )

    blocks = [
        f"Сформировано (UTC): {ts.isoformat(timespec='seconds')}",
        f"Заведено: {brief.created_at.isoformat(timespec='seconds')}",
        f"Инцидент: {brief.title}",
        "",
        "ВЫВОД",
        f"Вердикт: {brief.verdict_value} ({brief.verdict})",
        f"Обоснованность: {brief.confidence_grade} ({brief.confidence_score:.2f} из 1.00)",
        f"Риск: {brief.risk_class} ({brief.risk_score:.2f})",
        "",
        "ЧЕГО НЕ ХВАТАЕТ",
        missing_block,
        "",
        "ЧЕМ ПОДТВЕРЖДЕНО",
        f"- сырых доказательств: {brief.evidence.raw_evidence_count}",
        f"- организационных документов с контрольной суммой: {brief.evidence.organizational_documents}",
        f"- записей аудиторского следа: {brief.evidence.audit_entries}",
        f"- доказательный пакет собран: {'да' if brief.evidence.forensic_bundle_exported else 'нет'}",
        "",
        "ЧТО ПРОИЗОШЛО",
        brief.explanation or "-",
        "Сработавшие инварианты:",
        "\n".join(f"- {title}" for title in brief.invariants) if brief.invariants else "- нет",
        "",
        "МЕРЫ",
        measures_block,
        "",
        "ПОСЛЕДНЕЕ РЕШЕНИЕ",
        decision_line,
        "",
        brief.boundary_note,
    ]

    pdf.set_font(body_font, "", 10)
    for block in blocks:
        for paragraph in block.split("\n"):
            if hasattr(pdf, "set_x") and hasattr(pdf, "l_margin"):
                pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 5, _break_long_tokens(T(paragraph)))
        pdf.ln(1)

    return _document_bytes(pdf)


def _missing_line(item: MissingContextItem) -> str:
    """Пункт маршрута добора с адресом: какой документ, у кого, за какое окно."""
    parts = [item.text]
    if item.required_document:
        parts.append(f"документ: {item.required_document}")
    if item.sanctioning_party:
        parts.append(f"утверждающий: {item.sanctioning_party}")
    if item.admissible_window:
        parts.append(f"окно: {item.admissible_window}")
    return " · ".join(parts)
