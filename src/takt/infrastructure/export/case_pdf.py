"""Генерация PDF «паспорт инцидента» (спринт 11 ТЗ). Требует extra: pip install '.[export]'"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from takt.domain.entities.case import Case

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


def render_case_pdf(
    case: Case,
    *,
    generated_at: datetime | None = None,
    unicode_font_path: str | None = None,
) -> bytes:
    try:
        from fpdf import FPDF
    except ImportError as e:
        raise RuntimeError(
            "Для PDF установите зависимость: pip install 'takt-industrial-risk-layer[export]'"
        ) from e

    ts = generated_at or datetime.now()

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

    body_font = "TaktUni" if font_file else "Helvetica"

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

    out = pdf.output()
    if isinstance(out, str):
        return out.encode("latin-1")
    return bytes(out)
