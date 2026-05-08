from __future__ import annotations

import builtins
import sys
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.export.case_pdf import render_case_pdf
from takt.interface_adapters.api.main import create_app


def test_render_pdf_bytes():
    c = Case(
        case_id="pdf1",
        status=CaseStatus.TRIAGE,
        title="demo",
        risk_class="MEDIUM",
        risk_score=0.5,
        created_at=datetime.now(timezone.utc),
        xai_summary="test summary",
    )
    raw = render_case_pdf(c)
    assert raw[:4] == b"%PDF"


def test_render_pdf_cyrillic_title_smoke():
    c = Case(
        case_id="pdf-ru",
        status=CaseStatus.NEW,
        title="Инцидент — проверка PDF",
        risk_class="LOW",
        risk_score=0.15,
        created_at=datetime.now(timezone.utc),
        xai_summary="Кратко: безопасность",
    )
    raw = render_case_pdf(c)
    assert raw[:4] == b"%PDF"


def test_render_case_pdf_missing_unicode_font_path_uses_helvetica(tmp_path) -> None:
    missing = tmp_path / "missing.ttf"
    assert not missing.is_file()
    c = Case(
        case_id="pdf-font",
        status=CaseStatus.NEW,
        title="OK",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
    )
    raw = render_case_pdf(c, unicode_font_path=str(missing))
    assert raw[:4] == b"%PDF"


def test_render_case_pdf_encodes_when_output_returns_str(monkeypatch: pytest.MonkeyPatch) -> None:
    import fpdf

    class FPdfStub:
        def set_auto_page_break(self, *_, **__) -> None:
            pass

        def add_page(self) -> None:
            pass

        def set_font(self, *_, **__) -> None:
            pass

        def cell(self, *_, **__) -> None:
            pass

        def ln(self, *_, **__) -> None:
            pass

        def multi_cell(self, *_, **__) -> None:
            pass

        def output(self, *_, **__):
            return "%PDF-1.3\nstub-line"

    monkeypatch.setattr(fpdf, "FPDF", FPdfStub)
    c = Case(
        case_id="pdf-str",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
    )
    raw = render_case_pdf(c)
    assert raw == ("%PDF-1.3\nstub-line").encode("latin-1")


def test_render_case_pdf_triggers_add_font_when_unicode_file_exists(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import fpdf

    font = tmp_path / "hook.ttf"
    font.touch()
    captured: list[tuple[str, str, str]] = []

    real_cls = fpdf.FPDF

    def factory(*args, **kwargs):
        pdf = real_cls(*args, **kwargs)

        def add_font(family, style="", fname="", *args, **kwargs):
            captured.append((family, style or "", fname or ""))

        pdf.add_font = add_font  # type: ignore[method-assign]

        real_set = pdf.set_font

        def set_font(family=None, style="", size=0):
            resolved = "Helvetica" if family == "TaktUni" else family
            return real_set(resolved, style, size)

        pdf.set_font = set_font  # type: ignore[method-assign]
        return pdf

    monkeypatch.setattr(fpdf, "FPDF", factory)
    c = Case(
        case_id="font-hook",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
    )
    raw = render_case_pdf(c, unicode_font_path=str(font))
    assert raw[:4] == b"%PDF"
    assert len(captured) == 1
    assert captured[0][0] == "TaktUni"
    assert captured[0][2] == str(font.resolve())


def test_render_case_pdf_raises_when_fpdf_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    sys.modules.pop("fpdf", None)

    real_import = builtins.__import__

    def fake_import(name: str, globals=None, locals=None, fromlist=(), level: int = 0):
        if name == "fpdf":
            raise ImportError("No module named 'fpdf'")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    c = Case(
        case_id="pdf-missing",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(RuntimeError, match="pip install"):
        render_case_pdf(c)


def test_api_pdf_route():
    app = create_app()
    client = TestClient(app)
    r = client.post("/assess", json={"observed_at": "2026-04-30T21:00:00+00:00", "operation": "POLL"})
    assert r.status_code == 200
    cid = r.json()["case_id"]
    pdf = client.get(f"/cases/{cid}/export.pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert len(pdf.headers["x-takt-pdf-sha256"]) == 64
    detail = client.get(f"/cases/{cid}").json()
    assert detail["pdf_last_sha256"] == pdf.headers["x-takt-pdf-sha256"]
    assert detail["pdf_last_generated_at"]


def test_api_pdf_route_has_stable_sha_for_unchanged_case():
    app = create_app()
    client = TestClient(app)
    r = client.post("/assess", json={"observed_at": "2026-04-30T21:00:00+00:00", "operation": "POLL"})
    assert r.status_code == 200
    cid = r.json()["case_id"]

    first = client.get(f"/cases/{cid}/export.pdf")
    second = client.get(f"/cases/{cid}/export.pdf")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.headers["x-takt-pdf-sha256"] == second.headers["x-takt-pdf-sha256"]
    assert first.content == second.content
