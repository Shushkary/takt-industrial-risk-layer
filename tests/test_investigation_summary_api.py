"""Итоговое описание через API: шаблон, сохранение, утверждение и выход в документы.

Здесь проверяется маршрут целиком — от заготовки до того, что редакция дошла до паспорта и
доказательного пакета. Разрыв D07 аудита «След смены» ровно в этом и состоял: данные в деле
были, а до читаемого выхода не доходили.
"""

from __future__ import annotations

import contextlib
import json
import re
import zlib
from datetime import UTC, datetime
from io import BytesIO
from zipfile import ZipFile

from fastapi.testclient import TestClient

from takt.application.use_cases.investigation_summary import SECTION_KEYS
from takt.domain.entities.case import Case, CaseStatus
from takt.interface_adapters.api.main import create_app

NOW = datetime(2026, 9, 9, 10, 0, tzinfo=UTC)


def _client_with_case(case_id: str = "sum-1") -> tuple[TestClient, object]:
    app = create_app()
    app.state.repo.save(
        Case(
            case_id=case_id,
            status=CaseStatus.TRIAGE,
            title="Захват инженерной станции",
            risk_class="HIGH",
            risk_score=0.81,
            created_at=NOW,
            normalized_event_ids=["e-1"],
            invariant_hits=["INV-OT-01"],
        )
    )
    return TestClient(app), app


def _sections(text: str = "Инженерная станция захвачена.") -> dict[str, str]:
    sections = dict.fromkeys(SECTION_KEYS, "")
    sections["executive_summary"] = text
    return sections


def _pdf_text(payload: bytes) -> str:
    """Видимый текст PDF без пробелов.

    Потоки документа сжаты, а длинные значения намеренно разбиваются переносом, чтобы не
    уходить за поле страницы. Проверяется присутствие значения, а не его вёрстка.
    """
    chunks: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", payload, re.DOTALL):
        raw = match.group(1)
        with contextlib.suppress(zlib.error):
            raw = zlib.decompress(raw)
        chunks.append(raw.decode("latin-1", errors="ignore"))
    body = "".join(chunks) + payload.decode("latin-1", errors="ignore")
    return "".join(body.split())


def test_the_template_comes_with_titles_and_prompts() -> None:
    """Аналитик получает не пустое поле, а вопросы, на которые отвечает отчёт об инциденте."""
    client, _ = _client_with_case()

    with client:
        body = client.get("/cases/sum-1/summary").json()

    assert [item["key"] for item in body["sections"]] == list(SECTION_KEYS)
    assert all(item["title"] and item["prompt"] for item in body["sections"])
    assert body["current"] is None
    assert body["template"]["facts"]["case_id"] == "sum-1"


def test_saving_and_approving_a_version() -> None:
    client, _ = _client_with_case()

    with client:
        saved = client.post(
            "/cases/sum-1/summary",
            json={"sections": _sections(), "confidence": "moderate"},
        )
        assert saved.status_code == 200, saved.text
        version = saved.json()["version"]

        approved = client.post("/cases/sum-1/summary/approve", json={"version": version})
        assert approved.status_code == 200, approved.text

        body = client.get("/cases/sum-1/summary").json()

    assert body["current"]["version"] == version
    assert body["current"]["approved"] is True
    assert len(body["versions"]) == 1


def test_an_empty_summary_is_refused_by_the_api() -> None:
    client, _ = _client_with_case()

    with client:
        response = client.post(
            "/cases/sum-1/summary",
            json={"sections": dict.fromkeys(SECTION_KEYS, ""), "confidence": "moderate"},
        )

    assert response.status_code == 400
    assert "empty" in response.json()["detail"]


def test_approving_a_missing_version_is_refused() -> None:
    client, _ = _client_with_case()

    with client:
        response = client.post("/cases/sum-1/summary/approve", json={"version": 3})

    assert response.status_code == 400


def test_the_summary_survives_a_restart_of_the_store(tmp_path) -> None:
    """Редакция — доказательный материал: она обязана пережить перезапуск, а не жить в памяти."""
    import os

    from takt.infrastructure.stores.sqlite_store import SqliteCaseStore

    path = tmp_path / "cases.sqlite3"
    os.environ["TAKT_STORAGE"] = "sqlite"
    os.environ["TAKT_SQLITE_PATH"] = str(path)
    try:
        app = create_app()
        app.state.repo.save(
            Case(case_id="sum-2", status=CaseStatus.TRIAGE, title="дело", risk_class="LOW",
                 risk_score=0.2, created_at=NOW)
        )
        with TestClient(app) as client:
            client.post(
                "/cases/sum-2/summary",
                json={"sections": _sections("Текст, который обязан пережить перезапуск."),
                      "confidence": "high"},
            )
        app.state.repo.close()

        reopened = SqliteCaseStore(path)
        try:
            case = reopened.get("sum-2")
            assert case is not None
            assert len(case.investigation_summaries) == 1
            record = case.investigation_summaries[0]
            assert record.confidence == "high"
            assert "пережить перезапуск" in record.sections["executive_summary"]
            assert len(record.checksum) == 64
        finally:
            reopened.close()
    finally:
        os.environ.pop("TAKT_STORAGE", None)
        os.environ.pop("TAKT_SQLITE_PATH", None)


def test_the_approved_version_reaches_the_forensic_bundle() -> None:
    """Пакет должен показывать, что предъявлено, а что ему предшествовало."""
    client, _ = _client_with_case("sum-3")

    with client:
        client.post(
            "/cases/sum-3/summary",
            json={"sections": _sections("Черновая редакция."), "confidence": "low"},
        )
        client.post(
            "/cases/sum-3/summary",
            json={"sections": _sections("Утверждаемая редакция."), "confidence": "high"},
        )
        client.post("/cases/sum-3/summary/approve", json={"version": 2})
        archive = client.get("/cases/sum-3/forensic-bundle.zip")

    assert archive.status_code == 200
    with ZipFile(BytesIO(archive.content)) as zf:
        names = set(zf.namelist())
        payload = json.loads(zf.read("investigation-summary.json").decode("utf-8"))
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))

    assert "investigation-summary.json" in names
    assert payload["presented_version"] == 2
    assert payload["presented_state"] == "approved"
    assert [item["version"] for item in payload["versions"]] == [1, 2]
    # У элемента пакета своё контрольное значение — редакцию можно сверить, не доверяя архиву.
    item = next(row for row in manifest["items"] if row["path"] == "investigation-summary.json")
    assert len(item["sha256"]) == 64
    assert item["element_type"] == "итоговое описание"


def test_an_unapproved_summary_is_presented_as_a_draft() -> None:
    """Черновик и утверждённый итог — разные вещи, и пакет обязан их различать."""
    client, _ = _client_with_case("sum-4")

    with client:
        client.post(
            "/cases/sum-4/summary",
            json={"sections": _sections("Ещё не утверждено."), "confidence": "low"},
        )
        archive = client.get("/cases/sum-4/forensic-bundle.zip")

    with ZipFile(BytesIO(archive.content)) as zf:
        payload = json.loads(zf.read("investigation-summary.json").decode("utf-8"))

    assert payload["presented_state"] == "draft"


def test_the_summary_reaches_the_case_passport() -> None:
    """Паспорт берут в руки: итог обязан быть в нём, а не только в машинном экспорте."""
    client, _ = _client_with_case("sum-5")

    with client:
        client.post(
            "/cases/sum-5/summary",
            json={"sections": _sections("SUMMARY_MARKER в итоге."), "confidence": "high"},
        )
        client.post("/cases/sum-5/summary/approve", json={"version": 1})
        pdf = client.get("/cases/sum-5/export.pdf")

    assert pdf.status_code == 200
    text = _pdf_text(pdf.content)
    assert "SUMMARY_MARKER" in text
    assert "Investigationsummary" in text
