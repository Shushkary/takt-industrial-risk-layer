"""Русские обозначения в АРМ: словарь один и приходит из продукта.

Аналитик и руководитель читают слова, а не коды. Проверяется не наличие переводов в `app.js` —
их там и не должно быть, — а то, что интерфейс **берёт названия у продукта** и нигде не
показывает код там, где есть название.

Два свойства, которые легко потерять при следующей правке:

1. **Параллельного словаря в АРМ нет.** Свой список статусов или источников разошёлся бы с
   `GET /catalog/vocabulary` при первом же добавлении значения — и разошёлся бы молча.
2. **Значения из данных источника не переводятся.** Операция, протокол, идентификаторы узлов и
   учётных записей — материал доказательства; перевод исказил бы то, что в журнале.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ARM = Path(__file__).resolve().parents[1] / "frontend" / "takt-pt-arm"
_INDEX = _ARM / "index.html"
_APP = _ARM / "app.js"


def _app() -> str:
    return _APP.read_text(encoding="utf-8")


def test_vocabulary_comes_from_the_product() -> None:
    app = _app()

    assert "/catalog/vocabulary" in app
    assert "function term(" in app


def test_vocabulary_is_loaded_before_the_first_render() -> None:
    """Иначе очередь мигнёт кодами и перерисуется словами."""
    app = _app()

    assert "loadVocabulary().then(" in app
    start = app.index("loadVocabulary().then(")
    assert "refresh();" in app[start : start + 250]


@pytest.mark.parametrize(
    "table",
    ["risk_class", "case_status", "event_source", "entity_type", "artifact_type"],
)
def test_each_vocabulary_table_is_actually_used(table: str) -> None:
    """Таблица, которую никто не читает, — это перевод, который пользователь не увидит."""
    assert f"term('{table}'" in _app(), table


def test_arm_keeps_no_parallel_dictionary_of_statuses_or_sources() -> None:
    """Свой словарь разошёлся бы с продуктом молча.

    Коды статусов и источников не должны встречаться в `app.js` как ключи локальных таблиц:
    единственное место, где они называются, — ответ `GET /catalog/vocabulary`.
    """
    app = _app()

    for code in ("FALSE_POSITIVE", "EXPECTED_BEHAVIOR", "CONFIRMED", "TRIAGE"):
        assert code not in app, f"код статуса {code} попал в интерфейс"
    for code in ("auth_logs", "plc_polling", "network_events", "service_desk"):
        assert code not in app, f"код источника {code} попал в интерфейс"


def test_invariant_names_come_from_the_rule_catalog() -> None:
    """Названия правил — из каталога инвариантов, по которому работает сам движок."""
    app = _app()

    assert "'/invariants'" in app
    assert "invariantTitles" in app
    assert "function invariantTitle(" in app


def test_invariant_chip_keeps_the_rule_id_in_the_tooltip() -> None:
    """Аналитику идентификатор нужен, чтобы найти правило в config/invariants.

    Показывать его вместо названия — значит заставлять читать код; убрать совсем — лишить
    возможности сопоставить срабатывание с конфигурацией.
    """
    app = _app()
    start = app.index("function renderInvariants(")
    block = app[start : app.index("\nfunction entityButton(", start)]

    assert "chip.title = id" in block


def test_risk_class_code_still_drives_the_colour() -> None:
    """Цвет остаётся на коде: перевод не должен ломать выделение критичности."""
    app = _app()

    assert "risk ${escapeHtml(String(item.risk_class || '').toLowerCase())}" in app


def test_source_data_values_are_not_translated() -> None:
    """Операция и протокол приходят из журнала источника и остаются как есть."""
    app = _app()

    assert "term('operation'" not in app
    assert "term('protocol'" not in app
    # Операция печатается напрямую — это значение из данных, а не наше обозначение.
    assert "escapeHtml(event.operation)" in app


def test_untranslated_code_falls_back_to_the_code_itself() -> None:
    """Выдуманный перевод хуже кода: его нельзя сверить с ответом API."""
    app = _app()
    start = app.index("function term(")
    block = app[start : app.index("\nfunction firstArtifact(", start)]

    assert "|| value" in block


def test_markup_has_no_latin_designations_left() -> None:
    """В видимом тексте разметки латиницей остаются только UTC и путь API."""
    text = _INDEX.read_text(encoding="utf-8")
    visible = re.findall(r">([^<>]*[A-Za-z]{2,}[^<>]*)<", text)

    unexpected = [
        item.strip()
        for item in visible
        if item.strip() and "UTC" not in item and "/simulation" not in item
    ]
    assert not unexpected, unexpected
