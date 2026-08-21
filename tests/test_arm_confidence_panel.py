"""Обоснованность вывода и маршрут добора в АРМ аналитика.

Закрывает фронтовую часть разрывов G-3, G-5 и G-1 из
[`docs/customer_value_map.md`](../docs/customer_value_map.md). АРМ живёт без сборщика SPA,
поэтому проверяется то, что проверяемо статически и что ломается чаще всего: расхождение
разметки и кода, второй расчёт показателя в интерфейсе, потерянная граница продукта.

Главное, что здесь закреплено: **интерфейс не считает обоснованность сам**. Показатель
приходит из `verdict_confidence` в ответе API. Свой расчёт в АРМ разошёлся бы с тем, что
уходит в сводку руководителю и в доказательный контур, и разошёлся бы незаметно.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_ARM = Path(__file__).resolve().parents[1] / "frontend" / "takt-pt-arm"
_INDEX = _ARM / "index.html"
_APP = _ARM / "app.js"
_STYLES = _ARM / "styles.css"


def _index() -> str:
    return _INDEX.read_text(encoding="utf-8")


def _app() -> str:
    return _APP.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "element_id",
    [
        "verdictBadge",
        "confidenceGrade",
        "confidenceScore",
        "confidenceComponents",
        "missingBlock",
        "missingList",
        "briefButton",
    ],
)
def test_confidence_elements_exist(element_id: str) -> None:
    """Код обращается к этим идентификаторам напрямую."""
    assert f'id="{element_id}"' in _index(), element_id


def test_app_reads_confidence_from_the_api_answer() -> None:
    """Показатель берётся из ответа продукта, а не собирается в интерфейсе."""
    app = _app()

    assert "renderConfidence(item.verdict_confidence)" in app
    assert "confidence.components" in app
    assert "confidence.missing" in app


def test_arm_does_not_recompute_the_confidence_score() -> None:
    """Второй расчёт в интерфейсе разошёлся бы с доказательным контуром — и незаметно.

    Веса составляющих объявлены в домене (`verdict_confidence.CONFIDENCE_WEIGHTS`). Появление
    их числовых значений в арифметике `app.js` означало бы, что АРМ считает свою величину.
    """
    app = _app()
    render_start = app.index("function renderConfidence(")
    render_block = app[render_start : app.index("\nfunction gradeClass(", render_start)]

    for forbidden in ("0.40", "0.25", "0.20", "0.15"):
        assert forbidden not in render_block, f"в АРМ появился собственный расчёт веса {forbidden}"
    assert "confidence.score" in render_block


def test_missing_block_is_hidden_when_there_is_nothing_to_collect() -> None:
    """Пустой блок «Чего не хватает» читался бы как «данных нет», а не «всё на месте»."""
    app = _app()
    start = app.index("function renderMissing(")
    block = app[start : app.index("\nfunction openDecisionBrief(", start)]

    assert "block.hidden = !items.length" in block


def test_missing_route_shows_where_to_get_the_document() -> None:
    """Маршрут добора без адреса — это снова «контекста нет» без выхода (G-1)."""
    app = _app()
    start = app.index("function renderMissing(")
    block = app[start : app.index("\nfunction openDecisionBrief(", start)]

    for field in ("required_document", "sanctioning_party", "admissible_window"):
        assert field in block, field


def test_decision_brief_opens_the_product_document() -> None:
    """Сводка для руководителя — документ продукта, а не пересказ из интерфейса аналитика."""
    app = _app()

    assert "/decision-brief.pdf" in app
    assert "$('#briefButton').addEventListener('click', openDecisionBrief)" in app


def test_help_registry_covers_the_new_blocks() -> None:
    """Блок без пояснения в этом АРМ не заводится."""
    app = _app()

    assert "confidence: {" in app
    assert "missing: {" in app


def test_confidence_help_states_the_grade_cap() -> None:
    """Ограничение оценки — продуктовое обещание, а не деталь реализации.

    Аналитик должен понимать, почему при отличном качестве данных обоснованность не высокая,
    иначе он сочтёт это ошибкой интерфейса.
    """
    app = _app()
    start = app.index("confidence: {")
    text = app[start : start + 1800]

    assert "не бывает высокой" in text
    assert "слабейшему звену" in text


def test_verdict_and_grade_are_visible_together() -> None:
    """Вердикт без обоснованности — половина основания для решения."""
    index = _index()
    start = index.index('class="verdict-line"')
    line = index[start : index.index("</div>", start)]

    assert 'id="verdictBadge"' in line
    assert 'id="confidenceGrade"' in line


def test_styles_define_confidence_classes() -> None:
    styles = _STYLES.read_text(encoding="utf-8")

    for selector in (".verdict.undet", ".grade.high", ".component-fill", ".missing-block"):
        assert selector in styles, selector


def test_confidence_block_declares_no_active_control() -> None:
    """Граница продукта: в блоке нет кнопок исполнения мер."""
    index = _index()
    start = index.index('class="block confidence-block"')
    block = index[start : index.index('id="missingBlock"')]

    for word in ("Изолировать", "Заблокировать", "Выполнить", "Отправить"):
        assert word not in block, word
