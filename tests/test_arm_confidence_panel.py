"""Вердикт и маршрут добора контекста в АРМ аналитика.

Закрывает фронтовую часть разрывов G-3, G-5 и G-1 из
[`docs/customer_value_map.md`](../docs/customer_value_map.md). АРМ живёт без сборщика SPA,
поэтому проверяется то, что проверяемо статически и что ломается чаще всего: расхождение
разметки и кода, второй расчёт показателя в интерфейсе, потерянная граница продукта.

Оценка обоснованности с окна снята: показывается вердикт и перечень «Чего не хватает».
Главное, что здесь закреплено: **интерфейс ничего не считает сам**. Вердикт приходит из
`verdict_confidence` в ответе API. Свой расчёт в АРМ разошёлся бы с тем, что уходит в сводку
руководителю и в доказательный контур, и разошёлся бы незаметно.
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
        "missingBlock",
        "missingList",
        "briefButton",
    ],
)
def test_verdict_elements_exist(element_id: str) -> None:
    """Код обращается к этим идентификаторам напрямую."""
    assert f'id="{element_id}"' in _index(), element_id


def test_app_reads_the_verdict_from_the_api_answer() -> None:
    """Вердикт берётся из ответа продукта, а не собирается в интерфейсе."""
    app = _app()

    assert "renderConfidence(item.verdict_confidence)" in app
    assert "confidence.verdict" in app
    assert "confidence.missing" in app


def test_arm_shows_no_confidence_score_of_its_own() -> None:
    """Оценка обоснованности снята с окна, а не пересчитана в интерфейсе.

    Веса составляющих объявлены в домене (`verdict_confidence.CONFIDENCE_WEIGHTS`). Ни их
    числовых значений, ни разложения по составляющим в показе быть не должно: и то и другое
    означало бы, что АРМ считает свою величину.
    """
    app = _app()
    render_start = app.index("function renderConfidence(")
    render_block = app[render_start : app.index(chr(10) + "function renderMissing(", render_start)]

    for forbidden in ("0.40", "0.25", "0.20", "0.15", "confidence.score", "confidence.components"):
        assert forbidden not in render_block, f"в показе вердикта появилось: {forbidden}"


def test_missing_block_is_hidden_when_there_is_nothing_to_collect() -> None:
    """Пустой блок «Чего не хватает» читался бы как «данных нет», а не «всё на месте»."""
    app = _app()
    start = app.index("function renderMissing(")
    block = app[start : app.index(chr(10) + "function openDecisionBrief(", start)]

    assert "block.hidden = !items.length" in block


def test_missing_route_shows_where_to_get_the_document() -> None:
    """Маршрут добора без адреса — это снова «контекста нет» без выхода (G-1)."""
    app = _app()
    start = app.index("function renderMissing(")
    block = app[start : app.index(chr(10) + "function openDecisionBrief(", start)]

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

    assert "verdict: {" in app
    assert "missing: {" in app


def test_verdict_help_names_the_third_outcome() -> None:
    """Неопределённый вердикт — ответ продукта, а не несработавшая кнопка.

    Не объяснив третий исход, окно оставляет аналитика с догадкой, что расчёт не прошёл.
    """
    app = _app()
    start = app.index("  verdict: {")
    text = app[start : app.index(chr(10) + "  },", start)]

    assert "неопределённое" in text
    assert "не отказ" in text


def test_verdict_badge_stands_alone_in_the_line() -> None:
    """Оценка обоснованности убрана из строки вердикта вместе с разложением."""
    index = _index()
    start = index.index('class="verdict-line"')
    line = index[start : index.index("</div>", start)]

    assert 'id="verdictBadge"' in line
    for removed in ('id="confidenceGrade"', 'id="confidenceScore"', 'id="confidenceComponents"'):
        assert removed not in index, removed


def test_styles_define_verdict_classes() -> None:
    styles = _STYLES.read_text(encoding="utf-8")

    for selector in (".verdict.undet", ".verdict.leg", ".verdict.illeg", ".missing-block"):
        assert selector in styles, selector


def test_verdict_block_declares_no_active_control() -> None:
    """Граница продукта: в блоке нет кнопок исполнения мер."""
    index = _index()
    start = index.index('class="block confidence-block"')
    block = index[start : index.index('id="missingBlock"')]

    for word in ("Изолировать", "Заблокировать", "Выполнить", "Отправить"):
        assert word not in block, word
