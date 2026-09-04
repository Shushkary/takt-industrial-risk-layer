"""Модальное окно «Конфиг» в АРМ: правка весов оценки риска.

АРМ живёт без сборщика SPA, поэтому проверяется то, что проверяемо статически и что ломается
незаметно: кнопка без обработчика, действие без ограничения по роли, форма, считающая
показатель за продукт.

Главное, что здесь закреплено: **окно не заводит второго набора весов**. Оно читает и пишет
тот же `config/risk_weights.yaml` через маршруты продукта, роль проверяет продукт, а сумма
весов в форме — подсказка, а не собственная проверка вместо продуктовой.
"""

from __future__ import annotations

from pathlib import Path

_ARM = Path(__file__).resolve().parents[1] / "frontend" / "takt-pt-arm"
_INDEX = (_ARM / "index.html").read_text(encoding="utf-8")
_APP = (_ARM / "app.js").read_text(encoding="utf-8")
_STYLES = (_ARM / "styles.css").read_text(encoding="utf-8")


def test_config_button_is_in_the_header() -> None:
    """Настройка продукта не принадлежит ни одному делу — значит, шапке, а не карточке."""
    assert 'id="configOpen"' in _INDEX
    assert "$('#configOpen').addEventListener('click', openRiskWeightsConfig)" in _APP


def test_config_button_is_shown_only_to_the_administrator() -> None:
    """Недоступное роли действие скрывается, а не отвечает отказом после нажатия."""
    start = _APP.index("function applyPermissions(")
    block = _APP[start : _APP.index("\n}", start)]

    assert "permissions().administration" in block
    assert "$('#configOpen').hidden" in block
    assert "$('#configHelp').hidden" in block


def test_form_reads_and_writes_the_product_route() -> None:
    """Тот же файл конфигурации, что правится на сервере, а не копия набора в браузере."""
    start = _APP.index("async function openRiskWeightsConfig(")
    block = _APP[start : _APP.index("\nfunction openAccessKeyForm(", start)]

    assert "api('/config/risk-weights')" in block
    assert "method: 'PUT'" in block
    assert "'/config/risk-weights'" in block


def test_reason_is_required_before_writing() -> None:
    """Причина уходит в журнал вместе с версией: без неё правка не объяснена ничем."""
    start = _APP.index("async function openRiskWeightsConfig(")
    block = _APP[start : _APP.index("\nfunction openAccessKeyForm(", start)]

    assert "Причина обязательна" in block
    assert block.index("Причина обязательна") < block.index("method: 'PUT'")


def test_sum_of_weights_is_shown_before_the_answer() -> None:
    """Иначе несбалансированный набор выясняется только отказом, и непонятно, что править."""
    start = _APP.index("async function openRiskWeightsConfig(")
    block = _APP[start : _APP.index("\nfunction openAccessKeyForm(", start)]

    assert "Сумма весов" in block
    assert "должна равняться 1.000" in block


def test_window_says_that_collected_cases_are_not_recomputed() -> None:
    """Новый набор действует на последующие дела: молчание об этом читалось бы как пересчёт."""
    start = _APP.index("async function openRiskWeightsConfig(")
    block = _APP[start : _APP.index("\nfunction openAccessKeyForm(", start)]

    assert "не пересчитываются" in block


def test_help_entry_explains_the_version_and_the_sum() -> None:
    """Два продуктовых обещания: сумма равна единице, версия поднимается при каждой записи."""
    start = _APP.index("  risk_weights: {")
    entry = _APP[start : _APP.index(chr(10) + "  },", start)]

    assert "risk_weights.yaml" in entry
    assert "единице" in entry
    assert "версия" in entry.lower()


def test_form_layout_is_declared() -> None:
    assert ".modal-body .config-grid" in _STYLES
