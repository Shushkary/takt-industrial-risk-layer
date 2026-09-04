"""Читаемость рабочего места аналитика: очередь, цепочка событий, журнал.

Замечания, с которых начата работа, все про одно: окно показывало, из чего инцидент собран,
вместо того чтобы отвечать, что произошло. Очередь читалась как список кодов правил, цепочка
повторяла одно и то же событие десятками строк, половина колонок стояла пустой, а счётчик
событий выдавал отсутствие состава за ноль.

АРМ живёт без сборщика SPA, поэтому проверяется то, что проверяемо статически и что ломается
незаметно: пропавшая функция, разъехавшаяся разметка, потерянный признак колонки. Поведение
проверяется прогоном в браузере, эти тесты его не подменяют.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ARM = Path(__file__).resolve().parents[1] / "frontend" / "takt-pt-arm"
_INDEX = (_ARM / "index.html").read_text(encoding="utf-8")
_APP = (_ARM / "app.js").read_text(encoding="utf-8")
_STYLES = (_ARM / "styles.css").read_text(encoding="utf-8")


# --- Очередь ---------------------------------------------------------------


def test_queue_card_is_built_from_product_fields() -> None:
    """Класс риска и число срабатываний не повторяются в заголовке.

    Заголовок конвейера приёма выглядит как «[x35] Риск низкий: NEW_IP_ADDRESS_IN_DNS_LOGS».
    Класс риска карточка показывает отдельным полем и цветом, число в префиксе равно счётчику
    событий — слева у каждой строки очереди оказывалось одно и то же слово «Риск».
    """
    assert "function queueHeadline(" in _APP
    assert "GENERATED_TITLE" in _APP

    start = _APP.index("function renderQueue(")
    block = _APP[start : _APP.index("\nfunction ", start + 10)]
    assert "queueHeadline(item)" in block
    assert "item.primary_asset_id" in block, "актив не показан: очередь ищут по активу"
    assert "plural(count" in block, "счётчик событий без согласования числительного"


def test_generated_title_pattern_matches_the_pipeline_titles() -> None:
    """Шаблон разбирает ровно те заголовки, которые собирает продукт."""
    source = re.search(r"const GENERATED_TITLE = (/.+/);", _APP)
    assert source is not None, "шаблон заголовка не найден"
    pattern = re.compile(source.group(1)[1:-1])

    assert pattern.match("[x35] Риск низкий: NEW_IP_ADDRESS_IN_DNS_LOGS")
    assert pattern.match("Риск критический: WRITE_REGISTER")
    # Заголовок, который человек задал при сборке пивотом, разбирать нельзя: его писали.
    assert not pattern.match("Разведка с адреса 192.168.188.179 (датасет AIT)")


def test_operation_code_is_shown_as_a_code() -> None:
    """Код операции — значение из журнала источника, а не фраза: переводить его нельзя."""
    start = _APP.index("function queueHeadline(")
    block = _APP[start : _APP.index("\nlet lastQueueSignature", start)]

    assert "code: true" in block
    assert "trigger_operation" in block
    assert "queue-title${headline.code ? ' mono' : ''}" in _APP


# --- Цепочка событий -------------------------------------------------------


def test_identical_events_collapse_into_a_series() -> None:
    """Тридцать строк одного события — один факт, а не тридцать.

    Поиск шага, который отличается от соседних, глазами по всей таблице — ровно та работа,
    которую продукт берётся сократить.
    """
    assert "function chainSeriesKey(" in _APP
    assert "function chainSeriesRow(" in _APP

    start = _APP.index("function paintChain(")
    block = _APP[start : _APP.index("\n// --- Расширение разбора", start)]
    assert "chainSeriesKey(visible[index])" in block
    assert "series-toggle" in block


def test_collapsed_events_stay_in_the_table() -> None:
    """Отцепить нужно конкретное событие: серия не может подменить его собой."""
    start = _APP.index("function paintChain(")
    block = _APP[start : _APP.index("\n// --- Расширение разбора", start)]

    assert "row.hidden = true" in block, "события серии не остаются в таблице"
    assert "chainRow(item, relink, true)" in block


def test_counter_names_the_number_of_rows_when_series_are_collapsed() -> None:
    """Иначе «показано 69», а строк на экране двенадцать, и непонятно, что произошло."""
    start = _APP.index("function paintChain(")
    block = _APP[start : _APP.index("\n// --- Расширение разбора", start)]

    assert "if (rows !== shown)" in block
    assert "строк ${rows}" in block


@pytest.mark.parametrize("column", ["host", "user", "process", "address", "artifact"])
def test_optional_chain_columns_are_marked(column: str) -> None:
    """Колонка прячется по метке, а не по позиции: слева стоит необязательная колонка отметки."""
    assert f'data-col="{column}"' in _INDEX, f"нет метки у колонки {column} в шапке"
    assert f'data-col="{column}"' in _APP, f"нет метки у колонки {column} в ячейках"
    assert f'table.chain.hide-{column} [data-col="{column}"]' in _STYLES


def test_empty_columns_are_hidden() -> None:
    """У инцидента по веб-журналам пусты четыре колонки из девяти, а «Операция» усечена."""
    assert "function hideEmptyChainColumns(" in _APP
    assert "CHAIN_OPTIONAL_COLUMNS" in _APP

    start = _APP.index("function hideEmptyChainColumns(")
    block = _APP[start : _APP.index("\nfunction chainCells(", start)]
    assert "visible.length > 0" in block, "пустая цепочка спрятала бы все колонки разом"


# --- Счётчик событий -------------------------------------------------------


def test_event_count_does_not_pass_a_missing_composition_for_zero() -> None:
    """Ноль означал бы «событий нет», а карточка в очереди в тот же момент называет другое число."""
    start = _APP.index("const composition =")
    block = _APP[start : start + 500]

    assert "declared" in block
    assert "'—'" in block, "нет прочерка для случая, когда состава в ответе нет"


# --- Журнал действий -------------------------------------------------------


def test_journal_shortens_checksums_without_touching_the_wording() -> None:
    """Хеш занимал всю строку и вытеснял то, ради чего журнал читают: кто и что сделал.

    Формулировку записи интерфейс не трогает: журнал инцидента — доказательный материал, и
    часть записей продукт ищет по точному тексту (`ASSEMBLY_MARKER`, отчёт соответствия).
    """
    assert "function journalAction(" in _APP
    start = _APP.index("function journalAction(")
    block = _APP[start : _APP.index("\nfunction renderJournal(", start)]

    assert "JOURNAL_LONG_VALUE" in block
    assert "copyable(match[0]" in block, "полное значение должно копироваться"
    assert "escapeHtml(text.slice(last))" in block


def test_journal_lays_out_three_columns() -> None:
    """Взгляд идёт по автору сверху вниз, а не ищет его в середине строки."""
    rule = re.search(r"\.journal-item \{(.*?)\}", _STYLES, re.DOTALL)
    assert rule is not None
    assert "display: grid" in rule.group(1)
    assert "grid-template-columns" in rule.group(1)


# --- Шапка -----------------------------------------------------------------


def test_header_is_split_into_groups() -> None:
    """Одиннадцать кнопок одним весом читались как один список, где связь стоит рядом с настройками."""
    head = _INDEX[_INDEX.index('<div class="top-state">') : _INDEX.index("</header>")]

    assert head.count('class="top-group"') >= 2
    assert 'class="top-group top-status"' in head
    assert ".top-group + .top-group" in _STYLES, "группы ничем не разделены"


def test_product_name_does_not_wrap() -> None:
    """На 800 px блок «ТАКТ · рабочее место аналитика» ломался на три строки."""
    rule = re.search(r"\.top-title \{(.*?)\}", _STYLES, re.DOTALL)
    assert rule is not None
    assert "nowrap" in rule.group(1)
