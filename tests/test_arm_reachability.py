"""Достижимость возможностей продукта из основного интерфейса АРМ.

Замечание, с которого начата работа: карточки сущностей продукт отдаёт для `host`, `user` и
`process`, а кликабельны в интерфейсе были только узел и учётная запись. Тот же разрыв нашёлся
у сборки инцидентов: загрузка датасета выполняет её сама, а событиям, принятым через API,
запустить её из интерфейса было нечем. Возможность, до которой аналитик не может дотянуться,
для него не существует, и молчит такой разрыв тише всего остального.

Проверяется статически то, что ломается незаметно: пропавшая колонка, кнопка без обработчика,
действие без ограничения по роли, разъехавшиеся доли колонок. Поведение проверяется прогоном
в браузере, эти тесты его не подменяют.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ARM = Path(__file__).resolve().parents[1] / "frontend" / "takt-pt-arm"
_INDEX = (_ARM / "index.html").read_text(encoding="utf-8")
_APP = (_ARM / "app.js").read_text(encoding="utf-8")
_STYLES = (_ARM / "styles.css").read_text(encoding="utf-8")

# Виды сущностей, для которых продукт отдаёт карточку истории.
CARD_TYPES = ("host", "user", "process")

# Колонки таблицы состава дела и таблицы поиска — по девять в каждой.
CHAIN_COLUMNS = 9


@pytest.mark.parametrize("entity_type", CARD_TYPES)
def test_backend_card_type_is_reachable_from_the_chain_table(entity_type: str) -> None:
    """Каждый вид карточки открывается кнопкой в таблице состава дела."""
    assert f"entityButton('{entity_type}'" in _APP, entity_type


def test_process_column_exists_in_both_tables() -> None:
    """Колонка процесса есть и в составе дела, и в результатах поиска."""
    assert _INDEX.count(">Процесс ") + _INDEX.count(">Процесс<") >= 2


def test_process_column_has_a_help_entry() -> None:
    assert 'data-help="entity_process"' in _INDEX
    assert re.search(r"^  entity_process: \{$", _APP, re.MULTILINE)


def test_search_results_show_the_process_of_the_event() -> None:
    """Фильтр по процессу в поиске был, а самого значения в выдаче не было."""
    assert "put('process_id', '#searchProcess')" in _APP
    assert "copyable(entities.process_id" in _APP


@pytest.mark.parametrize("table", ["chain-case", "chain-search"])
def test_column_widths_cover_every_column(table: str) -> None:
    """Доли покрывают все девять колонок и дают в сумме 100%.

    Колонка без доли схлопывается в ноль: при `table-layout: fixed` браузер не возвращает ей
    место по содержимому. Так и произошло с «Артефактом», когда доли считались от начала ряда,
    а слева появлялась необязательная колонка отметки события.
    """
    widths = re.findall(rf"table\.{table} th:nth-(?:last-)?child\(\d+\).*?width: (\d+)%", _STYLES)
    assert len(widths) == CHAIN_COLUMNS, f"{table}: доли заданы для {len(widths)} колонок"
    assert sum(int(value) for value in widths) == 100, f"{table}: сумма долей {widths}"


def test_case_table_counts_columns_from_the_end() -> None:
    """У таблицы состава дела слева необязательная колонка — счёт только от конца ряда."""
    assert "table.chain-case th:nth-last-child(" in _STYLES
    assert "table.chain-case th:nth-child(" not in _STYLES


def test_relink_column_keeps_its_own_width() -> None:
    assert "table.chain th.relink-cell, table.chain td.relink-cell { width: 28px; }" in _STYLES


# --------------------------------------------------------------------------- #
# Сборка инцидентов
# --------------------------------------------------------------------------- #

def test_assembly_can_be_started_from_the_queue() -> None:
    """События, принятые через API, тоже должны собираться — без возврата в консоль.

    Загрузка датасета выполняет шаг сама, но приём через `POST /events` этого не делает, и без
    кнопки аналитик оставался с лентой мелких дел и без способа что-либо с ней сделать.
    """
    assert 'id="assembleAuto"' in _INDEX
    assert "'/cases/assemble/auto'" in _APP
    assert "$('#assembleAuto').addEventListener('click', runAutoAssembly);" in _APP


def test_assembly_is_hidden_from_a_read_only_role() -> None:
    """Недоступное роли действие скрывается, а не отказывает после нажатия."""
    assert "$('#assembleAuto').hidden = !canWrite;" in _APP
    assert "$('#assembleRoleNote').hidden = canWrite;" in _APP


def test_assembly_has_a_help_entry() -> None:
    assert 'data-help="assemble_auto"' in _INDEX
    assert re.search(r"^  assemble_auto: \{$", _APP, re.MULTILINE)
