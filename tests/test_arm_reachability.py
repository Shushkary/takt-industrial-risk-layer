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

# Конец функции в исходнике АРМ: закрывающая скобка на нулевом отступе. По ней вырезается
# тело проверяемой функции — искать по номеру строки нельзя, он уедет с первой же правкой.
SIG = "\n}\n"

# Виды сущностей, для которых продукт отдаёт карточку истории.
CARD_TYPES = ("host", "user", "process")

# Колонки таблицы состава дела.
CHAIN_COLUMNS = 9


@pytest.mark.parametrize("entity_type", CARD_TYPES)
def test_backend_card_type_is_reachable_from_the_chain_table(entity_type: str) -> None:
    """Каждый вид карточки открывается кнопкой в таблице состава дела."""
    assert f"entityButton('{entity_type}'" in _APP, entity_type


def test_process_column_exists_in_the_chain_table() -> None:
    """Колонка процесса есть в составе дела: без неё карточка процесса недостижима."""
    assert _INDEX.count(">Процесс ") + _INDEX.count(">Процесс<") >= 1


def test_process_column_has_a_help_entry() -> None:
    assert 'data-help="entity_process"' in _INDEX
    assert re.search(r"^  entity_process: \{$", _APP, re.MULTILINE)


@pytest.mark.parametrize("table", ["chain-case"])
def test_column_widths_cover_every_column(table: str) -> None:
    """Ширина задана всем девяти колонкам.

    Колонка без ширины схлопывается в ноль: при `table-layout: fixed` браузер не возвращает ей
    место по содержимому. Так и произошло с «Артефактом», когда доли считались от начала ряда,
    а слева появлялась необязательная колонка отметки события.
    """
    widths = re.findall(
        rf"table\.{table} th:nth-(?:last-)?child\(\d+\).*?width: (\d+)(%|ch)", _STYLES
    )
    assert len(widths) == CHAIN_COLUMNS, f"{table}: ширина задана для {len(widths)} колонок"


def test_every_chain_column_is_measured_in_characters() -> None:
    """Ширина колонки не может зависеть от того, какой шрифт подставит браузер.

    Доля в процентах этого не даёт: ширина знака зависит от шрифта, и на одной и той же доле
    значение то помещается, то теряет хвост. С метки времени это и началось — в разных
    браузерах у неё пропадали секунды. `min-width` тоже не помогает: при `table-layout: fixed`
    браузер берёт ширины из первой строки и ограничение на ячейке не применяет.

    Секунды в метке — не деталь оформления: по ним читается порядок событий внутри минуты.
    """
    pattern = (
        r"table\.chain-case th:nth-last-child\((\d)\), "
        r"table\.chain-case td:nth-last-child\(\d\) \{ width: (\d+)ch"
    )
    widths = re.findall(pattern, _STYLES)
    assert len(widths) == CHAIN_COLUMNS, f"в знаках заданы {len(widths)} колонок из {CHAIN_COLUMNS}"

    leftover = (
        r"table\.chain-case th:nth-last-child\(\d\), "
        r"table\.chain-case td:nth-last-child\(\d\) \{ width: \d+%"
    )
    assert not re.search(leftover, _STYLES), "осталась колонка, заданная долей таблицы"


def test_chain_table_grows_past_its_frame_instead_of_squeezing_columns() -> None:
    """Девять колонок с длинными значениями в ширину рабочей колонки не помещаются.

    При `width: 100%` фиксированная раскладка растянула бы колонки по рамке, и заданные знаки
    перестали бы что-либо значить. Таблица растёт под сумму колонок и прокручивается вбок
    внутри своей рамки — прокрутка честнее молчаливого усечения.
    """
    rule = re.search(r"\ntable\.chain \{(.*?)\}", _STYLES, re.DOTALL)
    assert rule is not None
    assert "width: max-content" in rule.group(1)
    assert "min-width: 100%" in rule.group(1)

    frame = re.search(r"\.table-scroll \{(.*?)\}", _STYLES, re.DOTALL)
    assert frame is not None
    assert "overflow: auto" in frame.group(1), "рамке нечем прокручивать таблицу"



def test_series_row_shows_the_whole_time_range() -> None:
    """Урезать диапазон до начала значило бы скрыть, сколько серия длилась."""
    assert re.search(
        r"table\.chain-case tr\.row-series td:nth-last-child\(9\) \{\s*white-space: normal;",
        _STYLES,
    ), "диапазон в строке серии не переносится и обрезается"


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


# --------------------------------------------------------------------------- #
# Расширение до узла (второй шаг сборки пивотом)
# --------------------------------------------------------------------------- #

def test_host_expansion_can_be_started_from_the_case_panel() -> None:
    """`POST /cases/assemble/pivot` умеет `expand_hosts` давно, кнопки не было.

    Второй шаг разбора — расширение ядра до уровня узла — был задокументирован
    (`docs/pt_techlab/analyst_window.md`) и вызывался только утилитой командной строки:
    аналитик, собравший инцидент через АРМ, не мог его выполнить, не уходя в консоль.
    """
    assert 'id="expandBlock"' in _INDEX
    assert 'id="expandHostList"' in _INDEX
    assert "'/cases/assemble/pivot'" in _APP
    assert "$('#expandHostsButton').addEventListener('click', runExpandToHosts);" in _APP


def test_host_expansion_reads_seeds_from_pivot_seed_artifacts() -> None:
    """Сиды для повторной сборки берутся из уже сохранённых артефактов дела.

    Не набираются заново и не хранятся отдельно от продукта: `case.artifacts` с
    `source === 'pivot-seed'` — тот же список, что показывает пакет реагирования.
    """
    assert "item.source === 'pivot-seed'" in _APP
    assert "`${item.type}:${item.value}`" in _APP


def test_host_expansion_hides_for_a_pipeline_case_without_seeds() -> None:
    """Дело конвейера расширять до узла нечего: узел уже и есть его ключ группировки."""
    assert "block.hidden = true;" in _APP
    assert "if (!seeds.length) {" in _APP


def test_host_expansion_is_hidden_from_a_read_only_role() -> None:
    assert "$('#expandHostsButton').hidden = !canWrite;" in _APP
    assert "$('#expandHostsRoleNote').hidden = canWrite;" in _APP


def test_host_expansion_has_a_help_entry() -> None:
    assert 'data-help="expand_hosts"' in _INDEX
    assert re.search(r"^  expand_hosts: \{$", _APP, re.MULTILINE)


# --------------------------------------------------------------------------- #
# Порог отличительности — параметр, а не спрятанная константа
# --------------------------------------------------------------------------- #

def test_assembly_threshold_is_adjustable_from_the_queue() -> None:
    """Значение по умолчанию (12) откалибровано на одном корпусе и не универсально:

    на независимой проверке (`tests/test_auto_assemble_incidents_ext001.py`, реальная
    внешняя цепочка EXT-001) тот же порог не связывает вообще ничего. Аналитик, у которого
    свой поток ведёт себя иначе, должен иметь возможность подставить своё число, не уходя
    в конфигурацию или командную строку.
    """
    assert 'id="assembleThreshold"' in _INDEX
    assert "distinctive_max_events: Number(thresholdRaw)" in _APP


def test_assembly_threshold_has_a_help_entry_stating_the_trade_off() -> None:
    assert 'data-help="assemble_threshold"' in _INDEX
    assert re.search(r"^  assemble_threshold: \{$", _APP, re.MULTILINE)
# --------------------------------------------------------------------------- #
# Контекст сущности: полученная история и её сохранение между записями
# --------------------------------------------------------------------------- #

def test_entity_history_is_reachable_past_the_tenth_record() -> None:
    """История узла обрывалась на десятой записи молча.

    У `eng-ws-04` карточка писала «Событий всего 18», окружение показывало последние десять,
    кнопки продолжения не было. Восемь недостающих событий уже пришли ответом продукта —
    ограничение стояло в срезе на стороне АРМ.
    """
    assert 'id="entityEnvironmentMore"' in _INDEX, "кнопки продолжения истории нет"
    assert 'id="entityEnvironmentCount"' in _INDEX, "«Показано 10 из 18» не показывается"
    assert "function renderEntityEnvironment(" in _APP

    block = _APP[_APP.index("function renderEntityEnvironment(") :]
    block = block[: block.index("\n}\n")]
    assert "Показано ${shown} из ${received}" in block
    assert "Показать ещё ${rest}" in block
    # Разворачивается уже полученный массив: срез на десяти как предел показа исчез.
    assert ".slice(0, 10)" not in _APP[_APP.index("async function openEntity(") :]


def test_entity_history_names_the_request_limit_instead_of_faking_pages() -> None:
    """За серверным пределом навигация не имитируется, предел называется.

    API отдаёт до `event_limit` записей и общее число отдельно. Когда история в предел
    упёрлась, окно говорит это прямо, а не показывает кнопку, за которой ничего нет.
    """
    assert "ENTITY_EVENT_LIMIT" in _APP
    assert "event_limit=${ENTITY_EVENT_LIMIT}" in _APP, "предел запроса задаётся явно"
    block = _APP[_APP.index("function renderEntityEnvironment(") :]
    block = block[: block.index("\n}\n")]
    assert "entityEnvironmentTotal" in block
    assert "за пределом запроса" in block


def test_writing_a_finding_keeps_the_entity_open() -> None:
    """Запись находки сбрасывала карточку сущности: продолжение разбора стоило открытия заново.

    `addFinding` перечитывает тот же инцидент, а `openCase` очищал панель сущности всегда —
    и при переходе к другому делу, и при перечитывании текущего.
    """
    start = _APP.index("async function openCase(")
    block = _APP[start : _APP.index("\n}\n", start)]
    assert "const switching = caseId !== selectedCaseId;" in block
    assert "if (switching) resetEntityPanel();" in block, "контекст сбрасывается не только при смене дела"
    # Состав дела пересобран — отметка выбранной сущности в цепочке восстанавливается.
    assert "if (!switching) restoreEntityHighlight();" in block
    assert "function restoreEntityHighlight(" in _APP
# --------------------------------------------------------------------------- #
# Поиск кандидатов на присоединение: полнота выдачи и раскрытые фильтры
# --------------------------------------------------------------------------- #

def test_case_events_are_excluded_by_the_product_not_by_the_browser() -> None:
    """При 51 совпадении, первые 50 из которых в деле, окно отвечало «не нашлось».

    Страница из 50 записей читалась целиком, а события дела отсеивались уже в браузере —
    единственный кандидат за пределами страницы терялся вместе с ней.
    """
    start = _APP.index("async function loadAttachPage(")
    block = _APP[start : _APP.index(SIG, start)]
    assert "exclude_case_id" in block, "исключение состава дела снова считает браузер"
    # Полное число кандидатов приходит заголовком продукта, а не длиной страницы.
    assert "X-Total-Count" in block
    assert "Показано ${attachShown} из ${attachTotal}" in block
    assert 'id="attachMore"' in _INDEX, "за первой страницей кандидатов нет продолжения"

    # Отсев по составу рабочей области ушёл: он и был причиной потери кандидата.
    search = _APP[_APP.index("async function runAttachSearch(") :]
    search = search[: search.index(SIG)]
    assert "lastWorkspaceEvents" not in search


def test_indicator_is_searched_as_a_type_and_value_pair() -> None:
    """`domain=target-hash` находило событие, где target-hash имеет тип hash.

    Тип и значение должны уходить продукту вместе и относиться к одному артефакту.
    """
    start = _APP.index("function attachSearchParams(")
    block = _APP[start : _APP.index(SIG, start)]
    assert "params.set('artifact_type', type)" in block
    assert "params.set('artifact_value', artifactValue)" in block

    # Индикаторы дела предлагаются списком: значение не переносится руками.
    options = _APP[_APP.index("function caseEntityOptions(") :]
    options = options[: options.index(SIG)]
    assert "event.artifacts" in options
    assert "term('artifact_type'" in options


def test_search_filters_of_the_product_are_reachable_from_the_window() -> None:
    """API принимал источник, время и процесс; дотянуться до них из окна было нечем."""
    for marker in ('id="attachSource"', 'id="attachFrom"', 'id="attachTo"'):
        assert marker in _INDEX, marker

    start = _APP.index("function attachSearchParams(")
    block = _APP[start : _APP.index(SIG, start)]
    for parameter in ("source", "observed_from", "observed_to"):
        assert f"params.set('{parameter}'" in block, parameter

    # Процесс дела попадает в список отбора: раньше его там не было вовсе.
    options = _APP[_APP.index("function caseEntityOptions(") :]
    options = options[: options.index(SIG)]
    assert "process_id" in options

    # Классы источников берутся из словаря продукта, а не из своего списка в окне.
    panel = _APP[_APP.index("function openAttachPanel(") :]
    panel = panel[: panel.index(SIG)]
    assert "vocabulary.event_source" in panel
# --------------------------------------------------------------------------- #
# Идентичность процесса: ключ внутри, PID на экране
# --------------------------------------------------------------------------- #

def test_process_card_opens_by_key_but_shows_the_pid() -> None:
    """Два узла с одним PID открывали одну карточку процесса на 52 события.

    Ключ сущности и показываемое значение разведены: карточка открывается по ключу
    «узел+PID» (или по идентификатору запуска), а в цепочке и в карточке остаётся PID —
    показывать аналитику внутренний ключ незачем.
    """
    button = _APP[_APP.index("function entityButton(") :]
    button = button[: button.index(SIG)]
    assert "const id = key || value;" in button
    assert "data-entity-label" in button, "показываемое значение потерялось вместе с ключом"

    assert "entityButton('process', entities.process_id, event.process_key)" in _APP
    # Ключ считает продукт и отдаёт рабочей областью: считать его в браузере значило бы
    # завести второй контракт идентичности.
    assert "process_key" in _APP

    entity = _APP[_APP.index("async function openEntity(") :]
    entity = entity[: entity.index(SIG)]
    assert "card.display_id" in entity


def test_process_card_names_the_limit_of_its_identity() -> None:
    """«Узел и PID» не различает повторные запуски — читающий должен это видеть."""
    entity = _APP[_APP.index("async function openEntity(") :]
    entity = entity[: entity.index(SIG)]
    assert "term('process_identity', card.identity)" in entity
    assert "Опознан по" in entity


def test_attach_search_filters_a_process_by_key() -> None:
    """PID одного узла не должен приводить события другого в кандидаты."""
    options = _APP[_APP.index("function caseEntityOptions(") :]
    options = options[: options.index(SIG)]
    assert "process_key:" in options
