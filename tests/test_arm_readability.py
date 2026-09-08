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


# --- Раскладка, замеченная на живом стенде ---------------------------------


def test_queue_title_shows_that_it_continues() -> None:
    """Код обрывался на середине слова без знака продолжения и читался как полное значение."""
    rule = re.search(r"\.queue-title \{(.*?)\}", _STYLES, re.DOTALL)
    assert rule is not None
    assert "line-clamp: 2" in rule.group(1)
    assert "overflow: hidden" in rule.group(1)


def test_chain_header_stays_visible_while_scrolling() -> None:
    """Таблица прокручивается внутри рамки: без закреплённой шапки колонки без подписей."""
    rule = re.search(r"table\.chain thead th \{(.*?)\}", _STYLES, re.DOTALL)
    assert rule is not None, "шапка цепочки не закреплена"
    assert "position: sticky" in rule.group(1)
    assert "background: var(--panel)" in rule.group(1), "прозрачная шапка наложится на строки"


def test_four_metrics_fit_one_row() -> None:
    """Четвёртая плитка уходила на свою строку — ряд читался как «три и одна»."""
    rule = re.search(r"\.metrics \{(.*?)\}", _STYLES, re.DOTALL)
    assert rule is not None
    assert "minmax(132px" in rule.group(1)


def test_settings_window_is_reachable_for_every_role() -> None:
    """Порог сборки — настройка рабочего места: скрытая кнопка оставила бы окно недостижимым.

    Прецедент: после переноса прав кнопка осталась с атрибутом `hidden` в разметке, показывать
    её стало некому, и на стенде без настроенной аутентификации настройки были недоступны
    вообще никому.
    """
    button = re.search(r"<button id=\"configOpen\"[^>]*>", _INDEX)
    assert button is not None, "кнопки настроек нет в шапке"
    assert "hidden" not in button.group(0), "кнопка настроек скрыта разметкой"

    start = _APP.index("function applyPermissions(")
    block = _APP[start : _APP.index(chr(10) + "}", start)]
    assert "$('#configOpen').hidden" not in block, "видимость кнопки снова решается ролью"


def test_header_wraps_instead_of_stretching_the_page() -> None:
    """Прецедент: группы сделали строку состояния неразрывной.

    Пока элементов было одиннадцать по отдельности, строка сжималась между любыми двумя.
    После разбивки на группы она перестала переноситься и на 900 px растянула страницу до
    1475 px — рабочее место возилось по горизонтали.
    """
    rule = re.search(r"\.top-state \{(.*?)\}", _STYLES, re.DOTALL)
    assert rule is not None
    assert "flex-wrap: wrap" in rule.group(1), "строка состояния не переносится"

    group = re.search(r"\.top-group \{(.*?)\}", _STYLES, re.DOTALL)
    assert group is not None
    assert "flex-wrap: wrap" in group.group(1)


def test_no_invariant_label_is_left_in_the_window() -> None:
    """Проверка на стенде нашла два: сводка симуляции и карточка шага цепочки.

    Термин переименован в видимом тексте целиком, иначе одна вкладка говорит «правила», а
    соседняя — «инварианты», и аналитик считает их разными вещами. Комментарии кода не в счёт:
    там остаётся язык домена.
    """
    # Записи, где термин продукта назван намеренно: словарь понятий, пояснение о правилах и
    # путь к каталогу правил в файловой системе.
    allowed = ("config/invariants", "называется инвариантом", "называется Инвариант")

    left = []
    for number, line in enumerate(_APP.split("\n"), 1):
        if re.match(r"^\s*(//|\*)", line):
            continue
        for quoted in re.findall(r"'[^'\n]*'", line):
            if "нвариант" in quoted and not any(mark in quoted for mark in allowed):
                left.append(f"{number}: {quoted[:70]}")

    assert not left, "в окне остался термин «инвариант»: " + "; ".join(left)


def test_effort_counters_show_the_total_before_the_player_is_touched() -> None:
    """Два нуля рядом с «сокращение 98.7%» читались как несчитавшийся показатель.

    Счётчики накопительные и идут за курсором плеера, но при открытии вкладки курсор стоит на
    нуле, и блок «Трудоёмкость разбора» показывал 0 и 0 при 75 действиях в таблице ниже.
    Заголовок блока обещает трудоёмкость разбора инцидента, а не отрезка воспроизведения.
    """
    start = _APP.index("function updateCounters(")
    block = _APP[start : _APP.index(chr(10) + "}", start)]

    assert "const atRest = simCursor <= 0" in block
    assert "alongPlayer(effort.current_actions)" in block
    assert "alongPlayer(effort.takt_actions)" in block
    # Ход за плеером сохраняется: это по-прежнему накопительные счётчики.
    assert "cumulative(total || 0, steps, simCursor)" in block


# --- Работа за смену -------------------------------------------------------


def test_decision_bar_stays_visible_while_scrolling() -> None:
    """Экран расследования — тринадцать блоков: вердикт уходит с экрана первым.

    К «Вариантам реагирования» аналитик уже не видел, какой вердикт он обосновывает.
    """
    assert 'id="caseBar"' in _INDEX
    rule = re.search(r"\.case-bar \{(.*?)\}", _STYLES, re.DOTALL)
    assert rule is not None
    assert "position: sticky" in rule.group(1)
    # `overflow: hidden` на панели сделал бы её контейнером прокрутки, и полоса не липла бы.
    panel = re.findall(r"\n\.panel \{(.*?)\}", _STYLES, re.DOTALL)
    assert panel, "правило .panel не найдено"
    assert any("overflow: clip" in block for block in panel)


def test_decision_buttons_reuse_the_domain_transitions() -> None:
    """Свой список статусов предлагал бы переходы, которые домен отклонит."""
    start = _APP.index("function openDecision(")
    block = _APP[start : _APP.index("\n}", start)]
    assert "openStatusForm()" in block

    bar = _APP[_APP.index("function renderCaseBar(") : _APP.index("\n// Блоки, которые")]
    # Кнопки строятся по переходам домена, а не по списку статусов, записанному в окне:
    # свой список предлагал бы тупиковые варианты и завёл бы второй словарь статусов.
    assert "for (const code of currentCaseTransitions)" in bar
    assert "term('case_status', code)" in bar


def test_empty_blocks_collapse_but_the_answer_stays_open() -> None:
    """Половина из тринадцати блоков пуста, и заголовки занимали столько же места."""
    assert "function refreshBlockCollapse(" in _APP
    assert "ALWAYS_OPEN_BLOCKS" in _APP
    start = _APP.index("const ALWAYS_OPEN_BLOCKS")
    line = _APP[start : start + 200]
    for title in ("Вердикт", "Чего не хватает", "Цепочка событий"):
        assert title in line, f"блок «{title}» может свернуться сам"


def test_queue_says_when_an_event_is_already_covered_by_another_incident() -> None:
    """Одно событие давало две записи очереди, и вторая выглядела нетронутой.

    Признак приходит сводкой очереди (`coverage`, `covered_by_case_id`): считать покрытие
    по загруженной сотне строк в браузере запрещено — оно вышло бы неполным.
    """
    assert "function queueCoveredButton(" in _APP
    block = _APP[_APP.index("function queueCoveredButton(") :]
    block = block[: block.index(chr(10) + "}" + chr(10))]
    assert "item.covered_by_case_id" in block, "признак берётся у продукта"
    assert "term('case_coverage'" in block, "название покрытия — из словаря продукта"
    assert "term('case_status', item.covered_by_status)" in block
    # По метке открывается разобранный инцидент, а не текущее дело.
    assert "openCase(coveredBy" in block
    # Частичное покрытие без чисел ничего не говорит.
    assert "item.coverage === 'partial'" in block

    # Признак входит в подпись очереди, иначе метка появится неизвестно когда.
    signature = _APP[_APP.index("function queueSignature(") :]
    assert "covered_by_case_id" in signature[: signature.index(chr(10) + "}" + chr(10))]

    # Сведённая строка называет, сколько её дел уже разобрано.
    groups = _APP[_APP.index("function renderGroups(") :]
    assert "group.covered_cases" in groups[: groups.index(chr(10) + "}" + chr(10))]


def test_queue_can_be_paged_past_the_first_hundred() -> None:
    """«Показано 100 из 500» было честным, но тупиковым: остальные доставались только фильтром."""
    assert 'id="queueMore"' in _INDEX
    assert "queueLimit += QUEUE_PAGE_LIMIT" in _APP
    assert "function resetQueueLimit(" in _APP
    # Смена отбора возвращает к первой странице, иначе окно тянет страницы под прежний набор.
    assert "refreshFromFirstPage" in _APP


def test_keyboard_walks_the_queue() -> None:
    """Разбор очереди — самый частый жест за смену, и он был весь мышью."""
    start = _APP.index("// --- Клавиатура ---")
    block = _APP[start : _APP.index("// --- Полоса решения", start)]

    assert "ArrowDown" in block and "ArrowUp" in block
    assert "QUEUE_STEP_DELAY_MS" in block, "удержанная стрелка слала бы запрос на каждый шаг"
    assert "keyboardIsBusy" in block, "«/» в поле поиска — символ, а не команда"


def test_queue_holds_one_keyboard_stop() -> None:
    """Сотня загруженных строк была сотней остановок Tab на пути из очереди.

    Замер: при показанных 100 из 518 строк выход из списка стоил 100 нажатий. Внутри списка
    строки достаются стрелками, поэтому остановка Tab нужна одна — на выбранной строке, а до
    выбора на первой.
    """
    start = _APP.index("function renderQueue(")
    block = _APP[start : _APP.index("\nfunction setQueueTabStop(", start)]
    assert "button.tabIndex = -1" in block, "каждая строка очереди снова стала остановкой Tab"
    assert "setQueueTabStop(" in block

    assert "function setQueueTabStop(" in _APP
    stop = _APP[_APP.index("function setQueueTabStop(") :]
    stop = stop[: stop.index("\n}\n")]
    # Обход гасится целиком, потом поднимается одна запись: и строка, и её метка покрытия.
    assert "item.tabIndex = -1;" in stop
    assert "button.tabIndex = 0;" in stop
    assert ".queue-covered" in stop, "метки покрытия остальных строк вернулись в обход Tab"

    # Стрелка ведёт остановку за собой, иначе обратный Tab вернёт к прежней строке.
    move = _APP[_APP.index("function moveQueueSelection(") :]
    assert "setQueueTabStop(button)" in move[: move.index("\n}\n")]

    # Выбор кейса без перестройки списка тоже переносит остановку.
    active = _APP[_APP.index("function updateActiveQueueItem(") :]
    assert "setQueueTabStop(" in active[: active.index("\n}\n")]


def test_keyboard_leaves_the_queue_for_the_investigation() -> None:
    """Из очереди в область расследования быстрого перехода не было вовсе."""
    assert 'id="skipToWork"' in _INDEX, "ссылка «К расследованию» перед очередью"
    assert ".skip-to-work" in _STYLES
    # Цель перевода фокуса должна его принимать: заголовок и пустое состояние сами не фокусируемы.
    assert 'id="caseTitle" class="case-title" tabindex="-1"' in _INDEX
    assert 'id="workEmpty" class="muted pad" tabindex="-1"' in _INDEX

    assert "function focusInvestigation(" in _APP
    assert "$('#skipToWork').addEventListener('click', focusInvestigation);" in _APP

    # Enter открывает инцидент и уводит фокус в карточку; стрелка — нет, она листает список.
    start = _APP.index("// --- Клавиатура ---")
    block = _APP[start : _APP.index("// --- Полоса решения", start)]
    assert "openCase(focused.dataset.caseId, { moveFocus: true })" in block
    assert "openCase(caseId), QUEUE_STEP_DELAY_MS" in block, "стрелка не должна забирать фокус"


def test_saved_decision_leaves_a_predictable_focus() -> None:
    """Кнопка «Сохранить» уходит с экрана вместе с формой, и фокус падал на документ."""
    start = _APP.index("async function submitStatusForm(")
    block = _APP[start : _APP.index("\n}\n", start)]
    assert "openCase(selectedCaseId, { moveFocus: true })" in block


def test_journal_shows_the_reason_behind_a_decision() -> None:
    """Причина смены статуса уходила в продукт и не возвращалась на экран.

    Замер: у закрытого инцидента в API одна причина, в журнале АРМ — ноль. Журнал показывал
    «status -> CONFIRMED», и основание приходилось добирать документом или через коллегу.
    """
    assert 'id="decisionRecords"' in _INDEX
    assert 'id="decisionRecordsList"' in _INDEX
    assert "function renderDecisionRecords(" in _APP

    start = _APP.index("function renderDecisionRecords(")
    block = _APP[start : _APP.index("\n}\n", start)]
    # Время, автор, переход и причина: без причины блок повторял бы журнал.
    assert "record.reason" in block
    assert "record.prev_status" in block and "record.next_status" in block
    assert "term('case_status'" in block
    assert "record.actor" in block

    # Карточка передаёт состав решений продукта, а не собирает его из текста журнала.
    case = _APP[_APP.index("function renderCase(") :]
    case = case[: case.index("\n}\n")]
    assert "renderDecisionRecords(item.decision_records || [])" in case

    # Строка журнала остаётся дословной: соответствие решению по тексту не угадывается.
    journal = _APP[_APP.index("function renderJournal(") :]
    journal = journal[: journal.index("\n}\n")]
    assert "decision" not in journal.lower()


def test_bulk_decision_reads_the_selection_from_the_product() -> None:
    """Размечать «то, что видно» значило бы размечать случайный срез дозагруженной очереди."""
    start = _APP.index("async function submitBulkDecision(")
    block = _APP[start : _APP.index("\n}\n", start)]

    assert "queueQueryString()" in block
    assert "BULK_DECISION_MAX" in block
    # Решение по каждому инциденту — отдельная запись журнала со своей причиной.
    assert "/decision" in block
    assert "failures" in block, "отказ по одному инциденту должен быть назван"


def test_narrow_layout_does_not_stretch_the_whole_page() -> None:
    """Окно 768 px давало документ 1663 px: вбок ездила вся страница, а не таблица.

    В одноколоночной раскладке `1fr` — это `minmax(auto, 1fr)`, и нижней границей колонки
    становится самое широкое содержимое строки. Таблица состава шире окна намеренно и
    прокручивается внутри своего контейнера; через `auto` она растягивала колонку, а вместе
    с ней фильтры очереди и полосу решения.
    """
    narrow = re.search(
        r"@media \(max-width: 1200px\) \{.*?\.layout \{\s*grid-template-columns: ([^;]+);",
        _STYLES,
        re.DOTALL,
    )
    assert narrow, "одноколоночного правила раскладки нет"
    assert narrow.group(1).strip() == "minmax(0, 1fr)", narrow.group(1)

    side_idle = re.search(
        r"\.layout\.side-idle \{\s*grid-template-columns: minmax\(0, 1fr\);", _STYLES
    )
    assert side_idle, "свёрнутая колонка на узком экране снова растягивает страницу"

    # Панель не должна расширяться под содержимое: прокрутка предусмотрена внутри цепочки.
    panel = re.search(r"^\.panel \{(.*?)\}", _STYLES, re.DOTALL | re.MULTILINE)
    assert panel and "min-width: 0" in panel.group(1)

    # Собственная прокрутка состава остаётся: её убирать было нельзя.
    assert ".table-scroll" in _STYLES and "overflow: auto" in _STYLES


def test_side_column_gives_its_width_back_when_empty() -> None:
    """Треть ширины экрана простаивала под две строки «нет»."""
    assert "function refreshSideColumn(" in _APP
    assert ".layout.side-idle" in _STYLES


def test_new_incidents_are_marked() -> None:
    """Очередь опрашивается раз в 15 с, и вернувшийся к экрану не знал, что прибыло."""
    assert "function markFreshCases(" in _APP
    assert "queueFreshIds" in _APP
    assert "fresh-dot" in _INDEX or "fresh-dot" in _APP
    # Открытый инцидент перестаёт быть новостью.
    start = _APP.index("async function openCase(")
    assert "queueFreshIds.delete(caseId)" in _APP[start : start + 300]


def test_entity_card_says_how_the_entity_was_marked_before() -> None:
    """«Этот адрес трижды признавали штатным» — самый дешёвый способ закрыть инцидент."""
    assert "function renderEntityDecisions(" in _APP
    start = _APP.index("function renderEntityDecisions(")
    block = _APP[start : _APP.index("\n}", start)]
    assert "статус известен у" in block, "неполнота выборки должна быть названа"


def test_effort_caveats_are_shown_next_to_the_numbers() -> None:
    """Продукт возвращает оговорки в том же ответе, что и числа, а окно показывало только числа.

    Отдельно называется то, чего в счётчиках не видно: числитель соотношения измерен по
    журналу, а знаменатель посчитан моделью.
    """
    assert 'id="effortCaveats"' in _INDEX
    start = _APP.index("function renderEffortCaveats(")
    block = _APP[start : _APP.index("\n}", start)]

    assert "effort.caveats" in block
    assert "current_actions_measured" in block and "takt_actions_measured" in block
