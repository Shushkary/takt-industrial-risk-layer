"""Вкладка «Цепочка атаки» в АРМ: связность разметки, реестра пояснений и сборки.

АРМ намеренно живёт без сборщика SPA и без package.json, поэтому здесь проверяется то, что
проверяемо статически и что ломается чаще всего: кнопка пояснения без записи в реестре,
разъехавшийся параметр версии, потерянный идентификатор элемента, закоммиченные артефакты
сборки. Поведение плеера проверяется прогоном в браузере, эти тесты его не подменяют.

Реестр пояснений — единственный: `HELP` в `app.js`. Параллельного механизма подсказок быть
не должно, иначе часть окна останется без объяснений.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ARM = Path(__file__).resolve().parents[1] / "frontend" / "takt-pt-arm"
_INDEX = _ARM / "index.html"
_APP = _ARM / "app.js"
_STYLES = _ARM / "styles.css"

_HELP_ATTR = re.compile(r'data-help="([a-z0-9_]+)"')
_HELP_KEY = re.compile(r"^  ([a-z0-9_]+): \{$", re.MULTILINE)
_VERSION = re.compile(r"\?v=(\d{8}-\d{2})")


def _index() -> str:
    return _INDEX.read_text(encoding="utf-8")


def _app() -> str:
    return _APP.read_text(encoding="utf-8")


def test_every_help_button_has_a_registry_entry() -> None:
    """Кнопка «?» без записи в реестре открывала бы пустое окно."""
    used = set(_HELP_ATTR.findall(_index()))
    declared = set(_HELP_KEY.findall(_app()))
    missing = sorted(used - declared)
    assert not missing, f"нет пояснений для: {missing}"


def test_registry_has_no_unused_entries() -> None:
    """Запись без кнопки — мёртвый текст, который никто не увидит."""
    used = set(_HELP_ATTR.findall(_index()))
    declared = set(_HELP_KEY.findall(_app()))
    # `step` открывается из кода при клике по шагу цепочки, а не кнопкой в разметке.
    orphans = sorted(declared - used - {"step", "mitre"})
    assert not orphans, f"пояснения без кнопки: {orphans}"


def test_simulation_help_topics_are_present() -> None:
    """Каждый блок вкладки объяснён, включая счётчики и методику."""
    declared = set(_HELP_KEY.findall(_app()))
    required = {
        "simulation",
        "counters",
        "counter_manual",
        "counter_takt",
        "reduction",
        "effort_method",
        "player",
        "attack_graph",
        "sim_summary",
        "step",
        "seconds_per_action",
        "counter_time",
    }
    assert required <= declared, f"не хватает пояснений: {sorted(required - declared)}"


def test_method_modal_states_what_is_measured_and_what_is_modelled() -> None:
    """Модалка методики обязана разделять замер и расчёт и не обещать измеренного времени."""
    app = _app()
    start = app.index("effort_method: {")
    text = app[start : start + 2200]
    assert "append-only" in text
    assert "actor=" in text
    assert "модель" in text.lower()
    assert "не измерял" in text
    assert "baseline_methodology.md" in text


@pytest.mark.parametrize(
    "element_id",
    [
        "tabSimulation",
        "tabInvestigation",
        "simulationView",
        "simBody",
        "simCase",
        "simCaseId",
        "simCaseStatus",
        "simCaseRisk",
        "simCaseTitle",
        "simCaseSelect",
        "toInvestigation",
        "showProcesses",
        "graphLegend",
        "manualActions",
        "taktActions",
        "reductionValue",
        "playPause",
        "stepForward",
        "stepBack",
        "resetPlayer",
        "playerPosition",
        "phaseLegend",
        "stepList",
        "attackGraph",
        "simSummary",
        "methodButton",
        "secondsPerAction",
        "timeValue",
        "timeDelta",
    ],
)
def test_simulation_elements_exist(element_id: str) -> None:
    """Логика вкладки обращается к этим идентификаторам напрямую."""
    assert f'id="{element_id}"' in _index(), element_id


def test_app_uses_the_declared_elements() -> None:
    app = _app()
    for selector in ("#stepList", "#attackGraph", "#manualActions", "#taktActions", "#playPause"):
        assert selector in app, selector


def test_cache_version_is_consistent_and_bumped() -> None:
    """Единый параметр версии: иначе браузер отдаст старую сборку при новой разметке."""
    versions = set(_VERSION.findall(_index())) | set(_VERSION.findall(_app()))
    assert len(versions) == 1, f"параметр версии разъехался: {sorted(versions)}"
    assert versions >= {"20260822-04"}, versions


def test_build_artifacts_are_not_committed() -> None:
    """Минификаты и .gz создаются сборкой и в репозитории не хранятся."""
    ignored = (_ARM / ".gitignore").read_text(encoding="utf-8")
    for artifact in ("app.min.js", "styles.min.css", "index.prod.html", "*.gz"):
        assert artifact in ignored, artifact


def test_phase_colors_cover_the_domain_phases() -> None:
    """Легенда и граф раскрашиваются по тем же фазам, что объявлены в домене."""
    from takt.domain.entities.kill_chain import KillChainPhase

    app = _app()
    start = app.index("const PHASE_COLORS = {")
    block = app[start : app.index("};", start)]
    for phase in KillChainPhase:
        assert f"{phase.value}:" in block, phase.value


def test_counters_do_not_depend_on_the_player_position() -> None:
    """Счётчики трудоёмкости показывают значения кейса целиком, без интерполяции по шагам.

    Прецедент: итоговые числа раскладывались по шагам пропорционально позиции плеера. На
    нулевой позиции экран показывал «0 действий вручную, 0 в ТАКТ» рядом с «сокращение
    88.6%», а на первом шаге — «3 против 0», то есть стопроцентное сокращение. Ни одно из
    промежуточных чисел ничего не измеряло: ручная оценка считается по составу кейса, замер
    в ТАКТ — по журналу действий, и ни то ни другое не накапливается по шагам цепочки.
    """
    app = _app()
    assert "function cumulative(" not in app, "интерполяция счётчиков вернулась"

    start = app.index("function updateCounters()")
    block = app[start : app.index("\n}", start)]
    assert "effort.current_actions" in block and "effort.takt_actions" in block
    assert "simCursor" not in block, "счётчик снова зависит от позиции плеера"

    # Плеер двигает состав пройденного, а не оценку трудоёмкости.
    cursor = app[app.index("function setCursor(") : app.index("\n}", app.index("function setCursor("))]
    assert "updateCounters()" not in cursor


def test_the_case_under_analysis_is_named_in_the_view() -> None:
    """Прецедент: вкладка не показывала, какой инцидент разбирается.

    Идентификатор и заголовок приходили в ответе API и выбрасывались, а очередь на время
    разбора скрыта — на экране не оставалось ни одного признака кейса, и скриншот вкладки
    нельзя было приложить к отчёту.
    """
    app = _app()
    start = app.index("function renderSimCase()")
    block = app[start : app.index("\n}", start)]
    for element, value in (
        ("#simCaseId", "case_id"),
        ("#simCaseStatus", "status"),
        ("#simCaseRisk", "risk_class"),
        ("#simCaseTitle", "title"),
    ):
        assert element in block and value in block, element
    # Источник сведений — ответ по цепочке, а пока его нет — запись очереди.
    assert "simulation.case_id === selectedCaseId" in block
    assert "cases.find(" in block
    # Инцидент переключается, не покидая вкладку.
    assert "$('#simCaseSelect').addEventListener('change'" in app

    # Шапка рисуется до запроса и переживает ошибку: иначе сообщение «Цепочка не построена»
    # висит без указания инцидента, а список инцидентов исчезает вместе со скрытой шапкой —
    # из состояния ошибки становится нечем выбрать другой кейс.
    opener = app[
        app.index("async function openSimulation()") : app.index("\n}", app.index("async function openSimulation()"))
    ]
    assert opener.index("renderSimCase()") < opener.index("await api("), "шапка рисуется после запроса"
    catch = opener[opener.index("} catch (error) {") :]
    assert "$('#simCase').hidden = true" not in catch, "шапка прячется вместе с выбором инцидента"


def test_view_is_not_called_a_simulation() -> None:
    """«Симуляция» на рынке — эмуляция атаки (BAS), а вкладка разбирает принятые события.

    Название обещало бы синтетику ровно там, где продукт доказывает подлинность данных.
    Путь эндпоинта `/cases/{id}/simulation` — часть контракта и не переименовывается;
    проверяется то, что читает человек.
    """
    index = _index()
    start = index.index('id="tabSimulation"')
    assert "Цепочка атаки" in index[start : index.index("</button>", start)]

    view = index[index.index('id="simulationView"') : index.index('id="modal"')]
    assert "Реконструкция цепочки атаки" in view
    assert "имуляц" not in view


def test_simulation_view_declares_no_active_control() -> None:
    """Во вкладке нет кнопок исполнения: реагирование остаётся рекомендацией."""
    index = _index()
    start = index.index('id="simulationView"')
    view = index[start : index.index('id="modal"')]
    forbidden = ("Изолировать", "Заблокировать", "Выполнить", "Отправить команду", "Применить")
    for word in forbidden:
        assert word not in view, word
    assert "ТАКТ не выполняет действия реагирования" in view


def test_styles_define_phase_and_player_classes() -> None:
    styles = _STYLES.read_text(encoding="utf-8")
    for selector in (".legend-item", ".step.played", ".step.current", "#attackGraph .edge-line.played"):
        assert selector in styles, selector


def test_hidden_attribute_is_enforced_over_author_display() -> None:
    """Атрибут hidden обязан скрывать элемент, даже если класс задаёт display.

    Прецедент: `.layout { display: grid }` перебивал браузерное `[hidden] { display: none }`,
    и обе вкладки — «Расследование» и «Цепочка атаки» — показывались одновременно. Разницы между
    вкладками не было видно вообще.
    """
    styles = _STYLES.read_text(encoding="utf-8")
    # Селектор ищется в начале строки: в комментарии рядом он тоже упоминается.
    rule = re.search(r"^\[hidden\]\s*\{([^}]*)\}", styles, re.MULTILINE)
    assert rule is not None, "правило для атрибута hidden отсутствует"
    assert "display: none !important" in rule.group(1), rule.group(1)


def test_tab_switch_hides_the_other_view() -> None:
    """Переключение вкладки скрывает противоположный раздел, а не только показывает свой."""
    app = _app()
    start = app.index("function showTab(")
    block = app[start : app.index("\n}", start)]
    assert ".layout" in block and "hidden = isSimulation" in block
    assert "$('#simulationView').hidden = !isSimulation" in block


def test_attack_graph_draws_the_process_chain() -> None:
    """Цепочка процессов — дословное требование целевой задачи ТЗ № 6.

    `process_id` и `parent_process_id` есть в модели события и приходят в `steps[].entities`,
    а граф читал только учётную запись, узел и адрес. Слой включается отдельно: процессы
    многочисленны и без переключателя забивают собой остальное.
    """
    app = _app()
    start = app.index("function chainGraph(")
    block = app[start : app.index("\n}", start)]
    assert "parent_process_id" in block and "process_id" in block
    assert "'породил'" in block, "нет связи родитель — потомок"
    assert "withProcesses" in block, "слой процессов не переключается"
    assert "$('#showProcesses')" in app


def test_source_address_is_a_label_on_the_host_not_a_node() -> None:
    """У всех четырёх классов источников `src_address` — собственный адрес наблюдающего узла.

    Отдельным узлом он задваивал бы узел и рисовал связь, которой в данных нет: `src_ip` и
    `host_id` в маппинге EDR, SIEM, NDR и OT описывают одну и ту же машину. Показывается
    подписью на узле.
    """
    app = _app()
    start = app.index("function chainGraph(")
    block = app[start : app.index("\n}", start)]
    # Узел заводится вызовом add(<значение>, <тип>, ...) — именно его здесь быть не должно.
    assert "add(parts.src_address," not in block, "адрес источника стал отдельным узлом"
    assert "addresses.add(parts.src_address)" in block


def test_attack_graph_shows_direction_type_and_entry_point() -> None:
    """Граф атаки без направления, типа и точки входа не читается.

    Рёбра «действует на» и «обращается к» направлены; тип сущности кодируется формой, потому
    что цвет уже занят фазой; точка входа — узел и учётная запись первого шага цепочки.
    """
    app = _app()
    assert "marker-end" in app and "orient" in app, "нет стрелок на рёбрах"

    shapes = app[app.index("function nodeShape(") : app.index("\n}", app.index("function nodeShape("))]
    for kind in ("host", "address", "process"):
        assert f"'{kind}'" in shapes, kind
    assert "polygon" in shapes and "rect" in shapes and "circle" in shapes

    render = app[
        app.index("function renderAttackGraph()") : app.index("\n}", app.index("function renderAttackGraph()"))
    ]
    assert "entry-ring" in render and "точка входа" in render
    # Точка входа — не адрес и не процесс того же шага.
    assert "node.type === 'host' || node.type === 'user'" in render


def test_attack_graph_lays_out_by_phase_and_sizes_itself() -> None:
    """Раскладка по фазам слева направо, высота — по числу рядов.

    Сетка «пять в ряд» смысла не несла: соседство на экране не означало связи. Хуже того, при
    фиксированном viewBox 320 px узлы с шестнадцатого уходили за границу и пропадали молча.
    """
    app = _app()
    assert "const perRow" not in app, "вернулась сетка фиксированной ширины"
    layout = app[app.index("function graphLayout(") : app.index("\n}", app.index("function graphLayout("))]
    assert "simulation.phases" in layout, "колонки не привязаны к фазам"
    assert "height" in layout and "rows" in layout

    render = app[
        app.index("function renderAttackGraph()") : app.index("\n}", app.index("function renderAttackGraph()"))
    ]
    assert "svg.style.height" in render and "setAttribute('viewBox'" in render


def test_effort_block_comes_after_the_chain() -> None:
    """Вкладка открывается разбором, а не показателем эффективности.

    Блок «Трудоёмкость разбора» стоял первым — метрика для покупателя перед тем, ради чего
    аналитик открыл вкладку. У сравнимых продуктов страница инцидента открывается разбором
    (Defender — attack story, Cortex — causality view), а показатели эффективности SOC живут
    в отдельном разделе отчётов. Порядок: цепочка, граф, итог, и только потом цена разбора.
    """
    index = _index()
    view = index[index.index('id="simulationView"') : index.index('id="modal"')]
    order = [
        view.index("<h4>Плеер цепочки</h4>"),
        view.index("<h4>Граф атаки</h4>"),
        view.index("<h4>Итог разбора</h4>"),
        view.index("<h4>Трудоёмкость разбора</h4>"),
    ]
    assert order == sorted(order), "порядок блоков вкладки изменился"


def test_time_difference_between_manual_and_takt_is_shown() -> None:
    """Заказчик обязан видеть разницу, а не вычитать её в уме.

    Раньше плитка показывала «3 мин 20 с / 29 мин 20 с» — две величины через косую черту,
    порядок которых читался только из подписи, — и те же два значения дублировались под
    счётчиками действий. Теперь плитка показывает саму разницу, а слагаемые стоят под ней.
    """
    app = _app()
    start = app.index("function updateCounters()")
    block = app[start : app.index("\n}", start)]
    assert "formatDuration(manualTime - taktTime)" in block, "разница не вычисляется"
    # Слагаемые остаются на виду: иначе разницу нельзя перепроверить.
    assert "${formatDuration(manualTime)} − ${formatDuration(taktTime)}" in block

    index = _index()
    assert "Разница во времени" in index


def test_time_reduction_is_never_shown_as_a_second_percentage() -> None:
    """Процент в интерфейсе один — по действиям.

    Модельное время пропорционально действиям, поэтому процент сокращения времени совпал бы
    с процентом сокращения действий и выглядел бы вторым независимым доказательством,
    которым не является. Разница во времени показывается в минутах.
    """
    app = _app()
    start = app.index("function updateCounters()")
    block = app[start : app.index("\n}", start)]
    percent_lines = [line for line in block.splitlines() if "%" in line and "//" not in line]
    assert len(percent_lines) == 1, percent_lines
    assert "reduction" in percent_lines[0]


def test_time_is_labelled_as_model_everywhere() -> None:
    """Время нигде не подаётся как измеренная величина."""
    app = _app()
    start = app.index("const perAction = effort.seconds_per_action;")
    block = app[start : start + 1200]
    assert "модель" in block
    index = _index()
    assert "допущение для оценки времени, не замер" in index
