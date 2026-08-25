"""Вкладка «Симуляция» в АРМ: связность разметки, реестра пояснений и сборки.

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
    assert versions >= {"20260825-01"}, versions


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


def test_counters_reach_the_reported_totals() -> None:
    """Прирост счётчика распределён так, что итог совпадает с ответом API.

    Ровное распределение с округлением может не сойтись на последнем шаге, поэтому в коде
    предусмотрен явный возврат полного значения при достижении конца.
    """
    app = _app()
    start = app.index("function cumulative(")
    block = app[start : app.index("}\n", app.index("return Math.round", start))]
    assert "if (index >= steps) return total;" in block


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
    и обе вкладки — «Расследование» и «Симуляция» — показывались одновременно. Разницы между
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


def test_time_is_labelled_as_model_everywhere() -> None:
    """Время нигде не подаётся как измеренная величина."""
    app = _app()
    start = app.index("const perAction = effort.seconds_per_action;")
    block = app[start : start + 1200]
    assert "модель" in block
    index = _index()
    assert "допущение для оценки времени, не замер" in index

# --- Форма подачи пояснений (F-15) -----------------------------------------

_HELP_ENTRY = re.compile(r"^  ([a-z0-9_]+): \{\n(.*?)^  \},$", re.MULTILINE | re.DOTALL)
_DOC_PATH = re.compile(r"^    doc: '([^']+)',$", re.MULTILINE)


def _help_entries() -> dict[str, str]:
    return {key: block for key, block in _HELP_ENTRY.findall(_app())}


def test_every_entry_answers_all_three_questions() -> None:
    """Запись отвечает на «что это», «откуда» и «что делать» — все три, а не сколько получилось.

    Прецедент: пока запись была массивом абзацев, порядок вопросов держался договорённостью.
    У десяти записей из сорока двух ответа «откуда» просто не было, и по коду это не читалось —
    массив из двух строк выглядел так же законно, как из трёх.
    """
    incomplete: list[str] = []
    for key, block in _help_entries().items():
        missing = [field for field in ("title", "what", "source", "action") if f"    {field}: " not in block]
        if missing:
            incomplete.append(f"{key}: нет полей {missing}")
    assert not incomplete, incomplete


def test_documentation_links_point_at_files_that_exist() -> None:
    """Мёртвая ссылка на документ хуже её отсутствия: аналитик идёт по ней в момент спора."""
    repo_root = _ARM.parents[1]
    broken = [doc for doc in _DOC_PATH.findall(_app()) if not (repo_root / doc).is_file()]
    assert not broken, f"пояснения ссылаются на несуществующие документы: {broken}"


def test_help_registry_has_no_leftover_paragraph_arrays() -> None:
    """Старая форма записи рядом с новой означала бы два способа писать пояснение."""
    assert "    body: [" not in _app()


def test_modal_traps_focus_and_locks_the_background() -> None:
    """Фон под окном прокручивался, а Tab уводил фокус за подложку — с клавиатуры окно не закрывалось."""
    app = _app()

    assert "function trapFocus(" in app
    assert "modal-open" in app
    assert "'Tab'" in app
    assert "body.modal-open" in _STYLES.read_text(encoding="utf-8")


def test_help_button_shows_a_short_hint_on_hover() -> None:
    """Иначе всякий вопрос стоит двух действий: открыть окно и закрыть его."""
    app = _app()

    assert "function fillHelpHints(" in app
    assert "function firstSentence(" in app


def test_glossary_explains_the_private_language_of_the_product() -> None:
    """Эти слова продукт использует везде и нигде не объясняет — спор о них дороже любого другого."""
    entries = _help_entries()
    assert "glossary" in entries, "записи словаря понятий нет"
    glossary = entries["glossary"]
    for term in (
        "Инвариант",
        "Отличительная сущность",
        "Пивот",
        "Расширение до уровня узла",
        "Добор контекста",
        "Триадный вердикт",
        "Обоснованность",
    ):
        assert term in glossary, f"словарь понятий не объясняет «{term}»"


def test_glossary_is_reachable_from_the_header() -> None:
    """Словарь нужен в первые смены, а не после того, как аналитик найдёт нужный блок."""
    index = _index()
    header = index[index.index("<header") : index.index("</header>")]
    assert 'data-help="glossary"' in header

# --- Зона показа времени (F-16) ---------------------------------------------


def test_time_zone_is_switchable_and_remembered() -> None:
    """Раньше выбора не было, и пояснение прямо предлагало переводить время в уме."""
    app = _app()
    index = _index()

    assert "takt.time_zone" in app
    assert "function toggleTimeZone(" in app
    assert 'id="timeZoneToggle"' in index


def test_time_is_never_shown_without_naming_the_zone() -> None:
    """Время без обозначения зоны — это не время, а число, которое каждый читает по-своему."""
    app = _app()

    assert "function zoneLabel(" in app
    assert "function stamp(" in app
    # Подпись колонки цепочки берёт зону из того же места, что и значения.
    assert "$('#chainTimeZone').textContent = zoneLabel();" in app
    assert 'id="chainTimeZone"' in _index()


def test_switching_the_zone_does_not_touch_stored_time() -> None:
    """Пересчёт — только для показа: в запросах и доказательном пакете время остаётся исходным."""
    app = _app()
    start = app.index("function toggleTimeZone(")
    block = app[start : app.index("\n}", start)]

    # Переключатель перерисовывает карточку и не отправляет ничего в продукт.
    assert "api(" not in block

# --- Мелочи, каждая из которых ломается молча (F-17) ------------------------


def test_chain_is_ordered_by_moment_not_by_string() -> None:
    """Строковое сравнение меток времени работает ровно до первого смещения, отличного от +00:00.

    Событие со смещением `+03:00` при сравнении строк встаёт в цепочке не на своё место —
    и ход инцидента, ради которого цепочку и читают, восстанавливается неверно.
    """
    app = _app()
    start = app.index("function paintChain(")
    block = app[start : app.index("\nfunction ", start + 10)]

    assert "Date.parse" in block
    assert "localeCompare" not in block


def test_build_keeps_cyrillic_as_cyrillic() -> None:
    """Без --charset=utf8 esbuild экранирует каждую букву в \\uXXXX, и сборка крупнее исходника."""
    build = (_ARM / "build-production.mjs").read_text(encoding="utf-8")

    assert "--charset=utf8" in build


def test_nginx_does_not_route_to_a_contour_that_does_not_exist() -> None:
    """Маршрут `/api/v1/stream/cases` — остаток прежней редакции: такого контура в продукте нет."""
    conf = (_ARM / "nginx.takt-pt-arm.conf").read_text(encoding="utf-8")
    directives = [line.strip() for line in conf.splitlines() if not line.strip().startswith("#")]

    assert not [line for line in directives if "/api/v1" in line], "маршрут несуществующего контура"


def test_nginx_strips_the_api_prefix_like_the_local_stand() -> None:
    """Маршруты продукта зарегистрированы от корня: досланный префикс `/api` даёт 404 на каждом запросе.

    Проверено запуском backend с `--root-path=/api`: uvicorn префикс не снимает, `/api/cases`
    отвечает 404, `/cases` — 200. Локальный стенд снимает префикс, конфигурации не должны
    расходиться.
    """
    conf = (_ARM / "nginx.takt-pt-arm.conf").read_text(encoding="utf-8")
    directives = [line.strip() for line in conf.splitlines() if not line.strip().startswith("#")]
    proxy_lines = [line for line in directives if line.startswith("proxy_pass")]

    assert proxy_lines, "в конфигурации не осталось ни одного proxy_pass"
    assert not [line for line in proxy_lines if line.endswith("/api/;")], proxy_lines

# --- Ручная корректировка состава дела, ТЗ §5.2 (P3-1) ----------------------


def test_every_correction_of_the_case_is_available_from_the_workstation() -> None:
    """Четыре действия продукта: отцепить, прицепить, присоединить дело, выделить в отдельное."""
    app = _app()

    assert "/detach" in app
    assert "/events/attach" in app
    assert "/merge" in app
    assert "/split" in app


def test_correction_is_gated_by_the_role_from_the_product() -> None:
    """Право второй линии приходит из `GET /session`, а не решается в интерфейсе."""
    app = _app()

    assert "permissions().case_relink" in app
    assert "function relinkAllowed(" in app


def test_no_correction_is_sent_without_a_reason() -> None:
    """Причина уходит в журнал дела: правка состава меняет доказательный материал.

    Проверяется не наличие поля, а то, что **каждое** действие спрашивает причину перед
    запросом: забытая проверка в одном из четырёх обработчиков — это запись в append-only
    журнал без объяснения, и отменить её нельзя.
    """
    app = _app()

    assert "function relinkReasonOrWarn(" in app
    for handler in ("detachSelected", "splitSelected", "attachEvent", "mergeSelectedCase"):
        start = app.index(f"async function {handler}(")
        block = app[start : app.index("\n}", start)]
        assert "relinkReasonOrWarn()" in block, handler
        # Причина проверяется до запроса, а не после.
        assert block.index("relinkReasonOrWarn()") < block.index("api("), handler


def test_event_to_attach_is_chosen_from_what_the_product_returned() -> None:
    """Продукт принимает любой идентификатор, включая несуществующий.

    Набранный вручную идентификатор проверить нечем: `GET /events/search` ищет по содержимому
    события, а не по его идентификатору. Поэтому прицепить можно только событие из ответа
    продукта — иначе в деле останется ссылка в никуда.
    """
    app = _app()
    index = _index()

    assert "/events/search" in app
    assert "function runAttachSearch(" in app
    # Поля для ручного ввода идентификатора события в разметке нет.
    assert 'id="attachEventId"' not in index


def test_case_to_merge_is_chosen_from_the_queue() -> None:
    """Опечатка в идентификаторе дела — это необратимое действие не над тем делом."""
    index = _index()
    app = _app()

    assert '<select id="mergeSource"' in index
    assert "function openMergePanel(" in app
    assert "item.case_id !== selectedCaseId" in app


def test_manual_correction_is_counted_apart_from_machine_assembly() -> None:
    """Назвать правку аналитика расширением значило бы приписать решение человека механизму."""
    app = _app()

    assert "правки аналитика" in app
    # Признак ручной правки берётся из ответа продукта, а не из списка кодов в интерфейсе.
    assert "evidence.manual" in app
