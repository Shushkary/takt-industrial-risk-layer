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
        "saved_actions",
        "lm",
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
        "tabSearch",
        "simulationView",
        "searchView",
        "searchBody",
        "decodeResults",
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
        "savedActions",
        "savedActionsBasis",
        "lmButton",
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
    assert versions >= {"20260825-03"}, versions


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


def test_saved_actions_block_matches_the_manual_process_model() -> None:
    """Шаги в блоке «За счёт чего сокращены действия» — те же, что в модели трудоёмкости.

    Блок объясняет разбор `effort.model_breakdown`, а ключи этого разбора задаёт домен модели
    ручного процесса. Разъедься они — интерфейс показал бы прочерк вместо механизма, и никто
    бы не заметил: строка на месте, текст пустой.
    """
    from takt.application.use_cases.investigation_effort import ManualProcessModel

    app = _app()
    start = app.index("const MANUAL_STEP_MECHANISM = {")
    block = app[start : app.index("\n};", start)]
    steps = ManualProcessModel().actions(sources=1, entities=1, events=1)
    for step in steps:
        assert f"'{step}'" in block, f"шаг модели без пояснения механизма: {step}"


def test_saved_actions_are_taken_from_the_product_answer() -> None:
    """Блок не пересчитывает трудоёмкость: иначе его итог разошёлся бы со счётчиками выше."""
    app = _app()
    start = app.index("function renderSavedActions(")
    block = app[start : app.index(chr(10) + "}" + chr(10), start)]
    assert "simulation.effort" in block
    assert "model_breakdown" in block


def test_language_model_help_states_that_the_module_is_absent() -> None:
    """Пояснение про языковую модель обязано различать замысел и поставку.

    Иначе на демонстрации кнопка «Роль языковой модели» читается как заявление о том, что
    модель уже работает, — а сокращение действий получено без неё.
    """
    entry = _help_entries()["lm"]
    assert "в поставке нет" in entry
    assert "вне контура вердикта" in entry
    assert "журнале аудита" in entry
    assert "product_boundary.md" in entry


def test_clicks_help_does_not_pass_the_journal_off_as_a_click_count() -> None:
    """Журнал считает действия, меняющие состояние дела, а навигацию не видит вовсе."""
    entry = _help_entries()["clicks"]
    assert "не клики" in entry
    assert "actor" in entry or "меткой актора" in entry


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


def test_tab_switch_hides_every_other_view() -> None:
    """Переключение вкладки скрывает все остальные разделы, а не только показывает свой.

    Раньше разделов было два, и проверка называла их по именам. Вкладок стало три (появился
    поиск по событиям), и перечисление имён пришлось бы дописывать при каждой следующей — то
    есть о забытом разделе тест узнал бы последним. Проверяется то же свойство, но по реестру
    вкладок: каждый объявленный раздел получает `hidden` из признака активности.
    """
    app = _app()
    start = app.index("const TABS = {")
    registry = app[start : app.index("};", start)]
    for view in (".layout", "#searchView", "#simulationView"):
        assert view in registry, view

    start = app.index("function showTab(")
    block = app[start : app.index("\n}\n", start)]
    assert "Object.entries(TABS)" in block
    assert "hidden = !active" in block


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

# --- Организационный документ, ТЗ §6.3 (P3-2) -------------------------------


def test_the_document_the_case_asks_for_can_be_attached_from_the_same_place() -> None:
    """Блок «Чего не хватает» называл документ, а приложить его было нечем — тупик на демонстрации."""
    app = _app()
    index = _index()

    assert "/manual-permits" in app
    missing_block = index[index.index('id="missingBlock"') : index.index('id="permitForm"')]
    assert 'id="permitOpen"' in missing_block


def test_permit_form_is_prefilled_from_the_case_it_belongs_to() -> None:
    """Продукт сверяет документ с активом и операцией дела: набирать их заново — приглашение к опечатке."""
    app = _app()
    start = app.index("function openPermitForm(")
    block = app[start : app.index("\nfunction closePermitForm(", start)]

    assert "primary_asset_id" in block
    assert "trigger_operation" in block
    assert "sanctioning_party" in block


def test_workstation_does_not_judge_the_document_itself() -> None:
    """Вердикт обязан быть воспроизводимым: второй расчёт в браузере разошёлся бы с пакетом."""
    app = _app()
    start = app.index("async function submitPermitForm(")
    block = app[start : app.index("\n// Итог сверки", start)]

    for word in ("legitimate", "illegitimate", "undetermined"):
        assert word not in block, f"интерфейс делает собственный вывод по документу: {word}"
    assert "term('permit_verdict'" in _app()


def test_result_of_the_check_is_shown_right_away() -> None:
    """Приложить документ и не узнать, снял ли он неопределённость, — работа вслепую."""
    app = _app()

    assert "function showPermitResult(" in app
    start = app.index("function showPermitResult(")
    block = app[start : app.index("\nfunction renderPermits(", start)]
    assert "rationale" in block
    assert "counterfactual" in block


def test_attached_documents_stay_visible_with_their_checksum() -> None:
    """По контрольной сумме организационного контекста проверяется, что документ не подменили."""
    app = _app()
    index = _index()

    assert "function renderPermits(" in app
    assert "organizational_context_sha256" in app
    assert 'id="permitList"' in index

# --- Сведение однотипных дел в очереди (P3-3) -------------------------------


def test_queue_can_be_shown_collapsed_by_the_product() -> None:
    """Группировка загруженной страницы считала бы сотню дел из нескольких сотен."""
    app = _app()

    assert "/cases/groups" in app
    assert "group_by" in app
    assert 'id="queueModeRule"' in _index()


def test_collapsed_row_is_not_opened_as_a_case() -> None:
    """У группы нет ни состава событий, ни вердикта: карточка предъявила бы вывод, которого нет."""
    app = _app()
    start = app.index("function drillIntoGroup(")
    block = app[start : app.index("\n}", start)]

    assert "queueDrill" in block
    assert "top_case_id" in block


def test_group_filter_does_not_pretend_to_be_the_search_field() -> None:
    """Ни актива, ни операции в видимых фильтрах нет — отбор показывается отдельной строкой."""
    index = _index()
    app = _app()

    assert 'id="queueDrill"' in index
    assert 'id="queueDrillClear"' in index
    assert "primary_asset_id" in app
    assert "trigger_operation_contains" in app


def test_counters_agree_with_russian_numerals() -> None:
    """«284 дела» и «1 дело» — подпись собирается интерфейсом и в ответе продукта не приходит."""
    app = _app()

    assert "function plural(" in app
    assert "'дело', 'дела', 'дел'" in app

# --- Выходные документы по делу (P3-4) --------------------------------------


def test_documents_are_requested_with_the_access_key() -> None:
    """Прямая ссылка ключ не несёт: при штатной конфигурации вкладка открывалась пустой с 401.

    Выглядело это как «отчёт не формируется», хотя продукт отвечал ровно то, что должен.
    """
    app = _app()

    assert "function openDocument(" in app
    assert "window.open(`${API_BASE}" not in app
    start = app.index("async function openDocument(")
    block = app[start : app.index("\nfunction openDecisionBrief(", start)]
    assert "authHeaders()" in block
    assert "createObjectURL" in block
    assert "revokeObjectURL" in block


def test_case_report_is_reachable_from_the_case() -> None:
    """ТЗ §5.10: паспорт инцидента — выходной документ, а не производная справка."""
    app = _app()

    assert "/export.pdf" in app
    assert 'id="reportButton"' in _index()

# --- Единый поиск, разбор значения, поиск в очереди (P3-4) ------------------


def test_events_are_searchable_across_all_sources() -> None:
    """ТЗ §5: четыре класса источников приведены к одной модели — поиск один, а не по консоли на каждый."""
    app = _app()

    assert "function runEventSearch(" in app
    assert "/events/search" in app
    assert 'id="searchView"' in _index()


def test_search_without_any_filter_is_refused() -> None:
    """Запрос без отбора вернул бы весь принятый поток — тысячу событий ни о чём."""
    app = _app()
    start = app.index("async function runEventSearch(")
    block = app[start : app.index("function showSearchError(", start)]

    assert "keys()" in block
    assert "весь принятый поток" in block


def test_attaching_from_search_still_demands_a_reason() -> None:
    """Правка состава дела меняет доказательный материал, из какого бы места её ни начали."""
    app = _app()
    start = app.index("async function attachFoundEvent(")
    block = app[start : app.index("// --- Разбор", start)]

    assert "Причина обязательна" in block
    assert block.index("Причина обязательна") < block.index("api(")


def test_decoding_is_done_by_the_product() -> None:
    """Результат разбора приводится как довод: он обязан совпадать с тем, что видит продукт."""
    app = _app()

    assert "/enrichment/decode" in app
    start = app.index("async function runDecode(")
    block = app[start : app.index('\n}', start)]
    assert "atob" not in block and "decodeURIComponent" not in block


def test_failed_decoding_is_shown_too() -> None:
    """«Не является base64» — это ответ; молчание выглядит как несработавшая кнопка."""
    app = _app()

    assert "не разобрано" in app


def test_queue_search_can_look_at_the_case_id_and_the_asset() -> None:
    """Раньше поле искало только заголовок, хотя продукт умеет и то и другое."""
    app = _app()
    index = _index()

    assert 'id="queueSearchField"' in index
    assert "case_id_prefix" in app
    assert "primary_asset_id" in app
