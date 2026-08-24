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
    assert versions >= {"20260824-02"}, versions


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
