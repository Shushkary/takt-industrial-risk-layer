"""Регресс по накопленным сценариям заказчика.

Разрыв G-6 из [`docs/customer_value_map.md`](../docs/customer_value_map.md). Каждая фикстура в
`tests/fixtures/case_scenarios/` — закрытое дело с вердиктом, подтверждённым человеком,
выгруженное через `GET /cases/{id}/scenario.json` или
[`scripts/export_case_scenario.py`](../scripts/export_case_scenario.py).

Прогон идёт на **боевых** весах из `config/risk_weights.yaml`, а не на тестовых константах.
Это и есть смысл разрыва: изменение весов или предиката, ломающее накопленный случай, обязано
ронять тест здесь, а не всплывать у заказчика после релиза.

Смежное: [`test_detection_quality.py`](test_detection_quality.py) держит TPR/FPR по
синтетическому корпусу, здесь — воспроизводимость на реальных разобранных делах.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from takt.application.use_cases.backtest import RunBacktestUseCase
from takt.application.use_cases.case_scenario import SCENARIO_SCHEMA_VERSION, event_from_dict
from takt.infrastructure.config.pipeline import build_assessment_pipeline
from takt.infrastructure.config.weights_loader import load_risk_weights
from takt.infrastructure.stores.memory import InMemoryCaseStore

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCENARIO_DIR = Path(__file__).resolve().parent / "fixtures" / "case_scenarios"
_WEIGHTS_PATH = _REPO_ROOT / "config" / "risk_weights.yaml"
_INVARIANT_DIR = _REPO_ROOT / "config" / "invariants"


def _scenario_files() -> list[Path]:
    return sorted(_SCENARIO_DIR.glob("*.json"))


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _replay(scenario: dict[str, Any]) -> Any:
    """Прогнать сценарий через боевую конфигурацию и вернуть дело последнего события.

    Предыстория (`context_events`) проигрывается первой: оконные инварианты вроде серии
    неуспешных аутентификаций без неё не сработают. Ожидаемый исход сверяется по делу, в
    которое попало последнее событие самого дела, — предыстория могла создать свои дела.
    """
    context = [event_from_dict(item) for item in scenario.get("context_events", [])]
    events = [event_from_dict(item) for item in scenario["events"]]
    repo = InMemoryCaseStore()
    pipeline = build_assessment_pipeline(
        load_risk_weights(_WEIGHTS_PATH),
        repo=repo,
        invariant_catalog_dir=_INVARIANT_DIR,
    )
    RunBacktestUseCase(pipeline.process).execute(
        context + events,
        graph_edges=list(pipeline.graph_edges),
        polling_intervals_us=list(pipeline.polling_intervals_us),
        trust_by_source=pipeline.trust_by_source,
    )

    last_event_id = events[-1].event_id
    for case in repo.list_all():
        if last_event_id in case.normalized_event_ids:
            return case
    raise AssertionError(f"после прогона событие {last_event_id} не попало ни в одно дело")


def test_scenario_directory_exists() -> None:
    """Каталог заводится вместе с механизмом: пустой — это состояние, а не поломка."""
    assert _SCENARIO_DIR.is_dir()


@pytest.mark.parametrize("path", _scenario_files(), ids=lambda p: p.stem)
def test_scenario_schema_is_current(path: Path) -> None:
    scenario = _load(path)

    assert scenario["schema_version"] == SCENARIO_SCHEMA_VERSION
    assert scenario["events"], "сценарий без событий невоспроизводим"
    assert scenario["expected"]["verdict"] in ("LEG", "ILLEG")
    assert scenario["confirmed_by"], "сценарий обязан нести того, кто подтвердил вердикт"


@pytest.mark.parametrize("path", _scenario_files(), ids=lambda p: p.stem)
def test_scenario_still_produces_the_confirmed_invariants(path: Path) -> None:
    """Накопленный случай продолжает ловиться теми же инвариантами."""
    scenario = _load(path)
    case = _replay(scenario)

    expected = set(scenario["expected"]["invariant_hits"])
    missed = expected - set(case.invariant_hits)
    assert not missed, (
        f"{path.stem}: перестали срабатывать инварианты {sorted(missed)} —"
        " накопленный случай заказчика больше не воспроизводится"
    )


@pytest.mark.parametrize("path", _scenario_files(), ids=lambda p: p.stem)
def test_scenario_still_produces_the_confirmed_risk_class(path: Path) -> None:
    """Класс риска — то, по чему принималось решение; его снижение меняет исход разбора."""
    scenario = _load(path)
    case = _replay(scenario)

    assert case.risk_class == scenario["expected"]["risk_class"], (
        f"{path.stem}: класс риска изменился с {scenario['expected']['risk_class']}"
        f" на {case.risk_class}"
    )


@pytest.mark.parametrize("path", _scenario_files(), ids=lambda p: p.stem)
def test_scenario_replay_is_deterministic(path: Path) -> None:
    scenario = _load(path)

    first, second = _replay(scenario), _replay(scenario)

    assert sorted(first.invariant_hits) == sorted(second.invariant_hits)
    assert round(first.risk_score, 9) == round(second.risk_score, 9)
