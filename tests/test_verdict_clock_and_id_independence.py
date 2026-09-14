"""T3. Независимость вердикта от системных часов и генератора идентификаторов.

Время наблюдателя и значение счётчика идентификаторов доказательствами не являются. Дело,
разобранное сегодня и то же дело, разобранное через пять лет, обязаны дать один вердикт: иначе
экспертиза не воспроизведёт вывод, и доказательный пакет нельзя предъявить.

Отсюда требование: подмена `SystemClockPort` и `IdProviderPort` не меняет наблюдаемую часть
вердикта. Идентификатор дела и отметка создания при этом меняться обязаны — они и есть выход
этих портов; в `verdict_fingerprint` они не входят, и это зафиксировано отдельным тестом ниже,
чтобы исключение не выглядело подгонкой.

Датировку доказательного пакета закрывают уже существующие тесты, и здесь они не дублируются
(регламент задачи, раздел 0):

- `tests/test_forensic_bundle.py::test_root_hash_does_not_depend_on_the_moment_of_generation`
- `tests/test_forensic_bundle.py::test_package_still_records_when_it_was_produced`
- `tests/test_forensic_bundle.py::test_root_hash_changes_when_the_case_changes`

Смежный сторож: `tests/test_domain_ast_policy.py` запрещает `datetime.now` и `uuid4` в домене,
то есть закрывает источник. Здесь проверяется наблюдаемое следствие.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from conftest_variational import GUARD_WEIGHTS, Scenario, scenarios, verdict_fingerprint

from takt.application.use_cases.assess_risk import AssessRiskUseCase

# Две точки на шкале, разнесённые так, чтобы задеть всё, что может зависеть от «сейчас».
# Время суток выбрано по разные стороны штатной смены намеренно: если взять обе точки ночью
# (например, 00:00 и 23:59), инвариант `out_of_shift_access` сработает одинаково в обоих
# прогонах, и гвард станет зелёным, ничего не проверив.
EARLY = datetime(2020, 1, 1, 3, 0, 0, tzinfo=UTC)      # глубокая ночь, вне смены
LATE = datetime(2031, 6, 17, 13, 30, 0, tzinfo=UTC)    # середина рабочего дня, в смене


class _FrozenClock:
    """`SystemClockPort` с неподвижным временем."""

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now_utc(self) -> datetime:
        return self._moment


class _FixedIds:
    """`IdProviderPort` с постоянным идентификатором — чтобы различие было заметным."""

    def __init__(self, value: str) -> None:
        self._value = value

    def new_case_id_short(self) -> str:
        return self._value


def _assess(scenario: Scenario, *, moment: datetime, case_id: str, pass_clock: bool):
    use_case = AssessRiskUseCase(
        GUARD_WEIGHTS,
        plc_hosts=scenario.plc_hosts,
        clock=_FrozenClock(moment),
        ids=_FixedIds(case_id),
    )
    return use_case.execute(
        scenario.event,
        recent_events=list(scenario.recent_events),
        tickets=list(scenario.tickets),
        graph_edges=list(scenario.graph_edges),
        polling_intervals_us=scenario.polling_intervals_us,
        # `clock=None` — путь производства: `IngestFacade` подаёт в оценку `now_utc()`
        # настенных часов, а не отметку события.
        clock=scenario.event.observed_at if pass_clock else None,
    )


@pytest.mark.parametrize("scenario", scenarios(), ids=lambda s: s.name)
def test_verdict_does_not_depend_on_ports_when_time_comes_from_the_event(scenario: Scenario) -> None:
    """Когда опорное время берётся из данных дела, порты на вердикт не влияют вовсе.

    Это та конфигурация, в которой требование δ(вердикт) = 0 выполняется: и часы, и генератор
    идентификаторов подменены, а наблюдаемая часть вердикта совпадает побайтово.
    """
    early = _assess(scenario, moment=EARLY, case_id="aaaaaaaa", pass_clock=True)
    late = _assess(scenario, moment=LATE, case_id="zzzzzzzz", pass_clock=True)

    assert verdict_fingerprint(early) == verdict_fingerprint(late)


@pytest.mark.parametrize("scenario", scenarios(), ids=lambda s: s.name)
def test_verdict_does_not_depend_on_the_wall_clock(scenario: Scenario) -> None:
    """Тот же вердикт, когда опорное время приходит из порта часов, — сильная форма требования.

    Это путь производства: `IngestFacade` подаёт в оценку `now_utc()` настенных часов, а не
    отметку события. Требование тем не менее выполняется — фазу смены и прочие временные
    признаки инварианты считают по `observed_at` самого события, а `ts` уходит только в
    метаданные дела (идентификатор, отметка создания, запись журнала).

    Проверено на точках, разнесённых по фазам смены (EARLY — ночь, LATE — рабочий день):
    при совпадении фаз гвард был бы зелёным, ничего не проверив.
    """
    early = _assess(scenario, moment=EARLY, case_id="aaaaaaaa", pass_clock=False)
    late = _assess(scenario, moment=LATE, case_id="zzzzzzzz", pass_clock=False)

    assert verdict_fingerprint(early) == verdict_fingerprint(late)


def test_identifier_and_creation_stamp_are_expected_to_move() -> None:
    """Исключение `case_id` и `created_at` из сравнения — осознанное, а не подгонка.

    Оба значения суть выход подменяемых портов. Если бы они не менялись, порты не были бы
    подменены, и весь гвард проверял бы тождество.
    """
    scenario = scenarios()[0]
    # `pass_clock=False` — опорное время берётся из порта, иначе отметка создания пришла бы из
    # события и совпала бы в обоих прогонах, а проверка стала бы тождеством.
    early = _assess(scenario, moment=EARLY, case_id="aaaaaaaa", pass_clock=False)
    late = _assess(scenario, moment=LATE, case_id="zzzzzzzz", pass_clock=False)

    assert early.suggested_case.case_id != late.suggested_case.case_id
    assert early.suggested_case.created_at != late.suggested_case.created_at


def test_fingerprint_excludes_only_port_outputs() -> None:
    """Страховка: из сравнения исключены ровно идентификатор и отметка, ничего сверх того."""
    scenario = scenarios()[0]
    result = _assess(scenario, moment=EARLY, case_id="aaaaaaaa", pass_clock=True)
    fingerprint = verdict_fingerprint(result)

    assert "case_id" not in fingerprint
    assert "created_at" not in fingerprint
    # Всё, ради чего вердикт предъявляется, в сравнении присутствует.
    assert {"risk_class", "risk_score", "invariant_hits", "xai_summary"} <= set(fingerprint)
