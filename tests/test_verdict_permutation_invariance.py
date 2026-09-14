"""T2. Перестановочная инвариантность вердикта по порядку поступления событий.

Порядок, в котором события дошли до конвейера, доказательством не является: он зависит от
сетевых задержек, размера пачки выгрузки и очерёдности коннекторов. Доказательство — отметки
времени внутри самих событий, и каноническая упорядоченность обязана восстанавливаться внутри
системы.

Отсюда требование: вердикт, набор сработавших инвариантов, канонический манифест и агрегатное
контрольное значение неподвижны при любой перестановке входного потока.

Падение этого теста означает утечку порядка поступления в канонизацию: система запомнила, в
какой последовательности ей подали данные, и предъявила это как часть вывода. По регламенту
задачи домен здесь не правится — падение выносится в отчёт с минимальным воспроизводящим
примером.
"""

from __future__ import annotations

import random

import pytest
from conftest_variational import GUARD_WEIGHTS, Scenario, scenarios, verdict_fingerprint

from takt.application.use_cases.assess_risk import AssessRiskUseCase

# Seed фиксирован литералом: гвард обязан быть воспроизводим целиком, включая сами перестановки.
# Случайность в тестах допустима только так (регламент задачи, раздел «Запрещено», п. 4).
SEED = 20260914

# Число перестановок на сценарий в обычном прогоне. Вынесено в константу намеренно: ночной
# прогон поднимает её до 1000, не трогая тело теста. Держать 1000 в обычном прогоне нельзя —
# шесть сценариев дали бы шесть тысяч полных прогонов конвейера на каждый запуск набора.
PERMUTATIONS = 200
PERMUTATIONS_NIGHTLY = 1000


def _assess(scenario: Scenario, *, rng: random.Random | None) -> dict[str, object]:
    """Прогон сценария; при переданном `rng` наборы контекста подаются в случайном порядке.

    Переставляются только те наборы, порядок которых не несёт смысла: недавние события (каждое
    со своей отметкой времени), наряды и рёбра графа связей. Интервалы опроса
    (`polling_intervals_us`) намеренно НЕ переставляются: там порядок — это сам ритм опроса,
    то есть доказательство, а не артефакт доставки.
    """
    recent = list(scenario.recent_events)
    tickets = list(scenario.tickets)
    edges = list(scenario.graph_edges)
    if rng is not None:
        rng.shuffle(recent)
        rng.shuffle(tickets)
        rng.shuffle(edges)

    use_case = AssessRiskUseCase(GUARD_WEIGHTS, plc_hosts=scenario.plc_hosts)
    result = use_case.execute(
        scenario.event,
        recent_events=recent,
        tickets=tickets,
        graph_edges=edges,
        polling_intervals_us=scenario.polling_intervals_us,
        clock=scenario.event.observed_at,
    )
    return verdict_fingerprint(result)


# Сценарии с известной утечкой порядка поступления. Помечены `xfail(strict=True)`: дефект
# зарегистрирован, а не спрятан — тест станет красным в тот момент, когда утечку закроют, и
# пометку придётся снять осознанно. Правка домена в объём этой задачи не входит (регламент,
# раздел «Запрещено», п. 3), поэтому находка вынесена в отчёт.
#
# Суть: `evaluate_sequence_gaps` и `evaluate_stale_telemetry`
# (`src/takt/domain/engines/data_quality.py`) идут по последовательности в том порядке, в каком
# её подали, и считают `delta = cur.observed_at - prev.observed_at` без сортировки и без
# модуля. На переставленном окне контекста delta становится большой или отрицательной, и
# появляются ложные `telemetry_gap` и `stale_data`, которых в данных нет.
#
# Достижимо в производстве: `recent_events` приходит из
# `SqliteRecentEventStore.list_recent_events`, а таблица `recent_events` по собственному
# docstring хранит «порядок» поступления, а не хронологию `observed_at`.
KNOWN_ORDER_LEAK: frozenset[str] = frozenset(
    {"серия неуспешных аутентификаций с несколькими связями"}
)


def _params() -> list[object]:
    out: list[object] = []
    for scenario in scenarios():
        marks = (
            pytest.mark.xfail(
                strict=True,
                reason=(
                    "утечка порядка поступления в оценку качества данных: "
                    "evaluate_sequence_gaps / evaluate_stale_telemetry не канонизируют окно "
                    "контекста по observed_at (находка T2, домен не правится в этой задаче)"
                ),
            ),
        )
        out.append(
            pytest.param(scenario, marks=marks, id=scenario.name)
            if scenario.name in KNOWN_ORDER_LEAK
            else pytest.param(scenario, id=scenario.name)
        )
    return out


@pytest.mark.parametrize("scenario", _params())
def test_verdict_is_invariant_under_input_permutation(scenario: Scenario) -> None:
    """Вердикт одинаков на всех перестановках входного потока."""
    reference = _assess(scenario, rng=None)
    rng = random.Random(SEED)

    for attempt in range(PERMUTATIONS):
        observed = _assess(scenario, rng=rng)
        assert observed == reference, (
            f"{scenario.name}: перестановка №{attempt} изменила вердикт.\n"
            f"ожидалось: {reference}\nполучено:  {observed}"
        )


def test_canonical_ordering_by_observed_at_restores_invariance() -> None:
    """Локализация находки: сортировка окна по `observed_at` возвращает неподвижность.

    Тест не чинит домен — он показывает, где именно проходит граница дефекта, и что
    требуется ровно канонизация окна контекста, а не пересмотр оценки качества данных.
    Это материал для решения владельца, а не обход гварда: сортировку делает здесь вызывающая
    сторона, в самом конвейере её по-прежнему нет.
    """
    scenario = next(s for s in scenarios() if s.name in KNOWN_ORDER_LEAK)
    rng = random.Random(SEED)

    def run(order: list) -> dict[str, object]:
        use_case = AssessRiskUseCase(GUARD_WEIGHTS, plc_hosts=scenario.plc_hosts)
        result = use_case.execute(
            scenario.event,
            recent_events=sorted(order, key=lambda e: (e.observed_at, e.event_id)),
            tickets=list(scenario.tickets),
            graph_edges=list(scenario.graph_edges),
            polling_intervals_us=scenario.polling_intervals_us,
            clock=scenario.event.observed_at,
        )
        return verdict_fingerprint(result)

    reference = run(list(scenario.recent_events))
    for attempt in range(PERMUTATIONS):
        shuffled = list(scenario.recent_events)
        rng.shuffle(shuffled)
        assert run(shuffled) == reference, f"перестановка №{attempt} пережила канонизацию"


def test_corpus_has_something_to_permute() -> None:
    """Страховка от вырождения: на одноэлементных наборах перестановка тождественна.

    Без этой проверки корпус из одних однособытийных сценариев оставил бы T2 зелёным,
    перестав что-либо проверять.
    """
    permutable = {
        s.name: len(s.recent_events) + len(s.tickets) + len(s.graph_edges)
        for s in scenarios()
    }
    assert max(permutable.values()) >= 6, (
        "в корпусе нет сценария с достаточным числом переставляемых элементов: " f"{permutable}"
    )


def test_permutations_are_actually_generated() -> None:
    """Seed обязан давать разные перестановки, иначе гвард прогоняет один и тот же порядок."""
    scenario = max(scenarios(), key=lambda s: len(s.recent_events))
    rng = random.Random(SEED)
    orders = set()
    for _ in range(50):
        order = list(scenario.recent_events)
        rng.shuffle(order)
        orders.add(tuple(e.event_id for e in order))
    assert len(orders) > 1, "перестановки не порождаются: rng.shuffle не меняет порядок"
