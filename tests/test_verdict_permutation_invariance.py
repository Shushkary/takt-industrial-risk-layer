"""T2. Перестановочная инвариантность вердикта по порядку поступления событий.

Порядок, в котором события дошли до конвейера, доказательством не является: он зависит от
сетевых задержек, размера пачки выгрузки и очерёдности коннекторов. Доказательство — отметки
времени внутри самих событий, и каноническая упорядоченность обязана восстанавливаться внутри
системы.

Отсюда требование: вердикт, набор сработавших инвариантов, канонический манифест и агрегатное
контрольное значение неподвижны при любой перестановке входного потока.

Падение этого теста означает утечку порядка поступления в канонизацию: система запомнила, в
какой последовательности ей подали данные, и предъявила это как часть вывода.

Гвард уже нашёл две такие утечки, и обе закрыты:

- `InvariantEvaluator` срезал окно правила как последние N **по позиции** в поданном списке,
  то есть по порядку поступления. Перестановка отдавала правилу другое подмножество событий;
- `evaluate_sequence_gaps` и `evaluate_stale_telemetry` шли по последовательности в порядке
  подачи и считали `delta` между соседями, порождая ложные `telemetry_gap` и `stale_data`.

Обе канонизируют окно по `(observed_at, event_id)` до использования.
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


@pytest.mark.parametrize("scenario", scenarios(), ids=lambda s: s.name)
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


def test_canonical_ordering_is_idempotent_for_the_caller() -> None:
    """Канонизация на стороне вызывающего ничего не меняет: конвейер уже делает её сам.

    Тест закрепляет границу найденного и закрытого дефекта. Пока окно контекста не
    канонизировалось внутри (`InvariantEvaluator` срезал последние N по позиции, а движки
    качества данных шли по последовательности в порядке подачи), сортировка снаружи была
    единственным способом получить неподвижный вердикт. Теперь она избыточна — и тест
    покажет, если канонизацию из конвейера уберут: внешняя сортировка останется зелёной,
    а гвард выше покраснеет.
    """
    scenario = max(scenarios(), key=lambda s: len(s.recent_events))
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
