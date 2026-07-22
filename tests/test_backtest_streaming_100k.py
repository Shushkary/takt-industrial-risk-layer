"""Регрессия: потоковый бэктест на 100k+ событий без материализации в список.

ТЗ: async back-test на 100k+ событий. `RunBacktestUseCase.execute` принимает
`Iterable`, поэтому источник может быть генератором — в памяти держится
только скользящее окно контекста, а не весь набор событий.

Синтетический трафик намеренно разнесён по многим активам во времени (не
патологический сценарий «всё сливается в один кейс»): при подготовке этого
теста такой сценарий выявил O(n²) в `InMemoryCaseStore.find_open_by_fingerprint`
(линейный скан всего хранилища на каждое событие) — исправлено индексом
`_open_by_fingerprint` в `src/takt/infrastructure/stores/memory.py`.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Iterator

from takt.application.use_cases.assess_risk import AssessRiskUseCase
from takt.application.use_cases.backtest import RunBacktestUseCase
from takt.application.use_cases.process_event import ProcessEventUseCase
from takt.domain.entities.event import EventSource, NormalizedEvent
from takt.infrastructure.stores.memory import InMemoryCaseStore

_N = 100_000


def _weights() -> dict[str, float | int]:
    return {
        "rhythm": 0.22,
        "graph": 0.22,
        "context": 0.18,
        "user": 0.18,
        "data_quality": 0.20,
        "mandelbrot_entropy_cap": 2.5,
        "eps_soft_cap": 100_000,
    }


_ASSET_COUNT = 2_000


def _generate_events(n: int) -> Iterator[NormalizedEvent]:
    """
    Генератор, а не список: ни одно событие не удерживается дольше окна контекста.

    Разнесено по **`_ASSET_COUNT`** различных активов, каждый следующий заход на
    тот же актив — за пределами **`alert_fatigue.bucket_sec`** (300с по умолчанию),
    чтобы события не сливались в единственный, бесконечно растущий кейс: это
    приближение к реальному потоку телеметрии (много активов, разнесённых во
    времени), а не к патологическому сценарию «один кейс на 100k событий».
    """
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)
    for i in range(n):
        asset_idx = i % _ASSET_COUNT
        cycle = i // _ASSET_COUNT
        yield NormalizedEvent(
            event_id=f"ev-{i:07d}",
            observed_at=base + timedelta(seconds=asset_idx) + timedelta(seconds=400 * cycle),
            source=EventSource.PLC_POLLING,
            protocol="TCP",
            operation="POLL",
            payload_size=64,
            payload={"asset_id": f"plc-{asset_idx:04d}"},
        )


def test_streaming_backtest_processes_100k_events_from_a_generator() -> None:
    repo = InMemoryCaseStore()
    assess = AssessRiskUseCase(_weights(), plc_hosts=frozenset({f"plc-{i:04d}" for i in range(_ASSET_COUNT)}))
    proc = ProcessEventUseCase(assess, repo)
    bt = RunBacktestUseCase(proc)

    events = _generate_events(_N)
    # Подтверждаем на уровне типа, что это одноразовый итератор, а не Sequence:
    # обращение к len()/индексации было бы TypeError, execute() не должен их использовать.
    assert not hasattr(events, "__len__")

    start = time.monotonic()
    report = bt.execute(
        events,
        graph_edges=[],
        polling_intervals_us=[1000.0, 1000.0, 1000.0, 1000.0],
        trust_by_source=None,
    )
    elapsed = time.monotonic() - start

    assert report.events_processed == _N
    assert sum(report.risk_class_histogram.values()) == _N
    # Регрессионный порог (~37с локально), не гонка производительности: с запасом на CI-железо.
    # Резкий выход за порог обычно значит регресс в O(1) поиске по fingerprint (см. docstring).
    assert elapsed < 180.0, f"streaming backtest of {_N} events took {elapsed:.1f}s"
