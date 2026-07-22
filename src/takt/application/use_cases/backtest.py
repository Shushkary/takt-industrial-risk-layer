from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from takt.application.use_cases.process_event import ProcessEventUseCase
from takt.domain.engines.causal_mesh import GraphEdge
from takt.domain.entities.event import NormalizedEvent
from takt.domain.entities.maintenance import ServiceTicket


@dataclass(slots=True)
class BacktestReport:
    events_processed: int
    cases_created: int
    merges: int
    risk_class_histogram: dict[str, int] = field(default_factory=dict)


class RunBacktestUseCase:
    """
    Пакетный прогон истории (MVP — последовательно, без реального графа).

    `events` — любой `Iterable`, в т.ч. генератор (например,
    `takt.infrastructure.importers.csv_events.iter_normalized_from_csv`):
    входной набор не материализуется целиком в памяти, в памяти держится
    только скользящее окно последних `recent_context_event_count` событий.
    """

    def __init__(self, process: ProcessEventUseCase) -> None:
        self._process = process

    def execute(
        self,
        events: Iterable[NormalizedEvent],
        *,
        graph_edges: list[GraphEdge] | None = None,
        polling_intervals_us: list[float] | None = None,
        trust_by_source: Mapping[str, float] | None = None,
    ) -> BacktestReport:
        hist: Counter[str] = Counter()
        merges = 0
        created = 0
        processed = 0
        n = self._process.recent_context_event_count
        window: deque[NormalizedEvent] = deque(maxlen=n)
        edges = graph_edges or []
        intervals = polling_intervals_us or [1000.0, 1000.0, 4670.0, 21_800.0]
        tickets: list[ServiceTicket] = []
        for ev in events:
            clock = ev.observed_at
            recent = list(window)
            out = self._process.execute(
                ev,
                recent_events=recent,
                tickets=tickets,
                graph_edges=edges,
                polling_intervals_us=intervals,
                clock=clock,
                trust_by_source=trust_by_source,
            )
            if out.merged_into_existing:
                merges += 1
            else:
                created += 1
            hist[out.assessment.risk_class] += 1
            window.append(ev)
            processed += 1
        return BacktestReport(
            events_processed=processed,
            cases_created=created,
            merges=merges,
            risk_class_histogram=dict(hist),
        )
