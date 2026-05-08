from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Mapping, Sequence

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
    """Пакетный прогон истории (MVP — последовательно, без реального графа)."""

    def __init__(self, process: ProcessEventUseCase) -> None:
        self._process = process

    def execute(
        self,
        events: Sequence[NormalizedEvent],
        *,
        graph_edges: list[GraphEdge] | None = None,
        polling_intervals_us: list[float] | None = None,
        trust_by_source: Mapping[str, float] | None = None,
    ) -> BacktestReport:
        hist: Counter[str] = Counter()
        merges = 0
        created = 0
        window: list[NormalizedEvent] = []
        edges = graph_edges or []
        intervals = polling_intervals_us or [1000.0, 1000.0, 4670.0, 21_800.0]
        tickets: list[ServiceTicket] = []
        for i, ev in enumerate(events):
            clock = ev.observed_at
            n = self._process.recent_context_event_count
            recent = window[-n:] if len(window) > n else window[:]
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
        return BacktestReport(
            events_processed=len(events),
            cases_created=created,
            merges=merges,
            risk_class_histogram=dict(hist),
        )
