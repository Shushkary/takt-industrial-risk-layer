"""L1 Domain — ядро чистой архитектуры «SOC core» (итерация 1).

Слой не импортирует ничего из ``takt.application``, ``takt.interface_adapters``
или ``takt.infrastructure`` и не обращается напрямую к времени/UUID —
источники недетерминизма инъектируются через порты (``Clock``, ``IdGenerator``).
"""

from takt.domain.soc.correlation import CorrelationEdge, CorrelationEngine
from takt.domain.soc.entity_baseline import EntityBaseline
from takt.domain.soc.invariants import (
    ALL_INVARIANTS,
    InvariantViolation,
    check_all_invariants,
)
from takt.domain.soc.normalized_event import NormalizedEvent, SourceClass
from takt.domain.soc.ports import (
    Clock,
    EnrichmentData,
    EnrichmentProvider,
    EventRepository,
    IdGenerator,
)
from takt.domain.soc.welford import BaselineStats

__all__ = [
    "ALL_INVARIANTS",
    "BaselineStats",
    "Clock",
    "CorrelationEdge",
    "CorrelationEngine",
    "EnrichmentData",
    "EnrichmentProvider",
    "EntityBaseline",
    "EventRepository",
    "IdGenerator",
    "InvariantViolation",
    "NormalizedEvent",
    "SourceClass",
    "check_all_invariants",
]
