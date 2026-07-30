"""Сборка зависимостей ядра «SOC core» для surface ``/api/v1``.

Контекст держит движки и адаптеры (write/read-модели, dead-letter, журнал,
плейбуки, SSE-брокер), собранные из чистых слоёв L1/L2/L4.
"""

from __future__ import annotations

from pathlib import Path

from takt.application.soc.playbook_engine import PlaybookEngine
from takt.application.soc.read_models import GetAttackChain, GetCaseCard, SearchEvents
from takt.application.soc.write_use_cases import (
    AddFinding,
    ManualGroupOverride,
    ProcessEvent,
    RecordCaseDecision,
)
from takt.domain.soc.invariants import default_invariants
from takt.infrastructure.security.sha256_hasher import Sha256HasherAdapter
from takt.infrastructure.soc.dead_letter_store import (
    InMemoryDeadLetterStore,
    SqliteDeadLetterStore,
)
from takt.infrastructure.soc.journal import HashChainJournal
from takt.infrastructure.soc.repositories import (
    InMemoryAttackChainProjection,
    InMemoryCaseProjection,
    InMemoryEventRepository,
    InMemoryEventSearchProjection,
)
from takt.infrastructure.soc.system import SystemClock, UuidIdGenerator
from takt.interface_adapters.api.v1.broadcaster import CaseEventBroadcaster

_PLAYBOOK_PATH = Path(__file__).resolve().parents[5] / "playbooks" / "default.yaml"


class SocApiContext:
    """Контекст зависимостей ``/api/v1``."""

    def __init__(self, *, sqlite_path: str | None = None) -> None:
        self.clock = SystemClock()
        self.ids = UuidIdGenerator()
        self.hasher = Sha256HasherAdapter()
        self.invariants = default_invariants(self.clock)

        self.event_repo = InMemoryEventRepository()
        self.case_projection = InMemoryCaseProjection()
        self.search_projection = InMemoryEventSearchProjection()
        self.chain_projection = InMemoryAttackChainProjection()
        self.journal = HashChainJournal()

        if sqlite_path:
            self.dead_letters = SqliteDeadLetterStore(sqlite_path)
        else:
            self.dead_letters = InMemoryDeadLetterStore()

        self.broadcaster = CaseEventBroadcaster()

        # Use cases (CQRS).
        self.process_event = ProcessEvent(self.event_repo, self.ids)
        self.record_decision = RecordCaseDecision(self.journal, self.clock)
        self.add_finding = AddFinding(self.journal, self.clock, self.ids)
        self.manual_override = ManualGroupOverride(self.journal, self.clock)
        self.get_case_card = GetCaseCard(self.case_projection)
        self.search_events = SearchEvents(self.search_projection)
        self.get_attack_chain = GetAttackChain(self.chain_projection)

        if _PLAYBOOK_PATH.is_file():
            self.playbooks = PlaybookEngine.from_yaml(_PLAYBOOK_PATH)
        else:  # pragma: no cover - плейбук поставляется в репозитории
            self.playbooks = PlaybookEngine([])
