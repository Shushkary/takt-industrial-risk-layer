from __future__ import annotations

from typing import Protocol, runtime_checkable

from takt.domain.entities.case import Case


@runtime_checkable
class CaseRepositoryPort(Protocol):
    def save(self, case: Case) -> None: ...

    def get(self, case_id: str) -> Case | None: ...

    def list_all(self) -> list[Case]: ...

    def find_open_by_fingerprint(self, fingerprint: str) -> Case | None:
        """Открытый кейс с тем же burst_fingerprint (NEW/TRIAGE)."""
        ...
