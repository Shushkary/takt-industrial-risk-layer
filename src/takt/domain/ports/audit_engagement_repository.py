from __future__ import annotations

from typing import Protocol, runtime_checkable

from takt.domain.entities.audit_engagement import AuditEngagement


@runtime_checkable
class AuditEngagementRepositoryPort(Protocol):
    def save(self, engagement: AuditEngagement) -> None: ...

    def get(self, engagement_id: str) -> AuditEngagement | None: ...

    def list_all(self) -> list[AuditEngagement]: ...
