from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from takt.application.system_defaults import default_id_provider
from takt.domain.entities.case import CaseArtifact, Finding
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import IdProviderPort


@dataclass(frozen=True, slots=True)
class ArtifactInput:
    type: str
    value: str
    host_id: str = ""
    verification_status: str = "unverified"


class CaseFindingsUseCase:
    def __init__(self, repo: CaseRepositoryPort, ids: IdProviderPort = default_id_provider) -> None:
        self._repo = repo
        self._ids = ids

    def _case(self, case_id: str):
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError(f"unknown case: {case_id}")
        return case

    def _audit(self, case, action: str, actor: str, clock: datetime, payload: dict) -> None:
        case.append_audit(f"{action} appended", clock, actor=actor)
        self._repo.save(case)
        record = getattr(self._repo, "record_operation_event", None)
        if callable(record):
            record(
                operation_type=action, entity_id=case.case_id, actor=actor,
                payload_json=json.dumps(payload, ensure_ascii=False), created_at=clock.isoformat(),
            )

    @staticmethod
    def _artifact(item: ArtifactInput, actor: str, clock: datetime, source: str) -> CaseArtifact:
        if not item.type.strip() or not item.value.strip():
            raise ValueError("artifact type and value are required")
        return CaseArtifact(
            type=item.type.strip().lower(), value=item.value.strip(), host_id=item.host_id.strip(),
            verification_status=item.verification_status.strip() or "unverified",
            source=source, added_by=actor, created_at=clock,
        )

    def add_artifact(self, case_id: str, item: ArtifactInput, *, actor: str, clock: datetime) -> CaseArtifact:
        case = self._case(case_id)
        artifact = self._artifact(item, actor, clock, "manual")
        case.artifacts.append(artifact)
        self._audit(case, "case.artifact.add", actor, clock, {"type": artifact.type, "value": artifact.value})
        return artifact

    def add_finding(
        self, case_id: str, text: str, event_ids: list[str], artifacts: list[ArtifactInput],
        *, actor: str, clock: datetime,
    ) -> Finding:
        content = text.strip()
        if not content:
            raise ValueError("finding text is required")
        case = self._case(case_id)
        unknown = sorted(set(event_ids) - set(case.normalized_event_ids))
        if unknown:
            raise ValueError(f"events are not attached to case: {', '.join(unknown)}")
        finding_artifacts = [self._artifact(item, actor, clock, "finding") for item in artifacts]
        finding = Finding(
            finding_id=self._ids.new_case_id_short(), text=content, author=actor,
            created_at=clock, event_ids=list(dict.fromkeys(event_ids)), artifacts=finding_artifacts,
        )
        case.findings.append(finding)
        case.artifacts.extend(finding_artifacts)
        self._audit(case, "case.finding.add", actor, clock, {"finding_id": finding.finding_id})
        return finding
