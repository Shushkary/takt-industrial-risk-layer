from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from takt.application.use_cases.forensic_export_facade import (
    ForensicExportFacade,
    ForensicSupplementalFileError,
)
from takt.domain.entities.audit_engagement import AuditEngagement, AuditFinalReport, AuditStage


class _AuditEngagementUseCase:
    def __init__(self, engagement: AuditEngagement | None) -> None:
        self._engagement = engagement

    def get(self, engagement_id: str) -> AuditEngagement | None:
        if self._engagement is not None and self._engagement.engagement_id == engagement_id:
            return self._engagement
        return None


def test_forensic_export_facade_builds_audit_engagement_supplemental_files() -> None:
    engagement = AuditEngagement(
        engagement_id="eng-1",
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        status="completed",
        customer="Plant A",
        scope="Forensic audit",
        case_ids=["case-1"],
        nda_signed=True,
        evidence_intake_checklist=["nda"],
        stages=[
            AuditStage(
                code="kickoff",
                title="Kickoff",
                day_range="D0",
                status="completed",
                started_at=datetime(2026, 5, 26, 12, 5, tzinfo=UTC),
            )
        ],
        final_report=AuditFinalReport(
            title="Final",
            uri="report://final",
            summary="done",
            generated_at=datetime(2026, 5, 26, 13, 0, tzinfo=UTC),
        ),
    )
    facade = ForensicExportFacade(
        forensic_uc=None,
        forensic_verify_uc=None,
        audit_engagement_uc=_AuditEngagementUseCase(engagement),
    )

    files = facade._supplemental_files("case-1", "eng-1")

    assert [path for path, _, _ in files] == ["engagement.json", "engagement-report.json"]
    payload = json.loads(files[0][2].decode("utf-8"))
    assert payload["engagement_id"] == "eng-1"
    assert payload["case_ids"] == ["case-1"]
    assert payload["final_report"]["title"] == "Final"


def test_forensic_export_facade_rejects_unlinked_audit_engagement() -> None:
    engagement = AuditEngagement(
        engagement_id="eng-1",
        created_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        status="active",
        customer="Plant A",
        scope="Forensic audit",
        case_ids=["other-case"],
    )
    facade = ForensicExportFacade(
        forensic_uc=None,
        forensic_verify_uc=None,
        audit_engagement_uc=_AuditEngagementUseCase(engagement),
    )

    with pytest.raises(ForensicSupplementalFileError) as exc:
        facade._supplemental_files("case-1", "eng-1")

    assert exc.value.code == "engagement_case_mismatch"
