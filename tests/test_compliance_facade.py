from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from takt.application.use_cases.compliance_facade import ComplianceFacade
from takt.domain.entities.audit_engagement import AuditEngagement, AuditFinalReport


class _ComplianceReportUseCase:
    def execute(self):
        return SimpleNamespace(
            generated_at=datetime(2026, 5, 26, 12, 0, tzinfo=timezone.utc),
            total_cases=0,
            open_cases=0,
            by_status={},
            by_risk_class={},
            avg_dq_score=1.0,
            dq_partial_count=0,
            dq_reasons={},
            cases_without_manual_permit=0,
            cases_with_forensic_bundle_audit=0,
            high_risk_without_decision=0,
            false_positive_count=0,
            expected_behavior_count=0,
            invariant_hits={},
            remediation_attempts_by_kind={},
            remediation_attempts_by_status={},
            readiness_flags=[],
        )


class _ForensicReadinessUseCase:
    def execute(self, **_kwargs):
        return SimpleNamespace(
            generated_at=datetime(2026, 5, 26, 12, 0, tzinfo=timezone.utc),
            total_cases=0,
            ready_cases=0,
            not_ready_cases=0,
            missing_by_code={},
            cases=[],
        )


class _AuditEngagementUseCase:
    def list_all(self):
        return [
            AuditEngagement(
                engagement_id="active-1",
                created_at=datetime(2026, 5, 26, 12, 0, tzinfo=timezone.utc),
                status="active",
                customer="Plant A",
                scope="Audit",
            ),
            AuditEngagement(
                engagement_id="done-1",
                created_at=datetime(2026, 5, 26, 12, 0, tzinfo=timezone.utc),
                status="completed",
                customer="Plant A",
                scope="Audit",
                final_report=AuditFinalReport(
                    title="Final",
                    uri="report://final",
                    summary="done",
                    generated_at=datetime(2026, 5, 26, 13, 0, tzinfo=timezone.utc),
                ),
            ),
        ]


def _facade() -> ComplianceFacade:
    return ComplianceFacade(
        repo=None,  # type: ignore[arg-type]
        clock=None,  # type: ignore[arg-type]
        compliance_report_uc=_ComplianceReportUseCase(),
        forensic_readiness_uc=_ForensicReadinessUseCase(),
        evidence_checklist_uc=None,
        remediation_uc=None,
        remediation_list_uc=None,
        audit_engagement_uc=_AuditEngagementUseCase(),
    )


def test_compliance_facade_summarizes_audit_engagements_in_mode_report() -> None:
    body = _facade().mode_report(compliance_enabled=True)

    assert body["audit"]["audit_engagements"] == {
        "total": 2,
        "active": 1,
        "completed": 1,
        "with_final_report": 1,
    }


def test_compliance_facade_summarizes_audit_engagements_in_data_quality_report() -> None:
    body = _facade().data_quality_report()

    assert body["audit_engagements"]["total"] == 2
    assert body["audit_engagements"]["with_final_report"] == 1
