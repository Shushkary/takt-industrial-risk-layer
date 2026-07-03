from __future__ import annotations

from datetime import timezone

from fastapi import HTTPException

from takt.application.use_cases.audit_engagement import (
    CreateAuditEngagementCommand,
    FinalizeAuditReportCommand,
)
from takt.domain.entities.audit_engagement import AuditEngagement
from takt.interface_adapters.api.dependencies import ApiContext
from takt.interface_adapters.api.schemas.audit_engagements import (
    AuditEngagementCreateBody,
    AuditEngagementOut,
    AuditEngagementReportOut,
    AuditFinalizeReportBody,
    AuditFinalReportOut,
    AuditFindingBody,
    AuditStageAdvanceBody,
    AuditStageOut,
)


def _audit_engagement_out(item: AuditEngagement) -> AuditEngagementOut:
    return AuditEngagementOut(
        engagement_id=item.engagement_id,
        created_at=item.created_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
        status=item.status,
        customer=item.customer,
        scope=item.scope,
        case_ids=list(item.case_ids),
        nda_signed=item.nda_signed,
        evidence_intake_checklist=list(item.evidence_intake_checklist),
        stages=[
            AuditStageOut(
                code=s.code,
                title=s.title,
                day_range=s.day_range,
                status=s.status,
                started_at=(s.started_at.astimezone(timezone.utc).isoformat(timespec="seconds") if s.started_at else None),
                completed_at=(s.completed_at.astimezone(timezone.utc).isoformat(timespec="seconds") if s.completed_at else None),
                note=s.note,
            )
            for s in item.stages
        ],
        findings=list(item.findings),
        final_report=(
            AuditFinalReportOut(
                title=item.final_report.title,
                uri=item.final_report.uri,
                summary=item.final_report.summary,
                generated_at=item.final_report.generated_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
            )
            if item.final_report is not None
            else None
        ),
    )


def register_audit_engagement_routes(ctx: ApiContext) -> None:
    app = ctx.app
    if ctx.audit_engagement_uc is None:
        raise RuntimeError("audit engagement use case is required")
    audit_engagement_uc = ctx.audit_engagement_uc

    @app.post("/audit-engagements", response_model=AuditEngagementOut, tags=["Analytics"])
    def create_audit_engagement(body: AuditEngagementCreateBody):
        item = audit_engagement_uc.create(
            CreateAuditEngagementCommand(
                customer=body.customer,
                scope=body.scope,
                case_ids=list(body.case_ids),
                nda_signed=body.nda_signed,
                evidence_intake_checklist=list(body.evidence_intake_checklist),
            )
        )
        return _audit_engagement_out(item)

    @app.get("/audit-engagements", response_model=list[AuditEngagementOut], tags=["Analytics"])
    def list_audit_engagements():
        return [_audit_engagement_out(item) for item in audit_engagement_uc.list_all()]

    @app.get("/audit-engagements/{engagement_id}", response_model=AuditEngagementOut, tags=["Analytics"])
    def get_audit_engagement(engagement_id: str):
        item = audit_engagement_uc.get(engagement_id)
        if item is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        return _audit_engagement_out(item)

    @app.post("/audit-engagements/{engagement_id}/advance-stage", response_model=AuditEngagementOut, tags=["Analytics"])
    def advance_audit_engagement_stage(engagement_id: str, body: AuditStageAdvanceBody):
        try:
            item = audit_engagement_uc.advance_stage(engagement_id, note=body.note)
        except ValueError as e:
            message = str(e)
            code = 404 if "unknown engagement" in message else 400
            raise HTTPException(status_code=code, detail=message) from e
        return _audit_engagement_out(item)

    @app.post("/audit-engagements/{engagement_id}/findings", response_model=AuditEngagementOut, tags=["Analytics"])
    def add_audit_engagement_finding(engagement_id: str, body: AuditFindingBody):
        try:
            item = audit_engagement_uc.add_finding(engagement_id, body.finding)
        except ValueError as e:
            message = str(e)
            code = 404 if "unknown engagement" in message else 400
            raise HTTPException(status_code=code, detail=message) from e
        return _audit_engagement_out(item)

    @app.post("/audit-engagements/{engagement_id}/final-report", response_model=AuditEngagementOut, tags=["Analytics"])
    def finalize_audit_engagement_report(engagement_id: str, body: AuditFinalizeReportBody):
        try:
            item = audit_engagement_uc.finalize_report(
                engagement_id,
                FinalizeAuditReportCommand(
                    title=body.title,
                    uri=body.uri,
                    summary=body.summary,
                ),
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        return _audit_engagement_out(item)

    @app.get("/audit-engagements/{engagement_id}/export/report.json", response_model=AuditEngagementReportOut, tags=["Analytics"])
    def export_audit_engagement_report(engagement_id: str):
        try:
            report = audit_engagement_uc.export_report(engagement_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail="engagement not found") from e
        return AuditEngagementReportOut(
            format="TAKT Audit Engagement Report",
            generated_at=report.generated_at,
            engagement=_audit_engagement_out(report.engagement),
            findings_count=report.findings_count,
            stages_completed=report.stages_completed,
            stages_total=report.stages_total,
            nda_signed=report.nda_signed,
            has_final_report=report.has_final_report,
        )
