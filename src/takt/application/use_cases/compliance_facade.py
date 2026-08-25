from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from typing import Any

from takt.application.use_cases.compliance_report import (
    FORENSIC_READINESS_MISSING_CODES,
    REMEDIATION_KIND_DESCRIPTIONS,
)
from takt.application.use_cases.remediation import (
    ListRemediationAttemptsQuery,
    RecordRemediationAttemptCommand,
)
from takt.domain.entities.case import RemediationAttempt
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import SystemClockPort


@dataclass(frozen=True, slots=True)
class RemediationReadinessRecheckResult:
    case_id: str
    ready: bool
    missing_codes: list[str]
    attempt: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class RemediationReadinessHistoryResult:
    case_id: str
    total_matched: int
    entries: list[dict[str, Any]]


class ComplianceFacade:
    def __init__(
        self,
        *,
        repo: CaseRepositoryPort,
        clock: SystemClockPort,
        compliance_report_uc: Any,
        forensic_readiness_uc: Any,
        evidence_checklist_uc: Any,
        remediation_uc: Any,
        remediation_list_uc: Any,
        audit_engagement_uc: Any | None = None,
    ) -> None:
        self._repo = repo
        self._clock = clock
        self._compliance_report_uc = compliance_report_uc
        self._forensic_readiness_uc = forensic_readiness_uc
        self._evidence_checklist_uc = evidence_checklist_uc
        self._remediation_uc = remediation_uc
        self._remediation_list_uc = remediation_list_uc
        self._audit_engagement_uc = audit_engagement_uc

    def data_quality_report(self) -> dict[str, Any]:
        report = self._compliance_report_uc.execute()
        return {
            "generated_at": report.generated_at.astimezone(UTC).isoformat(timespec="seconds"),
            "total_cases": report.total_cases,
            "open_cases": report.open_cases,
            "by_status": report.by_status,
            "by_risk_class": report.by_risk_class,
            "avg_dq_score": report.avg_dq_score,
            "dq_partial_count": report.dq_partial_count,
            "dq_reasons": report.dq_reasons,
            "cases_without_manual_permit": report.cases_without_manual_permit,
            "cases_with_forensic_bundle_audit": report.cases_with_forensic_bundle_audit,
            "high_risk_without_decision": report.high_risk_without_decision,
            "false_positive_count": report.false_positive_count,
            "expected_behavior_count": report.expected_behavior_count,
            "invariant_hits": report.invariant_hits,
            "remediation_attempts_by_kind": report.remediation_attempts_by_kind,
            "remediation_attempts_by_status": report.remediation_attempts_by_status,
            "readiness_flags": [
                {"code": f.code, "ok": f.ok, "value": f.value, "threshold": f.threshold}
                for f in report.readiness_flags
            ],
            "audit_engagements": self._audit_engagements(),
        }

    def forensic_readiness(self, *, only_not_ready: bool = False, missing_code: str = "") -> dict[str, Any]:
        report = self._forensic_readiness_uc.execute(
            only_not_ready=only_not_ready,
            missing_code=missing_code,
        )
        return {
            "generated_at": report.generated_at.astimezone(UTC).isoformat(timespec="seconds"),
            "total_cases": report.total_cases,
            "ready_cases": report.ready_cases,
            "not_ready_cases": report.not_ready_cases,
            "missing_by_code": report.missing_by_code,
            "allowed_missing_codes": sorted(FORENSIC_READINESS_MISSING_CODES),
            "cases": [
                {
                    "case_id": c.case_id,
                    "status": c.status,
                    "risk_class": c.risk_class,
                    "risk_score": c.risk_score,
                    "ready": c.ready,
                    "missing": list(c.missing),
                }
                for c in report.cases
            ],
        }

    def remediation_kinds_catalog(self) -> dict[str, Any]:
        return {
            "kinds": [
                {"kind": kind, "description": description}
                for kind, description in sorted(REMEDIATION_KIND_DESCRIPTIONS.items())
            ]
        }

    def remediations(self, *, case_id: str = "", kind: str = "", status: str = "", limit: int = 100) -> dict[str, Any]:
        attempts = self._remediation_list_uc.execute(
            ListRemediationAttemptsQuery(case_id=case_id, kind=kind, status=status, limit=limit)
        )
        return {"attempts": [self.remediation_attempt_to_detail(a) for a in attempts]}

    def mode_report(self, *, compliance_enabled: bool) -> dict[str, Any]:
        dq_report = self._compliance_report_uc.execute()
        readiness = self._forensic_readiness_uc.execute()
        return {
            "mode": "compliance" if compliance_enabled else "standard",
            "compliance_enabled": compliance_enabled,
            "generated_at": dq_report.generated_at.astimezone(UTC).isoformat(timespec="seconds"),
            "product_boundary": {
                "is_crypto_tool": False,
                "has_active_control": False,
                "requires_operator_final_decision": True,
                "crypto_note": "ТАКТ не является СКЗИ; ГОСТ/КЭП выполняется внешним сертифицированным сервисом при необходимости.",
                "active_control_note": "ТАКТ не выполняет блокировку, останов, переключение, перезагрузку или команды на ПЛК.",
            },
            "reports": {
                "data_quality": "/compliance/data-quality-report",
                "forensic_readiness": "/compliance/forensic-readiness",
                "remediation_kinds": "/compliance/remediation-kinds",
                "remediations": "/compliance/remediations",
            },
            "readiness": {
                "total_cases": readiness.total_cases,
                "ready_cases": readiness.ready_cases,
                "not_ready_cases": readiness.not_ready_cases,
                "missing_by_code": readiness.missing_by_code,
                "dq_partial_count": dq_report.dq_partial_count,
                "high_risk_without_decision": dq_report.high_risk_without_decision,
                "cases_without_manual_permit": dq_report.cases_without_manual_permit,
                "cases_with_forensic_bundle_audit": dq_report.cases_with_forensic_bundle_audit,
            },
            "manual_confirmation": {
                "required_for_high_risk": True,
                "decision_endpoint": "/cases/{case_id}/decision",
                "permit_endpoint": "/cases/{case_id}/manual-permits",
                "reason_required": True,
            },
            "service_desk_context": {
                "supported": True,
                "fields": ["заявка", "наряд", "окно работ", "утверждающий", "основание"],
            },
            "audit": {"operator_history": True, "audit_engagements": self._audit_engagements()},
        }

    def evidence_checklist(self, case_id: str) -> dict[str, Any]:
        checklist = self._evidence_checklist_uc.execute(case_id)
        return {
            "generated_at": checklist.generated_at.astimezone(UTC).isoformat(timespec="seconds"),
            "case_id": checklist.case_id,
            "ready": checklist.ready,
            "remediation_summary": checklist.remediation_summary,
            "items": [
                {
                    "code": item.code,
                    "ok": item.ok,
                    "detail": item.detail,
                    "remediation_kind": item.remediation_kind,
                    "remediation_action": item.remediation_action,
                    "remediation_attempted": item.remediation_attempted,
                    "latest_remediation_status": item.latest_remediation_status,
                }
                for item in checklist.items
            ],
        }

    def record_remediation_attempt(
        self,
        *,
        case_id: str,
        kind: str,
        status: str,
        action: str,
        result: str,
        note: str,
        actor: str,
        request_id: str,
    ) -> dict[str, Any]:
        attempt = self._remediation_uc.execute(
            RecordRemediationAttemptCommand(
                case_id=case_id,
                kind=kind,
                status=status,
                action=action,
                result=result,
                note=note,
                actor=actor,
                request_id=request_id,
            )
        )
        return {"attempt": self.remediation_attempt_to_detail(attempt)}

    def recheck_readiness(
        self,
        *,
        case_id: str,
        attempt_id: str,
        note: str,
        actor: str,
    ) -> RemediationReadinessRecheckResult:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError("case not found")
        checklist = self._evidence_checklist_uc.execute(case_id)
        ready = checklist.ready
        missing_codes = [item.code for item in checklist.items if not item.ok]
        attempt_id = attempt_id.strip()
        note = note.strip()
        updated_attempt: RemediationAttempt | None = None
        if attempt_id:
            updated_attempt = next((item for item in case.remediation_attempts if item.attempt_id == attempt_id), None)
            if updated_attempt is None:
                raise ValueError("remediation attempt not found")
            updated_attempt.readiness_after = ready
            if updated_attempt.status in {"recorded", "started"}:
                updated_attempt.status = "completed" if ready else "failed"
            if not updated_attempt.result:
                updated_attempt.result = "readiness_recheck:ready" if ready else "readiness_recheck:not_ready"
            if note:
                updated_attempt.note = f"{updated_attempt.note} | recheck_note={note}" if updated_attempt.note else note
        case.append_audit(
            (
                "remediation readiness recheck "
                f"ready={ready} missing_codes={','.join(missing_codes) or '-'} "
                f"attempt_id={attempt_id or '-'}"
            ),
            self._clock.now_utc(),
            actor=actor,
        )
        self._repo.save(case)
        return RemediationReadinessRecheckResult(
            case_id=case_id,
            ready=ready,
            missing_codes=missing_codes,
            attempt=self.remediation_attempt_to_detail(updated_attempt) if updated_attempt else None,
        )

    def recheck_history(
        self,
        *,
        case_id: str,
        limit: int = 100,
        offset: int = 0,
        attempt_id: str = "",
        ready: bool | None = None,
    ) -> RemediationReadinessHistoryResult:
        case = self._repo.get(case_id)
        if case is None:
            raise ValueError("case not found")
        out: list[dict[str, Any]] = []
        total_matched = 0
        attempt_id_filter = attempt_id.strip()
        for line in reversed(case.audit_log):
            entry = _recheck_entry_from_audit_line(line)
            if entry is None:
                continue
            if attempt_id_filter and entry["attempt_id"] != attempt_id_filter:
                continue
            if ready is not None and bool(entry["ready"]) != ready:
                continue
            total_matched += 1
            if total_matched <= offset:
                continue
            if len(out) < limit:
                out.append(entry)
        return RemediationReadinessHistoryResult(case_id=case_id, total_matched=total_matched, entries=out)

    @staticmethod
    def remediation_attempt_to_detail(a: RemediationAttempt) -> dict[str, Any]:
        return {
            "attempt_id": a.attempt_id,
            "case_id": a.case_id,
            "kind": a.kind,
            "status": a.status,
            "actor": a.actor,
            "created_at": a.created_at.astimezone(UTC).isoformat(timespec="seconds"),
            "action": a.action,
            "result": a.result,
            "readiness_before": a.readiness_before,
            "readiness_after": a.readiness_after,
            "note": a.note,
            "request_id": a.request_id,
        }

    def _audit_engagements(self) -> dict[str, int]:
        if self._audit_engagement_uc is None:
            return {}
        items = self._audit_engagement_uc.list_all()
        return {
            "total": len(items),
            "active": sum(1 for item in items if item.status == "active"),
            "completed": sum(1 for item in items if item.status == "completed"),
            "with_final_report": sum(1 for item in items if item.final_report is not None),
        }


def _recheck_entry_from_audit_line(line: str) -> dict[str, Any] | None:
    parts = [chunk.strip() for chunk in line.split(" | ")]
    if len(parts) < 2:
        return None
    msg = parts[1]
    pref = "remediation readiness recheck "
    if not msg.startswith(pref):
        return None
    fields: dict[str, str] = {}
    for token in msg[len(pref) :].split():
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        fields[k] = v
    ready_raw = fields.get("ready", "").lower()
    if ready_raw not in {"true", "false"}:
        return None
    missing_raw = fields.get("missing_codes", "-")
    actor = ""
    for p in parts[2:]:
        if p.startswith("actor="):
            actor = p.split("=", 1)[1]
            break
    return {
        "ts": parts[0],
        "ready": ready_raw == "true",
        "missing_codes": [] if missing_raw in {"", "-"} else [x for x in missing_raw.split(",") if x],
        "attempt_id": "" if fields.get("attempt_id", "-") == "-" else fields.get("attempt_id", ""),
        "actor": actor,
    }
