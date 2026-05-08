from __future__ import annotations

from dataclasses import dataclass

from takt.application.use_cases.compliance_report import REMEDIATION_KIND_DESCRIPTIONS
from takt.domain.entities.case import RemediationAttempt
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.domain.ports.system_ports import IdProviderPort, SystemClockPort


@dataclass(frozen=True, slots=True)
class RecordRemediationAttemptCommand:
    case_id: str
    kind: str
    actor: str
    status: str = "recorded"
    action: str = ""
    result: str = ""
    note: str = ""
    request_id: str = ""


@dataclass(frozen=True, slots=True)
class ListRemediationAttemptsQuery:
    case_id: str = ""
    kind: str = ""
    status: str = ""
    limit: int = 100


class RecordRemediationAttemptUseCase:
    def __init__(self, repo: CaseRepositoryPort, clock: SystemClockPort, ids: IdProviderPort) -> None:
        self._repo = repo
        self._clock = clock
        self._ids = ids

    def execute(self, cmd: RecordRemediationAttemptCommand) -> RemediationAttempt:
        case = self._repo.get(cmd.case_id)
        if case is None:
            raise ValueError(f"unknown case {cmd.case_id}")
        kind = cmd.kind.strip()
        if kind not in REMEDIATION_KIND_DESCRIPTIONS:
            allowed = ", ".join(sorted(REMEDIATION_KIND_DESCRIPTIONS))
            raise ValueError(f"invalid remediation kind; use one of: {allowed}")
        status = cmd.status.strip().lower() or "recorded"
        if status not in {"recorded", "started", "completed", "failed"}:
            raise ValueError("invalid remediation status; use one of: completed, failed, recorded, started")
        readiness_before = _readiness_ok(case)
        attempt = RemediationAttempt(
            attempt_id=self._ids.new_case_id_short(),
            case_id=case.case_id,
            kind=kind,
            status=status,
            actor=cmd.actor.strip() or "unknown",
            created_at=self._clock.now_utc(),
            action=cmd.action.strip(),
            result=cmd.result.strip(),
            readiness_before=readiness_before,
            readiness_after=_readiness_ok(case),
            note=cmd.note.strip(),
            request_id=cmd.request_id.strip(),
        )
        case.remediation_attempts.append(attempt)
        case.append_audit(
            (
                f"remediation attempt kind={attempt.kind} status={attempt.status} "
                f"action={attempt.action or '-'} result={attempt.result or '-'} "
                f"readiness_before={attempt.readiness_before} readiness_after={attempt.readiness_after}"
            ),
            attempt.created_at,
            actor=attempt.actor,
        )
        self._repo.save(case)
        return attempt


class ListRemediationAttemptsUseCase:
    def __init__(self, repo: CaseRepositoryPort) -> None:
        self._repo = repo

    def execute(self, query: ListRemediationAttemptsQuery) -> tuple[RemediationAttempt, ...]:
        kind = query.kind.strip()
        if kind and kind not in REMEDIATION_KIND_DESCRIPTIONS:
            allowed = ", ".join(sorted(REMEDIATION_KIND_DESCRIPTIONS))
            raise ValueError(f"invalid remediation kind; use one of: {allowed}")
        status = query.status.strip().lower()
        if status and status not in {"recorded", "started", "completed", "failed"}:
            raise ValueError("invalid remediation status; use one of: completed, failed, recorded, started")
        case_id = query.case_id.strip()
        limit = max(1, min(query.limit, 500))
        attempts = [
            attempt
            for case in self._repo.list_all()
            if not case_id or case.case_id == case_id
            for attempt in case.remediation_attempts
            if (not kind or attempt.kind == kind) and (not status or attempt.status == status)
        ]
        attempts.sort(key=lambda item: (item.created_at, item.attempt_id), reverse=True)
        return tuple(attempts[:limit])


def _is_high_risk(case) -> bool:
    return case.risk_class.upper() in {"HIGH", "CRITICAL"} or case.risk_score >= 0.75


def _readiness_ok(case) -> bool:
    if case.dq_partial:
        return False
    if not case.invariant_hits:
        return False
    if _is_high_risk(case) and not case.decision_records:
        return False
    if not case.manual_permits:
        return False
    if not any("forensic bundle generated root_hash=" in line for line in case.audit_log):
        return False
    return True
