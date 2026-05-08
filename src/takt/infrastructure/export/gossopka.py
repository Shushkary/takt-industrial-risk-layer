from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from takt.domain.entities.case import Case
from takt.domain.invariants.catalog import invariant_titles_by_id


def _utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _incident_category(case: Case) -> str:
    hits = set(case.invariant_hits)
    if {"c2_external_dns", "lateral_movement", "brute_force"} & hits:
        return "computer_attack_signs"
    if {"runtime_config_change", "log_wiping", "illegal_function_code"} & hits:
        return "unauthorized_change_or_access"
    if {"physical_invariant_breach", "conflict_logic", "blind_command"} & hits:
        return "industrial_process_disruption_risk"
    return "security_event_requiring_triage"


class _GossopkaInvariantHit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title_ru: str


class _GossopkaManualPermit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    work_order_number: str
    actor: str
    created_at: str
    asset_id: str
    operation: str
    verdict: str
    confidence: float
    rationale: str
    counterfactual: str
    note: str


class _GossopkaRemediationAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attempt_id: str
    kind: str
    status: str
    actor: str
    created_at: str
    action: str
    result: str
    readiness_before: bool | None = None
    readiness_after: bool | None = None
    note: str
    request_id: str


class _GossopkaDecisionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ts: str
    actor: str
    prev_status: str
    next_status: str
    reason: str
    request_id: str


class _GossopkaCardSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: str
    format_version: str
    generated_at: str
    legal_context: dict[str, str]
    incident: dict[str, object]
    critical_information_infrastructure: dict[str, str]
    evidence: dict[str, object]
    operator_actions: dict[str, object]


class _GossopkaTransportSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contract: str = Field(min_length=1)
    contract_version: str = Field(min_length=1)
    generated_at: str
    exchange: dict[str, str]
    payload: _GossopkaCardSchema


class _GossopkaOfficialCardSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: str
    format_version: str
    generated_at: str
    legal_context: dict[str, str]
    exchange_profile: dict[str, str]
    incident: dict[str, object]
    critical_information_infrastructure: dict[str, str]
    evidence: dict[str, object]
    operator_actions: dict[str, object]


class _GossopkaOfficialTransportSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contract: str = Field(min_length=1)
    contract_version: str = Field(min_length=1)
    generated_at: str
    exchange: dict[str, str]
    payload: _GossopkaOfficialCardSchema


def validate_gossopka_card(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        _GossopkaCardSchema.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"invalid gossopka card: {exc}") from exc
    return payload


def _signature_status_default() -> str:
    raw = os.environ.get("TAKT_GOSSOPKA_SIGNATURE_STATUS", "").strip()
    if raw:
        return raw
    strict_mode = os.environ.get("TAKT_FORENSIC_CRYPTO_MODE", "").strip().lower() == "gost_strict"
    if os.environ.get("TAKT_FORENSIC_SIGN_URL", "").strip():
        if strict_mode:
            return "external_gost2012_detached"
        return "external_qualified_detached"
    if strict_mode:
        return "unsigned_mvp"
    if os.environ.get("TAKT_FORENSIC_HMAC_SECRET", "").strip():
        return "hmac_sha256_mvp"
    return "unsigned_mvp"


def case_to_gossopka_card(
    case: Case,
    *,
    generated_at: datetime,
    signature_status: str = "",
) -> dict[str, Any]:
    """MVP machine-readable incident card for ГосСОПКА-oriented handoff.

    This is not a certified exchange format. It is a stable internal JSON contract that preserves
    the fields required to later map the Risk Case into an operator's official ГосСОПКА workflow.
    """
    titles = invariant_titles_by_id()
    manual_permits = [
        {
            "work_order_number": p.work_order_number,
            "actor": p.actor,
            "created_at": _utc_iso(p.created_at),
            "asset_id": p.asset_id,
            "operation": p.operation,
            "verdict": p.verdict,
            "confidence": p.confidence,
            "rationale": p.rationale,
            "counterfactual": p.counterfactual,
            "note": p.note,
        }
        for p in case.manual_permits
    ]
    card = {
        "format": "TAKT-GosSOPKA-MVP",
        "format_version": "0.1",
        "generated_at": _utc_iso(generated_at),
        "legal_context": {
            "uk_rf_article": "274.1",
            "purpose": "operator_and_engineer_defense_evidence",
            "signature_status": signature_status.strip() or _signature_status_default(),
        },
        "incident": {
            "case_id": case.case_id,
            "status": case.status.value,
            "category": _incident_category(case),
            "risk_class": case.risk_class,
            "risk_score": case.risk_score,
            "detected_at": _utc_iso(case.created_at),
            "title": case.title,
            "description": case.xai_summary,
        },
        "critical_information_infrastructure": {
            "object_id": case.primary_asset_id,
            "asset_id": case.primary_asset_id,
            "last_event_source": case.last_event_source,
            "trigger_operation": case.trigger_operation,
        },
        "evidence": {
            "event_ids": list(case.normalized_event_ids),
            "fingerprint": case.burst_fingerprint,
            "invariant_hits": [
                {"id": hit, "title_ru": titles.get(hit, hit)}
                for hit in case.invariant_hits
            ],
            "data_quality": {
                "dq_score": case.dq_score,
                "partial_observability": case.dq_partial,
                "reasons": list(case.dq_reasons),
            },
            "manual_permits": manual_permits,
            "audit_tail": list(case.audit_log[-50:]),
        },
        "operator_actions": {
            "manual_permit_count": len(manual_permits),
            "latest_manual_permit_verdict": manual_permits[-1]["verdict"] if manual_permits else "",
            "remediation_attempts": [
                {
                    "attempt_id": a.attempt_id,
                    "kind": a.kind,
                    "status": a.status,
                    "actor": a.actor,
                    "created_at": _utc_iso(a.created_at),
                    "action": a.action,
                    "result": a.result,
                    "readiness_before": a.readiness_before,
                    "readiness_after": a.readiness_after,
                    "note": a.note,
                    "request_id": a.request_id,
                }
                for a in case.remediation_attempts
            ],
            "decision_records": [
                {
                    "ts": _utc_iso(r.ts),
                    "actor": r.actor,
                    "prev_status": r.prev_status,
                    "next_status": r.next_status,
                    "reason": r.reason,
                    "request_id": r.request_id,
                }
                for r in case.decision_records
            ],
        },
    }
    return validate_gossopka_card(card)


def case_to_gossopka_official_card(
    case: Case,
    *,
    generated_at: datetime,
    signature_status: str = "",
) -> dict[str, Any]:
    base = case_to_gossopka_card(case, generated_at=generated_at, signature_status=signature_status)
    card = {
        **base,
        "format": "GOSSOPKA-INCIDENT-CARD",
        "format_version": "1.0-interop",
        "exchange_profile": {
            "profile": "official_operator_interop",
            "payload_contract": "GOSSOPKA-INCIDENT-CARD",
            "producer": "TAKT",
        },
    }
    try:
        _GossopkaOfficialCardSchema.model_validate(card)
    except ValidationError as exc:
        raise ValueError(f"invalid official gossopka card: {exc}") from exc
    return card


def case_to_gossopka_transport_payload(
    case: Case,
    *,
    generated_at: datetime,
    exchange_mode: str = "pull_http_json",
) -> dict[str, Any]:
    envelope = {
        "contract": "TAKT-GosSOPKA-Transport",
        "contract_version": "0.1",
        "generated_at": _utc_iso(generated_at),
        "exchange": {
            "mode": exchange_mode,
            "content_type": "application/json",
            "encoding": "utf-8",
        },
        "payload": case_to_gossopka_card(case, generated_at=generated_at),
    }
    try:
        _GossopkaTransportSchema.model_validate(envelope)
    except ValidationError as exc:
        raise ValueError(f"invalid gossopka transport payload: {exc}") from exc
    return envelope


def case_to_gossopka_official_transport_payload(
    case: Case,
    *,
    generated_at: datetime,
    exchange_mode: str = "pull_http_json",
    signature_status: str = "",
) -> dict[str, Any]:
    envelope = {
        "contract": "GOSSOPKA-TRANSPORT-INTEROP",
        "contract_version": "1.0",
        "generated_at": _utc_iso(generated_at),
        "exchange": {
            "mode": exchange_mode,
            "content_type": "application/json",
            "encoding": "utf-8",
        },
        "payload": case_to_gossopka_official_card(
            case,
            generated_at=generated_at,
            signature_status=signature_status,
        ),
    }
    try:
        _GossopkaOfficialTransportSchema.model_validate(envelope)
    except ValidationError as exc:
        raise ValueError(f"invalid official gossopka transport payload: {exc}") from exc
    return envelope
