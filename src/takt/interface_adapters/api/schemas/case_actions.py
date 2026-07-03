from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from takt.domain.entities.case import CaseStatus


class CaseDecisionResponse(BaseModel):
    ok: Literal[True] = True
    case_id: str
    status: str


class DecisionBody(BaseModel):
    status: CaseStatus
    reason: str = ""


class ManualPermitBody(BaseModel):
    work_order_number: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(default="", max_length=256)
    operation: str = Field(default="", max_length=256)
    action_class: str = Field(default="", max_length=256)
    executor: str = Field(default="", max_length=256)
    approver: str = Field(default="", max_length=256)
    valid_from: str = Field(default="", max_length=128)
    valid_to: str = Field(default="", max_length=128)
    document_status: str = Field(default="", max_length=128)
    restrictions: str = Field(default="", max_length=1000)
    note: str = Field(default="", max_length=2000)


class OperatorActionBody(BaseModel):
    reason: str = Field(default="", max_length=2000)
    note: str = Field(default="", max_length=2000)


class FormalVerdictConfirmationBody(BaseModel):
    verdict: Literal["легитимное", "нелегитимное", "неопределённое"]
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=2000)
    note: str = Field(default="", max_length=2000)


class RemediationAttemptBody(BaseModel):
    kind: str = Field(min_length=1, max_length=128)
    status: str = Field(default="recorded", max_length=64)
    action: str = Field(default="", max_length=512)
    result: str = Field(default="", max_length=2000)
    note: str = Field(default="", max_length=2000)
