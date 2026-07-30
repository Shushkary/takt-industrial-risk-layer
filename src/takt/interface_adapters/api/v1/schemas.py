"""Pydantic-схемы surface ``/api/v1``."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EventIn(BaseModel):
    """Входная нормализуемая запись события."""

    source_class: str
    ts: datetime
    raw_ref: str
    host_id: str | None = None
    user_id: str | None = None
    process: str | None = None
    address: str | None = None
    artifact: str | None = None


class ProcessEventOut(BaseModel):
    case_id: str
    created: bool
    content_hash: str


class SearchOut(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: str | None = None
    total_count: int


class DecisionIn(BaseModel):
    decision: str = Field(min_length=1)
    note: str = ""


class HintOut(BaseModel):
    rule_id: str
    recommendation: str
    priority: int


class DeadLetterOut(BaseModel):
    id: int
    raw_data: str
    error_type: str
    error_detail: str
    ts: str
