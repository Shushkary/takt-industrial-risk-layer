from __future__ import annotations

from pydantic import BaseModel, Field


class CorrelationReasonBody(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class CorrelationAttachBody(CorrelationReasonBody):
    event_id: str = Field(min_length=1, max_length=256)


class CorrelationMergeBody(CorrelationReasonBody):
    source_case_id: str = Field(min_length=1, max_length=256)


class CorrelationSplitBody(CorrelationReasonBody):
    event_ids: list[str] = Field(min_length=1, max_length=10_000)

