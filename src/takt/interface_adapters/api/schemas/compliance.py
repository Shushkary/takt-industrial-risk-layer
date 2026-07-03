from __future__ import annotations

from pydantic import BaseModel, Field


class RemediationAttemptBody(BaseModel):
    kind: str = Field(min_length=1, max_length=128)
    status: str = Field(default="recorded", max_length=64)
    action: str = Field(default="", max_length=512)
    result: str = Field(default="", max_length=2000)
    note: str = Field(default="", max_length=2000)
