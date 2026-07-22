from __future__ import annotations

from pydantic import BaseModel, Field


class ArtifactBody(BaseModel):
    type: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=4096)
    host_id: str = Field(default="", max_length=512)
    verification_status: str = Field(default="unverified", max_length=64)


class FindingBody(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    event_ids: list[str] = Field(default_factory=list, max_length=10_000)
    artifacts: list[ArtifactBody] = Field(default_factory=list, max_length=1000)
