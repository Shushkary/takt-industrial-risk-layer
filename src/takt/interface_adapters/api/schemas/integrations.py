from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class SiemForwardResponse(BaseModel):
    ok: Literal[True] = True
    http_status: int


class SiemForwardAsyncResponse(BaseModel):
    ok: Literal[True] = True
    http_status: int
    async_handled: Literal[True] = Field(serialization_alias="async")


class SiemForwardBody(BaseModel):
    case_id: str
    target_url: str
