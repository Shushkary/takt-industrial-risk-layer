from __future__ import annotations

from pydantic import BaseModel, Field


class DecodeBody(BaseModel):
    value: str = Field(min_length=1, max_length=65536)


class DecodedValueOut(BaseModel):
    kind: str
    value: str
    success: bool
    error: str = ""


class DecodeResponse(BaseModel):
    input: str
    decodings: list[DecodedValueOut]
