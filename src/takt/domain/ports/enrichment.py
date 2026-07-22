from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class ReputationVerdict:
    indicator_type: str
    value: str
    verdict: str
    source: str
    checked_at: datetime
    ttl_seconds: int = 0
    details: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class SandboxSubmission:
    task_id: str
    submitted_at: datetime
    status: str


@dataclass(frozen=True, slots=True)
class SandboxVerdict:
    task_id: str
    verdict: str
    checked_at: datetime
    details: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class DecodedValue:
    kind: str
    value: str
    success: bool
    error: str = ""


@runtime_checkable
class ReputationPort(Protocol):
    def check(self, *, indicator_type: str, value: str, actor: str) -> ReputationVerdict: ...


@runtime_checkable
class SandboxPort(Protocol):
    def submit_file(self, *, filename: str, content: bytes, actor: str) -> SandboxSubmission: ...

    def verdict(self, *, task_id: str, actor: str) -> SandboxVerdict: ...


@runtime_checkable
class DecoderServicePort(Protocol):
    def decode(self, value: str) -> list[DecodedValue]: ...
