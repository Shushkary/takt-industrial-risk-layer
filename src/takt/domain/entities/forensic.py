from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ForensicEvidenceItem:
    """One immutable evidence object included into a forensic bundle."""

    path: str
    media_type: str
    sha256: str
    chain_sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ForensicBundle:
    """Forensic package metadata without infrastructure-specific archive details."""

    case_id: str
    generated_at: datetime
    root_hash_sha256: str
    signature_status: str
    process_suitability: str
    signature_ref: str = ""
    items: tuple[ForensicEvidenceItem, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ForensicBundleVerificationIssue:
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class ForensicBundleVerification:
    ok: bool
    case_id: str
    root_hash_sha256: str
    signature_status: str
    checked_items: int
    issues: tuple[ForensicBundleVerificationIssue, ...] = field(default_factory=tuple)
