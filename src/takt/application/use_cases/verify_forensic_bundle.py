from __future__ import annotations

from takt.domain.entities.forensic import ForensicBundleVerification
from takt.domain.ports.forensic_bundle import ForensicBundleVerifierPort


class VerifyForensicBundleUseCase:
    """Application use case for offline-style bundle integrity verification."""

    def __init__(self, verifier: ForensicBundleVerifierPort) -> None:
        self._verifier = verifier

    def execute(self, archive_bytes: bytes) -> ForensicBundleVerification:
        return self._verifier.verify_bundle(archive_bytes)

