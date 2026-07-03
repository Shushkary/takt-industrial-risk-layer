from __future__ import annotations

from typing import Any

from takt.domain.ports.case_repository import CaseRepositoryPort


class AuditLedgerFacade:
    def __init__(self, repo: CaseRepositoryPort) -> None:
        self._repo = repo

    def verify_case_ledger(self, case_id: str) -> Any:
        verifier = getattr(self._repo, "verify_audit_ledger", None)
        if not callable(verifier):
            raise NotImplementedError("audit ledger verification is unavailable for this storage")
        if self._repo.get(case_id) is None:
            raise ValueError("case not found")
        return verifier(case_id)

    def verify_operation_ledger(self, stream_key: str = "") -> Any:
        verifier = getattr(self._repo, "verify_operation_ledger", None)
        if not callable(verifier):
            raise NotImplementedError("operation audit ledger verification is unavailable for this storage")
        return verifier(stream_key.strip())
