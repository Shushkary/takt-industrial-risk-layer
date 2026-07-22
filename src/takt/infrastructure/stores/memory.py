from __future__ import annotations

import threading
from copy import deepcopy
from datetime import UTC, datetime

from takt.domain.entities.audit_engagement import AuditEngagement
from takt.domain.entities.case import Case, CaseStatus
from takt.domain.ports.audit_engagement_repository import AuditEngagementRepositoryPort
from takt.domain.ports.baseline import ExpectedBehaviorPort
from takt.domain.ports.case_repository import CaseRepositoryPort
from takt.infrastructure.stores._helpers import (
    case_created_at_utc,
    clone_case,
    normalize_expected_pair,
)

_OPEN_STATUSES = (CaseStatus.NEW, CaseStatus.TRIAGE)


class InMemoryCaseStore(CaseRepositoryPort):
    """
    Индекс **`_open_by_fingerprint`** (fingerprint -> case_id) держит
    `find_open_by_fingerprint` на O(1) вместо линейного скана всех кейсов
    на каждое входящее событие — при 100k+ событиях за прогон бэктеста
    линейный скан растущего хранилища даёт O(n²).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_id: dict[str, Case] = {}
        self._open_by_fingerprint: dict[str, str] = {}

    @staticmethod
    def _case_fingerprints(case: Case) -> tuple[str, ...]:
        return tuple(dict.fromkeys([case.burst_fingerprint, *case.correlation_fingerprints]))

    def _reindex_locked(self, case: Case) -> None:
        for fp in self._case_fingerprints(case):
            if not fp:
                continue
            current_id = self._open_by_fingerprint.get(fp)
            if case.status in _OPEN_STATUSES:
                if current_id is None or current_id == case.case_id:
                    self._open_by_fingerprint[fp] = case.case_id
                    continue
                current_case = self._by_id.get(current_id)
                if current_case is None or case_created_at_utc(case) >= case_created_at_utc(current_case):
                    self._open_by_fingerprint[fp] = case.case_id
            elif current_id == case.case_id:
                del self._open_by_fingerprint[fp]

    def save(self, case: Case) -> None:
        with self._lock:
            self._by_id[case.case_id] = clone_case(case)
            self._reindex_locked(case)

    def get(self, case_id: str) -> Case | None:
        with self._lock:
            case = self._by_id.get(case_id)
            return None if case is None else clone_case(case)

    def list_all(self) -> list[Case]:
        with self._lock:
            cases = [clone_case(case) for case in self._by_id.values()]
        return sorted(cases, key=case_created_at_utc, reverse=True)

    def find_open_by_fingerprint(self, fingerprint: str) -> Case | None:
        with self._lock:
            case_id = self._open_by_fingerprint.get(fingerprint)
            if case_id is None:
                return None
            case = self._by_id.get(case_id)
            if case is None or case.status not in _OPEN_STATUSES:
                return None
            return clone_case(case)

    def find_open_by_fingerprints(self, fingerprints: list[str]) -> tuple[Case, str] | None:
        for fingerprint in fingerprints:
            case = self.find_open_by_fingerprint(fingerprint)
            if case is not None:
                return case, fingerprint
        return None


class InMemoryIdempotencyStore:
    """In-memory кеш идемпотентности (при **storage.backend: memory**)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._m: dict[str, tuple[str, str, str]] = {}

    def idempotency_delete_expired(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self._lock:
            dead = [k for k, (_, _, exp) in self._m.items() if exp < now]
            for k in dead:
                del self._m[k]

    def idempotency_get(self, key: str) -> tuple[str, str] | None:
        with self._lock:
            t = self._m.get(key)
            if t is None:
                return None
            h, js, exp = t
            now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            if exp < now:
                del self._m[key]
                return None
            return h, js

    def idempotency_put(self, key: str, body_hash: str, response_json: str, expires_at_iso: str) -> None:
        with self._lock:
            self._m[key] = (body_hash, response_json, expires_at_iso)


class InMemoryExpectedBehavior(ExpectedBehaviorPort):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._pairs: set[tuple[str, str]] = set()

    def mark_expected(self, asset_id: str, operation: str) -> None:
        pair = normalize_expected_pair(asset_id, operation)
        if pair is None:
            return
        with self._lock:
            self._pairs.add(pair)

    def is_expected(self, asset_id: str, operation: str) -> bool:
        pair = normalize_expected_pair(asset_id, operation)
        if pair is None:
            return False
        with self._lock:
            return pair in self._pairs


class InMemoryAuditEngagementStore(AuditEngagementRepositoryPort):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_id: dict[str, AuditEngagement] = {}

    def save(self, engagement: AuditEngagement) -> None:
        with self._lock:
            self._by_id[engagement.engagement_id] = deepcopy(engagement)

    def get(self, engagement_id: str) -> AuditEngagement | None:
        with self._lock:
            item = self._by_id.get(engagement_id)
            return None if item is None else deepcopy(item)

    def list_all(self) -> list[AuditEngagement]:
        with self._lock:
            items = [deepcopy(item) for item in self._by_id.values()]
        return sorted(items, key=lambda i: i.created_at, reverse=True)
