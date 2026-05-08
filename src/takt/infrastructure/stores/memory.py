from __future__ import annotations

from copy import deepcopy
import threading
from datetime import datetime, timezone

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


class InMemoryCaseStore(CaseRepositoryPort):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_id: dict[str, Case] = {}

    def save(self, case: Case) -> None:
        with self._lock:
            self._by_id[case.case_id] = clone_case(case)

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
            candidates = [
                case
                for case in self._by_id.values()
                if case.burst_fingerprint == fingerprint
                and case.status in (CaseStatus.NEW, CaseStatus.TRIAGE)
            ]
            if not candidates:
                return None
            return clone_case(max(candidates, key=case_created_at_utc))


class InMemoryIdempotencyStore:
    """In-memory кеш идемпотентности (при **storage.backend: memory**)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._m: dict[str, tuple[str, str, str]] = {}

    def idempotency_delete_expired(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
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
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
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
