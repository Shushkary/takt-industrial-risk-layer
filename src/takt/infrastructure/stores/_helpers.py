from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

from takt.domain.entities.case import Case


def clone_case(case: Case) -> Case:
    return deepcopy(case)


def case_created_at_utc(case: Case) -> datetime:
    dt = case.created_at
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_expected_pair(asset_id: str, operation: str) -> tuple[str, str] | None:
    aid = asset_id.strip().lower()
    op = operation.strip().upper()
    if not aid or not op:
        return None
    return aid, op
