from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore


def test_sqlite_transaction_commits_on_success(tmp_path):
    db = tmp_path / "tx.db"
    store = SqliteCaseStore(db)
    t0 = datetime(2026, 5, 5, 8, 0, tzinfo=UTC)
    c = Case(
        case_id="tx1",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=t0,
    )
    with store.transaction():
        store.save(c)
    store.close()
    store2 = SqliteCaseStore(db)
    assert store2.get("tx1") is not None
    store2.close()


def test_sqlite_transaction_rollbacks_on_error(tmp_path):
    db = tmp_path / "tx2.db"
    store = SqliteCaseStore(db)
    t0 = datetime(2026, 5, 5, 9, 0, tzinfo=UTC)
    c = Case(
        case_id="tx-rollback",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=t0,
    )
    with pytest.raises(RuntimeError, match="boom"):
        with store.transaction():
            store.save(c)
            raise RuntimeError("boom")
    assert store.get("tx-rollback") is None
    store.close()


def test_sqlite_transaction_rejects_use_after_close(tmp_path: Path) -> None:
    store = SqliteCaseStore(tmp_path / "closed.db")
    store.close()
    with pytest.raises(RuntimeError, match="closed"):
        with store.transaction():
            pass
