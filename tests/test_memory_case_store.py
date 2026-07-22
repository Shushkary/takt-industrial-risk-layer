from __future__ import annotations

from datetime import datetime, timedelta, timezone

from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.stores.memory import InMemoryCaseStore


def test_in_memory_find_open_by_fingerprint_skips_confirmed():
    repo = InMemoryCaseStore()
    t0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    fp = "plc_polling|asset-z|POLL"
    closed = Case(
        case_id="c-done",
        status=CaseStatus.CONFIRMED,
        title="t",
        risk_class="LOW",
        risk_score=0.2,
        created_at=t0,
        burst_fingerprint=fp,
        primary_asset_id="asset-z",
        trigger_operation="POLL",
    )
    repo.save(closed)
    assert repo.find_open_by_fingerprint(fp) is None


def test_in_memory_find_open_by_fingerprint_returns_newest_open_case():
    repo = InMemoryCaseStore()
    t0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    fp = "plc_polling|asset-z|POLL"
    older = Case(
        case_id="older",
        status=CaseStatus.NEW,
        title="old",
        risk_class="LOW",
        risk_score=0.2,
        created_at=t0,
        burst_fingerprint=fp,
    )
    newer = Case(
        case_id="newer",
        status=CaseStatus.TRIAGE,
        title="new",
        risk_class="MEDIUM",
        risk_score=0.4,
        created_at=t0 + timedelta(minutes=1),
        burst_fingerprint=fp,
    )
    repo.save(older)
    repo.save(newer)

    found = repo.find_open_by_fingerprint(fp)

    assert found is not None
    assert found.case_id == "newer"


def test_in_memory_store_returns_snapshots_not_live_objects():
    repo = InMemoryCaseStore()
    t0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    case = Case(
        case_id="snapshot",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.2,
        created_at=t0,
        normalized_event_ids=["e1"],
    )
    repo.save(case)
    case.normalized_event_ids.append("external")

    loaded = repo.get("snapshot")
    assert loaded is not None
    assert loaded.normalized_event_ids == ["e1"]

    loaded.normalized_event_ids.append("mutated-copy")
    loaded_again = repo.get("snapshot")
    assert loaded_again is not None
    assert loaded_again.normalized_event_ids == ["e1"]


def test_in_memory_find_open_by_fingerprint_index_ignores_out_of_order_older_save():
    """Индекс `_open_by_fingerprint` не должен откатываться на более старый кейс
    при сохранении в другом порядке, чем created_at."""
    repo = InMemoryCaseStore()
    t0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    fp = "plc_polling|asset-z|POLL"
    newer = Case(
        case_id="newer",
        status=CaseStatus.NEW,
        title="new",
        risk_class="MEDIUM",
        risk_score=0.4,
        created_at=t0 + timedelta(minutes=1),
        burst_fingerprint=fp,
    )
    older = Case(
        case_id="older",
        status=CaseStatus.NEW,
        title="old",
        risk_class="LOW",
        risk_score=0.2,
        created_at=t0,
        burst_fingerprint=fp,
    )
    repo.save(newer)
    repo.save(older)

    found = repo.find_open_by_fingerprint(fp)
    assert found is not None
    assert found.case_id == "newer"


def test_in_memory_find_open_by_fingerprint_index_drops_entry_when_case_closes():
    repo = InMemoryCaseStore()
    t0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    fp = "plc_polling|asset-z|POLL"
    case = Case(
        case_id="c1",
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.2,
        created_at=t0,
        burst_fingerprint=fp,
    )
    repo.save(case)
    assert repo.find_open_by_fingerprint(fp) is not None

    case.status = CaseStatus.CONFIRMED
    repo.save(case)
    assert repo.find_open_by_fingerprint(fp) is None

    reopened = Case(
        case_id="c2",
        status=CaseStatus.TRIAGE,
        title="t2",
        risk_class="LOW",
        risk_score=0.2,
        created_at=t0 + timedelta(hours=1),
        burst_fingerprint=fp,
    )
    repo.save(reopened)
    found = repo.find_open_by_fingerprint(fp)
    assert found is not None
    assert found.case_id == "c2"


def test_in_memory_find_open_by_fingerprint_scales_across_many_distinct_fingerprints():
    """Регрессия по производительности O(1) поиска: не должно требовать
    сканирования всего хранилища при большом числе не связанных кейсов."""
    repo = InMemoryCaseStore()
    t0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
    n = 5_000
    for i in range(n):
        repo.save(
            Case(
                case_id=f"case-{i:05d}",
                status=CaseStatus.NEW,
                title="t",
                risk_class="LOW",
                risk_score=0.1,
                created_at=t0 + timedelta(seconds=i),
                burst_fingerprint=f"fp-{i:05d}",
            )
        )
    found = repo.find_open_by_fingerprint(f"fp-{n - 1:05d}")
    assert found is not None
    assert found.case_id == f"case-{n - 1:05d}"
    assert repo.find_open_by_fingerprint("fp-does-not-exist") is None
