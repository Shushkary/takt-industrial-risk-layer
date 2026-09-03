"""`SqliteCaseStore.save` пишет только изменившиеся ключи корреляции.

До исправления `save()` на каждый вызов делал `DELETE FROM case_correlation_keys WHERE
case_id = ?`, а затем заново вставлял все ключи дела — `O(число ключей дела)` на **каждое**
событие, независимо от того, появился ли у дела хоть один новый ключ. Ключи практически
всегда только накапливаются, поэтому на растущем деле полная перезапись росла вместе с ним:
замер на корпусе INC-002 (`tests/fixtures/pt_techlab/inc_002/`) при включённой
SOC-корреляции показал рост с 27 до 222 мс на событие, а полный приём 1030 событий — с 31
до 268 секунд.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from takt.domain.entities.case import Case, CaseStatus
from takt.infrastructure.stores.sqlite_store import SqliteCaseStore


def _case(case_id: str, *, burst: str, corr: list[str], created_at: datetime) -> Case:
    return Case(
        case_id=case_id,
        status=CaseStatus.NEW,
        title="t",
        risk_class="LOW",
        risk_score=0.1,
        created_at=created_at,
        burst_fingerprint=burst,
        correlation_fingerprints=list(corr),
    )


def _keys_for_case(repo: SqliteCaseStore, case_id: str) -> set[str]:
    rows = repo._conn.execute(
        "SELECT fingerprint FROM case_correlation_keys WHERE case_id = ?", (case_id,)
    ).fetchall()
    return {row[0] for row in rows}


def test_growing_correlation_keys_stay_indexed(tmp_path) -> None:
    """Каждое новое сохранение добавляет только новые ключи — старые остаются в индексе."""
    repo = SqliteCaseStore(tmp_path / "cases.sqlite3")
    try:
        t0 = datetime(2026, 9, 1, 6, 0, tzinfo=UTC)
        repo.save(_case("c-1", burst="burst-1", corr=["corr:host:aaa"], created_at=t0))
        assert _keys_for_case(repo, "c-1") == {"burst-1", "corr:host:aaa"}

        repo.save(
            _case(
                "c-1", burst="burst-1", corr=["corr:host:aaa", "corr:hash:bbb"],
                created_at=t0 + timedelta(minutes=1),
            )
        )
        assert _keys_for_case(repo, "c-1") == {"burst-1", "corr:host:aaa", "corr:hash:bbb"}
        assert repo.find_open_by_fingerprint("burst-1") is not None
        found = repo.find_open_by_fingerprints(["corr:hash:bbb"])
        assert found is not None and found[0].case_id == "c-1"
    finally:
        repo.close()


def test_removed_fingerprint_is_dropped_from_the_index(tmp_path) -> None:
    """Ключ, которого у дела больше нет, перестаёт находить его в поиске.

    В текущем коде продукта ключи только накапливаются, но индекс не должен полагаться на
    это как на инвариант: удаление ключа должно снимать его из `case_correlation_keys`,
    а не оставлять устаревшую запись, указывающую на дело, которое по этому ключу больше
    не собирается.
    """
    repo = SqliteCaseStore(tmp_path / "cases.sqlite3")
    try:
        t0 = datetime(2026, 9, 1, 6, 0, tzinfo=UTC)
        repo.save(_case("c-1", burst="burst-1", corr=["corr:host:aaa"], created_at=t0))
        repo.save(_case("c-1", burst="burst-1", corr=[], created_at=t0))

        assert _keys_for_case(repo, "c-1") == {"burst-1"}
        assert repo.find_open_by_fingerprints(["corr:host:aaa"]) is None
    finally:
        repo.close()


def test_unchanged_fingerprints_skip_the_reindex(tmp_path) -> None:
    """Сохранение без изменения состава ключей не трогает `case_correlation_keys`.

    `sqlite3.Connection.execute` — метод расширения на C-уровне, monkeypatch на самом
    соединении Python не даёт (атрибут только для чтения); executed-SQL наблюдается через
    штатный `set_trace_callback`.
    """
    repo = SqliteCaseStore(tmp_path / "cases.sqlite3")
    try:
        t0 = datetime(2026, 9, 1, 6, 0, tzinfo=UTC)
        case = _case("c-1", burst="burst-1", corr=["corr:host:aaa"], created_at=t0)
        repo.save(case)

        statements: list[str] = []
        repo._conn.set_trace_callback(statements.append)
        try:
            case.title = "изменился только заголовок"
            repo.save(case)
        finally:
            repo._conn.set_trace_callback(None)

        touching_keys = [sql for sql in statements if "case_correlation_keys" in sql]
        assert touching_keys == [], f"индекс ключей корреляции переписан без нужды: {touching_keys}"
    finally:
        repo.close()


def test_reindex_cost_does_not_grow_with_case_size(tmp_path) -> None:
    """Стоимость сохранения перестаёт расти вместе с числом накопленных ключей дела.

    До исправления время `save()` росло линейно с числом уже записанных ключей дела —
    каждое новое событие переписывало все прежние. После исправления оно должно оставаться
    примерно постоянным: сохранение с одним новым ключом стоит одинаково что на первом
    вызове, что на сотом.
    """
    repo = SqliteCaseStore(tmp_path / "cases.sqlite3")
    try:
        t0 = datetime(2026, 9, 1, 6, 0, tzinfo=UTC)
        keys: list[str] = []

        def _save_with_one_new_key(index: int) -> float:
            keys.append(f"corr:host:{index:04d}")
            case = _case("c-1", burst="burst-1", corr=list(keys), created_at=t0 + timedelta(seconds=index))
            start = time.perf_counter()
            repo.save(case)
            return time.perf_counter() - start

        for index in range(20):
            _save_with_one_new_key(index)

        durations = [_save_with_one_new_key(index) for index in range(20, 220)]
        early = sum(durations[:20]) / 20
        late = sum(durations[-20:]) / 20

        # O(размер дела) дало бы рост в разы на 220 накопленных ключах; здесь допускается
        # запас на дрожание таймера, а не на квадратичный рост.
        assert late < early * 3, f"стоимость растёт с размером дела: {early:.5f} с -> {late:.5f} с"
    finally:
        repo.close()
