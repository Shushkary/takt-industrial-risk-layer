"""Очередь сигналов сборки: приём отмечает работу, отдельный процесс её выполняет.

Сборка инцидента стоит полного обхода хранилища дел — на 8000 дел это 1,8 с. Пока прогон
идёт внутри запроса приёма, эти секунды платит приём. Очередь разрывает связь: приём делает
одну короткую запись (`UPDATE ... SET pending = pending + 1`), а прогон выполняет
`python -m takt.tools.assembly_worker` в своём процессе.

Очередь лежит в той же базе, что дела и события: отдельный брокер потребовал бы новой
зависимости в SBOM и ещё одного сервиса при сертификации, а сигнал здесь — счётчик, который
переживает перезапуск воркера и не нуждается в доставке «ровно один раз». Точное число
сигналов не важно: любой ненулевой счётчик означает «в потоке появилось срабатывание,
инциденты нужно пересобрать».

Аренда в той же строке не даёт двум воркерам гонять один и тот же прогон. Она не вечная:
воркер продлевает её каждым циклом, поэтому упавший процесс освобождает сборку сам, без
ручного снятия блокировки.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

from takt.infrastructure.stores.sqlite_connection import (
    checkpoint_wal_best_effort as _checkpoint_wal_best_effort,
)
from takt.infrastructure.stores.sqlite_connection import (
    configure_sqlite_connection as _configure_sqlite_connection,
)
from takt.infrastructure.stores.sqlite_connection import (
    dt_to_sql as _dt_to_sql,
)
from takt.infrastructure.stores.sqlite_schema import ensure_assembly_queue_schema


class SqliteAssemblyQueue:
    """Единственная строка со счётчиком сигналов и арендой воркера."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._closed = False
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        _configure_sqlite_connection(self._conn)
        ensure_assembly_queue_schema(self._conn)

    @property
    def database_path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            _checkpoint_wal_best_effort(self._conn)
            self._conn.close()
            self._closed = True

    # --- сигналы ----------------------------------------------------------

    def note_hits(self, count: int = 1) -> None:
        """Отмечает срабатывания, из-за которых инциденты нужно пересобрать."""
        if count <= 0:
            return
        with self._lock:
            self._raise_if_closed()
            self._conn.execute(
                "UPDATE assembly_queue SET pending = pending + ? WHERE id = 1", (int(count),)
            )

    def pending(self) -> int:
        """Сколько сигналов ждёт прогона. Для наблюдения; работу забирает `take_pending`."""
        with self._lock:
            self._raise_if_closed()
            row = self._conn.execute("SELECT pending FROM assembly_queue WHERE id = 1").fetchone()
            return 0 if row is None else int(row["pending"])

    def take_pending(self) -> int:
        """Забирает накопленные сигналы и обнуляет счётчик.

        Чтение и обнуление — одной транзакцией: иначе срабатывание, пришедшее между ними,
        потерялось бы, и поток остался бы без инцидента до следующего срабатывания.
        """
        with self._lock:
            self._raise_if_closed()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT pending FROM assembly_queue WHERE id = 1").fetchone()
                taken = 0 if row is None else int(row["pending"])
                if taken:
                    self._conn.execute("UPDATE assembly_queue SET pending = 0 WHERE id = 1")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            return taken

    # --- аренда воркера ---------------------------------------------------

    def acquire_lease(self, *, owner: str, now: datetime, ttl_sec: float) -> bool:
        """Берёт аренду, если она свободна, просрочена или уже принадлежит этому воркеру.

        Срок хранится текстом в UTC (`dt_to_sql`), поэтому сравнение строк здесь — сравнение
        моментов времени: одинаковый формат и одинаковая зона у всех записей.
        """
        deadline = _dt_to_sql(now + timedelta(seconds=max(0.0, ttl_sec)))
        with self._lock:
            self._raise_if_closed()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT lease_owner, lease_until FROM assembly_queue WHERE id = 1"
                ).fetchone()
                held_by = "" if row is None else str(row["lease_owner"])
                until = "" if row is None else str(row["lease_until"])
                free = not held_by or held_by == owner or until <= _dt_to_sql(now)
                if free:
                    self._conn.execute(
                        "UPDATE assembly_queue SET lease_owner = ?, lease_until = ? WHERE id = 1",
                        (owner, deadline),
                    )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            return free

    def release_lease(self, *, owner: str) -> None:
        """Освобождает аренду. Чужую не трогает: снимать её вправе только владелец."""
        with self._lock:
            self._raise_if_closed()
            self._conn.execute(
                "UPDATE assembly_queue SET lease_owner = '', lease_until = '' "
                "WHERE id = 1 AND lease_owner = ?",
                (owner,),
            )

    def _raise_if_closed(self) -> None:
        if self._closed:
            raise RuntimeError("очередь сборки закрыта")
