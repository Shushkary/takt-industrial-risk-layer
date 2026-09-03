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

import json
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

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

# Отпечатки настройки сборки в `app_metadata`: по ним процессы сверяются друг с другом.
_API_SETTINGS_KEY = "incident_assembly_api"
_WORKER_SETTINGS_KEY = "incident_assembly_worker"


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

    # --- отпечатки настройки ----------------------------------------------

    def publish_api_settings(
        self,
        *,
        mode: str,
        distinctive_max_events: int,
        config_path: str,
        owner: str,
        at: datetime,
    ) -> None:
        """Оставляет в базе, с какой настройкой сборки поднялся процесс API.

        Воркеру не с чем сверяться, кроме этой записи: конфигурацию каждый процесс читает
        сам, и разойтись они могут молча — разные файлы, разные монтирования, разные
        переменные окружения.
        """
        self._put_metadata(
            _API_SETTINGS_KEY,
            {
                "mode": mode,
                "distinctive_max_events": int(distinctive_max_events),
                "config_path": config_path,
                "owner": owner,
                "at": _dt_to_sql(at),
            },
        )

    def publish_worker_settings(
        self,
        *,
        mode: str,
        distinctive_max_events: int,
        config_path: str,
        owner: str,
        at: datetime,
    ) -> None:
        """То же со стороны воркера: по отметке видно, что процесс сборки жив."""
        self._put_metadata(
            _WORKER_SETTINGS_KEY,
            {
                "mode": mode,
                "distinctive_max_events": int(distinctive_max_events),
                "config_path": config_path,
                "owner": owner,
                "at": _dt_to_sql(at),
            },
        )

    def api_settings(self) -> dict[str, Any] | None:
        """Отпечаток API или `None`, если он с этой базой ещё не поднимался."""
        return self._get_metadata(_API_SETTINGS_KEY)

    def worker_settings(self) -> dict[str, Any] | None:
        return self._get_metadata(_WORKER_SETTINGS_KEY)

    def _put_metadata(self, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            self._raise_if_closed()
            self._conn.execute(
                """
                INSERT INTO app_metadata (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, json.dumps(value, ensure_ascii=False)),
            )

    def _get_metadata(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            self._raise_if_closed()
            row = self._conn.execute(
                "SELECT value FROM app_metadata WHERE key = ? LIMIT 1", (key,)
            ).fetchone()
        if row is None:
            return None
        try:
            parsed = json.loads(str(row["value"]))
        except json.JSONDecodeError:
            # Испорченный отпечаток — не повод ронять процесс: сверять будет нечего, и об
            # этом скажут так же, как об отсутствующем.
            return None
        return parsed if isinstance(parsed, dict) else None

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
