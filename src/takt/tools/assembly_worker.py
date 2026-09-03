"""Процесс сборки инцидентов: забирает сигналы приёма и выполняет прогон.

Запуск:

```powershell
python -m takt.tools.assembly_worker
```

Работает вместе с `incident_assembly.mode: worker` в `config/risk_weights.yaml`: в этом
режиме приём только отмечает срабатывания в очереди, а прогон идёт здесь — в отдельном
процессе, не задерживая приём событий. Разбор режима —
`takt.application.use_cases.assembly_worker`.

Один воркер на базу. Аренда в таблице очереди не даёт второму процессу гонять тот же прогон;
она продлевается каждым циклом, поэтому упавший воркер освобождает сборку сам, без ручного
снятия блокировки. Второй запущенный экземпляр выходит с кодом 3 и говорит, кто держит
аренду, — молчаливое ожидание выглядело бы как исправная работа.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import time
from datetime import UTC, datetime
from types import FrameType

from takt.application.use_cases.assemble_incident import AssembleIncidentUseCase
from takt.application.use_cases.assembly_worker import AssemblyWorkerService
from takt.application.use_cases.auto_assemble_incidents import AutoAssembleIncidentsUseCase
from takt.infrastructure.config.settings_helpers import incident_assembly_settings
from takt.infrastructure.stores.sqlite_assembly_queue import SqliteAssemblyQueue
from takt.interface_adapters.api.main import create_app

# Аренда переживает несколько пропущенных циклов: короткая заставляла бы сменщика перехватывать
# сборку у живого воркера, затянувшегося на большом хранилище дел.
_LEASE_CYCLES = 10
_MIN_LEASE_SEC = 60.0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Сборка инцидентов ТАКТ отдельным процессом")
    parser.add_argument(
        "--poll-sec",
        type=float,
        default=None,
        help="как часто проверять очередь сигналов; по умолчанию incident_assembly.worker_poll_sec",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="один цикл и выход: для проверки настройки и для запуска по расписанию извне",
    )
    parser.add_argument(
        "--max-runs",
        type=int,
        default=0,
        help="остановиться после стольких прогонов сборки (0 — без ограничения)",
    )
    return parser


class _StopSignal:
    """Останов по SIGTERM/SIGINT: цикл дорабатывает и освобождает аренду.

    Без этого `docker stop` убивал бы процесс мимо `finally`, и аренда держалась бы до
    истечения срока — сменщик ждал бы минуту на пустом месте.
    """

    def __init__(self) -> None:
        self.requested = False

    def install(self) -> None:
        for name in ("SIGTERM", "SIGINT"):
            sig = getattr(signal, name, None)
            if sig is not None:
                signal.signal(sig, self._handle)

    def _handle(self, signum: int, frame: FrameType | None) -> None:
        self.requested = True


def run(*, poll_sec: float | None = None, once: bool = False, max_runs: int = 0) -> int:
    app = create_app()
    repo = app.state.repo
    events = getattr(app.state, "recent_event_store", None)
    database_path = getattr(repo, "database_path", None)
    if events is None or database_path is None:
        print(
            "assembly worker: требуется постоянное хранилище (TAKT_STORAGE=sqlite)",
            file=sys.stderr,
        )
        return 2

    weights = app.state.risk_weights
    settings = incident_assembly_settings(weights)
    interval = float(poll_sec if poll_sec is not None else settings.worker_poll_sec)
    if not settings.defers_to_worker:
        # Не ошибка: воркер годится и как догоняющая сборка. Но если приём собирает сам,
        # сигналов не будет, и молчание воркера объясняется настройкой, а не отсутствием атак.
        print(f"assembly worker: incident_assembly.mode={settings.mode}, сигналов от приёма не будет")

    queue = SqliteAssemblyQueue(database_path)
    owner = f"{socket.gethostname()}:{os.getpid()}"
    lease_ttl = max(_MIN_LEASE_SEC, interval * _LEASE_CYCLES)
    stop = _StopSignal()
    stop.install()
    try:
        if not queue.acquire_lease(owner=owner, now=datetime.now(UTC), ttl_sec=lease_ttl):
            print("assembly worker: аренда занята другим процессом, выхожу", file=sys.stderr)
            return 3
        service = AssemblyWorkerService(
            queue=queue,
            assemble=AutoAssembleIncidentsUseCase(
                assemble=AssembleIncidentUseCase(events=events, repo=repo, weights=weights),
                repo=repo,
                events=events,
                distinctive_max_events=settings.distinctive_max_events,
            ),
            on_error=lambda exc: print(f"assembly run failed: {exc}", file=sys.stderr),
        )
        print(
            f"assembly worker started owner={owner} poll={interval}s"
            f" threshold={settings.distinctive_max_events} db={database_path}"
        )
        while not stop.requested:
            queue.acquire_lease(owner=owner, now=datetime.now(UTC), ttl_sec=lease_ttl)
            report = service.run_once()
            if report is not None:
                print(
                    f"assembled incidents={len(report.incidents)} events={report.assembled_events}"
                    f" considered={len(report.considered_cases)} skipped={len(report.skipped_cases)}"
                    f" retired={len(report.retired_case_ids)}"
                )
                for item in report.incidents:
                    print(f"  incident {item.case_id} events={item.event_count} seeds={','.join(item.seeds)}")
            if once or (max_runs > 0 and service.runs >= max_runs):
                break
            time.sleep(interval)
        print(f"assembly worker stopped runs={service.runs}")
        return 0
    except KeyboardInterrupt:
        print("assembly worker stopped by user")
        return 0
    finally:
        queue.release_lease(owner=owner)
        for resource in (queue, events, repo, getattr(app.state, "baseline", None)):
            close = getattr(resource, "close", None)
            if callable(close):
                close()


def main() -> int:
    args = build_parser().parse_args()
    return run(poll_sec=args.poll_sec, once=args.once, max_runs=args.max_runs)


if __name__ == "__main__":
    raise SystemExit(main())
