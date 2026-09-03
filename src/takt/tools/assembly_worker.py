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
from takt.application.use_cases.assembly_worker import (
    AssemblyWorkerService,
    assembly_config_mismatches,
)
from takt.application.use_cases.auto_assemble_incidents import AutoAssembleIncidentsUseCase
from takt.infrastructure.config.settings_helpers import (
    IncidentAssemblySettings,
    incident_assembly_settings,
)
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
    parser.add_argument(
        "--allow-config-mismatch",
        action="store_true",
        help=(
            "запуститься, даже если настройка сборки расходится с той, с которой поднялся API"
            " (например, догоняющая сборка с другим порогом отличительности)"
        ),
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


def _config_agrees_with_api(
    queue: SqliteAssemblyQueue,
    *,
    settings: IncidentAssemblySettings,
    allow_mismatch: bool,
) -> bool:
    """Сверяет настройку сборки с той, с которой поднялся API.

    Оба процесса читают конфигурацию сами, и разойтись они могут молча: разные файлы, разные
    монтирования, разные переменные окружения. Итог во всех случаях один — инцидентов нет, —
    но чинится он по-разному, поэтому расхождение называется на старте, а не остаётся
    догадкой при разборе жалобы.
    """
    api = queue.api_settings()
    if api is None:
        # Воркера могли поднять раньше API — но чаще это значит, что процессы смотрят в
        # разные базы, и тогда воркер будет исправно ждать сигналов, которых там не будет.
        print(
            "assembly worker: API с этой базой ещё не запускался — проверьте TAKT_SQLITE_PATH"
            " и TAKT_CONFIG, если инциденты не появляются"
        )
        return True

    mismatches = assembly_config_mismatches(
        api=api,
        worker_mode=settings.mode,
        worker_distinctive_max_events=settings.distinctive_max_events,
    )
    if not mismatches:
        return True

    stream = sys.stdout if allow_mismatch else sys.stderr
    print("assembly worker: настройка расходится с API", file=stream)
    for item in mismatches:
        print(f"  {item.describe()}", file=stream)
    print(
        f"  конфигурация API: {api.get('config_path', '?')} (процесс {api.get('owner', '?')},"
        f" {api.get('at', '?')})",
        file=stream,
    )
    if allow_mismatch:
        print("  запуск разрешён флагом --allow-config-mismatch", file=stream)
        return True
    print(
        "  приведите конфигурации к одному виду или запустите с --allow-config-mismatch",
        file=stream,
    )
    return False


def run(
    *,
    poll_sec: float | None = None,
    once: bool = False,
    max_runs: int = 0,
    allow_config_mismatch: bool = False,
) -> int:
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

    queue = SqliteAssemblyQueue(database_path)
    owner = f"{socket.gethostname()}:{os.getpid()}"
    lease_ttl = max(_MIN_LEASE_SEC, interval * _LEASE_CYCLES)
    stop = _StopSignal()
    stop.install()
    try:
        if not settings.defers_to_worker:
            # Собственная конфигурация не отправляет сборку сюда. Не ошибка — воркер годится
            # и как догоняющая сборка, — но молчание процесса иначе объяснялось бы отсутствием
            # атак, а не настройкой.
            print(
                f"assembly worker: incident_assembly.mode={settings.mode},"
                " сигналов от приёма не будет"
            )
        if not _config_agrees_with_api(
            queue, settings=settings, allow_mismatch=allow_config_mismatch
        ):
            return 4
        queue.publish_worker_settings(
            mode=settings.mode,
            distinctive_max_events=settings.distinctive_max_events,
            config_path=str(app.state.takt_config_path),
            owner=owner,
            at=datetime.now(UTC),
        )
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
    return run(
        poll_sec=args.poll_sec,
        once=args.once,
        max_runs=args.max_runs,
        allow_config_mismatch=args.allow_config_mismatch,
    )


if __name__ == "__main__":
    raise SystemExit(main())
