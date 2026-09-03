from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from takt.application.use_cases.assemble_incident import AssembleIncidentUseCase
from takt.application.use_cases.auto_assemble_incidents import AutoAssembleIncidentsUseCase
from takt.domain.entities.event import EventSource
from takt.domain.ports.event_source_reader import EventSourceReaderPort
from takt.infrastructure.importers.nad_events import NadEventSourceReader
from takt.infrastructure.importers.siem_events import PtSiemEventSourceReader
from takt.infrastructure.importers.soc_csv import (
    CsvEventSourceReader,
    map_edr,
    map_ndr,
    map_netflow,
    map_ot,
    map_siem,
)
from takt.interface_adapters.api.main import create_app

MAPPERS = {
    "edr": map_edr,
    "siem": map_siem,
    "ndr": map_ndr,
    # Тот же файл потоков читается как Netflow: без вердикта средства обнаружения.
    "netflow": map_netflow,
    "ot": map_ot,
}

# Выгрузки, приходящие построчным NDJSON, а не CSV: по одному JSON-объекту на строку, как в
# ответе `_search`/`scroll`. Читатель выгрузки PT NAD в продукте был и раньше, но точки входа
# для него не было — принять выгрузку со стенда было нечем.
NDJSON_READERS: dict[str, Callable[..., EventSourceReaderPort]] = {
    "nad": NadEventSourceReader,
    # Выгрузка PT SIEM по таксономии стенда. Имя `siem` занято CSV-выгрузкой
    # обезличенного датасета: у неё другие колонки, и подменять её было бы регрессией.
    "pt_siem": PtSiemEventSourceReader,
}

# Имя в командной строке называет формат выгрузки, а не класс источника события: выгрузка
# PT NAD приходит в класс `ndr`, файл потоков, прочитанный как Netflow, — в `network_events`.
# Класс нужен, чтобы взять для читателя настроенное доверие: настраивается оно по классу.
SOURCE_CLASS = {
    "edr": EventSource.EDR.value,
    "siem": EventSource.SIEM.value,
    "ndr": EventSource.NDR.value,
    "netflow": EventSource.NETWORK.value,
    "ot": EventSource.OT.value,
    "nad": EventSource.NDR.value,
    "pt_siem": EventSource.SIEM.value,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Потоковая загрузка SOC-датасета в TAKT")
    parser.add_argument("--source", required=True, choices=sorted(SOURCE_CLASS))
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument("--progress-every", type=int, default=1000)
    parser.add_argument(
        "--no-assemble",
        action="store_true",
        help=(
            "не выполнять догоняющую сборку в конце загрузки. Сборку по ходу приёма флаг не"
            " отменяет — она настраивается в YAML (incident_assembly.on_ingest); без"
            " догоняющего прогона в инцидент не попадут события после последнего срабатывания."
        ),
    )
    parser.add_argument(
        "--distinctive-max-events",
        type=int,
        default=12,
        help="порог отличительности сущности: не чаще скольких раз она встречается в потоке",
    )
    return parser


def _reader(source: str, path: Path, *, trust: float) -> EventSourceReaderPort:
    """Читатель выгрузки по имени источника: CSV или построчный NDJSON.

    Тип возврата — доменный порт, а не голый `Iterable`: так mypy проверяет, что каждый
    читатель импортёров действительно реализует шов «внешний источник событий». До этого
    порт не был назван ни в одном модуле и ничего не удерживал.
    """
    ndjson = NDJSON_READERS.get(source)
    if ndjson is not None:
        return ndjson(path, ingest_trust=trust)
    return CsvEventSourceReader(path, MAPPERS[source], ingest_trust=trust)


def _assemble_incidents(app, *, distinctive_max_events: int) -> None:
    """Догоняющий прогон сборки в конце загрузки.

    Приём собирает инцидент сам, по ходу потока (`incident_assembly.on_ingest`), но каждый
    его прогон видит поток по состоянию на очередное срабатывание инварианта. События,
    пришедшие после последнего срабатывания, попадут в инцидент только на следующем прогоне,
    а в пакетной загрузке следующего прогона не будет — файл кончился. Этот шаг закрывает
    хвост: он выполняется один раз и видит корпус целиком.

    Порог отличительности здесь задаётся аргументом командной строки и может отличаться от
    того, с которым работал приём: это же значение принимает `POST /cases/assemble/auto`.
    """
    store = getattr(app.state, "recent_event_store", None)
    if store is None:
        print("assemble skipped: требуется постоянное хранилище событий (TAKT_STORAGE=sqlite)")
        return
    use_case = AutoAssembleIncidentsUseCase(
        assemble=AssembleIncidentUseCase(
            events=store, repo=app.state.repo, weights=getattr(app.state, "risk_weights", {})
        ),
        repo=app.state.repo,
        events=store,
        distinctive_max_events=distinctive_max_events,
    )
    report = use_case.execute(actor="load_dataset")
    print(
        f"assembled incidents={len(report.incidents)} events={report.assembled_events}"
        f" considered={len(report.considered_cases)} skipped={len(report.skipped_cases)}"
    )
    for item in report.incidents:
        print(f"  incident {item.case_id} events={item.event_count} seeds={','.join(item.seeds)}")


def run(
    *,
    source: str,
    path: Path,
    progress_every: int = 1000,
    assemble: bool = True,
    distinctive_max_events: int = 12,
) -> int:
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    app = create_app()
    configured_trust = app.state.trust_by_source or {}
    reader = _reader(source, path, trust=float(configured_trust.get(SOURCE_CLASS[source], 1.0)))
    processed = 0
    failed = 0
    try:
        for event in reader:
            try:
                app.state.ingest_facade.assess_normalized_event(
                    event,
                    # Доверие передаётся целиком, как его передаёт API: оценка ищет значение
                    # по классу самого события, а не по имени из командной строки.
                    trust_by_source=configured_trust,
                )
                processed += 1
                if progress_every > 0 and processed % progress_every == 0:
                    print(f"progress source={source} processed={processed} failed={failed}")
            except Exception as exc:
                failed += 1
                print(f"event failed source={source} event_id={event.event_id} reason={exc}", file=sys.stderr)
        # Сборка выполняется и при сбойных строках. Пропускать её означало бы, что одна
        # непрочитанная строка из тысячи молча оставляет оператора без инцидента: в выводе
        # он видит только `failed=1` и не знает, что шаг вообще не запускался. Состав
        # инцидента выводится из принятых событий, а следующая успешная загрузка пересобирает
        # его под тем же идентификатором.
        if assemble:
            if failed:
                print(f"assemble: часть строк не принята (failed={failed}), инцидент собран по принятым")
            _assemble_incidents(app, distinctive_max_events=distinctive_max_events)
    finally:
        for attr in ("recent_event_store", "repo", "baseline", "audit_engagement_store"):
            resource = getattr(app.state, attr, None)
            close = getattr(resource, "close", None)
            if callable(close):
                close()
    print(f"complete source={source} processed={processed} failed={failed}")
    return 0 if failed == 0 else 1


def main() -> int:
    args = build_parser().parse_args()
    return run(
        source=args.source,
        path=args.path,
        progress_every=args.progress_every,
        assemble=not args.no_assemble,
        distinctive_max_events=args.distinctive_max_events,
    )


if __name__ == "__main__":
    raise SystemExit(main())
