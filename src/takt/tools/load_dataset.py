from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

from takt.domain.entities.event import EventSource, NormalizedEvent
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
NDJSON_READERS: dict[str, Callable[..., Iterable[NormalizedEvent]]] = {
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
    return parser


def _reader(source: str, path: Path, *, trust: float) -> Iterable[NormalizedEvent]:
    """Читатель выгрузки по имени источника: CSV или построчный NDJSON."""
    ndjson = NDJSON_READERS.get(source)
    if ndjson is not None:
        return ndjson(path, ingest_trust=trust)
    return CsvEventSourceReader(path, MAPPERS[source], ingest_trust=trust)


def run(*, source: str, path: Path, progress_every: int = 1000) -> int:
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
    return run(source=args.source, path=args.path, progress_every=args.progress_every)


if __name__ == "__main__":
    raise SystemExit(main())
