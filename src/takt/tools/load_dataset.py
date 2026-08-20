from __future__ import annotations

import argparse
import sys
from pathlib import Path

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Потоковая загрузка SOC-датасета в TAKT")
    parser.add_argument("--source", required=True, choices=sorted(MAPPERS))
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument("--progress-every", type=int, default=1000)
    return parser


def run(*, source: str, path: Path, progress_every: int = 1000) -> int:
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    app = create_app()
    trust = float(app.state.trust_by_source.get(source, 1.0))
    reader = CsvEventSourceReader(path, MAPPERS[source], ingest_trust=trust)
    processed = 0
    failed = 0
    try:
        for event in reader:
            try:
                app.state.ingest_facade.assess_normalized_event(
                    event,
                    trust_by_source={source: trust},
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
