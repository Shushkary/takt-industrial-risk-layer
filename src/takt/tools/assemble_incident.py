"""CLI сборки инцидента пивотом по сущностям.

Нужен там, где нет смысла поднимать HTTP: подготовка демонстрационного стенда сразу после
`takt.tools.load_dataset`. Работает с тем же постоянным хранилищем, что и API, поэтому
требует `TAKT_STORAGE=sqlite` — при хранилище в памяти собранный кейс некому передать.

Пример (демо-сценарий INC-002):

    python -m takt.tools.assemble_incident --case-id INC-002 \
        --seed user:smirnov --seed user:svc_build --seed address:185.220.101.34 \
        --seed artifact:domain:cdn-metrics.example-analytics.com \
        --seed host:artifact:app-setup.msi --seed host:pipeline:release-prod \
        --expand-host ws-17 --expand-host build-srv-01
"""

from __future__ import annotations

import argparse
import sys

from takt.application.use_cases.assemble_incident import (
    AssembleIncidentUseCase,
    IncidentSeed,
)
from takt.interface_adapters.api.main import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Сборка инцидента пивотом по сущностям")
    parser.add_argument("--case-id", required=True, help="идентификатор собираемого кейса")
    parser.add_argument(
        "--seed",
        action="append",
        default=[],
        metavar="ВИД:ЗНАЧЕНИЕ",
        help="отличительная сущность: host:ws-17, user:smirnov, address:10.0.0.1, artifact:domain:example",
    )
    parser.add_argument("--title", default="", help="заголовок кейса")
    parser.add_argument(
        "--expand-host",
        action="append",
        default=[],
        metavar="УЗЕЛ",
        help="узел, до уровня которого расширяется разбор после сборки ядра",
    )
    parser.add_argument("--expand-padding-sec", type=int, default=0, help="запас окна расширения, секунды")
    parser.add_argument("--actor", default="", help="кто выполняет сборку, для журнала кейса")
    return parser


def run(
    *,
    case_id: str,
    seeds: list[str],
    title: str = "",
    expand_hosts: list[str] | None = None,
    expand_padding_sec: int = 0,
    actor: str = "",
) -> int:
    if not seeds:
        print("error: нужна хотя бы одна сущность (--seed)", file=sys.stderr)
        return 2
    try:
        parsed = [IncidentSeed.parse(item) for item in seeds]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    app = create_app()
    store = getattr(app.state, "recent_event_store", None)
    if store is None:
        print(
            "error: сборка требует постоянного хранилища событий — задай TAKT_STORAGE=sqlite",
            file=sys.stderr,
        )
        return 2
    try:
        use_case = AssembleIncidentUseCase(events=store, repo=app.state.repo)
        assembled = use_case.execute(
            case_id=case_id,
            seeds=parsed,
            title=title,
            expand_hosts=tuple(expand_hosts or ()),
            expand_padding_sec=expand_padding_sec,
            actor=actor,
        )
    except LookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        for attr in ("recent_event_store", "repo", "baseline", "audit_engagement_store"):
            resource = getattr(app.state, attr, None)
            close = getattr(resource, "close", None)
            if callable(close):
                close()

    print(
        f"assembled case={assembled.case.case_id}"
        f" core={len(assembled.core_event_ids)}"
        f" expanded={len(assembled.expanded_event_ids)}"
        f" total={assembled.total_events}"
        f" from_cases={len(assembled.source_case_ids)}"
    )
    return 0


def main() -> int:
    args = build_parser().parse_args()
    return run(
        case_id=args.case_id,
        seeds=args.seed,
        title=args.title,
        expand_hosts=args.expand_host,
        expand_padding_sec=args.expand_padding_sec,
        actor=args.actor,
    )


if __name__ == "__main__":
    raise SystemExit(main())
