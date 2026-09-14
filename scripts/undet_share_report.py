"""T5. Доля UNDET по корпусу дел — публикуемая метрика.

UNDET («не определено») — не отказ системы, а честный доклад о вырожденной краевой задаче:
имеющихся данных недостаточно, чтобы однозначно восстановить путь между доинцидентным
состоянием и зафиксированным исходом. Величина этой доли — характеристика корпуса и полноты
организационного контекста, а не дефект движка.

Читать метрику нужно в обе стороны, и вторая важнее первой:

- доля растёт — в корпусе не хватает нарядов, заявок и окон работ, маршрут добора длинный;
- доля близка к нулю на шумном корпусе — **признак ложной уверенности**, а не качества:
  система перестала сознаваться в нехватке данных и начала натягивать вывод.

Порогов здесь нет намеренно. На текущем размере корпуса любой порог был бы произволом, а
блокирующая проверка в CI превратила бы честную неопределённость в то, что выгодно прятать.
Метрика информационная.

Запуск:

    python scripts/undet_share_report.py                      # хранилище из TAKT_SQLITE_PATH
    python scripts/undet_share_report.py --sqlite data/takt_cases.db
    python scripts/undet_share_report.py --json               # машиночитаемый вывод
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from takt.domain.entities.case import Case  # noqa: E402
from takt.domain.services.verdict_confidence import verdict_confidence  # noqa: E402

TRIAD = ("LEG", "ILLEG", "UNDET")


@dataclass(frozen=True, slots=True)
class UndetShare:
    """Состав корпуса по триаде вердикта и доля неопределённых."""

    n_total: int
    n_leg: int
    n_illeg: int
    n_undet: int

    @property
    def share_undet(self) -> float:
        """Доля UNDET в корпусе; на пустом корпусе — 0.0, а не деление на ноль."""
        return (self.n_undet / self.n_total) if self.n_total else 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "n_total": self.n_total,
            "n_LEG": self.n_leg,
            "n_ILLEG": self.n_illeg,
            "n_UNDET": self.n_undet,
            "share_UNDET": round(self.share_undet, 4),
        }


def undet_share(cases: Iterable[Case]) -> UndetShare:
    """Свести корпус дел к составу по триаде.

    Вердикт берётся тем же путём, каким его видит интерфейс: `verdict_confidence(case).verdict`.
    Отдельного счётчика здесь не заводится — иначе отчёт мог бы разойтись с карточкой дела.
    """
    counts: Counter[str] = Counter()
    total = 0
    for case in cases:
        total += 1
        verdict = verdict_confidence(case).verdict
        counts[verdict if verdict in TRIAD else "UNDET"] += 1
    return UndetShare(
        n_total=total,
        n_leg=counts["LEG"],
        n_illeg=counts["ILLEG"],
        n_undet=counts["UNDET"],
    )


def _load_cases(sqlite_path: str) -> Sequence[Case]:
    from takt.infrastructure.stores.sqlite_store import SqliteCaseStore

    store = SqliteCaseStore(sqlite_path)
    return store.list_all()


def _render(share: UndetShare, *, as_json: bool) -> str:
    if as_json:
        return json.dumps(share.to_dict(), ensure_ascii=False, indent=2)
    lines = [
        "Состав корпуса по триадному вердикту",
        "",
        f"  дел всего        n_total = {share.n_total}",
        f"  законно          n_LEG   = {share.n_leg}",
        f"  незаконно        n_ILLEG = {share.n_illeg}",
        f"  не определено    n_UNDET = {share.n_undet}",
        "",
        f"  доля UNDET       {share.share_undet:.1%}",
        "",
        "Доля, близкая к нулю на шумном корпусе, — признак ложной уверенности, а не качества:",
        "система перестала сознаваться в нехватке данных. Порогов у метрики нет намеренно.",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Доля UNDET по корпусу дел")
    parser.add_argument(
        "--sqlite",
        default=os.environ.get("TAKT_SQLITE_PATH", "data/takt_cases.db"),
        help="путь к файлу SQLite с делами (по умолчанию — TAKT_SQLITE_PATH)",
    )
    parser.add_argument("--json", action="store_true", help="машиночитаемый вывод")
    args = parser.parse_args(argv)

    if not Path(args.sqlite).exists():
        print(f"хранилище не найдено: {args.sqlite}", file=sys.stderr)
        return 2

    share = undet_share(_load_cases(args.sqlite))
    print(_render(share, as_json=args.json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
