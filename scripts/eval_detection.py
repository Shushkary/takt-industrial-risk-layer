#!/usr/bin/env python3
"""
Сертификационный трек (Приказ ФСТЭК №239, `docs/certification_risk_roadmap.md`):
протоколы true positive / false positive по инвариантам.

Прогоняет размеченный корпус `tests/fixtures/detection_eval/scenarios.py`
через `collect_extended_invariants` (код-дефолтный каталог правил,
`default_extended_rule_specs()` — не зависит от боевого YAML в
`config/invariants/`, см. предупреждение в `docs/invariant_matrix.md`
о расхождении noop/prod) и печатает TPR/FPR по каждому инварианту
из `IN_SCOPE_INVARIANT_IDS`.

Это методология и минимальный синтетический корпус (11 из 26 инвариантов),
не эталонная промышленная выборка. Результат — не финальная сертификационная
метрика, а воспроизводимый baseline для расширения.

Usage:
    python scripts/eval_detection.py [--json OUT.json] [--markdown OUT.md]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "detection_eval"))

from eval_core import Confusion, evaluate  # noqa: E402
from scenarios import all_scenarios  # noqa: E402


def _fmt_rate(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.2f}"


def render_markdown(matrix: dict[str, Confusion], scenario_count: int) -> str:
    lines = [
        "# Протокол true positive / false positive (детекция инвариантов)",
        "",
        f"Сгенерировано `scripts/eval_detection.py`; корпус: {scenario_count} сценариев, "
        f"{len(matrix)} инвариантов в объёме.",
        "",
        "Не эталонная промышленная выборка — минимальный синтетический корпус для baseline методологии.",
        "Оценка идёт по код-дефолтному каталогу правил (`default_extended_rule_specs()`), не по боевому "
        "YAML из `config/invariants/` — см. `docs/invariant_matrix.md`.",
        "",
        "| invariant_id | TP | FP | FN | TN | TPR | FPR |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for iid, c in sorted(matrix.items()):
        lines.append(f"| `{iid}` | {c.tp} | {c.fp} | {c.fn} | {c.tn} | {_fmt_rate(c.tpr)} | {_fmt_rate(c.fpr)} |")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_json(matrix: dict[str, Confusion], scenario_count: int) -> dict:
    return {
        "scenario_count": scenario_count,
        "invariants_in_scope": sorted(matrix.keys()),
        "results": {
            iid: {"tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn, "tpr": c.tpr, "fpr": c.fpr}
            for iid, c in sorted(matrix.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=None, help="Write JSON report to this path")
    parser.add_argument("--markdown", type=Path, default=None, help="Write Markdown report to this path")
    args = parser.parse_args()

    scenarios = all_scenarios()
    matrix = evaluate()
    md = render_markdown(matrix, len(scenarios))
    print(md)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(render_json(matrix, len(scenarios)), indent=2), encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(md, encoding="utf-8")

    failing = [iid for iid, c in matrix.items() if (c.tpr or 0.0) < 1.0 or (c.fpr or 0.0) > 0.0]
    if failing:
        print(f"WARNING: below-target invariants: {', '.join(sorted(failing))}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
