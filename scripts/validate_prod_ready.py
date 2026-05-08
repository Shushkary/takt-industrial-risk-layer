#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


def run(prod_ready_path: Path) -> int:
    text = prod_ready_path.read_text(encoding="utf-8")
    allowed_unfilled_prefixes = ("| 1.", "| 2.", "| 3.", "| 4.")
    violations: list[str] = []
    for line in text.splitlines():
        if "_(заполнить)_" not in line:
            continue
        if line.startswith(allowed_unfilled_prefixes):
            continue
        # Approvals section can stay empty by design.
        if line.startswith("| Tech lead |") or line.startswith("| Operations |") or line.startswith("| Security"):
            continue
        if line.startswith("| Product / заказчик |"):
            continue
        violations.append(line)

    if violations:
        print("prod_ready_validation=FAILED")
        for item in violations:
            print(f"violation={item}")
        return 2

    print("prod_ready_validation=OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate prod-ready placeholders policy.")
    parser.add_argument(
        "--prod-ready",
        default="docs/releases/2026-05-07_v0.6.23_prod_ready.md",
        help="Path to prod-ready markdown to validate.",
    )
    args = parser.parse_args()
    return run(Path(args.prod_ready).expanduser().resolve())


if __name__ == "__main__":
    raise SystemExit(main())
