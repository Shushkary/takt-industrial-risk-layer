"""Внешние материалы не обещают хранилища, которого в коде нет.

Прецедент: описание решения для конкурса называло слой «SQLite/PostgreSQL-совместимым», хотя
`TAKT_STORAGE` принимает только `memory` и `sqlite`, а адаптера PostgreSQL в репозитории нет.
Такое расхождение проверяется первым же вопросом «а какая у вас СУБД» и обесценивает остальные
утверждения материала, потому что показывает: написанному нельзя верить без проверки.

Правило продукта — `docs/product_boundary.md`, раздел «Заявления во внешних материалах»:
публичные тексты не обещают больше, чем подтверждает код.
"""

from __future__ import annotations

from pathlib import Path

from takt.infrastructure.config.settings_helpers import SUPPORTED_STORAGE_BACKENDS

_REPO_ROOT = Path(__file__).resolve().parents[1]

# Имена СУБД, появление которых в описании хранилища означает заявление о поддержке.
_DATABASE_NAMES: tuple[str, ...] = (
    "SQLite",
    "PostgreSQL",
    "MySQL",
    "Oracle",
    "MS SQL",
    "ClickHouse",
    "MongoDB",
)

# Абзацы-заявления о хранилище решения: документ и первые слова строки.
_STORAGE_CLAIMS: tuple[tuple[str, str], ...] = (
    ("docs/pt_techlab_2026_solution_description.md", "Хранилище решения"),
)


def test_storage_claims_name_only_backends_that_exist() -> None:
    """В абзаце о хранилище названы только те СУБД, для которых есть адаптер."""
    supported = {name.lower() for name in SUPPORTED_STORAGE_BACKENDS}

    for relative_path, opening in _STORAGE_CLAIMS:
        text = (_REPO_ROOT / relative_path).read_text(encoding="utf-8")
        claims = [line for line in text.splitlines() if line.startswith(opening)]
        assert claims, f"{relative_path}: абзац «{opening}…» пропал"

        for line in claims:
            named = [name for name in _DATABASE_NAMES if name.lower() in line.lower()]
            unsupported = sorted(name for name in named if name.lower() not in supported)
            # Названная как план СУБД допустима, если рядом сказано, что адаптера нет.
            if unsupported:
                assert "адаптера серверной СУБД в MVP нет" in line, (
                    f"{relative_path}: заявлена поддержка {unsupported}, "
                    f"а в коде есть только {sorted(supported)}"
                )
