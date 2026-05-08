from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_run():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "validate_prod_ready.py"
    spec = importlib.util.spec_from_file_location("validate_prod_ready_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


def test_validate_prod_ready_allows_only_manual_1_to_4_and_approvals(tmp_path: Path) -> None:
    run = _load_run()
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "| 1. Commit SHA релизного образа | _(заполнить)_ |",
                "| 2. Image tag / digest | _(заполнить)_ |",
                "| 3. Окно выкладки | _(заполнить)_ |",
                "| 4. Ответственный за выкладку | _(заполнить)_ |",
                "| 5. Backup БД выполнен (путь к backup) | `backup.sqlite` |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | `true` |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | `unknown` |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | `ok` |",
                "| Tech lead | | | |",
                "| Operations | | | |",
                "| Security (если требуется) | | | |",
                "| Product / заказчик | | | |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert run(prod) == 0


def test_validate_prod_ready_fails_when_auto_field_unfilled(tmp_path: Path) -> None:
    run = _load_run()
    prod = tmp_path / "prod_ready.md"
    prod.write_text(
        "\n".join(
            [
                "| 1. Commit SHA релизного образа | _(заполнить)_ |",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert run(prod) == 2
