from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_run():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "verify_release_package.py"
    spec = importlib.util.spec_from_file_location("verify_release_package_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


def _load_build_run():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "build_release_package.py"
    spec = importlib.util.spec_from_file_location("build_release_package_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


def test_verify_release_package_ok_and_detects_tamper(tmp_path: Path) -> None:
    build_run = _load_build_run()
    verify_run = _load_run()
    db = tmp_path / "ops.db"
    package_root = tmp_path / "dist"
    docs = tmp_path / "docs" / "releases"
    docs.mkdir(parents=True, exist_ok=True)
    prod = docs / "prod_ready.md"
    readiness = docs / "readiness.md"
    prod.write_text(
        "\n".join(
            [
                "## 2) Manual input required (4 поля)",
                "| 5. Backup БД выполнен (путь к backup) | _(заполнить)_ |",
                "| 6. `db_migrate.py` выполнен (версия схемы/вывод) | _(заполнить)_ |",
                "| 7. Режим forensic подписи в prod (`mvp` или `gost_strict` + env) | _(заполнить)_ |",
                "| 8. Smoke-check после выкладки (ссылка/лог) | _(заполнить)_ |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    readiness.write_text("# readiness\n", encoding="utf-8")
    rc = build_run(
        db,
        package_root=package_root,
        prod_ready=prod,
        readiness=readiness,
        apply_migrate=True,
        strict=False,
        strict_generate_sbom=False,
    )
    assert rc == 0
    package_dir = [p for p in package_root.iterdir() if p.is_dir() and p.name.startswith("release-package-")][0]
    assert verify_run(package_dir) == 0

    evidence = package_dir / "operational_tails_evidence.md"
    evidence.write_text(evidence.read_text(encoding="utf-8") + "\n# tamper\n", encoding="utf-8")
    assert verify_run(package_dir) == 2
