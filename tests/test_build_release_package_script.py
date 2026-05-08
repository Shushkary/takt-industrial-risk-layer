from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_run():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "build_release_package.py"
    spec = importlib.util.spec_from_file_location("build_release_package_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run


def _load_manifest_package_dir():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "scripts" / "build_release_package.py"
    spec = importlib.util.spec_from_file_location("build_pkg_helper", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._manifest_package_dir


def test_manifest_package_dir_is_repo_relative_when_under_repo() -> None:
    repo = Path(__file__).resolve().parents[1]
    fn = _load_manifest_package_dir()
    assert fn(repo / "dist" / "release-package-demo", repo) == "dist/release-package-demo"


def test_manifest_package_dir_fallback_when_outside_repo() -> None:
    repo = Path(__file__).resolve().parents[1]
    fn = _load_manifest_package_dir()
    outside = repo.parent / "_outside_release_pkg_demo"
    assert fn(outside, repo) == str(outside)


def test_build_release_package_generates_bundle_and_manifest(tmp_path: Path) -> None:
    run = _load_run()
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

    # Reuse real release docs paths for required artifacts; only override prod/readiness/package root.
    rc = run(
        db,
        package_root=package_root,
        prod_ready=prod,
        readiness=readiness,
        apply_migrate=True,
        strict=False,
        strict_generate_sbom=False,
    )
    assert rc == 0
    package_dirs = [p for p in package_root.iterdir() if p.is_dir() and p.name.startswith("release-package-")]
    assert len(package_dirs) == 1
    manifest_path = package_dirs[0] / "manifest.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "READY"
    assert (package_dirs[0] / manifest["evidence_file"]).is_file()
    assert "sha256" in manifest and isinstance(manifest["sha256"], dict)
    for name in manifest["included_files"]:
        assert name in manifest["sha256"]
