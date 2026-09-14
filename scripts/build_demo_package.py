#!/usr/bin/env python3
"""Сборка демонстрационного пакета для заказчика.

Пакет самодостаточен: ядро ТАКТ, АРМ аналитика, конфигурация Docker,
демонстрационные данные и инструкция. Разворачивается на стороне заказчика
двумя командами, доступа к репозиторию не требует.

    python -m scripts.build_demo_package
    python -m scripts.build_demo_package --out-dir dist --no-arm-build

Почему сборка скриптом, а не архивом каталога:

- **АРМ собирается заново.** `index.html` подключает `app.min.js`, а не исходник:
  без пересборки в пакет ушла бы старая редакция интерфейса при внешне успешной
  сборке. Это тот же порядок, что и при выкладке (см. CLAUDE.md).
- **Состав отбирается явно.** В репозитории лежат документы с адресами и учётными
  записями стендов (`docs/stand/`), данные прогонов и артефакты сборки — заказчику
  ничего этого не передаётся. В пакет попадают только перечисленные ниже пути.
- **Целостность проверяема.** Рядом с пакетом кладутся `SHA256SUMS` и `MANIFEST.json`:
  заказчик может убедиться, что получил то же, что было собрано.

Файлы `.gz` АРМ в пакет намеренно не входят: `gzip_static` в конфигурации стенда
не включён, а устаревший `.gz` рядом с исходником — известный способ получить
старый код при внешне успешной выкладке.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Ядро и развёртывание. Слева — путь в репозитории, справа — путь в пакете.
CORE_FILES: tuple[tuple[str, str], ...] = (
    ("Dockerfile", "Dockerfile"),
    ("pyproject.toml", "pyproject.toml"),
    ("demo/compose.yml", "docker-compose.yml"),
    ("demo/nginx.arm.conf", "nginx.arm.conf"),
    ("demo/README.md", "README.md"),
    ("demo/seed/seed.py", "seed/seed.py"),
    ("scripts/seed_demo_chain.py", "seed/seed_demo_chain.py"),
)

CORE_DIRS: tuple[tuple[str, str], ...] = (
    ("src", "src"),
    ("config", "config"),
)

# АРМ: только то, что реально отдаётся браузеру. `app.js` и `styles.css` идут как
# исходники минифицированных файлов — интегратору они нужны для разбора интерфейса.
ARM_FILES: tuple[str, ...] = (
    "index.html",
    "env.js",
    "styles.css",
    "app.js",
    "app.min.js",
    "README.md",
)

# Демонстрационные данные INC-002: четыре класса источников плюс их описание.
DATASET_FILES: tuple[str, ...] = (
    "edr.csv",
    "siem.csv",
    "ndr.csv",
    "ot.csv",
    "README_INC-002.md",
    "data_contract_INC-002.md",
)

# Документы, на которые ссылаются пояснения в АРМ (поле `doc` реестра `HELP` в `app.js`),
# плюс конфигурация и описание прототипа: на них ссылается инструкция пакета.
# Состав проверяется тестом `tests/test_demo_package_contents.py`: ссылка из интерфейса,
# для которой нет документа, даёт аналитику 404 вместо пояснения.
DOC_FILES: tuple[str, ...] = (
    "api_reference.md",
    "configuration.md",
    "customer_value_map.md",
    "detection_quality.md",
    "invariant_matrix.md",
    "product_boundary.md",
    "risk_scale_calibration.md",
    "threat_model.md",
    "pt_techlab/adr_source_classes.md",
    "pt_techlab/analyst_window.md",
    "pt_techlab/baseline_methodology.md",
    "pt_techlab/correlation_quality.md",
    "pt_techlab/data_contract.md",
    "pt_techlab/prototype.md",
    "pt_techlab/rbac_matrix.md",
    "pt_techlab/simulation.md",
)

# Мусор сборки и кэши: в пакет не попадают ни при каком составе каталогов.
EXCLUDE_DIR_NAMES = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"})
EXCLUDE_SUFFIXES = frozenset({".pyc", ".pyo", ".db", ".db-wal", ".db-shm"})


def _version() -> str:
    for line in (ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit("в pyproject.toml не найдена версия")


def _revision() -> str:
    """Ревизия репозитория — чтобы пакет можно было сопоставить с кодом."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return out.stdout.strip()


def _build_arm() -> None:
    """Пересборка `app.min.js`: `index.html` подключает сборку, а не исходник."""
    arm_root = ROOT / "frontend" / "takt-pt-arm"
    print("сборка АРМ: node build-production.mjs")
    subprocess.run(
        ["node", "build-production.mjs"],
        cwd=arm_root,
        check=True,
        shell=sys.platform == "win32",
    )


def _copy_tree(source: Path, target: Path) -> None:
    def ignore(directory: str, names: list[str]) -> set[str]:
        skipped = {name for name in names if name in EXCLUDE_DIR_NAMES}
        skipped |= {name for name in names if Path(name).suffix in EXCLUDE_SUFFIXES}
        return skipped

    shutil.copytree(source, target, ignore=ignore)


def _copy_file(source: Path, target: Path) -> None:
    if not source.is_file():
        raise SystemExit(f"нет файла для пакета: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def _set_docs_base(env_js: Path) -> None:
    """Пояснения АРМ ссылаются на документы рядом со стендом, а не на репозиторий.

    В репозитории база указывает на публичный GitHub: так документ всегда
    соответствует выложенному коду. У заказчика на изолированном контуре такая
    ссылка не откроется, поэтому в пакете база переводится на локальную раздачу
    (`/docs/` в конфигурации nginx).
    """
    text = env_js.read_text(encoding="utf-8")
    marker = "window.TAKT_DOCS_BASE = "
    if marker not in text:
        raise SystemExit(f"в {env_js.name} не найдено объявление TAKT_DOCS_BASE")
    head, _, tail = text.partition(marker)
    _, _, rest = tail.partition("\n")
    replaced = f"{head}{marker}'./';\n{rest}"
    env_js.write_text(replaced, encoding="utf-8")


def build(out_dir: Path, *, arm_build: bool, keep_dir: bool) -> Path:
    version = _version()
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    name = f"takt-demo-{version}-{stamp}"
    package = out_dir / name

    if package.exists():
        shutil.rmtree(package)
    package.mkdir(parents=True)

    if arm_build:
        _build_arm()

    for source, target in CORE_FILES:
        _copy_file(ROOT / source, package / target)
    for source, target in CORE_DIRS:
        _copy_tree(ROOT / source, package / target)

    arm_source = ROOT / "frontend" / "takt-pt-arm"
    for item in ARM_FILES:
        _copy_file(arm_source / item, package / "arm" / item)
    _set_docs_base(package / "arm" / "env.js")

    dataset_source = ROOT / "tests" / "fixtures" / "pt_techlab" / "inc_002"
    for item in DATASET_FILES:
        _copy_file(dataset_source / item, package / "seed" / "inc_002" / item)

    for item in DOC_FILES:
        _copy_file(ROOT / "docs" / item, package / "docs" / item)

    files = sorted(p for p in package.rglob("*") if p.is_file())
    checksums = {p.relative_to(package).as_posix(): _sha256(p) for p in files}

    sums_path = package / "SHA256SUMS"
    sums_path.write_text(
        "".join(f"{digest}  {path}\n" for path, digest in checksums.items()),
        encoding="utf-8",
    )

    manifest = {
        "package": name,
        "product": "ТАКТ Industrial Risk Layer",
        "version": version,
        "revision": _revision(),
        "built_at": datetime.now(UTC).isoformat(),
        "scenarios": ["INC-002 (компрометация конвейера сборки)", "Захват инженерной станции"],
        "data_notice": "Все демонстрационные данные синтетические; на реальном объекте не наблюдались.",
        "entrypoints": {
            "arm": "http://127.0.0.1:8080/",
            "api_docs": "http://127.0.0.1:8090/docs",
        },
        "file_count": len(files),
        "files": checksums,
    }
    (package / "MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    archive = out_dir / f"{name}.zip"
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(p for p in package.rglob("*") if p.is_file()):
            zf.write(path, f"{name}/{path.relative_to(package).as_posix()}")

    if not keep_dir:
        shutil.rmtree(package)

    size_mb = archive.stat().st_size / (1024 * 1024)
    print(f"пакет: {archive}")
    print(f"  файлов: {len(files) + 2}, размер архива: {size_mb:.1f} МБ")
    print(f"  версия {version}, ревизия {manifest['revision'][:12]}")
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "dist", help="куда положить архив")
    parser.add_argument(
        "--no-arm-build",
        action="store_true",
        help="не пересобирать АРМ (только если сборка уже сделана вручную)",
    )
    parser.add_argument("--keep-dir", action="store_true", help="оставить распакованный каталог рядом с архивом")
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    build(args.out_dir, arm_build=not args.no_arm_build, keep_dir=args.keep_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
