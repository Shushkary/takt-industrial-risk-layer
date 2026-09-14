"""T8. Числовые факты из «Чисел-фактов» сверяются с кодом, а не друг с другом.

Если один числовой факт живёт в нескольких местах, обход контура «документ → документ →
код → документ» перестаёт возвращать то же значение: где-то по дороге цифра обновилась, а
где-то нет. Расхождение накапливается тихо и обнаруживается на разборе с экспертом.

Регламент проекта (`CLAUDE.md`) уже назначил единственное место хранения —
`docs/current_operational_reference.md`, раздел «Числа-факты». Этот тест делает назначение
исполняемым: каждая строка таблицы сверяется со своим источником в коде и конфигурации.

Что сознательно **не** проверяется:

- объём прогона (число тестов и время) — сам раздел объявляет его приблизительным, потому что
  оно меняется каждым коммитом; точное значение даёт вывод `pytest`;
- память контейнера API — это наблюдение на стенде, а не инвариант кода; условия замера
  записаны рядом со значением, воспроизводится командой `docker stats`.

Размер каталога инвариантов проверяется отдельным, более старым тестом
(`tests/test_docs_invariant_count_consistency.py`): он сверяет не только «Числа-факты», но и
формулировки во всех документах-источниках правды. Здесь он не дублируется.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from takt.domain.invariants.catalog import InvariantId

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE = _REPO_ROOT / "docs" / "current_operational_reference.md"


def _numeric_facts() -> dict[str, str]:
    """Строки таблицы «Числа-факты»: название факта → заявленное значение."""
    text = _REFERENCE.read_text(encoding="utf-8")
    start = text.index("## Числа-факты")
    section = text[start : text.index("\n---", start)]

    facts: dict[str, str] = {}
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        columns = [c.strip() for c in stripped.strip("|").split("|")]
        if len(columns) != 3 or columns[0] in ("Факт", "---"):
            continue
        if set(columns[0]) <= set("-: "):
            continue
        facts[columns[0]] = columns[1]
    return facts


def test_numeric_facts_table_is_parsed() -> None:
    """Страховка: если таблица переехала или сменила форму, тест обязан упасть здесь."""
    facts = _numeric_facts()
    assert len(facts) >= 8, f"в разделе «Числа-факты» разобрано подозрительно мало строк: {facts}"


def test_package_version_matches_pyproject() -> None:
    """Версия пакета в справочнике равна версии в `pyproject.toml`."""
    declared = _numeric_facts()["Версия пакета"]
    with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
        actual = tomllib.load(handle)["project"]["version"]

    assert f"`{actual}`" == declared, f"справочник: {declared}, pyproject: {actual}"


def test_supported_python_matches_pyproject_and_ci() -> None:
    """`requires-python` и матрица CI совпадают с заявленными в справочнике."""
    declared = _numeric_facts()["Поддерживаемый Python"]
    with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
        requires = tomllib.load(handle)["project"]["requires-python"]

    ci = (_REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    matrix = re.search(r"python-version:\s*\[(.+?)\]", ci)
    assert matrix, "матрица версий Python в CI не найдена"
    versions = re.findall(r"\d+\.\d+", matrix.group(1))

    assert requires in declared, f"requires-python {requires} не отражён в «{declared}»"
    assert versions[0] in declared and versions[-1] in declared, (
        f"матрица CI {versions} не отражена в «{declared}»"
    )


def test_docker_python_matches_dockerfile() -> None:
    """Версия интерпретатора в образе равна заявленной."""
    declared = _numeric_facts()["Python в Docker-образе"]
    dockerfile = (_REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    base = re.search(r"^FROM python:(\d+\.\d+)", dockerfile, re.MULTILINE)

    assert base, "базовый образ python в Dockerfile не найден"
    assert base.group(1) in declared, f"справочник: {declared}, Dockerfile: {base.group(1)}"


def test_invariant_catalog_size_matches_enum_and_yaml() -> None:
    """Размер каталога сверяется с enum и с числом YAML-файлов."""
    declared = _numeric_facts()["Доменных инвариантов"]
    enum_size = len(list(InvariantId))
    yaml_files = list((_REPO_ROOT / "config" / "invariants").glob("*.yaml"))

    assert str(enum_size) in declared, f"справочник: {declared}, InvariantId: {enum_size}"
    assert enum_size == len(yaml_files), (
        f"enum InvariantId: {enum_size}, файлов config/invariants/*.yaml: {len(yaml_files)}"
    )


def test_disabled_invariants_count_matches_config() -> None:
    """«Отключено в проде» равно числу YAML с `predicate_ref: builtin:noop`.

    Считается именно объявление исполнителя, а не упоминание строки: в одном файле
    (`out_of_shift_access.yaml`) `builtin:noop` встречается в комментарии, и подсчёт по
    вхождению подстроки дал бы на единицу больше.
    """
    declared = _numeric_facts()["Инвариантов отключено в проде (`builtin:noop`)"]
    noop = [
        path.name
        for path in sorted((_REPO_ROOT / "config" / "invariants").glob("*.yaml"))
        if re.search(r"^\s*predicate_ref:\s*builtin:noop\s*$", path.read_text(encoding="utf-8"), re.MULTILINE)
    ]

    assert str(len(noop)) in declared, f"справочник: {declared}, фактически noop: {sorted(noop)}"


def test_sqlite_schema_version_has_one_value_in_code() -> None:
    """Версия схемы совпадает со справочником и одинакова в обеих константах кода.

    Констант две и они не связаны ссылкой: `CURRENT_DB_SCHEMA_VERSION` в хранилище и
    `LATEST_SCHEMA_VERSION` в скрипте миграций. Пока они равны, расхождения нет; разойдутся —
    приложение поднимет схему, которую скрипт миграций не поддерживает, и откат станет
    невозможен без восстановления базы. Такой простой в проекте уже был
    (`deploy/docker/README.md`, «Перед остановкой контейнера»).
    """
    declared = _numeric_facts()["Версия схемы SQLite"]

    store = (_REPO_ROOT / "src" / "takt" / "infrastructure" / "stores" / "sqlite_store.py").read_text(
        encoding="utf-8"
    )
    migrate = (_REPO_ROOT / "scripts" / "db_migrate.py").read_text(encoding="utf-8")

    in_store = re.search(r"^CURRENT_DB_SCHEMA_VERSION\s*=\s*(\d+)", store, re.MULTILINE)
    in_migrate = re.search(r"^LATEST_SCHEMA_VERSION\s*=\s*(\d+)", migrate, re.MULTILINE)

    assert in_store, "CURRENT_DB_SCHEMA_VERSION не найдена в sqlite_store.py"
    assert in_migrate, "LATEST_SCHEMA_VERSION не найдена в scripts/db_migrate.py"
    assert in_store.group(1) == in_migrate.group(1), (
        f"версия схемы разошлась: хранилище {in_store.group(1)}, миграции {in_migrate.group(1)}"
    )
    assert in_store.group(1) in declared, f"справочник: {declared}, код: {in_store.group(1)}"


def test_detection_protocol_coverage_matches_its_document() -> None:
    """«11 из 26» сверяется с `docs/detection_quality.md`, где протокол и описан."""
    declared = _numeric_facts()["Инвариантов с baseline-протоколом детектирования"]
    quality = (_REPO_ROOT / "docs" / "detection_quality.md").read_text(encoding="utf-8")
    covered = re.search(r"(\d+)\s+из\s+(\d+)\s+инвариантов", quality)

    assert covered, "объём протокола не найден в docs/detection_quality.md"
    assert covered.group(1) in declared, f"справочник: {declared}, протокол: {covered.group(0)}"
    assert covered.group(2) == str(len(list(InvariantId)))
