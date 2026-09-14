"""Состав демонстрационного пакета: сторож против расхождения с репозиторием.

Пакет собирается отбором путей, а не архивацией каталога: заказчику не передаются
документы с адресами стендов, данные прогонов и артефакты сборки. Цена отбора —
список, который молча устаревает. Здесь он сверяется с кодом.

Главная проверка — документы. Пояснения в АРМ ссылаются на файлы репозитория
(поле `doc` реестра `HELP` в `app.js`). Ссылка, для которой в пакете нет документа,
даёт аналитику 404 вместо пояснения, и заметить это можно только открыв каждое
пояснение на стенде заказчика.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_demo_package", ROOT / "scripts" / "build_demo_package.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = _load_builder()


def _arm_doc_references() -> set[str]:
    """Пути документов, на которые ссылаются пояснения АРМ."""
    app_js = (ROOT / "frontend" / "takt-pt-arm" / "app.js").read_text(encoding="utf-8")
    return set(re.findall(r"doc:\s*'([^']+)'", app_js))


def test_arm_help_documents_are_packaged() -> None:
    packaged = {f"docs/{item}" for item in BUILDER.DOC_FILES}
    missing = sorted(_arm_doc_references() - packaged)
    assert not missing, (
        "пояснения АРМ ссылаются на документы, которых нет в пакете — "
        f"добавьте их в DOC_FILES: {missing}"
    )


def test_packaged_documents_exist() -> None:
    missing = [item for item in BUILDER.DOC_FILES if not (ROOT / "docs" / item).is_file()]
    assert not missing, f"в DOC_FILES перечислены несуществующие документы: {missing}"


@pytest.mark.parametrize("source", [source for source, _ in BUILDER.CORE_FILES])
def test_core_file_exists(source: str) -> None:
    assert (ROOT / source).is_file(), f"файл пакета отсутствует в репозитории: {source}"


@pytest.mark.parametrize("source", [source for source, _ in BUILDER.CORE_DIRS])
def test_core_dir_exists(source: str) -> None:
    assert (ROOT / source).is_dir(), f"каталог пакета отсутствует в репозитории: {source}"


@pytest.mark.parametrize("item", BUILDER.ARM_FILES)
def test_arm_file_exists(item: str) -> None:
    path = ROOT / "frontend" / "takt-pt-arm" / item
    if item in {"app.min.js"}:
        # Артефакт сборки в git не хранится; сборщик пакета создаёт его сам.
        pytest.skip("артефакт сборки АРМ создаётся при сборке пакета")
    assert path.is_file(), f"файл АРМ отсутствует: {item}"


@pytest.mark.parametrize("item", BUILDER.DATASET_FILES)
def test_dataset_file_exists(item: str) -> None:
    path = ROOT / "tests" / "fixtures" / "pt_techlab" / "inc_002" / item
    assert path.is_file(), f"файл демонстрационных данных отсутствует: {item}"


def test_docs_base_is_rewritten_to_local(tmp_path: Path) -> None:
    """В пакете база документации переводится на локальную раздачу.

    В репозитории она указывает на публичный GitHub: у заказчика на изолированном
    контуре такая ссылка не откроется.
    """
    env_js = tmp_path / "env.js"
    env_js.write_text(
        "// комментарий\nwindow.TAKT_DOCS_BASE = 'https://github.com/example/blob/main/';\n",
        encoding="utf-8",
    )
    BUILDER._set_docs_base(env_js)
    text = env_js.read_text(encoding="utf-8")
    assert "window.TAKT_DOCS_BASE = './';" in text
    assert "github.com" not in text
    assert text.startswith("// комментарий")


def test_stand_deploy_docs_are_not_packaged() -> None:
    """Документы выкладки содержат адрес боевой ВМ и учётную запись — наружу не идут."""
    packaged = set(BUILDER.DOC_FILES)
    assert not {item for item in packaged if item.startswith("stand/")}
