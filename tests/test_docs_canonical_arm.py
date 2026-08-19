"""Документы-источники правды называют канонический АРМ однозначно.

Прецедент: `CLAUDE.md` называл основным `frontend/takt-pt-arm`, а `docs/pt_techlab/prototype.md`
и таблица критериев §12.5 вели жюри в `frontend/takt-arm`. Для заявки это хуже опечатки:
эксперт открывает не тот интерфейс и видит не тот сценарий.

Канонический интерфейс — `frontend/takt-pt-arm` (решение от 2026-08-03). Второй фронтенд
остаётся в проекте как вспомогательный, поэтому полностью запретить упоминания нельзя —
проверяется другое: рядом с каждым упоминанием вспомогательного АРМ стоит пометка о его роли,
в самой строке или в ближайшем заголовке над ней.

Исторические документы (планы спринтов, отчёт аудита) намеренно не проверяются: они фиксируют
состояние на момент написания.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]

_CANONICAL_ARM = "takt-pt-arm"
_AUXILIARY_ARM = "takt-arm"

# Документы, которые читает жюри и разработчик, начиная работу.
_ENTRY_POINT_DOCS: tuple[str, ...] = (
    "README.md",
    "CLAUDE.md",
    "docs/pt_techlab/README.md",
    "docs/pt_techlab/prototype.md",
)

# Достаточно любой из пометок: важно, что роль второго фронтенда названа рядом.
_ROLE_MARKERS: tuple[str, ...] = ("вспомогательн", "не для демо")

_HEADING = re.compile(r"^#{1,6}\s")


def _mentions_auxiliary(line: str) -> bool:
    """Строка упоминает вспомогательный АРМ (а не канонический)."""
    # `takt-pt-arm` не содержит подстроку `takt-arm`, поэтому проверка прямая.
    return _AUXILIARY_ARM in line


def _has_marker(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _ROLE_MARKERS)


def _nearest_heading(lines: list[str], index: int) -> str:
    for candidate in range(index, -1, -1):
        if _HEADING.match(lines[candidate]):
            return lines[candidate]
    return ""


def test_auxiliary_arm_is_always_marked_as_auxiliary() -> None:
    """Во входных документах вспомогательный АРМ не выглядит основным."""
    violations: list[str] = []
    for rel_path in _ENTRY_POINT_DOCS:
        path = _REPO_ROOT / rel_path
        assert path.exists(), f"{rel_path}: документ отсутствует, обнови список в тесте"
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            if not _mentions_auxiliary(line):
                continue
            if _has_marker(line) or _has_marker(_nearest_heading(lines, number)):
                continue
            violations.append(f"{rel_path}:{number + 1}: «{line.strip()}» — роль АРМ не названа")
    assert not violations, (
        f"Вспомогательный АРМ подан как основной (канонический — frontend/{_CANONICAL_ARM}):\n"
        + "\n".join(violations)
    )


def test_criteria_table_points_to_canonical_arm() -> None:
    """Критерий 5 ТЗ (удобство пользователя) ведёт жюри в канонический АРМ."""
    text = (_REPO_ROOT / "docs" / "pt_techlab" / "README.md").read_text(encoding="utf-8")
    rows = [line for line in text.splitlines() if line.startswith("| 5 |")]
    assert len(rows) == 1, "строка критерия 5 в таблице §12.5 не найдена или не одна"
    assert _CANONICAL_ARM in rows[0], rows[0]


def test_canonical_arm_directory_exists() -> None:
    """Канонический АРМ — реальный каталог, а не только упоминание в тексте."""
    assert (_REPO_ROOT / "frontend" / _CANONICAL_ARM / "index.html").is_file()


def test_rule_detects_unmarked_mention() -> None:
    """Проверка самого правила: помеченное упоминание проходит, непомеченное — нет."""
    assert _mentions_auxiliary("см. frontend/takt-arm") is True
    assert _mentions_auxiliary("см. frontend/takt-pt-arm") is False
    assert _has_marker("| `frontend/takt-arm` | Вспомогательный |") is True
    assert _has_marker("cd frontend/takt-arm && npm ci") is False
