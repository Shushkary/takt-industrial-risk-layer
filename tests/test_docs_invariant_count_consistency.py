"""Число инвариантов в документации совпадает с кодом и каталогом YAML.

Прецедент: после переноса `alert_fatigue_guard` в L2-пайплайн дедупликации часть документации
осталась с формулировкой «25 инвариантов», тогда как `InvariantId` и `config/invariants/*.yaml`
содержат 26 записей. Такое расхождение ловилось глазами при подготовке материалов для жюри и
сертификации — теперь ловится прогоном.

Проверяются только документы-источники правды. Исторические планы спринтов сознательно
исключены: они фиксируют состояние на момент написания и не переписываются задним числом.

Сверяются именно заявления о **размере каталога** («каталог N инвариантов», «матрица N
инвариантов», «проверка N инвариантов», «X из N инвариантов»). Утверждения о подмножествах
(«7 инвариантов отключены», «8 инвариантов Блоков 4-6») к размеру каталога не относятся
и намеренно не проверяются.
"""

from __future__ import annotations

import re
from pathlib import Path

from takt.domain.invariants.catalog import INVARIANT_RECORDS, InvariantId

_REPO_ROOT = Path(__file__).resolve().parents[1]

# Документы, которые обязаны отражать текущее состояние кода.
_AUTHORITATIVE_DOCS: tuple[str, ...] = (
    "README.md",
    "CLAUDE.md",
    "docs/current_operational_reference.md",
    "docs/product_boundary.md",
    "docs/invariant_matrix.md",
    "docs/detection_quality.md",
    "docs/threat_model.md",
    "docs/certification_risk_roadmap.md",
    "docs/pt_techlab/README.md",
)

# «каталог 26 инвариантов», «матрица 26 инвариантов», «проверка 26 инвариантов»,
# «26 инвариантов поведения» — заявления о полном каталоге.
# Слово «все» в шаблон не входит: «все 11 инвариантов в объёме протокола» — это подмножество.
_CATALOG_SIZE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:каталог\w*|матриц\w*|проверк\w*|полн\w+\s+набор\w*)\s+(?:из\s+)?(\d+)\s+"
        r"(?:доменн\w+\s+)?инвариант",
        re.IGNORECASE,
    ),
    re.compile(r"(\d+)\s+инвариантов\s+поведения", re.IGNORECASE),
    # «11 из 26 инвариантов», «7/26 инвариантов» — знаменатель равен размеру каталога.
    re.compile(r"\d+\s*(?:из|/)\s*(\d+)\s+инвариант", re.IGNORECASE),
)


def _expected_count() -> int:
    return len(InvariantId)


def test_yaml_catalog_matches_domain_enum() -> None:
    """Число YAML-файлов совпадает с числом записей enum и каталога записей."""
    yaml_files = sorted((_REPO_ROOT / "config" / "invariants").glob("*.yaml"))
    assert len(yaml_files) == _expected_count()
    assert len(INVARIANT_RECORDS) == _expected_count()


def test_authoritative_docs_state_actual_catalog_size() -> None:
    """Документы-источники правды не называют устаревший размер каталога инвариантов."""
    expected = _expected_count()
    violations: list[str] = []
    for rel_path in _AUTHORITATIVE_DOCS:
        path = _REPO_ROOT / rel_path
        if not path.exists():
            violations.append(f"{rel_path}: документ отсутствует, обнови список в тесте")
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in _CATALOG_SIZE_PATTERNS:
            for match in pattern.finditer(text):
                number = int(match.group(1))
                if number == expected:
                    continue
                line_no = text.count("\n", 0, match.start()) + 1
                fragment = " ".join(match.group(0).split())
                violations.append(f"{rel_path}:{line_no}: «{fragment}» — в коде {expected} инвариантов")
    assert not violations, "Документация разошлась с каталогом инвариантов:\n" + "\n".join(violations)


def test_pattern_detects_catalog_claims() -> None:
    """Проверка самого правила: заявления о каталоге распознаются, подмножества — нет."""

    def totals(text: str) -> list[int]:
        return [int(m.group(1)) for p in _CATALOG_SIZE_PATTERNS for m in p.finditer(text)]

    assert totals("каталог 25 инвариантов") == [25]
    assert totals("матрица 26 инвариантов") == [26]
    assert totals("11 из 26 инвариантов покрыты протоколом") == [26]
    assert totals("7 инвариантов отключены в проде") == []
    assert totals("8 инвариантов Блоков 4-6 требуют контекста") == []
