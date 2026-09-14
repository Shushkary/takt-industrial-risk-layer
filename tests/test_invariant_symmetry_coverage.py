"""T4. Каждый инвариант каталога объявляет защищаемую симметрию.

Инвариант — это утверждение о том, что некоторая величина процесса не меняется без
регламентной причины: маршрут доступа, период опроса, состав сегмента, разрешительное поле.
Колонка «Защищаемая симметрия» в `docs/invariant_matrix.md` называет эту величину явно.

Смысл проверки не в полноте документации. Инвариант, не защищающий ни одной симметрии, —
кандидат на ревизию как ad hoc-проверка: он ловит частный признак, а не удерживает свойство
процесса, и на разборе с экспертом такой пункт защитить нечем.

`TBD` допускается и не роняет тест: честно названная незаполненная клетка полезнее выдуманной
формулировки. Число `TBD` печатается в отчёт прогона, чтобы оно не росло молча.

Размер каталога здесь не проверяется и не дублируется: он живёт в
`docs/current_operational_reference.md` и сверяется тестом
`tests/test_docs_invariant_count_consistency.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

from takt.domain.invariants.catalog import InvariantId

_REPO_ROOT = Path(__file__).resolve().parents[1]
_MATRIX = _REPO_ROOT / "docs" / "invariant_matrix.md"

_TBD = "TBD"

# Строка таблицы: `| \`id\` | детектирует | вход | статус | симметрия |`
_ROW = re.compile(r"^\|\s*`([a-z0-9_]+)`\s*\|(.+)\|\s*$")


def _symmetry_by_id() -> dict[str, str]:
    """Идентификатор инварианта → содержимое колонки «Защищаемая симметрия»."""
    found: dict[str, str] = {}
    for line in _MATRIX.read_text(encoding="utf-8").splitlines():
        match = _ROW.match(line.strip())
        if not match:
            continue
        columns = [c.strip() for c in match.group(2).split("|")]
        if len(columns) < 4:
            continue
        found[match.group(1)] = columns[-1]
    return found


def test_every_invariant_has_a_row_in_the_matrix() -> None:
    """Ни один член `InvariantId` не остался без строки каталога."""
    documented = set(_symmetry_by_id())
    declared = {member.value for member in InvariantId}

    assert declared - documented == set(), (
        "в матрице нет строк для инвариантов: " f"{sorted(declared - documented)}"
    )


def test_matrix_has_no_rows_for_unknown_invariants() -> None:
    """Обратная сторона: в каталоге нет строк для инвариантов, которых нет в коде."""
    documented = set(_symmetry_by_id())
    declared = {member.value for member in InvariantId}

    assert documented - declared == set(), (
        "в матрице есть строки без соответствующего InvariantId: " f"{sorted(documented - declared)}"
    )


def test_every_invariant_declares_a_protected_symmetry() -> None:
    """Колонка симметрии заполнена у всех — значением или честным TBD."""
    empty = sorted(key for key, value in _symmetry_by_id().items() if not value)

    assert not empty, (
        "колонка «Защищаемая симметрия» пуста у инвариантов: "
        f"{empty}. Поставьте TBD, если симметрия не определена — пустая клетка "
        "неотличима от забытой."
    )


def test_report_how_many_symmetries_are_undecided(capsys) -> None:
    """Число `TBD` печатается в вывод прогона: оно не должно расти незаметно.

    Тест намеренно не делает `TBD` ошибкой. Порог здесь был бы произволом: каталог не
    дописывается инженером в одиночку, часть симметрий требует решения владельца продукта.
    """
    undecided = sorted(key for key, value in _symmetry_by_id().items() if value == _TBD)
    total = len(_symmetry_by_id())

    with capsys.disabled():
        print(
            f"\n[T4] симметрия не определена у {len(undecided)} из {total} инвариантов: "
            f"{undecided or '—'}"
        )

    # Утверждение слабое намеренно: оно ловит вырождение каталога в сплошной TBD,
    # а не отсутствие конкретной формулировки.
    assert len(undecided) < total, "ни один инвариант не объявил симметрии — каталог выродился"
