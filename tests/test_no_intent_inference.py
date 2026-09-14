"""T6. Вывод системы не содержит суждений об умысле, вине и мотиве.

ТАКТ восстанавливает **путь**: последовательность наблюдённых событий и её отношение к
разрешительному полю. Мотив по наблюдениям не восстанавливается. `ILLEG` означает ровно
«путь не согласован с нарядом, заявкой или окном работ» — и ничего сверх этого.

Различие не стилистическое. Умысел и вина — элементы субъективной стороны деяния, и их
установление относится к компетенции суда (для ст. 274.1 УК РФ умысел подлежит доказыванию).
Продукт, который в выводе называет действие умышленным, подменяет собой суд и делает
доказательный пакет уязвимым ровно в том месте, ради которого он собирается.

**Область проверки — только то, что видит пользователь.** Сканируются строковые литералы
кода (в питоне — через AST, поэтому комментарии и docstring в область не попадают вовсе),
заголовки инвариантов из конфигурации и пользовательские строки АРМ. Технические документы,
комментарии и юридические ссылки исключены намеренно: без этого тест поймал бы собственную
формулировку границы и превратился бы в шум.

Смежная граница: `docs/product_boundary.md`, раздел «Объективная сторона деяния — да; умысел,
вина, мотив — никогда».
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]

# Лексемы субъективной стороны. Границы слова расставлены так, чтобы не ловить однокоренные
# слова с другим значением: «намеренно» (то есть «сознательно, по решению разработчика») —
# служебное слово документации, а не суждение о намерении субъекта.
_FORBIDDEN: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("умысел", re.compile(r"умысл[а-я]*|умысел", re.IGNORECASE)),
    ("умышленность", re.compile(r"умышленн[а-я]*|умышленно", re.IGNORECASE)),
    ("вина", re.compile(r"\bвин[аеуы]\b|виновн[а-я]*", re.IGNORECASE)),
    ("намерение", re.compile(r"намерени[а-я]*|с намерением", re.IGNORECASE)),
    ("злоумышленник", re.compile(r"злоумышл[а-я]*", re.IGNORECASE)),
    ("преступность деяния", re.compile(r"преступн[а-я]*", re.IGNORECASE)),
    ("цель причинения вреда", re.compile(r"с целью причинени[а-я]*", re.IGNORECASE)),
)

# Что показывается пользователю: русские подписи домена, сборка итогового описания, пакет
# реагирования, выгрузки и отчёты, заголовки инвариантов, строки АРМ.
_OUTPUT_SOURCES: tuple[str, ...] = (
    "src/takt/domain/vocabulary.py",
    "src/takt/domain/services",
    "src/takt/application/use_cases/investigation_summary.py",
    "src/takt/application/use_cases/response_package.py",
    "src/takt/application/use_cases/remediation.py",
    "src/takt/application/use_cases/reconstruct_chain.py",
    "src/takt/application/use_cases/compliance_report.py",
    "src/takt/infrastructure/export",
    "config/invariants",
    "frontend/takt-pt-arm/app.js",
    "frontend/takt-pt-arm/index.html",
)

# Белый список: пути, где перечисленные лексемы допустимы по существу. Это места, где продукт
# формулирует саму границу — то есть говорит, чего он не утверждает.
_WHITELIST: frozenset[str] = frozenset(
    {
        "docs/product_boundary.md",
        "tests/test_no_intent_inference.py",
    }
)


def _python_string_literals(path: Path) -> list[tuple[int, str]]:
    """Строковые литералы модуля без docstring: то, что может уйти пользователю."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))

    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            found.append((node.lineno, node.value))
    return found


def _plain_text_lines(path: Path) -> list[tuple[int, str]]:
    return list(enumerate(path.read_text(encoding="utf-8").splitlines(), start=1))


def _scan_targets() -> list[Path]:
    targets: list[Path] = []
    for entry in _OUTPUT_SOURCES:
        node = _REPO_ROOT / entry
        if node.is_dir():
            targets.extend(
                p
                for p in sorted(node.rglob("*"))
                if p.is_file() and p.suffix in {".py", ".yaml", ".yml", ".js", ".html"}
            )
        elif node.is_file():
            targets.append(node)
    return [p for p in targets if p.relative_to(_REPO_ROOT).as_posix() not in _WHITELIST]


def _occurrences() -> list[tuple[str, int, str, str]]:
    """(путь, строка, лексема, фрагмент) по всем сканируемым источникам вывода."""
    hits: list[tuple[str, int, str, str]] = []
    for path in _scan_targets():
        rel = path.relative_to(_REPO_ROOT).as_posix()
        chunks = _python_string_literals(path) if path.suffix == ".py" else _plain_text_lines(path)
        for lineno, text in chunks:
            for label, pattern in _FORBIDDEN:
                match = pattern.search(text)
                if match:
                    hits.append((rel, lineno, label, text.strip()[:160]))
    return hits


def test_output_contains_no_judgement_about_intent_or_guilt() -> None:
    """В пользовательском выводе нет лексем субъективной стороны деяния."""
    hits = _occurrences()
    report = "\n".join(f"  {rel}:{line} — «{label}» в: {snippet}" for rel, line, label, snippet in hits)

    assert not hits, (
        "в шаблонах вывода найдены суждения о субъективной стороне деяния.\n"
        "Продукт восстанавливает путь, а не мотив: умысел и вина устанавливаются судом.\n"
        f"{report}"
    )


def test_scanner_actually_reads_something() -> None:
    """Страховка: пустая область сканирования сделала бы тест тождественно зелёным."""
    targets = _scan_targets()
    assert len(targets) >= 10, f"область сканирования подозрительно мала: {len(targets)} файлов"


def test_scanner_catches_a_planted_phrase(tmp_path: Path) -> None:
    """Страховка: лексемы действительно ловятся, а регулярные выражения не сломаны."""
    planted = "Действия совершены умышленно, с целью причинения вреда"
    matched = [label for label, pattern in _FORBIDDEN if pattern.search(planted)]
    assert "умышленность" in matched
    assert "цель причинения вреда" in matched


def test_scanner_does_not_catch_the_word_deliberately() -> None:
    """«Намеренно» — служебное слово документации, а не суждение о намерении субъекта.

    Без этой проверки лексема «намерени» поймала бы сорок с лишним технических «намеренно»
    по репозиторию, и гвард пришлось бы отключить как шумный.
    """
    benign = "Поле в список намеренно не входит: это состояние домена, а не значение пароля"
    matched = [label for label, pattern in _FORBIDDEN if pattern.search(benign)]
    assert matched == [], f"служебное «намеренно» поймано как суждение об умысле: {matched}"
