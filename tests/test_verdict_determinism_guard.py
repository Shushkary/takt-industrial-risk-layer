"""Сторож детерминизма контура вердикта (L1 Domain + L2 Application).

Юридическая значимость доказательного пакета держится на воспроизводимости: повторный прогон
на тех же входных данных обязан дать тот же вердикт (LEG / ILLEG / UNDET), то же объяснение и
то же агрегированное контрольное значение манифеста. Любой недетерминированный компонент внутри
контура вынесения вердикта — обращение к внешнему сервису, генератор случайных чисел, вызов LLM —
разрушает это свойство: экспертиза не сможет воспроизвести результат.

Поэтому в `takt.domain` и `takt.application` запрещены импорты сетевых клиентов, генераторов
случайности и SDK языковых моделей. ИИ-ассистент допустим только как изолированный модуль вне
контура вердикта (см. `docs/product_boundary.md`, раздел «Детерминизм вердикта»).

Смежные сторожи: `tests/test_domain_ast_policy.py` (время и uuid), контракты `import-linter`.
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_VERDICT_PATH_ROOTS = (
    _REPO_ROOT / "src" / "takt" / "domain",
    _REPO_ROOT / "src" / "takt" / "application",
)

# Корни модулей, запрещённые в контуре вердикта, с причиной для сообщения об ошибке.
_FORBIDDEN_ROOTS: dict[str, str] = {
    # Сетевые вызовы: внешний ответ невоспроизводим и делает вердикт зависимым от среды.
    "httpx": "сетевой вызов в контуре вердикта",
    "requests": "сетевой вызов в контуре вердикта",
    "aiohttp": "сетевой вызов в контуре вердикта",
    "socket": "сетевой вызов в контуре вердикта",
    "http": "сетевой вызов в контуре вердикта",
    "ftplib": "сетевой вызов в контуре вердикта",
    "smtplib": "сетевой вызов в контуре вердикта",
    "telnetlib": "сетевой вызов в контуре вердикта",
    "xmlrpc": "сетевой вызов в контуре вердикта",
    # Случайность: два прогона на одних данных дадут разный результат.
    "random": "источник недетерминизма (используй детерминированный порядок или порт)",
    "secrets": "источник недетерминизма (криптография и токены — инфраструктурный слой)",
    # LLM и ML-инференс: недетерминированный вывод внутри вердикта недопустим,
    # ИИ-ассистент выносится в изолированный модуль вне контура вердикта.
    "openai": "LLM в контуре вердикта",
    "anthropic": "LLM в контуре вердикта",
    "llama_cpp": "LLM в контуре вердикта",
    "transformers": "инференс модели в контуре вердикта",
    "torch": "инференс модели в контуре вердикта",
    "onnxruntime": "инференс модели в контуре вердикта",
    "takt.ai": "изолированный ИИ-модуль не должен попадать в контур вердикта",
}

# Точечные исключения: детерминированные подмодули запрещённых корней.
_ALLOWED_PREFIXES: tuple[str, ...] = (
    "urllib.parse",  # разбор строк, без сетевого обращения
)

# `urllib` целиком запрещать нельзя (используется `urllib.parse`), поэтому проверяем подмодули.
_FORBIDDEN_PREFIXES: tuple[tuple[str, str], ...] = (
    ("urllib.request", "сетевой вызов в контуре вердикта"),
    ("urllib.error", "сетевой вызов в контуре вердикта"),
)


def _imported_names(tree: ast.AST) -> list[tuple[str, int]]:
    """Собирает полные имена импортируемых модулей вместе с номерами строк."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # относительный импорт внутри пакета — всегда свой код
                continue
            if node.module:
                found.append((node.module, node.lineno))
    return found


def _violation_reason(module: str) -> str | None:
    """Возвращает причину запрета для импортируемого модуля или None, если импорт допустим."""
    if any(module == prefix or module.startswith(prefix + ".") for prefix in _ALLOWED_PREFIXES):
        return None
    for prefix, reason in _FORBIDDEN_PREFIXES:
        if module == prefix or module.startswith(prefix + "."):
            return reason
    root = module.split(".")[0]
    if root in _FORBIDDEN_ROOTS:
        return _FORBIDDEN_ROOTS[root]
    if module == "takt.ai" or module.startswith("takt.ai."):
        return _FORBIDDEN_ROOTS["takt.ai"]
    return None


def test_verdict_path_has_no_nondeterministic_imports() -> None:
    """В домене и слое приложения нет сетевых вызовов, случайности и вызовов LLM."""
    violations: list[str] = []
    for root in _VERDICT_PATH_ROOTS:
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for module, lineno in _imported_names(tree):
                reason = _violation_reason(module)
                if reason is not None:
                    violations.append(f"{path.relative_to(_REPO_ROOT)}:{lineno}: import {module} — {reason}")
    assert not violations, (
        "Нарушен детерминизм контура вердикта (см. docs/product_boundary.md):\n" + "\n".join(violations)
    )


def test_allowed_deterministic_stdlib_is_not_flagged() -> None:
    """Проверка самого правила: детерминированные модули не считаются нарушением."""
    assert _violation_reason("urllib.parse") is None
    assert _violation_reason("datetime") is None
    assert _violation_reason("takt.domain.entities.case") is None


def test_rule_flags_known_violations() -> None:
    """Проверка самого правила: запрещённые импорты действительно ловятся."""
    for module in ("httpx", "requests.adapters", "random", "openai", "urllib.request", "takt.ai.search"):
        assert _violation_reason(module) is not None, module
