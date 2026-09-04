"""RBAC-матрица маршрутов API поверх ролей из `api_keys.py`.

Роли: `operator`, `auditor`, `admin`. Иерархия для write-операций:
`admin` может всё, что может `operator`; `auditor` — только чтение
(включая `POST /forensic-bundle/verify`, который не меняет состояние).

Не публичные, не GET/HEAD пути по умолчанию требуют роль `operator`
(или `admin`); явно перечисленные административные операции (массовый
импорт кейсов, форвардинг в SIEM, сервисный аудит engagement, правка
весов оценки риска) требуют роль `admin`.
"""

from __future__ import annotations

_READ_LIKE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# Пути, где даже не-GET запрос не меняет постоянное состояние дела/системы
# и потому доступен auditor наравне с operator/admin.
_READ_EQUIVALENT_PATHS: frozenset[str] = frozenset({"/forensic-bundle/verify"})

# Административные операции: массовый импорт, исходящая пересылка в SIEM,
# сервисный workflow аудита (engagement), правка весов оценки риска.
#
# Веса здесь потому, что правка меняет оценку всех последующих дел, а не одного открытого:
# это настройка продукта, а не шаг расследования.
_ADMIN_ONLY_PREFIXES: tuple[str, ...] = (
    "/cases/import/full.json",
    "/integrations/siem/forward",
    "/audit-engagements",
    "/config/risk-weights",
)

ROLE_RANK: dict[str, int] = {
    "manager": 0,
    "analyst_l1": 1,
    "analyst_l2": 2,
    "admin": 3,
    # Backward-compatible aliases.
    "auditor": 0,
    "operator": 2,
}

_L2_SUFFIXES: tuple[str, ...] = (
    "/merge",
    "/split",
    "/events/attach",
)


def _requires_l2(path: str) -> bool:
    if not path.startswith("/cases/"):
        return False
    return path.endswith(_L2_SUFFIXES) or ("/events/" in path and path.endswith("/detach"))


def required_role_for_route(method: str, path: str) -> str | None:
    """Минимальная роль для маршрута; `None` — доступно любой аутентифицированной роли."""
    if method.upper() in _READ_LIKE_METHODS:
        return None
    if path in _READ_EQUIVALENT_PATHS:
        return None
    if any(path == p or path.startswith(f"{p}/") for p in _ADMIN_ONLY_PREFIXES):
        return "admin"
    if _requires_l2(path):
        return "analyst_l2"
    return "analyst_l1"


def role_satisfies(role: str, required: str | None) -> bool:
    if required is None:
        return role in ROLE_RANK
    if required in {"operator", "analyst_l1"}:
        return ROLE_RANK.get(role, -1) >= ROLE_RANK["analyst_l1"]
    if required == "analyst_l2":
        return ROLE_RANK.get(role, -1) >= ROLE_RANK["analyst_l2"]
    if required == "admin":
        return role == "admin"
    return False
