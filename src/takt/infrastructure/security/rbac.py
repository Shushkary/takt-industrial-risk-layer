"""RBAC-матрица маршрутов API поверх ролей из `api_keys.py`.

Роли: `operator`, `auditor`, `admin`. Иерархия для write-операций:
`admin` может всё, что может `operator`; `auditor` — только чтение
(включая `POST /forensic-bundle/verify`, который не меняет состояние).

Не публичные, не GET/HEAD пути по умолчанию требуют роль `operator`
(или `admin`); явно перечисленные административные операции (массовый
импорт кейсов, форвардинг в SIEM, сервисный аудит engagement) требуют
роль `admin`.
"""

from __future__ import annotations

_READ_LIKE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# Пути, где даже не-GET запрос не меняет постоянное состояние дела/системы
# и потому доступен auditor наравне с operator/admin.
_READ_EQUIVALENT_PATHS: frozenset[str] = frozenset({"/forensic-bundle/verify"})

# Административные операции: массовый импорт, исходящая пересылка в SIEM,
# сервисный workflow аудита (engagement).
_ADMIN_ONLY_PREFIXES: tuple[str, ...] = (
    "/cases/import/full.json",
    "/integrations/siem/forward",
    "/audit-engagements",
)

ROLE_RANK: dict[str, int] = {"auditor": 0, "operator": 1, "admin": 2}


def required_role_for_route(method: str, path: str) -> str | None:
    """Минимальная роль для маршрута; `None` — доступно любой аутентифицированной роли."""
    if method.upper() in _READ_LIKE_METHODS:
        return None
    if path in _READ_EQUIVALENT_PATHS:
        return None
    if any(path == p or path.startswith(f"{p}/") for p in _ADMIN_ONLY_PREFIXES):
        return "admin"
    return "operator"


def role_satisfies(role: str, required: str | None) -> bool:
    if required is None:
        return role in ROLE_RANK
    if required == "operator":
        return role in ("operator", "admin")
    if required == "admin":
        return role == "admin"
    return False
