"""RBAC для ``/api/v1``: роли и зависимость ``require_role``.

Матрица ролей реализует ``docs/pt_techlab/rbac_matrix.md``:
    analyst_l1 < analyst_l2 < admin по правам записи; manager — только чтение.
Старые роли поддерживаются для совместимости: operator→analyst_l2, auditor→manager.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from fastapi import Request

from takt.interface_adapters.api.v1.problem import ProblemException


class Role(StrEnum):
    ANALYST_L1 = "analyst_l1"
    ANALYST_L2 = "analyst_l2"
    MANAGER = "manager"
    ADMIN = "admin"


# Ранг для иерархических сравнений (write-права).
ROLE_RANK: dict[str, int] = {
    "manager": 0,
    "analyst_l1": 1,
    "analyst_l2": 2,
    "admin": 3,
    # Обратная совместимость.
    "auditor": 0,
    "operator": 2,
}

# Каноникализация устаревших ролей.
_ROLE_ALIASES = {"operator": "analyst_l2", "auditor": "manager"}


def canonical_role(raw: str | None) -> str | None:
    if not raw:
        return None
    value = raw.strip().lower()
    value = _ROLE_ALIASES.get(value, value)
    return value if value in {r.value for r in Role} else None


def role_from_request(request: Request) -> str | None:
    """Роль запроса: из middleware (``state.takt_role``) либо заголовка ``X-Role``."""
    state_role = getattr(request.state, "takt_role", None)
    role = canonical_role(state_role) if isinstance(state_role, str) else None
    if role is None:
        role = canonical_role(request.headers.get("X-Role"))
    return role


def require_role(*allowed: Role | str) -> Callable[[Request], str]:
    """FastAPI-зависимость: пропустить только перечисленные роли (или роль выше по рангу).

    Правило иерархии: если среди ``allowed`` есть write-роль уровня L1/L2, любой
    более привилегированный ранг также допускается (admin может всё, что L2/L1).
    Для явно перечисленного ``manager`` совпадение — точное (read-only роль).
    """
    allowed_values = {a.value if isinstance(a, Role) else str(a) for a in allowed}
    min_write_rank = min(
        (ROLE_RANK[v] for v in allowed_values if v in {"analyst_l1", "analyst_l2", "admin"}),
        default=None,
    )

    def _dependency(request: Request) -> str:
        role = role_from_request(request)
        if role is None:
            raise ProblemException(
                status=401,
                title="Unauthorized",
                detail="роль не определена (ожидается ключ с ролью или заголовок X-Role)",
                type_suffix="missing-role",
            )
        if role in allowed_values:
            return role
        if min_write_rank is not None and ROLE_RANK.get(role, -1) >= min_write_rank:
            return role
        raise ProblemException(
            status=403,
            title="Forbidden",
            detail=f"роль '{role}' недостаточна для операции (нужна одна из {sorted(allowed_values)})",
            type_suffix="insufficient-role",
        )

    return _dependency
