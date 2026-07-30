"""Курсорная пагинация: непрозрачный токен на основе монотонного ``seq``.

Курсор — base64url(``"seq:<n>"``). Токен непрозрачен для клиента и устойчив к
вставкам (в отличие от offset). ``limit`` ограничен сверху значением 200.
"""

from __future__ import annotations

import base64
import binascii

MAX_LIMIT = 200
DEFAULT_LIMIT = 50


def encode_cursor(seq: int) -> str:
    """Закодировать позицию ``seq`` в непрозрачный курсор."""
    raw = f"seq:{int(seq)}".encode()
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cursor(token: str | None) -> int | None:
    """Декодировать курсор в ``seq``; ``None`` при отсутствии токена.

    Некорректный токен приводит к ``ValueError`` (маршрут вернёт 400).
    """
    if token is None or token == "":
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("некорректный cursor") from exc
    if not raw.startswith("seq:"):
        raise ValueError("некорректный cursor")
    try:
        return int(raw[len("seq:") :])
    except ValueError as exc:
        raise ValueError("некорректный cursor") from exc


def bound_limit(limit: int | None) -> int:
    """Ограничить ``limit`` диапазоном [1, 200] со значением по умолчанию 50."""
    if limit is None:
        return DEFAULT_LIMIT
    return max(1, min(int(limit), MAX_LIMIT))
