from __future__ import annotations

from urllib.parse import urlencode

from fastapi import Request

# Верхняя граница смещения страницы для маршрутов, где смещение уходит прямо в SQL `OFFSET`
# (`/events/search`, карточка сущности). Без границы значение больше 2^63−1 роняло запрос —
# «OverflowError: Python int too large to convert to SQLite INTEGER» — и клиент получал 500
# вместо отказа; поймано прогоном schemathesis. Миллион выбран как заведомо недостижимый
# предел листания: он на порядок выше корпуса бэктеста в 100 000 событий и на много порядков
# ниже переполнения, то есть отсекает бессмысленное, не трогая рабочие страницы.
MAX_PAGE_OFFSET = 1_000_000


def offset_limit_link_header(
    request: Request,
    *,
    offset: int,
    limit: int | None,
    total_before_slice: int,
) -> str | None:
    if limit is None or total_before_slice == 0:
        return None
    raw_pairs = list(request.query_params.multi_items())
    path = request.url.path
    chunks: list[str] = []

    def href(new_offset: int) -> str:
        pairs = [(k, v) for k, v in raw_pairs if k not in ("offset", "limit")]
        pairs.append(("offset", str(new_offset)))
        pairs.append(("limit", str(limit)))
        return f"{path}?{urlencode(pairs)}"

    if offset + limit < total_before_slice:
        chunks.append(f'<{href(offset + limit)}>; rel="next"')
    if offset > 0:
        chunks.append(f'<{href(max(0, offset - limit))}>; rel="prev"')
    return ", ".join(chunks) if chunks else None
