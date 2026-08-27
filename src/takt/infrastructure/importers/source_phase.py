"""Фаза цепочки по классификации, объявленной средством обнаружения.

Датасет AIT-ADS отдаёт фазу отдельной колонкой, и такое событие приходит в продукт уже
размеченным. Стенд PT фазу не передаёт: в схемах PT NAD колонки для неё нет, а PT SIEM
классифицирует инцидент категорией (`incident.category`). Без перевода этой категории в фазу
вкладка «Симуляция» на данных стенда пуста — цепочка строится только из размеченных событий.

Здесь фаза дописывается в `payload` ровно тогда, когда источник её не проставил, и всегда
вместе с происхождением: из какого поля и какого значения она выведена и на каком основании.
Это разделяет два разных утверждения — «источник сообщил фазу» и «фаза выведена из категории
источника», — и аналитик видит разницу в окне шага.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from takt.domain.entities.kill_chain import (
    PHASE_FIELD,
    PHASE_ORIGIN_FIELD,
    PHASE_REASON_FIELD,
    parse_phase,
)
from takt.infrastructure.config.source_phase_map_yaml import (
    SourcePhaseMap,
    default_source_phase_map_path,
    load_source_phase_map_cached,
)

logger = logging.getLogger(__name__)

_ENV_PATH = "TAKT_KILL_CHAIN_MAP"


def source_phase_map() -> SourcePhaseMap | None:
    """Таблица перевода. Её отсутствие не останавливает приём: события идут без фазы."""
    path = os.environ.get(_ENV_PATH, "").strip() or str(default_source_phase_map_path())
    try:
        return load_source_phase_map_cached(path)
    except FileNotFoundError:
        logger.warning("kill chain map not found path=%s", path)
        return None
    except ValueError as exc:
        # Ошибку в таблице показываем в логе и работаем без перевода: приписать фазу по
        # сломанной таблице хуже, чем не приписать вовсе.
        logger.warning("kill chain map is invalid path=%s reason=%s", path, exc)
        return None


def annotate_phase(payload: dict[str, Any]) -> dict[str, Any]:
    """Дописать фазу, если источник её не проставил.

    Готовая разметка приоритетна и никогда не перезаписывается: событие, где фазу назвал сам
    источник, — более сильное утверждение, чем перевод категории.
    """
    if parse_phase(payload.get(PHASE_FIELD)) is not None:
        return payload
    mapping = source_phase_map()
    if mapping is None:
        return payload
    found = mapping.phase_for_payload(payload)
    if found is None:
        return payload
    phase, origin, reason = found
    payload[PHASE_FIELD] = phase.value
    payload[PHASE_ORIGIN_FIELD] = origin
    payload[PHASE_REASON_FIELD] = reason
    return payload


__all__ = ["annotate_phase", "source_phase_map"]
