"""L3 Interface Adapters — версия API ``/api/v1`` (итерация 1: чистая архитектура).

Содержит: единый обработчик ошибок RFC 9457, RBAC-зависимость ``require_role``,
курсорную пагинацию, SSE-поток изменений кейсов и роутеры под префиксом ``/api/v1``.
"""

from takt.interface_adapters.api.v1.wiring import register_v1

__all__ = ["register_v1"]
