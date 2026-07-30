"""Внутрипроцессный брокер SSE-событий об изменении статуса кейсов.

Хранит кольцевой буфер последних событий (для реплея новым подписчикам) и
раздаёт события живым подписчикам через ``asyncio.Queue``.
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Any


class CaseEventBroadcaster:
    """Простой pub/sub для событий кейсов (без внешних зависимостей)."""

    def __init__(self, buffer_size: int = 256) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def publish(self, event: dict[str, Any]) -> None:
        """Опубликовать событие: сохранить в буфер и разослать подписчикам."""
        self._buffer.append(event)
        for queue in list(self._subscribers):
            queue.put_nowait(event)

    def recent(self, limit: int) -> list[dict[str, Any]]:
        """Последние ``limit`` событий из буфера (для реплея)."""
        if limit <= 0:
            return []
        items = list(self._buffer)
        return items[-limit:]

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)
