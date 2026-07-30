"""Circuit breaker + retry с экспоненциальным backoff и jitter (без сторонних библиотек).

Состояния автомата:
    CLOSED    — запросы проходят; после ``failure_threshold`` подряд ошибок → OPEN.
    OPEN      — запросы отклоняются мгновенно; по истечении ``reset_timeout`` → HALF_OPEN.
    HALF_OPEN — пропускается пробный запрос: успех → CLOSED, ошибка → снова OPEN.

Время и генератор случайных чисел инъектируются (``time_fn``, ``rng``), поэтому
поведение полностью воспроизводимо в тестах.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeVar

T = TypeVar("T")


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(RuntimeError):
    """Выбрасывается при попытке вызова, когда breaker в состоянии OPEN."""


class CircuitBreaker:
    """Автомат circuit breaker с тремя состояниями."""

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        reset_timeout: float = 30.0,
        time_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold должен быть >= 1")
        self._failure_threshold = failure_threshold
        self._reset_timeout = reset_timeout
        self._time = time_fn
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> CircuitState:
        """Актуальное состояние с учётом возможного перехода OPEN → HALF_OPEN."""
        if (
            self._state is CircuitState.OPEN
            and self._opened_at is not None
            and self._time() - self._opened_at >= self._reset_timeout
        ):
            self._state = CircuitState.HALF_OPEN
        return self._state

    @property
    def degraded(self) -> bool:
        """Источник деградировал (breaker не в CLOSED)."""
        return self.state is not CircuitState.CLOSED

    def call(self, fn: Callable[[], T]) -> T:
        """Выполнить ``fn`` под защитой breaker."""
        current = self.state
        if current is CircuitState.OPEN:
            raise CircuitBreakerError("circuit breaker OPEN — источник недоступен")
        try:
            result = fn()
        except Exception:
            self._on_failure()
            raise
        self._on_success()
        return result

    def _on_success(self) -> None:
        self._failures = 0
        self._opened_at = None
        self._state = CircuitState.CLOSED

    def _on_failure(self) -> None:
        self._failures += 1
        if self._state is CircuitState.HALF_OPEN or self._failures >= self._failure_threshold:
            self._state = CircuitState.OPEN
            self._opened_at = self._time()


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Политика повторов: экспоненциальный backoff + полный jitter."""

    max_attempts: int = 3
    base_delay: float = 0.1
    max_delay: float = 5.0
    multiplier: float = 2.0

    def delay_for_attempt(self, attempt: int, rng: random.Random) -> float:
        """Задержка перед попыткой ``attempt`` (1-based) с полным jitter.

        Полный jitter (AWS): ``delay = uniform(0, min(max_delay, base*mult^(attempt-1)))``.
        """
        raw = self.base_delay * (self.multiplier ** (attempt - 1))
        capped = min(self.max_delay, raw)
        return rng.uniform(0.0, capped)


def retry_with_backoff(
    fn: Callable[[], T],
    *,
    policy: RetryPolicy | None = None,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    rng: random.Random | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> T:
    """Повторять ``fn`` согласно ``policy`` при исключениях из ``retry_on``.

    ``rng`` и ``sleep_fn`` инъектируются ради детерминизма в тестах.
    """
    active_policy = policy or RetryPolicy()
    active_rng = rng or random.Random()
    last_exc: BaseException | None = None
    for attempt in range(1, active_policy.max_attempts + 1):
        try:
            return fn()
        except retry_on as exc:
            last_exc = exc
            if attempt >= active_policy.max_attempts:
                break
            sleep_fn(active_policy.delay_for_attempt(attempt, active_rng))
    assert last_exc is not None
    raise last_exc
