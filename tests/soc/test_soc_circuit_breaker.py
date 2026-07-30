"""Тесты circuit breaker и retry с backoff (детерминированные через инъекции)."""

from __future__ import annotations

import random

import pytest

from takt.infrastructure.resilience.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    RetryPolicy,
    retry_with_backoff,
)


class _Clock:
    """Управляемые часы для теста (монотонное время)."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def _boom() -> None:
    raise RuntimeError("boom")


def test_opens_after_threshold() -> None:
    clock = _Clock()
    cb = CircuitBreaker(failure_threshold=3, reset_timeout=10.0, time_fn=clock)
    for _ in range(3):
        with pytest.raises(RuntimeError):
            cb.call(_boom)
    assert cb.state is CircuitState.OPEN
    # В OPEN вызовы отклоняются мгновенно.
    with pytest.raises(CircuitBreakerError):
        cb.call(lambda: 1)


def test_half_open_after_timeout_then_close_on_success() -> None:
    clock = _Clock()
    cb = CircuitBreaker(failure_threshold=2, reset_timeout=10.0, time_fn=clock)
    for _ in range(2):
        with pytest.raises(RuntimeError):
            cb.call(_boom)
    assert cb.state is CircuitState.OPEN
    clock.t += 10.0  # истёк reset_timeout
    assert cb.state is CircuitState.HALF_OPEN
    # Успешный пробный вызов → CLOSED.
    assert cb.call(lambda: 42) == 42
    assert cb.state is CircuitState.CLOSED


def test_half_open_failure_reopens() -> None:
    clock = _Clock()
    cb = CircuitBreaker(failure_threshold=1, reset_timeout=5.0, time_fn=clock)
    with pytest.raises(RuntimeError):
        cb.call(_boom)
    assert cb.state is CircuitState.OPEN
    clock.t += 5.0
    assert cb.state is CircuitState.HALF_OPEN
    with pytest.raises(RuntimeError):
        cb.call(_boom)
    assert cb.state is CircuitState.OPEN


def test_success_resets_failure_counter() -> None:
    cb = CircuitBreaker(failure_threshold=3, time_fn=_Clock())
    with pytest.raises(RuntimeError):
        cb.call(_boom)
    cb.call(lambda: 1)  # успех сбрасывает счётчик
    with pytest.raises(RuntimeError):
        cb.call(_boom)
    assert cb.state is CircuitState.CLOSED


def test_retry_succeeds_after_transient_failures() -> None:
    attempts = {"n": 0}
    sleeps: list[float] = []

    def flaky() -> str:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ValueError("transient")
        return "ok"

    result = retry_with_backoff(
        flaky,
        policy=RetryPolicy(max_attempts=5, base_delay=0.1),
        rng=random.Random(0),
        sleep_fn=sleeps.append,
    )
    assert result == "ok"
    assert attempts["n"] == 3
    assert len(sleeps) == 2  # две паузы перед 2-й и 3-й попытками


def test_retry_exhausts_and_raises_last() -> None:
    sleeps: list[float] = []
    with pytest.raises(ValueError):
        retry_with_backoff(
            _fail_always,
            policy=RetryPolicy(max_attempts=3),
            rng=random.Random(1),
            sleep_fn=sleeps.append,
        )
    assert len(sleeps) == 2


def _fail_always() -> None:
    raise ValueError("always")


def test_backoff_delay_is_capped_and_deterministic() -> None:
    policy = RetryPolicy(base_delay=1.0, multiplier=2.0, max_delay=4.0)
    rng = random.Random(123)
    # Полный jitter: 0 <= delay <= min(max_delay, base*mult^(n-1)).
    for attempt, cap in [(1, 1.0), (2, 2.0), (3, 4.0), (4, 4.0)]:
        d = policy.delay_for_attempt(attempt, rng)
        assert 0.0 <= d <= cap
