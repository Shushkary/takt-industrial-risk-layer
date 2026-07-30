"""7 ключевых инвариантов ядра L1 в виде отдельных стратегий-классов.

Каждая стратегия реализует ``check(event) -> InvariantViolation | None`` и не имеет
побочных эффектов. Инварианты, зависящие от «сейчас» (INV-01), получают порт
``Clock`` через конструктор — домен не обращается к системному времени напрямую.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from takt.domain.soc.normalized_event import ALLOWED_SOURCE_CLASSES, NormalizedEvent
from takt.domain.soc.ports import Clock

# Максимальный допустимый «дрейф в будущее» относительно Clock.now().
FUTURE_TOLERANCE_SECONDS = 60.0
# Нижняя граница здравого времени (защита от timestamp=0 / эпохи Unix).
MIN_SANE_TS = datetime(2000, 1, 1, tzinfo=UTC)
# Валидный формат идентификатора узла.
_HOST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


@dataclass(frozen=True, slots=True)
class InvariantViolation:
    """Нарушение инварианта: код, человекочитаемая причина и поле-нарушитель."""

    code: str
    reason: str
    field: str


@runtime_checkable
class InvariantStrategy(Protocol):
    """Контракт стратегии-инварианта."""

    code: str

    def check(self, event: NormalizedEvent) -> InvariantViolation | None: ...


class Inv01TimestampNotInFuture:
    """INV-01: ``ts`` не в будущем (не более 60 с от ``Clock.now()``)."""

    code = "INV-01"

    def __init__(self, clock: Clock, tolerance_seconds: float = FUTURE_TOLERANCE_SECONDS) -> None:
        self._clock = clock
        self._tolerance = timedelta(seconds=tolerance_seconds)

    def check(self, event: NormalizedEvent) -> InvariantViolation | None:
        now = self._clock.now()
        if event.ts > now + self._tolerance:
            return InvariantViolation(self.code, "ts в будущем относительно текущего времени", "ts")
        return None


class Inv02SourceClassAllowed:
    """INV-02: ``source_class`` из допустимого перечня."""

    code = "INV-02"

    def check(self, event: NormalizedEvent) -> InvariantViolation | None:
        if event.source_class not in ALLOWED_SOURCE_CLASSES:
            return InvariantViolation(self.code, "source_class вне допустимого перечня", "source_class")
        return None


class Inv03RawRefNotBlank:
    """INV-03: ``raw_ref`` не пустой и не состоит только из пробелов."""

    code = "INV-03"

    def check(self, event: NormalizedEvent) -> InvariantViolation | None:
        if not event.raw_ref or not event.raw_ref.strip():
            return InvariantViolation(self.code, "raw_ref пустой или состоит из пробелов", "raw_ref")
        return None


class Inv04HostIdFormat:
    """INV-04: ``host_id`` имеет валидный формат (если указан)."""

    code = "INV-04"

    def check(self, event: NormalizedEvent) -> InvariantViolation | None:
        if event.host_id is None:
            return None
        if not _HOST_ID_RE.match(event.host_id):
            return InvariantViolation(self.code, "host_id имеет недопустимый формат", "host_id")
        return None


class Inv05AddressValid:
    """INV-05: ``address`` — валидный IP или CIDR (если указан)."""

    code = "INV-05"

    def check(self, event: NormalizedEvent) -> InvariantViolation | None:
        if event.address is None:
            return None
        raw = event.address.strip()
        try:
            if "/" in raw:
                ipaddress.ip_network(raw, strict=False)
            else:
                ipaddress.ip_address(raw)
        except ValueError:
            return InvariantViolation(self.code, "address не является валидным IP/CIDR", "address")
        return None


class Inv06AtLeastOneEntity:
    """INV-06: хотя бы одно из (host_id, user_id, process, address, artifact) не None."""

    code = "INV-06"

    def check(self, event: NormalizedEvent) -> InvariantViolation | None:
        if any((event.host_id, event.user_id, event.process, event.address, event.artifact)):
            return None
        return InvariantViolation(self.code, "нет ни одной непустой сущности для корреляции", "entities")


class Inv07TimestampNotBeforeEpochGuard:
    """INV-07: ``ts`` не раньше 2000-01-01 (защита от timestamp=0)."""

    code = "INV-07"

    def check(self, event: NormalizedEvent) -> InvariantViolation | None:
        if event.ts < MIN_SANE_TS:
            return InvariantViolation(self.code, "ts раньше 2000-01-01 (подозрение на timestamp=0)", "ts")
        return None


def default_invariants(clock: Clock) -> list[InvariantStrategy]:
    """Стандартный набор всех 7 инвариантов (INV-01 требует порт ``Clock``)."""
    return [
        Inv01TimestampNotInFuture(clock),
        Inv02SourceClassAllowed(),
        Inv03RawRefNotBlank(),
        Inv04HostIdFormat(),
        Inv05AddressValid(),
        Inv06AtLeastOneEntity(),
        Inv07TimestampNotBeforeEpochGuard(),
    ]


# Стратегии без зависимостей от времени — удобны для статических проверок/тестов.
ALL_INVARIANTS: tuple[type, ...] = (
    Inv01TimestampNotInFuture,
    Inv02SourceClassAllowed,
    Inv03RawRefNotBlank,
    Inv04HostIdFormat,
    Inv05AddressValid,
    Inv06AtLeastOneEntity,
    Inv07TimestampNotBeforeEpochGuard,
)


def check_all_invariants(
    event: NormalizedEvent, invariants: list[InvariantStrategy]
) -> list[InvariantViolation]:
    """Прогнать событие через набор инвариантов и собрать все нарушения."""
    violations: list[InvariantViolation] = []
    for inv in invariants:
        violation = inv.check(event)
        if violation is not None:
            violations.append(violation)
    return violations
