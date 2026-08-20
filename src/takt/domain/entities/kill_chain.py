"""Фазы цепочки атаки и техники MITRE ATT&CK.

Фаза — это классификация шага атаки, пришедшая вместе с событием от разметки датасета или
от вышестоящего средства обнаружения. ТАКТ её не вычисляет и не угадывает: если источник
фазу не проставил, поле остаётся пустым. Приписать фазу самостоятельно значило бы выдать
предположение за факт, а окно расследования строится на том, что аналитик видит источник
каждого утверждения.

Чистый модуль: без ввода-вывода и без зависимостей от инфраструктуры.
"""

from __future__ import annotations

import re
from enum import StrEnum

# Поля события, в которых приходит разметка. Импортёры кладут исходную строку источника
# в `payload` целиком, поэтому отдельного маппинга не требуется.
PHASE_FIELD = "attack_phase"
TECHNIQUE_FIELD = "mitre_technique"


class KillChainPhase(StrEnum):
    """Фазы в порядке развития атаки. Порядок значим: по нему строится хронология окна."""

    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    C2 = "c2"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


PHASE_TITLES_RU: dict[KillChainPhase, str] = {
    KillChainPhase.RECON: "Разведка",
    KillChainPhase.INITIAL_ACCESS: "Первичный доступ",
    KillChainPhase.EXECUTION: "Выполнение",
    KillChainPhase.C2: "Управляющий канал",
    KillChainPhase.PRIVILEGE_ESCALATION: "Эскалация привилегий",
    KillChainPhase.LATERAL_MOVEMENT: "Горизонтальное перемещение",
    KillChainPhase.PERSISTENCE: "Закрепление",
    KillChainPhase.EXFILTRATION: "Эксфильтрация",
    KillChainPhase.IMPACT: "Воздействие",
}

PHASE_ORDER: tuple[KillChainPhase, ...] = tuple(KillChainPhase)

# Идентификатор техники ATT&CK: `T1059` или `T1558.003`.
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def parse_phase(raw: object) -> KillChainPhase | None:
    """Фаза из значения поля. Неизвестное или пустое значение даёт None, а не исключение.

    Разметка приходит из внешнего датасета, и одна неизвестная строка не повод ронять
    разбор всего инцидента: событие просто останется без фазы.
    """
    text = str(raw or "").strip().lower()
    if not text:
        return None
    try:
        return KillChainPhase(text)
    except ValueError:
        return None


def parse_technique(raw: object) -> str | None:
    """Идентификатор техники ATT&CK в каноническом виде или None."""
    text = str(raw or "").strip().upper()
    if not text or not _TECHNIQUE.match(text):
        return None
    return text


def phase_title_ru(phase: KillChainPhase | None) -> str:
    return PHASE_TITLES_RU[phase] if phase is not None else "не размечено"


def phase_index(phase: KillChainPhase | None) -> int:
    """Порядковый номер фазы. Неразмеченное событие уходит в конец сортировки."""
    return PHASE_ORDER.index(phase) if phase is not None else len(PHASE_ORDER)
