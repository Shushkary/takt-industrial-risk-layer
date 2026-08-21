"""Русские названия обозначений продукта — единый источник правды.

Интерфейс аналитика показывает не коды, а слова: не ``LOW``, а «низкий», не ``auth_logs``, а
«журналы аутентификации». Раньше такие подписи жили бы в двух местах — в API и в АРМ — и
разошлись бы при первом же добавлении статуса или источника. Здесь один словарь, который
отдаётся наружу через ``GET /catalog/vocabulary``.

Что переводится и что нет — граница проходит по происхождению значения:

- **Наши обозначения** переводятся: класс риска, статус дела, триадный вердикт, класс источника,
  тип сущности и артефакта. Их придумал продукт, и показывать их кодом незачем.
- **Значения из данных источника** не переводятся: операция (``WRITE_REGISTER``), протокол
  (``MODBUS``), идентификаторы узлов и учётных записей. Это материал доказательства; перевод
  исказил бы то, что зафиксировано в журнале, и предъявить такой перевод экспертизе нельзя.

Полнота словаря проверяется тестом: новый член перечисления без русского названия роняет
прогон, а не показывается пользователю кодом.
"""

from __future__ import annotations

from takt.domain.entities.case import CaseStatus
from takt.domain.entities.event import ArtifactType, EventSource

RISK_CLASS_RU: dict[str, str] = {
    "LOW": "низкий",
    "MEDIUM": "средний",
    "HIGH": "высокий",
    "CRITICAL": "критический",
}

CASE_STATUS_RU: dict[str, str] = {
    CaseStatus.NEW.value: "новое",
    CaseStatus.TRIAGE.value: "в разборе",
    CaseStatus.CONFIRMED.value: "подтверждено",
    CaseStatus.FALSE_POSITIVE.value: "ложное срабатывание",
    CaseStatus.EXPECTED_BEHAVIOR.value: "штатное действие",
    CaseStatus.MERGED.value: "объединено",
}

VERDICT_RU: dict[str, str] = {
    "LEG": "легитимное",
    "ILLEG": "нелегитимное",
    "UNDET": "неопределённое",
}

EVENT_SOURCE_RU: dict[str, str] = {
    EventSource.EDR.value: "защита рабочих станций",
    EventSource.SIEM.value: "система сбора событий",
    EventSource.NDR.value: "анализ сетевого трафика",
    EventSource.OT.value: "промышленная телеметрия",
    EventSource.AUTH_LOGS.value: "журналы аутентификации",
    EventSource.NETWORK.value: "сетевые события",
    EventSource.PLC_POLLING.value: "опрос контроллеров",
    EventSource.SERVICE_DESK.value: "служба заявок",
    EventSource.UNKNOWN.value: "источник не определён",
}

ENTITY_TYPE_RU: dict[str, str] = {
    "host": "узел",
    "user": "учётная запись",
    "process": "процесс",
    "address": "адрес",
    "destination": "адрес назначения",
}

ARTIFACT_TYPE_RU: dict[str, str] = {
    ArtifactType.HOST.value: "узел",
    ArtifactType.FILE.value: "файл",
    ArtifactType.HASH.value: "контрольная сумма",
    ArtifactType.PROCESS.value: "процесс",
    ArtifactType.ACCOUNT.value: "учётная запись",
    ArtifactType.ADDRESS.value: "адрес",
    ArtifactType.URL.value: "ссылка",
    ArtifactType.DOMAIN.value: "домен",
    ArtifactType.SPN.value: "служба Kerberos",
    ArtifactType.REPO.value: "репозиторий кода",
}

WORK_PHASE_RU: dict[str, str] = {
    "WORK_SHIFT": "рабочая смена",
    "NIGHT": "ночь",
    "WEEKEND": "выходной",
}

CONFIDENCE_GRADE_RU: tuple[str, ...] = ("высокая", "средняя", "низкая")
"""Оценки обоснованности вывода. Уже по-русски — перечислены для полноты словаря."""


def risk_class_ru(value: str) -> str:
    """Название класса риска. Неизвестный код возвращается как есть, а не подменяется догадкой."""
    return RISK_CLASS_RU.get((value or "").strip().upper(), value)


def vocabulary() -> dict[str, dict[str, str]]:
    """Весь словарь одним объектом — то, что отдаётся интерфейсу."""
    return {
        "risk_class": dict(RISK_CLASS_RU),
        "case_status": dict(CASE_STATUS_RU),
        "verdict": dict(VERDICT_RU),
        "event_source": dict(EVENT_SOURCE_RU),
        "entity_type": dict(ENTITY_TYPE_RU),
        "artifact_type": dict(ARTIFACT_TYPE_RU),
    }
