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

CORRELATION_RULE_RU: dict[str, str] = {
    "pivot": "ядро",
    "host-expansion": "расширение",
    "manual_attach": "прицеплено аналитиком",
    "manual_detach": "отцеплено аналитиком",
    "manual_merge": "объединено аналитиком",
    "manual_split": "разделено аналитиком",
}
"""Основание попадания события в кейс (`correlation_evidence.rule`)."""

CHAIN_STEP_KIND_RU: dict[str, str] = {
    "process_spawn": "запуск процесса",
    "network_move": "сетевое перемещение",
}
"""Вид перехода в реконструкции цепочки (`attack_chain.steps[].kind`)."""

GRAPH_EDGE_KIND_RU: dict[str, str] = {
    "initiated": "запустил",
    "spawned": "породил",
    "runs": "выполняет",
    "network": "обратился к",
}
"""Вид связи между сущностями кейса (`graph.edges[].type`)."""

TYPICALITY_RU: dict[str, str] = {
    "first_seen": "первое появление",
    "rare": "редко: менее 3 событий",
    "typical": "часто: 3 и более событий",
}
"""Частота сущности в накопленной истории. Это счётчик событий, а не модель поведения:
порог назван прямо в самом названии, чтобы «обычная активность» не читалась как вывод
о нормальности."""

ROLE_RU: dict[str, str] = {
    "analyst_l1": "аналитик первой линии",
    "analyst_l2": "аналитик второй линии",
    "manager": "руководитель",
    "admin": "администратор",
    "operator": "оператор",
    "auditor": "аудитор",
}
"""Роль ключа доступа (`role` в ответе `GET /session`).

Роль видна аналитику в шапке рабочего места: она объясняет, почему часть действий недоступна.
Названия живут здесь, а не в АРМ, по общему правилу словаря — иначе при добавлении роли
интерфейс молча показал бы код."""

DQ_REASON_RU: dict[str, str] = {
    "telemetry_gap": "разрыв в телеметрии",
    "stale_data": "устаревшие данные",
    "source_reputation_drift": "просадка доверия к источнику",
}
"""Причины неполной наблюдаемости (`dq_reasons`)."""

LEDGER_ISSUE_RU: dict[str, str] = {
    "line_sha_mismatch": "контрольная сумма записи не сходится",
    "payload_sha_mismatch": "контрольная сумма содержимого не сходится",
    "prev_chain_mismatch": "разрыв цепочки: ссылка на предыдущую запись не сходится",
    "chain_mismatch": "контрольная сумма цепочки не сходится",
}
"""Нарушения целостности append-only журнала (`issue` в ответе проверки).

Это сообщение аналитик читает в тот момент, когда доказательный контур под вопросом:
код вроде `prev_chain_mismatch` здесь хуже всего, потому что требует перевода на ходу."""


def risk_class_ru(value: str) -> str:
    """Название класса риска. Неизвестный код возвращается как есть, а не подменяется догадкой."""
    return RISK_CLASS_RU.get((value or "").strip().upper(), value)


def case_status_ru(value: str) -> str:
    """Название статуса дела. Неизвестный код возвращается как есть."""
    return CASE_STATUS_RU.get((value or "").strip(), value)


def plural_ru(count: int, one: str, few: str, many: str) -> str:
    """Согласование существительного с числительным: 1 событие, 2 события, 5 событий.

    Нужно там, где текст собирается продуктом и уходит пользователю: «Собрано 41 событий»
    в сводке кейса читается как небрежность ровно в том месте, где продукт объясняет
    основание вывода.
    """
    tail_two = abs(count) % 100
    tail_one = abs(count) % 10
    if 11 <= tail_two <= 14:
        return many
    if tail_one == 1:
        return one
    if 2 <= tail_one <= 4:
        return few
    return many


def events_ru(count: int) -> str:
    """«1 событие» / «2 события» / «5 событий» вместе с числом."""
    return f"{count} {plural_ru(count, 'событие', 'события', 'событий')}"


def vocabulary() -> dict[str, dict[str, str]]:
    """Весь словарь одним объектом — то, что отдаётся интерфейсу."""
    return {
        "risk_class": dict(RISK_CLASS_RU),
        "case_status": dict(CASE_STATUS_RU),
        "verdict": dict(VERDICT_RU),
        "event_source": dict(EVENT_SOURCE_RU),
        "entity_type": dict(ENTITY_TYPE_RU),
        "artifact_type": dict(ARTIFACT_TYPE_RU),
        "correlation_rule": dict(CORRELATION_RULE_RU),
        "chain_step_kind": dict(CHAIN_STEP_KIND_RU),
        "graph_edge_kind": dict(GRAPH_EDGE_KIND_RU),
        "typicality": dict(TYPICALITY_RU),
        "dq_reason": dict(DQ_REASON_RU),
        "ledger_issue": dict(LEDGER_ISSUE_RU),
        "role": dict(ROLE_RU),
    }
