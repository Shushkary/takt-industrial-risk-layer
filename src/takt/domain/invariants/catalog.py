"""Идентификаторы инвариантов по ТЗ MPV 2.0 (25 правил, 6 блоков)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class InvariantId(StrEnum):
    # Блок 1 — Ритмика и протоколы
    POLLING_JITTER = "polling_jitter"
    ILLEGAL_FUNCTION_CODE = "illegal_function_code"
    PAYLOAD_LENGTH_DRIFT = "payload_length_drift"
    REQUEST_REPLY_DISSONANCE = "request_reply_dissonance"

    # Блок 2 — Топология
    JUMP_SERVER_BYPASS = "jump_server_bypass"
    NEW_NODE_AIRGAP = "new_node_airgap"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"

    # Блок 3 — Идентификация
    UNTRUSTED_IP_ADMIN = "untrusted_ip_admin"
    BRUTE_FORCE = "brute_force"
    OUT_OF_SHIFT_ACCESS = "out_of_shift_access"
    PROTOCOL_ESCALATION = "protocol_escalation"

    # Блок 4 — Физическая логика
    CONFLICT_LOGIC = "conflict_logic"
    PHYSICAL_INVARIANT_BREACH = "physical_invariant_breach"
    BLIND_COMMAND = "blind_command"
    CYCLIC_SERVICE_CRASH = "cyclic_service_crash"

    # Блок 5 — Целостность
    LOG_WIPING = "log_wiping"
    RUNTIME_CONFIG_CHANGE = "runtime_config_change"
    C2_EXTERNAL_DNS = "c2_external_dns"
    TRUST_INDEX_DROP = "trust_index_drop"

    # Блок 6 — Данные и HITL
    STALE_DATA = "stale_data"
    TELEMETRY_GAP = "telemetry_gap"
    SOURCE_REPUTATION_DRIFT = "source_reputation_drift"
    EXPERT_DISSONANCE = "expert_dissonance"
    CONTEXT_DISSONANCE = "context_dissonance"
    POLLING_PERIOD_DOUBLING_SUSPECT = "polling_period_doubling_suspect"


_B1 = "Блок 1 — Ритмика и протоколы"
_B2 = "Блок 2 — Топология"
_B3 = "Блок 3 — Идентификация"
_B4 = "Блок 4 — Физическая логика"
_B5 = "Блок 5 — Целостность"
_B6 = "Блок 6 — Данные и HITL"


@dataclass(frozen=True, slots=True)
class InvariantRecord:
    """Справочная запись для каталога (API / интеграции)."""

    id: str
    block_key: str
    block_label_ru: str
    title_ru: str


INVARIANT_RECORDS: tuple[InvariantRecord, ...] = (
    InvariantRecord(InvariantId.POLLING_JITTER.value, "rhythm", _B1, "Аномальный джиттер интервалов опроса"),
    InvariantRecord(InvariantId.ILLEGAL_FUNCTION_CODE.value, "rhythm", _B1, "Недопустимый код функции / IEC ASDU type id"),
    InvariantRecord(InvariantId.PAYLOAD_LENGTH_DRIFT.value, "rhythm", _B1, "Дрейф размера полезной нагрузки"),
    InvariantRecord(InvariantId.REQUEST_REPLY_DISSONANCE.value, "rhythm", _B1, "Расхождение запрос/ответ по протоколу"),
    InvariantRecord(InvariantId.JUMP_SERVER_BYPASS.value, "topology", _B2, "Доступ к ПЛК/критузлу минуя jump-сервер"),
    InvariantRecord(InvariantId.NEW_NODE_AIRGAP.value, "topology", _B2, "Новый узел в сегменте air-gap"),
    InvariantRecord(InvariantId.LATERAL_MOVEMENT.value, "topology", _B2, "Признаки lateral movement"),
    InvariantRecord(InvariantId.RECONNAISSANCE.value, "topology", _B2, "Разведка: скан, SNMP walk, топология"),
    InvariantRecord(InvariantId.UNTRUSTED_IP_ADMIN.value, "identity", _B3, "Админ-действия с недоверенного IP"),
    InvariantRecord(InvariantId.BRUTE_FORCE.value, "identity", _B3, "Серия неуспешных аутентификаций"),
    InvariantRecord(InvariantId.OUT_OF_SHIFT_ACCESS.value, "identity", _B3, "Администрирование вне штатной фазы/смены"),
    InvariantRecord(InvariantId.PROTOCOL_ESCALATION.value, "identity", _B3, "Эскалация «тяжёлого» протокола по активу"),
    InvariantRecord(InvariantId.CONFLICT_LOGIC.value, "physics", _B4, "Конфликт логики управления / взаимоисключающие команды"),
    InvariantRecord(InvariantId.PHYSICAL_INVARIANT_BREACH.value, "physics", _B4, "Нарушение физического инварианта процесса"),
    InvariantRecord(InvariantId.BLIND_COMMAND.value, "physics", _B4, "Команда записи без предшествующего чтения/опроса"),
    InvariantRecord(InvariantId.CYCLIC_SERVICE_CRASH.value, "physics", _B4, "Циклический отказ сервиса исполнения"),
    InvariantRecord(InvariantId.LOG_WIPING.value, "integrity", _B5, "Очистка журналов / аудита"),
    InvariantRecord(InvariantId.RUNTIME_CONFIG_CHANGE.value, "integrity", _B5, "Изменение конфигурации на исполнении"),
    InvariantRecord(InvariantId.C2_EXTERNAL_DNS.value, "integrity", _B5, "Подозрительный внешний DNS / C2-паттерн"),
    InvariantRecord(InvariantId.TRUST_INDEX_DROP.value, "integrity", _B5, "Просадка индекса доверия источника"),
    InvariantRecord(InvariantId.STALE_DATA.value, "data_hitl", _B6, "Устаревшие данные в конвейере"),
    InvariantRecord(InvariantId.TELEMETRY_GAP.value, "data_hitl", _B6, "Разрыв телеметрии / пропуск выборок"),
    InvariantRecord(InvariantId.SOURCE_REPUTATION_DRIFT.value, "data_hitl", _B6, "Дрейф репутации источника"),
    InvariantRecord(InvariantId.EXPERT_DISSONANCE.value, "data_hitl", _B6, "Расхождение с экспертной оценкой / HITL"),
    InvariantRecord(InvariantId.CONTEXT_DISSONANCE.value, "data_hitl", _B6, "Расхождение с контекстом ТО / заявок"),
    InvariantRecord(
        InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value,
        "rhythm",
        _B1,
        "Подозрение на шаг к удвоению периода в ряду интервалов опроса (эвристика)",
    ),
)


def all_invariant_records() -> tuple[InvariantRecord, ...]:
    return INVARIANT_RECORDS


def invariant_titles_by_id() -> dict[str, str]:
    """Краткие заголовки для SIEM / отчётов (по `InvariantRecord.id`)."""
    return {r.id: r.title_ru for r in INVARIANT_RECORDS}