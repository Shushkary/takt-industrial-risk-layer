"""Объяснение оценки риска (XAI).

ВНИМАНИЕ: движок входит в алгоритмическое ядро под патентной защитой (заявка № 2026112859),
см. `CLAUDE.md`. Правка от 2026-08-21 — **текстовая**: класс риска и сработавшие инварианты
печатаются русскими названиями вместо кодов. Состав объяснения, порядок выбора рекомендации и
контрфакта, а также любые вычисления не менялись; сверка с формулой изобретения выполнена —
формула описывает контрфактическое объяснение вердикта, а не язык подписей.
"""

from __future__ import annotations

from dataclasses import dataclass

from takt.domain.engines.risk_engine import RiskAssessment
from takt.domain.invariants.catalog import InvariantId, invariant_titles_by_id
from takt.domain.vocabulary import risk_class_ru

# Заголовки правил из кодового каталога. Считаются один раз: `build_xai` вызывается на каждом
# событии, а таблица неизменна в пределах процесса.
_TITLES_BY_ID: dict[str, str] = invariant_titles_by_id()


def _invariant_title(invariant_id: str) -> str:
    """Название правила. Неизвестный идентификатор возвращается как есть.

    Каталог здесь кодовый: домен не читает YAML. Если в боевом каталоге правило переименовано,
    объяснение покажет идентификатор — это честнее, чем подставить устаревшее название.
    """
    return _TITLES_BY_ID.get(invariant_id, invariant_id)


@dataclass(frozen=True, slots=True)
class XAIReport:
    what: str
    why_unusual: str
    recommendation: str
    counterfactual: str


# --- Контекстные шаблоны для recommendation ---
_REC_MAP: dict[str, str] = {
    InvariantId.JUMP_SERVER_BYPASS.value: "Проверить маршрут доступа к ПЛК — прямой доступ в обход jump-сервера запрещён.",
    InvariantId.NEW_NODE_AIRGAP.value: "Проверить легитимность нового узла в air-gap сегменте.",
    InvariantId.LATERAL_MOVEMENT.value: "Изучить цепочку переходов между хостами — возможное латеральное движение.",
    InvariantId.RECONNAISSANCE.value: "Заблокировать источник сканирования; проверить границы сегмента.",
    InvariantId.UNTRUSTED_IP_ADMIN.value: "Проверить IP-адрес администратора — источник не в списке доверенных.",
    InvariantId.BRUTE_FORCE.value: "Заблокировать источник перебора; проверить политику паролей.",
    InvariantId.OUT_OF_SHIFT_ACCESS.value: "Связаться с дежурным — админская активность вне смены.",
    InvariantId.PROTOCOL_ESCALATION.value: "Проверить легитимность повышения уровня протокола.",
    InvariantId.LOG_WIPING.value: "Срочно проверить целостность журналов аудита — возможна очистка.",
    InvariantId.RUNTIME_CONFIG_CHANGE.value: "Проверить легитимность изменения конфигурации в runtime.",
    InvariantId.C2_EXTERNAL_DNS.value: "Изолировать узел — обнаружен внешний C2/DNS-вызов.",
    InvariantId.TRUST_INDEX_DROP.value: "Проверить источник — индекс доверия критически снизился.",
    InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value: "Проверить физическое состояние канала связи — риск обрыва.",
    InvariantId.POLLING_JITTER.value: "Проверить стабильность опроса ПЛК — растущий джиттер.",
    InvariantId.CONTEXT_DISSONANCE.value: "Согласовать критическую операцию с Service Desk — нет заявки.",
    InvariantId.STALE_DATA.value: "Проверить датчик — данные не обновляются (замерзание).",
    InvariantId.TELEMETRY_GAP.value: "Проверить канал телеметрии — обнаружена потеря пакетов.",
    InvariantId.SOURCE_REPUTATION_DRIFT.value: "Проверить источник — дрейф репутации.",
    InvariantId.PHYSICAL_INVARIANT_BREACH.value: "Проверить физические параметры — аномальная скорость изменения.",
    InvariantId.CYCLIC_SERVICE_CRASH.value: "Проверить сервис — циклические падения (≥3).",
    InvariantId.BLIND_COMMAND.value: "Проверить легитимность управляющей команды без предшествующего опроса.",
    InvariantId.CONFLICT_LOGIC.value: "Проверить логику управления — взаимоисключающие команды.",
    InvariantId.EXPERT_DISSONANCE.value: "Согласовать с экспертом — расхождение с экспертной оценкой.",
}

# --- Контекстные шаблоны для counterfactual ---
_CF_MAP: dict[str, str] = {
    InvariantId.JUMP_SERVER_BYPASS.value: "Событие было бы нормальным при доступе через jump-сервер.",
    InvariantId.NEW_NODE_AIRGAP.value: "Событие было бы нормальным, если бы узел был в реестре активов.",
    InvariantId.LATERAL_MOVEMENT.value: "Событие было бы нормальным при отсутствии цепочки переходов между хостами.",
    InvariantId.UNTRUSTED_IP_ADMIN.value: "Событие было бы нормальным, если бы IP был в списке доверенных.",
    InvariantId.OUT_OF_SHIFT_ACCESS.value: "Событие было бы нормальным в рабочую смену (08:00–20:00).",
    InvariantId.CONTEXT_DISSONANCE.value: "Событие было бы нормальным при действующей заявке Service Desk.",
    InvariantId.BRUTE_FORCE.value: "Событие было бы нормальным при количестве неудач ниже порога.",
    InvariantId.PROTOCOL_ESCALATION.value: "Событие было бы нормальным при том же уровне протокола.",
    InvariantId.POLLING_PERIOD_DOUBLING_SUSPECT.value: "Событие было бы нормальным при стабильных интервалах опроса.",
    InvariantId.POLLING_JITTER.value: "Событие было бы нормальным при стабильной частоте опроса.",
    InvariantId.STALE_DATA.value: "Событие было бы нормальным при обновлении данных датчика.",
    InvariantId.TELEMETRY_GAP.value: "Событие было бы нормальным при отсутствии разрывов в телеметрии.",
    InvariantId.SOURCE_REPUTATION_DRIFT.value: "Событие было бы нормальным при trust источника ≥ 0.85.",
    InvariantId.PHYSICAL_INVARIANT_BREACH.value: "Событие было бы нормальным при скорости изменения в пределах нормы.",
    InvariantId.CYCLIC_SERVICE_CRASH.value: "Событие было бы нормальным при отсутствии повторных падений сервиса.",
    InvariantId.BLIND_COMMAND.value: "Событие было бы нормальным при предшествующем опросе (READ/POLL).",
    InvariantId.CONFLICT_LOGIC.value: "Событие было бы нормальным при отсутствии взаимоисключающих команд.",
    InvariantId.LOG_WIPING.value: "Событие было бы нормальным без признаков очистки журналов.",
    InvariantId.RUNTIME_CONFIG_CHANGE.value: "Событие было бы нормальным при плановом изменении конфигурации.",
    InvariantId.C2_EXTERNAL_DNS.value: "Событие было бы нормальным без внешних DNS-запросов.",
    InvariantId.TRUST_INDEX_DROP.value: "Событие было бы нормальным при trust источника ≥ 0.3.",
    InvariantId.REQUEST_REPLY_DISSONANCE.value: "Событие было бы нормальным при предшествующем запросе к активу.",
    InvariantId.RECONNAISSANCE.value: "Событие было бы нормальным без признаков сканирования сети.",
    InvariantId.EXPERT_DISSONANCE.value: "Событие было бы нормальным при совпадении с экспертной оценкой.",
}


def build_xai(
    assessment: RiskAssessment,
    *,
    invariant_hits: list[str],
    context_note: str,
) -> XAIReport:
    # Объяснение читает человек: класс риска, вклады векторов и правила называются словами
    # словаря аналитика — «частота», «связи», «учётная запись», «качество данных», а не
    # обозначениями модели («ритм», «граф», «DQ»). Идентификаторы
    # правил остаются ключами `_REC_MAP` и `_CF_MAP` ниже — подменять их названиями нельзя,
    # иначе рекомендация и контрфакт перестанут находиться.
    hits = (
        ", ".join(_invariant_title(iid) for iid in invariant_hits)
        if invariant_hits
        else "срабатываний нет"
    )
    what = f"Агрегированный риск {assessment.score:.2f}, класс {risk_class_ru(assessment.risk_class)}."
    why = (
        f"Вклады: частота={assessment.breakdown.rhythm:.2f}, связи={assessment.breakdown.graph:.2f}, "
        f"контекст={assessment.breakdown.context:.2f}, учётная запись={assessment.breakdown.user:.2f}, "
        f"качество данных={assessment.breakdown.data_quality:.2f}. Правила: {hits}. {context_note}"
    )
    # Контекстная рекомендация: приоритет — первый сработавший инвариант с известным шаблоном
    rec = "Назначить триаж оператору; проверить журналы источника и заявки Service Desk."
    for iid in invariant_hits:
        mapped = _REC_MAP.get(iid)
        if mapped:
            rec = mapped
            break
    # Контекстный counterfactual: объединяем до 2 условий
    cf_parts: list[str] = []
    for iid in invariant_hits:
        cf = _CF_MAP.get(iid)
        if cf and cf not in cf_parts:
            cf_parts.append(cf)
    if not cf_parts:
        cf = "Событие было бы типичным при действующем окне регламентных работ и известном jump-маршруте."
    else:
        cf = " ".join(cf_parts[:2])
    return XAIReport(what=what, why_unusual=why, recommendation=rec, counterfactual=cf)
