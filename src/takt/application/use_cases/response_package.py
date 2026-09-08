"""Состав пакета реагирования: кандидаты, их происхождение и привязка к узлам.

Пакет собирался в браузере из артефактов дела с ``source=pivot-seed`` и знал три типа — узел,
учётную запись и адрес. Аудит «След смены» (разрыв D03) показал следствие: у дела с seed-хешем
и доменом таблица предлагала только учётные записи, адрес и заморозку конвейера; дело,
собранное не пивотом, оставляло панель пустой; у учётной записи и адреса поле узла молча
пустовало. Пункт ТЗ о пакете с типами и привязкой к узлам выполнялся для части объектов, а
остальное аналитик дописывал руками — за пределами доказательного контура.

Здесь состав считает продукт. Каждый кандидат несёт:

- **тип и значение** — то, к чему относится рекомендация;
- **узел** и признак того, что узел известен: неизвестный узел показывается неизвестным и не
  отмечается по умолчанию. Подставить сюда «первый попавшийся» узел дела значило бы приписать
  объекту привязку, которой в данных нет;
- **происхождение** — пивот, ручной артефакт дела или сущность/артефакт события;
- **события-основания** и **класс источника** — по ним рекомендацию можно проверить;
- **статус проверки** артефакта, если он у дела есть.

ТАКТ этих действий не выполняет и команд не отправляет: пакет — перечень рекомендаций,
исполняет их внешняя система после подтверждения аналитика
(``docs/product_boundary.md``). Граница приходит вместе с пакетом, а не выводится интерфейсом.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from takt.domain.entities.case import Case
from takt.domain.entities.event import ArtifactType, NormalizedEvent

BOUNDARY_NOTE = (
    "ТАКТ не выполняет эти действия и не отправляет команды. Исполняет внешняя система "
    "после подтверждения аналитика."
)

PACKAGE_FINDING_PREFIX = "Пакет реагирования"
"""Начало текста находки, которой записывается подтверждённый пакет. По нему считается версия."""

# Рекомендация по типу объекта. Это текст для человека, а не команда: перечень намеренно
# короткий и не содержит параметров исполнения — исполняет внешняя система.
_ACTIONS: dict[str, str] = {
    "host": "Изоляция узла",
    "account": "Сброс учётной записи",
    "address": "Блокировка адреса",
    "domain": "Блокировка домена",
    "url": "Блокировка ссылки",
    "hash": "Блокировка файла по контрольной сумме",
    "file": "Изъятие файла и проверка",
    "process": "Остановка процесса на узле",
    "spn": "Смена пароля сервисной учётной записи",
    "repo": "Заморозка конвейера сборки до проверки объекта",
    "pipeline": "Заморозка конвейера сборки",
}

# Порядок строк в таблице: сначала то, что изолирует узел и учётную запись, потом сетевые
# объекты, потом файловые. Порядок фиксирован, чтобы повторный расчёт давал ту же таблицу.
_TYPE_ORDER = ("host", "account", "address", "domain", "url", "hash", "file", "process", "spn", "repo", "pipeline")

_CORE = "core"
_EXPANDED = "expanded"


@dataclass(frozen=True, slots=True)
class ResponseCandidate:
    """Одна строка пакета: объект, рекомендация и то, чем она обоснована."""

    type: str
    value: str
    action: str
    host_id: str = ""
    host_known: bool = False
    origin: str = "event"
    """`pivot-seed` — отличительная сущность сборки, `manual` — артефакт, добавленный
    аналитиком, `event` — сущность или артефакт события, `host-expansion` — узел, добранный
    расширением до узла."""
    event_ids: tuple[str, ...] = ()
    source: str = ""
    verification_status: str = ""
    group: str = _CORE
    selected_by_default: bool = True


@dataclass(frozen=True, slots=True)
class ResponsePackage:
    version: int
    candidates: list[ResponseCandidate] = field(default_factory=list)
    boundary_note: str = BOUNDARY_NOTE


def _artifact_type(value: str) -> str:
    """Тип артефакта продукта; неизвестное обозначение остаётся как есть, а не подменяется."""
    normalized = (value or "").strip().lower()
    return normalized


def _is_pipeline_object(artifact_type: str, value: str) -> bool:
    """Объект конвейера приходит в поле узла с префиксом вида `pipeline:` или `artifact:`.

    Изолировать его нельзя — это не узел сети.
    """
    return artifact_type == ArtifactType.HOST.value and ":" in value


def _package_version(case: Case) -> int:
    """Версия отбора: сколько пакетов по этому делу уже подтверждено, плюс текущий."""
    confirmed = sum(1 for item in case.findings if item.text.startswith(PACKAGE_FINDING_PREFIX))
    return confirmed + 1


def build_response_package(
    case: Case,
    events: Sequence[NormalizedEvent] | Iterable[NormalizedEvent],
    *,
    expanded_hosts: Sequence[str] = (),
) -> ResponsePackage:
    """Кандидаты пакета по делу и его событиям.

    Объект, наблюдённый на двух узлах, остаётся двумя строками: изолировать надо оба, и
    решение по каждому своё. Один и тот же объект на одном узле сливается в одну строку с
    объединением событий-оснований.
    """
    ordered = sorted(events, key=lambda item: (item.observed_at, item.event_id))
    # Ключ строки — тип, значение и узел: объект на разных узлах не сливается.
    rows: dict[tuple[str, str, str], dict] = {}

    def add(
        *, type_: str, value: str, host_id: str, origin: str, group: str,
        event_id: str = "", source: str = "", verification_status: str = "",
    ) -> None:
        value = (value or "").strip()
        if not value:
            return
        host = (host_id or "").strip()
        key = (type_, value, host)
        row = rows.get(key)
        if row is None:
            row = {
                "type": type_, "value": value, "host_id": host, "origin": origin, "group": group,
                "event_ids": [], "source": source, "verification_status": verification_status,
            }
            rows[key] = row
        elif _origin_rank(origin) < _origin_rank(row["origin"]):
            # Пивот и ручной артефакт весомее событийного происхождения: строку описывает
            # то основание, которое аналитик увидит первым.
            row["origin"] = origin
            row["group"] = group
            if verification_status:
                row["verification_status"] = verification_status
        if event_id and event_id not in row["event_ids"]:
            row["event_ids"].append(event_id)
        if source and not row["source"]:
            row["source"] = source

    # 1. Артефакты дела: отличительные сущности сборки и то, что добавил аналитик.
    for artifact in case.artifacts:
        artifact_type = _artifact_type(artifact.type)
        origin = "pivot-seed" if artifact.source == "pivot-seed" else "manual"
        if _is_pipeline_object(artifact_type, artifact.value):
            add(type_="repo", value=artifact.value, host_id="", origin=origin, group=_CORE,
                verification_status=artifact.verification_status)
            continue
        add(
            type_=artifact_type, value=artifact.value, host_id=artifact.host_id,
            origin=origin, group=_CORE, verification_status=artifact.verification_status,
        )

    # 2. Сущности и артефакты событий: без них дело, собранное не пивотом, оставалось без пакета.
    for event in ordered:
        entities = event.entities
        source = event.source.value
        if entities is not None:
            host = (entities.host_id or "").strip()
            add(type_="host", value=host, host_id=host, origin="event", group=_CORE,
                event_id=event.event_id, source=source)
            add(type_="account", value=(entities.user_id or ""), host_id=host, origin="event",
                group=_CORE, event_id=event.event_id, source=source)
            add(type_="process", value=(entities.process_id or ""), host_id=host, origin="event",
                group=_CORE, event_id=event.event_id, source=source)
            for address in (entities.src_address, entities.dst_address):
                add(type_="address", value=(address or ""), host_id=host, origin="event",
                    group=_CORE, event_id=event.event_id, source=source)
        else:
            host = ""
        for event_artifact in event.artifacts:
            add(
                type_=event_artifact.type.value, value=event_artifact.value, host_id=host,
                origin="event", group=_CORE, event_id=event.event_id, source=source,
            )

    # 3. Узлы, добранные расширением: они попали в дело по узлу, а не по признаку атаки,
    #    поэтому идут отдельной группой и по умолчанию не отмечены.
    for host in expanded_hosts:
        add(type_="host", value=host, host_id=host, origin="host-expansion", group=_EXPANDED)

    candidates = [
        ResponseCandidate(
            type=row["type"],
            value=row["value"],
            action=_ACTIONS.get(row["type"], "Проверка объекта"),
            host_id=row["host_id"],
            host_known=bool(row["host_id"]),
            origin=row["origin"],
            event_ids=tuple(row["event_ids"]),
            source=row["source"],
            verification_status=row["verification_status"],
            group=row["group"],
            # Узел неизвестен — решение остаётся за аналитиком: молчаливая отметка означала бы
            # рекомендацию без адресата. Узел расширения тоже требует явного решения.
            selected_by_default=bool(row["host_id"]) and row["group"] == _CORE,
        )
        for row in rows.values()
    ]
    candidates.sort(key=lambda item: (
        0 if item.group == _CORE else 1,
        _TYPE_ORDER.index(item.type) if item.type in _TYPE_ORDER else len(_TYPE_ORDER),
        item.value,
        item.host_id,
    ))
    return ResponsePackage(version=_package_version(case), candidates=candidates)


def _origin_rank(origin: str) -> int:
    return {"pivot-seed": 0, "manual": 1, "host-expansion": 2, "event": 3}.get(origin, 4)
