"""Демонстрационная цепочка атаки для стенда: девять фаз, четыре класса источников.

**Это синтетика.** Ни одно событие здесь не наблюдалось: сценарий написан, чтобы на вкладке
«Симуляция» было видно, из чего складывается разница между ручным разбором и разбором в ТАКТ.
Заголовок инцидента говорит об этом прямо, и в материалы такой прогон идёт только с этой
пометкой — числовая характеристика без ссылки на измерение запрещена
(`docs/product_boundary.md`).

Зачем нужен отдельный сценарий. На корпусе AIT инцидент `INC-AIT-001` даёт 69 шагов, но 65 из
них — одна фаза разведки с одного адреса, два класса источников и одна отличительная сущность.
Модель ручного процесса (`investigation_effort.py`) считает так:

    открыть консоли источников          = источников
    поиск сущностей по системам         = сущностей × источников
    перенос идентификаторов             = сущностей × (источников − 1)
    фиксация событий в заметке          = событий
    сведение итога                      = 1

На `INC-AIT-001` это 2 + 2 + 1 + 69 + 1 = 75, где 69 из 75 — переписывание событий в заметку.
Разница получается, но показывает она усидчивость, а не работу: межсистемного разбора в ней
пять действий из семидесяти пяти. Здесь сценарий устроен наоборот — четыре класса источников и
шесть отличительных сущностей, — и большая часть ручных действий приходится на то, ради чего
аналитик и переключается между консолями: искать одни и те же идентификаторы в разных системах
и переносить их руками.

Запуск (по умолчанию — локальный стенд):

    python -m scripts.seed_demo_chain --base-url http://127.0.0.1:8090
    python -m scripts.seed_demo_chain --base-url https://ralta.ru/takt_pt_arm/api
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

# --- Обстановка сценария ----------------------------------------------------
#
# Отличительные сущности выбраны так, чтобы каждая встречалась в нескольких фазах: именно на
# них собирается инцидент пивотом, и именно их аналитик вручную носил бы из системы в систему.

ATTACKER = "203.0.113.77"
ENGINEER_WS = "eng-ws-04"
JUMP_HOST = "jump-01"
HISTORIAN = "hist-01"
PLC = "plc-line-3"

USER_ENGINEER = "eng.petrov"
USER_SERVICE = "svc-scada"
USER_BACKUP = "admin.backup"

TOOL_HASH = "9f2c4a1b7e5d8c3f6a0b2d4e8c1f7a35b9d6e2c4a8f1b3d5e7c9a0b2d4f6e8c1a"
TOOL_PATH = "C:\\ProgramData\\svc\\upd_agent.exe"
C2_DOMAIN = "cdn-updates.example.net"

BASE_TIME = datetime(2026, 3, 17, 9, 0, tzinfo=UTC)

CASE_TITLE = (
    "Демонстрационный сценарий: захват инженерной станции и остановка линии розлива "
    "(синтетические данные)"
)


@dataclass(frozen=True, slots=True)
class Step:
    """Один шаг сценария. `count` разворачивается в серию одинаковых событий."""

    minute: int
    phase: str
    source: str
    operation: str
    asset_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    count: int = 1
    every_sec: int = 20


# --- Сценарий ---------------------------------------------------------------
#
# Девять фаз в порядке `KillChainPhase`. Классов источников ровно четыре — те, что названы
# в ТЗ и в пояснениях окна: журналы входа приходят через SIEM, а не отдельным классом.
# Пятый класс в сценарии противоречил бы строке разбора «события четырёх классов
# источников приведены к одной модели». Времена подобраны так, чтобы на ленте были видны и
# всплески, и паузы: разведка идёт очередью, подбор пароля — плотной серией, а выход на
# управляющий канал — редкими одиночными обращениями.

SCENARIO: tuple[Step, ...] = (
    # 1. Разведка: внешний адрес обходит сеть предприятия.
    Step(2, "recon", "ndr", "PORT_SCAN_DETECTED", ENGINEER_WS,
         {"src_address": ATTACKER, "dst_address": "10.20.0.41", "host_id": ENGINEER_WS}, count=4, every_sec=25),
    Step(4, "recon", "ndr", "PORT_SCAN_DETECTED", JUMP_HOST,
         {"src_address": ATTACKER, "dst_address": "10.20.0.15", "host_id": JUMP_HOST}, count=3, every_sec=25),
    Step(6, "recon", "ndr", "SERVICE_BANNER_GRAB", HISTORIAN,
         {"src_address": ATTACKER, "dst_address": "10.20.0.60", "host_id": HISTORIAN}, count=3, every_sec=30),

    # 2. Первичный доступ: подбор пароля к учётной записи инженера и один удачный вход.
    Step(14, "initial_access", "siem", "VPN_LOGIN_FAILED", JUMP_HOST,
         {"user_id": USER_ENGINEER, "src_address": ATTACKER, "host_id": JUMP_HOST}, count=9, every_sec=35),
    Step(20, "initial_access", "siem", "VPN_LOGIN_SUCCESS", JUMP_HOST,
         {"user_id": USER_ENGINEER, "src_address": ATTACKER, "host_id": JUMP_HOST}),

    # 3. Выполнение: запуск загрузчика на инженерной станции.
    Step(26, "execution", "edr", "PROCESS_CREATE", ENGINEER_WS,
         {"user_id": USER_ENGINEER, "host_id": ENGINEER_WS, "process_id": "powershell.exe",
          "file_path": TOOL_PATH, "sha256": TOOL_HASH}, count=2, every_sec=40),
    Step(29, "execution", "edr", "FILE_WRITE", ENGINEER_WS,
         {"user_id": USER_ENGINEER, "host_id": ENGINEER_WS, "file_path": TOOL_PATH, "sha256": TOOL_HASH}, count=2, every_sec=30),

    # 4. Управляющий канал: редкие обращения к внешнему узлу.
    Step(33, "c2", "ndr", "TLS_BEACON", ENGINEER_WS,
         {"src_address": "10.20.0.41", "dst_address": ATTACKER, "host_id": ENGINEER_WS,
          "dns_query": C2_DOMAIN}, count=6, every_sec=180),

    # 5. Повышение привилегий: кража токена служебной учётной записи.
    Step(41, "privilege_escalation", "edr", "TOKEN_IMPERSONATION", ENGINEER_WS,
         {"user_id": USER_BACKUP, "host_id": ENGINEER_WS, "process_id": "lsass.exe"}, count=2, every_sec=45),
    Step(44, "privilege_escalation", "siem", "PRIVILEGE_GROUP_MEMBER_ADDED", ENGINEER_WS,
         {"user_id": USER_BACKUP, "host_id": ENGINEER_WS}, count=2, every_sec=40),

    # 6. Горизонтальное перемещение: инженерная станция → узел перехода → историк.
    Step(55, "lateral_movement", "edr", "SMB_SESSION_SETUP", JUMP_HOST,
         {"user_id": USER_BACKUP, "host_id": JUMP_HOST, "src_address": "10.20.0.41",
          "dst_address": "10.20.0.15"}, count=3, every_sec=40),
    Step(60, "lateral_movement", "siem", "REMOTE_SERVICE_START", HISTORIAN,
         {"user_id": USER_SERVICE, "host_id": HISTORIAN, "src_address": "10.20.0.15",
          "dst_address": "10.20.0.60"}, count=3, every_sec=45),
    Step(66, "lateral_movement", "edr", "CREDENTIAL_ACCESS", HISTORIAN,
         {"user_id": USER_SERVICE, "host_id": HISTORIAN, "process_id": "reg.exe"}, count=2, every_sec=40),

    # 7. Закрепление: задание планировщика и служба.
    Step(75, "persistence", "edr", "SCHEDULED_TASK_CREATE", HISTORIAN,
         {"user_id": USER_SERVICE, "host_id": HISTORIAN, "file_path": TOOL_PATH, "sha256": TOOL_HASH}, count=2, every_sec=35),
    Step(78, "persistence", "siem", "SERVICE_INSTALL", JUMP_HOST,
         {"user_id": USER_BACKUP, "host_id": JUMP_HOST, "file_path": TOOL_PATH}, count=2, every_sec=35),

    # 8. Выгрузка: крупная передача наружу.
    Step(85, "exfiltration", "ndr", "DATA_UPLOAD_LARGE", HISTORIAN,
         {"src_address": "10.20.0.60", "dst_address": ATTACKER, "host_id": HISTORIAN,
          "dns_query": C2_DOMAIN}, count=6, every_sec=90),

    # 9. Воздействие: запись в регистры контроллера и остановка линии.
    Step(105, "impact", "ot", "WRITE_REGISTER", PLC,
         {"user_id": USER_SERVICE, "host_id": PLC, "src_address": "10.20.0.60"}, count=5, every_sec=25),
    Step(110, "impact", "ot", "LINE_STOP", PLC,
         {"user_id": USER_SERVICE, "host_id": PLC}, count=2, every_sec=60),
)

# Отличительные сущности сценария — по ним инцидент собирается пивотом. Каждая встречается в
# нескольких фазах: именно их аналитик и носил бы руками между консолями.
SEEDS: tuple[str, ...] = (
    f"address:{ATTACKER}",
    f"user:{USER_ENGINEER}",
    f"user:{USER_BACKUP}",
    f"user:{USER_SERVICE}",
    f"artifact:hash:{TOOL_HASH}",
    f"artifact:domain:{C2_DOMAIN}",
)


def build_events() -> list[dict[str, Any]]:
    """Развёртывание сценария в поток событий."""
    events: list[dict[str, Any]] = []
    for step in SCENARIO:
        start = BASE_TIME + timedelta(minutes=step.minute)
        for index in range(step.count):
            moment = start + timedelta(seconds=step.every_sec * index)
            payload = dict(step.payload)
            payload["attack_phase"] = step.phase
            events.append(
                {
                    "observed_at": moment.isoformat(),
                    "protocol": "TCP",
                    "operation": step.operation,
                    "asset_id": step.asset_id,
                    "source": step.source,
                    "payload_size": 512,
                    "payload": payload,
                }
            )
    events.sort(key=lambda item: item["observed_at"])
    return events


def _post(base_url: str, path: str, body: dict[str, Any], api_key: str) -> Any:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", **({"X-API-Key": api_key} if api_key else {})},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def _get(base_url: str, path: str, api_key: str) -> Any:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        headers={"X-API-Key": api_key} if api_key else {},
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def seed(base_url: str, api_key: str, batch_size: int = 70) -> str:
    events = build_events()
    print(f"событий в сценарии: {len(events)}")

    for start in range(0, len(events), batch_size):
        chunk = events[start : start + batch_size]
        _post(base_url, "/events/batch", {"events": chunk}, api_key)
        print(f"  принято {start + len(chunk)} из {len(events)}")

    # Инцидент собирается вокруг отличительных сущностей: пивот берёт все события, где они
    # встречаются, из всех источников сразу. Идентификатор берётся у любого дела, заведённого
    # приёмом по этому сценарию, — пивот пересобирает его состав, а не заводит второе дело.
    recent = _get(base_url, "/cases?limit=100&sort=risk_score_desc", api_key)
    anchor = next(
        (case["case_id"] for case in recent if case.get("primary_asset_id") == PLC),
        recent[0]["case_id"] if recent else "",
    )
    if not anchor:
        raise SystemExit("приём не завёл ни одного дела: собирать нечего")

    assembled = _post(
        base_url,
        "/cases/assemble/pivot",
        {"case_id": anchor, "seeds": list(SEEDS), "title": CASE_TITLE, "actor": "demo-seed"},
        api_key,
    )
    case_id = assembled.get("case_id", anchor)
    print(f"инцидент собран: {case_id}")
    print(f"  событий в ядре: {assembled.get('core_events', '—')}")
    return case_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8090")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()
    try:
        seed(args.base_url, args.api_key)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"{error.code}: {error.read().decode('utf-8')[:400]}") from error


if __name__ == "__main__":
    main()
