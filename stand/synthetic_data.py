"""
Синтетический стенд TAKT Industrial Risk Layer.

Детерминированный генератор данных для демонстрации АРМ SOC-оператора и
сравнения «ручного режима» с «режимом ТАКТ».

Сценарий: многошаговая атака на АСУ ТП подстанции по протоколу IEC-104.
  1. Внешний узел сканирует периметр (netflow).
  2. Подбор пароля к инженерной АРМ (syslog auth).
  3. Успешный вход на инженерную станцию (user compromise).
  4. Загрузка постороннего артефакта (файл-имплант).
  5. Запись уставки/команды управления на ПЛК (IEC-104 C_SC_NA_1).
  6. Аномальная телеметрия HMI (SNMP trap).

Реальная цепочка «спрятана» среди сотен шумовых событий — это и есть суть
разницы между ручным разбором и работой с коррелированным кейсом ТАКТ.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

# Детерминированность стенда: один и тот же seed → одни и те же данные.
SEED = 20260730
_BASE_TS = datetime(2026, 7, 30, 9, 0, 0, tzinfo=timezone.utc)

SEVERITIES = ["critical", "high", "medium", "low"]
SOURCE_CLASSES = ["netflow", "syslog", "snmp", "iec104", "endpoint", "firewall"]

# Активы промышленного сегмента (АСУ ТП подстанции).
HOSTS = [
    "eng-ws-01", "eng-ws-02", "hmi-scada-01", "plc-rtu-14",
    "plc-rtu-15", "jump-host-01", "historian-01", "gw-iec104-01",
]
USERS = ["a.petrov", "svc_scada", "operator1", "s.ivanov", "admin_local"]
ADDRESSES = [
    "10.20.0.11", "10.20.0.12", "10.20.5.14", "10.20.5.15",
    "10.20.9.1", "185.203.44.17", "45.155.205.9", "10.20.0.254",
]


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _mk_id(prefix: str, *parts: Any) -> str:
    h = hashlib.sha256("::".join(str(p) for p in parts).encode()).hexdigest()[:10]
    return f"{prefix}-{h}"


# --------------------------------------------------------------------------- #
# Реальная цепочка атаки (то, что оператор должен найти).                      #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ChainStep:
    order: int
    source_class: str
    host_id: str
    user_id: str | None
    address: str | None
    process: str | None
    artifact: str | None
    severity: str
    offset_min: int
    trigger_operation: str
    correlation_reason: str
    invariant: str
    raw_line: str


ATTACK_CHAIN: list[ChainStep] = [
    ChainStep(
        order=1, source_class="netflow", host_id="gw-iec104-01", user_id=None,
        address="185.203.44.17", process=None, artifact=None, severity="low",
        offset_min=0, trigger_operation="perimeter_scan",
        correlation_reason="Внешний IP сканирует диапазон АСУ ТП (>200 SYN за 30 c)",
        invariant="INV-NET-01: внешний источник не должен инициировать соединения к OT-сегменту",
        raw_line="netflow src=185.203.44.17 dst=10.20.5.0/24 flags=S count=214 dur=30s",
    ),
    ChainStep(
        order=2, source_class="syslog", host_id="eng-ws-01", user_id="a.petrov",
        address="185.203.44.17", process="sshd", artifact=None, severity="medium",
        offset_min=6, trigger_operation="auth_bruteforce",
        correlation_reason="Тот же внешний IP: 48 неуспешных входов за 4 мин на инженерную АРМ",
        invariant="INV-AUTH-03: >5 неуспешных аутентификаций за окно → бросок риска",
        raw_line="sshd[3111]: Failed password for a.petrov from 185.203.44.17 port 51344 ssh2 (x48)",
    ),
    ChainStep(
        order=3, source_class="syslog", host_id="eng-ws-01", user_id="a.petrov",
        address="185.203.44.17", process="sshd", artifact=None, severity="high",
        offset_min=11, trigger_operation="auth_success",
        correlation_reason="Успешный вход сразу после brute-force с того же IP",
        invariant="INV-AUTH-04: успех после серии отказов с того же источника",
        raw_line="sshd[3111]: Accepted password for a.petrov from 185.203.44.17 port 51402 ssh2",
    ),
    ChainStep(
        order=4, source_class="endpoint", host_id="eng-ws-01", user_id="a.petrov",
        address=None, process="powershell.exe", artifact="C:\\Temp\\iec_pusher.exe",
        severity="high", offset_min=14, trigger_operation="artifact_drop",
        correlation_reason="Неизвестный исполняемый файл записан скомпрометированным пользователем",
        invariant="INV-EDR-07: неподписанный бинарь в Temp на OT-хосте",
        raw_line="edr host=eng-ws-01 user=a.petrov proc=powershell.exe wrote C:\\Temp\\iec_pusher.exe sha256=e3b0c442...",
    ),
    ChainStep(
        order=5, source_class="iec104", host_id="plc-rtu-14", user_id="a.petrov",
        address="10.20.5.14", process="iec_pusher.exe", artifact=None, severity="critical",
        offset_min=17, trigger_operation="C_SC_NA_1_write",
        correlation_reason="Команда управления (single command) на ПЛК вне окна ТО, источник — инженерная АРМ",
        invariant="INV-OT-11: запись уставки/команды на ПЛК вне разрешённого окна обслуживания",
        raw_line="iec104 asdu=C_SC_NA_1 ioa=1401 val=ON coa=14 src=eng-ws-01 dst=plc-rtu-14 window=UNSCHEDULED",
    ),
    ChainStep(
        order=6, source_class="snmp", host_id="hmi-scada-01", user_id=None,
        address="10.20.0.11", process=None, artifact=None, severity="critical",
        offset_min=19, trigger_operation="telemetry_anomaly",
        correlation_reason="HMI фиксирует отклонение параметра после команды на ПЛК (z-score 6.4)",
        invariant="INV-OT-12: телеметрия за пределами baseline после управляющего воздействия",
        raw_line="snmp trap hmi-scada-01 oid=1.3.6.1.4.1 bus_voltage=deviation zscore=6.4",
    ),
]


# --------------------------------------------------------------------------- #
# Кейсы.                                                                       #
# --------------------------------------------------------------------------- #
def _findings_for_chain() -> list[dict]:
    findings = []
    seen: set[tuple[str, str]] = set()
    for step in ATTACK_CHAIN:
        for etype, eid in (
            ("host", step.host_id),
            ("user", step.user_id),
            ("address", step.address),
            ("process", step.process),
            ("artifact", step.artifact),
        ):
            if eid and (etype, eid) not in seen:
                seen.add((etype, eid))
                findings.append({
                    "id": _mk_id("fnd", etype, eid),
                    "entity_type": etype,
                    "entity_id": eid,
                    "added_at": _iso(_BASE_TS + timedelta(minutes=step.offset_min)),
                })
    return findings


def build_cases() -> list[dict]:
    rng = random.Random(SEED)
    cases: list[dict] = []

    # Ключевой кейс — коррелированная цепочка IEC-104.
    chain_case_id = "CASE-2026-0731"
    cases.append({
        "id": chain_case_id,
        "severity": "critical",
        "status": "new",
        "created_at": _iso(_BASE_TS + timedelta(minutes=19)),
        "updated_at": _iso(_BASE_TS + timedelta(minutes=19)),
        "title": "Несанкционированная команда управления на ПЛК (цепочка IEC-104)",
        "risk_score": 0.94,
        "xai_summary": (
            "Коррелировано 6 событий из 4 источников за 19 минут: внешнее сканирование → "
            "brute-force → вход → доставка импланта → команда C_SC_NA_1 на plc-rtu-14 → "
            "аномалия телеметрии HMI. Единый источник 185.203.44.17 и пользователь a.petrov."
        ),
        "findings": _findings_for_chain(),
        "_chain": True,
    })

    # Шумовые/фоновые кейсы (типовые срабатывания без реальной атаки).
    noise_titles = [
        ("Просроченный сертификат historian", "medium", "investigating"),
        ("Всплеск ICMP от gw-iec104-01", "low", "new"),
        ("Повтор входа svc_scada (плановая ротация)", "low", "resolved"),
        ("Обновление прошивки plc-rtu-15", "medium", "new"),
        ("Диск historian-01 заполнен на 82%", "high", "investigating"),
    ]
    for i, (title, sev, status) in enumerate(noise_titles):
        off = 30 + i * 25
        host = rng.choice(HOSTS)
        cases.append({
            "id": f"CASE-2026-{732 + i:04d}"[:9] + f"{732 + i:04d}"[-4:],
            "severity": sev,
            "status": status,
            "created_at": _iso(_BASE_TS + timedelta(minutes=off)),
            "updated_at": _iso(_BASE_TS + timedelta(minutes=off + 3)),
            "title": title,
            "risk_score": round(rng.uniform(0.15, 0.55), 2),
            "xai_summary": "Одиночное срабатывание правила, корреляций не обнаружено.",
            "findings": [{
                "id": _mk_id("fnd", host, i),
                "entity_type": "host",
                "entity_id": host,
                "added_at": _iso(_BASE_TS + timedelta(minutes=off)),
            }],
            "_chain": False,
        })
    return cases


def build_events_for_case(case_id: str) -> list[dict]:
    cases = {c["id"]: c for c in build_cases()}
    case = cases.get(case_id)
    if not case:
        return []
    if case.get("_chain"):
        return [{
            "id": _mk_id("evt", case_id, s.order),
            "source_class": s.source_class,
            "host_id": s.host_id,
            "user_id": s.user_id,
            "process": s.process,
            "address": s.address,
            "artifact": s.artifact,
            "ts": _iso(_BASE_TS + timedelta(minutes=s.offset_min)),
            "severity": s.severity,
        } for s in ATTACK_CHAIN]
    # Для шумовых кейсов — несколько незначимых событий.
    rng = random.Random(hash(case_id) & 0xFFFFFFFF)
    return [{
        "id": _mk_id("evt", case_id, i),
        "source_class": rng.choice(SOURCE_CLASSES),
        "host_id": case["findings"][0]["entity_id"],
        "user_id": None,
        "process": None,
        "address": rng.choice(ADDRESSES),
        "artifact": None,
        "ts": _iso(_BASE_TS + timedelta(minutes=rng.randint(30, 180), seconds=rng.randint(0, 59))),
        "severity": case["severity"],
    } for i in range(rng.randint(2, 4))]


def build_attack_chain(case_id: str) -> dict:
    cases = {c["id"]: c for c in build_cases()}
    case = cases.get(case_id)
    if not case or not case.get("_chain"):
        return {"nodes": [], "edges": []}

    nodes: list[dict] = []
    seen: set[str] = set()

    def add_node(ntype: str, nid: str, sev: str) -> str:
        node_id = f"{ntype}:{nid}"
        if node_id not in seen:
            seen.add(node_id)
            nodes.append({
                "id": node_id,
                "type": ntype,
                "label": nid,
                "severity": sev,
            })
        return node_id

    edges: list[dict] = []
    prev_key: str | None = None
    for s in ATTACK_CHAIN:
        # Основная сущность шага для позиционирования цепочки.
        if s.source_class == "iec104" or s.host_id.startswith("plc"):
            key = add_node("host", s.host_id, s.severity)
        elif s.artifact:
            key = add_node("artifact", s.artifact, s.severity)
        elif s.user_id:
            key = add_node("user", s.user_id, s.severity)
        elif s.address:
            key = add_node("address", s.address, s.severity)
        else:
            key = add_node("host", s.host_id, s.severity)

        if prev_key and prev_key != key:
            edges.append({
                "id": _mk_id("edge", prev_key, key, s.order),
                "source": prev_key,
                "target": key,
                "correlation_reason": s.correlation_reason,
            })
        prev_key = key
    return {"nodes": nodes, "edges": edges}


def build_baseline(entity_type: str, entity_id: str) -> dict:
    """Онлайн-статистика Welford: последние z-score для sparkline."""
    rng = random.Random(hashlib.sha256(f"{entity_type}:{entity_id}".encode()).hexdigest()[:8].encode() if False else (hash((entity_type, entity_id)) & 0xFFFFFFFF))
    base = [rng.gauss(0, 0.8) for _ in range(28)]
    # Скомпрометированные сущности «выстреливают» в конце ряда.
    if entity_id in {"plc-rtu-14", "hmi-scada-01", "a.petrov", "185.203.44.17"}:
        base[-4:] = [2.1, 3.8, 6.4, 5.2]
    z = [round(v, 2) for v in base]
    mean = round(sum(z) / len(z), 3)
    var = sum((v - mean) ** 2 for v in z) / len(z)
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "z_scores": z,
        "mean": mean,
        "stddev": round(var ** 0.5, 3),
    }


# --------------------------------------------------------------------------- #
# Сырой поток событий для «ручного режима».                                    #
# --------------------------------------------------------------------------- #
def build_raw_event_stream(noise_count: int = 480) -> list[dict]:
    """
    Плоский, нескоррелированный поток «как из SIEM/лог-коллектора».
    6 событий реальной атаки перемешаны с сотнями шумовых.
    Именно этот массив оператор вынужден перебирать вручную.
    """
    rng = random.Random(SEED + 1)
    rows: list[dict] = []

    # Шумовые события.
    noise_templates = [
        ("syslog", "INFO", "systemd: Started Session {n} of user svc_scada"),
        ("netflow", "INFO", "flow src={a} dst=10.20.0.254 proto=tcp bytes={b}"),
        ("snmp", "INFO", "trap {h} oid=1.3.6.1.2.1 ifInOctets ok"),
        ("firewall", "INFO", "ACCEPT src={a} dst={a2} dpt=502 proto=tcp"),
        ("endpoint", "INFO", "proc {h} svchost.exe spawned services.exe"),
        ("syslog", "WARN", "ntpd: time sync jitter {n}ms on {h}"),
        ("iec104", "INFO", "iec104 asdu=M_ME_NC_1 ioa={n} measured value ok src={h}"),
        ("firewall", "INFO", "ACCEPT src={a} dst={a2} dpt=2404 proto=tcp"),
    ]
    for i in range(noise_count):
        sc, lvl, tmpl = rng.choice(noise_templates)
        line = tmpl.format(
            n=rng.randint(1, 9999),
            a=rng.choice(ADDRESSES[:5]),
            a2=rng.choice(ADDRESSES[:5]),
            b=rng.randint(200, 90000),
            h=rng.choice(HOSTS),
        )
        rows.append({
            "id": _mk_id("raw", i),
            "ts": _iso(_BASE_TS + timedelta(minutes=rng.randint(-40, 200), seconds=rng.randint(0, 59))),
            "source_class": sc,
            "level": lvl,
            "host_id": rng.choice(HOSTS),
            "message": line,
            "is_attack": False,
            "attack_step": None,
        })

    # Реальная цепочка — вкрапляем.
    for s in ATTACK_CHAIN:
        rows.append({
            "id": _mk_id("raw-atk", s.order),
            "ts": _iso(_BASE_TS + timedelta(minutes=s.offset_min)),
            "source_class": s.source_class,
            "level": "ALERT" if s.severity in ("critical", "high") else "NOTICE",
            "host_id": s.host_id,
            "message": s.raw_line,
            "is_attack": True,
            "attack_step": s.order,
        })

    rows.sort(key=lambda r: r["ts"])
    return rows


if __name__ == "__main__":
    import json
    print("cases:", len(build_cases()))
    print("chain events:", len(build_events_for_case("CASE-2026-0731")))
    print("chain graph:", json.dumps(build_attack_chain("CASE-2026-0731"), ensure_ascii=False)[:200])
    print("raw stream:", len(build_raw_event_stream()), "events (6 attack + noise)")
