"""
Метрика проекта: ВРЕМЯ ОБРАБОТКИ ДАННЫХ ОПЕРАТОРОМ.

Прозрачная параметрическая модель сравнивает два режима разбора ОДНОГО и того же
инцидента (цепочка IEC-104 из stand/synthetic_data.py):

  • «Ручной режим»  — оператор перебирает сырой поток из N событий в SIEM/логах,
    вручную сопоставляет источники, реконструирует цепочку и оформляет вывод.
  • «Режим ТАКТ»    — оператор получает готовый коррелированный кейс с XAI-резюме,
    графом атаки и baseline-сущностями; ему остаётся проверить и подтвердить.

Все допущения вынесены в параметры и подписаны — числа воспроизводимы и обоснованы.
Модель даёт априорную оценку; во фронтенде есть живой секундомер, чтобы измерить
фактическое время конкретного оператора на тех же данных.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from synthetic_data import ATTACK_CHAIN, build_raw_event_stream


@dataclass(frozen=True)
class ManualAssumptions:
    # Оператор не читает все события, но обязан просмотреть значимую выборку,
    # чтобы не пропустить цепочку среди шума.
    scan_fraction: float = 0.45          # доля потока, реально просматриваемая глазами
    sec_per_event_scan: float = 3.5      # сек на беглый разбор одного события
    sources_to_pivot: int = 4            # число разных источников (netflow/syslog/edr/iec104/snmp)
    sec_per_pivot: float = 90.0          # переключение инструмента/запрос по источнику
    sec_manual_correlation: float = 360.0  # ручная сборка связи «кто→что→куда» по времени и сущностям
    sec_report: float = 300.0            # оформление вывода/карточки инцидента


@dataclass(frozen=True)
class TaktAssumptions:
    sec_read_xai: float = 40.0           # чтение XAI-резюме кейса
    sec_per_graph_node: float = 12.0     # проверка узла графа атаки
    sec_check_baseline: float = 30.0     # взгляд на sparkline typicality (z-score)
    sec_decision: float = 45.0           # решение + подтверждение статуса


def manual_seconds(raw_events: int, chain_len: int, a: ManualAssumptions) -> dict:
    scan = raw_events * a.scan_fraction * a.sec_per_event_scan
    pivots = a.sources_to_pivot * a.sec_per_pivot
    correlate = a.sec_manual_correlation
    report = a.sec_report
    total = scan + pivots + correlate + report
    return {
        "breakdown": {
            "Просмотр сырого потока": round(scan),
            "Переключение между источниками": round(pivots),
            "Ручная корреляция цепочки": round(correlate),
            "Оформление вывода": round(report),
        },
        "total_sec": round(total),
    }


def takt_seconds(chain_len: int, graph_nodes: int, a: TaktAssumptions) -> dict:
    read = a.sec_read_xai
    graph = graph_nodes * a.sec_per_graph_node
    baseline = a.sec_check_baseline
    decision = a.sec_decision
    total = read + graph + baseline + decision
    return {
        "breakdown": {
            "Чтение XAI-резюме": round(read),
            "Проверка графа атаки": round(graph),
            "Проверка baseline (z-score)": round(baseline),
            "Решение и подтверждение": round(decision),
        },
        "total_sec": round(total),
    }


def run() -> dict:
    raw = build_raw_event_stream()
    raw_n = len(raw)
    chain_len = len(ATTACK_CHAIN)
    # число узлов графа атаки для этого кейса
    from synthetic_data import build_attack_chain
    graph_nodes = len(build_attack_chain("CASE-2026-0731")["nodes"])

    ma, ta = ManualAssumptions(), TaktAssumptions()
    manual = manual_seconds(raw_n, chain_len, ma)
    takt = takt_seconds(chain_len, graph_nodes, ta)

    speedup = round(manual["total_sec"] / takt["total_sec"], 1)
    saved = manual["total_sec"] - takt["total_sec"]

    return {
        "scenario": "Цепочка IEC-104: несанкционированная команда управления на ПЛК",
        "dataset": {
            "raw_events_total": raw_n,
            "attack_events": chain_len,
            "attack_events_ratio": round(chain_len / raw_n, 4),
            "sources": ManualAssumptions().sources_to_pivot,
            "attack_graph_nodes": graph_nodes,
        },
        "assumptions": {"manual": asdict(ma), "takt": asdict(ta)},
        "manual": manual,
        "takt": takt,
        "result": {
            "manual_total_sec": manual["total_sec"],
            "takt_total_sec": takt["total_sec"],
            "manual_human": _fmt(manual["total_sec"]),
            "takt_human": _fmt(takt["total_sec"]),
            "seconds_saved": saved,
            "seconds_saved_human": _fmt(saved),
            "speedup_x": speedup,
        },
    }


def _fmt(sec: int) -> str:
    m, s = divmod(int(sec), 60)
    if m and s:
        return f"{m} мин {s} с"
    if m:
        return f"{m} мин"
    return f"{s} с"


def to_markdown(r: dict) -> str:
    res = r["result"]
    lines = [
        "# Метрика: время обработки инцидента оператором",
        "",
        f"**Сценарий:** {r['scenario']}",
        "",
        f"**Набор данных стенда:** {r['dataset']['raw_events_total']} событий в сыром потоке, "
        f"из них {r['dataset']['attack_events']} — реальная цепочка атаки "
        f"({r['dataset']['attack_events_ratio']*100:.1f}% сигнала), "
        f"{r['dataset']['sources']} источника, {r['dataset']['attack_graph_nodes']} узла графа атаки.",
        "",
        "## Итог",
        "",
        "| Режим | Время обработки |",
        "|---|---|",
        f"| 🖐️ Полностью ручной | **{res['manual_human']}** ({res['manual_total_sec']} с) |",
        f"| ⚡ Режим ТАКТ | **{res['takt_human']}** ({res['takt_total_sec']} с) |",
        f"| **Экономия** | **{res['seconds_saved_human']}**, ускорение **×{res['speedup_x']}** |",
        "",
        "## Ручной режим — из чего складывается время",
        "",
        "| Этап | Секунды |",
        "|---|---|",
    ]
    for k, v in r["manual"]["breakdown"].items():
        lines.append(f"| {k} | {v} |")
    lines += ["", "## Режим ТАКТ — из чего складывается время", "", "| Этап | Секунды |", "|---|---|"]
    for k, v in r["takt"]["breakdown"].items():
        lines.append(f"| {k} | {v} |")
    lines += [
        "",
        "## Допущения модели",
        "",
        "Модель параметрическая и воспроизводимая (см. `stand/benchmark.py`). "
        "Числа основаны на типовых значениях triage в SOC. Во фронтенде на экране "
        "«Сравнение» есть живой секундомер — фактическое время конкретного оператора "
        "измеряется на тех же данных стенда.",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    report = run()
    print(json.dumps(report["result"], ensure_ascii=False, indent=2))
