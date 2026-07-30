"""
Синтетический стенд TAKT — API-сервер.

Отдаёт контракт `/api/v1/*`, который ожидает фронтенд АРМ
(frontend/src/api/client.ts), плюс данные для экрана «Сравнение» и
антихрупкие расширения (петля обучения, лок, вердикт, аудит, chaos).

Базовые эндпоинты:
  • GET   /api/v1/cases                         список кейсов (риск пересчитан по весам)
  • GET   /api/v1/cases/{id}                     кейс
  • PATCH /api/v1/cases/{id}                     смена статуса / severity
  • GET   /api/v1/cases/{id}/attack-chain        граф атаки
  • GET   /api/v1/cases/{id}/events              события кейса
  • GET   /api/v1/events/search                  поиск (курсорная пагинация)
  • POST  /api/v1/findings                       добавить находку
  • GET   /api/v1/baseline/{type}/{id}           baseline (z-score sparkline)
  • GET   /api/v1/stream/cases                   SSE-поток (heartbeat + chaos)
  • GET   /api/v1/raw-events                     сырой поток для «ручного режима»
  • GET   /api/v1/benchmark                      метрика времени оператора
  • GET   /health                                проверка живости

Антихрупкие расширения:
  • POST  /api/v1/cases/{id}/verdict             вердикт TP/FP/benign → петля обучения
  • POST  /api/v1/cases/{id}/lock  · /unlock     queue lock (эксклюзив оператора)
  • POST  /api/v1/cases/{id}/escalate            эскалация L1→L2
  • GET   /api/v1/model                          состояние модели (веса, калибровка)
  • GET   /api/v1/audit                          неизменяемый аудит-лог (hash-chain)
  • GET   /api/v1/chaos  · POST /api/v1/chaos    инъекция хаоса (hormesis)
  • POST  /api/v1/reset                          сброс стенда к исходному состоянию

Запуск:  uvicorn server:app --host 0.0.0.0 --port 8090
"""
from __future__ import annotations

import asyncio
import json
import random
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from benchmark import run as run_benchmark
from benchmark import to_markdown
from engine_state import STATE
from synthetic_data import (
    build_attack_chain,
    build_baseline,
    build_events_for_case,
    build_raw_event_stream,
)

app = FastAPI(title="TAKT Synthetic Stand", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Базовые эндпоинты кейсов                                                     #
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict:
    chaos = STATE.get_chaos()
    return {
        "status": "ok" if chaos["mode"] == "off" else "degraded",
        "cases": len(STATE.list_cases()),
        "chaos": chaos["mode"],
        "ts": _now_z(),
    }


@app.get("/api/v1/cases")
def list_cases() -> list[dict]:
    return STATE.list_cases()


@app.get("/api/v1/cases/{case_id}")
def get_case(case_id: str):
    case = STATE.get_case(case_id)
    if not case:
        return JSONResponse(status_code=404, content={"detail": "Кейс не найден"})
    return case


@app.patch("/api/v1/cases/{case_id}")
async def patch_case(case_id: str, request: Request):
    body = await request.json()
    case = None
    if "severity" in body:
        case = STATE.set_severity(case_id, body["severity"], body.get("operator", "operator.shift-A"))
    if "status" in body:
        case = STATE.set_status(case_id, body["status"])
    if case is None:
        case = STATE.get_case(case_id)
    if not case:
        return JSONResponse(status_code=404, content={"detail": "Кейс не найден"})
    return case


# --------------------------------------------------------------------------- #
# Антихрупкость: вердикт + петля обучения                                      #
# --------------------------------------------------------------------------- #
@app.post("/api/v1/cases/{case_id}/verdict")
async def post_verdict(case_id: str, request: Request):
    body = await request.json()
    verdict = body.get("verdict")
    if verdict not in ("tp", "fp", "benign"):
        return JSONResponse(status_code=400, content={"detail": "verdict ∈ {tp, fp, benign}"})
    result = STATE.record_verdict(
        case_id,
        verdict=verdict,
        reason=body.get("reason", ""),
        operator=body.get("operator", "operator.shift-A"),
        risk_feedback=body.get("risk_feedback"),
    )
    if result is None:
        return JSONResponse(status_code=404, content={"detail": "Кейс не найден"})
    return result


# --------------------------------------------------------------------------- #
# Антихрупкость: queue lock                                                    #
# --------------------------------------------------------------------------- #
@app.post("/api/v1/cases/{case_id}/lock")
async def post_lock(case_id: str, request: Request):
    body = await request.json()
    res = STATE.lock(case_id, body.get("operator", "operator.shift-A"))
    if res is None:
        return JSONResponse(status_code=404, content={"detail": "Кейс не найден"})
    if res.get("conflict"):
        return JSONResponse(status_code=409, content=res)
    return res


@app.post("/api/v1/cases/{case_id}/unlock")
async def post_unlock(case_id: str, request: Request):
    body = await request.json()
    STATE.unlock(case_id, body.get("operator", "operator.shift-A"))
    return {"status": "ok"}


@app.post("/api/v1/cases/{case_id}/escalate")
async def post_escalate(case_id: str, request: Request):
    body = await request.json()
    case = STATE.escalate(case_id, body.get("operator", "operator.shift-A"))
    if case is None:
        return JSONResponse(status_code=404, content={"detail": "Кейс не найден"})
    return case


# --------------------------------------------------------------------------- #
# Антихрупкость: модель, аудит, chaos, reset                                   #
# --------------------------------------------------------------------------- #
@app.get("/api/v1/model")
def model() -> dict:
    return STATE.model_snapshot()


@app.get("/api/v1/audit")
def audit(limit: int = 100) -> dict:
    return {"items": STATE.audit_log(limit)}


@app.get("/api/v1/chaos")
def get_chaos() -> dict:
    return STATE.get_chaos()


@app.post("/api/v1/chaos")
async def set_chaos(request: Request):
    body = await request.json()
    mode = body.get("mode", "off")
    valid = ("off", "burst", "drop_source", "dup", "future", "malformed", "latency")
    if mode not in valid:
        return JSONResponse(status_code=400, content={"detail": f"mode ∈ {valid}"})
    return STATE.set_chaos(mode)


@app.post("/api/v1/reset")
def reset() -> dict:
    STATE.reset()
    return {"status": "ok", "ts": _now_z()}


# --------------------------------------------------------------------------- #
# Граф / события / поиск / находки / baseline                                  #
# --------------------------------------------------------------------------- #
@app.get("/api/v1/cases/{case_id}/attack-chain")
def attack_chain(case_id: str) -> dict:
    return build_attack_chain(case_id)


@app.get("/api/v1/cases/{case_id}/events")
def case_events(case_id: str) -> list[dict]:
    return build_events_for_case(case_id)


@app.get("/api/v1/events/search")
def search_events(q: str = Query(default=""), cursor: str | None = None, limit: int = 50) -> dict:
    raw = build_raw_event_stream()
    ql = q.lower().strip()
    matched = [r for r in raw if not ql or ql in r["message"].lower() or ql in r["source_class"]]
    start = int(cursor) if cursor and cursor.isdigit() else 0
    page = matched[start:start + limit]
    next_cursor = str(start + limit) if start + limit < len(matched) else None
    items = [{
        "id": r["id"],
        "source_class": r["source_class"],
        "host_id": r["host_id"],
        "ts": r["ts"],
        "severity": "critical" if r["level"] == "ALERT" else "low",
    } for r in page]
    return {"items": items, "next_cursor": next_cursor, "total_count": len(matched)}


@app.post("/api/v1/findings")
async def add_finding(request: Request) -> dict:
    body = await request.json()
    case = STATE.get_case(body.get("case_id", ""))
    # Находки на стенде носят демонстрационный характер (состояние — в STATE).
    return {"status": "ok", "case_found": case is not None}


@app.get("/api/v1/baseline/{entity_type}/{entity_id}")
def baseline(entity_type: str, entity_id: str) -> dict:
    return build_baseline(entity_type, entity_id)


@app.get("/api/v1/raw-events")
def raw_events(limit: int = 1000) -> dict:
    """Сырой нескоррелированный поток для «ручного режима» экрана сравнения."""
    rows = build_raw_event_stream()[:limit]
    return {
        "items": rows,
        "total_count": len(rows),
        "attack_step_count": sum(1 for r in rows if r["is_attack"]),
    }


@app.get("/api/v1/benchmark")
def benchmark() -> dict:
    return run_benchmark()


@app.get("/api/v1/benchmark.md")
def benchmark_md():
    return PlainTextResponse(to_markdown(run_benchmark()), media_type="text/markdown; charset=utf-8")


# --------------------------------------------------------------------------- #
# SSE-поток с heartbeat и реакцией на chaos                                    #
# --------------------------------------------------------------------------- #
@app.get("/api/v1/stream/cases")
async def stream_cases(request: Request) -> StreamingResponse:
    """
    SSE-поток новых/обновлённых кейсов.

    • heartbeat-комментарий (`: hb`) с меткой времени раз в ~3 c — клиент по нему
      детектирует «замолчавший» канал (stale) даже без новых кейсов.
    • Реакция на инъекцию хаоса (hormesis): всплеск, обрыв источника, дубли,
      события «из будущего», битый payload, задержка. Стенд деградирует, не падает.
    """
    async def gen():
        cases = STATE.list_cases()
        order = list(cases)
        i = 0
        rng = random.Random(1)

        # Первое сообщение — сразу самый критичный кейс.
        top = sorted(order, key=lambda c: c.get("risk_score", 0), reverse=True)[0]
        yield f"data: {json.dumps(top, ensure_ascii=False)}\n\n"

        while True:
            if await request.is_disconnected():
                break

            chaos = STATE.get_chaos()
            mode = chaos["mode"]

            # Интервал зависит от режима: burst — быстрее, latency — медленнее.
            interval = 8.0
            if mode == "burst":
                interval = 0.4
            elif mode == "latency":
                interval = 16.0

            # Heartbeat пока ждём (кроме drop_source — там намеренно «тишина»).
            # Именованное событие `heartbeat` — EventSource не отдаёт коммент-строки,
            # поэтому stale-детектор клиента слушает именно это событие.
            waited = 0.0
            step = 1.5
            while waited < interval:
                await asyncio.sleep(min(step, interval - waited))
                waited += step
                if mode != "drop_source":
                    yield f"event: heartbeat\ndata: {json.dumps({'ts': _now_z(), 'chaos': mode})}\n\n"
                if await request.is_disconnected():
                    return

            if mode == "drop_source":
                # Источник «отвалился»: heartbeat молчит, клиент увидит stale.
                STATE.bump_chaos()
                continue

            case = dict(STATE.get_case(order[i % len(order)]["id"]) or order[i % len(order)])
            case["updated_at"] = _now_z()

            if mode == "future":
                # Событие «из будущего» — рассинхрон времени источника.
                future = datetime.now(timezone.utc) + timedelta(hours=3)
                case["updated_at"] = future.isoformat().replace("+00:00", "Z")
                STATE.bump_chaos()
            elif mode == "malformed":
                # Битый payload — клиент должен пережить, а не упасть.
                STATE.bump_chaos()
                yield "data: {broken json ==>\n\n"
                i += 1
                continue

            payload = json.dumps(case, ensure_ascii=False)
            yield f"data: {payload}\n\n"

            if mode == "dup":
                # Дубликат того же события — идемпотентность на клиенте.
                STATE.bump_chaos()
                yield f"data: {payload}\n\n"

            i += 1

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
