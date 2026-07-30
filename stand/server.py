"""
Синтетический стенд TAKT — API-сервер.

Отдаёт ровно тот контракт `/api/v1/*`, который ожидает фронтенд АРМ
(frontend/src/api/client.ts), плюс данные для экрана «Сравнение»:
  • GET  /api/v1/cases                         список кейсов
  • GET  /api/v1/cases/{id}                     кейс
  • PATCH /api/v1/cases/{id}                     смена статуса
  • GET  /api/v1/cases/{id}/attack-chain         граф атаки
  • GET  /api/v1/cases/{id}/events               события кейса
  • GET  /api/v1/events/search                   поиск (курсорная пагинация)
  • POST /api/v1/findings                        добавить находку
  • GET  /api/v1/baseline/{type}/{id}            baseline (z-score sparkline)
  • GET  /api/v1/stream/cases                    SSE-поток новых кейсов
  • GET  /api/v1/raw-events                      сырой поток для «ручного режима»
  • GET  /api/v1/benchmark                       метрика: время оператора (модель)
  • GET  /health                                 проверка живости

Запуск:  uvicorn server:app --host 0.0.0.0 --port 8090
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from benchmark import run as run_benchmark
from benchmark import to_markdown
from synthetic_data import (
    build_attack_chain,
    build_baseline,
    build_cases,
    build_events_for_case,
    build_raw_event_stream,
)

app = FastAPI(title="TAKT Synthetic Stand", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Изменяемое состояние кейсов в памяти (статусы, находки), чтобы PATCH/POST работали.
_CASES: dict[str, dict] = {}


def _load() -> None:
    _CASES.clear()
    for c in build_cases():
        c = dict(c)
        c.pop("_chain", None)
        _CASES[c["id"]] = c


_load()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "cases": len(_CASES), "ts": datetime.now(timezone.utc).isoformat()}


@app.get("/api/v1/cases")
def list_cases() -> list[dict]:
    # Сортировка по риску убыванию — критичное сверху.
    return sorted(_CASES.values(), key=lambda c: c.get("risk_score", 0), reverse=True)


@app.get("/api/v1/cases/{case_id}")
def get_case(case_id: str):
    case = _CASES.get(case_id)
    if not case:
        return JSONResponse(status_code=404, content={"detail": "Кейс не найден"})
    return case


@app.patch("/api/v1/cases/{case_id}")
async def patch_case(case_id: str, request: Request):
    case = _CASES.get(case_id)
    if not case:
        return JSONResponse(status_code=404, content={"detail": "Кейс не найден"})
    body = await request.json()
    if "status" in body:
        case["status"] = body["status"]
        case["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return case


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
    case = _CASES.get(body.get("case_id", ""))
    if case is not None:
        case.setdefault("findings", []).append({
            "id": f"fnd-{len(case['findings'])+1}",
            "entity_type": body.get("entity_type"),
            "entity_id": body.get("entity_id"),
            "added_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })
    return {"status": "ok"}


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
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(to_markdown(run_benchmark()), media_type="text/markdown; charset=utf-8")


@app.get("/api/v1/stream/cases")
async def stream_cases(request: Request) -> StreamingResponse:
    """
    SSE-поток. Периодически «поднимает» очередной кейс наверх очереди,
    имитируя живой приток инцидентов в АРМ.
    """
    async def gen():
        order = list(_CASES.values())
        i = 0
        # Первое сообщение — сразу критичный кейс.
        yield f"data: {json.dumps(sorted(order, key=lambda c: c.get('risk_score',0), reverse=True)[0], ensure_ascii=False)}\n\n"
        while True:
            if await request.is_disconnected():
                break
            await asyncio.sleep(8)
            case = dict(order[i % len(order)])
            case["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            yield f"data: {json.dumps(case, ensure_ascii=False)}\n\n"
            i += 1

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
