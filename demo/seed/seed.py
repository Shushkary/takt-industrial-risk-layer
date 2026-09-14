"""Засев демонстрационного стенда: INC-002 плюс синтетическая цепочка.

Запускается одноразовым контейнером (`docker compose run --rm seed`) и делает
четыре шага:

1. дожидается готовности API;
2. загружает выгрузки INC-002 четырёх классов источников (EDR, SIEM, NDR, OT)
   напрямую в хранилище — так же, как это делает штатный `takt.tools.load_dataset`;
3. запускает сборку инцидентов по отличительным сущностям;
4. добавляет синтетическую цепочку «захват инженерной станции» через HTTP API.

**Все данные синтетические.** Ни одно событие не наблюдалось на реальном объекте:
выгрузки INC-002 сгенерированы (`gen.py` в каталоге исходных данных), цепочка
написана для показа. Числовые характеристики продукта на этих данных не измеряются.

Повторный запуск отклоняется: события пришли бы в хранилище вторым экземпляром и
состав инцидента перестал бы соответствовать описанию. Пересев — `--force`
(к уже загруженным данным добавится второй экземпляр) либо чистый том:
`docker compose down -v`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SEED_DIR = Path(__file__).resolve().parent
DATASET_DIR = SEED_DIR / "inc_002"
SOURCES = ("edr", "siem", "ndr", "ot")

# Отметка засева лежит рядом с базой, а не по фиксированному пути: том и база живут и
# умирают вместе, поэтому `docker compose down -v` снимает отметку заодно с данными.
# Путь берётся из той же переменной, что и база, — иначе отметка и данные разъезжаются.
MARKER = Path(os.environ.get("TAKT_SQLITE_PATH", "data/takt_demo.db")).parent / ".demo-seeded"


def wait_ready(base_url: str, *, attempts: int = 60, delay_sec: float = 2.0) -> None:
    """Ожидание готовности API. Без него засев падает на первом же запросе."""
    last = ""
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(f"{base_url}/ready", timeout=5) as response:
                if response.status == 200:
                    return
                last = f"HTTP {response.status}"
        except OSError as error:
            last = str(error)
        time.sleep(delay_sec)
    raise SystemExit(f"API не ответил на {base_url}/ready: {last}")


def post(base_url: str, path: str, body: dict) -> dict:
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        return json.loads(response.read().decode("utf-8"))


def load_datasets() -> None:
    """Выгрузки INC-002 — напрямую в хранилище, тем же путём, что и в продукте."""
    from takt.tools.load_dataset import run as load_run

    for source in SOURCES:
        path = DATASET_DIR / f"{source}.csv"
        if not path.is_file():
            raise SystemExit(f"нет файла выгрузки: {path}")
        print(f"[1/4] загрузка выгрузки {source}: {path.name}")
        # Догоняющая сборка выключена: она запускается один раз после всех четырёх
        # источников, иначе инцидент собирался бы по неполному потоку.
        code = load_run(source=source, path=path, progress_every=0, assemble=False)
        if code != 0:
            raise SystemExit(f"загрузка {source} завершилась с кодом {code}")


def assemble(base_url: str) -> None:
    print("[2/4] сборка инцидентов по отличительным сущностям")
    report = post(base_url, "/cases/assemble/auto", {"actor": "demo-seed"})
    for incident in report.get("incidents", []):
        print(f"      инцидент {incident['case_id']}: событий {incident['event_count']}")
    if not report.get("incidents"):
        print("      инцидентов не собрано — проверьте, что выгрузки загрузились")


def seed_chain(base_url: str) -> None:
    print("[3/4] синтетическая цепочка «захват инженерной станции»")
    sys.path.insert(0, str(SEED_DIR))
    from seed_demo_chain import seed as seed_demo_chain  # noqa: PLC0415

    seed_demo_chain(base_url, "")


def summary(base_url: str) -> None:
    print("[4/4] итог")
    request = urllib.request.Request(f"{base_url}/cases?limit=5&sort=risk_score_desc")
    with urllib.request.urlopen(request, timeout=60) as response:
        cases = json.loads(response.read().decode("utf-8"))
    for case in cases:
        print(f"      {case.get('case_id')}  {case.get('risk_class')}  событий {case.get('event_count')}")
    print()
    print("      АРМ аналитика: http://127.0.0.1:8080/")
    print("      Swagger API:   http://127.0.0.1:8090/docs")


def main() -> int:
    parser = argparse.ArgumentParser(description="Засев демонстрационного стенда ТАКТ")
    parser.add_argument("--base-url", default=os.environ.get("TAKT_DEMO_API_BASE", "http://api:8090"))
    parser.add_argument("--force", action="store_true", help="повторить засев поверх уже загруженных данных")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    if MARKER.exists() and not args.force:
        print(f"стенд уже заполнен ({MARKER.read_text(encoding='utf-8').strip()}).")
        print("Повторный засев добавил бы второй экземпляр событий и разошёлся бы с описанием.")
        print("Чистый прогон: docker compose down -v && docker compose up -d --build")
        return 0

    wait_ready(base_url)
    load_datasets()
    assemble(base_url)
    seed_chain(base_url)
    MARKER.parent.mkdir(parents=True, exist_ok=True)
    MARKER.write_text(time.strftime("%Y-%m-%dT%H:%M:%S%z"), encoding="utf-8")
    summary(base_url)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")[:400]
        raise SystemExit(f"API ответил {error.code}: {body}") from error
