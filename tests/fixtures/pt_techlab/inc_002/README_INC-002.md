# Фикстура INC-002 — компрометация конвейера сборки через фишинг

Синтетический датасет для демо Positive Technologies (Техлаб 2026).
Замена сценария «котельная»: профильный кейс — атака на CI/CD софтверной компании.
Все данные синтетические, данных заказчика нет.

## Файлы

| Файл | Событий | Источник |
|---|---|---|
| `edr.csv` | 531 | EDR (процессы, файлы) |
| `siem.csv` | 240 | SIEM (правила корреляции) |
| `ndr.csv` | 227 | NDR (сетевые потоки) |
| `ot.csv` | 32 | Целостность CI/сборки (вместо OT) |
| `nad_sample.ndjson` | 12 | PT NAD, поле `credentials.password` замаскировано |

Всего 1030 событий, из них 27 — цепочка `INC-002`, остальное фон и отвлекающие аномалии.

## Цепочка атаки (2026-08-17, UTC)

| T+ | Фаза | Источник | Ключевые события |
|---|---|---|---|
| 0–3 мин | Фишинг, запуск | EDR | OUTLOOK -> mshta -> powershell -> invoice_viewer.exe (ws-17, smirnov) |
| 3–38 мин | C2 по DoH | NDR/NAD | 6x C2_SUSPECT -> cdn-metrics.example-analytics.com (185.220.101.34); SIEM видит лишь 1 слабое SUSPICIOUS_OUTBOUND |
| 12–14 мин | Kerberoasting | SIEM | KERBEROS_TGS_RC4 по 3 SPN, аномалия входа svc_build |
| 15–17 мин | Lateral movement | NDR+EDR | SMB ws-17 -> build-srv-01, wmiprvse под svc_build |
| 20–24 мин | Подмена артефакта | CI (ot.csv) | ARTIFACT_HASH_MISMATCH, UNSIGNED_ARTIFACT_PUSH, CODE_REPO_WRITE_OFFHOURS |

## Отвлекающие аномалии (для проверки ложных срабатываний)

- `BG-ADMIN` — легитимный админ off-hours (похоже на lateral movement).
- `BG-SCAN` — санкционированный сканер уязвимостей scan-01.
- `BG-BACKUP` — ночной бэкап с большим SMB-трафиком.

## Ключевые сущности для пивота

`smirnov` -> `ws-17` (10.10.1.26) -> `svc_build` -> `build-srv-01` (10.10.3.5) -> `release-prod` / `app-setup.msi`.

## Ожидаемый вердикт

Подтверждённая компрометация: фишинг -> C2 (DoH) -> kerberoasting -> захват svc_build ->
попытка внедрения неподписанного артефакта в релизный конвейер.
Рекомендации (без автоматических действий): изоляция ws-17, сброс svc_build,
блокировка домена/IP C2, заморозка pipeline release-prod, проверка хэшей артефактов.

## Воспроизведение

`python gen.py` — детерминированная генерация (seed=42).
