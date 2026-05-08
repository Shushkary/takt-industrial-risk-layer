# Runbook — Deploy Smoke Checks

Запускается сразу после выкладки релизного образа.

## 0) Быстрый чек «5 минут до релиза»

Минимальный проход (в порядке выполнения):

1. `GET /ready` возвращает `ready=true`; для strict-среды дополнительно `forensic_crypto_mode=gost_strict`, `forensic_strict_ready=true`, `forensic_strict_missing=[]`.
2. Один `POST /assess` успешно создаёт кейс и возвращает `case_id`.
3. `GET /cases/<CASE_ID>/forensic-bundle.zip` отдаёт заголовки `X-TAKT-Forensic-Root-Hash` и `X-TAKT-Forensic-Signature-Status`.
4. `POST /forensic-bundle/verify` по скачанному ZIP возвращает `ok=true`, а в strict-среде не возникает `forensic_signing_unavailable` (ожидается `false`).
5. `GET /cases/<CASE_ID>/export/gossopka-official-transport.json` возвращает `200` (флаг `gossopka_official_ok=true` в operational tails / `release_finalize`).
6. `POST /audit-engagements` и `GET /audit-engagements/<ENGAGEMENT_ID>/export/report.json` проходят успешно.

Если любой шаг падает, релиз не продвигается до выяснения причины.

## 1) Health/ready/live

```powershell
curl -sS http://127.0.0.1:8090/live
curl -sS http://127.0.0.1:8090/ready
curl -sS http://127.0.0.1:8090/health
```

Проверить:

- `ready=true`;
- ожидаемый `case_storage` (`sqlite` для prod-сценария);
- `sqlite_schema_version` соответствует ожидаемой версии.

## 2) Минимальный assess flow

```powershell
curl -sS -X POST "http://127.0.0.1:8090/assess" ^
  -H "Content-Type: application/json" ^
  -d "{\"observed_at\":\"2026-05-07T12:00:00+00:00\",\"operation\":\"READ\",\"asset_id\":\"plc-smoke\"}"
```

Сохранить `case_id` из ответа.

## 3) Экспорт и forensic verify

```powershell
curl -sS "http://127.0.0.1:8090/cases/<CASE_ID>/export/siem.json"
curl -sS "http://127.0.0.1:8090/cases/<CASE_ID>/forensic-bundle/manifest"
curl -sS -o forensic-smoke.zip "http://127.0.0.1:8090/cases/<CASE_ID>/forensic-bundle.zip"
curl -sS -X POST "http://127.0.0.1:8090/forensic-bundle/verify" ^
  -H "Content-Type: application/zip" ^
  --data-binary "@forensic-smoke.zip"
```

Проверить:

- forensic verify возвращает `ok=true`;
- `signature_status` соответствует ожидаемому режиму среды:
  - `mvp`: допустимы `unsigned_mvp`, `hmac_sha256_mvp`, `external_qualified_detached`;
  - `gost_strict`: ожидается `external_gost2012_detached` (без HMAC fallback).
- HTTP-ответ `forensic-bundle.zip` содержит заголовки `X-TAKT-Forensic-Root-Hash` и `X-TAKT-Forensic-Signature-Status`.
- Если в strict-среде получен `503` с `forensic_signing_unavailable`, проверить доступность `TAKT_FORENSIC_SIGN_URL`/`TAKT_FORENSIC_VERIFY_URL` из runtime и валидность ответа signer.

## 3.1) GosSOPKA official-format export (release gate)

```powershell
curl -sS "http://127.0.0.1:8090/cases/<CASE_ID>/export/gossopka-official-transport.json"
```

Ожидается HTTP `200` и валидный JSON; соответствует `gossopka_official_ok` в отчёте `close_operational_tails.py` и первой smoke-проверке в `release_finalize.py`.

## 4) Audit Engagement API smoke

```powershell
curl -sS -X POST "http://127.0.0.1:8090/audit-engagements" ^
  -H "Content-Type: application/json" ^
  -d "{\"customer\":\"smoke\",\"scope\":\"release smoke\",\"case_ids\":[\"<CASE_ID>\"],\"nda_signed\":true,\"evidence_intake_checklist\":[\"nda\",\"logs\"]}"
curl -sS "http://127.0.0.1:8090/audit-engagements"
curl -sS "http://127.0.0.1:8090/audit-engagements/<ENGAGEMENT_ID>/export/report.json"
```

Сохранить `engagement_id` из ответа `POST /audit-engagements`.

Проверить:

- создание engagement успешно (`engagement_id` выдан);
- `export/report.json` возвращает `format=TAKT Audit Engagement Report`;
- `has_final_report` корректно отражает состояние engagement.

## 5) Ledger verify (SQLite)

```powershell
curl -sS "http://127.0.0.1:8090/cases/<CASE_ID>/audit-ledger/verify"
curl -sS "http://127.0.0.1:8090/audit-ledger/operations/verify?stream_key=decision:<CASE_ID>"
```

Проверить:

- `ok=true` для доступных stream'ов;
- для пустого stream `checked_entries` может быть `0`.

## 6) Metrics (если включено)

```powershell
curl -sS "http://127.0.0.1:8090/metrics"
```

Проверить наличие ключевых метрик:

- `takt_business_risk_score`
- `takt_business_invariant_hits_total`
- `takt_business_dq_degraded_ratio`
- `takt_business_event_to_case_latency_seconds`
- `takt_business_case_merges_total`
