# Контракт данных — фикстура INC-002

Схемы совпадают с текущими фикстурами `tests/fixtures/pt_techlab/` (обратная совместимость
импортёров). Дополнение — `nad_sample.ndjson` (PT NAD).

## edr.csv
`timestamp, event_id, hostname, username, process_guid, parent_process_guid, remote_ip, sha256, image_path, event_type, incident_id`
- `event_type`: PROCESS_START | FILE_WRITE
- `remote_ip` может быть пустым.

## siem.csv
`event_time, record_id, device_host, subject_user, src_ip, dst_ip, rule_name, indicator_type, indicator, incident_id`
- Новые `rule_name`: KERBEROS_TGS_RC4, LOGON_SERVICE_ACCOUNT_ANOMALY, REMOTE_EXEC_WMI,
  CODE_REPO_WRITE_OFFHOURS, VULN_SCAN_START.
- `indicator_type`: domain | host | spn | account | repo.

## ndr.csv
`start_time, flow_id, src_host, src_ip, dst_ip, app_protocol, verdict, dns_query, bytes, incident_id`
- Новые `verdict`: C2_SUSPECT, LATERAL_SUSPECT, SCAN_SUSPECT, ALLOWED.
- `app_protocol`: DNS | DoH | HTTPS | SMB | TCP.

## ot.csv (переосмыслен под целостность CI)
`timestamp, event_id, asset_id, src_address, dst_address, protocol, operation, tag, payload_size, incident_id`
- `asset_id`: `artifact:<имя>` | `pipeline:<имя>` (вместо plc-XX).
- `protocol`: CI_PIPELINE.
- `operation`: ARTIFACT_HASH_MISMATCH | UNSIGNED_ARTIFACT_PUSH | BUILD_OK | SIGN_OK | POLL.

## nad_sample.ndjson (PT NAD)
Одно JSON-событие на строку. Поля: `ts, flow_id, src{ip,host}, dst{ip,port}, app_proto,
dns{query,rrtype}?, smb{share,command}?, verdict, bytes, credentials{login,password}?, incident_id`.
- **Безопасность:** `credentials.password` всегда `***REDACTED***` — маскируется
  импортёром `nad_events.py` (REDACTED_FIELDS) до записи в payload.
- `credentials` может быть null.

## Инварианты (проверять тестами)
1. Все `incident_id in {INC-002, BG-ADMIN, BG-SCAN, BG-BACKUP, BACKGROUND}`.
2. Временные метки — ISO 8601 UTC (суффикс Z), файлы отсортированы по времени.
3. Цепочка INC-002 = 27 событий; корреляция должна связать smirnov -> ws-17 ->
   svc_build -> build-srv-01 -> release-prod.
4. Ни одно значение `password` не содержит открытый текст.
5. Генерация детерминирована: `python gen.py`, seed=42, итог 1030 событий
   (edr=531, siem=240, ndr=227, ot=32).
