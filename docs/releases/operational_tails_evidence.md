# Operational tails evidence (20260507T135527Z)

## Inputs
- db_path: `dist/ops-tail-test.sqlite`
- apply_migrate: `true`

## Actions
- backup_created: `dist/ops-tail-test.backup.20260507T135527Z.sqlite`
- migrate_executed: `true`
- smoke_db_created: `dist/ops-tail-test.smoke.20260507T135527Z.sqlite`

## Ledger verify
- case_ledger: `{'ok': True, 'checked_entries': 0, 'issue': ''}`
- operation_ledger: `{'ok': True, 'checked_entries': 0, 'issue': ''}`

## API smoke
- smoke_result: `{'health_status_code': 200, 'assess_status_code': 200, 'case_id': '1ab34dc3', 'forensic_verify_ok': True, 'forensic_signing_unavailable': False, 'gossopka_official_ok': True, 'audit_engagement_api_ok': True}`

## Ready-to-copy fields
- backup_path: `dist/ops-tail-test.backup.20260507T135527Z.sqlite`
- migrate_done: `true`
- smoke_case_id: `1ab34dc3`
- forensic_verify_ok: `true`
- forensic_signing_unavailable: `false`
- gossopka_official_ok: `true`
- audit_engagement_api_ok: `true`
