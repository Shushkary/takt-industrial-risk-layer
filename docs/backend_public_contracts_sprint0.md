# Backend public contracts baseline

Date: 2026-05-20

Sprint 0 freezes the current backend API surface before splitting `src/takt/interface_adapters/api/main.py`.
The machine-checkable baseline is `tests/test_openapi_contract_snapshot.py`.

## Snapshot scope

The snapshot compares every public OpenAPI operation by:

- HTTP method;
- path;
- tag list;
- `200` response schema name, including array item schema names.

The snapshot intentionally does not compare JSON field order.

## First frontend-facing contracts

These endpoints are the first contracts expected by frontend integration and must remain stable during the backend refactor:

- `GET /cases`
- `GET /cases/{case_id}`
- `POST /cases/{case_id}/decision`
- `GET /invariants`
- `GET /topology/demo-graph`
- `GET /compliance/mode`

## Sprint 0 smoke contracts

The Sprint 0 smoke test covers:

- `GET /live`
- `GET /ready`
- `GET /health`
- `GET /invariants`
- `GET /cases`
- `GET /cases/stats`
- `GET /compliance/mode`
- `GET /audit-ledger/operations/verify`
- `GET /topology/demo-graph`
- `GET /cases/{case_id}/forensic-bundle/manifest`
- `GET /cases/{case_id}/forensic-bundle.zip`
- `POST /forensic-bundle/verify`

The baseline preserves the product boundary from `docs/product_boundary.md`: no active equipment control, no PLC commands, no automatic production decision without an operator, and no cryptography in the domain core.
