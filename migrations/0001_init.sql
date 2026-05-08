CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY NOT NULL,
  status TEXT NOT NULL,
  title TEXT NOT NULL,
  risk_class TEXT NOT NULL,
  risk_score REAL NOT NULL,
  created_at TEXT NOT NULL,
  normalized_event_ids TEXT NOT NULL,
  xai_summary TEXT NOT NULL,
  audit_log TEXT NOT NULL,
  burst_fingerprint TEXT NOT NULL,
  primary_asset_id TEXT NOT NULL,
  trigger_operation TEXT NOT NULL,
  invariant_hits TEXT NOT NULL,
  observations TEXT NOT NULL DEFAULT '[]',
  invariant_hit_records TEXT NOT NULL DEFAULT '[]',
  manual_permits TEXT NOT NULL DEFAULT '[]',
  decision_records TEXT NOT NULL DEFAULT '[]',
  remediation_attempts TEXT NOT NULL DEFAULT '[]',
  dq_score REAL NOT NULL,
  dq_partial INTEGER NOT NULL,
  dq_reasons TEXT NOT NULL,
  last_event_source TEXT NOT NULL,
  pdf_last_sha256 TEXT NOT NULL DEFAULT '',
  pdf_last_generated_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cases_fp_status
  ON cases (burst_fingerprint, status);

CREATE TABLE IF NOT EXISTS expected_behavior (
  asset_id_norm TEXT NOT NULL,
  operation_upper TEXT NOT NULL,
  PRIMARY KEY (asset_id_norm, operation_upper)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  idem_key TEXT PRIMARY KEY NOT NULL,
  body_hash TEXT NOT NULL,
  response_json TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idempotency_expires
  ON idempotency_keys (expires_at);

CREATE TABLE IF NOT EXISTS app_metadata (
  key TEXT PRIMARY KEY NOT NULL,
  value TEXT NOT NULL
);

