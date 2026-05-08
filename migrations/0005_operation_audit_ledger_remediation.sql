ALTER TABLE cases ADD COLUMN remediation_attempts TEXT NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS operation_audit_ledger (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  stream_key TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  prev_chain_sha256 TEXT NOT NULL,
  chain_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operation_audit_stream_seq
  ON operation_audit_ledger (stream_key, seq);

