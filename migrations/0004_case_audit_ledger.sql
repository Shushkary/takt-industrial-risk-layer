CREATE TABLE IF NOT EXISTS case_audit_ledger (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  audit_line TEXT NOT NULL,
  line_sha256 TEXT NOT NULL,
  prev_chain_sha256 TEXT NOT NULL,
  chain_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_case_audit_ledger_case_seq
  ON case_audit_ledger (case_id, seq);

