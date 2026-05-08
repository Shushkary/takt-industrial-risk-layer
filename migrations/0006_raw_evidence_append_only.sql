ALTER TABLE cases ADD COLUMN raw_evidence_refs TEXT NOT NULL DEFAULT '[]';

CREATE TRIGGER IF NOT EXISTS trg_case_audit_ledger_no_update
  BEFORE UPDATE ON case_audit_ledger
BEGIN
  SELECT RAISE(ABORT, 'case_audit_ledger is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_case_audit_ledger_no_delete
  BEFORE DELETE ON case_audit_ledger
BEGIN
  SELECT RAISE(ABORT, 'case_audit_ledger is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_operation_audit_ledger_no_update
  BEFORE UPDATE ON operation_audit_ledger
BEGIN
  SELECT RAISE(ABORT, 'operation_audit_ledger is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_operation_audit_ledger_no_delete
  BEFORE DELETE ON operation_audit_ledger
BEGIN
  SELECT RAISE(ABORT, 'operation_audit_ledger is append-only');
END;
