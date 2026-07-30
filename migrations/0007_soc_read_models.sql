-- Итерация 1 (чистая архитектура): read-model проекции и dead-letter store.
-- Денормализованная карточка кейса для быстрого чтения UI (CQRS read side).
CREATE TABLE IF NOT EXISTS case_cards (
  case_id TEXT PRIMARY KEY NOT NULL,
  severity TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  degraded_sources INTEGER NOT NULL DEFAULT 0,
  card_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT ''
);

-- Индекс полнотекстового поиска по событиям (курсорная пагинация по seq).
CREATE TABLE IF NOT EXISTS event_search_index (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  content_hash TEXT NOT NULL,
  case_id TEXT NOT NULL DEFAULT '',
  source_class TEXT NOT NULL DEFAULT '',
  host_id TEXT,
  user_id TEXT,
  address TEXT,
  ts TEXT NOT NULL DEFAULT '',
  haystack TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_event_search_haystack ON event_search_index(haystack);
CREATE INDEX IF NOT EXISTS idx_event_search_case ON event_search_index(case_id);

-- Dead-letter store: изоляция невалидных записей (нарушения инвариантов).
CREATE TABLE IF NOT EXISTS dead_letters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  raw_data TEXT NOT NULL,
  error_type TEXT NOT NULL,
  error_detail TEXT NOT NULL,
  ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dead_letters_ts ON dead_letters(ts);
