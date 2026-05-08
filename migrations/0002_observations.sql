ALTER TABLE cases ADD COLUMN observations TEXT NOT NULL DEFAULT '[]';
ALTER TABLE cases ADD COLUMN invariant_hit_records TEXT NOT NULL DEFAULT '[]';

