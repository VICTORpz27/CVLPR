
CREATE TABLE IF NOT EXISTS suggestion_groups (
  id TEXT PRIMARY KEY,
  representative_body TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Autres',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE suggestions
ADD COLUMN group_id TEXT;

CREATE INDEX IF NOT EXISTS suggestions_group_idx
ON suggestions(group_id);
