CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('superadmin','admin','member','reader')), active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS suggestions (id TEXT PRIMARY KEY, body TEXT NOT NULL, firstname TEXT, lastname TEXT, class_name TEXT, category TEXT NOT NULL DEFAULT 'À vérifier', moderation TEXT NOT NULL DEFAULT 'pending' CHECK(moderation IN ('pending','approved','spam','duplicate','review')), workflow TEXT NOT NULL DEFAULT 'new', fingerprint TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS suggestions_status_idx ON suggestions(moderation,created_at);
CREATE INDEX IF NOT EXISTS suggestions_fingerprint_idx ON suggestions(fingerprint,created_at);
CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, user_id TEXT, action TEXT NOT NULL, target_id TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
