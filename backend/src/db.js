import 'dotenv/config';
import path from 'path';
import Database from 'better-sqlite3';
import fs from 'fs';
import { fileURLToPath } from 'url';

// Resolve __filename and __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Fixed default DB path logic
const defaultDbPath = path.join(__dirname, '..', 'data', 'alerts.db');

const dbPath = process.env.DATABASE_FILE || defaultDbPath;
const dir = path.dirname(dbPath);

// Ensure directory exists
if (!fs.existsSync(dir)) {
  fs.mkdirSync(dir, { recursive: true });
}

// Open DB
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

db.exec(`
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  name TEXT,
  role TEXT DEFAULT 'analyst',
  notify_by_email INTEGER DEFAULT 1,
  notify_preferences TEXT DEFAULT '{}',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  owner_id INTEGER,
  pattern TEXT NOT NULL,
  enabled INTEGER DEFAULT 1,
  notify_on_change INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Trigger to auto-update updated_at on rule changes
CREATE TRIGGER IF NOT EXISTS trg_rules_updated_at
AFTER UPDATE ON rules
FOR EACH ROW
BEGIN
  UPDATE rules SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  src_ip TEXT,
  dst_ip TEXT,
  proto TEXT,
  rule TEXT,
  rule_id INTEGER,
  severity TEXT DEFAULT 'medium',
  desc TEXT,
  payload_ref TEXT,
  host TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER,
  action TEXT,
  target_type TEXT,
  target_id INTEGER,
  diff TEXT,
  metadata TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS notification_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  recipients TEXT,
  status TEXT DEFAULT 'pending',
  attempts INTEGER DEFAULT 0,
  last_error TEXT,
  next_run_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  sent_at DATETIME
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_status ON notification_queue(status, next_run_at);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC);
CREATE INDEX IF NOT EXISTS idx_rules_updated_at ON rules(updated_at DESC);
`);

// Seed admin user if env vars provided
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

if (ADMIN_USERNAME && ADMIN_EMAIL) {
  try {
    const exists = db
      .prepare('SELECT id FROM users WHERE username = ? OR email = ?')
      .get(ADMIN_USERNAME, ADMIN_EMAIL);

    if (!exists) {
      const info = db
        .prepare(
          'INSERT INTO users (username, email, name, role) VALUES (?, ?, ?, ?)'
        )
        .run(ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_USERNAME, 'admin');

      console.log(
        `Seeded admin user id=${info.lastInsertRowid} (${ADMIN_USERNAME})`
      );
    } else {
      console.log('Admin user already exists, skipping seed.');
    }
  } catch (e) {
    console.error('Error seeding admin user:', e.message);
  }
}

export default db;
