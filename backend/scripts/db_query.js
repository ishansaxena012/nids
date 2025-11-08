// just for logging purpose
import db from "../src/db.js";

// recent rules
const rules = db
  .prepare(
    "SELECT id, name, pattern, enabled, created_at, updated_at FROM rules ORDER BY updated_at DESC LIMIT 10"
  )
  .all();

console.log("---- Rules ----");
console.log(rules);

// recent alerts
const alerts = db
  .prepare(
    "SELECT id, src_ip, dst_ip, proto, severity, created_at FROM alerts ORDER BY created_at DESC LIMIT 10"
  )
  .all();

console.log("---- Alerts ----");
console.log(alerts);

//  pending notifications
const notifs = db
  .prepare(
    "SELECT id, event_type, status, attempts, last_error, created_at FROM notification_queue ORDER BY created_at DESC LIMIT 10"
  )
  .all();

console.log("---- Notifications ----");
console.log(notifs);

// recent audit logs
const audits = db
  .prepare(
    "SELECT id, action, target_type, target_id, ts FROM audit_logs ORDER BY ts DESC LIMIT 10"
  )
  .all();

console.log("---- Audit Logs ----");
console.log(audits);
