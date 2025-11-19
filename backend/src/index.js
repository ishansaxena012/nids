import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import db from "./db.js";
import { logger } from "./utils.js";
import { spawn } from "child_process"; 

const PORT = process.env.PORT || 3000;
const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "1mb" }));

// --- CONFIGURATION ---
// Set the device ID determined in our previous analysis (5 for Qualcomm Wi-Fi)
// This should ideally come from .env, but since it's missing, we define it here.
const SENSOR_DEVICE_ID = process.env.SENSOR_DEVICE_ID || '5'; 

// ALERT FUNCTION (Unchanged - already robust)
/**
 * Ingests an alert into the database and enqueues notifications.
 * @param {object} alert - The alert object.
 * @returns {number} The ID of the inserted alert.
 * @throws {Error} if insertion fails.
 */

function ingestAlert(alert) {
  // Validation
  if (!alert.src_ip || !alert.dst_ip) {
    throw new Error("src_ip and dst_ip are required");
  }

  // Database Insert
    const stmt = db.prepare(
    `INSERT INTO alerts (ts, src_ip, dst_ip, proto, rule, rule_id, severity, desc, payload_ref, host)
      VALUES (COALESCE(@ts, CURRENT_TIMESTAMP), @src_ip, @dst_ip, @proto, @rule, @rule_id, @severity, @desc, @payload_ref, @host)`
  );


  const info = stmt.run({
    ts: alert.time || null,
    src_ip: alert.src_ip,
    dst_ip: alert.dst_ip,
    proto: alert.proto || null,
    rule: alert.rule || null,
    rule_id: alert.rule_id || null,
    severity: alert.severity || "medium",
    desc: alert.desc || null,
    payload_ref: alert.payload_ref || null,
    host: alert.host || null, 
  });

  const insertedId = info.lastInsertRowid;
  logger.info({
    event: "alert_ingested",
    id: insertedId,
    src: alert.src_ip,
    dst: alert.dst_ip,
    severity: alert.severity || "medium",
  });

  // Notification Logic
  const sev = (alert.severity || "medium").toLowerCase();
  if (sev === "high" || sev === "critical") {
    const payload = {
      alert_id: insertedId,
      src_ip: alert.src_ip,
      dst_ip: alert.dst_ip,
      proto: alert.proto,
      rule: alert.rule,
      desc: alert.desc,
    };
    const qstmt = db.prepare(
      "INSERT INTO notification_queue (event_type, payload, recipients) VALUES (?, ?, ?)"
    );
    qstmt.run("alert.high", JSON.stringify(payload), null);
    logger.info({ event: "notification_enqueued", alert_id: insertedId });
  }

  return insertedId;
}

// ALERTS ENDPOINTS (Unchanged)
app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/api/alerts", (req, res) => {
  const rows = db
    .prepare("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200")
    .all();
  res.json(rows);
});

// route uses the new ingestAlert function
app.post("/api/alerts", (req, res) => {
  try {
    const insertedId = ingestAlert(req.body);
    return res.status(201).json({ status: "ok", id: insertedId });
  } catch (err) {
    if (err.message.includes("required")) {
      return res.status(400).json({ error: err.message });
    }
    logger.error({ event: "alert_ingest_error", err: err.message });
    return res.status(500).json({ error: "internal_error" });
  }
});

// Pending notifications
app.get("/api/notifications/pending", (req, res) => {
  const rows = db
    .prepare(
      "SELECT * FROM notification_queue WHERE status = 'pending' ORDER BY created_at DESC LIMIT 200"
    )
    .all();
  res.json(rows);
});

// RULES + AUDIT ROUTES (Unchanged)
function computeDiff(oldObj = {}, newObj = {}) {
  const diffs = [];
  const keys = new Set([
    ...Object.keys(oldObj || {}),
    ...Object.keys(newObj || {}),
  ]);
  for (const k of keys) {
    const a =
      oldObj && Object.prototype.hasOwnProperty.call(oldObj, k) ? oldObj[k] : null;
    const b =
      newObj && Object.prototype.hasOwnProperty.call(newObj, k) ? newObj[k] : null;
    const aStr = a === undefined ? null : a;
    const bStr = b === undefined ? null : b;
    if (String(aStr) !== String(bStr)) {
      diffs.push({ field: k, old: aStr, new: bStr });
    }
  }
  return diffs;
}

// List rules
app.get("/api/rules", (req, res) => {
  const rows = db
    .prepare("SELECT * FROM rules ORDER BY updated_at DESC, created_at DESC")
    .all();
  res.json(rows);
});

// Create rule
app.post("/api/rules", (req, res) => {
  try {
    const p = req.body || {};
    if (!p.name || !p.pattern)
      return res.status(400).json({ error: "name & pattern required" });

    const stmt = db.prepare(
      "INSERT INTO rules (name, owner_id, pattern, enabled, notify_on_change) VALUES (?, ?, ?, ?, ?)"
    );
    const info = stmt.run(
      p.name,
      p.owner_id || null,
      p.pattern,
      p.enabled ? 1 : 0,
      p.notify_on_change ? 1 : 0
    );
    const ruleId = info.lastInsertRowid;

    // audit: record creation
    const actorId = p.actor_id || null;
    const diff = JSON.stringify([
      { field: "create", old: null, new: { name: p.name, pattern: p.pattern } },
    ]);
    db.prepare(
      "INSERT INTO audit_logs (actor_id, action, target_type, target_id, diff, metadata) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(
      actorId,
      "rule.create",
      "rule",
      ruleId,
      diff,
      JSON.stringify({ ip: req.ip })
    );

    const rule = db.prepare("SELECT * FROM rules WHERE id = ?").get(ruleId);
    return res.status(201).json(rule);
  } catch (err) {
    logger.error({ event: "rule_create_error", error: err.message });
    return res.status(500).json({ error: "internal" });
  }
});

// Update rule
app.put("/api/rules/:id", (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare("SELECT * FROM rules WHERE id = ?").get(id);
    if (!existing) return res.status(404).json({ error: "not_found" });

    const p = req.body || {};
    const updateStmt = db.prepare(
      "UPDATE rules SET name=@name, owner_id=@owner_id, pattern=@pattern, enabled=@enabled, notify_on_change=@notify_on_change, updated_at = CURRENT_TIMESTAMP WHERE id=@id"
    );
    updateStmt.run({
      id,
      name: p.name ?? existing.name,
      owner_id: p.owner_id ?? existing.owner_id,
      pattern: p.pattern ?? existing.pattern,
      enabled:
        typeof p.enabled === "boolean" ? (p.enabled ? 1 : 0) : existing.enabled,
      notify_on_change:
        typeof p.notify_on_change === "boolean"
          ? p.notify_on_change
            ? 1
            : 0
          : existing.notify_on_change,
    });

    const updated = db.prepare("SELECT * FROM rules WHERE id = ?").get(id);

    // compute diff and write audit
    const diffs = computeDiff(existing, updated);
    db.prepare(
      "INSERT INTO audit_logs (actor_id, action, target_type, target_id, diff, metadata) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(
      p.actor_id || null,
      "rule.update",
      "rule",
      id,
      JSON.stringify(diffs),
      JSON.stringify({ ip: req.ip })
    );

    // enqueue a notification_queue entry (recipients null) if notify_on_change is true
    const notify = existing.notify_on_change || updated.notify_on_change;
    if (notify) {
      const payload = { rule_id: id, rule_name: updated.name, diffs };
      db.prepare(
        "INSERT INTO notification_queue (event_type, payload, recipients) VALUES (?, ?, ?)"
      ).run("rule.changed", JSON.stringify(payload), null);
    }

    return res.json(updated);
  } catch (err) {
    logger.error({ event: "rule_update_error", error: err.message });
    return res.status(500).json({ error: "internal" });
  }
});

// Delete rule
app.delete("/api/rules/:id", (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare("SELECT * FROM rules WHERE id = ?").get(id);
    if (!existing) return res.status(404).json({ error: "not_found" });

    db.prepare("DELETE FROM rules WHERE id = ?").run(id);

    const actorId = req.body && req.body.actor_id ? req.body.actor_id : null;
    const diff = JSON.stringify([{ field: "delete", old: existing, new: null }]);
    db.prepare(
      "INSERT INTO audit_logs (actor_id, action, target_type, target_id, diff, metadata) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(
      actorId,
      "rule.delete",
      "rule",
      id,
      diff,
      JSON.stringify({ ip: req.ip })
    );

    // enqueue notification about deletion (recipients null)
    const payload = { rule_id: id, rule_name: existing.name, deleted: true };
    db.prepare(
      "INSERT INTO notification_queue (event_type, payload, recipients) VALUES (?, ?, ?)"
    ).run("rule.deleted", JSON.stringify(payload), null);

    return res.json({ status: "deleted" });
  } catch (err) {
    logger.error({ event: "rule_delete_error", error: err.message });
    return res.status(500).json({ error: "internal" });
  }
});

// Fetch global audit logs
app.get("/api/audit", (req, res) => {
  const rows = db
    .prepare("SELECT * FROM audit_logs ORDER BY ts DESC LIMIT 500")
    .all();
  res.json(rows);
});

// Fetch audit logs for a specific rule
app.get("/api/rules/:id/audit", (req, res) => {
  const id = Number(req.params.id);
  const rows = db
    .prepare(
      "SELECT * FROM audit_logs WHERE target_type = ? AND target_id = ? ORDER BY ts DESC"
    )
    .all("rule", id);
  res.json(rows);
});

// end RULES + AUDIT ROUTES 

// SENSOR LAUNCHER
// Launches the C++ NIDS sensor as a child process
function launchNIDSSensor() {
  const sensorPath = "../sensor/build/nids_sensor.exe";

  logger.info({ event: "sensor_spawning", path: sensorPath, device_id: SENSOR_DEVICE_ID });

  // 🔹 The sensor needs the device ID as an argument.
  const nidsProcess = spawn(sensorPath, [SENSOR_DEVICE_ID], {
    cwd: process.cwd(),
    shell: false
  });

  // buffer for partial lines from stdout
  let partialSensorOutput = "";

  nidsProcess.stdout.on("data", (data) => {
    partialSensorOutput += data.toString();

    let boundary;
    while ((boundary = partialSensorOutput.indexOf("\n")) !== -1) {
      const line = partialSensorOutput.substring(0, boundary).trim();
      partialSensorOutput = partialSensorOutput.substring(boundary + 1);

      if (!line) continue;

      logger.info({ event: "sensor_data", data: line });
      try {
        const alert = JSON.parse(line);
        ingestAlert(alert);
      } catch (err) {
        logger.error({
          event: "sensor_data_parse_error",
          data: line,
          error: err.message
        });
      }
    }
  });

  nidsProcess.stderr.on("data", (data) => {
    logger.info({ event: "sensor_stderr", output: data.toString() });
  });

  nidsProcess.on("close", (code) => {
    logger.warn({ event: "sensor_exited", code });
    // try to relaunch after a short delay
    setTimeout(launchNIDSSensor, 3000);
  });

  nidsProcess.on("error", (err) => {
    logger.error({ event: "sensor_spawn_error", error: err.message });
  });
}

// UPDATED SERVER START
app.listen(PORT, () => {
  logger.info({ event: "server_start", port: PORT });
  console.log(`✅ Server running at http://localhost:${PORT}`);
  
  // starts your C++ sensor
  launchNIDSSensor();
});