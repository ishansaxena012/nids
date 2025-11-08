import db from '../src/db.js'; 

console.log('Connecting to database...');

try {
  // Clear alerts
  const alertInfo = db.prepare('DELETE FROM alerts').run();
  console.log(`Successfully deleted ${alertInfo.changes} alerts.`);

  // Clear audit logs
  const auditInfo = db.prepare('DELETE FROM audit_logs').run();
  console.log(`Successfully deleted ${auditInfo.changes} audit log entries.`);

  // Clear notification queue
  const notificationInfo = db.prepare('DELETE FROM notification_queue').run();
  console.log(`Successfully deleted ${notificationInfo.changes} notification entries.`);

  console.log('\nAll tables cleared.');
} catch (err) {
  console.error('\nError clearing tables:', err.message);
}

db.close();