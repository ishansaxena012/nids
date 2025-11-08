// just for logging purpose
import db from '../src/db.js';

const deleted = db.prepare("DELETE FROM notification_queue WHERE last_error LIKE '%EmailJS%'").run();
console.log('Deleted rows:', deleted.changes);
