import db from "../src/db.js";

try {
  db.exec("ALTER TABLE alerts ADD COLUMN host TEXT;");
  console.log("Column 'host' added successfully.");
} catch (e) {
  console.error("Error:", e.message);
}
