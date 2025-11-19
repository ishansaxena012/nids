import db from "../src/db.js";
import { logger } from "../src/utils.js"; // Assuming you import logger/console

logger.info("Attempting to migrate DB schema to include 'host' column...");

try {
    // 1. Check if the column already exists to prevent runtime crashes on subsequent starts
    const schemaCheck = db.prepare("PRAGMA table_info(alerts);").all();
    const columnExists = schemaCheck.some(col => col.name === 'host');

    if (columnExists) {
        logger.info("Column 'host' already exists in alerts table. Migration skipped.");
    } else {
        // 2. Perform the ALTER TABLE command
        db.exec("ALTER TABLE alerts ADD COLUMN host TEXT;");
        logger.info("Column 'host' added successfully to alerts table. Database updated.");
    }

} catch (e) {
    // Note: If the table doesn't exist at all yet, this might error, 
    // but the db.js initialization handles table creation.
    logger.error({ event: "db_migration_error", error: e.message });
}