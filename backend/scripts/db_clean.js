// backend/scripts/db_clean.js

import path from 'path';
import fs from 'fs';

// --- FIXED PATH LOGIC ---
// 1. Determine the path of the current script file (backend/scripts)
const currentDir = path.dirname(new URL(import.meta.url).pathname);

// 2. Adjust process.cwd() base path for Windows compatibility and join 
//    to target the 'backend/data' directory, regardless of where the script is run from.
//    We assume 'data' is always relative to the 'backend' directory.

// For Windows, paths starting with a slash after path.dirname(new URL(...)) must be cleaned up
// but since the original db.js logic uses process.cwd() we adapt that here for consistency, 
// using 'backend/data' relative to the project root.

// We will use a fixed relative path that matches the location confirmed in the logs:
const BASE_DIR = path.join(process.cwd(), 'backend', 'data'); 
const DB_NAME = 'alerts.db';

// Define the file paths based on the correct final location
const dbFileName = path.join(BASE_DIR, DB_NAME);

// --------------------------

const dbFiles = [
    dbFileName,
    dbFileName + '-shm',
    dbFileName + '-wal'
];

console.log(`\n--- Attempting to clean database files located at: ${path.dirname(dbFileName)} ---`);

dbFiles.forEach(filePath => {
    if (fs.existsSync(filePath)) {
        try {
            // Note: On Windows, use path.normalize to handle drive letters if necessary.
            fs.unlinkSync(path.normalize(filePath)); 
            console.log(`✅ Deleted: ${path.basename(filePath)}`);
        } catch (err) {
            console.error(`❌ ERROR: Could not delete ${path.basename(filePath)}. Is the server fully shut down?`, err.message);
        }
    } else {
        console.log(`- File not found: ${path.basename(filePath)}`);
    }
});

console.log('--- Database cleanup complete. ---');