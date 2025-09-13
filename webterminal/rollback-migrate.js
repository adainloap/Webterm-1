// ====================
// rollback-migrate.js
// Reverts the last migration if something went wrong (with auto-backup)
// ====================

import sqlite3 from "sqlite3";
import fs from "fs";

const dbPath = "./users.db";

// Create a backup before rollback
function backupDatabase() {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = `./users_rollback_backup_${timestamp}.db`;

  fs.copyFileSync(dbPath, backupPath);
  console.log(`🗄️ Rollback backup created at: ${backupPath}`);
}

const db = new sqlite3.Database(dbPath);

function rollbackMigration() {
  backupDatabase();

  db.serialize(() => {
    db.run("BEGIN TRANSACTION;");

    // Check if users_old still exists
    db.get(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='users_old';",
      (err, row) => {
        if (err) {
          console.error("❌ Error checking tables:", err.message);
          db.exec("ROLLBACK;");
          db.close();
          return;
        }

        if (!row) {
          console.error(
            "⚠️ No 'users_old' table found. Rollback not possible."
          );
          db.exec("ROLLBACK;");
          db.close();
          return;
        }

        // Rename current (migrated) users table
        db.run("ALTER TABLE users RENAME TO users_new;");

        // Restore old table
        db.run("ALTER TABLE users_old RENAME TO users;");

        // Drop the migrated table
        db.run("DROP TABLE users_new;");

        db.run("COMMIT;", (err) => {
          if (err) {
            console.error("❌ Rollback failed:", err.message);
            db.exec("ROLLBACK;");
          } else {
            console.log("✅ Rollback complete. Old schema restored!");
          }
          db.close();
        });
      }
    );
  });
}

rollbackMigration();
