// ====================
// migrate.js
// A simple script to update the database schema (with auto-backup)
// ====================

import sqlite3 from "sqlite3";
import fs from "fs";
import path from "path";

const dbPath = "./users.db";

// Create a backup before migration
function backupDatabase() {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = `./users_backup_${timestamp}.db`;

  fs.copyFileSync(dbPath, backupPath);
  console.log(`🗄️ Backup created at: ${backupPath}`);
}

const db = new sqlite3.Database(dbPath);

function runMigration() {
  backupDatabase();

  db.serialize(() => {
    db.run("BEGIN TRANSACTION;");

    db.run(`ALTER TABLE users RENAME TO users_old;`);

    // Create the new table with the updated schema
    db.run(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        isAdmin INTEGER DEFAULT 0,
        public_ip TEXT,
        private_ip TEXT,
        lastLogin TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is2FAEnabled TEXT DEFAULT 'none',
        twoFactorSecret TEXT,
        webauthnCredentials TEXT,
        email TEXT,
        dob TEXT,
        firstName TEXT,
        lastName TEXT,
        consentGivenAt TEXT,
        parentalConsentGivenAt TEXT,
        parentalSignature TEXT,
        status TEXT DEFAULT 'pending',
        verificationToken TEXT,
        createdAt TEXT,
        email2FACode TEXT,
        email2FACodeExpiry DATETIME,
        resetToken TEXT,
        resetTokenExpiry INTEGER
      );
    `);

    // Copy data over from old table
    db.run(`
      INSERT INTO users (
        id, username, password, isAdmin, public_ip, private_ip, lastLogin,
        is2FAEnabled, twoFactorSecret, webauthnCredentials, email, dob, firstName, lastName,
        consentGivenAt, parentalConsentGivenAt, parentalSignature, status,
        verificationToken, createdAt, resetToken, resetTokenExpiry
      )
      SELECT
        id, username, password, isAdmin, public_ip, private_ip, lastLogin,
        CASE
          WHEN is2FAEnabled = 1 THEN 'authenticator'
          ELSE 'none'
        END,
        twoFactorSecret, webauthnCredentials, email, dob, firstName, lastName,
        consentGivenAt, parentalConsentGivenAt, parentalSignature, status,
        verificationToken, createdAt, resetToken, resetTokenExpiry
      FROM users_old;
    `);

    db.run(`DROP TABLE users_old;`);

    db.run("COMMIT;", (err) => {
      if (err) {
        console.error("❌ Migration failed:", err.message);
        db.exec("ROLLBACK;");
      } else {
        console.log("✅ Database migration complete!");
      }
      db.close();
    });
  });
}

runMigration();
