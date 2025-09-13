// ====================
// db.js
// ====================
import sqlite3 from "sqlite3";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

// ================================
// Resolve __dirname for ES modules
// ================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ================================
// Connect to SQLite database
// ================================
const db = new sqlite3.Database(join(__dirname, "users.db"), (err) => {
  if (err) {
    console.error("Error opening database", err.message);
  } else {
    console.log("✅ Database connected successfully.");

    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        dob TEXT NOT NULL,
        firstName TEXT NOT NULL,
        lastName TEXT NOT NULL,
        public_ip TEXT,
        private_ip TEXT,
        consentGivenAt TEXT,
        parentalConsentGivenAt TEXT,
        parentalSignature TEXT,
        status TEXT DEFAULT 'offline',
        isAdmin INTEGER DEFAULT 0,
        verificationToken TEXT,
        resetToken TEXT,
        resetTokenExpiry INTEGER,  
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
        dropboxToken TEXT,  -- Dropbox token
        megaFolderLink TEXT -- Personal Mega folder link
      )
    `, (err) => {
      if (err) console.error("Error creating users table:", err.message);
    });

    // Dropbox files table
    db.run(`
      CREATE TABLE IF NOT EXISTS dropbox_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        fileId TEXT NOT NULL,
        fileName TEXT NOT NULL,
        filePath TEXT NOT NULL,
        uploadedAt TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
      )
    `, (err) => {
      if (err) console.error("Error creating dropbox_files table:", err.message);
    });

    // Mega folders table
    db.run(`
      CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        mega_link TEXT NOT NULL,
        is_shared INTEGER DEFAULT 0,
        allowed_user_ids TEXT DEFAULT ''
      )
    `, (err) => {
      if (err) console.error("Error creating folders table:", err.message);
    });
  }
});

export default db;

// ================================
// User-related helpers
// ================================
export function setPublicIP(username, ip) {
  db.run(
    `UPDATE users SET public_ip = ?, status = 'online' WHERE username = ?`,
    [ip, username],
    (err) => {
      if (err) console.error("Failed to update public IP:", err.message);
    }
  );
}

export function setPrivateIP(username, ip) {
  db.run(
    `UPDATE users SET private_ip = ?, status = 'online' WHERE username = ?`,
    [ip, username],
    (err) => {
      if (err) console.error("Failed to update private IP:", err.message);
    }
  );
}

export function setOffline(username) {
  db.run(
    `UPDATE users SET status = 'offline' WHERE username = ?`,
    [username],
    (err) => {
      if (err) console.error("Failed to set user offline:", err.message);
    }
  );
}

export function setAdmin(username, isAdmin = true) {
  db.run(
    `UPDATE users SET isAdmin = ? WHERE username = ?`,
    [isAdmin ? 1 : 0, username],
    (err) => {
      if (err) console.error("Failed to update admin status:", err.message);
    }
  );
}

// ================================
// Dropbox helpers
// ================================
export function setDropboxToken(username, token) {
  db.run(
    `UPDATE users SET dropboxToken = ? WHERE username = ?`,
    [token, username],
    (err) => {
      if (err) console.error("Failed to update Dropbox token:", err.message);
    }
  );
}

export function saveDropboxFileMetadata(userId, fileId, fileName, filePath) {
  db.run(
    `INSERT INTO dropbox_files (userId, fileId, fileName, filePath) VALUES (?, ?, ?, ?)`,
    [userId, fileId, fileName, filePath],
    (err) => {
      if (err) console.error("Error saving Dropbox file metadata:", err.message);
    }
  );
}

export function getDropboxFileByUserAndFileId(userId, fileId, callback) {
  db.get(
    `SELECT * FROM dropbox_files WHERE userId = ? AND fileId = ?`,
    [userId, fileId],
    (err, row) => {
      if (err) console.error("Error retrieving Dropbox file metadata:", err.message);
      callback(err, row);
    }
  );
}

export function getAllDropboxFilesForUser(userId, callback) {
  db.all(
    `SELECT * FROM dropbox_files WHERE userId = ?`,
    [userId],
    (err, rows) => {
      if (err) console.error("Error retrieving Dropbox files for user:", err.message);
      callback(err, rows);
    }
  );
}

// ================================
// Mega.nz folder helpers
// ================================

// Save personal Mega folder link to users table
export function setMegaFolderLink(username, link) {
  db.run(
    `UPDATE users SET megaFolderLink = ? WHERE username = ?`,
    [link, username],
    (err) => {
      if (err) console.error("Failed to update Mega folder link:", err.message);
    }
  );
}

// Create a new folder record (personal or shared)
export function createFolderRecord({ name, owner_id, mega_link, is_shared = 0, allowed_user_ids = "" }) {
  db.run(
    `INSERT INTO folders (name, owner_id, mega_link, is_shared, allowed_user_ids)
     VALUES (?, ?, ?, ?, ?)`,
    [name, owner_id, mega_link, is_shared, allowed_user_ids],
    (err) => {
      if (err) console.error("Failed to insert folder record:", err.message);
    }
  );
}

// Get all folders accessible to a user
export function getFoldersForUser(username, callback) {
  db.all(
    `SELECT * FROM folders 
     WHERE owner_id = ? 
        OR (is_shared = 1 AND (allowed_user_ids LIKE ? OR allowed_user_ids LIKE ? OR allowed_user_ids LIKE ?))`,
    [
      username,
      `${username},%`, // at start
      `%,${username},%`, // in middle
      `%,${username}` // at end
    ],
    (err, rows) => {
      if (err) console.error("Error fetching folders:", err.message);
      callback(err, rows);
    }
  );
}
