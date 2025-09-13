// ====================
// db.js
// ====================
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// This promise will resolve with the database instance once it's ready.
const dbPromise = (async () => {
  try {
    const db = await open({
      filename: join(__dirname, "users.db"),
      driver: sqlite3.Database,
    });
    console.log("✅ Database connected successfully.");

    // ============================================
    // Initialize Users Table
    // ============================================
    await db.exec(`
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
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // ============================================
    // Initialize Folders Table (as required by megaService.js)
    // ============================================
    await db.exec(`
      CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        mega_link TEXT,
        is_shared INTEGER DEFAULT 0,
        allowed_user_ids TEXT,
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("✅ Tables initialized successfully.");
    return db;
  } catch (err) {
    console.error("❌ Error opening or initializing database", err.message);
    process.exit(1); // Exit if DB connection fails
  }
})();

// Export the resolved db connection
export default await dbPromise;

// ================================
// User Helper Functions (Promise-based)
// ================================
export async function setPublicIP(username, ip) {
  const db = await dbPromise;
  return db.run(
    `UPDATE users SET public_ip = ?, status = 'online' WHERE username = ?`,
    [ip, username]
  );
}

export async function setPrivateIP(username, ip) {
  const db = await dbPromise;
  return db.run(
    `UPDATE users SET private_ip = ?, status = 'online' WHERE username = ?`,
    [ip, username]
  );
}

export async function setOffline(username) {
  const db = await dbPromise;
  return db.run(
    `UPDATE users SET status = 'offline' WHERE username = ?`,
    [username]
  );
}

export async function setAdmin(username, isAdmin = true) {
  const db = await dbPromise;
  return db.run(
    `UPDATE users SET isAdmin = ? WHERE username = ?`,
    [isAdmin ? 1 : 0, username]
  );
}

// ================================
// Folder Helper Functions (Promise-based for megaService.js)
// ================================
export async function createFolderRecord(folderData) {
  const db = await dbPromise;
  const { name, owner_id, mega_link, is_shared } = folderData;
  const result = await db.run(
    `INSERT INTO folders (name, owner_id, mega_link, is_shared) VALUES (?, ?, ?, ?)`,
    [name, owner_id, mega_link, is_shared]
  );
  return result.lastID; // Return the ID of the new folder record
}

// This function is now redundant because createFolderRecord handles it.
// Kept for reference or if you have other scripts using it.
export async function setMegaFolderLink(username, link) {
    const db = await dbPromise;
    // This updates the personal folder link for a user in the folders table.
    return db.run(
        `UPDATE folders SET mega_link = ? WHERE owner_id = ? AND is_shared = 0 AND name = ?`,
        [link, username, username]
    );
}

export async function getFoldersForUser(username) {
  const db = await dbPromise;
  // A user can access folders they own OR folders they are allowed to see.
  return db.all(
    `SELECT * FROM folders WHERE owner_id = ? OR (is_shared = 1 AND allowed_user_ids LIKE '%' || ? || '%')`,
    [username, username]
  );
}
