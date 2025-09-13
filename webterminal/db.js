// db.js
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import fs from "fs";
import path from "path";
import "dotenv/config";

const adminUser = {
  username: "nekologgeradmin",
  password: "$2b$10$.9ACZ5gn.vJnCVAW8D/7seVbpHx93mWj4WVllJUIIbiMKFRWj1nCC", // bcrypt hash
  email: "admin@webterminal.local",
  dob: "1970-01-01",
  isAdmin: true,
  createdAt: "1970-01-01",
  public_ip: null,
  private_ip: null,
  status: "offline",
};

export let db;
const backupFile = path.join(process.cwd(), "adminsBackup.json");

// Initialize database
export async function initializeDb() {
  db = await open({
    filename: "./users.db",
    driver: sqlite3.Database,
  });

  // --- Users table ---
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      dob TEXT,
      firstName TEXT,
      lastName TEXT,
      public_ip TEXT,
      private_ip TEXT,
      consentGivenAt TEXT,
      parentalConsentGivenAt TEXT,
      parentalSignature TEXT,
      status TEXT,
      verificationToken TEXT,
      createdAt TEXT,
      is2FAEnabled TEXT DEFAULT 'none',
      twoFactorSecret TEXT,
      webauthnCredentials TEXT,
      isAdmin INTEGER DEFAULT 0
    );
  `);

  // --- Folders table ---
  await db.exec(`
    CREATE TABLE IF NOT EXISTS folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id TEXT UNIQUE NOT NULL,
      mega_link TEXT,
      is_shared BOOLEAN,
      FOREIGN KEY(owner_id) REFERENCES users(username)
    );
  `);

  // --- Submissions table (for geolocation/address consent) ---
  await db.exec(`
    CREATE TABLE IF NOT EXISTS submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      method TEXT,
      coords TEXT,
      address TEXT,
      ts TEXT NOT NULL,
      user_id INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  // Restore admins from backup if exists
  let backupAdmins = [];
  if (fs.existsSync(backupFile)) {
    try {
      const raw = fs.readFileSync(backupFile, "utf-8");
      backupAdmins = JSON.parse(raw);
    } catch (err) {
      console.error("Failed to read admins backup:", err.message);
    }
  }

  // Ensure main admin exists
  const adminExists = await db.get(
    `SELECT * FROM users WHERE username = ?`,
    [adminUser.username]
  );
  if (!adminExists) {
    console.log("Admin user does not exist. Creating now...");
    await db.run(
      `INSERT INTO users 
        (username, password, email, dob, firstName, lastName, public_ip, private_ip, status, isAdmin, is2FAEnabled, twoFactorSecret, createdAt) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        adminUser.username,
        adminUser.password,
        adminUser.email,
        adminUser.dob,
        "Admin",
        "User",
        null,
        null,
        "active",
        1,
        adminUser.is2FAEnabled || "none",
        adminUser.twoFactorSecret || null,
        adminUser.createdAt,
      ]
    );
    console.log("✅ Admin user created successfully.");
  }

  // Restore other admins from backup
  for (const admin of backupAdmins) {
    const exists = await db.get(
      `SELECT * FROM users WHERE username = ?`,
      [admin.username]
    );
    if (!exists) {
      await db.run(
        `INSERT INTO users 
          (username, password, email, dob, firstName, lastName, status, isAdmin, is2FAEnabled, twoFactorSecret, createdAt) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          admin.username,
          admin.password,
          admin.email,
          admin.dob || "1970-01-01",
          admin.firstName || "Admin",
          admin.lastName || "User",
          admin.status || "offline",
          1,
          admin.is2FAEnabled || "none",
          admin.twoFactorSecret || null,
          admin.createdAt || "1970-01-01",
        ]
      );
      console.log(`✅ Restored admin ${admin.username} from backup`);
    } else {
      // Update 2FA if missing
      if (!exists.is2FAEnabled) {
        await db.run(
          `UPDATE users SET is2FAEnabled = ?, twoFactorSecret = ? WHERE username = ?`,
          [
            admin.is2FAEnabled || "none",
            admin.twoFactorSecret || null,
            admin.username,
          ]
        );
        console.log(`🔄 Updated 2FA for admin ${admin.username}`);
      }
    }
  }
}

// Save all admins to backup file
export async function saveAdminsBackup() {
  try {
    const admins = await db.all(
      `SELECT username, password, email, dob, firstName, lastName, status, is2FAEnabled, twoFactorSecret, createdAt 
       FROM users WHERE isAdmin = 1`
    );
    fs.writeFileSync(backupFile, JSON.stringify(admins, null, 2), "utf-8");
    console.log("✅ Admins backup saved.");
  } catch (err) {
    console.error("Failed to save admins backup:", err.message);
  }
}

// --- User helpers ---
export async function findUser(username) {
  return db.get(`SELECT * FROM users WHERE username = ?`, [username]);
}

export async function findUserByEmail(email) {
  return db.get(`SELECT * FROM users WHERE email = ?`, [email]);
}

export async function setPublicIP(username, ip) {
  await db.run(`UPDATE users SET public_ip = ? WHERE username = ?`, [
    ip,
    username,
  ]);
}

export async function setPrivateIP(username, ip) {
  await db.run(`UPDATE users SET private_ip = ? WHERE username = ?`, [
    ip,
    username,
  ]);
}

export async function setAdmin(username) {
  await db.run(`UPDATE users SET isAdmin = 1 WHERE username = ?`, [username]);
}

export async function saveAdminSettings(
  username,
  is2FAEnabled,
  twoFactorSecret
) {
  try {
    const admin = await db.get(
      `SELECT * FROM users WHERE username = ? AND isAdmin = 1`,
      [username]
    );
    if (admin) {
      await db.run(
        `UPDATE users SET is2FAEnabled = ?, twoFactorSecret = ? WHERE username = ?`,
        [is2FAEnabled, twoFactorSecret, username]
      );
      await saveAdminsBackup();
    }
  } catch (err) {
    console.error(
      `Failed to save settings for admin ${username}:`,
      err.message
    );
  }
}

// --- Submissions helpers ---
export async function saveSubmission({
  method,
  coords,
  address,
  ts,
  user_id = null,
}) {
  await db.run(
    `INSERT INTO submissions (method, coords, address, ts, user_id) VALUES (?, ?, ?, ?, ?)`,
    [method, coords ? JSON.stringify(coords) : null, address || null, ts, user_id]
  );
}

export async function getAllSubmissions() {
  return db.all(`SELECT * FROM submissions ORDER BY ts DESC`);
}

export async function deleteSubmission(id) {
  return db.run(`DELETE FROM submissions WHERE id = ?`, [id]);
}

export async function clearSubmissions() {
  return db.run(`DELETE FROM submissions`);
}
