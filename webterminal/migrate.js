// migrate.js
import sqlite3 from "sqlite3";

const dbPath = "./users.db";
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run("BEGIN TRANSACTION;");

  db.run(`ALTER TABLE users ADD COLUMN uid TEXT;`, (err) => {
    if (err && !err.message.includes("duplicate column name")) {
      console.error("❌ Failed to add uid column:", err.message);
      db.exec("ROLLBACK;");
    } else {
      console.log("✅ uid column added (or already exists).");
      db.run("COMMIT;");
    }
    db.close();
  });
});
