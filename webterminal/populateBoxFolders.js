// ================================
// populateBoxFolders.js
// ================================
import db from './db.js';
import { createUserFolder } from './boxService.js';

// ================================
// Main
// ================================
async function main() {
  try {
    console.log("✅ Database is ready.");

    // THE FIX: Select the user's email in addition to their username.
    const users = await new Promise((resolve, reject) => {
      db.all("SELECT id, username, email FROM users", (err, rows) => {
        if (err) {
          return reject(err);
        }
        resolve(rows || []);
      });
    });

    console.log(`Found ${users.length} users to process.`);

    for (const user of users) {
      console.log(`\nProcessing user: ${user.username}`);
      try {
        // THE FIX: Pass the user's email to the function so it can send the invitation.
        const folder = await createUserFolder(user.username, user.email);

        if (folder) {
          console.log(`✅ Successfully processed folder for ${user.username}`);
        } else {
          console.error(`❌ Failed to process folder for ${user.username}. See previous error.`);
        }
      } catch (err) {
        console.error(`❌ An unexpected error occurred for ${user.username}:`, err.message);
      }
    }

    console.log("\n🎉 Finished populating folders.");
  } catch (err) {
    console.error("❌ A fatal error occurred during the process:", err);
    process.exit(1);
  } finally {
    // It's good practice to close the database connection when the script is done.
    if (db) {
      db.close();
      console.log("Database connection closed.");
    }
  }
}

main();

