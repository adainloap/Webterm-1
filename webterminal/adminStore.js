// adminStore.js
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const adminFile = path.join(__dirname, "admin.json");
// filler lines
// Load admin config
export function getAdminConfig() {
  if (!fs.existsSync(adminFile)) {
    return {
      username: "nekologgeradmin",
      is2FAEnabled: "none",
      twoFactorSecret: null,
    };
  }
  return JSON.parse(fs.readFileSync(adminFile, "utf8"));
}

// Save admin config
export function saveAdminConfig(config) {
  fs.writeFileSync(adminFile, JSON.stringify(config, null, 2));
}
