// ====================
// server.js
// ====================

// ====================
// Import dependencies
// ====================
import express from "express";
import session from "express-session";
import cors from "cors";
import bcrypt from "bcryptjs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import fs from "fs";
import http from "http";
import { Server } from "socket.io";
import { Server as SocketIO } from 'socket.io';
import pty from "node-pty";
import { db, findUser, setPublicIP, setPrivateIP, setAdmin, initializeDb } from "./db.js";
import { setOnline, setOffline, isOnline, getOnlineUsers } from "./userStatus.js";
import crypto from "crypto";
import "dotenv/config";
import Mailjet from "node-mailjet";
import os from "os";
import fetch from "node-fetch";
import multer from "multer";
import https from "https";
import { createUserFolder } from "./boxService.js";
import QRCode from "qrcode";
import speakeasy from "speakeasy"; // For generating 2FA secrets
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import path from "path";
// ==========================
// Resolve __dirname for ES
// ==========================
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// ====================
// App & Socket setup
// ====================
const app = express();
app.set("trust proxy", 1);
app.use(express.static(path.join(__dirname, "public")));
const server = http.createServer(app);
const io = new Server(server);

// ====================
// Middleware
// ====================
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);

// ====================
// Session middleware
// ====================
const sessionMiddleware = session({
  secret: "nekologger-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    maxAge: 24 * 60 * 60 * 1000,
  },
});
app.use(sessionMiddleware);

// ====================
// Views
// ====================
app.set("views", join(__dirname, "views"));
app.set("view engine", "ejs");

// ====================
// Mailjet client
// ====================
const mailjet = Mailjet.apiConnect(
  process.env.MAILJET_USER,
  process.env.MAILJET_PASS
);

// ====================
// WebAuthn configuration
// ====================
const rpName = "WebTerminal";
const rpID = process.env.APP_URL.replace(/https?:\/\//, "").replace(/:\d+/, "");

// ====================
// Admin user config
// ====================
const adminUser = {
  username: "nekologgeradmin",
  password: "$2b$10$.9ACZ5gn.vJnCVAW8D/7seVbpHx93mWj4WVllJUIIbiMKFRWj1nCC",
  email: "admin@webterminal.local",
  dob: "1970-01-01",
  isAdmin: true,
  createdAt: "1970-01-01",
  public_ip: null,
  private_ip: null,
  status: "offline",
};

// ====================
// Failed login tracking
// ====================
const failedAttempts = new Map();
const FAILED_MAX = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function recordFailedAttempt(key) {
  const entry = failedAttempts.get(key) || { count: 0, firstAttempt: Date.now() };
  entry.count++;
  failedAttempts.set(key, entry);
}

function clearFailedAttempts(key) {
  failedAttempts.delete(key);
}

function isLockedOut(key) {
  const entry = failedAttempts.get(key);
  if (!entry) return false;
  if (entry.count >= FAILED_MAX) {
    if (Date.now() - entry.firstAttempt < LOCKOUT_MS) return true;
    failedAttempts.delete(key);
  }
  return false;
}

// ====================
// Utility: IP detection
// ====================
export function getPrivateIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) return iface.address;
    }
  }
  return "IP not found";
}

async function getPublicIP() {
  try {
    const res = await fetch("https://api.ipify.org?format=json");
    const data = await res.json();
    return data.ip;
  } catch {
    return "Unknown";
  }
}

function getClientIP(req) {
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}

// ====================
// ROUTES
// ====================
app.get("/", (req, res) => {
  if (req.session?.user) {
    return res.redirect("/terminal");
  }
  res.redirect("/login");
});
// --- Login ---
app.get("/login", (req, res) => res.render("login", { error: null, message: null }));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const lockKey = username;
  if (isLockedOut(lockKey)) return res.render("login", { error: "Too many failed attempts", message: null });

  const clientPublicIP = getClientIP(req);
  const serverPrivateIP = getPrivateIP();

  // Admin login
  if (username === adminUser.username) {
    if (!bcrypt.compareSync(password, adminUser.password)) {
      recordFailedAttempt(lockKey);
      return res.render("login", { error: "Invalid credentials", message: null });
    }
    clearFailedAttempts(lockKey);

    const user = await findUser(adminUser.username);
    if (!user) {
      return res.render("login", { error: "Admin user not found in database.", message: null });
    }

    if (user.is2FAEnabled === 'none') {
      const secret = speakeasy.generateSecret({
        name: 'WebTerminal:Admin',
      });
      req.session.twoFactorSecret = secret.base32;
      req.session.userToVerify = user;
      return res.redirect("/2fa-login-admin");
    }

    req.session.userToVerify = user;
    return res.redirect("/2fa-login-admin");
  }

  // Regular user login
  const user = await findUser(username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    recordFailedAttempt(lockKey);
    return res.render("login", { error: "Invalid credentials", message: null });
  }

  if (user.status === "pending") {
    return res.render("login", { error: "Account not verified.", message: null });
  }

  clearFailedAttempts(lockKey);

  if (user.is2FAEnabled !== 'none') {
    req.session.userToVerify = user;
    req.session.twoFactorMethod = user.is2FAEnabled;
    return res.redirect("/2fa-login");
  }

  user.isAdmin = !!user.isAdmin;
  user.public_ip = clientPublicIP;
  user.private_ip = getPrivateIP();
  user.status = "online";

  req.session.user = user;
  req.session.is2faVerified = true;

  setPublicIP(user.username, clientPublicIP);
  setPrivateIP(user.username, user.private_ip);

  req.session.save(() => {
    io.emit("user_update", { username: user.username, status: "online", public_ip: clientPublicIP, private_ip: user.private_ip });
    res.redirect("/terminal");
  });
});

// --- Register ---
app.get("/register", (req, res) => res.render("register", { error: null }));

// CORRECTED AND INTEGRATED REGISTRATION ROUTE
app.post("/register", async (req, res) => {
  const { user_reg, pass_reg, email_reg, first_name_reg, last_name_reg, parentEmail, "dob-day": dobDay, "dob-month": dobMonth, "dob-year": dobYear } = req.body;
  const dob = `${dobYear}-${dobMonth}-${dobDay}`;
  if (!user_reg || !pass_reg || !email_reg || !dob || !first_name_reg || !last_name_reg) {
    return res.render("register", { error: "All fields are required" });
  }

  const birthDate = new Date(dob);
  const thirteenYearsAgo = new Date();
  thirteenYearsAgo.setFullYear(thirteenYearsAgo.getFullYear() - 13);
  const isUnder13 = birthDate > thirteenYearsAgo;
  if (isUnder13 && !parentEmail) {
    return res.render("register", { error: "Parent's email required for under 13" });
  }

  const recipientEmail = isUnder13 ? parentEmail : email_reg;
  const templateID = isUnder13 ? 7274421 : 7273798;
  const userIP = getClientIP(req);
  const privateIP = getPrivateIP();
  const createdAt = new Date().toISOString();

  try {
    const existingUser = await db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [user_reg, email_reg]);
    if (existingUser) {
      return res.render("register", { error: "Username or email already exists" });
    }

    const hashedPassword = bcrypt.hashSync(pass_reg, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const consentGivenAt = new Date().toISOString();
    const parentalConsentTimestamp = req.body.parentalConsent ? new Date().toISOString() : null;
    const parentSignature = req.body.parentSignature || null;

    const sql = `INSERT INTO users
      (username, password, email, dob, firstName, lastName, public_ip, private_ip, consentGivenAt, parentalConsentGivenAt, parentalSignature, status, verificationToken, createdAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`;
    const params = [user_reg, hashedPassword, email_reg, dob, first_name_reg, last_name_reg, userIP, privateIP, consentGivenAt, parentalConsentTimestamp, parentSignature, verificationToken, createdAt];

    await db.run(sql, params);

    try {
      const folder = await createUserFolder(user_reg, email_reg);
      if (folder) {
        console.log(`✅ Automatically created Box folder and invited new user: ${user_reg}`);
      } else {
        console.warn(`⚠️ Could not create Box folder for ${user_reg}. This is not a critical error.`);
      }
    } catch (boxError) {
      console.error("Box.com error during registration:", boxError.message);
    }

    const verificationLink = `${process.env.APP_URL}/verify?token=${verificationToken}`;
    const mailSubject = isUnder13 ? "Parental Consent Required" : "Verify Your Email Address";

    await mailjet.post("send", { version: "v3.1" }).request({
      Messages: [{
        From: { Email: "kinvilladam134@outlook.com", Name: "WebTerm" },
        To: [{ Email: recipientEmail, Name: first_name_reg }],
        TemplateID: templateID,
        TemplateLanguage: true,
        Subject: mailSubject,
        Variables: { username: user_reg, verification_link: verificationLink }
      }]
    });

    res.render("check-email", {
      email: recipientEmail,
      under13: isUnder13
    });

  } catch (err) {
    console.error("Registration Error:", err);
    if (err.message.includes("Mailjet")) {
        return res.render("register", { error: "Could not send verification email." });
    }
    return res.render("register", { error: "Could not create account due to a database error." });
  }
});

// --- Resend Verification Email ---
app.post("/resend-verification", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.render("resend-verification", { error: "Email is required" });
  }

  try {
    // Find the user
    const user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
    if (!user) {
      return res.render("resend-verification", { error: "No account found with that email." });
    }

    if (user.status === "active") {
      return res.render("resend-verification", { error: "Account is already verified. Please log in." });
    }

    // Generate new token
    const newToken = crypto.randomBytes(32).toString("hex");

    await db.run(
      `UPDATE users SET verificationToken = ? WHERE email = ?`,
      [newToken, email]
    );

    // Build verification link
    const verificationLink = `${process.env.APP_URL}/verify?token=${newToken}`;

    // Send email
    await mailjet.post("send", { version: "v3.1" }).request({
      Messages: [{
        From: { Email: "kinvilladam134@outlook.com", Name: "WebTerm" },
        To: [{ Email: email, Name: user.firstName || user.username }],
        TemplateID: 7273798, // use the verified template
        TemplateLanguage: true,
        Subject: "Resend: Verify Your Email Address",
        Variables: { username: user.username, verification_link: verificationLink }
      }]
    });

    res.render("check-email", { email, under13: false });

  } catch (err) {
    console.error("Resend Verification Error:", err);
    res.render("resend-verification", { error: "Could not resend verification email." });
  }
});


// --- Verify ---
app.get("/verify", async (req, res) => {
  const { token } = req.query;

  if (!token) {
    console.warn("⚠️ Verification attempt without token");
    return res.render("verified", { message: "No verification token provided.", email: null });
  }

  try {
    const user = await db.get(`SELECT * FROM users WHERE verificationToken = ?`, [token]);

    if (!user) {
      console.warn("⚠️ Invalid or already used verification token:", token);
      return res.render("verified", {
        message: "Invalid or expired verification token.",
        email: null
      });
    }

    await db.run(
      `UPDATE users SET status = 'active', verificationToken = NULL WHERE username = ?`,
      [user.username]
    );

    console.log("✅ User successfully verified:", user.username);
    return res.render("verified", {
      message: "Your account has been successfully verified. You can now log in.",
      email: user.email
    });

  } catch (err) {
    console.error("❌ Database error during verification:", err.message);
    return res.render("verified", {
      message: "Something went wrong during verification. Please try again later.",
      email: null
    });
  }
});


// ===========================================
// NEW: 2FA ROUTES
// ===========================================

// --- 2FA Login Page (for users with 2FA enabled) ---
app.get("/2fa-login", (req, res) => {
  if (req.session.user?.isAdmin || !req.session.userToVerify) {
    return res.redirect("/login");
  }
  const twoFactorMethod = req.session.userToVerify.is2FAEnabled;
  res.render("2fa-login", { error: null, twoFactorMethod });
});

// --- Unified Admin 2FA Page ---
app.get("/2fa-login-admin", async (req, res) => {
  if (!req.session.userToVerify?.isAdmin) {
    return res.redirect("/login");
  }

  if (req.session.twoFactorSecret) {
    const secret = req.session.twoFactorSecret;

    // Build otpauth URL
    const otpauthUrl = speakeasy.otpauthURL({
      secret,
      label: "WebTerminal:Admin",
      issuer: "WebTerminal",
    });

    // Generate QR code image as a data URL
    const qrCodeURL = await QRCode.toDataURL(otpauthUrl);

    res.render("2fa-login-admin", {
      error: null,
      secret,
      qrCodeURL, // now an inline image (data URI)
    });
  } else {
    res.render("2fa-login-admin", { error: null, secret: null, qrCodeURL: null });
  }
});


// --- 2FA Login POST (Authenticator App) ---
app.post("/2fa-login", (req, res) => {
  if (req.session.user?.isAdmin) {
    return res.redirect("/terminal");
  }
  const { token } = req.body;
  const user = req.session.userToVerify;

  if (!user) {
    return res.redirect("/login");
  }

  const isVerified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: "base32",
    token: token,
  });

  if (isVerified) {
    req.session.user = user;
    req.session.is2faVerified = true;
    delete req.session.userToVerify;
    delete req.session.twoFactorMethod;
    req.session.save(() => {
      io.emit("user_update", { username: user.username, status: "online", public_ip: user.public_ip, private_ip: user.private_ip });
      res.redirect("/terminal");
    });
  } else {
    res.render("2fa-login", { error: "Invalid 2FA code." });
  }
});

// --- Unified Admin 2FA Post ---
app.post("/2fa-login-admin", async (req, res) => {
  const { token } = req.body;
  const user = req.session.userToVerify;
  let secret = req.session.twoFactorSecret;

  if (!user || !user.isAdmin) {
    return res.redirect("/login");
  }

  if (!secret) {
    const adminFromDb = await findUser(user.username);
    secret = adminFromDb.twoFactorSecret;
  }

  const isVerified = speakeasy.totp.verify({
    secret: secret,
    encoding: "base32",
    token: token,
  });

  if (isVerified) {
    if (req.session.twoFactorSecret) {
      await db.run(
        `UPDATE users SET is2FAEnabled = 'authenticator', twoFactorSecret = ? WHERE username = ?`,
        [secret, user.username]
      );
    }

    req.session.user = user;
    req.session.is2faVerified = true;
    delete req.session.userToVerify;
    delete req.session.twoFactorSecret;
    req.session.save(() => {
      io.emit("user_update", { username: user.username, status: "online", public_ip: user.public_ip, private_ip: user.private_ip });
      res.redirect("/terminal");
    });
  } else {
    const qrCodeURL = req.session.twoFactorSecret ? 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' + encodeURIComponent(speakeasy.otpauthURL({ secret: secret, label: 'WebTerminal:Admin', issuer: 'WebTerminal' })) : null;
    res.render("2fa-login-admin", {
      error: "Invalid 2FA code.",
      secret: req.session.twoFactorSecret,
      qrCodeURL,
    });
  }
});


// --- NEW: Send 2FA Code via Email ---
app.post("/2fa-send-email-code", async (req, res) => {
  if (req.session.user?.isAdmin) {
    return res.status(200).send("Admin user does not require 2FA.");
  }
  const user = req.session.userToVerify;
  if (!user) return res.status(401).send("Unauthorized");

  const emailCode = Math.floor(100000 + Math.random() * 900000).toString();
  const emailCodeExpiry = Date.now() + 5 * 60 * 1000;

  req.session.email2FACode = emailCode;
  req.session.email2FACodeExpiry = emailCodeExpiry;
  await req.session.save();

  try {
    await mailjet.post("send", { version: "v3.1" }).request({
      Messages: [{
        From: { Email: "kinvilladam134@outlook.com", Name: "WebTerm" },
        To: [{ Email: user.email, Name: user.firstName }],
        TemplateID: 7274583,
        TemplateLanguage: true,
        Subject: "Your 2FA Login Code",
        Variables: {
          username: user.username,
          verification_link: emailCode
        }
      }]
    });
    res.status(200).send("Code sent to your email.");
  } catch (mailError) {
    console.error("Mailjet Error:", mailError);
    res.status(500).send("Could not send the email code.");
  }
});

// --- NEW: Verify 2FA Code from Email ---
app.post("/2fa-verify-email", (req, res) => {
  if (req.session.user?.isAdmin) {
    return res.redirect("/terminal");
  }
  const { emailToken } = req.body;
  const user = req.session.userToVerify;

  if (!user || !req.session.email2FACode || !req.session.email2FACodeExpiry) {
    return res.render("2fa-login", { error: "Session expired. Please try again." });
  }

  if (Date.now() > req.session.email2FACodeExpiry) {
    req.session.email2FACode = null;
    req.session.email2FACodeExpiry = null;
    return res.render("2fa-login", { error: "Code expired. Please request a new one." });
  }

  if (emailToken === req.session.email2FACode) {
    req.session.user = user;
    req.session.is2faVerified = true;
    delete req.session.userToVerify;
    delete req.session.twoFactorMethod;
    delete req.session.email2FACode;
    delete req.session.email2FACodeExpiry;

    req.session.save(() => {
      io.emit("user_update", { username: user.username, status: "online", public_ip: user.public_ip, private_ip: user.private_ip });
      res.redirect("/terminal");
    });
  } else {
    res.render("2fa-login", { error: "Invalid email code." });
  }
});

// --- 2FA Setup Page ---
app.get("/setup-2fa", async (req, res) => {
  if (!req.session.user || req.session.user?.isAdmin) {
    return res.redirect("/login");
  }

  const userFromDb = await findUser(req.session.user.username);
  if (!userFromDb) {
    return res.status(404).send("User not found.");
  }

  if (userFromDb.is2FAEnabled !== "none") {
    return res.send("2FA is already enabled for this account.");
  }

  const secret = speakeasy.generateSecret({
    name: "WebTerminal:" + userFromDb.username,
  });

  req.session.twoFactorSecret = secret.base32;

  // Build otpauth URL
  const otpauthUrl = speakeasy.otpauthURL({
    secret: secret.base32,
    label: "WebTerminal:" + userFromDb.username,
    issuer: "WebTerminal",
  });

  // Generate QR code as a data URI
  const qrCodeURL = await QRCode.toDataURL(otpauthUrl);

  res.render("setup-2fa", {
    qrCodeURL,
    secret: secret.base32,
    error: null,
  });
});


// --- 2FA Setup POST (Authenticator App) ---
app.post("/setup-2fa", (req, res) => {
  if (req.session.user?.isAdmin) {
    return res.redirect("/terminal");
  }
  const { token } = req.body;
  const user = req.session.user;
  const tempSecret = req.session.twoFactorSecret;

  if (!user || !tempSecret || !token) {
    return res.redirect("/login");
  }

  const isVerified = speakeasy.totp.verify({
    secret: tempSecret,
    encoding: "base32",
    token: token,
  });

  if (isVerified) {
    db.run(
      `UPDATE users SET is2FAEnabled = 'authenticator', twoFactorSecret = ? WHERE username = ?`,
      [tempSecret, user.username],
      (err) => {
        if (err) {
          console.error("Database error saving 2FA secret:", err.message);
          return res.status(500).send("Error enabling 2FA.");
        }
        user.is2FAEnabled = 'authenticator';
        delete req.session.twoFactorSecret;
        res.redirect("/terminal?2fa=success");
      }
    );
  } else {
    res.render("setup-2fa", { error: "Invalid 2FA code. Please try again." });
  }
});

// --- NEW: Enable Email 2FA ---
app.post("/enable-email-2fa", (req, res) => {
  if (!req.session.user || req.session.user?.isAdmin) {
    return res.status(401).send("Unauthorized");
  }
  const user = req.session.user;

  db.run(
    `UPDATE users SET is2FAEnabled = 'email', twoFactorSecret = NULL WHERE username = ?`,
    [user.username],
    (err) => {
      if (err) {
        console.error("Database error enabling email 2FA:", err.message);
        return res.status(500).send("Error enabling email 2FA.");
      }
      user.is2FAEnabled = 'email';
      res.redirect("/terminal?2fa=email-enabled");
    }
  );
});

// --- NEW: Start WebAuthn Registration ---
app.post("/2fa-webauthn-start-registration", async (req, res) => {
  if (!req.session.user || req.session.user?.isAdmin) return res.status(401).send("Unauthorized");
  const user = req.session.user;
  const username = user.username;

  const userID = crypto.createHash('sha256').update(username).digest();

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID,
    userName: user.email,
    attestationType: "none",
  });

  req.session.currentChallenge = options.challenge;
  res.json(options);
});

// --- NEW: Finish WebAuthn Registration ---
app.post("/2fa-webauthn-finish-registration", async (req, res) => {
  if (!req.session.user || req.session.user?.isAdmin) return res.status(401).send("Unauthorized");

  const user = req.session.user;
  const expectedChallenge = req.session.currentChallenge;

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin: process.env.APP_URL,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;

      const newCredential = {
        id: Buffer.from(credentialID).toString("base64"),
        publicKey: Buffer.from(credentialPublicKey).toString("base64"),
        counter,
        transports: req.body.response.transports || [],
      };

      db.get(`SELECT webauthnCredentials FROM users WHERE username = ?`, [user.username], (err, row) => {
        let credentials = row.webauthnCredentials ? JSON.parse(row.webauthnCredentials) : [];
        credentials.push(newCredential);

        db.run(
          `UPDATE users SET is2FAEnabled = 'webauthn', webauthnCredentials = ? WHERE username = ?`,
          [JSON.stringify(credentials), user.username],
          (err) => {
            if (err) {
              console.error("Database error saving WebAuthn credential:", err.message);
              return res.status(500).send("Error enabling WebAuthn 2FA.");
            }
            user.is2FAEnabled = 'webauthn';
            res.json({ verified: true });
          }
        );
      });

    } else {
      res.json({ verified: false, error: "Verification failed." });
    }

  } catch (error) {
    console.error("WebAuthn verification error:", error);
    res.json({ verified: false, error: error.message });
  }
});

// --- NEW: Start WebAuthn Authentication ---
app.post("/2fa-webauthn-start-login", async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).send("Username is required.");

  if (username === adminUser.username) {
    return res.status(403).send("Admin user does not use WebAuthn.");
  }

  db.get(`SELECT webauthnCredentials FROM users WHERE username = ?`, [username], async (err, row) => {
    if (err || !row || !row.webauthnCredentials) return res.status(404).send("User or credentials not found.");

    const credentials = JSON.parse(row.webauthnCredentials);
    if (credentials.length === 0) return res.status(404).send("No WebAuthn credentials found for this user.");

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: credentials.map(cred => ({
        id: Buffer.from(cred.id, "base64"),
        type: "public-key",
      })),
      userVerification: "preferred",
    });

    req.session.currentChallenge = options.challenge;
    req.session.tempUsername = username;
    res.json(options);
  });
});

// --- NEW: Finish WebAuthn Authentication ---
app.post("/2fa-webauthn-finish-login", async (req, res) => {
  const { body } = req;
  const expectedChallenge = req.session.currentChallenge;
  const username = req.session.tempUsername;

  if (!username || !expectedChallenge) return res.status(400).send("Session expired. Please try again.");

  if (username === adminUser.username) {
    return res.status(403).send("Admin user does not use WebAuthn.");
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user || !user.webauthnCredentials) return res.status(404).send("User or credentials not found.");

    const credentials = JSON.parse(user.webauthnCredentials);
    const existingCredential = credentials.find(cred => cred.id === body.id);
    if (!existingCredential) return res.status(400).send("Credential not found.");

    try {
      const verification = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin: process.env.APP_URL,
        expectedRPID: rpID,
        authenticator: {
          credentialID: Buffer.from(existingCredential.id, "base64"),
          credentialPublicKey: Buffer.from(existingCredential.publicKey, "base64"),
          counter: existingCredential.counter,
        },
        requireUserVerification: false,
      });

      const { verified, authenticationInfo } = verification;
      if (verified) {
        const newCounter = authenticationInfo.newCounter;
        existingCredential.counter = newCounter;

        db.run(
          `UPDATE users SET webauthnCredentials = ? WHERE username = ?`,
          [JSON.stringify(credentials), username],
          (err) => {
            if (err) {
              console.error("Database error updating counter:", err.message);
            }
          }
        );

        req.session.user = user;
        req.session.is2faVerified = true;
        delete req.session.currentChallenge;
        delete req.session.tempUsername;
        req.session.save(() => {
          io.emit("user_update", { username: user.username, status: "online", public_ip: user.public_ip, private_ip: user.private_ip });
          res.json({ verified: true });
        });
      } else {
        res.json({ verified: false, error: "Authentication failed." });
      }
    } catch (error) {
      console.error("WebAuthn verification error:", error);
      res.json({ verified: false, error: error.message });
    }
  });
});

// ===========================================
// NEW: Settings Route
// ===========================================
app.get("/settings", async (req, res) => {
  if (!req.session.user || req.session.user?.isAdmin) {
    return res.redirect("/login");
  }

  try {
    const userFromDb = await findUser(req.session.user.username);

    if (!userFromDb) {
      return res.status(404).send("User not found.");
    }

    res.render("settings", { user: userFromDb });
  } catch (error) {
    console.error("Error fetching user data for settings:", error);
    res.status(500).send("An error occurred while loading settings.");
  }
});


// --- Admin dashboard ---
app.get("/admin-dashboard", async (req, res) => {
  if (!req.session.user?.isAdmin) return res.redirect("/login");
  try {
    const rows = await db.all(`SELECT * FROM users`);
    const users = rows.filter(u => u.username !== "nekologgeradmin");

    // fetch submissions as well
    const submissions = await db.all(`SELECT * FROM submissions ORDER BY ts DESC`);

    res.render("admin-dashboard", { 
      user: req.session.user, 
      users, 
      submissions 
    });
  } catch (err) {
    console.error("Error loading admin dashboard:", err);
    res.status(500).send("Error loading dashboard");
  }
});

// --- Handle geolocation submissions (admins only) ---
app.post('/submit-location', async (req, res) => {
  if (!req.session.user?.isAdmin) {
    return res.status(403).send("Forbidden");
  }

  const { coords } = req.body;
  const ts = new Date().toISOString();
  let address = null;

  try {
    if (coords) {
      const [lat, lon] = coords.split(",").map(c => c.trim());

      // 1️⃣ Try LocationIQ first
      try {
        const locIqRes = await fetch(
          `https://us1.locationiq.com/v1/reverse?key=${process.env.LOCATIONIQ_API_KEY}&lat=${lat}&lon=${lon}&format=json`
        );
        if (locIqRes.ok) {
          const locIqData = await locIqRes.json();
          address = locIqData.display_name || null;
        }
      } catch (e) {
        console.warn("⚠️ LocationIQ failed, falling back to Nominatim");
      }

      // 2️⃣ Fallback to Nominatim if LocationIQ fails
      if (!address) {
        const nominatimRes = await fetch(
          `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}`,
          { headers: { "User-Agent": "WebTerm/1.0 (test)" } }
        );
        const nominatimData = await nominatimRes.json();
        address = nominatimData.display_name || null;
      }
    }

    await db.run(
      'INSERT INTO submissions (method, coords, address, ts) VALUES (?, ?, ?, ?)',
      ['geolocation', coords, address || 'N/A', ts]
    );

    res.sendStatus(200);
  } catch (err) {
    console.error("Error saving submission:", err);
    res.status(500).send("Database error");
  }
});

// Delete one submission
app.post("/admin/delete-submission", async (req, res) => {
  const { id } = req.body;
  try {
    await db.run("DELETE FROM submissions WHERE id = ?", [id]);
    res.redirect("/admin-dashboard");
  } catch (err) {
    console.error("Error deleting submission:", err);
    res.status(500).send("Database error");
  }
});

// Clear all submissions
app.post("/admin/clear-submissions", async (req, res) => {
  try {
    await db.run("DELETE FROM submissions");
    res.redirect("/admin-dashboard");
  } catch (err) {
    console.error("Error clearing submissions:", err);
    res.status(500).send("Database error");
  }
});


// --- Admin users JSON for live updates ---
app.get("/admin-users-json", (req, res) => {
  if (!req.session.user?.isAdmin) return res.status(403).send("Forbidden");

  db.all(`SELECT u.*, f.mega_link as megaFolderLink FROM users u LEFT JOIN folders f ON u.username = f.owner_id AND f.is_shared = 0`, [], (err, rows) => {
    if (err) return res.status(500).send("Database error");

    const users = rows
      .map(u => ({
        username: u.username,
        firstName: u.firstName,
        lastName: u.lastName,
        email: u.email,
        dob: u.dob,
        createdAt: u.createdAt,
        public_ip: u.public_ip || "N/A",
        private_ip: u.private_ip || "N/A",
        status: u.status || "offline",
        isAdmin: !!u.isAdmin,
        megaFolderLink: u.megaFolderLink || null
      }))
      .filter(u => u.username !== adminUser.username);

    res.json(users);
  });
});

// --- Admin ban ---
app.post("/admin-ban", (req, res) => {
  if (!req.session.user?.isAdmin) return res.redirect("/login");
  const { username } = req.body;
  db.run(`DELETE FROM users WHERE username = ?`, [username], (err) => {
    if (err) return res.send("Error banning user");
    io.emit("user_banned", { username });
    res.redirect("/admin-dashboard");
  });
});

// --- Forgot Password ---
app.get("/forgot-password", (req, res) => {
  res.render("forgot-password", { error: null, message: null });
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.render("forgot-password", { error: "Email is required.", message: null });
  }

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err) {
      return res.render("forgot-password", { error: "Database error.", message: null });
    }

    if (!user) {
      return res.render("forgot-password", { message: "If an account with that email exists, a password reset link has been sent.", error: null });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    const tokenExpiry = Date.now() + 3600000;

    db.run(`UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE username = ?`, [resetToken, tokenExpiry, user.username], async (updateErr) => {
      if (updateErr) {
        return res.render("forgot-password", { error: "Could not initiate password reset.", message: null });
      }

      const resetLink = `${process.env.APP_URL}/reset-password?token=${resetToken}`;
      const templateID = user.isAdmin ? 7274583 : 7273798;

      try {
        await mailjet.post("send", { version: "v3.1" }).request({
          Messages: [{
            From: { Email: "kinvilladam134@outlook.com", Name: "WebTerm" },
            To: [{ Email: email, Name: user.firstName }],
            TemplateID: templateID,
            TemplateLanguage: true,
            Subject: "Password Reset Request",
            Variables: {
              username: user.username,
              verification_link: resetLink
            }
          }]
        });
        return res.render("forgot-password", { message: "If an account with that email exists, a password reset link has been sent.", error: null });
      } catch (mailError) {
        console.error("Mailjet Error:", mailError);
        return res.render("forgot-password", { error: "Could not send the password reset email.", message: null });
      }
    });
  });
});

// --- Reset Password GET route ---
app.get("/reset-password", (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.render("reset-password", { error: "Invalid or missing token.", message: null });
  }
  db.get(`SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiry > ?`, [token, Date.now()], (err, user) => {
    if (err || !user) {
      return res.render("reset-password", { error: "Invalid or expired token.", message: null });
    }
    res.render("reset-password", { error: null, message: null, token });
  });
});

// --- Reset Password POST route ---
app.post("/reset-password", (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.render("reset-password", { token, error: "Token and new password are required.", message: null });
  }

  db.get(`SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiry > ?`, [token, Date.now()], (err, user) => {
    if (err || !user) {
      return res.render("reset-password", { token, error: "Invalid or expired token.", message: null });
    }

    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    db.run(`UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE username = ?`, [hashedPassword, user.username], (updateErr) => {
      if (updateErr) {
        return res.render("reset-password", { token, error: "Failed to reset password. Please try again.", message: null });
      }
      res.render("login", { message: "Your password has been reset. Please log in.", error: null });
    });
  });
});
app.post("/api/social-login", async (req, res) => {
  const { uid, email, displayName } = req.body;
  if (!uid || !email) return res.status(400).json({ success: false, message: "Invalid data" });

  try {
    // Check if user already exists
    let user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);

    if (!user) {
      // Create new user in DB
      const now = new Date().toISOString();
      const safeDisplayName = displayName || "User";  // <-- fallback here
      const username = safeDisplayName.replace(/\s+/g, "") + Math.floor(Math.random() * 1000);

      await db.run(
        `INSERT INTO users (username, email, uid, status, createdAt) VALUES (?, ?, ?, 'active', ?)`,
        [username, email, uid, now]
      );

      user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
    }

    // Set session
    req.session.user = {
      username: user.username,
      email: user.email,
      isAdmin: !!user.isAdmin,
      status: "online"
    };
    req.session.is2faVerified = true;

    res.json({ success: true, message: "Logged in via social account" });
  } catch (err) {
    console.error("Social login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// --- Make user admin ---
app.post("/admin-make-admin", async (req, res) => {
  try {
    // Only admins can perform this
    if (!req.session.user?.isAdmin) return res.status(403).send("Forbidden");

    const { username } = req.body;
    if (!username) return res.status(400).send("No username provided.");

    // Find the user
    const user = await findUser(username);
    if (!user) return res.status(404).send("User not found");

    // Set user as admin
    await setAdmin(username);

    // If the affected user is the current session, update session immediately
    if (req.session.user.username === username) {
      req.session.user.isAdmin = true;
    }

    // Notify frontend to refresh
    io.emit("update_users");

    res.send({ success: true, message: `${username} is now an admin.` });
  } catch (err) {
    console.error("Error in /admin-make-admin:", err);
    res.status(500).send("Failed to make user admin.");
  }
});



// --- Delete account ---
app.post("/delete-account", (req, res) => {
  if (!req.session.user || req.session.user?.isAdmin) return res.redirect("/login");
  const username = req.session.user.username;
  db.run(`DELETE FROM users WHERE username = ?`, [username], (err) => {
    if (err) return res.send("Error deleting account");
    io.emit("user_banned", { username });
    req.session.destroy(() => res.redirect("/register"));
  });
});

// --- Logout ---
app.get("/logout", (req, res) => {
  if (req.session.user) {
    setOffline(req.session.user.username);
    io.emit("user_update", { username: req.session.user.username, status: "offline" });
  }
  req.session.destroy(() => res.redirect("/login"));
});

// --- Report private IP from client ---
app.post("/report-private-ip", (req, res) => {
  const { private_ip } = req.body;
  if (!req.session.user || req.session.user.isAdmin) return res.status(403).send("Forbidden");

  const username = req.session.user.username;
  db.run(`UPDATE users SET private_ip = ? WHERE username = ?`, [private_ip, username], (err) => {
    if (err) console.error("Failed to update private IP:", err.message);
    io.emit("user_update", { username, private_ip });
    res.sendStatus(200);
  });
});

// ====================
// FOLDER ROUTES (Updated for PIN Verification)
// ====================

// --- User personal folder ---
app.get("/my-folder", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  db.get(`SELECT mega_link FROM folders WHERE owner_id = ? AND is_shared = 0`, [req.session.user.username], (err, folder) => {
    if (err || !folder || !folder.mega_link) {
      return res.status(404).send("No folder assigned, or the folder ID is missing.");
    }
    const folderId = folder.mega_link;
    const boxFolderUrl = `https://app.box.com/folder/${folderId}`;
    res.redirect(boxFolderUrl);
  });
});

// --- Admin access to any user folder ---
app.get("/admin/folder/:username", (req, res) => {
  if (!req.session.user?.isAdmin) return res.redirect("/login");
  const { username } = req.params;
  res.render("verify-pin", { username: username, error: null });
});

app.post("/admin/verify-folder-pin/:username", (req, res) => {
  if (!req.session.user?.isAdmin) return res.redirect("/login");

  const { username } = req.params;
  const { pin } = req.body;
  const adminPin = process.env.ADMIN_FOLDER_PIN;

  if (!adminPin) {
    return res.status(500).send("Admin PIN is not configured on the server.");
  }

  if (pin === adminPin) {
    db.get(`SELECT mega_link FROM folders WHERE owner_id = ? AND is_shared = 0`, [username], (err, folder) => {
      if (err || !folder || !folder.mega_link) {
        return res.status(404).send("User folder not found or folder ID is missing.");
      }
      const folderId = folder.mega_link;
      const boxFolderUrl = `https://app.box.com/folder/${folderId}`;
      res.redirect(boxFolderUrl);
    });
  } else {
    res.render("verify-pin", { username: username, error: "Invalid PIN. Please try again." });
  }
});
// ====================
// Static after routes
// ====================
app.use(express.static(join(__dirname, "public")));
// ====================
// Terminal & Chat Logic (Unified)
// ====================
app.get('/terminal', (req, res) => {
  if (!req.session?.user) {
    return res.redirect('/login');
  }
  // ✅ Pass user object to EJS so terminal.ejs doesn't break
  res.render('terminal', { user: req.session.user });
});

// ✅ Removed the stray req.session.save(...) here — it belongs in your login route after setting req.session.user

const workspaceRoot = join(__dirname, "workspaces");
if (!fs.existsSync(workspaceRoot)) fs.mkdirSync(workspaceRoot, { recursive: true });

io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

io.on("connection", (socket) => {
  const sess = socket.request.session;
  if (!sess?.user) return socket.disconnect(true);

  const username = sess.user.username;
  console.log(`✅ User ${username} connected to terminal`);

  // Ensure user workspace exists
  const wsDir = join(workspaceRoot, username);
  if (!fs.existsSync(wsDir)) fs.mkdirSync(wsDir, { recursive: true });

  // Spawn shell inside user workspace
  const shell = process.env.SHELL || (process.platform === "win32" ? "powershell.exe" : "bash");
  const ptyProcess = pty.spawn(shell, [], {
    cwd: wsDir,
    env: process.env,
    cols: 80,
    rows: 24,
    name: "xterm-color"
  });

  // Handle terminal output/input
  ptyProcess.on("data", (data) => socket.emit("term_output", data));
  socket.on("term_input", (data) => ptyProcess.write(data));
  socket.on("resize", ({ cols, rows }) => {
    try { ptyProcess.resize(cols, rows); } catch (err) { console.error("Resize error:", err); }
  });

  // Handle chat messages
  socket.on("chat_message", (message) => {
    io.emit("chat_message", { username: sess.user.username, message });
  });

  // Disconnect cleanup
  socket.on("disconnect", () => {
    try { ptyProcess.kill(); } catch {}
    console.log(`❌ User ${username} disconnected`);
    io.emit("user_update", { username, status: "offline" });
  });
});


// ====================
// Terminal & Chat Logic (Unified) — moved inside startServer()
// ====================

app.get('/terminal', (req, res) => {
  if (!req.session?.user) {
    return res.redirect('/login');
  }
  res.render('terminal', { user: req.session.user }); // ✅ Pass user to EJS
});

// --- Terms of Service ---
app.get("/tos", (req, res) => {
  res.render("tos");
});
// --- Privacy Policy ---
app.get("/privacy", (req, res) => {
  res.render("privacy");
});
// --- Cookies Policy ---
app.get("/cookies", (req, res) => {
  res.render("cookies");
});
// ====================
// START SERVER SECTION
// ====================

const startServer = async () => {
  try {
    await initializeDb();

    const PORT = process.env.PORT || 3000;   // ✅ only define this once
    const workspaceRoot = join(__dirname, "workspaces");
    if (!fs.existsSync(workspaceRoot)) fs.mkdirSync(workspaceRoot, { recursive: true });

    // Always HTTP on Render (Render handles HTTPS at the load balancer)
    const httpServer = http.createServer(app);
    const io = new SocketIO(httpServer);

    // Share session with Socket.IO
    io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

    // Terminal & Chat logic
    io.on("connection", (socket) => {
      const sess = socket.request.session;
      if (!sess?.user) return socket.disconnect(true);

      const username = sess.user.username;
      console.log(`✅ User ${username} connected to terminal`);

      // Ensure user workspace exists
      const wsDir = join(workspaceRoot, username);
      if (!fs.existsSync(wsDir)) fs.mkdirSync(wsDir, { recursive: true });

      // Spawn shell inside user workspace
      const shell = process.env.SHELL || (process.platform === "win32" ? "powershell.exe" : "bash");
      const ptyProcess = pty.spawn(shell, [], {
        cwd: wsDir,
        env: process.env,
        cols: 80,
        rows: 24,
        name: "xterm-color"
      });

      // Handle terminal output/input
      ptyProcess.on("data", (data) => socket.emit("term_output", data));
      socket.on("term_input", (data) => ptyProcess.write(data));
      socket.on("resize", ({ cols, rows }) => {
        try { ptyProcess.resize(cols, rows); } catch (err) { console.error("Resize error:", err); }
      });

      // Chat
      socket.on("chat_message", (message) => {
        io.emit("chat_message", { username: sess.user.username, message });
      });

      // Disconnect
      socket.on("disconnect", () => {
        try { ptyProcess.kill(); } catch {}
        console.log(`❌ User ${username} disconnected`);
        io.emit("user_update", { username, status: "offline" });
      });
    });

    // ✅ Start server
    httpServer.listen(PORT, "0.0.0.0", () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`   Open at: https://${process.env.CODESPACE_NAME}-${PORT}.app.github.dev/login`);
    });

    // Graceful shutdown
    process.on("SIGINT", () => {
      console.log(`\n🛑 SIGINT received. Shutting down server...`);
      httpServer.close(() => {
        console.log(`✅ Server closed.`);
        process.exit(0);
      });
    });

    process.on("SIGTERM", () => {
      console.log(`\n🛑 SIGTERM received. Shutting down server...`);
      httpServer.close(() => {
        console.log(`✅ Server closed.`);
        process.exit(0);
      });
    });

  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
};

startServer();