/**
 * CORTEX Defense System — Production Backend
 * Monolithic Node.js architecture with:
 *   - Active ransomware prevention (process kill + quarantine)
 *   - Full RBAC (ADMIN / ANALYST / VIEWER) with JWT
 *   - Incident lifecycle management
 *   - ML model versioning & dynamic loading
 *   - Structured Winston logging (system / threat / audit / error)
 *   - Reporting & CSV export
 *   - /api/health endpoint
 *   - Fault-tolerant monitoring loop
 *   - Helmet + rate-limit + CORS + input validation
 */

import "dotenv/config";
import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import { fileURLToPath } from "url";
import * as tf from "@tensorflow/tfjs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { exec } from "child_process";
import crypto from "crypto";
import { getFileSystemHandler } from "../ml_model/tf-utils.js";
import si from "systeminformation";
import logger from "./logger.js";

// ─── Constants ───────────────────────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.join(__dirname, "..");
const FRONTEND_DIR = path.join(PROJECT_ROOT, "frontend");
const DB_PATH =
  process.env.DB_PATH ||
  path.join(PROJECT_ROOT, "database", "ransomware_monitor_js.db");
const MODEL_DIR = path.join(PROJECT_ROOT, "ml_model", "model");
const FEATURE_CONFIG_PATH = path.join(
  PROJECT_ROOT,
  "ml_model",
  "feature_config.json"
);
const QUARANTINE_DIR = path.join(PROJECT_ROOT, "quarantine");
const JWT_SECRET =
  process.env.JWT_SECRET || "cortex_default_secret_random_88122";
const JWT_EXPIRY = process.env.JWT_EXPIRY || "10h";
const DETECTION_THRESHOLD = parseFloat(process.env.THRESHOLD || "0.7");
const PORT = process.env.PORT || 5001;
const ALLOWED_ROLES = ["ADMIN", "ANALYST", "VIEWER"];

// ─── State ───────────────────────────────────────────────────────────────────
let db;
let model;
let featureConfig;
let modelVersion = "unknown";

// ─── Utility: Input Validation ────────────────────────────────────────────────
function isValidString(v, maxLen = 255) {
  return typeof v === "string" && v.trim().length > 0 && v.length <= maxLen;
}

function sanitizeString(v) {
  return String(v || "").replace(/[<>"';&]/g, "").trim();
}

// ─── Database Init ────────────────────────────────────────────────────────────
async function initDb() {
  const dbDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

  db = await open({ filename: DB_PATH, driver: sqlite3.Database });

  // Enable WAL mode for better concurrency
  await db.exec("PRAGMA journal_mode=WAL;");
  await db.exec("PRAGMA foreign_keys=ON;");

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      fullname TEXT,
      role TEXT NOT NULL DEFAULT 'VIEWER',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id TEXT UNIQUE NOT NULL,
      timestamp TEXT NOT NULL,
      hostname TEXT,
      prediction_label TEXT,
      prediction_score REAL,
      action_taken TEXT,
      raw_features TEXT,
      severity_level TEXT DEFAULT 'LOW',
      status TEXT DEFAULT 'OPEN',
      analyst_comments TEXT DEFAULT '',
      prevention_status TEXT DEFAULT 'NONE',
      resolution_time TEXT
    );

    CREATE TABLE IF NOT EXISTS system_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      cpu_usage REAL,
      memory_usage REAL
    );

    CREATE TABLE IF NOT EXISTS model_versions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      version TEXT NOT NULL,
      path TEXT NOT NULL,
      accuracy REAL,
      precision_score REAL,
      recall_score REAL,
      f1_score REAL,
      trained_at TEXT NOT NULL
    );
  `);

  // Best-effort schema migrations for existing databases
  const migrations = [
    "ALTER TABLE users ADD COLUMN password_hash TEXT",
    "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'VIEWER'",
    "ALTER TABLE users ADD COLUMN fullname TEXT",
    "ALTER TABLE incidents ADD COLUMN incident_id TEXT",
    "ALTER TABLE incidents ADD COLUMN severity_level TEXT DEFAULT 'LOW'",
    "ALTER TABLE incidents ADD COLUMN status TEXT DEFAULT 'OPEN'",
    "ALTER TABLE incidents ADD COLUMN analyst_comments TEXT DEFAULT ''",
    "ALTER TABLE incidents ADD COLUMN prevention_status TEXT DEFAULT 'NONE'",
    "ALTER TABLE incidents ADD COLUMN resolution_time TEXT",
    "ALTER TABLE model_versions ADD COLUMN precision_score REAL",
    "ALTER TABLE model_versions ADD COLUMN recall_score REAL",
  ];
  for (const m of migrations) {
    try {
      await db.exec(m);
    } catch (_) { }
  }

  // Create indexes for performance
  await db.exec(`
    CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity_level);
    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp DESC);
  `);

  // Ensure admin user exists and in development always use known password (no 401 on login)
  const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || "admin123";
  const adminUser = await db.get("SELECT id, password_hash FROM users WHERE username = ?", "admin");
  const isProduction = process.env.NODE_ENV === "production";
  const resetAdmin = process.env.RESET_ADMIN_PASSWORD === "1" || process.env.RESET_ADMIN_PASSWORD === "true";
  const syncAdminInDev = !isProduction || resetAdmin;

  const defaultHash = await bcrypt.hash(defaultPassword, 12);

  if (!adminUser) {
    await db.run(
      "INSERT INTO users (username, password_hash, fullname, role, created_at) VALUES (?, ?, ?, ?, ?)",
      "admin",
      defaultHash,
      "Administrator",
      "ADMIN",
      new Date().toISOString()
    );
    logger.info(`[DB] Admin user created (username: admin, password: ${defaultPassword}).`);
  } else if (syncAdminInDev) {
    await db.run("UPDATE users SET password_hash = ? WHERE username = ?", defaultHash, "admin");
    logger.info(`[DB] Admin password synced (username: admin, password: ${defaultPassword}). Use these to log in.`);
  }

  logger.info(`[DB] Database initialized at ${DB_PATH}`);
}

// ─── ML Model Loader ─────────────────────────────────────────────────────────
async function loadModel() {
  if (!fs.existsSync(MODEL_DIR)) {
    logger.warn(
      `[ML] Model directory not found at ${MODEL_DIR}. Run "npm run train" first.`
    );
    return;
  }
  try {
    model = await tf.loadLayersModel(getFileSystemHandler(MODEL_DIR));
    if (fs.existsSync(FEATURE_CONFIG_PATH)) {
      featureConfig = JSON.parse(fs.readFileSync(FEATURE_CONFIG_PATH, "utf8"));
      modelVersion = featureConfig.version || "1";
      logger.info(
        `[ML] Model v${modelVersion} loaded. Features: ${featureConfig.numeric_features?.length}`
      );

      // Register in DB if not already there
      const exists = await db.get(
        "SELECT id FROM model_versions WHERE version = ?",
        String(modelVersion)
      );
      if (!exists) {
        const metrics = featureConfig.metrics || {};
        await db.run(
          `INSERT INTO model_versions (version, path, accuracy, precision_score, recall_score, f1_score, trained_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          String(modelVersion),
          MODEL_DIR,
          metrics.accuracy || 0,
          metrics.precision || 0,
          metrics.recall || 0,
          metrics.f1_score || 0,
          new Date().toISOString()
        );
      }
    }
  } catch (err) {
    logger.error("[ML] Error loading model:", { error: err.message });
  }
}

// ─── Classifier ───────────────────────────────────────────────────────────────
function classifyFeatures(features) {
  if (!model || !featureConfig) {
    return { prediction_label: "unknown", prediction_score: 0 };
  }
  try {
    const numericFeatures = featureConfig.numeric_features;
    const { mean, std } = featureConfig.scaler;
    const xArr = numericFeatures.map((name) => Number(features[name] ?? 0));
    const standardized = xArr.map((v, i) => (v - mean[i]) / (std[i] || 1e-6));
    const input = tf.tensor2d([standardized]);
    const probTensor = model.predict(input);
    const prob = probTensor.dataSync()[0];
    input.dispose();
    probTensor.dispose();
    const label = prob >= DETECTION_THRESHOLD ? "ransomware" : "normal";
    return { prediction_label: label, prediction_score: prob };
  } catch (err) {
    logger.error("[ML] Classification error:", { error: err.message });
    return { prediction_label: "unknown", prediction_score: 0 };
  }
}

// ─── Prevention Engine ────────────────────────────────────────────────────────
async function executePreventionAction(payload, prediction) {
  const pid = payload.pid || payload.process_id;
  const procName = payload.process_name || payload.name || "unknown";
  const execPath =
    payload.exec_path || payload.exe_path || payload.execution_path;
  const files = Array.isArray(payload.files)
    ? payload.files
    : payload.touched_files || [];

  let preventionStatus = "NONE";
  let action = "No action taken.";

  if (!fs.existsSync(QUARANTINE_DIR)) {
    fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
  }

  const processHash = crypto
    .createHash("sha256")
    .update(String(pid || Date.now()))
    .digest("hex")
    .slice(0, 12);

  logger.warn("[THREAT] Ransomware detected", {
    hostname: payload.hostname,
    score: prediction.prediction_score.toFixed(4),
    pid,
    procName,
    execPath,
  });

  if (pid) {
    try {
      const command =
        process.platform === "win32"
          ? `taskkill /F /PID ${parseInt(pid)}`
          : `kill -9 ${parseInt(pid)}`;

      await new Promise((resolve) => {
        exec(command, (error) => {
          if (error) {
            preventionStatus = "FAILED";
            action = `Failed to terminate PID ${pid} (${procName}): ${error.message}`;
            logger.error("[PREVENTION] Process kill failed", {
              pid,
              procName,
              error: error.message,
            });
          } else {
            preventionStatus = "BLOCKED";
            action = `Terminated PID ${pid} (${procName}).`;
            logger.warn("[PREVENTION] Process terminated", {
              pid,
              procName,
              execPath,
            });
          }
          resolve();
        });
      });
    } catch (e) {
      preventionStatus = "FAILED";
      action = `Exception during kill: ${e.message}`;
      logger.error("[PREVENTION] Exception in kill", { error: e.message });
    }

    // Only quarantine files if process was blocked
    if (preventionStatus === "BLOCKED" && files.length > 0) {
      for (const f of files) {
        try {
          const src = path.resolve(sanitizeString(f));
          if (fs.existsSync(src)) {
            const dest = path.join(
              QUARANTINE_DIR,
              `${path.basename(src)}.${processHash}.quarantine`
            );
            fs.renameSync(src, dest);
            logger.warn("[THREAT] File quarantined", { file: src, dest });
          }
        } catch (moveErr) {
          logger.error("[THREAT] Quarantine failed", {
            file: f,
            error: moveErr.message,
          });
        }
      }
    }
  } else {
    preventionStatus = "ESCALATED";
    action = `No PID available. Process: ${procName}. Escalated for manual review.`;
    logger.warn("[PREVENTION] No PID — escalated", {
      procName,
      execPath,
      hostname: payload.hostname,
    });
  }

  return { preventionStatus, action };
}

// ─── Express App ──────────────────────────────────────────────────────────────
const app = express();

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "script-src": [
          "'self'",
          "'unsafe-inline'",
          "https://cdnjs.cloudflare.com",
          "https://cdn.jsdelivr.net",
        ],
        "font-src": [
          "'self'",
          "https://fonts.gstatic.com",
          "https://cdnjs.cloudflare.com",
        ],
        "style-src": [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdnjs.cloudflare.com",
        ],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// Allow both localhost and 127.0.0.1 so cookies work regardless of how user opens the app
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((o) => o.trim())
  : [`http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`];
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // same-origin or non-browser
      if (allowedOrigins.includes(origin)) return cb(null, origin);
      return cb(null, allowedOrigins[0]); // fallback for dev
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false, limit: "2mb" }));
app.use(cookieParser());
app.use(
  morgan("combined", {
    stream: { write: (msg) => logger.info(msg.trim()) },
  })
);

// ─── Rate Limiters ────────────────────────────────────────────────────────────
const AUTH_RATE_MAX = parseInt(process.env.AUTH_RATE_MAX || "60", 10); // 60 per 15 min (configurable)
const isProduction = process.env.NODE_ENV === "production";
const isLocalhost = (ip) =>
  !ip || ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1";
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: AUTH_RATE_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    if (!isProduction) return true;
    if (isLocalhost(req.ip)) return true;
    const host = (req.get("host") || "").split(":")[0];
    if (host === "localhost" || host === "127.0.0.1") return true;
    return false;
  },
  handler: (req, res) => {
    res.status(429).json({
      status: "error",
      message: "Too many login attempts. Please wait 15 minutes and try again.",
    });
  },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: "error", message: "Rate limit exceeded." },
});

const ingestLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 60,
  message: { status: "error", message: "Ingest rate limit exceeded." },
});

app.use("/api", apiLimiter);

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) {
    return res
      .status(401)
      .json({ status: "error", message: "Unauthorized — no session" });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res
        .status(403)
        .json({ status: "error", message: "Session expired or invalid" });
    }
    req.user = user;
    next();
  });
}

function authorizeRoles(...allowed) {
  return (req, res, next) => {
    const role = ((req.user && req.user.role) || "VIEWER").toUpperCase();
    const allowedUpper = allowed.map((r) => r.toUpperCase());
    if (!allowedUpper.includes(role)) {
      logger.info("[AUDIT] Forbidden role attempt", {
        user: req.user?.username,
        role,
        required: allowed,
        path: req.path,
      });
      return res.status(403).json({ status: "error", message: "Forbidden" });
    }
    next();
  };
}

// ─── Static & Page Routes ─────────────────────────────────────────────────────
app.use("/static", express.static(path.join(FRONTEND_DIR, "static")));
app.get("/login", (_, res) =>
  res.sendFile(path.join(FRONTEND_DIR, "login.html"))
);
app.get("/register", (_, res) =>
  res.sendFile(path.join(FRONTEND_DIR, "register.html"))
);
app.get("/", (req, res) => {
  if (!req.cookies.auth_token) return res.redirect("/login");
  res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});

// ─── Auth Routes ──────────────────────────────────────────────────────────────
app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const { username, password, fullname, role } = req.body;

    if (!isValidString(username, 50) || !isValidString(password, 128)) {
      return res
        .status(400)
        .json({ status: "error", message: "Invalid username or password" });
    }

    // Only allow valid roles; default to VIEWER
    const userRole = ALLOWED_ROLES.includes((role || "").toUpperCase())
      ? role.toUpperCase()
      : "VIEWER";

    const existingUser = await db.get(
      "SELECT id FROM users WHERE username = ?",
      username
    );
    if (existingUser) {
      return res
        .status(400)
        .json({ status: "error", message: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    await db.run(
      "INSERT INTO users (username, password_hash, fullname, role, created_at) VALUES (?, ?, ?, ?, ?)",
      sanitizeString(username),
      hashedPassword,
      sanitizeString(fullname || username),
      userRole,
      new Date().toISOString()
    );

    logger.info("[AUDIT] User registered", { username, role: userRole });
    res.json({ status: "ok", message: "Registration successful" });
  } catch (err) {
    logger.error("[AUTH] Registration failed:", { error: err.message });
    res.status(500).json({ status: "error", message: "Registration failed" });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const raw = req.body || {};
    const username = typeof raw.username === "string" ? raw.username.trim() : "";
    const password = typeof raw.password === "string" ? raw.password : "";

    if (!username || username.length > 50) {
      return res
        .status(400)
        .json({ status: "error", message: "Username is required (max 50 characters)." });
    }
    if (!password || password.length > 128) {
      return res
        .status(400)
        .json({ status: "error", message: "Password is required (max 128 characters)." });
    }

    const user = await db.get(
      "SELECT * FROM users WHERE username = ?",
      username
    );
    if (!user || !(await bcrypt.compare(password, user.password_hash || ""))) {
      logger.info("[AUDIT] Failed login attempt", {
        username,
        ip: req.ip,
      });
      return res
        .status(401)
        .json({ status: "error", message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role || "VIEWER" },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 10 * 60 * 60 * 1000,
    });

    logger.info("[AUDIT] Successful login", {
      username: user.username,
      role: user.role,
      ip: req.ip,
    });

    // Redirect so browser navigates with cookie set (avoids client-side redirect timing issues)
    res.redirect(302, "/");
  } catch (err) {
    logger.error("[AUTH] Login error:", { error: err.message });
    res.status(500).json({ status: "error", message: "Login failed" });
  }
});

app.post("/api/logout", (req, res) => {
  const user = req.user || {};
  res.clearCookie("auth_token", { path: "/" });
  logger.info("[AUDIT] User logged out", { username: user.username });
  res.json({ status: "ok" });
});

app.get("/api/me", authenticateToken, (req, res) => {
  res.json({ status: "ok", user: req.user });
});

// ─── Ingest Endpoint (Prevention Engine) ─────────────────────────────────────
app.post("/api/ingest_features", ingestLimiter, async (req, res) => {
  try {
    const payload = req.body || {};
    const hostname = sanitizeString(payload.hostname || "unknown-host");
    const prediction = classifyFeatures(payload);

    let action = "No action taken.";
    let preventionStatus = "NONE";
    let severityLevel = "LOW";

    if (prediction.prediction_label === "ransomware") {
      severityLevel = prediction.prediction_score > 0.9 ? "CRITICAL" : "HIGH";
      const result = await executePreventionAction(payload, prediction);
      preventionStatus = result.preventionStatus;
      action = result.action;

      logger.warn("[AUDIT] Prevention executed", {
        hostname,
        preventionStatus,
        action,
        score: prediction.prediction_score,
      });
    }

    const incidentId = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    await db.run(
      `INSERT INTO incidents
        (incident_id, timestamp, hostname, prediction_label, prediction_score,
         action_taken, raw_features, severity_level, status, prevention_status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)`,
      incidentId,
      timestamp,
      hostname,
      prediction.prediction_label,
      prediction.prediction_score,
      action,
      JSON.stringify(payload),
      severityLevel,
      preventionStatus
    );

    res.json({
      status: "ok",
      ...prediction,
      action_taken: action,
      prevention_status: preventionStatus,
      incident_id: incidentId,
    });
  } catch (err) {
    logger.error("[INGEST] Feature ingestion failed:", { error: err.message });
    res.status(500).json({ status: "error", message: "Internal Server Error" });
  }
});

// ─── Incidents Routes ─────────────────────────────────────────────────────────
app.get("/api/incidents", authenticateToken, async (req, res) => {
  try {
    const { severity, status, limit = "500", page = "1" } = req.query;
    const pageSize = Math.min(parseInt(limit) || 500, 1000);
    const offset = (Math.max(parseInt(page) || 1, 1) - 1) * pageSize;

    let query = "SELECT * FROM incidents";
    const params = [];
    const filters = [];

    if (severity && ALLOWED_ROLES.includes(severity.toUpperCase())) {
      filters.push("severity_level = ?");
      params.push(severity.toUpperCase());
    } else if (severity) {
      filters.push("severity_level = ?");
      params.push(severity.toUpperCase());
    }

    if (status) {
      filters.push("status = ?");
      params.push(status.toUpperCase());
    }

    if (filters.length) query += " WHERE " + filters.join(" AND ");
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?";
    params.push(pageSize, offset);

    const rows = await db.all(query, ...params);
    const countQuery =
      "SELECT COUNT(*) as total FROM incidents" +
      (filters.length
        ? " WHERE " + filters.join(" AND ")
        : "");
    const countResult = await db.get(
      countQuery,
      ...params.slice(0, filters.length)
    );

    res.json({ data: rows, total: countResult.total, page: parseInt(page), pageSize });
  } catch (err) {
    logger.error("[INCIDENTS] Fetch failed:", { error: err.message });
    res.status(500).json({ status: "error", message: "Internal Server Error" });
  }
});

app.patch(
  "/api/incidents/:id/status",
  authenticateToken,
  authorizeRoles("ADMIN", "ANALYST"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;
      const allowed = ["OPEN", "INVESTIGATING", "RESOLVED"];

      if (!status || !allowed.includes(status.toUpperCase())) {
        return res
          .status(400)
          .json({ status: "error", message: "Invalid status value" });
      }

      const resolution_time =
        status.toUpperCase() === "RESOLVED" ? new Date().toISOString() : null;

      const result = await db.run(
        "UPDATE incidents SET status = ?, resolution_time = ? WHERE incident_id = ?",
        status.toUpperCase(),
        resolution_time,
        id
      );

      if (result.changes === 0) {
        return res
          .status(404)
          .json({ status: "error", message: "Incident not found" });
      }

      logger.info("[AUDIT] Incident status updated", {
        incident_id: id,
        newStatus: status.toUpperCase(),
        by: req.user?.username,
        role: req.user?.role,
      });

      res.json({ status: "ok", message: "Status updated" });
    } catch (err) {
      logger.error("[INCIDENTS] Status update failed:", { error: err.message });
      res.status(500).json({ status: "error" });
    }
  }
);

app.post(
  "/api/incidents/:id/comment",
  authenticateToken,
  authorizeRoles("ADMIN", "ANALYST"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { comment } = req.body;

      if (!isValidString(comment, 2000)) {
        return res
          .status(400)
          .json({ status: "error", message: "Invalid or missing comment" });
      }

      const row = await db.get(
        "SELECT analyst_comments FROM incidents WHERE incident_id = ?",
        id
      );
      if (!row) {
        return res
          .status(404)
          .json({ status: "error", message: "Incident not found" });
      }

      const timestamp = new Date().toISOString();
      const newEntry = `[${timestamp}] ${req.user.username}: ${sanitizeString(comment)}`;
      const updated = row.analyst_comments
        ? `${row.analyst_comments}\n${newEntry}`
        : newEntry;

      await db.run(
        "UPDATE incidents SET analyst_comments = ? WHERE incident_id = ?",
        updated,
        id
      );

      logger.info("[AUDIT] Incident comment added", {
        incident_id: id,
        by: req.user?.username,
      });

      res.json({ status: "ok" });
    } catch (err) {
      logger.error("[INCIDENTS] Comment failed:", { error: err.message });
      res.status(500).json({ status: "error" });
    }
  }
);

// Legacy PUT for backward compatibility with frontend modal
app.put("/api/incidents/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, severity_level, analyst_comments } = req.body;
    const role = (req.user?.role || "VIEWER").toUpperCase();

    if (role === "VIEWER") {
      return res
        .status(403)
        .json({ status: "error", message: "Viewers cannot modify incidents" });
    }

    const parts = [];
    const params = [];
    if (status) {
      parts.push("status = ?");
      params.push(status.toUpperCase());
    }
    if (severity_level) {
      parts.push("severity_level = ?");
      params.push(severity_level.toUpperCase());
    }
    if (analyst_comments !== undefined) {
      parts.push("analyst_comments = ?");
      params.push(sanitizeString(analyst_comments));
    }
    if (status && status.toUpperCase() === "RESOLVED") {
      parts.push("resolution_time = ?");
      params.push(new Date().toISOString());
    }

    if (parts.length === 0) {
      return res
        .status(400)
        .json({ status: "error", message: "No fields to update" });
    }

    params.push(id);
    await db.run(
      `UPDATE incidents SET ${parts.join(", ")} WHERE id = ?`,
      ...params
    );

    logger.info("[AUDIT] Incident updated via PUT", {
      id,
      by: req.user?.username,
      fields: parts,
    });

    res.json({ status: "ok", message: "Incident updated" });
  } catch (err) {
    logger.error("[INCIDENTS] PUT update failed:", { error: err.message });
    res.status(500).json({ status: "error" });
  }
});

// ─── System Health Routes ─────────────────────────────────────────────────────
app.get("/api/system_health", authenticateToken, async (req, res) => {
  try {
    const latestMetric = await db.get(
      "SELECT * FROM system_metrics ORDER BY timestamp DESC LIMIT 1"
    );
    const totalCount = await db.get(
      "SELECT COUNT(*) as c FROM incidents"
    );
    const ransomwareCount = await db.get(
      "SELECT COUNT(*) as c FROM incidents WHERE prediction_label = 'ransomware'"
    );
    const blockedCount = await db.get(
      "SELECT COUNT(*) as c FROM incidents WHERE prevention_status = 'BLOCKED'"
    );
    const successRate =
      ransomwareCount.c > 0 ? blockedCount.c / ransomwareCount.c : 0;

    // CPU histogram (last 30 readings)
    const cpuHistory = await db.all(
      "SELECT timestamp, cpu_usage FROM system_metrics ORDER BY timestamp DESC LIMIT 30"
    );
    const threatTrend = await db.all(
      `SELECT substr(timestamp, 1, 10) as day, COUNT(*) as count
       FROM incidents WHERE prediction_label='ransomware'
       GROUP BY day ORDER BY day DESC LIMIT 14`
    );
    const severityDist = await db.all(
      `SELECT severity_level, COUNT(*) as count FROM incidents GROUP BY severity_level`
    );

    res.json({
      cpu_usage: latestMetric?.cpu_usage ?? null,
      memory_usage: latestMetric?.memory_usage ?? null,
      total_incidents: totalCount.c,
      ransomware_incidents: ransomwareCount.c,
      blocked_count: blockedCount.c,
      prevention_success_rate: successRate,
      model_metrics: featureConfig ? featureConfig.metrics : {},
      model_name: `cortex-mlp-v${modelVersion}`,
      model_version: modelVersion,
      cpu_history: cpuHistory.reverse(),
      threat_trend: threatTrend.reverse(),
      severity_distribution: severityDist,
    });
  } catch (err) {
    logger.error("[HEALTH] System health fetch failed:", { error: err.message });
    res.status(500).json({ status: "error", message: "Internal Server Error" });
  }
});

// ─── /api/health (Public health check) ───────────────────────────────────────
app.get("/api/health", async (req, res) => {
  try {
    let database_status = "unknown";
    const model_status = model ? "loaded" : "missing";
    const model_ver = modelVersion;

    try {
      await db.get("SELECT 1");
      database_status = "ok";
    } catch (_) {
      database_status = "error";
    }

    res.json({
      server_status: "ok",
      database_status,
      model_status,
      model_version: model_ver,
      timestamp: new Date().toISOString(),
      uptime_seconds: Math.floor(process.uptime()),
    });
  } catch (err) {
    logger.error("[HEALTH] Health check failed:", { error: err.message });
    res.status(500).json({ status: "error" });
  }
});

// ─── Reporting Routes ─────────────────────────────────────────────────────────
app.get(
  "/api/reports/incidents/csv",
  authenticateToken,
  async (req, res) => {
    try {
      const rows = await db.all(
        `SELECT incident_id, timestamp, hostname, prediction_label, prediction_score,
                severity_level, status, prevention_status, analyst_comments, resolution_time
         FROM incidents ORDER BY timestamp DESC`
      );

      const headers = [
        "incident_id",
        "timestamp",
        "hostname",
        "prediction_label",
        "prediction_score",
        "severity_level",
        "status",
        "prevention_status",
        "analyst_comments",
        "resolution_time",
      ];

      const csv = [headers.join(",")];
      for (const r of rows) {
        const line = headers
          .map((h) => '"' + String(r[h] ?? "").replace(/"/g, '""') + '"')
          .join(",");
        csv.push(line);
      }

      const filename = `cortex_incidents_${new Date()
        .toISOString()
        .slice(0, 10)}.csv`;
      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${filename}"`
      );
      res.send(csv.join("\n"));

      logger.info("[AUDIT] CSV exported", { by: req.user?.username, rows: rows.length });
    } catch (err) {
      logger.error("[REPORT] CSV export failed:", { error: err.message });
      res.status(500).json({ status: "error" });
    }
  }
);

app.get(
  "/api/reports/system_summary",
  authenticateToken,
  async (req, res) => {
    try {
      const latestMetric = await db.get(
        "SELECT * FROM system_metrics ORDER BY timestamp DESC LIMIT 1"
      );
      const totalCount = await db.get(
        "SELECT COUNT(*) as c FROM incidents"
      );
      const ransomwareCount = await db.get(
        "SELECT COUNT(*) as c FROM incidents WHERE prediction_label = 'ransomware'"
      );
      const blockedCount = await db.get(
        "SELECT COUNT(*) as c FROM incidents WHERE prevention_status = 'BLOCKED'"
      );
      const failedCount = await db.get(
        "SELECT COUNT(*) as c FROM incidents WHERE prevention_status = 'FAILED'"
      );
      const escalatedCount = await db.get(
        "SELECT COUNT(*) as c FROM incidents WHERE prevention_status = 'ESCALATED'"
      );
      const openCount = await db.get(
        "SELECT COUNT(*) as c FROM incidents WHERE status = 'OPEN'"
      );
      const resolvedCount = await db.get(
        "SELECT COUNT(*) as c FROM incidents WHERE status = 'RESOLVED'"
      );
      const latestModel = await db.get(
        "SELECT * FROM model_versions ORDER BY id DESC LIMIT 1"
      );

      res.json({
        generated_at: new Date().toISOString(),
        current_cpu: latestMetric?.cpu_usage ?? null,
        current_memory: latestMetric?.memory_usage ?? null,
        total_incidents: totalCount.c,
        ransomware_incidents: ransomwareCount.c,
        normal_incidents: totalCount.c - ransomwareCount.c,
        prevention: {
          blocked: blockedCount.c,
          failed: failedCount.c,
          escalated: escalatedCount.c,
          success_rate:
            ransomwareCount.c > 0
              ? (blockedCount.c / ransomwareCount.c).toFixed(4)
              : "0",
        },
        incident_status: {
          open: openCount.c,
          resolved: resolvedCount.c,
        },
        model: latestModel
          ? {
            version: latestModel.version,
            accuracy: latestModel.accuracy,
            precision: latestModel.precision_score,
            recall: latestModel.recall_score,
            f1: latestModel.f1_score,
            trained_at: latestModel.trained_at,
          }
          : null,
      });
    } catch (err) {
      logger.error("[REPORT] Summary failed:", { error: err.message });
      res.status(500).json({ status: "error" });
    }
  }
);

// Model versions
app.get("/api/models", authenticateToken, async (req, res) => {
  try {
    const rows = await db.all(
      "SELECT * FROM model_versions ORDER BY id DESC"
    );
    res.json({ status: "ok", data: rows });
  } catch (err) {
    logger.error("[MODELS] Fetch failed:", { error: err.message });
    res.status(500).json({ status: "error" });
  }
});

// ─── 404 Handler ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ status: "error", message: "Route not found" });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  logger.error("[SERVER] Unhandled route error:", {
    error: err.message,
    stack: err.stack,
  });
  res.status(500).json({ status: "error", message: "Internal Server Error" });
});

// ─── Background: Metric Recording ────────────────────────────────────────────
async function recordMetrics() {
  try {
    const cpu = await si.currentLoad();
    const mem = await si.mem();
    await db.run(
      "INSERT INTO system_metrics (timestamp, cpu_usage, memory_usage) VALUES (?, ?, ?)",
      new Date().toISOString(),
      parseFloat(cpu.currentLoad.toFixed(2)),
      parseFloat(((mem.active / mem.total) * 100).toFixed(2))
    );
  } catch (err) {
    logger.error("[METRICS] Recording failed:", { error: err.message });
  }
}

// ─── Startup ──────────────────────────────────────────────────────────────────
async function start() {
  try {
    await initDb();
    await loadModel();
    if (!fs.existsSync(QUARANTINE_DIR)) {
      fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
    }

    // Metrics every 10s
    setInterval(() => {
      recordMetrics().catch((e) =>
        logger.error("[METRICS] Interval error:", { error: e.message })
      );
    }, 10000);

    app.listen(PORT, () => {
      logger.info(
        `[SERVER] Cortex Defense System running → http://localhost:${PORT}`
      );
      logger.info(`[SERVER] ML Model: v${modelVersion} | Threshold: ${DETECTION_THRESHOLD}`);
    });
  } catch (err) {
    logger.error("[STARTUP] Fatal error:", { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

start();

// ─── Global Fault Tolerance ───────────────────────────────────────────────────
process.on("unhandledRejection", (reason) => {
  logger.error("[FAULT] Unhandled Promise Rejection:", {
    reason: reason instanceof Error ? reason.stack : String(reason),
  });
});

process.on("uncaughtException", (err) => {
  logger.error("[FAULT] Uncaught Exception — attempting graceful recovery:", {
    message: err.message,
    stack: err.stack,
  });
  // Do NOT exit — allow degraded operation
});
