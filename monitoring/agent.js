/**
 * CORTEX — Monitoring Agent (Node.js)
 * Production-hardened behavioral telemetry collector.
 *
 * Collects:  CPU, memory, network, filesystem events, process info
 * Posts to:  /api/ingest_features  (Cortex backend)
 * Usage:     npm run agent
 */

import "dotenv/config";
import chokidar from "chokidar";
import os from "os";
import si from "systeminformation";
import fetch from "node-fetch";
import path from "path";

const BACKEND_API_URL =
  process.env.BACKEND_API_URL ||
  "http://127.0.0.1:5001/api/ingest_features";
const INTERVAL_SECONDS = parseInt(
  process.env.MONITOR_INTERVAL_SECONDS || "5",
  10
);
const WATCH_PATH = process.env.WATCH_PATH || process.cwd();

// ─── Telemetry State ──────────────────────────────────────────────────────────
const state = {
  fileModifications: 0,
  numFilesTouched: 0,
  suspiciousFiles: 0,
  failedAccessAttempts: 0,
  suspiciousFilePaths: [],

  // Previous network counters for delta calculation
  prevNetworkBytesSent: 0,
  prevNetworkBytesRecv: 0,
};

// Extensions commonly associated with ransomware output
const RANSOMWARE_EXTENSIONS = new Set([
  ".encrypted",
  ".locked",
  ".enc",
  ".crypto",
  ".crypt",
  ".wcry",
  ".wncry",
  ".wnry",
  ".cerber",
  ".zepto",
  ".locky",
]);

let consecutiveFailures = 0;
const MAX_FAILURES = 10;
let isRunning = true;

// ─── File System Watcher ──────────────────────────────────────────────────────
function startFileWatcher(rootPath) {
  console.log(`[AGENT] Watching filesystem: ${rootPath}`);

  const watcher = chokidar.watch(rootPath, {
    persistent: true,
    ignoreInitial: true,
    depth: 6,
    ignored: [
      /(^|[/\\])\../,     // dot files
      /node_modules/,
      /\.log$/,
      /\.db$/,
      /quarantine/,
    ],
    awaitWriteFinish: { stabilityThreshold: 200, pollInterval: 100 },
  });

  watcher.on("all", (event, filePath) => {
    try {
      if (["add", "change", "unlink", "addDir", "unlinkDir"].includes(event)) {
        state.numFilesTouched++;
        if (["add", "change"].includes(event)) {
          state.fileModifications++;
        }

        const ext = path.extname(filePath).toLowerCase();
        if (RANSOMWARE_EXTENSIONS.has(ext)) {
          state.suspiciousFiles++;
          state.suspiciousFilePaths.push(filePath);
          console.warn(`[AGENT] ⚠️  Suspicious extension detected: ${filePath}`);
        }
      }
    } catch (e) {
      // Ignore individual file errors
    }
  });

  watcher.on("error", (err) => {
    console.error("[AGENT] File watcher error:", err.message);
  });

  return watcher;
}

// ─── Feature Collection ───────────────────────────────────────────────────────
async function collectFeatures() {
  const hostname = os.hostname();
  const timestamp = Date.now() / 1000;

  // CPU & Memory
  const [cpuData, memData, netData, processData] = await Promise.all([
    si.currentLoad().catch(() => ({ currentLoad: 0 })),
    si.mem().catch(() => ({ active: 0, total: 1 })),
    si.networkStats().catch(() => []),
    si.processes().catch(() => ({ list: [] })),
  ]);

  const cpuUsage = parseFloat((cpuData.currentLoad || 0).toFixed(2));
  const memoryUsage = parseFloat(
    ((memData.active / memData.total) * 100).toFixed(2)
  );

  // Network deltas (bytes since last interval)
  const rawSent = netData.reduce((s, n) => s + (n.tx_bytes || 0), 0);
  const rawRecv = netData.reduce((s, n) => s + (n.rx_bytes || 0), 0);
  const networkBytesSent = Math.max(0, rawSent - state.prevNetworkBytesSent);
  const networkBytesRecv = Math.max(0, rawRecv - state.prevNetworkBytesRecv);
  state.prevNetworkBytesSent = rawSent;
  state.prevNetworkBytesRecv = rawRecv;

  // API calls approximation using I/O ops 
  let numApiCalls = 0;
  let failedFileAccesses = state.failedAccessAttempts;

  for (const p of processData.list || []) {
    if (
      typeof p.readOperations === "number" &&
      typeof p.writeOperations === "number"
    ) {
      numApiCalls += p.readOperations + p.writeOperations;
    }
  }

  // Snapshot counters then reset
  const fileModifications = state.fileModifications;
  const numFilesTouched = state.numFilesTouched;
  const suspiciousFiles = state.suspiciousFiles;
  const suspiciousPaths = [...state.suspiciousFilePaths];

  state.fileModifications = 0;
  state.numFilesTouched = 0;
  state.suspiciousFiles = 0;
  state.failedAccessAttempts = 0;
  state.suspiciousFilePaths = [];

  const fileModificationRate = fileModifications / Math.max(1, INTERVAL_SECONDS);
  const suspiciousExtensionRatio = numFilesTouched > 0
    ? suspiciousFiles / numFilesTouched
    : 0;

  return {
    timestamp,
    hostname,
    // Behavioral features
    file_modification_rate: parseFloat(fileModificationRate.toFixed(4)),
    entropy_rate: 0,     // Accurate calculation requires file reads
    avg_file_size_kb: 0,
    num_files_touched: numFilesTouched,
    cpu_usage: cpuUsage,
    memory_usage: memoryUsage,
    num_api_calls: numApiCalls,
    network_bytes_sent: networkBytesSent,
    network_bytes_recv: networkBytesRecv,
    suspicious_extension_ratio: parseFloat(suspiciousExtensionRatio.toFixed(4)),
    registry_modifications: 0,     // Requires Windows-specific APIs
    failed_file_accesses: failedFileAccesses,
    // Context (not ML features — used for prevention)
    files: suspiciousPaths,
    process_name: "monitoring-agent",
  };
}

// ─── Send Snapshot ────────────────────────────────────────────────────────────
async function sendSnapshot(snapshot) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const resp = await fetch(BACKEND_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(snapshot),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      console.error(`[AGENT] Backend error ${resp.status}: ${text}`);
      consecutiveFailures++;
      return;
    }

    const data = await resp.json();
    consecutiveFailures = 0;

    const label = data.prediction_label || "unknown";
    const score = data.prediction_score != null
      ? (data.prediction_score * 100).toFixed(1)
      : "?";
    const status = data.prevention_status || "";
    const ts = new Date(snapshot.timestamp * 1000).toLocaleString();

    const icon = label === "ransomware" ? "🚨" : "✅";
    console.log(
      `[AGENT] ${icon} ${ts} — ${label.toUpperCase()} (${score}%)` +
      (status ? ` | Prevention: ${status}` : "")
    );
  } catch (err) {
    clearTimeout(timeout);
    if (err.name === "AbortError") {
      console.error("[AGENT] Request timed out.");
    } else {
      console.error("[AGENT] Send failed:", err.message);
    }
    consecutiveFailures++;
  }
}

// ─── Main Loop ────────────────────────────────────────────────────────────────
async function loop() {
  while (isRunning) {
    try {
      const snapshot = await collectFeatures();
      await sendSnapshot(snapshot);

      if (consecutiveFailures >= MAX_FAILURES) {
        console.error(
          `[AGENT] ${MAX_FAILURES} consecutive failures. Check backend connectivity.`
        );
        consecutiveFailures = 0; // Reset to avoid log spam
      }
    } catch (err) {
      console.error("[AGENT] Loop iteration error:", err.message);
    }

    await new Promise((resolve) =>
      setTimeout(resolve, INTERVAL_SECONDS * 1000)
    );
  }
}

// ─── Startup ──────────────────────────────────────────────────────────────────
function main() {
  console.log("╔══════════════════════════════════════════╗");
  console.log("║   CORTEX Monitoring Agent — Starting...  ║");
  console.log("╚══════════════════════════════════════════╝");
  console.log(`[AGENT] Backend  : ${BACKEND_API_URL}`);
  console.log(`[AGENT] Interval : ${INTERVAL_SECONDS}s`);
  console.log(`[AGENT] Watch    : ${WATCH_PATH}`);
  console.log(`[AGENT] Platform : ${process.platform}\n`);

  startFileWatcher(WATCH_PATH);

  loop().catch((err) => {
    console.error("[AGENT] Fatal loop error:", err.message);
    process.exit(1);
  });
}

// Graceful shutdown
process.on("SIGINT", () => { isRunning = false; console.log("\n[AGENT] Shutting down…"); });
process.on("SIGTERM", () => { isRunning = false; console.log("\n[AGENT] Shutting down…"); });

main();
