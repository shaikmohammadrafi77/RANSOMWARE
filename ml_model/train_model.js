/**
 * CORTEX — ML Training Pipeline
 * Generates synthetic behavioral data, trains a neural network,
 * saves model with versioning, and records metadata to SQLite.
 *
 * Usage: npm run train
 */

import fs from "fs";
import path from "path";
import * as tf from "@tensorflow/tfjs";
import { getFileSystemHandler } from "./tf-utils.js";
import sqlite3 from "sqlite3";
import { open } from "sqlite";

const PROJECT_ROOT = process.cwd();
const MODELS_BASE_DIR = path.join(PROJECT_ROOT, "ml_model", "models");
const DB_PATH =
  process.env.DB_PATH ||
  path.join(PROJECT_ROOT, "database", "ransomware_monitor_js.db");

// ─── Behavioral Feature Schema ─────────────────────────────────────────────────
const NUMERIC_FEATURES = [
  "file_modification_rate",
  "entropy_rate",
  "avg_file_size_kb",
  "num_files_touched",
  "cpu_usage",
  "memory_usage",
  "num_api_calls",
  "network_bytes_sent",
  "network_bytes_recv",
  "suspicious_extension_ratio",
  "registry_modifications",
  "failed_file_accesses",
];

// ─── Version Management ────────────────────────────────────────────────────────
function getNextVersion() {
  if (!fs.existsSync(MODELS_BASE_DIR)) {
    fs.mkdirSync(MODELS_BASE_DIR, { recursive: true });
    return 1;
  }
  const dirs = fs.readdirSync(MODELS_BASE_DIR);
  let maxV = 0;
  for (const d of dirs) {
    if (d.startsWith("model_v")) {
      const v = parseInt(d.replace("model_v", ""), 10);
      if (!isNaN(v) && v > maxV) maxV = v;
    }
  }
  return maxV + 1;
}

// ─── Synthetic Data Generator ─────────────────────────────────────────────────
function randn(mean, std) {
  // Box-Muller transform
  let u = 0,
    v = 0;
  while (u === 0) u = Math.random();
  while (v === 0) v = Math.random();
  return Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2 * Math.PI * v) * std + mean;
}

function poisson(lambda) {
  const L = Math.exp(-Math.min(lambda, 100));
  let p = 1.0,
    k = 0;
  do {
    k++;
    p *= Math.random();
  } while (p > L);
  return k - 1;
}

function generateSyntheticDataset(nSamples = 4000) {
  const half = Math.floor(nSamples / 2);
  const data = [];
  const labels = [];

  // Normal process behavior
  for (let i = 0; i < half; i++) {
    data.push([
      Math.max(0, randn(5, 2)),           // file_modification_rate
      Math.max(0, randn(3, 1)),           // entropy_rate (bits)
      Math.max(1, randn(300, 100)),       // avg_file_size_kb
      poisson(20),                         // num_files_touched
      Math.min(100, Math.max(0, randn(20, 10))), // cpu_usage
      Math.min(100, Math.max(0, randn(30, 10))), // memory_usage
      poisson(50),                         // num_api_calls
      Math.max(0, randn(1e5, 5e4)),        // network_bytes_sent
      Math.max(0, randn(8e4, 4e4)),        // network_bytes_recv
      Math.min(1, Math.max(0, randn(0.01, 0.01))), // suspicious_extension_ratio
      poisson(2),                          // registry_modifications
      poisson(1),                          // failed_file_accesses
    ]);
    labels.push(0);
  }

  // Ransomware-like behavior — bulk encryption signatures
  for (let i = 0; i < half; i++) {
    data.push([
      Math.max(0, randn(200, 50)),         // high file modification rate
      Math.max(0, randn(7.5, 0.5)),        // high entropy (encrypted files)
      Math.max(1, randn(500, 150)),        // larger avg file size
      poisson(500),                         // many files touched
      Math.min(100, Math.max(0, randn(85, 8))),  // high CPU
      Math.min(100, Math.max(0, randn(75, 8))),  // high memory
      poisson(350),                         // many API calls
      Math.max(0, randn(5e5, 2e5)),         // high outbound (C2 comm)
      Math.max(0, randn(3e5, 1.5e5)),       // high inbound
      Math.min(1, Math.max(0, randn(0.65, 0.1))), // high suspicious ext ratio
      poisson(25),                          // many registry mods
      poisson(20),                          // many failed accesses
    ]);
    labels.push(1);
  }

  // Shuffle
  for (let i = data.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [data[i], data[j]] = [data[j], data[i]];
    [labels[i], labels[j]] = [labels[j], labels[i]];
  }

  return { data, labels };
}

// ─── Standardization ──────────────────────────────────────────────────────────
function standardize(tensor) {
  const { mean, variance } = tf.moments(tensor, 0);
  const std = tf.sqrt(variance);
  const standardized = tensor.sub(mean).div(std.add(1e-6));
  return { standardized, mean, std };
}

// ─── Main Training Function ───────────────────────────────────────────────────
async function train() {
  const version = getNextVersion();
  const MODEL_DIR = path.join(MODELS_BASE_DIR, `model_v${version}`);
  const FEATURE_CONFIG_PATH = path.join(
    MODELS_BASE_DIR,
    `feature_config_v${version}.json`
  );

  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║   CORTEX ML Training Pipeline — v${version}    ║`);
  console.log(`╚══════════════════════════════════════════╝\n`);

  console.log("[TRAIN] Generating synthetic behavioral dataset (4,000 samples)...");
  const { data, labels } = generateSyntheticDataset(4000);

  const xs = tf.tensor2d(data);
  const ys = tf.tensor2d(labels, [labels.length, 1]);

  console.log("[TRAIN] Standardizing features...");
  const { standardized, mean, std } = standardize(xs);

  // ── Model Architecture ────────────────────────────────────────────────────
  console.log("[TRAIN] Building neural network (MLP)...");
  const model = tf.sequential();

  model.add(
    tf.layers.dense({
      units: 64,
      activation: "relu",
      inputShape: [NUMERIC_FEATURES.length],
      kernelRegularizer: tf.regularizers.l2({ l2: 0.001 }),
    })
  );
  model.add(tf.layers.batchNormalization());
  model.add(tf.layers.dropout({ rate: 0.3 }));

  model.add(
    tf.layers.dense({
      units: 32,
      activation: "relu",
      kernelRegularizer: tf.regularizers.l2({ l2: 0.001 }),
    })
  );
  model.add(tf.layers.dropout({ rate: 0.2 }));

  model.add(
    tf.layers.dense({
      units: 16,
      activation: "relu",
    })
  );

  model.add(tf.layers.dense({ units: 1, activation: "sigmoid" }));

  model.compile({
    optimizer: tf.train.adam(0.001),
    loss: "binaryCrossentropy",
    metrics: ["accuracy"],
  });

  model.summary();

  console.log("\n[TRAIN] Training started...\n");
  const history = await model.fit(standardized, ys, {
    epochs: 25,
    batchSize: 64,
    validationSplit: 0.2,
    shuffle: true,
    verbose: 1,
    callbacks: {
      onEpochEnd: (epoch, logs) => {
        const acc = (logs.acc || logs.accuracy || 0) * 100;
        const valAcc = (logs.val_acc || logs.val_accuracy || 0) * 100;
        console.log(
          `  Epoch ${String(epoch + 1).padStart(2)} | ` +
          `Loss: ${logs.loss.toFixed(4)} | ` +
          `Acc: ${acc.toFixed(2)}% | ` +
          `Val Acc: ${valAcc.toFixed(2)}%`
        );
      },
    },
  });

  // ── Save Model ────────────────────────────────────────────────────────────
  fs.mkdirSync(MODEL_DIR, { recursive: true });
  console.log(`\n[TRAIN] Saving model → ${MODEL_DIR}`);
  await model.save(getFileSystemHandler(MODEL_DIR));

  // ── Feature Config ────────────────────────────────────────────────────────
  const meanArr = await mean.array();
  const stdArr = await std.array();
  const finalAcc =
    history.history.acc
      ? history.history.acc[history.history.acc.length - 1]
      : history.history.accuracy
        ? history.history.accuracy[history.history.accuracy.length - 1]
        : 0;
  const finalLoss =
    history.history.loss[history.history.loss.length - 1];

  const featureConfig = {
    version,
    numeric_features: NUMERIC_FEATURES,
    scaler: { mean: meanArr, std: stdArr },
    metrics: {
      accuracy: finalAcc,
      loss: finalLoss,
      // Full evaluation metrics populated by evaluate_model.js
      precision: null,
      recall: null,
      f1_score: null,
      threshold: 0.7,
    },
    trained_at: new Date().toISOString(),
    architecture: "MLP-64-32-16-1",
    framework: "TensorFlow.js",
  };

  fs.writeFileSync(FEATURE_CONFIG_PATH, JSON.stringify(featureConfig, null, 2));
  console.log(`[TRAIN] Feature config saved → ${FEATURE_CONFIG_PATH}`);

  // ── Copy as active model ───────────────────────────────────────────────────
  const activeModelDir = path.join(PROJECT_ROOT, "ml_model", "model");
  const activeFeaturePath = path.join(
    PROJECT_ROOT,
    "ml_model",
    "feature_config.json"
  );

  if (fs.existsSync(activeModelDir)) {
    fs.rmSync(activeModelDir, { recursive: true, force: true });
  }
  fs.cpSync(MODEL_DIR, activeModelDir, { recursive: true });
  fs.copyFileSync(FEATURE_CONFIG_PATH, activeFeaturePath);
  console.log(`[TRAIN] Model v${version} set as active model.`);

  // ── Store in database ─────────────────────────────────────────────────────
  try {
    const db = await open({ filename: DB_PATH, driver: sqlite3.Database });
    await db.run(
      `INSERT OR REPLACE INTO model_versions
        (version, path, accuracy, precision_score, recall_score, f1_score, trained_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      String(version),
      MODEL_DIR,
      finalAcc,
      null,
      null,
      null,
      new Date().toISOString()
    );
    await db.close();
    console.log(`[TRAIN] Model metadata stored in database.`);
  } catch (dbErr) {
    console.warn(`[TRAIN] DB write skipped (server may not be running): ${dbErr.message}`);
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║          Training Complete!              ║`);
  console.log(`╠══════════════════════════════════════════╣`);
  console.log(`║  Version  : v${version}                          ║`);
  console.log(`║  Accuracy : ${(finalAcc * 100).toFixed(2)}%                    ║`);
  console.log(`║  Loss     : ${finalLoss.toFixed(4)}                    ║`);
  console.log(`║  Run eval : npm run evaluate             ║`);
  console.log(`╚══════════════════════════════════════════╝\n`);

  // Cleanup tensors
  xs.dispose();
  ys.dispose();
  standardized.dispose();
  mean.dispose();
  std.dispose();
}

train().catch((err) => {
  console.error("[TRAIN] Fatal training error:", err);
  process.exit(1);
});
