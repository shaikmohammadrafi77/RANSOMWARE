/**
 * CORTEX — ML Evaluation Script
 * Loads the active model, runs predictions on a held-out validation set,
 * computes confusion matrix + all classification metrics,
 * and persists results to both the feature config and the SQLite database.
 *
 * Usage: npm run evaluate
 */

import fs from "fs";
import path from "path";
import * as tf from "@tensorflow/tfjs";
import { getFileSystemHandler } from "./tf-utils.js";
import sqlite3 from "sqlite3";
import { open } from "sqlite";

const PROJECT_ROOT = process.cwd();
const MODEL_DIR = path.join(PROJECT_ROOT, "ml_model", "model");
const FEATURE_CONFIG_PATH = path.join(PROJECT_ROOT, "ml_model", "feature_config.json");
const DB_PATH =
    process.env.DB_PATH ||
    path.join(PROJECT_ROOT, "database", "ransomware_monitor_js.db");

const THRESHOLD = parseFloat(process.env.THRESHOLD || "0.7");

// ─── Synthetic Validation Data (same distribution as training) ─────────────────
function randn(mean, std) {
    let u = 0, v = 0;
    while (u === 0) u = Math.random();
    while (v === 0) v = Math.random();
    return Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2 * Math.PI * v) * std + mean;
}

function poisson(lambda) {
    const L = Math.exp(-Math.min(lambda, 100));
    let p = 1.0, k = 0;
    do { k++; p *= Math.random(); } while (p > L);
    return k - 1;
}

function generateValidationData(nSamples = 2000) {
    const half = Math.floor(nSamples / 2);
    const data = [];
    const labels = [];

    for (let i = 0; i < half; i++) {
        data.push([
            Math.max(0, randn(5, 2)),
            Math.max(0, randn(3, 1)),
            Math.max(1, randn(300, 100)),
            poisson(20),
            Math.min(100, Math.max(0, randn(20, 10))),
            Math.min(100, Math.max(0, randn(30, 10))),
            poisson(50),
            Math.max(0, randn(1e5, 5e4)),
            Math.max(0, randn(8e4, 4e4)),
            Math.min(1, Math.max(0, randn(0.01, 0.01))),
            poisson(2),
            poisson(1),
        ]);
        labels.push(0);
    }

    for (let i = 0; i < half; i++) {
        data.push([
            Math.max(0, randn(200, 50)),
            Math.max(0, randn(7.5, 0.5)),
            Math.max(1, randn(500, 150)),
            poisson(500),
            Math.min(100, Math.max(0, randn(85, 8))),
            Math.min(100, Math.max(0, randn(75, 8))),
            poisson(350),
            Math.max(0, randn(5e5, 2e5)),
            Math.max(0, randn(3e5, 1.5e5)),
            Math.min(1, Math.max(0, randn(0.65, 0.1))),
            poisson(25),
            poisson(20),
        ]);
        labels.push(1);
    }

    return { data, labels };
}

// ─── Metrics Computation ───────────────────────────────────────────────────────
function computeMetrics(labels, predictions, threshold) {
    let TP = 0, FP = 0, TN = 0, FN = 0;
    for (let i = 0; i < labels.length; i++) {
        const pred = predictions[i][0] >= threshold ? 1 : 0;
        const actual = labels[i];
        if (pred === 1 && actual === 1) TP++;
        else if (pred === 1 && actual === 0) FP++;
        else if (pred === 0 && actual === 0) TN++;
        else FN++;
    }

    const accuracy = (TP + TN) / (TP + TN + FP + FN);
    const precision = TP + FP > 0 ? TP / (TP + FP) : 0;
    const recall = TP + FN > 0 ? TP / (TP + FN) : 0;
    const f1 = precision + recall > 0
        ? (2 * precision * recall) / (precision + recall)
        : 0;
    const specificity = TN + FP > 0 ? TN / (TN + FP) : 0;
    const fpr = FP + TN > 0 ? FP / (FP + TN) : 0;

    return { TP, FP, TN, FN, accuracy, precision, recall, f1, specificity, fpr };
}

function printConfusionMatrix(TP, FP, TN, FN) {
    const total = TP + FP + TN + FN;
    console.log("\n  ┌──────────────────────────────────────────┐");
    console.log("  │            CONFUSION MATRIX              │");
    console.log("  ├──────────────────────┬───────────────────┤");
    console.log("  │                      │   Predicted       │");
    console.log("  │                      ├─────────┬─────────┤");
    console.log("  │                      │   POS   │   NEG   │");
    console.log("  ├──────────────────────┼─────────┼─────────┤");
    console.log(`  │ Actual POS (Ransom)  │  ${String(TP).padEnd(7)}│  ${String(FN).padEnd(7)}│`);
    console.log("  ├──────────────────────┼─────────┼─────────┤");
    console.log(`  │ Actual NEG (Normal)  │  ${String(FP).padEnd(7)}│  ${String(TN).padEnd(7)}│`);
    console.log("  └──────────────────────┴─────────┴─────────┘");
    console.log(`  Total samples: ${total}\n`);
}

// ─── Main Evaluation ────────────────────────────────────────────────────────────
async function evaluate() {
    console.log("\n╔══════════════════════════════════════════╗");
    console.log("║   CORTEX ML Evaluation Pipeline          ║");
    console.log("╚══════════════════════════════════════════╝\n");

    if (!fs.existsSync(MODEL_DIR) || !fs.existsSync(FEATURE_CONFIG_PATH)) {
        console.error("[EVAL] ❌ Model or Feature Config not found.");
        console.error("       Run: npm run train");
        process.exit(1);
    }

    console.log("[EVAL] Loading model and feature configuration...");
    const model = await tf.loadLayersModel(getFileSystemHandler(MODEL_DIR));
    const config = JSON.parse(fs.readFileSync(FEATURE_CONFIG_PATH, "utf8"));

    console.log(`[EVAL] Model Version : v${config.version || "unknown"}`);
    console.log(`[EVAL] Detection Threshold: ${THRESHOLD}`);
    console.log(`[EVAL] Generating validation dataset (2,000 samples)...`);

    const { data, labels } = generateValidationData(2000);

    // Standardize using saved scaler
    const xArr = data.map((row) =>
        row.map((val, i) => (val - config.scaler.mean[i]) / (config.scaler.std[i] || 1e-6))
    );

    const xs = tf.tensor2d(xArr);

    console.log("[EVAL] Running inference...");
    const probTensor = model.predict(xs);
    const predictions = await probTensor.array();

    const metrics = computeMetrics(labels, predictions, THRESHOLD);
    const { TP, FP, TN, FN, accuracy, precision, recall, f1, specificity, fpr } = metrics;

    // Print results
    printConfusionMatrix(TP, FP, TN, FN);

    console.log("  ┌──────────────────────────────────────────┐");
    console.log("  │          CLASSIFICATION METRICS          │");
    console.log("  ├────────────────────────┬─────────────────┤");
    console.log(`  │ Accuracy               │ ${(accuracy * 100).toFixed(2).padStart(9)}%      │`);
    console.log(`  │ Precision              │ ${(precision * 100).toFixed(2).padStart(9)}%      │`);
    console.log(`  │ Recall (Sensitivity)   │ ${(recall * 100).toFixed(2).padStart(9)}%      │`);
    console.log(`  │ F1 Score               │ ${(f1 * 100).toFixed(2).padStart(9)}%      │`);
    console.log(`  │ Specificity            │ ${(specificity * 100).toFixed(2).padStart(9)}%      │`);
    console.log(`  │ False Positive Rate    │ ${(fpr * 100).toFixed(2).padStart(9)}%      │`);
    console.log(`  │ True Positives         │ ${String(TP).padStart(9)}       │`);
    console.log(`  │ True Negatives         │ ${String(TN).padStart(9)}       │`);
    console.log(`  │ False Positives        │ ${String(FP).padStart(9)}       │`);
    console.log(`  │ False Negatives        │ ${String(FN).padStart(9)}       │`);
    console.log("  └────────────────────────┴─────────────────┘\n");

    // Update feature config with evaluation metrics
    config.metrics = {
        ...config.metrics,
        accuracy,
        precision,
        recall,
        f1_score: f1,
        specificity,
        fpr,
        threshold: THRESHOLD,
        evaluated_at: new Date().toISOString(),
        confusion_matrix: { TP, FP, TN, FN },
    };
    fs.writeFileSync(FEATURE_CONFIG_PATH, JSON.stringify(config, null, 2));
    console.log("[EVAL] ✅ Metrics saved → feature_config.json");

    // Persist to database
    try {
        const db = await open({ filename: DB_PATH, driver: sqlite3.Database });
        await db.run(
            `UPDATE model_versions
       SET accuracy = ?, precision_score = ?, recall_score = ?, f1_score = ?
       WHERE version = ?`,
            accuracy, precision, recall, f1, String(config.version || 1)
        );
        await db.close();
        console.log("[EVAL] ✅ Metrics persisted to database.\n");
    } catch (dbErr) {
        console.warn(`[EVAL] ⚠️  DB update skipped: ${dbErr.message}\n`);
    }

    xs.dispose();
    probTensor.dispose();

    console.log(`╔══════════════════════════════════════════╗`);
    console.log(`║  Evaluation complete for model v${config.version || "?"}       ║`);
    console.log(`║  Accuracy: ${(accuracy * 100).toFixed(2)}%  |  F1: ${(f1 * 100).toFixed(2)}%              ║`);
    console.log(`╚══════════════════════════════════════════╝\n`);
}

evaluate().catch((err) => {
    console.error("[EVAL] Fatal error:", err);
    process.exit(1);
});
