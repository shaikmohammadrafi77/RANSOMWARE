import fs from "fs";
import path from "path";
import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import "dotenv/config";

const LOG_DIR = path.join(process.cwd(), "logs");
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// JSON format for all file transports
const jsonFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
);

// Pretty console format
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: "HH:mm:ss" }),
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
        const metaStr = Object.keys(meta).length ? " " + JSON.stringify(meta) : "";
        return `${timestamp} [${level}] ${message}${metaStr}`;
    })
);

// Shared rotation options
const rotationOpts = {
    datePattern: "YYYY-MM-DD",
    zippedArchive: true,
};

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || "info",
    format: jsonFormat,
    defaultMeta: { service: "cortex-defense" },
    transports: [
        // Console output
        new winston.transports.Console({ format: consoleFormat }),

        // System log — all info+ events
        new DailyRotateFile({
            ...rotationOpts,
            filename: path.join(LOG_DIR, "system-%DATE%.log"),
            maxFiles: "14d",
            level: "info",
        }),

        // Threat log — warn+ events (prevention actions, quarantine)
        new DailyRotateFile({
            ...rotationOpts,
            filename: path.join(LOG_DIR, "threat-%DATE%.log"),
            maxFiles: "30d",
            level: "warn",
        }),

        // Audit log — auth + admin actions (tagged with [AUDIT] in message)
        new DailyRotateFile({
            ...rotationOpts,
            filename: path.join(LOG_DIR, "audit-%DATE%.log"),
            maxFiles: "365d",
            level: "info",
        }),

        // Error log — only errors
        new DailyRotateFile({
            ...rotationOpts,
            filename: path.join(LOG_DIR, "error-%DATE%.log"),
            maxFiles: "90d",
            level: "error",
        }),
    ],

    // Uncaught exception handler
    exceptionHandlers: [
        new DailyRotateFile({
            ...rotationOpts,
            filename: path.join(LOG_DIR, "exceptions-%DATE%.log"),
            maxFiles: "30d",
        }),
    ],

    // Unhandled promise rejection handler
    rejectionHandlers: [
        new DailyRotateFile({
            ...rotationOpts,
            filename: path.join(LOG_DIR, "rejections-%DATE%.log"),
            maxFiles: "30d",
        }),
    ],
});

export default logger;
