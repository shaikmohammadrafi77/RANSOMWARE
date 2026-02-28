// Quick diagnostic wrapper — checks all imports resolve correctly
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('NODE VERSION:', process.version);
console.log('CWD:', process.cwd());
console.log('---');

const checks = [
    ['dotenv', () => import('dotenv/config')],
    ['express', () => import('express')],
    ['cors', () => import('cors')],
    ['sqlite3', () => import('sqlite3')],
    ['sqlite', () => import('sqlite')],
    ['@tensorflow/tfjs', () => import('@tensorflow/tfjs')],
    ['helmet', () => import('helmet')],
    ['express-rate-limit', () => import('express-rate-limit')],
    ['morgan', () => import('morgan')],
    ['bcryptjs', () => import('bcryptjs')],
    ['jsonwebtoken', () => import('jsonwebtoken')],
    ['cookie-parser', () => import('cookie-parser')],
    ['systeminformation', () => import('systeminformation')],
    ['winston', () => import('winston')],
    ['winston-daily-rotate-file', () => import('winston-daily-rotate-file')],
    ['ml_model/tf-utils.js', () => import('./ml_model/tf-utils.js')],
    ['backend/logger.js', () => import('./backend/logger.js')],
];

let ok = 0, fail = 0;
for (const [name, importer] of checks) {
    try {
        await importer();
        console.log(`  ✅  ${name}`);
        ok++;
    } catch (e) {
        console.error(`  ❌  ${name} — ${e.message}`);
        fail++;
    }
}

console.log(`\n--- ${ok} OK, ${fail} FAILED ---`);
if (fail === 0) {
    console.log('All imports OK. Trying full server start...');
}
