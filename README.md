# RANSOMWARE Defense System

AI-driven ransomware detection and active prevention platform. The system monitors host behavior, classifies activity with a neural network, and can automatically quarantine processes and files when ransomware is detected.

---

## How the System Works

### High-Level Flow

1. **Monitoring** — The monitoring agent (or any client) collects behavioral telemetry: CPU, memory, file changes, network I/O, and suspicious file extensions.
2. **Ingest** — Telemetry is sent to the backend at `POST /api/ingest_features`. The server runs the data through a TensorFlow.js model.
3. **Classification** — The ML model outputs a label (`benign` or `ransomware`) and a confidence score. If the score is above the threshold (default 0.7), the event is treated as ransomware.
4. **Prevention** — On a ransomware classification, the backend can kill related processes and move suspicious files to a quarantine folder.
5. **Incidents** — Every ingest creates an incident record in the database (open/resolved, severity, comments). The dashboard shows incidents, system health, and reports.

### Components

| Component | Role |
|-----------|------|
| **Backend** (`backend/server.js`) | Express API, SQLite DB, JWT auth, ML inference, prevention actions, static frontend serving |
| **Frontend** | Login, register, dashboard (incidents, AI model info, reports, CSV export) |
| **ML model** | TensorFlow.js model trained on synthetic behavioral features; loaded at startup from `ml_model/model` |
| **Monitoring agent** (`monitoring/agent.js`) | Optional; watches the filesystem and system stats, posts features to `/api/ingest_features` on an interval |

### Roles (RBAC)

- **ADMIN** — Full access, manage incidents, reports, model view.
- **ANALYST** — Manage incidents (status, comments), view dashboard and reports.
- **VIEWER** — Read-only dashboard and incidents.

---

## Project Structure

```
major project/
├── backend/
│   ├── server.js      # Main API, auth, ML inference, prevention
│   └── logger.js      # Winston logging
├── frontend/
│   ├── index.html     # Dashboard (after login)
│   ├── login.html     # Login page
│   ├── register.html  # User registration
│   └── static/
│       ├── app.js     # Dashboard logic, charts, API calls
│       └── styles.css # Styles
├── ml_model/
│   ├── train_model.js # Train model (synthetic data)
│   ├── evaluate_model.js
│   ├── tf-utils.js    # Model loading
│   ├── model/         # Active model (model.json + weights)
│   ├── models/        # Versioned models (model_v1, model_v2, ...)
│   └── feature_config.json
├── monitoring/
│   └── agent.js       # Telemetry collector, posts to backend
├── database/          # SQLite DB (created at runtime)
├── quarantine/        # Quarantined files (created when prevention runs)
├── logs/              # Winston logs
└── package.json
```

---

## Setup & Run

### Prerequisites

- **Node.js** >= 18.0.0

### Install

```bash
cd "major project"
npm install
```

### Start the app

```bash
npm start
```

- App: **http://localhost:5001**
- Login: **http://localhost:5001/login**
- Default credentials: **admin** / **admin123**

(In development, the admin password is synced to `admin123` on every server start.)

### Stopping the server on Windows

If a Node server is stuck or the port is already in use, you can forcibly stop all Node processes from PowerShell:

```powershell
taskkill /IM node.exe /F
```

Use this only when you know you do not need any other Node apps that are running.

### Optional: train the ML model

If `ml_model/model` is missing, run:

```bash
npm run train
```

Then restart the server so it loads the new model.

### Optional: run the monitoring agent

In a second terminal, from the project root:

```bash
npm run agent
```

This watches the current directory and system metrics, and sends feature payloads to `http://127.0.0.1:5001/api/ingest_features` every few seconds. Configure with `BACKEND_API_URL` and `MONITOR_INTERVAL_SECONDS` if needed.

---

## NPM Scripts

| Script | Description |
|--------|-------------|
| `npm start` | Start backend (serves API + frontend) |
| `npm run dev` | Start with nodemon (auto-restart) |
| `npm run train` | Train ML model (synthetic data, versioned under `ml_model/models/`) |
| `npm run evaluate` | Run model evaluation |
| `npm run agent` | Run monitoring agent (telemetry → backend) |
| `npm run clean` | Remove DB, model dir, and logs |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `5001` |
| `NODE_ENV` | `production` or other | — |
| `DB_PATH` | SQLite database path | `./database/ransomware_monitor_js.db` |
| `JWT_SECRET` | Secret for JWT signing | (in-code default) |
| `JWT_EXPIRY` | Token expiry | `10h` |
| `THRESHOLD` | Ransomware classification threshold | `0.7` |
| `DEFAULT_ADMIN_PASSWORD` | Password for default admin user | `admin123` |
| `RESET_ADMIN_PASSWORD` | Set to `1` or `true` to reset admin password on startup | — |
| `BACKEND_API_URL` | Agent: backend ingest URL | `http://127.0.0.1:5001/api/ingest_features` |
| `MONITOR_INTERVAL_SECONDS` | Agent: seconds between posts | `5` |
| `WATCH_PATH` | Agent: path to watch | current directory |

---

## API Overview

- **Auth:** `POST /api/login`, `POST /api/logout`, `POST /api/register`, `GET /api/me`
- **Ingest:** `POST /api/ingest_features` (payload: hostname + behavioral features)
- **Incidents:** `GET /api/incidents`, `PUT /api/incidents/:id`, status/comment updates
- **Health:** `GET /api/health`, `GET /api/system_health` (authenticated)
- **Reports:** `GET /api/reports/system_summary`, CSV export
- **Models:** `GET /api/models` (model versions and metadata)

---

## License

MIT.
