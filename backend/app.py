"""
Flask backend for AI-Driven Ransomware Detection and Prevention.

Responsibilities:
- Load the trained ML model pipeline.
- Expose an API to receive live feature snapshots from the monitoring agent.
- Run the detection engine and apply decision logic.
- Trigger prevention/response actions (simulated and safe).
- Store incidents and system metrics in SQLite.
- Serve a web dashboard (HTML/JS/CSS) for visualization.
"""

import json
import os
import threading
import time
from datetime import datetime
from typing import Any, Dict

import joblib
import psutil
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    create_engine,
    text,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
MODEL_PATH = os.path.join(PROJECT_ROOT, "ml_model", "model.joblib")
FEATURE_CONFIG_PATH = os.path.join(PROJECT_ROOT, "ml_model", "feature_config.json")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
DB_PATH = os.path.join(PROJECT_ROOT, "database", "ransomware_monitor.db")

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

app = Flask(
    __name__,
    static_folder=os.path.join(FRONTEND_DIR, "static"),
    template_folder=FRONTEND_DIR,
)
CORS(app)


# =======================
# Database Models / Setup
# =======================

engine = create_engine(f"sqlite:///{DB_PATH}", echo=False, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    hostname = Column(String(255))
    prediction_label = Column(String(50))
    prediction_score = Column(Float)
    action_taken = Column(String(255))
    raw_features = Column(String)  # JSON string


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


init_db()


# =======================
# Model Loading
# =======================

model_pipeline = None
feature_config: Dict[str, Any] = {}


def load_model() -> None:
    global model_pipeline, feature_config
    if not os.path.exists(MODEL_PATH):
        raise RuntimeError(
            f"Model not found at {MODEL_PATH}. Run 'python ml_model/train_model.py' first."
        )
    model_pipeline = joblib.load(MODEL_PATH)

    if os.path.exists(FEATURE_CONFIG_PATH):
        with open(FEATURE_CONFIG_PATH, "r", encoding="utf-8") as f:
            feature_config = json.load(f)
    else:
        feature_config = {"numeric_features": [], "model_name": "unknown", "metrics": {}}

    print(f"[BACKEND] Loaded model from {MODEL_PATH}")
    print(f"[BACKEND] Feature config: {feature_config.get('model_name')}")


load_model()


# =======================
# Detection & Prevention
# =======================

THRESHOLD = 0.7  # probability threshold for classifying as ransomware


def classify_features(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run the ML model on a single feature snapshot.
    Assumes features keys match training numeric features.
    """
    global model_pipeline, feature_config
    if model_pipeline is None:
        raise RuntimeError("Model pipeline is not loaded.")

    numeric_features = feature_config.get("numeric_features", [])
    x = [[features.get(name, 0.0) for name in numeric_features]]

    # Probability / decision function
    try:
        probs = model_pipeline.predict_proba(x)[0]
        # Assume class index 1 is ransomware
        ransomware_score = float(probs[1])
    except Exception:  # noqa: BLE001
        # Fallback if model has no predict_proba
        pred = int(model_pipeline.predict(x)[0])
        ransomware_score = 0.9 if pred == 1 else 0.1

    label = "ransomware" if ransomware_score >= THRESHOLD else "normal"
    return {
        "prediction_label": label,
        "prediction_score": ransomware_score,
    }


def prevention_actions(prediction: Dict[str, Any], features: Dict[str, Any]) -> str:
    """
    Simulated prevention and response logic.
    In a real system, this would:
    - Kill suspicious processes
    - Lock file writes
    - Quarantine directories
    - Disconnect network, etc.
    Here we log and describe the action without doing dangerous operations.
    """
    label = prediction["prediction_label"]
    score = prediction["prediction_score"]

    if label == "ransomware":
        action = (
            "Simulated: Isolated suspected process, blocked file writes, "
            "and restricted network access."
        )
    else:
        action = "No action (behavior within normal range)."

    print(
        f"[BACKEND] Decision: {label} (score={score:.3f}) -> {action}"
    )
    return action


def log_incident(
    hostname: str,
    prediction: Dict[str, Any],
    action: str,
    raw_features: Dict[str, Any],
) -> None:
    session = SessionLocal()
    try:
        incident = Incident(
            hostname=hostname,
            prediction_label=prediction["prediction_label"],
            prediction_score=float(prediction["prediction_score"]),
            action_taken=action,
            raw_features=json.dumps(raw_features),
        )
        session.add(incident)
        session.commit()
    finally:
        session.close()


def record_system_metric() -> None:
    session = SessionLocal()
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory().percent
        metric = SystemMetric(cpu_usage=cpu, memory_usage=mem)
        session.add(metric)
        session.commit()
    finally:
        session.close()


def metrics_collector_loop() -> None:
    while True:
        try:
            record_system_metric()
        except Exception as exc:  # noqa: BLE001
            print(f"[BACKEND] Error recording system metric: {exc}")
        time.sleep(10)


metrics_thread = threading.Thread(
    target=metrics_collector_loop, name="MetricsCollector", daemon=True
)
metrics_thread.start()


# ===========
# API Routes
# ===========


@app.route("/")
def index() -> Any:
    """Serve the main dashboard HTML."""
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/ingest_features", methods=["POST"])
def ingest_features() -> Any:
    """
    Receive feature snapshot from monitoring agent.
    Returns classification result and action description.
    """
    payload = request.get_json(force=True, silent=True) or {}
    hostname = str(payload.get("hostname", "unknown-host"))

    prediction = classify_features(payload)
    action = prevention_actions(prediction, payload)

    # Log to database
    log_incident(hostname, prediction, action, payload)

    # TODO: Here you could add email notifications / system pop-ups.

    return jsonify(
        {
            "status": "ok",
            "prediction_label": prediction["prediction_label"],
            "prediction_score": prediction["prediction_score"],
            "action_taken": action,
        }
    )


@app.route("/api/incidents", methods=["GET"])
def list_incidents() -> Any:
    """Return recent incidents for the dashboard."""
    session = SessionLocal()
    try:
        rows = (
            session.query(Incident)
            .order_by(Incident.timestamp.desc())
            .limit(100)
            .all()
        )
        out = []
        for r in rows:
            out.append(
                {
                    "id": r.id,
                    "timestamp": r.timestamp.isoformat(sep=" ", timespec="seconds"),
                    "hostname": r.hostname,
                    "prediction_label": r.prediction_label,
                    "prediction_score": r.prediction_score,
                    "action_taken": r.action_taken,
                }
            )
        return jsonify(out)
    finally:
        session.close()


@app.route("/api/system_health", methods=["GET"])
def system_health() -> Any:
    """Summarize basic system health and model metrics."""
    session = SessionLocal()
    try:
        # Latest system metric
        metric = (
            session.query(SystemMetric)
            .order_by(SystemMetric.timestamp.desc())
            .limit(1)
            .one_or_none()
        )

        # Incident counts
        total_incidents = session.execute(
            text("SELECT COUNT(*) FROM incidents")
        ).scalar_one()
        ransomware_incidents = session.execute(
            text(
                "SELECT COUNT(*) FROM incidents WHERE prediction_label='ransomware'"
            )
        ).scalar_one()

        health = {
            "cpu_usage": metric.cpu_usage if metric else None,
            "memory_usage": metric.memory_usage if metric else None,
            "total_incidents": total_incidents,
            "ransomware_incidents": ransomware_incidents,
            "model_metrics": feature_config.get("metrics", {}),
            "model_name": feature_config.get("model_name", "unknown"),
        }
        return jsonify(health)
    finally:
        session.close()


@app.route("/api/model_info", methods=["GET"])
def model_info() -> Any:
    """Expose model metadata for the dashboard."""
    return jsonify(feature_config)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

