Demo Script – AI-Driven Framework for Ransomware Detection and Prevention
=========================================================================

This script helps you perform a smooth, step-by-step demo during your project evaluation.

1. Introduction (1–2 minutes)
-----------------------------
- Briefly explain:
  - What ransomware is.
  - Why traditional antivirus is not enough.
  - That your project uses **machine learning + real-time monitoring** to detect and prevent ransomware-like behavior.

2. Show Project Structure (1–2 minutes)
---------------------------------------
- Open your IDE / file explorer and show key folders:
  - `ml_model/` – training pipeline and saved model.
  - `monitoring/` – real-time agent.
  - `backend/` – Flask API and detection engine.
  - `frontend/` – web dashboard.
  - `documentation/` – report, PPT content, viva questions.

3. Start Backend Server (1 minute)
----------------------------------
In Terminal 1:

```bash
cd "c:/Users/bhavi/major project"
venv\Scripts\activate
python backend/app.py
```

Explain:
- This launches the Flask backend.
- It loads the trained ML model from `ml_model/model.joblib`.
- It also starts a thread to collect system health metrics.

4. Start Monitoring Agent (1 minute)
------------------------------------
In Terminal 2:

```bash
cd "c:/Users/bhavi/major project"
venv\Scripts\activate
python monitoring/agent.py
```

Explain:
- The agent monitors file, CPU, memory, and network activity.
- Every few seconds it sends a JSON feature snapshot to the backend.
- The backend returns a prediction and simulated action (printed in the agent terminal).

5. Open Web Dashboard (1–2 minutes)
-----------------------------------
- Open a browser and go to:

```text
http://127.0.0.1:5000
```

Show:
- **System Health Card**:
  - CPU and memory usage.
  - Total and ransomware incidents.
- **Model Performance Card**:
  - Accuracy, Precision, Recall, F1 score.
- **Recent Incidents Table**:
  - ID, timestamp, host, prediction (badge), score, and action taken.
- Explain that the page auto-refreshes and can also be refreshed manually.

6. Generate Activity to Trigger Incidents (2–3 minutes)
-------------------------------------------------------
- Perform some file operations to create noticeable behavior:
  - Copy a folder with many files inside the monitored directory.
  - Run a script or application that performs heavy I/O.
- Observe:
  - The monitoring agent prints classification results (normal / ransomware).
  - The dashboard populates with new incident rows.
- Explain:
  - High file modification rate, increased I/O, and resource usage can resemble ransomware-like behavior.
  - The model uses multiple features to decide if it is suspicious.

7. Explain Detection & Prevention Logic (1–2 minutes)
-----------------------------------------------------
- Open `backend/app.py` and briefly show:
  - `classify_features()` – converts features to model input and gets probability.
  - `prevention_actions()` – explains simulated actions for ransomware cases.
  - `log_incident()` – stores incidents in SQLite for auditing.
- Highlight that in real deployment:
  - System can be integrated with OS APIs to actually kill processes, block writes, or cut network.

8. Show Training Pipeline (2–3 minutes)
---------------------------------------
- Open `ml_model/train_model.py` and highlight:
  - Synthetic dataset generation for normal vs ransomware-like samples.
  - Preprocessing steps (scaling numeric features).
  - Training of Random Forest, SVM, and MLP models.
  - Evaluation metrics and selection of best model.
  - Saving `model.joblib` and `feature_config.json`.
- Optional: briefly run:

```bash
python ml_model/train_model.py
```

and show the printed metrics.

9. Summarize System Workflow (1 minute)
--------------------------------------
Explain in simple steps:
1. Monitoring agent collects system behavior.
2. Agent sends feature snapshots to backend.
3. Backend model predicts normal vs ransomware.
4. Decision engine logs incident and triggers simulated prevention.
5. Dashboard shows live incidents and health.

10. Q&A (Remaining Time)
------------------------
- Be prepared to answer:
  - Why you chose certain features and models.
  - How you would handle real ransomware safely (sandbox/VM).
  - How to extend the system for enterprise or cloud deployment.

