Deployment Guide
================

This document describes how to deploy the **AI-Driven Framework for Ransomware Detection and Prevention** in different environments.

## 1. Local Development (Windows)

1. Open a terminal in the project root:
   ```bash
   cd "c:/Users/bhavi/major project"
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Train the model:
   ```bash
   python ml_model/train_model.py
   ```
5. Start the backend:
   ```bash
   python backend/app.py
   ```
6. In another terminal, start the monitoring agent:
   ```bash
   venv\Scripts\activate
   python monitoring/agent.py
   ```
7. Open the dashboard:
   - Navigate to `http://127.0.0.1:5000` in your browser.

## 2. Build a Windows EXE (Backend + Agent)

You can package the backend and monitoring agent using **PyInstaller**.

1. Install PyInstaller:
   ```bash
   pip install pyinstaller
   ```
2. Create a backend EXE:
   ```bash
   pyinstaller --onefile --name ransomware_backend backend/app.py
   ```
3. Create an agent EXE:
   ```bash
   pyinstaller --onefile --name ransomware_agent monitoring/agent.py
   ```
4. The EXEs will be located in the `dist/` folder.
5. Run:
   ```bash
   dist\ransomware_backend.exe
   dist\ransomware_agent.exe
   ```

> Note: When packaging, ensure that the `ml_model/model.joblib`, `ml_model/feature_config.json`, and `frontend/` are accessible relative to the EXEs or embedded via PyInstaller data options.

## 3. Docker Deployment

1. Ensure Docker Desktop is installed and running.
2. From the project root:
   ```bash
   docker build -t ai-ransomware-backend -f deployment/Dockerfile .
   ```
3. Run the container:
   ```bash
   docker run --name ai-ransomware-backend -p 5000:5000 ai-ransomware-backend
   ```
4. The backend and model training will run inside the container.
5. The monitoring agent is typically run **on the host** (so it can see real processes and files) pointing to the containerized backend:
   ```bash
   python monitoring/agent.py
   ```

## 4. Cloud Deployment (AWS / Azure)

### 4.1. AWS EC2 (Docker-based)

1. Launch an EC2 instance (e.g., t3.medium) with a Linux AMI.
2. Install Docker:
   ```bash
   sudo apt update
   sudo apt install -y docker.io
   sudo usermod -aG docker ubuntu
   newgrp docker
   ```
3. Copy project files to the server (via scp or Git).
4. Build and run:
   ```bash
   cd /path/to/project
   docker build -t ai-ransomware-backend -f deployment/Dockerfile .
   docker run -d --name ai-ransomware-backend -p 5000:5000 ai-ransomware-backend
   ```
5. Open EC2 security group port **5000** for your IP.
6. Access the dashboard at:
   - `http://<EC2_PUBLIC_IP>:5000`

### 4.2. Azure (App Service + Container)

1. Build and push the Docker image to Azure Container Registry (ACR).
2. Create an **Azure Web App for Containers**.
3. Configure the Web App to use the ACR image.
4. Set port 5000 as the exposed port.
5. Access the dashboard using the Azure Web App URL.

## 5. Continuous Learning & Model Updates

To enable continuous learning:

1. Periodically export new labeled behavioral data from the database or logs.
2. Retrain the model:
   ```bash
   python ml_model/train_model.py
   ```
3. Restart the backend to load the new `model.joblib`.

Automation ideas:
- Use a scheduled job (cron, Windows Task Scheduler) to run retraining weekly/monthly.
- Wrap retraining in a script that:
  - Backs up old models.
  - Evaluates performance on a validation set.
  - Only deploys the new model if it improves metrics.

