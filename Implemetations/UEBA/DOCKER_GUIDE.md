# 🐳 ZenGuard UEBA: Docker Deployment Guide

Welcome to the **User and Entity Behavior Analytics (UEBA)** Docker guide. This document provides everything you need to containerize, deploy, and interact with the UEBA inference engine.

---

## 🚀 Quick Start

### 1. Prerequisites
- [Docker](https://www.docker.com/get-started) installed and running.
- [Docker Compose](https://docs.docker.com/compose/install/) (included with Docker Desktop).

### 2. Building and Starting
From the root of the repository, navigate to the UEBA folder and run:

```bash
cd Implemetations/UEBA
docker-compose up --build -d
```

- `--build`: Forces a rebuild of the image (essential if you updated the `model.joblib`).
- `-d`: Runs in the background (detached mode).

### 3. Checking Status
Verify the container is running and healthy:

```bash
docker ps
```
You should see `zenguard_ueba_v2` running on port `8080` (mapped from internal `8000`).

---

## 📡 API Documentation

The Docker container exposes the following endpoints at `http://localhost:8080`.

### 1. Health Check
Internal check to ensure the ML model is loaded and the server is ready.
- **URL:** `/health`
- **Method:** `GET`
- **Example:**
  ```bash
  curl http://localhost:8080/health
  ```

### 2. SOAR Evaluation (Recommended)
The primary endpoint for the ZenGuard Pipeline. Converts raw network features into a **0-100 Risk Score** and provides feature context.
- **URL:** `/api/soar/evaluate`
- **Method:** `POST`
- **Payload Structure:**
  ```json
  {
    "failed_logins": 5,
    "privilege_change_attempted": 1,
    "external_connection": 1,
    "MFA_bypassed": 1,
    "session_duration": 120.5,
    "access_hour": 3,
    "device_trust_score": 0.2
  }
  ```
- **Example Curl:**
  ```bash
  curl -X POST http://localhost:8080/api/soar/evaluate \
       -H "Content-Type: application/json" \
       -d '{"failed_logins":5,"privilege_change_attempted":1,"external_connection":1,"MFA_bypassed":1,"session_duration":120.5,"access_hour":3,"device_trust_score":0.2}'
  ```

### 3. Standard ML Prediction
Returns the raw anomaly score and a boolean flag.
- **URL:** `/api/ueba/predict`
- **Method:** `POST`

---

## 🧪 Testing the Container

We have provided a specialized testing script `test_docker.py` that verifies the container's performance against a 30% holdout split of real network logs.

1. Ensure the container is running on port `8080`.
2. Run:
   ```bash
   python test_docker.py
   ```
This script will sample 5,000 records, fire them at the Docker API, and print an **F1 Anomaly Score** and **Confusion Matrix** to prove the containerized model is working exactly like the local one.

---

## 🛠️ Maintenance & Troubleshooting

### Stopping the Container
```bash
docker-compose down
```

### Viewing Logs
```bash
docker logs -f zenguard_ueba_v2
```

### Port Conflicts
By default, the Docker container maps to **8080** on your host to avoid clashing with a local Uvicorn instance running on **8000**. If you need to change this, edit the `ports:` section in `docker-compose.yml`.

> [!IMPORTANT]
> **Static Models:** The Docker image "bakes in" the `model.joblib` and `scaler.joblib` files. If you re-train your model using `train.py`, you **MUST** run `docker-compose up --build` to update the models inside the container.
