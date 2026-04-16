# ZenGuard SIEM & UEBA Stack Runbook

This guide explains how to start the complete ZenGuard environment, including the unified ELK stack, the Flask Dashboard, and the Python background agents.

## Directory Structure Changes (Note)
The `docker-compose.yml`, `siem_listener.py`, `zenguard_replayer.py`, and `run_detection_engine.py` are now located inside the `siem/` directory. The main dashboard is currently located in the `dashboard/` directory.

---

## 🚀 Step-by-Step Execution

### 1. Start the ELK Infrastructure (Docker)
This spins up Elasticsearch, Logstash, and Kibana in the background.

```powershell
cd "h:\Desktop\Mini Project\Code\siemfinal\siem"
docker compose up -d
```
> **Wait ~60 seconds** after this step for Elasticsearch to fully initialize before starting the python scripts.
* **Elasticsearch**: `http://localhost:9200`
* **Kibana**: `http://localhost:5601`

### 2. Start the Flask Dashboard
This launches the web interface for monitoring alerts and UEBA predictions.
```powershell
cd "h:\Desktop\Mini Project\Code\siemfinal\dashboard"
python app.py
```
* **Dashboard**: `http://localhost:5001` *(Note: Port 5000 is reserved by Logstash for raw TCP log ingestion).*

### 3. Start the SIEM Listener
The listener watches the Elasticsearch indices for events, extracting ML features and feeding them to the framework.
```powershell
cd "h:\Desktop\Mini Project\Code\siemfinal\siem"
python siem_listener.py
```

### 4. Start the Log Replayer (Synthetic Data)
The replayer feeds dataset logs into Logstash (which then goes to Elasticsearch) simulating a live network environment.
```powershell
cd "h:\Desktop\Mini Project\Code\siemfinal\siem"
python zenguard_replayer.py
```

### 5. Start the Detection Engine
The detection engine polls Elasticsearch directly to execute correlation rules (Brute Force, Data Exfil, etc.) and post resulting structured alerts back to the dashboard.
```powershell
cd "h:\Desktop\Mini Project\Code\siemfinal\siem"
python run_detection_engine.py
```

---

## Troubleshooting & Resetting

- **Network Collisions:** If Docker Compose errors with "Pool overlaps with other one on this address space", run:
  ```powershell
  docker rm -f zenguard_elasticsearch zenguard_kibana zenguard_logstash
  docker network prune
  ```
  Then attempt `docker compose up -d` again.
- Ensure the `.venv` or Python environment you're using has all requirements installed from `siem/requirements.txt` and `dashboard/requirements.txt`.
