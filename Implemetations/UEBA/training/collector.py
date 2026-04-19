import csv
import json
import logging
from fastapi import FastAPI, Request
from datetime import datetime
import uvicorn
import os

app = FastAPI()

CSV_FILE = "zenguard_collected_features.csv"
FEATURE_COLS = [
    "event_id",
    "attack_category",
    "session_duration",
    "failed_logins",
    "access_time_hour",
    "device_trust_score",
    "privilege_change_attempted",
    "external_connection",
    "MFA_bypassed",
    "event_type",
    "severity"
]

@app.on_event("startup")
def startup_event():
    # Write header if file doesn't exist
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(FEATURE_COLS)

@app.post("/api/ingest")
async def ingest(request: Request):
    payload = await request.json()
    events = payload.get("events", [])
    
    rows = []
    for evt in events:
        # Extract features
        access_time_raw = evt.get("access_time", evt.get("timestamp", ""))
        try:
            dt = datetime.fromisoformat(access_time_raw.replace("Z", "+00:00"))
            access_hour = dt.hour
        except Exception:
            access_hour = 12

        row = [
            evt.get("event_id", ""),
            evt.get("attack_category", "unknown"),
            float(evt.get("session_duration", 0.0)),
            int(evt.get("failed_logins", 0)),
            int(access_hour),
            float(evt.get("device_trust_score", 0.5)),
            int(evt.get("privilege_change_attempted", 0)),
            int(evt.get("external_connection", 0)),
            int(evt.get("MFA_bypassed", 0)),
            evt.get("event_type", "unknown"),
            evt.get("severity", "low")
        ]
        rows.append(row)

    if rows:
        with open(CSV_FILE, mode="a", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(rows)
            
    return {"status": "ok", "processed": len(rows)}

@app.post("/api/collect/stop")
async def stop_collect():
    import sys
    sys.exit(0)
    return {"status": "stopped"}

@app.get("/api/collect/status")
async def get_status():
    if not os.path.exists(CSV_FILE):
        return {"rows": 0}
    with open(CSV_FILE, "r") as f:
        count = sum(1 for line in f) - 1 # subtract header
    return {"rows": count}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5050)
