import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.joblib")

app = FastAPI(title="ZenGuard UEBA Inference API", version="2.0")

# Globals for lazy loading
model = None
scaler = None

class UEBAPayload(BaseModel):
    failed_logins: int
    privilege_change_attempted: int
    external_connection: int
    MFA_bypassed: int
    session_duration: float
    access_hour: int
    device_trust_score: float

@app.on_event("startup")
def load_artifacts():
    global model, scaler
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("[*] UEBA Model and Scaler loaded successfully.")
    else:
        print("[!] Warning: Model artifacts not found. Run train.py first.")

@app.get("/health")
def health_check():
    return {"status": "ok", "model_loaded": model is not None}

@app.post("/api/ueba/predict")
def predict_anomaly(payload: UEBAPayload):
    """
    Standard ML diagnostic endpoint.
    """
    if model is None or scaler is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Train the model first.")

    features = np.array([[
        payload.failed_logins,
        payload.privilege_change_attempted,
        payload.external_connection,
        payload.MFA_bypassed,
        payload.session_duration,
        payload.access_hour,
        payload.device_trust_score
    ]])

    features_scaled = scaler.transform(features)
    prediction = model.predict(features_scaled)[0]
    raw_score = model.score_samples(features_scaled)[0]

    return {
        "is_anomaly": bool(prediction == -1),
        "anomaly_score": float(raw_score)
    }

@app.post("/api/soar/evaluate")
def soar_evaluate(payload: UEBAPayload):
    """
    Decoupled SOAR endpoint. Bridges the gap between the Isolation Forest Unsupervised engine
    and the SOAR RL/Deterministic agent.
    """
    if model is None or scaler is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Train the model first.")

    features = np.array([[
        payload.failed_logins,
        payload.privilege_change_attempted,
        payload.external_connection,
        payload.MFA_bypassed,
        payload.session_duration,
        payload.access_hour,
        payload.device_trust_score
    ]])

    features_scaled = scaler.transform(features)
    prediction = model.predict(features_scaled)[0]
    raw_score = model.score_samples(features_scaled)[0]

    # Convert the ISO raw score [-0.5, 0.5] to a 0-100 risk integer.
    # A highly negative score is highly anomalous. Let's invert it for risk.
    # Example: raw_score = -0.37 -> (-(-0.37) + 0.5) * 100 = 87
    risk_score = int(max(0, min(100, (-raw_score + 0.5) * 100)))

    # Push to 100 manually if strict behavioral limits are completely violated
    # e.g. Brute forces skipping MFA.
    if payload.MFA_bypassed == 1 and payload.failed_logins > 3:
        risk_score = 100

    return {
        "risk_score": risk_score,
        "is_anomaly": bool(prediction == -1),
        "anomaly_score": float(raw_score),
        "feature_context": {
            "MFA_bypassed": payload.MFA_bypassed,
            "privilege_change_attempted": payload.privilege_change_attempted
        },
        "soar_ready": True
    }
