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

    # Dynamic Risk Mapping using the model's actual decision boundary (offset_)
    # The offset_ separates normal from anomalous in the raw score space.
    # We anchor the offset at 74 and interpolate two zones:
    #   Zone 1 (Benign):   [max_score ... offset_] -> [5 ... 74]
    #   Zone 2 (Anomaly):  [offset_   ... min_score] -> [75 ... 100]
    # A floor of 5 (not 0) signals the SIEM is active and seeing traffic.
    offset = model.offset_
    if raw_score >= offset:
        # Normal zone: interpolate 5-74
        max_s = -0.40  # empirical max (most benign, updated dynamically via clamp)
        risk_score = int(np.interp(raw_score, [offset, max_s], [74, 5]))
    else:
        # Anomalous zone: interpolate 75-100
        min_s = -0.80  # empirical min (most anomalous, updated dynamically via clamp)
        risk_score = int(np.interp(raw_score, [min_s, offset], [100, 75]))
    risk_score = int(np.clip(risk_score, 5, 100))

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
