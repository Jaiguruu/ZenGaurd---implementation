import os
import pandas as pd
import joblib
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Map to the specific model artifacts
UEBA_PATH = os.path.abspath(os.path.join(BASE_DIR, '..', 'UEBA'))
MODEL_PATH = os.path.join(UEBA_PATH, 'model.joblib')
SCALER_PATH = os.path.join(UEBA_PATH, 'scaler.joblib')
DATA_PATH = os.path.join(UEBA_PATH, 'ueba_dataset.csv')
OUTPUT_PATH = os.path.join(BASE_DIR, 'soar_real_training_data.csv')

print("[*] Performing offline vectorized Risk extraction...")

try:
    df = pd.read_csv(DATA_PATH)
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except Exception as e:
    print(f"[!] Error loading UEBA artifacts: {e}")
    exit(1)

FEATURES = ["failed_logins", "privilege_change_attempted", "external_connection", 
            "MFA_bypassed", "session_duration", "access_hour", "device_trust_score"]

df = df.dropna(subset=FEATURES)

# Suppress the scikit-learn missing feature names warning for the bulk transform
import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    # Transform in bulk
    features_scaled = scaler.transform(df[FEATURES])

raw_scores = model.score_samples(features_scaled)
predictions = model.predict(features_scaled)

# Mathematically apply the same risk translation used in model_server.py
# Risk Score = clamp((-raw_score + 0.5) * 100, 0, 100)
risk_scores = np.clip((-raw_scores + 0.5) * 100, 0, 100).astype(int)

# Create deterministic override blocks for strict violations
mask = (df["MFA_bypassed"] == 1) & (df["failed_logins"] > 3)
risk_scores[mask] = 100

# Compile final RL state representation columns
df['risk_score'] = risk_scores
df['is_anomaly'] = predictions == -1

# We just drop the extra L4 variables and save what SOAR cares about
# The context is MFA_bypassed, which is already in the dataframe
final_df = df[['risk_score', 'MFA_bypassed', 'is_anomaly']]

final_df.to_csv(OUTPUT_PATH, index=False)
print(f"[*] SUCCESSFULLY EXTRACTED {len(final_df)} REAL DISTRIBUTIONS to {OUTPUT_PATH}")
