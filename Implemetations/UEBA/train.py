import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "ueba_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.joblib")

FEATURES = [
    "failed_logins", 
    "privilege_change_attempted", 
    "external_connection", 
    "MFA_bypassed", 
    "session_duration", 
    "access_hour",
    "device_trust_score"
]

def train_model():
    print("[*] Loading dataset...")
    if not os.path.exists(DATASET_PATH):
        print(f"[!] Error: {DATASET_PATH} not found. Run generate_dataset.py first.")
        return

    df = pd.read_csv(DATASET_PATH)
    print(f"[*] Loaded {len(df)} records.")

    # Drop nulls just in case
    df = df.dropna(subset=FEATURES)

    # Convert attack_category to binary label for evaluation
    # 1: Normal (Inlier)
    # -1: Anomaly (Outlier)
    df['is_anomaly'] = df['attack_category'].apply(lambda x: 1 if x == 'benign' else -1)

    print("[*] Splitting dataset (70% Train, 30% Test)...")
    X = df[FEATURES]
    y = df['is_anomaly']

    # We split, but note that Isolation Forest doesn't use 'y_train' during fitting
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    print("[*] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save scaler immediately
    joblib.dump(scaler, SCALER_PATH)

    print("[*] Training Isolation Forest (Contamination = 0.05)...")
    # Setting contamination to 5% based on plan
    model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42, n_jobs=-1)
    
    # Fit strictly on the feature data (unsupervised)
    model.fit(X_train_scaled)

    # Save model
    joblib.dump(model, MODEL_PATH)

    print("\n[*] Validating model on 30% hold-out set...")
    # Predict (-1 is anomaly, 1 is normal)
    y_pred = model.predict(X_test_scaled)

    print("\n=== Classification Report ===")
    # map labels for easier reading (1 -> benign, -1 -> attack)
    print("Class 1 = Normal/Benign, Class -1 = Anomaly/Attack")
    print(classification_report(y_test, y_pred))

    print("=== Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred))
    
    print("\n[+] Training complete!")
    print(f"[+] Model saved to: {MODEL_PATH}")
    print(f"[+] Scaler saved to: {SCALER_PATH}")

if __name__ == "__main__":
    train_model()
