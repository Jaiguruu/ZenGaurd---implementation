import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "ueba_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.joblib")

FEATURES = [
    "failed_logins", "privilege_change_attempted", "external_connection", 
    "MFA_bypassed", "session_duration", "access_hour", "device_trust_score"
]

def run_tests():
    print("--- Running UEBA Unit Tests (Offline Validation) ---")
    df = pd.read_csv(DATASET_PATH).dropna(subset=FEATURES)
    df['is_anomaly'] = df['attack_category'].apply(lambda x: 1 if x == 'benign' else -1)
    
    # Precise 30% reproduction
    X = df[FEATURES]
    y = df['is_anomaly']
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    
    print(f"\n[+] Testing successful. Handled {len(X_test)} verification rows.")
    print("=== Classification Report ===")
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    run_tests()
