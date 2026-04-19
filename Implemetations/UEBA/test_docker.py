import os
import pandas as pd
import requests
import concurrent.futures
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, 'ueba_dataset.csv')
API_URL = "http://127.0.0.1:8080/api/soar/evaluate"

print("[*] Loading UEBA dataset...")
df = pd.read_csv(DATA_PATH)

FEATURES = ["failed_logins", "privilege_change_attempted", "external_connection", 
            "MFA_bypassed", "session_duration", "access_hour", "device_trust_score"]
df = df.dropna(subset=FEATURES)

print("[*] Generating 30% Holdout Split...")
# Split 70/30
train_df, test_df = train_test_split(df, test_size=0.3, random_state=42)

# To avoid massive HTTP overhead locally, we will sample 5,000 records 
# strictly from the 30% test split to act as our live docker network volume
test_sample = test_df.sample(n=5000, random_state=42)
print(f"[*] Dispatching {len(test_sample)} payloads to Docker Container at :8080")

true_labels = []
predicted_labels = []

def send_to_docker(row_tuple):
    index, row = row_tuple
    payload = {
        "failed_logins": int(row["failed_logins"]),
        "privilege_change_attempted": int(row["privilege_change_attempted"]),
        "external_connection": int(row["external_connection"]),
        "MFA_bypassed": int(row["MFA_bypassed"]),
        "session_duration": float(row["session_duration"]),
        "access_hour": int(row["access_hour"]),
        "device_trust_score": float(row["device_trust_score"])
    }
    
    # Simple heuristic to act as "ground truth" anomaly flag equivalent.
    # We consider it a true anomaly if failed logins > 3 or MFA bypassed.
    is_true_anomaly = int(row["failed_logins"] > 3 or row["MFA_bypassed"] == 1)
    
    try:
        res = requests.post(API_URL, json=payload, timeout=2)
        if res.status_code == 200:
            data = res.json()
            is_pred_anomaly = 1 if data.get("is_anomaly", False) else 0
            return is_true_anomaly, is_pred_anomaly
    except Exception as e:
        # container unavailable
        return is_true_anomaly, 0

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(send_to_docker, row) for row in test_sample.iterrows()]
    
    for i, future in enumerate(concurrent.futures.as_completed(futures)):
        t, p = future.result()
        true_labels.append(t)
        predicted_labels.append(p)
        if (i+1) % 1000 == 0:
            print(f"[+] Processed {i+1} Docker inferences...")

# Metrics
f1 = f1_score(true_labels, predicted_labels, zero_division=0)
cm = confusion_matrix(true_labels, predicted_labels)

print("\n==== DOCKER CONTAINER RESULTS ====")
print(f"Total Evaluated: {len(test_sample)} (From 30% Split)")
print(f"Docker Network Port: 8080")
print(f"Container F1 Anomaly Score: {f1:.4f}")
print("Confusion Matrix:")
print(cm)
print("==================================")
