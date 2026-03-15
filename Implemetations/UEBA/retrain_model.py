import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Ensure result directory exists
result_dir = "implementation result"
os.makedirs(result_dir, exist_ok=True)

# Synthetic data generation (matches notebook exactly)
np.random.seed(42)
n_samples = 15000
session_duration = np.random.normal(loc=2.0, scale=1.5, size=n_samples).clip(0.1, 10)
failed_logins = np.random.poisson(lam=0.2, size=n_samples).clip(0, 3)
access_time = np.random.randint(8, 19, size=n_samples)
device_trust_score = np.random.normal(loc=0.9, scale=0.1, size=n_samples).clip(0.5, 1.0)
privilege_change_attempted = np.random.choice([0, 1], p=[0.99, 0.01], size=n_samples)
external_connection = np.random.choice([0, 1], p=[0.8, 0.2], size=n_samples)
MFA_bypassed = np.zeros(n_samples)

data = pd.DataFrame({
    'session_duration': session_duration,
    'failed_logins': failed_logins,
    'access_time': access_time,
    'device_trust_score': device_trust_score,
    'privilege_change_attempted': privilege_change_attempted,
    'external_connection': external_connection,
    'MFA_bypassed': MFA_bypassed
})

n_anomalies = int(n_samples * 0.15)
anomaly_indices = np.random.choice(n_samples, n_anomalies, replace=False)
data.loc[anomaly_indices, 'failed_logins'] = np.random.randint(4, 15, size=n_anomalies)
data.loc[anomaly_indices, 'access_time'] = np.random.choice([1, 2, 3, 4, 22, 23], size=n_anomalies)
data.loc[anomaly_indices, 'device_trust_score'] = np.random.uniform(0.1, 0.5, size=n_anomalies)
data.loc[anomaly_indices, 'privilege_change_attempted'] = np.random.choice([0, 1], p=[0.2, 0.8], size=n_anomalies)
data.loc[anomaly_indices, 'external_connection'] = 1
data.loc[anomaly_indices, 'MFA_bypassed'] = np.random.choice([0, 1], p=[0.5, 0.5], size=n_anomalies)

features = ['session_duration', 'failed_logins', 'access_time', 'device_trust_score', 
            'privilege_change_attempted', 'external_connection', 'MFA_bypassed']
X = data[features]

print("Training ZenGuard UEBA Isolation Forest Model...")
ueba_model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42, n_jobs=-1)
ueba_model.fit(X)

model_path = os.path.join(result_dir, "zenguard_ueba_model.pkl")
joblib.dump(ueba_model, model_path)
print(f"Model successfully optimized and saved for current environment: {model_path}")
