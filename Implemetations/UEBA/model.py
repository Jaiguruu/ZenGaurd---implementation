import joblib
import os
import numpy as np
import warnings

# Suppress the irritating InconsistentVersionWarning from Scikit-Learn
warnings.filterwarnings("ignore", category=UserWarning)

class UEBAModel:
    def __init__(self, model_path=None):
        # We ignore the old model_path from the dashboard to forcefully load the new .joblib artifacts
        self.model_dir = os.path.dirname(os.path.abspath(__file__))
        
        self.model_file = os.path.join(self.model_dir, "model.joblib")
        self.scaler_file = os.path.join(self.model_dir, "scaler.joblib")
        
        self.model = None
        self.scaler = None
        self.load_artifacts()

    def load_artifacts(self):
        if not os.path.exists(self.model_file) or not os.path.exists(self.scaler_file):
            raise FileNotFoundError(f"UEBA model/scaler artifacts not found in {self.model_dir}. Please run train.py.")
        self.model = joblib.load(self.model_file)
        self.scaler = joblib.load(self.scaler_file)

    def predict(self, feature_df):
        """
        Returns:
            anomaly_pred: -1 for anomaly, 1 for normal
            raw_score: decision function score
            risk_score: 0–100 continuous risk score
        """
        if self.model is None or self.scaler is None:
            raise ValueError("Model is not loaded.")
            
        # Re-order the pandas DataFrame columns to match what the Isolation Forest requires during training
        feature_order = [
            'failed_logins', 'privilege_change_attempted', 'external_connection', 
            'MFA_bypassed', 'session_duration', 'access_time', 'device_trust_score'
        ]
        
        features_to_scale = feature_df[feature_order].copy()
        features_to_scale.rename(columns={'access_time': 'access_hour'}, inplace=True)
        
        features_scaled = self.scaler.transform(features_to_scale)
        
        anomaly_pred = self.model.predict(features_scaled)[0]
        raw_score = self.model.decision_function(features_scaled)[0]

        # --- Risk Scoring Logic (Calibrated for ZenGuard SLAs) ---
        # Normalize decision function to 0–1
        # Isolation Forest typically scores anomalies between -0.1 and -0.4
        min_score, max_score = -0.25, 0.45  
        normalized = (raw_score - min_score) / (max_score - min_score)

        # Clamp between 0 and 1
        normalized = max(0, min(1, normalized))

        # Invert: lower score = higher risk
        risk_score = int((1 - normalized) * 100)

        # Context-Aware SLA Enforcement (replicated from old logic & model_server.py)
        mfa_bypassed = int(feature_df['MFA_bypassed'].iloc[0])
        failed_logins = int(feature_df['failed_logins'].iloc[0])
        privilege_change_attempted = int(feature_df['privilege_change_attempted'].iloc[0])

        if mfa_bypassed == 1 and failed_logins > 3:
            risk_score = 100
        elif mfa_bypassed == 1:
            risk_score = max(risk_score, 95)
        elif privilege_change_attempted == 1:
            risk_score = max(risk_score, 75)
        elif failed_logins >= 5:
            risk_score = max(risk_score, 50)
            
        return anomaly_pred, raw_score, risk_score
