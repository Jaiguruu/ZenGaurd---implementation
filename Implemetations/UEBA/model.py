import joblib
import os
import pandas as pd

class UEBAModel:
    def __init__(self, model_path=None):
        if model_path is None:
            # Default path relative to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(current_dir, "implementation result", "zenguard_ueba_model.pkl")
        
        self.model_path = model_path
        self.model = None
        self.load_model()

    def load_model(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"UEBA model not found at {self.model_path}")
        self.model = joblib.load(self.model_path)

    def predict(self, feature_df):
        """
        Returns:
            anomaly_pred: -1 for anomaly, 1 for normal
            raw_score: decision function score
            risk_score: 0–100 continuous risk score
        """
        if self.model is None:
            raise ValueError("Model is not loaded.")
            
        anomaly_pred = self.model.predict(feature_df)[0]
        raw_score = self.model.decision_function(feature_df)[0]

        # --- Risk Scoring Logic (Calibrated for ZenGuard SLAs) ---
        # Normalize decision function to 0–1
        # Isolation Forest typically scores anomalies between -0.1 and -0.4
        min_score, max_score = -0.25, 0.45  
        normalized = (raw_score - min_score) / (max_score - min_score)

        # Clamp between 0 and 1
        normalized = max(0, min(1, normalized))

        # Invert: lower score = higher risk
        risk_score = int((1 - normalized) * 100)
        
        # --- Feature-Aware SLA Boosting ---
        # Ensure high-signal events land in their designated bands
        if feature_df.get('MFA_bypassed', [0]).iloc[0] == 1:
            risk_score = max(risk_score, 95) # Critical
        elif feature_df.get('privilege_change_attempted', [0]).iloc[0] == 1:
            risk_score = max(risk_score, 75) # High
        elif feature_df.get('failed_logins', [0]).iloc[0] >= 5:
            risk_score = max(risk_score, 50) # Medium
            
        return anomaly_pred, raw_score, risk_score
