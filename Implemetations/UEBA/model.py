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
            risk_score: 95 for anomaly, 50 for normal
        """
        if self.model is None:
            raise ValueError("Model is not loaded.")
            
        anomaly_pred = self.model.predict(feature_df)[0]
        raw_score = self.model.decision_function(feature_df)[0]
        risk_score = 95 if anomaly_pred == -1 else 50
        
        return anomaly_pred, raw_score, risk_score
