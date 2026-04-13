import os
import sys
import pandas as pd
import json

# Add the parent directory to path for cross-module imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from UEBA.model import UEBAModel
from SOAR.engine import SOAREngine

def run_test():
    print("--- ZenGuard End-to-End Verification Runner ---\n")
    
    # Initialize Engines
    model_path = os.path.join(parent_dir, "UEBA", "implementation result", "zenguard_ueba_model.pkl")
    ueba = UEBAModel(model_path=model_path)
    soar = SOAREngine()
    
    scenarios = [
        {
            "name": "Scenario 1: Normal Activity",
            "expected_band": "LOW", "expected_playbooks": 0,
            "data": {
                "session_duration": 1.5, "failed_logins": 0, "access_time": 14, 
                "device_trust_score": 0.95, "privilege_change_attempted": 0, 
                "external_connection": 0, "MFA_bypassed": 0
            }
        },
        {
            "name": "Scenario 2: Brute Force Attempt",
            "expected_band": "MEDIUM", "expected_playbooks": 1,
            "data": {
                "session_duration": 0.2, "failed_logins": 8, "access_time": 22, 
                "device_trust_score": 0.3, "privilege_change_attempted": 0, 
                "external_connection": 1, "MFA_bypassed": 0
            }
        },
        {
            "name": "Scenario 3: High Risk Anomaly",
            "expected_band": "HIGH", "expected_playbooks": 2,
            "data": {
                "session_duration": 10.0, "failed_logins": 2, "access_time": 1, 
                "device_trust_score": 0.15, "privilege_change_attempted": 1, 
                "external_connection": 1, "MFA_bypassed": 0
            }
        },
        {
            "name": "Scenario 4: Critical (MFA Bypass)",
            "expected_band": "CRITICAL", "expected_playbooks": 3,
            "data": {
                "session_duration": 4.5, "failed_logins": 2, "access_time": 3, 
                "device_trust_score": 0.1, "privilege_change_attempted": 1, 
                "external_connection": 1, "MFA_bypassed": 1
            }
        }
    ]
    
    features = ['session_duration', 'failed_logins', 'access_time', 'device_trust_score', 
                'privilege_change_attempted', 'external_connection', 'MFA_bypassed']

    for scenario in scenarios:
        print(f"--- Running {scenario['name']} ---")
        input_df = pd.DataFrame([scenario['data']])[features]
        
        # UEBA
        pred, raw, risk = ueba.predict(input_df)
        
        band = "LOW"
        if risk >= 95: band = "CRITICAL"
        elif risk >= 75: band = "HIGH"
        elif risk >= 50: band = "MEDIUM"
        
        band_pass = "PASS" if band == scenario['expected_band'] else f"FAIL (Got {band})"
        print(f"UEBA Outcome: Risk Score = {risk} | Band = {band} | [{band_pass}]")
        
        # SOAR
        actions = soar.evaluate_and_respond(risk, scenario['data'])
        playbook_count = len(actions)
        playbook_pass = "PASS" if playbook_count == scenario['expected_playbooks'] else f"FAIL (Got {playbook_count})"
        
        print(f"SOAR Outcome: {playbook_count} Playbooks Triggered | [{playbook_pass}]")
        if actions:
            for action in actions:
                print(f"  - {action['playbook']}")
        print("")

if __name__ == "__main__":
    run_test()
