import requests
import time
import subprocess
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
API_URL = "http://127.0.0.1:8000"

def test_integration():
    print("--- ZenGuard SIEM-to-UEBA Integration Test ---")
    
    # 1. Start uvicorn as subprocess
    print("[*] Starting Model Server...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "model_server:app", "--port", "8000"], 
        cwd=BASE_DIR, 
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL
    )
    # Wait for startup
    ready = False
    for i in range(10):
        try:
            resp = requests.get(f"{API_URL}/health")
            if resp.status_code == 200:
                ready = True
                break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            
    if not ready:
        raise Exception("Model Server failed to start completely.")
        
    try:
        print("[+] Healthcheck passed.")

        # Synthetic SIEM payload (Benign)
        payload_benign = {
            "failed_logins": 0, "privilege_change_attempted": 0, 
            "external_connection": 0, "MFA_bypassed": 0, 
            "session_duration": 4.5, "access_hour": 10, "device_trust_score": 0.8
        }
        res = requests.post(f"{API_URL}/api/soar/evaluate", json=payload_benign).json()
        assert res["is_anomaly"] == False, f"Benign traffic triggered anomaly! Score: {res['risk_score']}"
        print(f"[+] Benign validation passed. Risk Score: {res['risk_score']}")

        # Synthetic SIEM payload (Brute Force)
        payload_attack = {
            "failed_logins": 6, "privilege_change_attempted": 1, 
            "external_connection": 1, "MFA_bypassed": 1, 
            "session_duration": 1.5, "access_hour": 3, "device_trust_score": 0.2
        }
        res2 = requests.post(f"{API_URL}/api/soar/evaluate", json=payload_attack).json()
        assert res2["is_anomaly"] == True, "Brute force bypassed detection!"
        print(f"[+] Insider Attack validation passed. Risk Score: {res2['risk_score']}")
        
        # Verify SOAR feature loopback
        assert res2["feature_context"]["MFA_bypassed"] == 1
        print("[+] SOAR Context passed back properly.")
        
        print("\n=== INTEGRATION TESTS SUCCESSFUL ===")
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    test_integration()
