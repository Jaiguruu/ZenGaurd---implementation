import pandas as pd
import joblib
import os
import sys
import json

# Ensure the local directory is in the path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from soar_engine import SOAREngine

def test_soar_integration():
    print("--- Starting ZenGuard SOAR Verification ---")
    
    # 1. Initialize Engine
    soar = SOAREngine()
    
    # 2. Test Case: Normal Activity (Risk 50)
    print("\n[Test 1] Simulating Normal Activity...")
    actions_normal = soar.evaluate_and_respond(50)
    if len(actions_normal) == 0:
        print("✅ SUCCESS: No playbooks triggered for Risk 50.")
    else:
        print(f"❌ FAILURE: Triggered {len(actions_normal)} playbooks for Risk 50.")

    # 3. Test Case: High Risk (Risk 95)
    print("\n[Test 2] Simulating High Risk Anomaly...")
    actions_high = soar.evaluate_and_respond(95)
    if len(actions_high) == 3:
        print("✅ SUCCESS: 3 playbooks triggered for Risk 95.")
        for action in actions_high:
            print(f"  - Triggered: {action['playbook']}")
    else:
        print(f"❌ FAILURE: Expected 3 playbooks, got {len(actions_high)}.")

    # 4. Test Case: Context-Aware Prioritization
    print("\n[Test 3] Simulating MFA Bypass Context...")
    context = {'MFA_bypassed': 1}
    actions_priority = soar.evaluate_and_respond(95, feature_context=context)
    if actions_priority[0]['playbook'] == "Enforce MFA":
        print("✅ SUCCESS: MFA Enforcement prioritized due to bypass context.")
    else:
        print(f"❌ FAILURE: MFA Enforcement not prioritized. First action: {actions_priority[0]['playbook']}")

    # 5. Check History
    print("\n[Test 4] Checking SOAR History...")
    history = soar.get_history()
    if len(history) >= 6:
        print(f"✅ SUCCESS: History recorded {len(history)} executions.")
    else:
        print(f"❌ FAILURE: History only recorded {len(history)} executions.")

    print("\n--- Verification Complete ---")

if __name__ == "__main__":
    test_soar_integration()
