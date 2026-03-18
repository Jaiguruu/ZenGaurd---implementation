from soar_engine import SOAREngine
import json

def test_standalone_soar():
    print("=== ZenGuard Standalone SOAR Verification ===")
    soar = SOAREngine()
    
    # Test 1: High Risk Case
    print("\n[Test 1] Risk 98 - Expect 3 actions")
    actions = soar.evaluate_and_respond(98)
    if len(actions) == 3:
        print("✅ SUCCESS: 3 playbooks triggered.")
    else:
        print(f"❌ FAILURE: Expected 3, got {len(actions)}")

    # Test 2: Low Risk Case
    print("\n[Test 2] Risk 40 - Expect 0 actions")
    actions = soar.evaluate_and_respond(40)
    if len(actions) == 0:
        print("✅ SUCCESS: No playbooks triggered for low risk.")
    else:
        print(f"❌ FAILURE: Triggered {len(actions)} playbooks unexpectedly.")

    # Test 3: Prioritization
    print("\n[Test 3] MFA Bypass Prioritization")
    context = {"MFA_bypassed": 1}
    # We'll re-initialize or clear history if needed, but here we just check the return
    actions = soar.evaluate_and_respond(96, incident_context=context)
    if actions[0]['playbook'] == "Enforce MFA":
        print("✅ SUCCESS: MFA Enforcement prioritized.")
    else:
        print(f"❌ FAILURE: Priority incorrect. First action was {actions[0]['playbook']}")

    print("\n=== Verification Complete ===")

if __name__ == "__main__":
    test_standalone_soar()
