import os
import sys

# Add the parent directory (Implemetations) to path for cross-module imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from SOAR.engine import SOAREngine

DIVIDER = "=" * 65

def run_rl_thinking_test():
    print(DIVIDER)
    print("   ZenGuard - RL Agent Decision Transparency Report")
    print(DIVIDER)

    soar = SOAREngine()

    test_cases = [
        {
            "label": "SCENARIO 1 - Normal Activity",
            "risk_score": 20,
            "context": {"MFA_bypassed": 0}
        },
        {
            "label": "SCENARIO 2 - Brute Force (Medium Risk)",
            "risk_score": 62,
            "context": {"MFA_bypassed": 0}
        },
        {
            "label": "SCENARIO 3 - High Risk Anomaly",
            "risk_score": 85,
            "context": {"MFA_bypassed": 0}
        },
        {
            "label": "SCENARIO 4 - Critical Threat (MFA Bypass)",
            "risk_score": 97,
            "context": {"MFA_bypassed": 1}
        }
    ]

    for case in test_cases:
        print(f"\n{DIVIDER}")
        print(f"  {case['label']}")
        print(DIVIDER)

        # Trigger the engine so RL explanation is generated
        actions = soar.evaluate_and_respond(case["risk_score"], case["context"])

        # Get the RL thought log
        explanation = soar.get_last_rl_explanation()

        if explanation is None:
            print("  [RL Agent not available - fallback mode active]")
        else:
            # Print reasoning trace line by line
            for line in explanation["reasoning_trace"]:
                print(f"  {line}")

        # Print what the deterministic policy actually enforced
        print(f"")
        print(f"  DETERMINISTIC POLICY ENFORCED:")
        if actions:
            for a in actions:
                print(f"    [OK] {a['playbook']}")
        else:
            print(f"    [OK] No playbooks (Low risk - no action needed)")

        # Show agreement/override status
        rl_action = explanation["rl_best_action"] if explanation else "N/A"
        
        if explanation:
            agreed = (
                (case["risk_score"] >= 95 and "All 3" in rl_action) or
                (50 <= case["risk_score"] < 75 and "MFA only" in rl_action) or
                (case["risk_score"] < 50 and "Do Nothing" in rl_action)
            )
            verdict = "[OK] RL AGREES with policy" if agreed else \
                      "[!!] RL OVERRIDDEN by deterministic policy (SLA enforcement)"
            print(f"")
            print(f"  VERDICT: {verdict}")

    print(f"\n{DIVIDER}")
    print("  Test Complete.")
    print(DIVIDER)

if __name__ == "__main__":
    run_rl_thinking_test()
