import datetime
import os
try:
    from .rl_agent import SOARRLAgent
except ImportError:
    from rl_agent import SOARRLAgent

class SOARPlaybook:
    def __init__(self, name, description):
        self.name = name
        self.description = description

    def execute(self, user_id="Unknown", context=None):
        # In a real implementation, this would call external APIs (IdP, EDR, Firewall)
        # For this prototype, we simulate execution and return a status log.
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "timestamp": timestamp,
            "playbook": self.name,
            "action": self.description,
            "status": "SUCCESS",
            "target": user_id
        }

class SOAREngine:
    def __init__(self):
        self.playbooks = {
            "enforce_mfa": SOARPlaybook("Enforce MFA", "Triggering multi-factor authentication challenge for the user."),
            "isolate_endpoint": SOARPlaybook("Isolate Endpoint", "Quarantining the device via EDR integration to prevent lateral movement."),
            "revoke_privileges": SOARPlaybook("Revoke Privileges", "Temporarily revoking administrative privileges and terminating active sessions.")
        }
        self.history = []
        
        self.fallback_mode = False
        try:
            self.agent = SOARRLAgent()
            qtable_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soar_qtable.pkl")
            if os.path.exists(qtable_path):
                self.agent.load(qtable_path)
            else:
                print("Warning: soar_qtable.pkl not found. Run train_rl_agent.py to train the agent.")
                self.fallback_mode = True
        except Exception as e:
            print(f"Warning: RL Agent initialization failed ({e}). Falling back to rule-based logic.")
            self.fallback_mode = True

    def evaluate_and_respond(self, risk_score, feature_context=None):
        """
        Evaluates the risk score and executes relevant playbooks.
        Returns a list of execution logs.
        """
        # ── RL Thinking Log ──────────────────────────────────────
        self.last_rl_explanation = None
        if not self.fallback_mode:
            try:
                self.last_rl_explanation = self.agent.explain_decision(
                    risk_score, feature_context
                )
            except Exception:
                pass
        # ─────────────────────────────────────────────────────────

        triggered_actions = []
        
        if self.fallback_mode:
            # Core Implementation Rule from Base Paper:
            # If Risk Score is 95, trigger all standard mitigations.
            if risk_score >= 95:
                # Execute standard high-risk playbooks
                playbook_keys = ["enforce_mfa", "isolate_endpoint", "revoke_privileges"]
                
                # Context-aware prioritization (SOAR Optimization)
                if feature_context and feature_context.get('MFA_bypassed') == 1:
                    # If MFA was bypassed, prioritize the MFA challenge first
                    playbook_keys = ["enforce_mfa", "revoke_privileges", "isolate_endpoint"]
                
                for key in playbook_keys:
                    log = self.playbooks[key].execute(context=feature_context)
                    triggered_actions.append(log)
                    self.history.append(log)
        else:
            state = self.agent.get_state(risk_score, feature_context)
            action_code = self.agent.choose_action(state, explore=False)
            
            # --- Deterministic Policy Override (SLA Compliance) ---
            playbook_keys = []
            if risk_score >= 95:
                # Critical Band: All 3 playbooks
                playbook_keys = ["enforce_mfa", "isolate_endpoint", "revoke_privileges"]
            elif risk_score >= 75:
                # High Band: MFA + Isolate
                playbook_keys = ["enforce_mfa", "isolate_endpoint"]
            elif risk_score >= 50:
                # Medium Band: Enforce MFA
                playbook_keys = ["enforce_mfa"]
            else:
                # Low Band: Based on RL Agent (usually empty)
                if action_code == 1:
                    playbook_keys = ["enforce_mfa"]
                # (Other RL-driven edge cases can be added here)
                
            # Context-aware prioritization (SOAR Optimization)
            if feature_context and feature_context.get('MFA_bypassed') == 1:
                if "enforce_mfa" in playbook_keys:
                    # Ensure MFA is the first action taken if bypassed
                    playbook_keys.remove("enforce_mfa")
                    playbook_keys.insert(0, "enforce_mfa")

            for key in playbook_keys:
                log = self.playbooks[key].execute(context=feature_context)
                triggered_actions.append(log)
                self.history.append(log)
        
        return triggered_actions

    def get_history(self):
        return self.history

    def get_last_rl_explanation(self):
        """Returns the RL agent's last decision explanation dict."""
        return getattr(self, 'last_rl_explanation', None)
