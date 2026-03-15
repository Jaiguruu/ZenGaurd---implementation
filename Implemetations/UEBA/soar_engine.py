import datetime

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

    def evaluate_and_respond(self, risk_score, feature_context=None):
        """
        Evaluates the risk score and executes relevant playbooks.
        Returns a list of execution logs.
        """
        triggered_actions = []
        
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
        
        return triggered_actions

    def get_history(self):
        return self.history
