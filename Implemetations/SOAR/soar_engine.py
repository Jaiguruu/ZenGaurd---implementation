import datetime
import time

class SOARPlaybook:
    def __init__(self, name, description):
        self.name = name
        self.description = description

    def execute(self, user_id="Unknown", context=None):
        """
        Simulates the execution of a security playbook.
        """
        # In a real-world scenario, this would involve API calls to:
        # - Identity Providers (Okta, Azure AD)
        # - EDR/Antivirus (CrowdStrike, SentinelOne)
        # - Firewalls/WAFs (Palo Alto, Cloudflare)
        
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

    def evaluate_and_respond(self, risk_score, incident_context=None, callback=None):
        """
        Evaluates the risk score and executes relevant playbooks.
        Allows an optional callback for progress visualization.
        """
        triggered_actions = []
        
        # Threshold for automated response
        if risk_score >= 95:
            playbook_keys = ["enforce_mfa", "isolate_endpoint", "revoke_privileges"]
            
            # Context-aware prioritization
            if incident_context and incident_context.get('MFA_bypassed') == 1:
                # Prioritize MFA if it was already bypassed
                playbook_keys = ["enforce_mfa", "revoke_privileges", "isolate_endpoint"]
            
            for key in playbook_keys:
                if callback:
                    callback(f"Initiating {self.playbooks[key].name}...")
                    time.sleep(0.5) # Simulate backend processing latency
                
                log = self.playbooks[key].execute(context=incident_context)
                triggered_actions.append(log)
                self.history.append(log)
                
                if callback:
                    callback(f"Successfully executed: {self.playbooks[key].name}", status="success")
        
        return triggered_actions

    def get_history(self):
        return self.history
