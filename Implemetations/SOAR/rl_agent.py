import numpy as np
import pickle
import random
import os

class SOARRLAgent:
    """
    Reinforcement Learning (Q-Learning) agent for SOAR decision making.
    
    State space (tuple):
    - risk_band: 0=low(0-49), 1=medium(50-74), 2=high(75-94), 3=critical(95-100)
    - mfa_bypassed: 0 or 1
    - anomaly_flag: 0 or 1 (risk_score > 74)
    
    Action space (0-6 discrete actions):
    0: Do nothing
    1: enforce_mfa only
    2: isolate_endpoint only
    3: revoke_privileges only
    4: enforce_mfa + isolate_endpoint
    5: enforce_mfa + revoke_privileges
    6: All three playbooks
    
    Reward design:
    Rewards are assigned based on how appropriate the action is given the risk.
    - Low risk + action 0: +2
    - Critical risk + action 0: -10
    - Critical risk + action 6: +10
    - Low risk + action 6: -5 (over-response)
    - Medium/High risk + partial responses: +3 to +6 based on appropriateness
    - MFA bypass context + MFA action includes enforce_mfa: +3 bonus
    """
    
    def __init__(self, alpha=0.1, gamma=0.95, epsilon=1.0):
        self.q_table = {}
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.actions = list(range(7))

    def get_state(self, risk_score, feature_context):
        if risk_score <= 49:
            risk_band = 0
        elif risk_score <= 74:
            risk_band = 1
        elif risk_score <= 94:
            risk_band = 2
        else:
            risk_band = 3
            
        mfa_bypassed = 0
        if feature_context and feature_context.get('MFA_bypassed') == 1:
            mfa_bypassed = 1
            
        if feature_context and 'is_anomaly' in feature_context:
            anomaly_flag = 1 if feature_context['is_anomaly'] else 0
        else:
            anomaly_flag = 1 if risk_score > 74 else 0

        return (risk_band, mfa_bypassed, anomaly_flag)

    def choose_action(self, state, explore=False):
        if explore and random.uniform(0, 1) < self.epsilon:
            return random.choice(self.actions)
        
        q_values = [self.q_table.get((state, a), 0.0) for a in self.actions]
        max_q = max(q_values)
        best_actions = [a for a, q in zip(self.actions, q_values) if q == max_q]
        return random.choice(best_actions)

    def update(self, state, action, reward, next_state):
        current_q = self.q_table.get((state, action), 0.0)
        next_max_q = max([self.q_table.get((next_state, a), 0.0) for a in self.actions]) if next_state else 0.0
        
        new_q = current_q + self.alpha * (reward + self.gamma * next_max_q - current_q)
        self.q_table[(state, action)] = new_q

    def save(self, path):
        with open(path, 'wb') as f:
            pickle.dump(self.q_table, f)

    def load(self, path):
        with open(path, 'rb') as f:
            self.q_table = pickle.load(f)

    def _get_reward(self, state, action):
        risk_band, mfa_bypassed, anomaly_flag = state
        reward = 0
        
        # Action 0 on low or medium risk
        if risk_band <= 1 and action == 0:
            reward = 5
        # Action 0 on critical risk
        elif risk_band == 3 and action == 0:
            reward = -10
        # Action 6 on critical risk
        elif risk_band == 3 and action == 6:
            reward = 10
        # Action 6 on low or medium risk
        elif risk_band <= 1 and action == 6:
            reward = -5
            
        # Partial responses on medium/high risk
        elif risk_band in [1, 2]:
            if action in [1, 2, 3]:
                reward = 2 if risk_band == 1 else 6
            elif action in [4, 5]:
                reward = 1 if risk_band == 1 else 8
            elif action == 6:
                reward = -2 if risk_band == 1 else 5
            elif action == 0:
                reward = 5 if risk_band == 1 else -5
        
        # Penalty for over-response on low risk / missing response on high risk
        if risk_band == 0 and action not in [0, 6]:
            reward = -2
        if risk_band == 3 and action not in [0, 6]:
            reward = 3 # Better than 0, but worse than 6
            
        # MFA bypass context bonus
        if mfa_bypassed == 1 and action in [1, 4, 5, 6]:
            reward += 3
            
        return reward

    def train(self, episodes=5000, save_path="soar_qtable.pkl"):
        raise RuntimeError(
            "Synthetic training is disabled. Run collect_rl_dataset.py first "
            "to generate soar_real_training_data.csv, then re-run train_rl_agent.py."
        )

    def explain_decision(self, risk_score, feature_context=None):
        """
        Returns a detailed dictionary explaining exactly what the
        RL agent is thinking for a given input — the state it sees,
        all Q-values for every action, the best action it would pick,
        and a human-readable reasoning trace.
        """
        state = self.get_state(risk_score, feature_context)
        risk_band, mfa_bypassed, anomaly_flag = state

        # Get Q-values for all 7 actions
        action_labels = {
            0: "Do Nothing",
            1: "Enforce MFA only",
            2: "Isolate Endpoint only",
            3: "Revoke Privileges only",
            4: "Enforce MFA + Isolate Endpoint",
            5: "Enforce MFA + Revoke Privileges",
            6: "All 3 Playbooks (MFA + Isolate + Revoke)"
        }

        q_values = {}
        for a in self.actions:
            q_values[a] = round(self.q_table.get((state, a), 0.0), 4)

        best_action = max(q_values, key=q_values.get)
        best_q = q_values[best_action]

        # Build reasoning trace
        band_labels = {0: "LOW (0-49)", 1: "MEDIUM (50-74)",
                       2: "HIGH (75-94)", 3: "CRITICAL (95-100)"}

        reasoning = []
        reasoning.append(f"INPUT    Risk Score: {risk_score}")
        reasoning.append(f"STATE    Risk Band: {band_labels[risk_band]} | "
                         f"MFA Bypassed: {'YES' if mfa_bypassed else 'NO'} | "
                         f"Anomaly Flag: {'YES' if anomaly_flag else 'NO'}")
        reasoning.append(f"")
        reasoning.append(f"Q-VALUE TABLE (learned rewards per action):")
        for a, label in action_labels.items():
            marker = " [BEST]" if a == best_action else ""
            reasoning.append(f"  Action {a} [{label}]: Q = {q_values[a]}{marker}")
        reasoning.append(f"")
        reasoning.append(f"RL CHOICE    Action {best_action}: {action_labels[best_action]} "
                         f"(Q = {best_q})")

        if mfa_bypassed and best_action in [1, 4, 5, 6]:
            reasoning.append(f"BONUS NOTE : MFA bypass detected. RL received +3 reward "
                             f"bonus during training for actions that include MFA enforcement.")

        if risk_band == 3 and best_action != 6:
            reasoning.append(f"WARNING : RL did NOT choose Action 6 for CRITICAL risk. "
                             f"Deterministic policy will OVERRIDE this to enforce SLA.")
        elif risk_band == 3 and best_action == 6:
            reasoning.append(f"MATCH   : RL agrees with deterministic policy for CRITICAL risk.")

        if risk_band <= 1 and best_action == 0:
            reasoning.append(f"MATCH   : RL correctly chose 'Do Nothing' for LOW/MEDIUM risk.")

        return {
            "state": {
                "risk_band": band_labels[risk_band],
                "mfa_bypassed": bool(mfa_bypassed),
                "anomaly_flag": bool(anomaly_flag)
            },
            "q_values": {action_labels[a]: q_values[a] for a in self.actions},
            "rl_best_action": action_labels[best_action],
            "rl_best_q": best_q,
            "reasoning_trace": reasoning
        }
