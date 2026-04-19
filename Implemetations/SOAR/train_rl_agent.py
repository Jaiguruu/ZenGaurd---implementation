import os
import sys
import random
import pandas as pd

# Ensure the local directory is in the path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rl_agent import SOARRLAgent

def main():
    print("Initializing SOAR RL Agent...")
    agent = SOARRLAgent()
    
    table_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soar_qtable.pkl")
    data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soar_real_training_data.csv")
    
    if os.path.exists(data_path):
        print(f"[*] Authentic dataset found at {data_path}. Training from actual UEBA distributions.")
        df = pd.read_csv(data_path)
        episodes = len(df)
        
        epsilon_min = 0.05
        decay_rate = (1.0 - epsilon_min) / episodes
        
        for index, row in df.iterrows():
            risk_score = int(row['risk_score'])
            mfa_bypassed = int(row['MFA_bypassed'])
            context = {'MFA_bypassed': mfa_bypassed}
            
            state = agent.get_state(risk_score, context)
            action = agent.choose_action(state, explore=True)
            
            reward = agent._get_reward(state, action)
            agent.update(state, action, reward, next_state=None)
            
            agent.epsilon = max(epsilon_min, agent.epsilon - decay_rate)
            
    else:
        print(f"[!] REAL DATASET NOT FOUND. Training agent for 5000 random synthetic episodes...")
        agent.train(episodes=5000, save_path=table_path)
        
    agent.save(table_path)
    
    print(f"Training complete. Q-table saved to: {table_path}")
    print(f"Epsilon decayed to: {agent.epsilon:.4f}")
    print(f"Q-table size: {len(agent.q_table)} entries")

if __name__ == "__main__":
    main()
