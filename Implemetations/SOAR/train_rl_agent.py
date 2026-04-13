import os
import sys

# Ensure the local directory is in the path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rl_agent import SOARRLAgent

def main():
    print("Initializing SOAR RL Agent...")
    agent = SOARRLAgent()
    
    table_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soar_qtable.pkl")
    
    print(f"Training agent for 5000 episodes...")
    agent.train(episodes=5000, save_path=table_path)
    
    print(f"Training complete. Q-table saved to: {table_path}")
    
    # Just to show some stats
    print(f"Epsilon decayed to: {agent.epsilon:.4f}")
    print(f"Q-table size: {len(agent.q_table)} entries")

if __name__ == "__main__":
    main()
