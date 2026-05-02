import pandas as pd
import numpy as np
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "ueba_dataset.csv")

def inject_mfa_bypass():
    print("[*] Loading ueba_dataset.csv for injection...")
    if not os.path.exists(DATASET_PATH):
        print(f"[!] Error: {DATASET_PATH} not found.")
        return

    df = pd.read_csv(DATASET_PATH)
    
    print("[*] Current MFA_bypassed counts:")
    print(df['MFA_bypassed'].value_counts())

    # Ensure MFA_bypassed is reset to 0 first (clean state)
    df['MFA_bypassed'] = 0

    # Probability logic
    # 30% of actual attacks will have MFA_bypassed = 1
    # 0.5% of benign traffic will have MFA_bypassed = 1 (glitch/noise)
    np.random.seed(42) # Reproducible injection
    
    is_attack = df['attack_category'] != 'benign'
    is_benign = df['attack_category'] == 'benign'

    # Vectors for random assignment
    attack_rand = np.random.rand(sum(is_attack))
    benign_rand = np.random.rand(sum(is_benign))

    # Apply
    df.loc[is_attack, 'MFA_bypassed'] = (attack_rand < 0.30).astype(int)
    df.loc[is_benign, 'MFA_bypassed'] = (benign_rand < 0.005).astype(int)

    print("\n[*] New MFA_bypassed counts:")
    print(df['MFA_bypassed'].value_counts())

    print("\n[*] Correlation with Attack Status:")
    print(pd.crosstab(df['attack_category'] != 'benign', df['MFA_bypassed']))

    print(f"[*] Saving updated dataset to {DATASET_PATH}...")
    df.to_csv(DATASET_PATH, index=False)
    print("[+] Injection complete!")

if __name__ == "__main__":
    inject_mfa_bypass()
