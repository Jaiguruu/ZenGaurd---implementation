# UEBA Module: Developer Guide

**Role Analogy:** *The Behavioral Profiler*  
Your job is unsupervised pattern recognition and translation. You sit explicitly in the middle of the stack, turning the raw data from the SIEM into a human-readable risk format that the armed guards (SOAR) can act upon.

## Your Responsibilities
- Offline Model Generation: By ignoring the heavy SIEM network components, you operate locally using `generate_dataset.py` to quickly squash large 400MB raw dataset dumps into 11MB feature-rich matrices (`ueba_dataset.csv`).
- Training an Unsupervised machine learning engine (Isolation Forest via `train.py`).
- Hosting the live interaction API via FastAPI in `model_server.py`. 
- You convert complex float-point isolation bounds mathematically into an easy to understand `0-100` **Risk Score**.

## What You Need To Know About SIEM
- The SIEM is noisy. Your FastAPI server must be hardened to ensure it drops data not containing the 7 exact identity columns (`failed_logins`, `MFA_bypassed`, etc).
- SIEM expects your `model_server.py` to be perpetually alive on standard port `:8000` waiting for standard HTTP payloads. 

## What You Need To Know About SOAR
- The SOAR developer is orchestrating Reinforcement Learning matrices (Q-Learning) and Deterministic Python conditions (`if score > X`). They lack data science libraries like `numpy` or `sklearn`. 
- You **must** provide SOAR an exact integer (e.g., `Risk Score of 95`) not an isolation bound (e.g. `Score of -0.422`).
- You **must loopback Context**. A score of 100 tells the RL agent to block *something*, but looping back `"feature_context": {"MFA_bypassed": 1}` empowers the SOAR deterministic fallback mechanisms to physically alter their payload targets explicitly to matching identity playbooks.
