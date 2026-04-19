# SOAR Module: Developer Guide

**Role Analogy:** *The Armed Security Guards*  
Your job is strictly mitigation and autonomous action. You don't analyze packet captures (that's SIEM), and you don't calculate anomaly thresholds mathematically (that's UEBA). You observe the final translated alarm metrics and decide whether to close ports, block IPs, or terminate user access.

## Your Responsibilities
- Orchestrating the custom Reinforcement Learning `rl_agent.py` Q-Learning structures.
- Crafting deterministic "If-Else" fallback logic inside your `engine.py`. For example, ensuring that a physical password rotation occurs immediately if the user breached the perimeter without MFA, overriding RL thresholds.
- Simulating actions to build your Q-Table metrics during standard local retraining.

## What You Need To Know About UEBA
- The UEBA developer serves intelligence via HTTP format exactly through `http://localhost:8000/api/soar/evaluate`. 
- You must map your Q-Learning state spaces around the explicit `risk_score` integer constraint (`0-100`).
- The UEBA explicitly provides an object dictionary called `feature_context`. The RL table will choose the *Severity* of the block, but you must instruct your deterministic systems using `feature_context["MFA_bypassed"]` to decide the *Type* of the block. 

## What You Need To Know About SIEM
- **Absolutely Nothing.**
- The stack is physically decoupled. The SIEM handles the massive overhead of data lakes and indexing. All intelligence is passed perfectly formatted to you exclusively through the unified UEBA ML layers.
