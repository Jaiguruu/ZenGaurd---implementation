# 🛡️ ZenGuard: SOC / UEBA & SOAR Automation

ZenGuard is an end-to-end security framework that integrates **User and Entity Behavior Analytics (UEBA)** with an **Automated SOAR Response Engine**. It uses Machine Learning to detect anomalies in SIEM logs and Reinforcement Learning (RL) to execute surgical security playbooks in real-time.

---

## 🚀 Getting Started

### Prerequisites
Ensure you have Python 3.8+ installed. You will need the following libraries:
```bash
pip install pandas scikit-learn joblib streamlit numpy
```

### 1. Clone the Repository
```bash
git clone https://github.com/Jaiguruu/ZenGaurd---implementation.git
cd ZenGaurd---implementation/Implemetations
```

### 2. Prepare the Models
The system relies on a trained UEBA model and an RL Q-table.
- **Train SOAR RL Agent**:
  ```bash
  cd SOAR
  python train_rl_agent.py
  cd ..
  ```

### 3. Run Automated Tests
Verify that the integration is working correctly across all 4 risk scenarios (Normal, Medium, High, and Critical).
```bash
cd Integration
python test_scenarios_runner.py
```

### 4. Launch the Dashboard
Experience the ZenGuard Analyst Dashboard:
```bash
streamlit run dashboard.py
```
Open your browser at **http://localhost:8501**.

---

## 📂 Project Structure & Components

| Directory / File | Contribution |
| :--- | :--- |
| **`UEBA/`** | The Anomaly Detection brain. Uses **Isolation Forest** to score incoming telemetry. |
| **`UEBA/model.py`** | Contains the linear calibration logic and SLA-based risk boosting. |
| **`SOAR/`** | The Response Engine. Orchestrates automated playbooks. |
| **`SOAR/rl_agent.py`** | A Q-Learning agent that optimizes security decisions based on learned rewards. |
| **`SOAR/engine.py`** | The core engine that balances RL recommendations with a deterministic safety policy. |
| **`Integration/`** | The fusion layer connecting UEBA, SOAR, and the Analyst UI. |
| **`Integration/dashboard.py`** | Streamlit-based dashboard for real-time SIEM log analysis. |
| **`Integration/test_rl_thinking.py`** | Transparency tool that logs the "RL Thinking Process" for security analysts. |

---

## 📊 Expected Results Matrix

Use the following table to verify system behavior in the dashboard or test runner:

| Scenario | Risk Band | Risk Score | Playbooks Triggered |
| :--- | :--- | :--- | :--- |
| **Normal Activity** | LOW | 0–49 | None |
| **Brute Force Attempt** | MEDIUM | 50–74 | Enforce MFA |
| **High Risk Anomaly** | HIGH | 75–94 | Enforce MFA + Isolate Endpoint |
| **Critical (MFA Bypass)** | CRITICAL | 95–100 | Enforce MFA + Isolate + Revoke |

---

## 🛠️ Key Features
- **Deterministic SLA Enforcement**: Guarantees specific security actions for every risk band.
- **RL Transparency**: The "Thinking Log" provides a full trace of why the AI made a decision.
- **Zero-Trust Ready**: Designed to integrate with Firewalls, IdPs, and EDR systems via modular playbooks.

---
Developed as part of the ZenGuard Security Framework Implementation.
