# ZenGuard Standalone SOAR Implementation

This folder contains a standalone implementation of the **Security Orchestration, Automation, and Response (SOAR)** component of ZenGuard.

## Features
- **Rule-based Response**: Automatically triggers playbooks when risk scores cross critical thresholds (>= 95).
- **Context-Aware Prioritization**: Dynamically reorders mitigation actions based on incident metadata (e.g., prioritizing MFA if a bypass is detected).
- **Backend Visualization**: A dedicated dashboard providing real-time visibility into incident processing and playbook execution.

## File Structure
- `soar_engine.py`: Core logic for evaluating risks and executing playbooks.
- `soar_dashboard.py`: Streamlit-based interface for incident simulation and backend visualization.
- `test_soar.py`: Script to verify logic correctness.

## How to Run

### 1. Prerequisite
Ensure you have the required dependencies installed:
```bash
pip install streamlit pandas
```

### 2. Launch the Dashboard
Run the following command in your terminal:
```bash
streamlit run e:\miniProZen\Implemetations\SOAR\soar_dashboard.py
```

### 3. Run Logic Verification
To verify the engine's decision-making logic:
```bash
python e:\miniProZen\Implemetations\SOAR\test_soar.py
```
