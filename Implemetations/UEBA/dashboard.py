import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import os
import sys

# Ensure the local directory is in the path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from soar_engine import SOAREngine

st.set_page_config(page_title="ZenGuard SOC Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ ZenGuard SOC / UEBA Analyst Dashboard")
st.markdown("Test the Isolation Forest model using manual inputs or simulate a SIEM log integration.")

# Initialize SOAR Engine in session state to persist history
if 'soar' not in st.session_state:
    st.session_state.soar = SOAREngine()

# Define path to the model relative to dashboard location
# Using absolute path derivation to work regardless of CWD
current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, "implementation result", "zenguard_ueba_model.pkl")

# Ensure the model exists before trying to load
if not os.path.exists(model_path):
    st.error(f"Error: Model not found at '{model_path}'. Please run the Jupyter Notebook first to generate the model.")
    st.stop()

try:
    ueba_model = joblib.load(model_path)
    st.sidebar.success(f"✅ Model loaded successfully from {model_path}")
except Exception as e:
    st.sidebar.error(f"Error loading model: {e}")
    st.stop()

# Sidebar - SOAR History
st.sidebar.markdown("---")
st.sidebar.header("📜 SOAR Execution History")
history = st.session_state.soar.get_history()
if not history:
    st.sidebar.info("No playbooks executed yet.")
else:
    for log in reversed(history[-10:]): # Show last 10 actions
        st.sidebar.markdown(f"**{log['timestamp']}**")
        st.sidebar.caption(f"{log['playbook']}: {log['status']}")

features = ['session_duration', 'failed_logins', 'access_time', 'device_trust_score', 
            'privilege_change_attempted', 'external_connection', 'MFA_bypassed']

col1, col2 = st.columns(2)

with col1:
    st.header("⚙️ Manual Playbook Parameters")
    session_duration = st.number_input("Session Duration (hrs)", min_value=0.0, max_value=24.0, value=1.5, step=0.1)
    failed_logins = st.number_input("Failed Logins", min_value=0, max_value=20, value=0, step=1)
    access_time = st.slider("Access Time (Hour)", min_value=0, max_value=23, value=14, step=1)
    device_trust_score = st.slider("Device Trust Score", min_value=0.0, max_value=1.0, value=0.9, step=0.05)
    privilege_change_attempted = st.selectbox("Privilege Change Attempt", options=[0, 1], format_func=lambda x: "Yes" if x == 1 else "No")
    external_connection = st.selectbox("External Connection", options=[0, 1], format_func=lambda x: "Yes" if x == 1 else "No")
    MFA_bypassed = st.selectbox("MFA Bypassed", options=[0, 1], format_func=lambda x: "Yes" if x == 1 else "No")

with col2:
    st.header("📡 SIEM Event Log (JSON)")
    st.markdown("*If valid JSON is provided here, it overrides manual inputs. Clear this box to use manual inputs.*")
    
    siem_json_template = '''{
  "session_duration": 4.5,
  "failed_logins": 5,
  "access_time": 2,
  "device_trust_score": 0.3,
  "privilege_change_attempted": 1,
  "external_connection": 1,
  "MFA_bypassed": 0
}'''
    
    siem_input = st.text_area("Paste Raw SIEM JSON Log here...", value="", height=350, placeholder=siem_json_template)

st.markdown("---")

if st.button("Execute ZenGuard UEBA Analysis", type="primary", use_container_width=True):
    use_json = False
    input_df = None
    
    if siem_input.strip():
        try:
            data_dict = json.loads(siem_input)
            if all(k in data_dict for k in features):
                input_df = pd.DataFrame([data_dict])[features]
                use_json = True
                st.info("Status: Parsed SIEM JSON event successfully.")
            else:
                st.warning("Status: JSON missing required features. Falling back to manual inputs.")
        except json.JSONDecodeError:
            st.warning("Status: Invalid JSON. Falling back to manual inputs.")
            
    if not use_json:
        input_data = {
            'session_duration': session_duration,
            'failed_logins': failed_logins,
            'access_time': access_time,
            'device_trust_score': device_trust_score,
            'privilege_change_attempted': privilege_change_attempted,
            'external_connection': external_connection,
            'MFA_bypassed': MFA_bypassed
        }
        input_df = pd.DataFrame([input_data])[features]
        st.info("Status: Using Manual Parameter Inputs.")
        
    anomaly_pred = ueba_model.predict(input_df)[0]
    raw_score = ueba_model.decision_function(input_df)[0]
    
    risk_score = 95 if anomaly_pred == -1 else 50
    
    # Trigger SOAR engine
    triggered_actions = st.session_state.soar.evaluate_and_respond(risk_score, input_df.iloc[0].to_dict())
    
    if risk_score == 95:
        st.error("🚨 **High Risk Detected!**")
        res_col1, res_col2 = st.columns([1, 2])
        with res_col1:
            st.metric("ZenGuard Risk Score", risk_score, delta="CRITICAL", delta_color="inverse")
            st.write(f"**Isolation Forest Score:** `{raw_score:.4f}`")
        
        with res_col2:
            st.subheader("🤖 Automated SOAR Responses")
            for action in triggered_actions:
                with st.expander(f"✅ {action['playbook']} - Executed", expanded=True):
                    st.write(f"**Action:** {action['action']}")
                    st.caption(f"Executed at {action['timestamp']} | Status: {action['status']}")
    else:
        st.success("✅ **Normal Behavior**")
        st.metric("ZenGuard Risk Score", risk_score, delta="LOW", delta_color="normal")
        st.write(f"**Isolation Forest Raw Score:** {raw_score:.4f}")
        st.markdown("---")
        st.markdown("No anomalous behavior detected. User session proceeds without interruption.")
