import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import os

st.set_page_config(page_title="ZenGuard SOC Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ ZenGuard SOC / UEBA Analyst Dashboard")
st.markdown("Test the Isolation Forest model using manual inputs or simulate a SIEM log integration.")

# Define path to the model relative to dashboard location
model_path = os.path.join("implementation result", "zenguard_ueba_model.pkl")

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
    
    if risk_score == 95:
        st.error("🚨 **High Risk Detected!**")
        st.write(f"### ZenGuard Risk Score: {risk_score}")
        st.write(f"**Isolation Forest Raw Score:** {raw_score:.4f}")
        st.markdown("---")
        st.markdown("#### SOAR Playbook Auto-Responses Triggered:")
        st.markdown("- **Action 1:** Enforce Multi-Factor Authentication (MFA)")
        st.markdown("- **Action 2:** Isolate Endpoint via EDR")
        st.markdown("- **Action 3:** Revoke Privileges & Terminate Session")
    else:
        st.success("✅ **Normal Behavior**")
        st.write(f"### ZenGuard Risk Score: {risk_score}")
        st.write(f"**Isolation Forest Raw Score:** {raw_score:.4f}")
        st.markdown("---")
        st.markdown("No anomalous behavior detected. User session proceeds without interruption.")
