import streamlit as st
import pandas as pd
import json
import os
import sys

# Add the parent directory (Implemetations) to path for cross-module imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from UEBA.model import UEBAModel
from SOAR.engine import SOAREngine

st.set_page_config(page_title="ZenGuard SOC Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ ZenGuard SOC / UEBA Analyst Dashboard")
st.markdown("Integrated Security Operations Dashboard: UEBA Detection & SOAR Response.")

# 1. Initialize Engines in session state
if 'soar' not in st.session_state:
    st.session_state.soar = SOAREngine()

if 'ueba' not in st.session_state:
    try:
        # Assuming the standard path relative to UEBA module
        st.session_state.ueba = UEBAModel()
        st.sidebar.success("✅ UEBA Model loaded successfully")
    except Exception as e:
        st.sidebar.error(f"❌ Error loading UEBA model: {e}")
        st.stop()

# 2. Sidebar - SOAR History
st.sidebar.markdown("---")
st.sidebar.header("📜 SOAR Execution History")
history = st.session_state.soar.get_history()
if not history:
    st.sidebar.info("No playbooks executed yet.")
else:
    for log in reversed(history[-10:]):
        st.sidebar.markdown(f"**{log['timestamp']}**")
        st.sidebar.caption(f"{log['playbook']}: {log['status']}")

# 3. Input Section
features = ['session_duration', 'failed_logins', 'access_time', 'device_trust_score', 
            'privilege_change_attempted', 'external_connection', 'MFA_bypassed']

col1, col2 = st.columns(2)

with col1:
    st.header("⚙️ Manual Parameters")
    session_duration = st.number_input("Session Duration (hrs)", min_value=0.0, max_value=24.0, value=1.5, step=0.1)
    failed_logins = st.number_input("Failed Logins", min_value=0, max_value=20, value=0, step=1)
    access_time = st.slider("Access Time (Hour)", min_value=0, max_value=23, value=14, step=1)
    device_trust_score = st.slider("Device Trust Score", min_value=0.0, max_value=1.0, value=0.9, step=0.05)
    privilege_change_attempted = st.selectbox("Privilege Change Attempt", options=[0, 1], format_func=lambda x: "Yes" if x == 1 else "No")
    external_connection = st.selectbox("External Connection", options=[0, 1], format_func=lambda x: "Yes" if x == 1 else "No")
    MFA_bypassed = st.selectbox("MFA Bypassed", options=[0, 1], format_func=lambda x: "Yes" if x == 1 else "No")

with col2:
    st.header("📡 SIEM Event Log (JSON)")
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

# 4. Analysis & Response Execution
if st.button("Execute Analysis & Response", type="primary", use_container_width=True):
    input_df = None
    if siem_input.strip():
        try:
            data_dict = json.loads(siem_input)
            input_df = pd.DataFrame([data_dict])[features]
            st.info("Parsed SIEM JSON event successfully.")
        except Exception as e:
            st.warning(f"Invalid JSON/Missing fields: {e}. Falling back to manual.")
            
    if input_df is None:
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

    # --- UEBA Step ---
    anomaly_pred, raw_score, risk_score = st.session_state.ueba.predict(input_df)
    
    # --- SOAR Step ---
    triggered_actions = st.session_state.soar.evaluate_and_respond(risk_score, input_df.iloc[0].to_dict())
    
    # --- UI Results ---
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
                    st.caption(f"Executed at {action['timestamp']}")
    else:
        st.success("✅ **Normal Behavior**")
        st.metric("ZenGuard Risk Score", risk_score, delta="LOW", delta_color="normal")
        st.write(f"**Isolation Forest Raw Score:** {raw_score:.4f}")
        st.markdown("No anomalous behavior detected. User session proceeds without interruption.")
