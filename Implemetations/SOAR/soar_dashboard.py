import streamlit as st
import pandas as pd
import json
import os
import sys
import time
from soar_engine import SOAREngine

# Page Configuration
st.set_page_config(page_title="ZenGuard SOAR Standalone", page_icon="🛡️", layout="wide")

# Initialize SOAR Engine in session state
if 'soar' not in st.session_state:
    st.session_state.soar = SOAREngine()

st.title("🛡️ ZenGuard SOAR - Standalone Incident Response")
st.markdown("""
This dashboard simulates a standalone **Security Orchestration, Automation, and Response (SOAR)** system. 
Incoming alerts from a SIEM or UEBA system trigger automated playbooks based on risk scores.
""")

# Sidebar for History
st.sidebar.header("📜 SOAR Execution History")
history = st.session_state.soar.get_history()
if not history:
    st.sidebar.info("No playbooks executed yet.")
else:
    for log in reversed(history[-10:]):
        st.sidebar.markdown(f"**{log['timestamp']}**")
        st.sidebar.caption(f"{log['playbook']}: {log['status']}")

# Main Layout
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📥 Incident Input")
    risk_score = st.slider("ZenGuard Risk Score (0-100)", min_value=0, max_value=100, value=96)
    
    st.markdown("**Incident Context (Optional JSON)**")
    context_template = '{"user_id": "soc_analyst_01", "MFA_bypassed": 1, "source_ip": "192.168.1.50"}'
    context_input = st.text_area("Provide incident context here...", value=context_template, height=150)

with col2:
    st.subheader("⚙️ Backend Process Visualization")
    placeholder = st.empty()
    
    if st.button("Process Incident", type="primary", use_container_width=True):
        context_data = {}
        if context_input.strip():
            try:
                context_data = json.loads(context_input)
            except json.JSONDecodeError:
                st.error("Invalid JSON context. Using default values.")

        # Backend Visualization logic
        with placeholder.container():
            st.info("🔍 Analyzing Risk Score and Context...")
            time.sleep(1)
            
            if risk_score >= 95:
                st.warning(f"🚨 Risk Score {risk_score} meets threshold for automated response.")
                
                # We'll use a direct loop to show progress since we want to visualize it in the dashboard
                # The engine's evaluate_and_respond will be called, but we'll show the steps here for better UI control
                
                progress_bar = st.progress(0)
                status_list = []
                
                # Determine playbooks based on logic
                playbooks = ["Enforce MFA", "Isolate Endpoint", "Revoke Privileges"]
                if context_data.get('MFA_bypassed') == 1:
                    playbooks = ["Enforce MFA", "Revoke Privileges", "Isolate Endpoint"]
                
                for i, pb_name in enumerate(playbooks):
                    # Update status
                    status_text = f"🔄 Executing {pb_name}..."
                    st.write(status_text)
                    
                    # Update progress
                    progress_bar.progress((i + 1) * 33)
                    
                    # Fake delay for "Backend work"
                    time.sleep(1.2)
                    
                    st.success(f"✅ {pb_name} Completed.")
                
                # Actually call the engine to record history
                triggered_actions = st.session_state.soar.evaluate_and_respond(risk_score, context_data)
                
                st.markdown("---")
                st.balloons()
                st.success("All automated mitigations successfully deployed.")
                
            else:
                st.success(f"✅ Risk Score {risk_score} is below threshold. Monitoring continues.")

st.markdown("---")
st.subheader("📊 Detailed Execution Logs")
if not history:
    st.info("Execute an incident to see detailed logs.")
else:
    df_history = pd.DataFrame(history)
    st.table(df_history.tail(10))

# Custom CSS for a more premium look
st.markdown("""
<style>
    .stButton>button {
        border-radius: 8px;
        height: 3em;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)
