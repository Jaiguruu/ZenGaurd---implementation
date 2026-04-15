# 🛡️ ZenGuard: Manual Verification Guide

This guide provides step-by-step instructions and sample JSON payloads to verify the integration between the **UEBA Anomaly Detection** and the **SOAR Response Engine**.

---

## 🚀 Scenario 1: Normal User Behavior
*Baseline activity for a trusted employee during working hours.*

**Payload:**
```json
{
  "session_duration": 1.5,
  "failed_logins": 0,
  "access_time": 14,
  "device_trust_score": 0.95,
  "privilege_change_attempted": 0,
  "external_connection": 0,
  "MFA_bypassed": 0
}
```

**Expected Result:**
- **Risk Score:** Low (0-49)
- **Status:** ✅ NORMAL BEHAVIOR
- **SOAR:** No automated playbooks triggered.

---

## 🔨 Scenario 2: Potential Brute Force / Anomaly
*High number of failed logins from an untrusted device.*

**Payload:**
```json
{
  "session_duration": 0.2,
  "failed_logins": 8,
  "access_time": 22,
  "device_trust_score": 0.3,
  "privilege_change_attempted": 0,
  "external_connection": 1,
  "MFA_bypassed": 0
}
```

**Expected Result:**
- **Risk Score:** Medium to High (50-94)
- **Status:** ⚠️ MEDIUM RISK or 🚨 HIGH RISK
- **SOAR:** Likely triggers `Enforce MFA`.

---

## 🚨 Scenario 3: Critical Threat (MFA Bypass)
*A session where MFA was bypassed and privilege changes were attempted.*

**Payload:**
```json
{
  "session_duration": 4.5,
  "failed_logins": 2,
  "access_time": 3,
  "device_trust_score": 0.1,
  "privilege_change_attempted": 1,
  "external_connection": 1,
  "MFA_bypassed": 1
}
```

**Expected Result:**
- **Risk Score:** Critical (95+)
- **Status:** ☣️ CRITICAL RISK DETECTED
- **SOAR:** Triggers multiple playbooks: `Enforce MFA`, `Revoke Privileges`, and `Isolate Endpoint`.

---

## 🛠️ How to Test
1. Ensure the dashboard is running: `streamlit run dashboard.py` inside the `Integration` folder.
2. Open the browser to the Streamlit URL.
3. Locate the **"📡 SIEM Event Log (JSON)"** text area on the right.
4. Copy one of the JSON blocks above and paste it into the field.
5. Click **"Execute Analysis & Response"**.
6. Observe the results in the **"📊 Analysis Outcome"** section.
