# ZenGuard SOAR & UEBA Manual Test Cases

Use these JSON snippets directly in the Streamlit Dashboard's **SIEM Event Log (JSON)** input box. They are designed to test the full spectrum of the SOC setup, from innocuous normal behavior to critical automated interventions.

### 1. Perfectly Normal Employee
```json
{
  "session_duration": 2.5,
  "failed_logins": 0,
  "access_time": 10,
  "device_trust_score": 0.95,
  "privilege_change_attempted": 0,
  "external_connection": 0,
  "MFA_bypassed": 0
}
```

### 2. Employee with Fat Fingers (Minor Typos)
```json
{
  "session_duration": 0.5,
  "failed_logins": 3,
  "access_time": 8,
  "device_trust_score": 0.90,
  "privilege_change_attempted": 0,
  "external_connection": 0,
  "MFA_bypassed": 0
}
```

### 3. Untrusted Device (Working from a Cafe)
```json
{
  "session_duration": 4.0,
  "failed_logins": 0,
  "access_time": 14,
  "device_trust_score": 0.30,
  "privilege_change_attempted": 0,
  "external_connection": 1,
  "MFA_bypassed": 0
}
```

### 4. Admin Taking a Weird Shift (Late Night)
```json
{
  "session_duration": 9.5,
  "failed_logins": 0,
  "access_time": 2,
  "device_trust_score": 0.80,
  "privilege_change_attempted": 0,
  "external_connection": 0,
  "MFA_bypassed": 0
}
```

### 5. Suspicious Privilege Request
```json
{
  "session_duration": 1.2,
  "failed_logins": 0,
  "access_time": 15,
  "device_trust_score": 0.95,
  "privilege_change_attempted": 1,
  "external_connection": 0,
  "MFA_bypassed": 0
}
```

### 6. Brute Force Attack from Outside
```json
{
  "session_duration": 0.1,
  "failed_logins": 12,
  "access_time": 3,
  "device_trust_score": 0.10,
  "privilege_change_attempted": 0,
  "external_connection": 1,
  "MFA_bypassed": 0
}
```

### 7. The Session Hijack (MFA Bypass)
```json
{
  "session_duration": 0.8,
  "failed_logins": 0,
  "access_time": 11,
  "device_trust_score": 0.40,
  "privilege_change_attempted": 0,
  "external_connection": 1,
  "MFA_bypassed": 1
}
```

### 8. Rogue Admin (Insider Threat)
```json
{
  "session_duration": 12.0,
  "failed_logins": 1,
  "access_time": 4,
  "device_trust_score": 0.70,
  "privilege_change_attempted": 1,
  "external_connection": 0,
  "MFA_bypassed": 0
}
```

### 9. Persistent External Attacker
```json
{
  "session_duration": 2.5,
  "failed_logins": 6,
  "access_time": 23,
  "device_trust_score": 0.05,
  "privilege_change_attempted": 0,
  "external_connection": 1,
  "MFA_bypassed": 0
}
```

### 10. The Nuclear Scenario (Everything went wrong)
```json
{
  "session_duration": 8.5,
  "failed_logins": 5,
  "access_time": 1,
  "device_trust_score": 0.0,
  "privilege_change_attempted": 1,
  "external_connection": 1,
  "MFA_bypassed": 1
}
```
