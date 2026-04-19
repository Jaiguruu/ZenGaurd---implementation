# ZenGuard — What is Prepared for UEBA & What the UEBA Developer Must Know

> This document is written **specifically for the person implementing UEBA**.
> It describes exactly what arrives at the UEBA boundary, what every field means,
> where it came from, what the caveats are, and what you are expected to give back.

---

## 1. The Big Picture — Where UEBA Sits

```
CIC-IDS-2017 / UNSW-NB15 CSVs
        │
        ▼
zenguard_replayer.py          ← synthesizes 4 missing identity features
        │  TCP JSON → port 5000
        ▼
Logstash                      ← parses, normalizes, enriches
        │  index
        ▼
Elasticsearch  (zenguard-* indices)
        │  poll every 5 seconds
        ▼
siem_listener.py              ← ANOMALY FILTER + UEBA PACKAGER  ← you hook in HERE
        │  HTTP POST JSON
        ▼
Flask dashboard /api/ingest   ← current stub recipient (your code replaces/augments this)
```

UEBA receives its data from **`siem_listener.py`** via an **HTTP POST** to a configured endpoint. The listener is already running and producing payloads — you only need to stand up an endpoint that accepts them, or integrate your model directly into the listener's code.

---

## 2. The Full UEBA Payload — Exact JSON Structure

Every POST body from `siem_listener.py` is this envelope:

```json
{
  "schema_version": "zenguard/ueba-payload/v1",
  "batch": {
    "generated_at":    "2026-04-15T17:52:03.441+00:00",
    "event_count":     12,
    "severity_summary": {
      "critical": 1,
      "high":     4,
      "medium":   5,
      "low":      2
    },
    "event_types": {
      "failed_logins":        6,
      "snort_alerts":         3,
      "privilege_escalation": 2,
      "wazuh_alert":          1
    },
    "unique_src_ips": ["45.33.1.22", "104.21.5.8", "198.51.100.7"]
  },
  "events": [
    { ...event object... },
    { ...event object... }
  ]
}
```

**`batch`** is a pre-computed summary for rapid triage — you can use `severity_summary` and `event_types` to decide whether the batch warrants a full model inference pass.

---

## 3. The Event Object — Every Field, Its Type, Origin, and Default

Each object inside `"events"` is one normalized security event. Here is the **complete schema**:

### 3.1 Identity & Routing Fields

| Field | Python Type | Example | Origin | Default if Missing |
|---|---|---|---|---|
| `event_id` | `str` | `"Abc1XYz_abc123"` | Elasticsearch `_id` (document dedup key) | `None` |
| `src_ip` | `str` | `"45.33.1.22"` | CSV `Source IP` / auth.log / Snort alert | `"0.0.0.0"` |
| `dst_ip` | `str` | `"192.168.1.10"` | CSV `Destination IP` / Snort alert | `"0.0.0.0"` |
| `user_id` | `str` | `"admin"` | auth.log parsed user / synthesized by replayer | `"unknown"` |
| `event_type` | `str` | `"failed_logins"` | Logstash normalization (lowercase) | `"unknown"` |
| `action` | `str` | `"failed_login"` | Logstash derived from `auth_result` | `None` |
| `severity` | `str` | `"medium"` | Logstash rule / Snort priority / Wazuh level | `"low"` |
| `timestamp` | `str` | `"2026-04-15T02:31:44+00:00"` | True event time (not ingest time) | `now()` |
| `log_source` | `str` | `"replayer"` | Logstash branch that processed this event | `None` |
| `endpoint_id` | `str` | `"corp-laptop-07"` | Filebeat `$HOSTNAME` injection | `None` |
| `detected_at` | `str` | `"2026-04-15T17:52:03+00:00"` | When siem_listener extracted this event | — |
| `listener_version` | `str` | `"2.0.0"` | siem_listener version tag | — |
| `zenguard_layer` | `int` | `2` | Always `2` (Layer 2 hand-off) | — |

### 3.2 Enrichment Fields (optional, may be `None`)

| Field | Type | Example | Source |
|---|---|---|---|
| `snort_msg` | `str` or `None` | `"ZenGuard SSH Brute Force Attempt"` | Snort alert description (only for snort events) |
| `wazuh_level` | `int` or `None` | `12` | Wazuh rule level 0–15 (only for wazuh events) |
| `src_country` | `str` or `None` | `"United States"` | GeoIP from Logstash (null for private IPs) |
| `src_city` | `str` or `None` | `"San Jose"` | GeoIP from Logstash |
| `tags` | `list[str]` | `["possible_brute_force", "replayer", "synthetic"]` | Logstash + Beats tags |

### 3.3 The 7 ZenGuard ML / UEBA Features — THE CORE INPUT

These are **the features your UEBA model consumes**. They are guaranteed to be present on every event with the listed types and defaults.

| Feature | Type | Range / Values | Default | Semantic Meaning |
|---|---|---|---|---|
| **`failed_logins`** | `int` | `0 – 30` | `0` | Number of failed authentication attempts **in this event** (not total historical). A single event can carry e.g. `14` if the replayer synthesized 14 failures for a brute-force flow. |
| **`privilege_change_attempted`** | `int` | `0` or `1` | `0` | Was an attempt made to escalate privileges (sudo, su, Windows UAC)? Boolean encoded as integer. |
| **`external_connection`** | `int` | `0` or `1` | `0` | Does the `src_ip` originate outside RFC-1918 private ranges (10.x, 172.16-31.x, 192.168.x)? Derived from the CSV src_ip. |
| **`MFA_bypassed`** | `int` | `0` or `1` | `0` | Was multi-factor authentication bypassed (session token reuse, stolen cookie, PAM bypass)? Boolean encoded as integer. |
| **`session_duration`** | `float` | `0.0 – ~1800.0` seconds | `0.0` | Duration of the network flow or session in **seconds**. Comes from CSV `flow_duration` (CIC: microseconds ÷ 1,000,000; UNSW: already seconds). |
| **`access_time`** | `str` | ISO8601 UTC | event `timestamp` | The timestamp when the user/attacker accessed the system. Synthesized: benign = 08:00–17:59 UTC; attacks = 00:00–05:59 or 22:00–23:59 UTC. |
| **`device_trust_score`** | `float` | `0.0 – 1.0` | `0.5` | How trusted is the device initiating the connection? Derived from whether `src_ip` is internal + attack category. `0.7–1.0` = managed asset; `0.05–0.40` = untrusted/external. |

---

## 4. Event Type Vocabulary — What Values `event_type` Can Take

Only the following `event_type` values are forwarded to UEBA (the listener filters to these 5):

| `event_type` value | What it means | Primary source |
|---|---|---|
| `"failed_logins"` | SSH/auth failed password events | auth.log (Filebeat) or replayer |
| `"snort_alerts"` | IDS alert fired (Snort fast-alert) | Snort log (Filebeat) or replayer |
| `"privilege_escalation"` | sudo/su escalation detected | auth.log sudo lines |
| `"wazuh_alert"` | EDR behavioural detection from Wazuh | Wazuh alerts.json (Filebeat) |
| `"port_scan"` | Reconnaissance scan activity | Snort or replayer `port_scan` category |

> [!IMPORTANT]
> `auth_success`, `auth_generic`, `app_generic`, and `unknown` event types are **NOT forwarded to UEBA**.
> The listener filters them out. Your UEBA model will never see a clean benign event directly — only anomalous ones.

---

## 5. Feature Provenance — Where Each Feature Actually Comes From

This is crucial for understanding the data quality and what the features represent in practice.

### 5.1 Features from CSV Data (real measurements)

| Feature | CIC-IDS-2017 source column | UNSW-NB15 source column | Notes |
|---|---|---|---|
| `src_ip` | ` Source IP` | `srcip` | Header has leading space in some CIC files |
| `dst_ip` | ` Destination IP` | `dstip` | Same |
| `session_duration` | ` Flow Duration` (µs ÷ 1e6) | `dur` (already seconds) | CIC stores microseconds — replayer converts |
| `external_connection` | Derived from `src_ip` RFC-1918 check | Same | Not a CSV column — computed |
| `attack_category` | ` Label` (normalized) | `attack_cat` (preferred) or `Label` | Used to drive synthesis rules below |

### 5.2 Features Synthesized by the Replayer (NOT from CSV — probabilistic)

These 4 features **do not exist in either dataset** and are synthesized by `synthesize_identity_features()` using attack-category-conditioned probability tables:

| Feature | How it's generated |
|---|---|
| `failed_logins` | `random.randint(lo, hi)` where lo/hi depend on attack category (e.g., brute_force → 8–30, benign → 0–1) |
| `privilege_change_attempted` | `random.random() < probability` where probability is category-conditioned (infiltration: 90%) |
| `MFA_bypassed` | Same pattern (infiltration: 80%, exploit: 50%, benign: 0%) |
| `device_trust_score` | `random.uniform(lo, hi)` — managed (internal, benign) → 0.70–1.00; unknown/attacker → 0.05–0.40 |

> [!WARNING]
> This is the most important caveat for UEBA design: **`failed_logins`, `privilege_change_attempted`, `MFA_bypassed`, and `device_trust_score` are statistical approximations, not ground-truth labels from the dataset.** They are realistic (conditioned on attack type) but they are not empirically measured. Your model must account for this if evaluating detection rates against dataset ground truth.

### 5.3 `access_time` — Synthesized Temporal Bias

Attack events are biased toward off-hours (00:00–05:59 and 22:00–23:59 UTC). Benign events are biased toward business hours (08:00–17:59 UTC). This is a **deliberate synthesis rule** designed to make the `suspicious_login` detection rule fire (Rule 2: off-hours + low trust = anomaly). Do not interpret `access_time` as the literal network capture time — that's in `timestamp`.

---

## 6. Concrete Event Examples

### 6.1 A Brute Force Event (from replayer, CIC dataset)

```json
{
  "event_id":    "XyZ1234ABC",
  "src_ip":      "45.33.1.22",
  "dst_ip":      "192.168.1.10",
  "user_id":     "admin",
  "event_type":  "failed_logins",
  "action":      "failed_login",
  "severity":    "medium",
  "timestamp":   "2026-04-15T02:14:33+00:00",
  "log_source":  "replayer",
  "endpoint_id": null,
  "snort_msg":   null,
  "wazuh_level": null,
  "src_country": "United States",
  "src_city":    "Los Angeles",
  "tags":        ["replayer", "synthetic", "possible_brute_force"],

  "failed_logins":              14,
  "privilege_change_attempted": 0,
  "external_connection":        1,
  "MFA_bypassed":               0,
  "session_duration":           0.048,
  "access_time":                "2026-04-15T02:14:33+00:00",
  "device_trust_score":         0.07,

  "detected_at":      "2026-04-15T17:52:01+00:00",
  "listener_version": "2.0.0",
  "zenguard_layer":   2
}
```

### 6.2 A Privilege Escalation + MFA Bypass (scenario trigger)

```json
{
  "event_id":    "ABc9876xyz",
  "src_ip":      "104.21.5.8",
  "dst_ip":      "192.168.1.22",
  "user_id":     "jsmith",
  "event_type":  "privilege_escalation",
  "action":      "privilege_escalation",
  "severity":    "high",
  "timestamp":   "2026-04-15T03:41:12+00:00",
  "log_source":  "replayer",
  "tags":        ["replayer", "synthetic"],

  "failed_logins":              0,
  "privilege_change_attempted": 1,
  "external_connection":        1,
  "MFA_bypassed":               1,
  "session_duration":           42.3,
  "access_time":                "2026-04-15T03:41:12+00:00",
  "device_trust_score":         0.05,

  "detected_at":      "2026-04-15T17:52:06+00:00",
  "listener_version": "2.0.0",
  "zenguard_layer":   2
}
```

### 6.3 A Snort IDS Alert

```json
{
  "event_id":    "snort_99abc",
  "src_ip":      "198.51.100.7",
  "dst_ip":      "192.168.1.5",
  "user_id":     "N/A",
  "event_type":  "snort_alerts",
  "action":      "ids_alert",
  "severity":    "critical",
  "timestamp":   "2026-04-15T04:02:55+00:00",
  "log_source":  "replayer",
  "snort_msg":   "ZenGuard SSH Brute Force Attempt",
  "tags":        ["replayer", "synthetic"],

  "failed_logins":              8,
  "privilege_change_attempted": 1,
  "external_connection":        1,
  "MFA_bypassed":               0,
  "session_duration":           0.12,
  "access_time":                "2026-04-15T04:02:55+00:00",
  "device_trust_score":         0.09,

  "detected_at":      "2026-04-15T17:52:09+00:00",
  "listener_version": "2.0.0",
  "zenguard_layer":   2
}
```

---

## 7. Attack Category → UEBA Feature Mapping Table

This is the synthesis rule table. If you want to understand what feature values look like for each attack class, use this:

| Attack Category | Source Dataset(s) | `failed_logins` | `priv_change_attempted` | `MFA_bypassed` | `device_trust_score` | `external_connection` | `access_time` bias |
|---|---|---|---|---|---|---|---|
| `benign` | CIC, UNSW | 0–1 | 2% prob | 0% | 0.70–1.00 (internal) | 0 (internal src) | Business hours (8–17h) |
| `brute_force` | CIC (SSH/FTP-Patator, Web BF) | **8–30** | 30% | 0% | 0.05–0.30 | 1 (external) | Off-hours (0–5h, 22–23h) |
| `dos_ddos` | CIC (DoS Hulk/GoldenEye/slowloris) | 0–2 | 0% | 0% | 0.05–0.25 | 1 | Off-hours |
| `port_scan` | CIC (PortScan), UNSW (Analysis, Recon) | 0–3 | 5% | 0% | 0.10–0.40 | 1 | Off-hours |
| `exploit` | CIC (XSS, SQLi, Heartbleed), UNSW (Fuzzers, Exploits, Generic) | 1–5 | **70%** | **50%** | 0.05–0.20 | 1 | Off-hours |
| `malware` | CIC (Bot), UNSW (Backdoors, Shellcode, Worms) | 2–10 | **80%** | **60%** | 0.05–0.15 | 1 | Off-hours |
| `infiltration` | CIC (Infiltration) | 3–15 | **90%** | **80%** | 0.05–0.10 | 1 | Off-hours |
| `unknown` | Any unrecognized label | 0–5 | 10% | 5% | 0.30–0.60 | varies | Off-hours |

---

## 8. What the Current Detection Engine Uses (and what's left for you)

The **detection engine** (Layer 3) already implements **rule-based detection** on the same 7 features. Understanding what it already does tells you what UEBA should add:

### What the rule engine already covers (deterministic thresholds):

| Rule | Logic | Decision boundary |
|---|---|---|
| Brute Force | `sum(failed_logins) >= 10` per user/IP in 1 min | Hard threshold |
| Suspicious Login | `hour in [0-4] AND trust < 0.5` | Two-variable AND |
| Privilege Escalation | `priv_change == 1 AND MFA_bypassed == 1` | Exact match |
| Lateral Movement | `len(unique_dst_ips) >= 3 AND external == 1` | Counting threshold |
| Data Exfiltration | `session_duration >= 3600 AND external == 1` | Hard threshold |

### What UEBA should add (statistical / ML-based):

The rule engine **cannot**:
- Detect **gradual/slow** brute-force (e.g., 1 attempt/hour, never hitting threshold=10)
- Detect **unusual-but-not-threshold-crossing** behavior (user logging in at 4:59 AM with trust=0.51)
- Build **user behavior baselines** and flag deviations (a user who normally works 9–5 suddenly accessing at 3 AM)
- **Score continuous risk** — the rule engine produces binary fired/not-fired per rule. UEBA should produce a continuous risk score per user/entity
- **Combine features non-linearly** — e.g., a user with `failed_logins=3`, `trust=0.4`, `external=1`, `access_hour=4` is highly suspicious but none of the 5 rules fires
- **Temporal sequence modeling** — detecting multi-step kill chains that unfold over hours/days beyond the 10-minute correlation window

---

## 9. Integration Contract — What You Receive, What You Must Return

### 9.1 What You Receive (inbound from siem_listener)

- **Protocol:** HTTP POST, `Content-Type: application/json`
- **Endpoint you expose:** configurable via `DASHBOARD_URL` env var in `siem_listener.py` (currently `http://localhost:5000/api/ingest`)
- **Frequency:** Every 5 seconds (one POST per poll cycle, if events exist)
- **Batch size:** Up to 200 events per batch (`MAX_EVENTS_PER_POLL`)
- **Payload:** The `zenguard/ueba-payload/v1` envelope (Section 2 above)

### 9.2 What You Must Return (HTTP response)

The listener only checks `response.raise_for_status()`. Any `2xx` response satisfies it. Recommended:

```json
HTTP 200 or 201
{
  "status": "ok",
  "processed": 12,
  "anomalies_detected": 3
}
```

If your endpoint returns 4xx/5xx or times out (>5 seconds), the listener logs a **warning** and the ES polling loop continues. Your endpoint failing never kills the pipeline.

### 9.3 What You Must Produce (outbound to dashboard)

The dashboard has a dedicated alerts endpoint at `POST /api/alerts/ingest`. Your UEBA anomaly outputs should POST to it. Accepted schemas:

**Option A — Single alert dict:**
```json
{
  "alert_id":    "<uuid>",
  "alert_type":  "ueba_anomaly",
  "severity":    "high",
  "user_id":     "admin",
  "src_ip":      "45.33.1.22",
  "dst_ip":      "192.168.1.10",
  "risk_score":  87.5,
  "is_correlated": false,
  "reason":      ["Anomaly score 3.2σ above user baseline", "Off-hours access from untrusted device"]
}
```

**Option B — UEBA envelope (same schema as detection engine uses):**
```json
{
  "schema_version": "zenguard/detection-alert/v1",
  "batch": { "generated_at": "...", "event_count": 1 },
  "events": [ { ...alert dict... } ]
}
```

The dashboard persists the alert to its `alerts` SQLite table and displays it in the frontend with the `is_correlated`, `risk_score`, and `reason` fields visible.

---

## 10. Data Quality Caveats — What You Must Design Around

> [!WARNING]
> These are critical design constraints. Ignoring them will produce misleading model evaluations.

| Caveat | Detail |
|---|---|
| **No real identity data in datasets** | CIC-IDS-2017 and UNSW-NB15 are pure network flow dumps. `user_id`, `failed_logins`, `privilege_change_attempted`, `MFA_bypassed`, `device_trust_score`, `access_time` are **all synthesized** — not measured. |
| **Benign events not forwarded** | The listener only forwards 5 anomalous event types. Your model sees a **pre-filtered stream** — you never see a clean normal event. If you need a baseline, you must query Elasticsearch `zenguard-*` directly for `event_type: auth_success`. |
| **`user_id` is synthetic** | Replayer generates usernames with `Faker` or a hardcoded pool (`jsmith`, `admin`, `root`, etc.). There is no real user behavioral history — you start from scratch. |
| **session_duration can be 0** | Many CIC-IDS-2017 flows have 0 or near-0 duration. Your exfiltration model thresholds should handle this gracefully. |
| **`src_ip = "0.0.0.0"` is a sentinel** | Zero-IP means IP was not parseable. You should skip or weight-down these events in your model. |
| **`user_id = "N/A"` for Snort events** | IDS alerts have no associated user — Snort fires on network traffic only. Your model must handle `N/A` users without crashing. |
| **`device_trust_score` default is 0.5** | Events that came through the Filebeat path (not replayer) may have `device_trust_score = 0.5` (the neutral default) because the Filebeat/Logstash pipeline has no device inventory to query. Only replayer events have realistic synthesized scores. |
| **Temporal context is shallow** | The listener's look-back window is 5 seconds. The detection engine is 5 minutes. Your UEBA model will need to query Elasticsearch directly for longer historical context (hours/days) to build user baselines. |
| **Tags indicate source** | If `"synthetic"` is in `tags`, the event came from the replayer. If `"possible_brute_force"` is in `tags`, Logstash's stateless heuristic already tagged it — you can use this as a weak feature signal. |

---

## 11. Directly Queryable ES Indices

If your UEBA model needs historical context beyond the 5-second window, query Elasticsearch directly:

| Index pattern | Content |
|---|---|
| `zenguard-*` | All events (replayer + Filebeat), full canonical schema |
| `zenguard-replayer-*` | Only replayer-originated events (has all 7 ML features reliably) |
| `zenguard-linux_auth-*` | SSH auth events from Filebeat |
| `zenguard-snort_ids-*` | IDS alerts from Filebeat |
| `zenguard-alerts-*` | Detection engine's structured alerts (rule-based Layer 3 output) |

**Connection:** `http://localhost:9200`, user: `elastic`, password: `ZenGuard@2024!`

Useful aggregation for user baseline building:
```json
GET zenguard-*/_search
{
  "size": 0,
  "aggs": {
    "by_user": {
      "terms": { "field": "user_id.keyword", "size": 100 },
      "aggs": {
        "avg_trust":     { "avg":  { "field": "device_trust_score" } },
        "total_fails":   { "sum":  { "field": "failed_logins" } },
        "event_types":   { "terms": { "field": "event_type.keyword" } }
      }
    }
  }
}
```

---

## 12. Quick-Reference Checklist for UEBA Developer

- [ ] **Stand up an HTTP endpoint** that accepts POST at `http://localhost:5000/api/ingest` (or change `DASHBOARD_URL` in `.env`)
- [ ] **Parse `payload["events"]`** — it's always a list; iterate it
- [ ] **Extract the 7 features** listed in Section 3.3 from each event dict — they are guaranteed present with typed defaults
- [ ] **Handle `user_id = "N/A"` and `src_ip = "0.0.0.0"`** — skip or use a global pool for these
- [ ] **Respond within 5 seconds** — the listener has a hard 5-second timeout on its POST
- [ ] **Accept that benign data is NOT in the stream** — only anomalous event types arrive
- [ ] **Account for synthesized features** — `failed_logins`, `privilege_change_attempted`, `MFA_bypassed`, `device_trust_score` are statistically realistic but not empirically measured from real users
- [ ] **POST your anomaly outputs to** `http://localhost:5001/api/alerts/ingest` with an `alert_id`, `alert_type`, `severity`, `risk_score`, `user_id`, `src_ip`, and `reason` list
- [ ] **Use `event_id` (= ES `_id`) as your idempotency key** — the listener may send overlapping events across adjacent poll cycles
- [ ] **Optionally query `zenguard-*` ES directly** for historical context to build user behavioral baselines
