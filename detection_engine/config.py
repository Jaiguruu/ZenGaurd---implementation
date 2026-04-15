"""
================================================================================
File: detection_engine/config.py
Project: ZenGuard Detection Engine

All runtime configuration is sourced from environment variables with safe
defaults. This keeps the engine 12-factor compliant and Docker-friendly.
================================================================================
"""

import os

# ---------------------------------------------------------------------------
# Elasticsearch connection (mirrors siem_listener.py settings)
# ---------------------------------------------------------------------------
ES_HOST     = os.getenv("ES_HOST",     "http://localhost:9200")
ES_USER     = os.getenv("ES_USER",     "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "ZenGuard@2024!")
ES_INDEX    = os.getenv("ES_INDEX",    "zenguard-*")

# Index where the engine will write generated alerts
ALERTS_INDEX_PREFIX = os.getenv("ALERTS_INDEX_PREFIX", "zenguard-alerts")

# ---------------------------------------------------------------------------
# Polling & time-window settings
# ---------------------------------------------------------------------------
POLL_INTERVAL_S    = int(os.getenv("POLL_INTERVAL_S",    "5"))   # seconds
LOOK_BACK_MINUTES  = int(os.getenv("LOOK_BACK_MINUTES",  "5"))   # sliding window
MAX_EVENTS_PER_POLL = int(os.getenv("MAX_EVENTS_PER_POLL", "500"))

# ---------------------------------------------------------------------------
# Downstream integration
# ---------------------------------------------------------------------------
# The existing Flask dashboard ingest endpoint
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:5001/api/ingest")

# New dedicated alerts endpoint on the dashboard (added in dashboard/app.py)
ALERTS_DASHBOARD_URL = os.getenv(
    "ALERTS_DASHBOARD_URL", "http://localhost:5001/api/alerts/ingest"
)

# ---------------------------------------------------------------------------
# Detection thresholds (all overridable via env)
# ---------------------------------------------------------------------------

# Rule 1 — Brute Force
BRUTE_FORCE_THRESHOLD       = int(os.getenv("BRUTE_FORCE_THRESHOLD", "10"))
BRUTE_FORCE_WINDOW_MINUTES  = int(os.getenv("BRUTE_FORCE_WINDOW_MINUTES", "1"))

# Rule 2 — Suspicious Login
SUSPICIOUS_LOGIN_START_HOUR   = int(os.getenv("SUSPICIOUS_LOGIN_START_HOUR",   "0"))  # 00:00
SUSPICIOUS_LOGIN_END_HOUR     = int(os.getenv("SUSPICIOUS_LOGIN_END_HOUR",     "5"))  # 05:00
SUSPICIOUS_TRUST_SCORE_CUTOFF = float(os.getenv("SUSPICIOUS_TRUST_SCORE_CUTOFF", "0.5"))

# Rule 5 — Data Exfiltration
EXFIL_SESSION_DURATION_THRESHOLD = float(
    os.getenv("EXFIL_SESSION_DURATION_THRESHOLD", "3600")  # seconds (1 hour)
)

# ---------------------------------------------------------------------------
# Lateral movement
# ---------------------------------------------------------------------------
LATERAL_MOVEMENT_UNIQUE_DST_IPS = int(os.getenv("LATERAL_MOVEMENT_UNIQUE_DST_IPS", "3"))
LATERAL_MOVEMENT_WINDOW_MINUTES = int(os.getenv("LATERAL_MOVEMENT_WINDOW_MINUTES", "5"))

# ---------------------------------------------------------------------------
# Correlation settings
# ---------------------------------------------------------------------------
CORRELATION_WINDOW_MINUTES = int(os.getenv("CORRELATION_WINDOW_MINUTES", "10"))

# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------
RETRY_MAX          = int(os.getenv("RETRY_MAX",           "10"))
RETRY_BASE_DELAY_S = float(os.getenv("RETRY_BASE_DELAY_S", "2.0"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE  = os.getenv("DETECTION_LOG_FILE", None)   # None → stdout only
