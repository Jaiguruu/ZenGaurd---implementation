#!/usr/bin/env python3
"""
================================================================================
File: run_detection_engine.py
Project: ZenGuard Zero Trust SIEM — Layer 3: Detection Engine

Description:
    Top-level entrypoint for the ZenGuard rule-based SIEM detection engine.

    Run alongside siem_listener.py (in a separate terminal or systemd unit).
    The detection engine independently polls Elasticsearch and generates
    structured, explainable alerts.

Usage:
    # Standard run (reads config from environment / defaults):
    python run_detection_engine.py

    # With overrides:
    ES_HOST=http://localhost:9200 LOOK_BACK_MINUTES=2 python run_detection_engine.py

    # With dotenv loaded automatically:
    python run_detection_engine.py  # .env in working directory is auto-loaded

Architecture:
    Elasticsearch (zenguard-*)
           ↓ poll every 5s
    [DetectionEngine]
       ├─ RULE_REGISTRY (5 rules)
       ├─ Correlator (chain detection)
       ├─ Scorer (risk 0-100)
       └─ AlertWriter
              ├─ ES: zenguard-alerts-YYYY.MM.dd
              └─ Flask dashboard: POST /api/alerts/ingest
================================================================================
"""

import os
import sys

# ---------------------------------------------------------------------------
# Load .env before importing config (so env vars are in place at import time)
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(_env_path):
        load_dotenv(_env_path)
        print(f"[run_detection_engine] Loaded environment from {_env_path}")
    else:
        print("[run_detection_engine] No .env file found — using system environment.")
except ImportError:
    print("[run_detection_engine] python-dotenv not installed; skipping .env load.")

# ---------------------------------------------------------------------------
# Run the engine
# ---------------------------------------------------------------------------
from detection_engine.engine import main

if __name__ == "__main__":
    main()
