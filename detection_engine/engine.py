"""
================================================================================
File: detection_engine/engine.py
Project: ZenGuard Detection Engine

Main Detection Engine — Entry Point
=====================================
The DetectionEngine class is the orchestrator that ties together:
  - Elasticsearch polling (every POLL_INTERVAL_S seconds)
  - Event extraction (reuses siem_listener.py's extract_metadata logic)
  - Rule evaluation (RULE_REGISTRY)
  - Correlation (Correlator)
  - Risk scoring (scorer)
  - Alert output (AlertWriter → ES + Dashboard)

Architecture Position
---------------------
    siem_listener.py  →  ES (zenguard-*)
                                ↓  poll every 5s
                       [DetectionEngine]      ← THIS MODULE
                         │   │   │
                         │   │   └──▶ Rule 1–5 evaluation
                         │   └──────▶ Correlation engine
                         └──────────▶ Risk scorer
                                          ↓
                              AlertWriter → zenguard-alerts-* (ES)
                                        → dashboard /api/alerts/ingest

Usage
-----
    # Direct run:
    python -m detection_engine.engine

    # Via run_detection_engine.py:
    python run_detection_engine.py
================================================================================
"""

from __future__ import annotations

import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Any

from elasticsearch import (
    Elasticsearch,
    AuthenticationException,
    ConnectionError as ESConnectionError,
)
from elasticsearch.exceptions import NotFoundError, RequestError, TransportError

from detection_engine import config
from detection_engine.rules import RULE_REGISTRY
from detection_engine.rules.base import RuleResult
from detection_engine.correlator import Correlator
from detection_engine.scorer import compute_risk_score
from detection_engine.alert_writer import AlertWriter

log = logging.getLogger("zenguard.detection.engine")


# ==============================================================================
# LOGGING SETUP
# ==============================================================================

class _JsonFormatter(logging.Formatter):
    """Machine-parseable JSON log lines for easy shipping to Elasticsearch."""

    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "ts":     datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level":  record.levelname,
            "logger": record.name,
            "msg":    record.getMessage(),
            "module": record.module,
            "line":   record.lineno,
        }
        if record.exc_info:
            obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(obj)


def _setup_logging(level: str, log_file: str | None) -> None:
    root = logging.getLogger("zenguard")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root.addHandler(handler)

    if log_file:
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
        fh.setFormatter(_JsonFormatter())
        root.addHandler(fh)


# ==============================================================================
# ELASTICSEARCH QUERY — All events in the look-back window
# ==============================================================================

def _build_detection_query(look_back_minutes: int, max_size: int) -> dict:
    """
    Fetch ALL events (not just specific event_types) from the look-back window.

    The detection rules themselves filter by field values — so we want the
    broadest possible event set to catch cross-type correlations
    (e.g., a failed_login event on the same user_id as a privilege_escalation).
    """
    return {
        "size": max_size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": [
            "@timestamp", "timestamp",
            "src_ip", "dst_ip", "user_id",
            "event_type", "action", "severity",
            "log_source", "endpoint_id",
            # UEBA features
            "failed_logins", "privilege_change_attempted",
            "MFA_bypassed", "device_trust_score",
            "session_duration", "external_connection", "access_time",
            "tags",
        ],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{look_back_minutes}m",
                                "lte": "now",
                            }
                        }
                    }
                ]
            }
        },
    }


def _extract_event(hit: dict) -> dict[str, Any]:
    """
    Normalize a single ES hit into the ZenGuard event schema.
    Mirrors siem_listener.py's extract_metadata() but includes all
    UEBA feature fields needed by the detection rules.
    """
    src = hit.get("_source", {})
    ts  = src.get("timestamp") or src.get("@timestamp") or datetime.now(timezone.utc).isoformat()

    return {
        "event_id":    hit.get("_id"),
        "src_ip":      src.get("src_ip")     or "0.0.0.0",
        "dst_ip":      src.get("dst_ip")     or "0.0.0.0",
        "user_id":     src.get("user_id")    or "unknown",
        "event_type":  src.get("event_type") or "unknown",
        "action":      src.get("action"),
        "severity":    src.get("severity")   or "low",
        "log_source":  src.get("log_source"),
        "endpoint_id": src.get("endpoint_id"),
        "timestamp":   ts,
        "tags":        src.get("tags", []),
        # UEBA features
        "failed_logins":              int(src.get("failed_logins",             0)   or 0),
        "privilege_change_attempted": int(src.get("privilege_change_attempted", 0)  or 0),
        "external_connection":        int(src.get("external_connection",        0)   or 0),
        "MFA_bypassed":               int(src.get("MFA_bypassed",               0)   or 0),
        "session_duration":           float(src.get("session_duration",         0.0) or 0.0),
        "access_time":                src.get("access_time") or ts,
        "device_trust_score":         float(src.get("device_trust_score",       0.5) or 0.5),
    }


# ==============================================================================
# DETECTION ENGINE
# ==============================================================================

class DetectionEngine:
    """
    Main orchestrator for ZenGuard rule-based detection.

    Lifecycle:
        engine = DetectionEngine()
        engine.run()   ← blocking daemon loop

    The engine can also be invoked for a single evaluation cycle:
        engine = DetectionEngine()
        engine.poll_and_detect()  ← for testing / manual invocation
    """

    def __init__(self):
        _setup_logging(config.LOG_LEVEL, config.LOG_FILE)
        self.correlator  = Correlator(window_minutes=config.CORRELATION_WINDOW_MINUTES)
        self._es: Elasticsearch | None = None
        self._alert_writer: AlertWriter | None = None
        self._retry_count = 0

        log.info(
            "DetectionEngine initialized | rules=%d | poll_interval=%ds | "
            "look_back=%dmin | corr_window=%dmin",
            len(RULE_REGISTRY),
            config.POLL_INTERVAL_S,
            config.LOOK_BACK_MINUTES,
            config.CORRELATION_WINDOW_MINUTES,
        )

    # ------------------------------------------------------------------
    # CONNECTION
    # ------------------------------------------------------------------

    def _connect(self) -> bool:
        """
        Attempt to connect to Elasticsearch.
        Returns True on success, False on failure (handles backoff externally).
        """
        try:
            self._es = Elasticsearch(
                hosts=[config.ES_HOST],
                basic_auth=(config.ES_USER, config.ES_PASSWORD),
                retry_on_timeout=True,
                max_retries=3,
                retry_on_status=(429, 502, 503, 504),
                connections_per_node=2,
                request_timeout=30,
            )
            if not self._es.ping():
                raise ESConnectionError("Ping failed")

            info = self._es.info()
            log.info(
                "Connected to Elasticsearch | cluster=%s version=%s",
                info.get("cluster_name"),
                info.get("version", {}).get("number"),
            )

            self._alert_writer = AlertWriter(
                es_client    = self._es,
                alerts_index = config.ALERTS_INDEX_PREFIX,
                dashboard_url = config.ALERTS_DASHBOARD_URL,
            )
            self._retry_count = 0
            return True

        except AuthenticationException as exc:
            log.critical("ES authentication failed: %s — check ES_USER/ES_PASSWORD", exc)
            sys.exit(2)
        except (ESConnectionError, TransportError) as exc:
            log.error("Cannot connect to Elasticsearch: %s", exc)
            return False

    # ------------------------------------------------------------------
    # SINGLE POLL CYCLE
    # ------------------------------------------------------------------

    def poll_and_detect(self) -> list[dict]:
        """
        Execute one full detection cycle:
          1. Query ES for events in the look-back window.
          2. Run all rules against the event set.
          3. Run the correlator against triggered results.
          4. Score and emit alerts.

        Returns:
            List of emitted alert dicts (empty if no rules fired).
        """
        assert self._es is not None, "Call _connect() before poll_and_detect()"

        # --- Step 1: Fetch events ---
        query = _build_detection_query(config.LOOK_BACK_MINUTES, config.MAX_EVENTS_PER_POLL)
        try:
            resp = self._es.search(
                index       = config.ES_INDEX,
                body        = query,
                ignore_unavailable = True,
                allow_no_indices   = True,
            )
        except (NotFoundError, RequestError, ESConnectionError, TransportError) as exc:
            raise  # propagate so run() can handle retry logic

        hits  = resp.get("hits", {}).get("hits", [])
        total = resp.get("hits", {}).get("total", {}).get("value", 0)

        log.debug("Fetched %d events (total in window: %d)", len(hits), total)

        if not hits:
            return []

        events = [_extract_event(hit) for hit in hits]

        # --- Step 2: Evaluate rules ---
        all_results:     list[RuleResult] = []
        triggered_results: list[RuleResult] = []

        for rule in RULE_REGISTRY:
            try:
                rule_results = rule.evaluate(events)
                for r in rule_results:
                    all_results.append(r)
                    if r.triggered:
                        triggered_results.append(r)
                        log.debug("Rule fired: %s — %d matched events", rule.NAME, len(r.matched_events))
            except Exception as exc:
                log.error("Rule %s raised exception: %s", rule.NAME, exc, exc_info=True)

        if not triggered_results:
            log.debug("No rules fired in this cycle.")
            return []

        # --- Step 3: Compute composite risk score ---
        score_result = compute_risk_score(triggered_results)
        log.info(
            "Cycle | events=%d | triggered_rules=%d | risk_score=%.1f",
            len(events), len(triggered_results), score_result.score
        )

        # --- Step 4: Emit per-rule alerts ---
        emitted_alerts: list[dict] = []
        for result in triggered_results:
            try:
                alert = self._alert_writer.emit_rule_alert(result, score_result, triggered_results)
                emitted_alerts.append(alert)
            except Exception as exc:
                log.error("Failed to emit rule alert for %s: %s", result.alert_type, exc, exc_info=True)

        # --- Step 5: Run correlation and emit correlated alerts ---
        correlated = self.correlator.ingest(triggered_results)
        for corr in correlated:
            try:
                alert = self._alert_writer.emit_correlated_alert(corr, score_result)
                emitted_alerts.append(alert)
            except Exception as exc:
                log.error("Failed to emit correlated alert %s: %s", corr.alert_type, exc, exc_info=True)

        # --- Step 6: Periodic correlator cleanup ---
        self.correlator.cleanup()

        return emitted_alerts

    # ------------------------------------------------------------------
    # DAEMON LOOP
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Blocking daemon loop. Polls ES every POLL_INTERVAL_S seconds.
        Implements exponential backoff for connection failures.
        """
        log.info("ZenGuard Detection Engine starting. Press Ctrl+C to stop.")

        while True:
            # --- Connection phase ---
            if self._es is None:
                if self._retry_count >= config.RETRY_MAX:
                    log.critical(
                        "Exceeded %d reconnection attempts. Exiting.", config.RETRY_MAX
                    )
                    sys.exit(1)

                delay = min(
                    config.RETRY_BASE_DELAY_S * (2 ** self._retry_count)
                    * (1 + random.uniform(-0.2, 0.2)),
                    120,
                )
                if self._retry_count > 0:
                    log.info(
                        "Retrying ES connection in %.1fs (attempt %d/%d)...",
                        delay, self._retry_count + 1, config.RETRY_MAX
                    )
                    time.sleep(delay)

                if not self._connect():
                    self._retry_count += 1
                    continue

            # --- Poll phase ---
            cycle_start = time.monotonic()
            try:
                alerts = self.poll_and_detect()
                if alerts:
                    log.info("Cycle complete: %d alert(s) emitted.", len(alerts))

            except (ESConnectionError, TransportError) as exc:
                log.error("ES connection lost during poll: %s", exc)
                self._es = None
                self._retry_count += 1
                continue

            except NotFoundError:
                log.debug("No indices matched zenguard-* (normal on fresh deploy).")

            except RequestError as exc:
                log.error("ES query error (check DSL): %s", exc)

            except Exception as exc:
                log.exception("Unexpected error in detection cycle: %s", exc)

            # --- Sleep to maintain poll interval ---
            elapsed = time.monotonic() - cycle_start
            sleep_s = max(0.0, config.POLL_INTERVAL_S - elapsed)
            log.debug("Cycle took %.3fs, sleeping %.3fs.", elapsed, sleep_s)
            time.sleep(sleep_s)


# ==============================================================================
# ENTRY POINT
# ==============================================================================

def main() -> None:
    engine = DetectionEngine()
    try:
        engine.run()
    except KeyboardInterrupt:
        log.info("ZenGuard Detection Engine shutting down gracefully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
