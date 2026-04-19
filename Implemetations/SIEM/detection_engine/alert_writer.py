"""
================================================================================
File: detection_engine/alert_writer.py
Project: ZenGuard Detection Engine

Alert Writer
============
Responsible for:
  1. Formatting a structured alert JSON from a RuleResult / CorrelatedAlert.
  2. Writing the alert back to Elasticsearch (index: zenguard-alerts-YYYY.MM.dd).
  3. POSTing the alert to the Flask dashboard's /api/alerts/ingest endpoint.

Alert Schema
------------
{
    "alert_id":         "<uuid>",
    "alert_type":       "<brute_force|suspicious_login|...>",
    "severity":         "<critical|high|medium|low>",
    "user_id":          "<...>",
    "src_ip":           "<...>",
    "dst_ip":           "<...>",           -- if available
    "reason":           ["...", "..."],    -- explainable evidence list
    "risk_score":       <0-100>,
    "risk_score_breakdown": { ... },
    "is_correlated":    <bool>,
    "correlated_chain": "<chain_name>",   -- if correlated
    "contributing_alerts": [ ... ],       -- alert_types that formed the chain
    "source_events":    [ ... ],          -- raw matched event IDs
    "timestamp":        "<ISO8601 UTC>",
    "zenguard_layer":   3
}
================================================================================
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

import requests

from detection_engine.rules.base import RuleResult
from detection_engine.scorer import ScoreResult
from detection_engine import config

if TYPE_CHECKING:
    from detection_engine.correlator import CorrelatedAlert

log = logging.getLogger("zenguard.detection.alert_writer")


# ---------------------------------------------------------------------------
# Alert Formatter
# ---------------------------------------------------------------------------

def _extract_entity(results: list[RuleResult]) -> dict[str, str]:
    """Pull the most complete user_id / src_ip / dst_ip from matched events."""
    user_id = "unknown"
    src_ip  = "unknown"
    dst_ip  = "unknown"

    for r in results:
        for evt in r.matched_events:
            u = evt.get("user_id") or user_id
            s = evt.get("src_ip")  or src_ip
            d = evt.get("dst_ip")  or dst_ip
            if u not in ("unknown", "N/A", None):
                user_id = u
            if s not in ("0.0.0.0", "unknown", None):
                src_ip = s
            if d not in ("0.0.0.0", "unknown", None):
                dst_ip = d

        # Also check meta
        user_id = r.meta.get("user_id", user_id) or user_id
        src_ip  = r.meta.get("src_ip",  src_ip)  or src_ip

    return {"user_id": user_id, "src_ip": src_ip, "dst_ip": dst_ip}


def build_rule_alert(
    result:       RuleResult,
    score_result: ScoreResult,
    all_triggered: list[RuleResult],
) -> dict[str, Any]:
    """
    Build a structured alert dict from a single triggered RuleResult.

    Args:
        result:        The specific RuleResult for this alert.
        score_result:  The composite ScoreResult for this poll cycle.
        all_triggered: All triggered results (for entity extraction).
    """
    now = datetime.now(timezone.utc).isoformat()
    entity = _extract_entity([result])

    # Extract all matched event IDs for traceability
    source_event_ids = [
        evt.get("event_id") for evt in result.matched_events
        if evt.get("event_id")
    ]

    return {
        "alert_id":        str(uuid.uuid4()),
        "alert_type":      result.alert_type,
        "severity":        result.severity,
        "user_id":         entity["user_id"],
        "src_ip":          entity["src_ip"],
        "dst_ip":          entity["dst_ip"],
        "reason":          result.reason,
        "risk_score":      score_result.score,
        "risk_score_breakdown": {
            "raw_sum":             score_result.raw_sum,
            "bonus_applied":       score_result.bonus_applied,
            "bonus_reasons":       score_result.bonus_reasons,
            "contributing_rules":  score_result.contributing_rules,
        },
        "is_correlated":     False,
        "correlated_chain":  None,
        "contributing_alerts": score_result.contributing_rules,
        "source_events":    source_event_ids,
        "meta":             result.meta,
        "timestamp":        now,
        "zenguard_layer":   3,
        # Shadow-fields for dashboard compatibility (mirrors events schema)
        "event_type":  result.alert_type,
        "action":      f"detection_rule:{result.alert_type}",
        "log_source":  "zenguard_detection_engine",
    }


def build_correlated_alert(
    corr:         "CorrelatedAlert",
    score_result: ScoreResult,
) -> dict[str, Any]:
    """
    Build a structured alert dict from a CorrelatedAlert.
    """
    now = datetime.now(timezone.utc).isoformat()
    entity = _extract_entity(corr.matched_results)

    source_event_ids = list({
        evt.get("event_id")
        for r in corr.matched_results
        for evt in r.matched_events
        if evt.get("event_id")
    })

    # Correlated alerts get the composite score + bonus
    final_score = min(score_result.score + corr.risk_score_bonus, 100.0)

    return {
        "alert_id":        str(uuid.uuid4()),
        "alert_type":      corr.alert_type,
        "severity":        corr.severity,
        "user_id":         corr.user_id or entity["user_id"],
        "src_ip":          corr.src_ip  or entity["src_ip"],
        "dst_ip":          entity["dst_ip"],
        "reason":          corr.reason,
        "risk_score":      round(final_score, 1),
        "risk_score_breakdown": {
            "raw_sum":             score_result.raw_sum,
            "bonus_applied":       score_result.bonus_applied + corr.risk_score_bonus,
            "bonus_reasons":       score_result.bonus_reasons,
            "contributing_rules":  score_result.contributing_rules,
            "correlation_bonus":   corr.risk_score_bonus,
        },
        "is_correlated":     True,
        "correlated_chain":  corr.alert_type,
        "contributing_alerts": corr.contributing_alert_types,
        "source_events":    source_event_ids,
        "meta":             {
            "chain_alert_types": corr.contributing_alert_types,
        },
        "timestamp":       now,
        "zenguard_layer":  3,
        # Dashboard compatibility
        "event_type":  corr.alert_type,
        "action":      f"correlation:{corr.alert_type}",
        "log_source":  "zenguard_correlator",
    }


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_to_elasticsearch(alert: dict, es_client, index_prefix: str) -> bool:
    """
    Index an alert into Elasticsearch.

    Args:
        alert:        The alert dict to index.
        es_client:    An already-connected Elasticsearch client.
        index_prefix: e.g. "zenguard-alerts" → index name "zenguard-alerts-2024.01.15"

    Returns:
        True if successful, False on error.
    """
    from datetime import datetime
    date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index    = f"{index_prefix}-{date_str}"

    try:
        resp = es_client.index(
            index    = index,
            id       = alert["alert_id"],
            document = alert,
        )
        log.info(
            "Alert indexed to ES: id=%s type=%s severity=%s index=%s result=%s",
            alert["alert_id"], alert["alert_type"], alert["severity"],
            index, resp.get("result")
        )
        return True

    except Exception as exc:
        log.error("Failed to index alert to ES: %s — alert_id=%s", exc, alert["alert_id"])
        return False


def write_to_dashboard(alert: dict, dashboard_url: str) -> bool:
    """
    POST an alert to the Flask dashboard's /api/alerts/ingest endpoint.

    The dashboard expects the same envelope format as the UEBA hand-off
    from siem_listener.py, but we wrap a single alert in the envelope so
    the dashboard can display it alongside regular events.

    Returns:
        True if HTTP 200/201, False otherwise.
    """
    # Wrap in the standard UEBA envelope so the dashboard's /api/ingest
    # can also accept alerts if /api/alerts/ingest is not yet implemented.
    envelope = {
        "schema_version": "zenguard/detection-alert/v1",
        "batch": {
            "generated_at":  alert["timestamp"],
            "event_count":   1,
            "alert_type":    alert["alert_type"],
        },
        "events": [alert],
    }

    try:
        resp = requests.post(dashboard_url, json=envelope, timeout=5)
        resp.raise_for_status()
        log.info(
            "Alert POSTed to dashboard: type=%s severity=%s status=%d",
            alert["alert_type"], alert["severity"], resp.status_code
        )
        return True
    except requests.exceptions.RequestException as exc:
        log.warning(
            "Dashboard POST failed (non-fatal): %s — alert_id=%s",
            exc, alert.get("alert_id")
        )
        return False


class AlertWriter:
    """
    Coordinates alert formatting and dual-channel output (ES + Dashboard).
    """

    def __init__(self, es_client, alerts_index: str, dashboard_url: str):
        self.es           = es_client
        self.alerts_index = alerts_index
        self.dash_url     = dashboard_url

    def emit_rule_alert(
        self,
        result:        RuleResult,
        score_result:  ScoreResult,
        all_triggered: list[RuleResult],
    ) -> dict:
        """Build and emit a rule-based alert. Returns the alert dict."""
        alert = build_rule_alert(result, score_result, all_triggered)
        self._emit(alert)
        return alert

    def emit_correlated_alert(
        self,
        corr:         "CorrelatedAlert",
        score_result:  ScoreResult,
    ) -> dict:
        """Build and emit a correlated alert. Returns the alert dict."""
        alert = build_correlated_alert(corr, score_result)
        self._emit(alert)
        return alert

    def _emit(self, alert: dict) -> None:
        """Write to both ES and the dashboard (failures are non-fatal)."""
        log.info(
            "ALERT EMITTED | type=%-25s severity=%-8s score=%.1f | user=%s src=%s",
            alert["alert_type"],
            alert["severity"],
            alert["risk_score"],
            alert["user_id"],
            alert["src_ip"],
        )
        write_to_elasticsearch(alert, self.es, self.alerts_index)
        write_to_dashboard(alert, self.dash_url)
