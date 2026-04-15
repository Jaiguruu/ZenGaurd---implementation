"""
================================================================================
File: detection_engine/rules/data_exfiltration.py
Project: ZenGuard Detection Engine

Rule 5: Data Exfiltration Indicator
======================================
Condition:
    session_duration >= EXFIL_SESSION_DURATION_THRESHOLD (default: 3600 s / 1 hr)
    AND external_connection == true

Rationale:
    A long-running session that is simultaneously transferring data to an
    external host is a classic data-exfiltration signature. The session_duration
    field captures how long a connection/session has been active, and
    external_connection flags traffic that leaves the perimeter.

Output:
    alert_type = "data_exfiltration"
    severity   = "high"
================================================================================
"""

from __future__ import annotations

import logging
from typing import Any

from detection_engine.rules.base import DetectionRule, RuleResult
from detection_engine import config

log = logging.getLogger("zenguard.detection.rules.data_exfiltration")


def _is_external(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.lower() in ("1", "true", "yes")
    return False


def _format_duration(seconds: float) -> str:
    """Human-readable duration string."""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


class DataExfiltrationRule(DetectionRule):
    """
    Detects potential data exfiltration via anomalously long sessions
    that are simultaneously connected to external networks.
    """

    NAME        = "data_exfiltration"
    DESCRIPTION = (
        "Detects sessions that exceed the normal duration threshold while "
        "simultaneously maintaining an external (internet-facing) connection, "
        "a pattern consistent with data exfiltration via slow/steady transfer."
    )
    SEVERITY    = "high"
    ALERT_TYPE  = "data_exfiltration"

    def evaluate(self, events: list[dict]) -> list[RuleResult]:
        threshold  = config.EXFIL_SESSION_DURATION_THRESHOLD
        results: list[RuleResult] = []

        for evt in events:
            session_dur = float(evt.get("session_duration", 0.0) or 0.0)
            is_external = _is_external(evt.get("external_connection", False))

            if session_dur >= threshold and is_external:
                user_id = evt.get("user_id", "unknown")
                src_ip  = evt.get("src_ip",  "0.0.0.0")
                dst_ip  = evt.get("dst_ip",  "unknown")

                results.append(self._match(
                    reason=[
                        f"Session from user '{user_id}' (src: {src_ip} → dst: {dst_ip}) "
                        f"has been active for {_format_duration(session_dur)}, "
                        f"which exceeds the threshold of {_format_duration(threshold)}.",
                        "external_connection=true confirms this session is "
                        "communicating with an external/internet-facing host.",
                        "Long-duration external sessions are indicative of "
                        "slow-and-low data exfiltration, C2 beaconing, or "
                        "unauthorized data staging.",
                    ],
                    matched_events=[evt],
                    risk_score_delta=30.0,
                    meta={
                        "user_id":          user_id,
                        "src_ip":           src_ip,
                        "dst_ip":           dst_ip,
                        "session_duration": session_dur,
                        "threshold":        threshold,
                    },
                ))
                log.warning(
                    "DataExfiltration detected: user=%s src=%s dst=%s duration=%.0fs",
                    user_id, src_ip, dst_ip, session_dur
                )

        return results if results else [self._no_match()]
