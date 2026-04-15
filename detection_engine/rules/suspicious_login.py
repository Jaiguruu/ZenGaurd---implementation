"""
================================================================================
File: detection_engine/rules/suspicious_login.py
Project: ZenGuard Detection Engine

Rule 2: Suspicious Login Behavior
===================================
Condition:
    access_time is outside the normal business window (00:00 – 05:00 UTC)
    AND device_trust_score < 0.5 (untrusted or unknown device)

Each qualifying event is evaluated independently (unlike brute_force, which
requires aggregation across events). A single event matching both criteria
produces one RuleResult.

Output:
    alert_type = "suspicious_login"
    severity   = "medium"
================================================================================
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from detection_engine.rules.base import DetectionRule, RuleResult
from detection_engine import config

log = logging.getLogger("zenguard.detection.rules.suspicious_login")

# ---------------------------------------------------------------------------
# Helper: parse access_time to a datetime object
# ---------------------------------------------------------------------------

def _parse_access_time(raw: Any) -> datetime | None:
    """
    Attempt to parse the access_time field.
    ZenGuard events store it as ISO8601 string (from the replayer) or a
    direct @timestamp copy. Returns UTC datetime or None on parse failure.
    """
    if isinstance(raw, datetime):
        return raw.astimezone(timezone.utc)

    if not isinstance(raw, str):
        return None

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(raw[:26].rstrip("Z"), fmt.rstrip("Z"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


class SuspiciousLoginRule(DetectionRule):
    """
    Flags login events that occur during off-hours AND come from an
    untrusted device, a combination that significantly elevates the
    probability of account compromise.
    """

    NAME        = "suspicious_login"
    DESCRIPTION = (
        "Detects login activity during anomalous hours (midnight–5am) "
        "combined with a low device trust score, indicating a potential "
        "account compromise or insider threat from an unmanaged device."
    )
    SEVERITY    = "medium"
    ALERT_TYPE  = "suspicious_login"

    def evaluate(self, events: list[dict]) -> list[RuleResult]:
        results: list[RuleResult] = []

        start_hour   = config.SUSPICIOUS_LOGIN_START_HOUR   # 0
        end_hour     = config.SUSPICIOUS_LOGIN_END_HOUR     # 5
        trust_cutoff = config.SUSPICIOUS_TRUST_SCORE_CUTOFF # 0.5

        for evt in events:
            # Consider all login events (successful or failed); off-hours
            # failed logins from untrusted devices are equally suspicious.
            access_time_raw  = evt.get("access_time") or evt.get("timestamp")
            trust_score      = float(evt.get("device_trust_score", 1.0) or 1.0)
            user_id          = evt.get("user_id", "unknown")
            src_ip           = evt.get("src_ip", "0.0.0.0")

            dt = _parse_access_time(access_time_raw)
            if dt is None:
                self.log.debug(
                    "Could not parse access_time for event %s — skipping",
                    evt.get("event_id")
                )
                continue

            hour = dt.hour  # UTC hour (0–23)

            # Check: off-hours window (default: 00:00–05:00 UTC)
            off_hours = start_hour <= hour < end_hour

            # Check: device trust score below threshold
            low_trust = trust_score < trust_cutoff

            if off_hours and low_trust:
                results.append(self._match(
                    reason=[
                        f"Login event for user '{user_id}' (src: {src_ip}) "
                        f"occurred at {dt.strftime('%H:%M:%S UTC')}, which falls "
                        f"within the suspicious window ({start_hour:02d}:00–{end_hour:02d}:00 UTC).",
                        f"Device trust score is {trust_score:.2f}, which is below "
                        f"the minimum trusted threshold of {trust_cutoff:.2f}.",
                        "Combination of off-hours access + untrusted device is a "
                        "high-confidence indicator of account compromise or "
                        "unauthorized access from a personal/unmanaged device.",
                    ],
                    matched_events=[evt],
                    risk_score_delta=25.0,
                    meta={
                        "access_hour_utc": hour,
                        "device_trust_score": trust_score,
                        "user_id": user_id,
                        "src_ip": src_ip,
                    },
                ))
                log.warning(
                    "SuspiciousLogin detected: user=%s src=%s hour=%d trust=%.2f",
                    user_id, src_ip, hour, trust_score
                )

        return results if results else [self._no_match()]
