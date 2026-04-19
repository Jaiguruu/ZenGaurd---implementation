"""
================================================================================
File: detection_engine/rules/brute_force.py
Project: ZenGuard Detection Engine

Rule 1: Brute Force Attack Detection
=====================================
Condition:
    failed_logins > BRUTE_FORCE_THRESHOLD (default 10)
    within BRUTE_FORCE_WINDOW_MINUTES (default 1 min)
    for the same user_id OR src_ip

Strategy:
    We receive all events from the look-back window. We group by (user_id, src_ip)
    and sum failed_logins. If the sum exceeds the threshold, we fire.

    Additionally, we count discrete failed_login events (event_type == "failed_logins")
    grouped by user_id and src_ip separately — catching both credential stuffing
    attacks (many users, same src_ip) and password spray attacks (same user, many IPs).

Output:
    alert_type = "brute_force"
    severity   = "high"
================================================================================
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from detection_engine.rules.base import DetectionRule, RuleResult
from detection_engine import config

log = logging.getLogger("zenguard.detection.rules.brute_force")


class BruteForceRule(DetectionRule):
    """
    Detects brute-force credential attacks by aggregating failed login counts
    per user_id and per src_ip within a rolling time window.

    Fires once per distinct attacking entity (user or IP) that crosses the
    threshold — so a single poll window may produce multiple RuleResult objects.
    """

    NAME        = "brute_force"
    DESCRIPTION = (
        "Detects a high volume of failed login attempts against the same "
        "user account or from the same source IP within a short time window, "
        "indicating a brute-force or credential-stuffing attack."
    )
    SEVERITY    = "high"
    ALERT_TYPE  = "brute_force"

    def evaluate(self, events: list[dict]) -> list[RuleResult]:
        """
        Group failed login events by user_id and src_ip.
        Return one RuleResult per entity that exceeds the threshold.
        """
        threshold       = config.BRUTE_FORCE_THRESHOLD
        window_minutes  = config.BRUTE_FORCE_WINDOW_MINUTES

        # --- Bucket accumulators ---
        # Each key maps to a list of matching events
        by_user: dict[str, list[dict]] = defaultdict(list)
        by_src:  dict[str, list[dict]] = defaultdict(list)

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        for evt in events:
            # Only consider failed_login events
            if evt.get("event_type") not in ("failed_logins", "failed_login"):
                continue

            # Event-level failed_logins count (a single event may represent N failures)
            count = int(evt.get("failed_logins", 1) or 1)

            user_id = evt.get("user_id") or "unknown"
            src_ip  = evt.get("src_ip")  or "0.0.0.0"

            # Skip sentinel values
            if user_id not in ("unknown", "N/A"):
                for _ in range(count):
                    by_user[user_id].append(evt)
            if src_ip != "0.0.0.0":
                for _ in range(count):
                    by_src[src_ip].append(evt)

        results: list[RuleResult] = []

        # --- Evaluate per-user ---
        for user_id, evts in by_user.items():
            if len(evts) >= threshold:
                unique_ips = {e.get("src_ip", "?") for e in evts}
                results.append(self._match(
                    reason=[
                        f"User '{user_id}' had {len(evts)} failed login attempts "
                        f"within {window_minutes} minute(s) "
                        f"(threshold: {threshold}).",
                        f"Source IP(s) involved: {', '.join(sorted(unique_ips))}.",
                        "This pattern is consistent with a brute-force or "
                        "credential-stuffing attack targeting a specific account.",
                    ],
                    matched_events=list({id(e): e for e in evts}.values()),  # dedup
                    risk_score_delta=35.0,
                    meta={
                        "entity_type": "user_id",
                        "entity_value": user_id,
                        "fail_count": len(evts),
                        "unique_src_ips": list(unique_ips),
                    },
                ))
                log.warning(
                    "BruteForce detected: user=%s count=%d ips=%s",
                    user_id, len(evts), unique_ips
                )

        # --- Evaluate per-source-IP ---
        for src_ip, evts in by_src.items():
            if len(evts) >= threshold:
                unique_users = {e.get("user_id", "?") for e in evts}
                results.append(self._match(
                    reason=[
                        f"Source IP {src_ip} generated {len(evts)} failed login "
                        f"attempts within {window_minutes} minute(s) "
                        f"(threshold: {threshold}).",
                        f"Targeted account(s): {', '.join(sorted(unique_users))}.",
                        "This pattern is consistent with a password spray attack "
                        "or horizontal credential-stuffing campaign.",
                    ],
                    matched_events=list({id(e): e for e in evts}.values()),
                    risk_score_delta=35.0,
                    meta={
                        "entity_type": "src_ip",
                        "entity_value": src_ip,
                        "fail_count": len(evts),
                        "unique_users": list(unique_users),
                    },
                ))
                log.warning(
                    "BruteForce detected: src_ip=%s count=%d users=%s",
                    src_ip, len(evts), unique_users
                )

        return results if results else [self._no_match()]
