"""
================================================================================
File: detection_engine/rules/lateral_movement.py
Project: ZenGuard Detection Engine

Rule 4: Possible Lateral Movement
===================================
Condition:
    Same src_ip contacts >= LATERAL_MOVEMENT_UNIQUE_DST_IPS (default: 3)
    unique destination IPs within LATERAL_MOVEMENT_WINDOW_MINUTES
    AND at least one of those events has external_connection == true

Rationale:
    An attacker who has gained initial access to the network will typically
    probe adjacent systems (lateral movement). The signature is:
      - One source → many targets (fan-out)
      - At least one connection exits the trusted network perimeter
        (external_connection flag, set by Logstash/replayer when dst_ip is
        outside the RFC-1918 ranges)

Output:
    alert_type = "lateral_movement"
    severity   = "high"
================================================================================
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from detection_engine.rules.base import DetectionRule, RuleResult
from detection_engine import config

log = logging.getLogger("zenguard.detection.rules.lateral_movement")


def _is_external(value: Any) -> bool:
    """Normalize external_connection to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.lower() in ("1", "true", "yes")
    return False


class LateralMovementRule(DetectionRule):
    """
    Flags a source IP that is fanning out to multiple unique destinations
    while also making at least one external connection — a classic lateral
    movement + beaconing pattern.
    """

    NAME        = "lateral_movement"
    DESCRIPTION = (
        "Detects a source IP communicating with multiple unique destination IPs "
        "in a short time window, with at least one external/internet-facing "
        "connection, indicative of post-exploitation lateral movement."
    )
    SEVERITY    = "high"
    ALERT_TYPE  = "lateral_movement"

    def evaluate(self, events: list[dict]) -> list[RuleResult]:
        threshold_ips = config.LATERAL_MOVEMENT_UNIQUE_DST_IPS

        # Group all events by src_ip
        by_src: dict[str, list[dict]] = defaultdict(list)

        for evt in events:
            src_ip = evt.get("src_ip", "0.0.0.0")
            if src_ip == "0.0.0.0":
                continue
            by_src[src_ip].append(evt)

        results: list[RuleResult] = []

        for src_ip, src_events in by_src.items():
            # Collect unique destination IPs
            dst_ips = {
                e.get("dst_ip", "0.0.0.0")
                for e in src_events
                if e.get("dst_ip") and e.get("dst_ip") != "0.0.0.0"
            }

            # Check for external connections within this src_ip's events
            has_external = any(_is_external(e.get("external_connection")) for e in src_events)

            if len(dst_ips) >= threshold_ips and has_external:
                # Collect known user_ids associated with this src_ip
                users = {
                    e.get("user_id", "unknown")
                    for e in src_events
                    if e.get("user_id") not in (None, "unknown", "N/A")
                }

                results.append(self._match(
                    reason=[
                        f"Source IP {src_ip} communicated with {len(dst_ips)} unique "
                        f"destination IPs within the analysis window "
                        f"(threshold: {threshold_ips} unique dst_ips).",
                        f"Destination IPs contacted: {', '.join(sorted(dst_ips))}.",
                        "At least one connection from this source has "
                        "external_connection=true, suggesting data is leaving "
                        "the trusted network perimeter.",
                        (
                            f"Associated user account(s): {', '.join(sorted(users))}."
                            if users else
                            "No clear user account association — possible service account or automated tooling."
                        ),
                    ],
                    matched_events=src_events,
                    risk_score_delta=30.0,
                    meta={
                        "src_ip":       src_ip,
                        "dst_ips":      list(dst_ips),
                        "dst_count":    len(dst_ips),
                        "has_external": has_external,
                        "users":        list(users),
                    },
                ))
                log.warning(
                    "LateralMovement detected: src=%s dst_count=%d external=%s",
                    src_ip, len(dst_ips), has_external
                )

        return results if results else [self._no_match()]
