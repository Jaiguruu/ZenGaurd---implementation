"""
================================================================================
File: detection_engine/rules/privilege_escalation.py
Project: ZenGuard Detection Engine

Rule 3: Privilege Escalation Risk
===================================
Condition:
    privilege_change_attempted == true (or == 1)
    AND MFA_bypassed == true (or == 1)

Both conditions on the same event → immediate, critical-severity alert.

This is the most dangerous single-event condition in the rule set:
an attacker who has already bypassed MFA and is now attempting to
escalate privileges is actively compromising the system.

Output:
    alert_type = "privilege_escalation"
    severity   = "critical"
================================================================================
"""

from __future__ import annotations

import logging

from detection_engine.rules.base import DetectionRule, RuleResult
from detection_engine import config

log = logging.getLogger("zenguard.detection.rules.privilege_escalation")


def _is_truthy(value) -> bool:
    """
    Normalize various representations of 'true' that appear in ES documents:
      - Python bool True
      - integer 1
      - string "1", "true", "yes"
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.lower() in ("1", "true", "yes")
    return False


class PrivilegeEscalationRule(DetectionRule):
    """
    Fires when a single event contains BOTH:
      - privilege_change_attempted = true/1
      - MFA_bypassed = true/1

    This combination indicates an attacker has defeated the second authentication
    factor and is now attempting to gain elevated system access.
    """

    NAME        = "privilege_escalation"
    DESCRIPTION = (
        "Detects a critical-risk scenario where a privilege change is attempted "
        "on the same event where MFA was bypassed, indicating an active account "
        "takeover with escalation to higher-privilege access."
    )
    SEVERITY    = "critical"
    ALERT_TYPE  = "privilege_escalation"

    def evaluate(self, events: list[dict]) -> list[RuleResult]:
        results: list[RuleResult] = []

        for evt in events:
            priv_attempted = _is_truthy(evt.get("privilege_change_attempted", False))
            mfa_bypassed   = _is_truthy(evt.get("MFA_bypassed",               False))

            if priv_attempted and mfa_bypassed:
                user_id = evt.get("user_id", "unknown")
                src_ip  = evt.get("src_ip",  "0.0.0.0")

                results.append(self._match(
                    reason=[
                        f"Event from user '{user_id}' (src: {src_ip}) contains "
                        "privilege_change_attempted=true.",
                        "The same event also has MFA_bypassed=true, indicating "
                        "the attacker has defeated multi-factor authentication.",
                        "An attacker with bypassed MFA attempting privilege "
                        "escalation represents an active, high-confidence account "
                        "compromise. Immediate containment is required.",
                    ],
                    matched_events=[evt],
                    risk_score_delta=40.0,   # maximum delta — this is critical
                    meta={
                        "user_id":                  user_id,
                        "src_ip":                   src_ip,
                        "privilege_change_attempted": True,
                        "MFA_bypassed":              True,
                        "event_type":               evt.get("event_type"),
                    },
                ))
                log.critical(
                    "PrivilegeEscalation detected: user=%s src=%s — MFA bypassed + priv change!",
                    user_id, src_ip
                )

        return results if results else [self._no_match()]
