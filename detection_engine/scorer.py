"""
================================================================================
File: detection_engine/scorer.py
Project: ZenGuard Detection Engine

Risk Scoring Engine
===================
Converts a set of triggered RuleResult objects into a single, normalized
risk score in the range [0, 100].

Scoring Model
-------------
Each rule contributes a `risk_score_delta` (0–40 points):
  - critical rules: up to 40 points
  - high rules:     up to 35 points
  - medium rules:   up to 25 points
  - low rules:      up to 10 points

The raw sum is capped at 100. Additionally, co-occurrence bonuses are applied:
  - If brute_force + privilege_escalation fire together → +10 bonus
    (indicates active account compromise in progress)
  - If lateral_movement + data_exfiltration fire together → +10 bonus
    (indicates post-exploitation exfiltration campaign)

The final score is stored in the generated alert for dashboard display,
Kibana KQL filtering, and SOAR triage prioritization.
================================================================================
"""

from __future__ import annotations

import logging
from typing import NamedTuple

from detection_engine.rules.base import RuleResult

log = logging.getLogger("zenguard.detection.scorer")

# ---------------------------------------------------------------------------
# Severity-to-max-delta mapping (sanity guard)
# ---------------------------------------------------------------------------
SEVERITY_MAX_DELTA: dict[str, float] = {
    "critical": 40.0,
    "high":     35.0,
    "medium":   25.0,
    "low":      10.0,
}

# ---------------------------------------------------------------------------
# Co-occurrence bonuses
# ---------------------------------------------------------------------------
CO_OCCURRENCE_BONUSES: list[tuple[frozenset[str], float, str]] = [
    (
        frozenset({"brute_force", "privilege_escalation"}),
        10.0,
        "brute_force + privilege_escalation co-occurrence: active account compromise in progress",
    ),
    (
        frozenset({"lateral_movement", "data_exfiltration"}),
        10.0,
        "lateral_movement + data_exfiltration co-occurrence: post-exploitation exfiltration campaign",
    ),
    (
        frozenset({"suspicious_login", "brute_force"}),
        5.0,
        "suspicious_login + brute_force co-occurrence: off-hours credential attack",
    ),
    (
        frozenset({"privilege_escalation", "lateral_movement", "data_exfiltration"}),
        15.0,
        "Full kill-chain correlation: escalation → lateral movement → exfiltration",
    ),
]


class ScoreResult(NamedTuple):
    score:          float          # Final 0–100 score
    raw_sum:        float          # Uncapped sum of deltas
    bonus_applied:  float          # Total co-occurrence bonuses
    bonus_reasons:  list[str]      # Human-readable bonus explanations
    contributing_rules: list[str]  # Alert types that contributed to score


def compute_risk_score(triggered_results: list[RuleResult]) -> ScoreResult:
    """
    Compute the composite risk score from a list of triggered RuleResult objects.

    Args:
        triggered_results: Only the RuleResults where triggered=True.

    Returns:
        ScoreResult with score, breakdown, and contributing rule names.
    """
    if not triggered_results:
        return ScoreResult(
            score=0.0, raw_sum=0.0, bonus_applied=0.0,
            bonus_reasons=[], contributing_rules=[]
        )

    # --- Base score: sum of deltas, clamped per-rule to their severity max ---
    raw_sum = 0.0
    contributing_rules: list[str] = []

    for result in triggered_results:
        max_delta = SEVERITY_MAX_DELTA.get(result.severity, 10.0)
        delta     = min(result.risk_score_delta, max_delta)
        raw_sum  += delta
        contributing_rules.append(result.alert_type)

    # --- Co-occurrence bonuses ---
    fired_types    = frozenset(contributing_rules)
    total_bonus    = 0.0
    bonus_reasons: list[str] = []

    for rule_set, bonus, reason in CO_OCCURRENCE_BONUSES:
        if rule_set.issubset(fired_types):
            total_bonus  += bonus
            bonus_reasons.append(reason)
            log.debug("Co-occurrence bonus applied: +%.1f — %s", bonus, reason)

    # --- Final capped score ---
    final_score = min(raw_sum + total_bonus, 100.0)
    final_score = round(final_score, 1)

    log.debug(
        "Risk score: raw=%.1f + bonus=%.1f = %.1f (rules: %s)",
        raw_sum, total_bonus, final_score, contributing_rules
    )

    return ScoreResult(
        score          = final_score,
        raw_sum        = raw_sum,
        bonus_applied  = total_bonus,
        bonus_reasons  = bonus_reasons,
        contributing_rules = contributing_rules,
    )
