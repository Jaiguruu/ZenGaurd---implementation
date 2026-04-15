"""
================================================================================
File: detection_engine/rules/base.py
Project: ZenGuard Detection Engine

Base abstractions that every detection rule must implement.

Design Goals:
  - Each rule is a self-contained class, making unit testing trivial.
  - RuleResult carries structured evidence so alerts are **explainable**.
  - The RULE_REGISTRY list in rules/__init__.py is the single place to
    register new rules — no other file needs touching.
================================================================================
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("zenguard.detection.rules")


# ---------------------------------------------------------------------------
# RuleResult — the output contract of every rule evaluation
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    """
    Structured result produced when a detection rule fires.

    Fields:
        triggered       : True if this rule fired for the given event(s).
        alert_type      : Machine-readable alert classifier (snake_case).
        severity        : One of critical / high / medium / low.
        reason          : Human-readable list of evidence strings. Each string
                          explains **why** the rule fired — this is what makes
                          the SIEM explainable to an analyst.
        risk_score_delta: How much this rule contributes to the overall risk
                          score (0–40 per rule; scorer.py sums them up).
        matched_events  : The raw event dicts that triggered this rule.
        meta            : Arbitrary key-value bag for rule-specific extras.
    """
    triggered:        bool            = False
    alert_type:       str             = ""
    severity:         str             = "low"
    reason:           list[str]       = field(default_factory=list)
    risk_score_delta: float           = 0.0
    matched_events:   list[dict]      = field(default_factory=list)
    meta:             dict[str, Any]  = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "triggered":        self.triggered,
            "alert_type":       self.alert_type,
            "severity":         self.severity,
            "reason":           self.reason,
            "risk_score_delta": self.risk_score_delta,
            "meta":             self.meta,
        }


# ---------------------------------------------------------------------------
# DetectionRule — Abstract Base Class
# ---------------------------------------------------------------------------

class DetectionRule(ABC):
    """
    Abstract base for all ZenGuard detection rules.

    Sub-class contract:
        - Set class-level attributes: NAME, DESCRIPTION, SEVERITY, ALERT_TYPE.
        - Implement evaluate(events) → RuleResult.
        - Call self._no_match() as a convenience for the non-firing case.

    The evaluate() method receives the **full window** of events that the
    engine fetched from Elasticsearch. The rule is responsible for filtering
    by whatever fields it needs (user_id, src_ip, event_type, etc.).
    """

    NAME:        str = "unnamed_rule"
    DESCRIPTION: str = ""
    SEVERITY:    str = "low"
    ALERT_TYPE:  str = "generic_alert"

    def __init__(self):
        self.log = logging.getLogger(f"zenguard.detection.rules.{self.NAME}")

    @abstractmethod
    def evaluate(self, events: list[dict]) -> list[RuleResult]:
        """
        Evaluate the rule against the provided event window.

        Args:
            events: List of normalized event dicts (from ES + extract_metadata).

        Returns:
            List of RuleResult objects (one per distinct entity that triggered
            the rule — e.g., one per distinct attacker src_ip).
        """
        ...

    def _no_match(self) -> RuleResult:
        """Convenience factory for a non-triggered result."""
        return RuleResult(triggered=False, alert_type=self.ALERT_TYPE)

    def _match(
        self,
        reason:          list[str],
        matched_events:  list[dict],
        risk_score_delta: float = 0.0,
        meta:            dict | None = None,
    ) -> RuleResult:
        """Convenience factory for a triggered result."""
        return RuleResult(
            triggered        = True,
            alert_type       = self.ALERT_TYPE,
            severity         = self.SEVERITY,
            reason           = reason,
            risk_score_delta = risk_score_delta,
            matched_events   = matched_events,
            meta             = meta or {},
        )

    def __repr__(self) -> str:
        return f"<Rule:{self.NAME} severity={self.SEVERITY}>"
