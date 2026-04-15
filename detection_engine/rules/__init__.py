"""
================================================================================
File: detection_engine/rules/__init__.py
Project: ZenGuard Detection Engine

RULE REGISTRY
=============
This is the single place where rules are registered.
To add a new rule:
  1. Create a new file in detection_engine/rules/
  2. Implement a class that inherits from DetectionRule
  3. Import it here and add an instance to RULE_REGISTRY

The engine iterates RULE_REGISTRY in order — place higher-priority rules first.
================================================================================
"""

from detection_engine.rules.brute_force          import BruteForceRule
from detection_engine.rules.suspicious_login      import SuspiciousLoginRule
from detection_engine.rules.privilege_escalation  import PrivilegeEscalationRule
from detection_engine.rules.lateral_movement      import LateralMovementRule
from detection_engine.rules.data_exfiltration     import DataExfiltrationRule

# ---------------------------------------------------------------------------
# RULE_REGISTRY — ordered list of instantiated rule objects
# The engine calls rule.evaluate(events) for each rule in this list.
# ---------------------------------------------------------------------------
RULE_REGISTRY = [
    PrivilegeEscalationRule(),   # Critical — evaluate first for fast-path alerting
    BruteForceRule(),            # High
    LateralMovementRule(),       # High
    DataExfiltrationRule(),      # High
    SuspiciousLoginRule(),       # Medium
]

__all__ = [
    "RULE_REGISTRY",
    "BruteForceRule",
    "SuspiciousLoginRule",
    "PrivilegeEscalationRule",
    "LateralMovementRule",
    "DataExfiltrationRule",
]
