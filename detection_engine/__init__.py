"""
ZenGuard Detection Engine — Rule-Based SIEM Detection Package
=============================================================
This package implements a modular, explainable rule engine that sits on top
of the existing ZenGuard ELK pipeline.

Package layout:
    detection_engine/
    ├── __init__.py          ← this file (public API surface)
    ├── config.py            ← all tunables / environment-variable bindings
    ├── rules/
    │   ├── __init__.py      ← registers all rules into RULE_REGISTRY
    │   ├── base.py          ← DetectionRule ABC + RuleResult dataclass
    │   ├── brute_force.py   ← Rule 1: Brute Force Attack
    │   ├── suspicious_login.py ← Rule 2: Suspicious Login
    │   ├── privilege_escalation.py ← Rule 3: Privilege Escalation
    │   ├── lateral_movement.py     ← Rule 4: Lateral Movement
    │   └── data_exfiltration.py    ← Rule 5: Data Exfiltration
    ├── correlator.py        ← multi-event correlation engine
    ├── scorer.py            ← risk scoring (0-100)
    ├── alert_writer.py      ← write alerts to ES + Flask dashboard
    └── engine.py            ← main polling loop (entry point)
"""

from detection_engine.engine import DetectionEngine

__all__ = ["DetectionEngine"]
__version__ = "1.0.0"
