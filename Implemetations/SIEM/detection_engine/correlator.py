"""
================================================================================
File: detection_engine/correlator.py
Project: ZenGuard Detection Engine

Multi-Event Correlation Engine
================================
The correlator looks across the *full set of alerts generated in a poll cycle*
and identifies higher-order attack chains — sequences of alert types that,
taken together, indicate a more serious compound threat than any single alert.

Correlation Chains Implemented
-------------------------------
1. Account Compromise Chain:
   brute_force → (any login success) → privilege_escalation
   → Combined alert: "account_compromise" (severity: critical)

2. Insider Threat Chain:
   suspicious_login → data_exfiltration
   → Combined alert: "insider_threat" (severity: critical)

3. Advanced Persistent Threat (APT) Chain:
   brute_force → lateral_movement → data_exfiltration
   → Combined alert: "apt_campaign" (severity: critical)

4. Full Kill Chain:
   brute_force + privilege_escalation + lateral_movement + data_exfiltration
   → Combined alert: "full_kill_chain" (severity: critical)

Design
------
Correlation state is maintained in a sliding window keyed by (user_id, src_ip).
Each poll cycle feeds into this window. Events older than CORRELATION_WINDOW_MINUTES
are expired.

The correlator is intentionally stateless across process restarts
(no Redis/DB dependency) — it accumulates state in-memory within each
running instance. For a production deployment with multiple listener
instances, this state should be moved to Redis.
================================================================================
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import NamedTuple

from detection_engine.rules.base import RuleResult
from detection_engine import config

log = logging.getLogger("zenguard.detection.correlator")


# ---------------------------------------------------------------------------
# Correlation Window — in-memory sliding window
# ---------------------------------------------------------------------------

class _EntityWindow:
    """
    Tracks alert_types seen for a (user_id, src_ip) entity over time.
    Implements TTL-based expiry on each append.
    """

    def __init__(self, window_minutes: int):
        self._window_minutes = window_minutes
        # Maps alert_type → list of (timestamp, RuleResult) tuples
        self._entries: dict[str, list[tuple[datetime, RuleResult]]] = defaultdict(list)

    def add(self, alert_type: str, result: RuleResult) -> None:
        self._expire_old()
        self._entries[alert_type].append((datetime.now(timezone.utc), result))

    def active_types(self) -> set[str]:
        self._expire_old()
        return {atype for atype, entries in self._entries.items() if entries}

    def all_results(self) -> list[RuleResult]:
        self._expire_old()
        results = []
        for entries in self._entries.values():
            results.extend(r for _, r in entries)
        return results

    def _expire_old(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self._window_minutes)
        for atype in list(self._entries):
            self._entries[atype] = [
                (ts, r) for ts, r in self._entries[atype] if ts >= cutoff
            ]
            if not self._entries[atype]:
                del self._entries[atype]


# ---------------------------------------------------------------------------
# Correlated Alert output type
# ---------------------------------------------------------------------------

class CorrelatedAlert(NamedTuple):
    alert_type:       str
    severity:         str
    user_id:          str
    src_ip:           str
    contributing_alert_types: list[str]
    reason:           list[str]
    matched_results:  list[RuleResult]
    risk_score_bonus: float


# ---------------------------------------------------------------------------
# Correlation Chain Definitions
# ---------------------------------------------------------------------------

CORRELATION_CHAINS: list[dict] = [
    {
        "name":            "full_kill_chain",
        "severity":        "critical",
        "required_types":  frozenset({"brute_force", "privilege_escalation", "lateral_movement", "data_exfiltration"}),
        "risk_bonus":      20.0,
        "reason_template": (
            "Full attack kill-chain detected: brute_force → privilege_escalation "
            "→ lateral_movement → data_exfiltration. This sequence represents a "
            "complete, active compromise of the target environment. Immediate "
            "incident response required."
        ),
    },
    {
        "name":            "apt_campaign",
        "severity":        "critical",
        "required_types":  frozenset({"brute_force", "lateral_movement", "data_exfiltration"}),
        "risk_bonus":      15.0,
        "reason_template": (
            "APT-pattern detected: initial access via brute force, followed by "
            "lateral movement and data exfiltration. Consistent with a targeted, "
            "multi-stage attack campaign."
        ),
    },
    {
        "name":            "account_compromise",
        "severity":        "critical",
        "required_types":  frozenset({"brute_force", "privilege_escalation"}),
        "risk_bonus":      10.0,
        "reason_template": (
            "Account compromise sequence detected: brute_force followed by "
            "privilege_escalation for the same entity. The attacker has "
            "successfully authenticated and is now escalating access rights."
        ),
    },
    {
        "name":            "insider_threat",
        "severity":        "critical",
        "required_types":  frozenset({"suspicious_login", "data_exfiltration"}),
        "risk_bonus":      10.0,
        "reason_template": (
            "Insider threat pattern detected: off-hours suspicious login from "
            "untrusted device followed by a long-duration external session. "
            "Consistent with an insider attempting to exfiltrate data undetected."
        ),
    },
    {
        "name":            "mfa_bypass_escalation",
        "severity":        "critical",
        "required_types":  frozenset({"privilege_escalation", "lateral_movement"}),
        "risk_bonus":      8.0,
        "reason_template": (
            "MFA bypass + lateral movement: an attacker who bypassed MFA and "
            "attempted privilege escalation is now performing lateral movement. "
            "Active post-exploitation activity is underway."
        ),
    },
]


# ---------------------------------------------------------------------------
# Correlator Class
# ---------------------------------------------------------------------------

class Correlator:
    """
    Stateful correlator that tracks alert types per (user_id, src_ip) entity
    over a sliding time window and fires correlated alerts when attack chains
    are observed.
    """

    def __init__(self, window_minutes: int | None = None):
        self._window = window_minutes or config.CORRELATION_WINDOW_MINUTES
        # Keyed by (user_id, src_ip)
        self._entity_windows: dict[tuple[str, str], _EntityWindow] = {}

    def _get_window(self, user_id: str, src_ip: str) -> _EntityWindow:
        key = (user_id, src_ip)
        if key not in self._entity_windows:
            self._entity_windows[key] = _EntityWindow(self._window)
        return self._entity_windows[key]

    def ingest(self, results: list[RuleResult]) -> list[CorrelatedAlert]:
        """
        Feed triggered rule results into the correlation engine.

        For each triggered result, the entity's window is updated. Then
        we check if any correlation chain is now satisfied.

        Args:
            results: Only triggered (result.triggered=True) RuleResult items.

        Returns:
            List of CorrelatedAlert objects (may be empty).
        """
        correlated: list[CorrelatedAlert] = []
        fired_chains: set[str] = set()  # prevent duplicate chain fires per cycle

        for result in results:
            if not result.triggered:
                continue

            # Extract entity identifiers from matched events
            entities: set[tuple[str, str]] = set()
            for evt in result.matched_events:
                user_id = evt.get("user_id") or "unknown"
                src_ip  = evt.get("src_ip")  or "0.0.0.0"
                entities.add((user_id, src_ip))

            # Fallback: use meta fields if no matched events have identifiers
            if not entities:
                user_id = result.meta.get("user_id", "unknown")
                src_ip  = result.meta.get("src_ip",  "unknown")
                entities.add((user_id, src_ip))

            for user_id, src_ip in entities:
                win = self._get_window(user_id, src_ip)
                win.add(result.alert_type, result)

                active = win.active_types()
                all_res = win.all_results()

                # Check each chain
                for chain in CORRELATION_CHAINS:
                    chain_key = f"{chain['name']}|{user_id}|{src_ip}"
                    if chain_key in fired_chains:
                        continue

                    if chain["required_types"].issubset(active):
                        corr = CorrelatedAlert(
                            alert_type       = chain["name"],
                            severity         = chain["severity"],
                            user_id          = user_id,
                            src_ip           = src_ip,
                            contributing_alert_types = list(active),
                            reason           = [
                                chain["reason_template"],
                                f"Entity: user_id='{user_id}', src_ip='{src_ip}'.",
                                f"Active alerts in {self._window}-minute window: "
                                f"{', '.join(sorted(active))}.",
                            ],
                            matched_results  = all_res,
                            risk_score_bonus = chain["risk_bonus"],
                        )
                        correlated.append(corr)
                        fired_chains.add(chain_key)

                        log.warning(
                            "CORRELATED ALERT: %s | user=%s src=%s | chain=%s",
                            chain["name"], user_id, src_ip, sorted(active)
                        )

        return correlated

    def cleanup(self) -> None:
        """Remove entity windows that have no active entries (memory management)."""
        empty_keys = [
            key for key, win in self._entity_windows.items()
            if not win.active_types()
        ]
        for key in empty_keys:
            del self._entity_windows[key]
        if empty_keys:
            log.debug("Correlation: purged %d expired entity windows.", len(empty_keys))
