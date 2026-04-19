# ADR-0001: Bridge Layer Between UEBA and SOAR

**Status**: Accepted
**Date**: 2026-04-19

## Context

The UEBA (User Entity Behavior Analytics) relies on a purely unsupervised scikit-learn `IsolationForest`. Its resulting outputs are float-point "Isolation Constraints" ranging roughly around `-0.5` to `0.5`, where deeply negative numbers equal mathematically isolated anomalous points.
However, our SIEM Orchestration Engine (SOAR), written via Q-Learning models (`rl_agent.py`) and standard deterministic heuristics (`engine.py`), explicitly evaluates events through a strictly boxed integer parameter `risk_score` (between 0 and 100), and relies on a `feature_context` parameter (dictionary containing `MFA_bypassed`).

## Decision

Instead of making the SOAR component deserialize isolation constraints, we decided to **construct a unified REST API translation layer** directly inside the UEBA model server (`model_server.py` `POST /api/soar/evaluate`). The UEBA now translates its own metrics into the format immediately consumable by SOAR, specifically injecting integer transformations for `risk_score` and looping the `MFA_bypassed` Boolean.

## Consequences

**Good**:

- Completely decouples the mathematically rigid IsolationForest from the SOC playbook engine.
- Ensures the `engine.py` component of SOAR never needs to import data science libraries (`numpy`, `scikit-learn`).
- The explicit loopback of `MFA_bypassed` ensures the SIEM's detection vectors trigger the prioritised contextual isolation playbooks inside SOAR seamlessly.

**Bad**:

- Mathematical constraints from Isolation Forests aren't perfect `0-100` gauges, meaning high anomaly bounds artificially squash out smaller deviations via the heuristic `risk_score` formula.

**Mitigations**:
Added a deterministic floor block inside the API where strict behavioral violations (like bypassing MFA combined with brute forcing) artificially thrust the `risk_score` integer up to 100 regardless of the forest's mathematical score, enforcing security parity.
