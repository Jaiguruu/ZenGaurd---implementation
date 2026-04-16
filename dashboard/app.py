"""
================================================================================
File: dashboard/app.py
Project: ZenGuard Zero Trust SIEM — Phase 6: Presentation Layer

Description:
    Flask application that acts as the central hub for the ZenGuard SIEM
    dashboard. It receives normalized security event payloads from
    siem_listener.py via HTTP POST, persists them in a SQLite database for
    durability across restarts, and serves them to the frontend via a REST API.

    The dashboard is a pure SIEM visualization layer — it displays ingested
    events, detection alerts, risk scores, behavioral analytics (UEBA features),
    and dataset provenance. It does NOT expose SOAR action endpoints in the
    active frontend flow.

Architecture position:
    siem_listener.py  →  POST /api/ingest  →  SQLite DB
                                                     ↓
    Browser (app.js)  ←  GET  /api/events  ←  Flask API
    Browser (app.js)  ←  GET  /api/stats   ←  Flask API

Run:
    cd dashboard/
    pip install flask flask-cors
    python app.py
================================================================================
"""

import json
import logging
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from flask import Flask, jsonify, request, render_template, abort
from flask_cors import CORS

# ==============================================================================
# APP FACTORY & CONFIGURATION
# ==============================================================================

app = Flask(__name__, template_folder="templates", static_folder="static")

# CORS: allow the frontend (potentially served from a different port during dev)
# to call our API. In production, restrict origins to your actual domain.
CORS(app, resources={r"/api/*": {"origins": "*"}})

# --- Configuration ---
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, "zenguard_events.db")
LOG_LEVEL   = os.getenv("LOG_LEVEL", "INFO")
MAX_EVENTS  = int(os.getenv("MAX_EVENTS", "500"))   # rolling window kept in DB

# Configure Flask's logger to emit structured lines
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
log = logging.getLogger("zenguard.dashboard")


# ==============================================================================
# DATABASE LAYER — SQLite
# Using SQLite instead of in-memory list so events survive Flask restarts.
# For a multi-worker production deployment, swap for PostgreSQL.
# ==============================================================================

def init_db() -> None:
    """
    Create the events and alerts tables if they don't already exist.
    Called once at startup. The schema is intentionally flat (no joins needed)
    to keep queries simple and the frontend payload small.
    """
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id           TEXT PRIMARY KEY,    -- ES document _id (dedup key)
                received_at  TEXT NOT NULL,        -- ISO8601 UTC ingest timestamp
                event_time   TEXT,                 -- original @timestamp from ES
                src_ip       TEXT,
                dst_ip       TEXT,
                user_id      TEXT,
                event_type   TEXT,
                action       TEXT,
                severity     TEXT,
                log_source   TEXT,
                endpoint_id  TEXT,
                risk_score   REAL DEFAULT 0.0,     -- computed below
                soar_action  TEXT DEFAULT NULL,    -- last SOAR action taken
                raw_json     TEXT                  -- full payload for drilldown
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_received_at ON events(received_at DESC)
        """)

        # ---------------------------------------------------------------
        # ALERTS TABLE — receives structured output from the detection engine
        # Separate from raw events so analysts can triage alerts independently.
        # ---------------------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id          TEXT PRIMARY KEY,
                received_at       TEXT NOT NULL,
                alert_type        TEXT NOT NULL,
                severity          TEXT NOT NULL,
                user_id           TEXT,
                src_ip            TEXT,
                dst_ip            TEXT,
                risk_score        REAL DEFAULT 0.0,
                is_correlated     INTEGER DEFAULT 0,   -- bool: 0/1
                correlated_chain  TEXT,
                reason_json       TEXT,               -- JSON array of reason strings
                soar_action       TEXT DEFAULT NULL,
                raw_json          TEXT                 -- full alert payload
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at DESC)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)
        """)

    log.info("Database initialized at %s", DB_PATH)


@contextmanager
def get_db():
    """
    Context manager that yields a SQLite connection with WAL mode enabled.
    WAL (Write-Ahead Logging) allows concurrent reads while a write is in
    progress — essential when the listener is ingesting while the browser
    is polling /api/events simultaneously.
    """
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row   # rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ==============================================================================
# RISK SCORING ENGINE
# A lightweight, rule-based risk scorer. Returns a float 0.0–100.0.
# In production this is replaced by the UEBA ML model output (Layer 3).
# The score is stored in the DB so the frontend can sort/filter by it.
# ==============================================================================

SEVERITY_SCORES = {"critical": 90, "high": 70, "medium": 40, "low": 10}
EVENT_TYPE_SCORES = {
    "privilege_escalation": 85,
    "failed_logins":        60,
    "snort_alerts":         55,
    "wazuh_alert":          50,
    "port_scan":            45,
    "auth_generic":         15,
}

def compute_risk_score(event: dict) -> float:
    """
    Combine severity and event_type into a deterministic risk score.
    Formula: weighted average (severity 60% + event_type 40%), capped at 100.
    """
    sev_score = SEVERITY_SCORES.get(event.get("severity", "low"), 10)
    et_score  = EVENT_TYPE_SCORES.get(event.get("event_type", "unknown"), 20)
    score = (sev_score * 0.6) + (et_score * 0.4)

    # Boost: if the event has a "possible_brute_force" tag, add 15 points
    tags = event.get("tags", [])
    if isinstance(tags, list) and "possible_brute_force" in tags:
        score = min(score + 15, 100)

    return round(score, 1)


# ==============================================================================
# API HELPERS
# ==============================================================================

def api_response(data: Any, status: int = 200):
    """Standardized JSON response envelope used by all endpoints."""
    envelope = {
        "status":    "ok" if status < 400 else "error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data":      data,
    }
    return jsonify(envelope), status


def require_json(f):
    """Decorator that returns 415 if the incoming request is not JSON."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.is_json:
            return api_response({"message": "Content-Type must be application/json"}, 415)
        return f(*args, **kwargs)
    return decorated


# ==============================================================================
# ROUTES — PAGES
# ==============================================================================

@app.route("/")
def index():
    """Serve the main dashboard HTML page."""
    return render_template("index.html")


# ==============================================================================
# ROUTES — DATA API
# ==============================================================================

@app.route("/api/ingest", methods=["POST"])
@require_json
def ingest():
    """
    Receive a UEBA payload batch from siem_listener.py.

    The listener posts the full envelope:
        {
            "schema_version": "zenguard/ueba-payload/v1",
            "batch": { "event_count": N, ... },
            "events": [ { ... }, ... ]
        }

    We iterate the `events` list, compute a risk score for each, and
    upsert into SQLite using the ES document `event_id` as the primary key.
    Using INSERT OR IGNORE (not REPLACE) preserves soar_action history if
    the same event_id is sent twice due to listener restart overlap.
    """
    payload = request.get_json(silent=True)
    if not payload:
        return api_response({"message": "Empty or invalid JSON body"}, 400)

    events = payload.get("events", [])
    if not isinstance(events, list):
        return api_response({"message": "'events' must be a list"}, 400)

    ingested = 0
    skipped  = 0

    with get_db() as conn:
        for evt in events:
            event_id = evt.get("event_id") or str(uuid.uuid4())
            risk     = compute_risk_score(evt)

            result = conn.execute("""
                INSERT OR IGNORE INTO events (
                    id, received_at, event_time, src_ip, dst_ip,
                    user_id, event_type, action, severity, log_source,
                    endpoint_id, risk_score, raw_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event_id,
                datetime.now(timezone.utc).isoformat(),
                evt.get("timestamp"),
                evt.get("src_ip"),
                evt.get("dst_ip"),
                evt.get("user_id"),
                evt.get("event_type"),
                evt.get("action"),
                evt.get("severity"),
                evt.get("log_source"),
                evt.get("endpoint_id"),
                risk,
                json.dumps(evt),
            ))

            if result.rowcount > 0:
                ingested += 1
            else:
                skipped += 1

        # Rolling window: delete events beyond the MAX_EVENTS cap to
        # prevent unbounded DB growth in long-running deployments.
        conn.execute("""
            DELETE FROM events WHERE id NOT IN (
                SELECT id FROM events ORDER BY received_at DESC LIMIT ?
            )
        """, (MAX_EVENTS,))

    log.info("Ingested %d events, skipped %d duplicates.", ingested, skipped)
    return api_response({"ingested": ingested, "skipped": skipped}, 201)


@app.route("/api/alerts/ingest", methods=["POST"])
@require_json
def ingest_alerts():
    """
    Receive structured detection alerts from the ZenGuard Detection Engine.

    The detection engine posts the standard UEBA envelope:
        {
            "schema_version": "zenguard/detection-alert/v1",
            "batch": { ... },
            "events": [ { alert_dict }, ... ]
        }

    Each alert dict contains:
        alert_id, alert_type, severity, user_id, src_ip, dst_ip,
        risk_score, is_correlated, correlated_chain, reason, ...

    Alerts are persisted to the 'alerts' table and can be queried
    via GET /api/alerts for dashboard display.
    """
    payload = request.get_json(silent=True)
    if not payload:
        return api_response({"message": "Empty or invalid JSON body"}, 400)

    # Accept both: envelope with 'events' key, or a bare single alert dict
    if "events" in payload:
        alert_list = payload.get("events", [])
    elif "alert_id" in payload:
        alert_list = [payload]   # bare single alert
    else:
        alert_list = []

    if not isinstance(alert_list, list):
        return api_response({"message": "'events' must be a list"}, 400)

    ingested = 0
    skipped  = 0

    with get_db() as conn:
        for alert in alert_list:
            alert_id = alert.get("alert_id")
            if not alert_id:
                import uuid
                alert_id = str(uuid.uuid4())

            import json as _json
            result = conn.execute("""
                INSERT OR IGNORE INTO alerts (
                    alert_id, received_at, alert_type, severity,
                    user_id, src_ip, dst_ip, risk_score,
                    is_correlated, correlated_chain, reason_json, raw_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                alert_id,
                datetime.now(timezone.utc).isoformat(),
                alert.get("alert_type", "unknown"),
                alert.get("severity",   "low"),
                alert.get("user_id"),
                alert.get("src_ip"),
                alert.get("dst_ip"),
                float(alert.get("risk_score", 0.0) or 0.0),
                1 if alert.get("is_correlated") else 0,
                alert.get("correlated_chain"),
                _json.dumps(alert.get("reason", [])),
                _json.dumps(alert),
            ))

            if result.rowcount > 0:
                ingested += 1
            else:
                skipped += 1

        # Rolling window — keep last 1000 alerts
        conn.execute("""
            DELETE FROM alerts WHERE alert_id NOT IN (
                SELECT alert_id FROM alerts ORDER BY received_at DESC LIMIT 1000
            )
        """)

    log.info("Alert ingest: %d ingested, %d skipped.", ingested, skipped)
    return api_response({"ingested": ingested, "skipped": skipped}, 201)


@app.route("/api/events", methods=["GET"])
def get_events():
    """
    Return stored events to the frontend polling loop.

    Query params:
        limit  (int, default 100) — max rows to return
        since  (ISO8601 string)   — only return events newer than this timestamp
        severity (str)            — filter by severity level

    The frontend app.js uses `since` to implement efficient incremental polling:
    it records the `received_at` of the newest event it has seen, and passes
    that as `since` on the next poll. This avoids re-rendering the entire
    table every 2 seconds.
    """
    limit    = min(int(request.args.get("limit", 100)), 500)
    since    = request.args.get("since")   # ISO8601 string or None
    severity = request.args.get("severity")

    query  = "SELECT * FROM events"
    params = []
    clauses = []

    if since:
        clauses.append("received_at > ?")
        params.append(since)
    if severity:
        clauses.append("severity = ?")
        params.append(severity.lower())

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY received_at DESC LIMIT ?"
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()

    events = [dict(row) for row in rows]

    # Compute summary stats for the KPI cards in a single pass
    total      = len(events)
    high_risk  = sum(1 for e in events if e.get("risk_score", 0) >= 70)
    by_severity = {}
    by_type     = {}
    for e in events:
        s = e.get("severity", "unknown")
        t = e.get("event_type", "unknown")
        by_severity[s] = by_severity.get(s, 0) + 1
        by_type[t]     = by_type.get(t, 0) + 1

    return api_response({
        "total":       total,
        "high_risk":   high_risk,
        "by_severity": by_severity,
        "by_type":     by_type,
        "events":      events,
    })


@app.route("/api/events/<string:event_id>", methods=["GET"])
def get_event_detail(event_id: str):
    """Return the full raw JSON payload for a single event (drilldown view)."""
    with get_db() as conn:
        row = conn.execute("SELECT raw_json FROM events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        return api_response({"message": "Event not found"}, 404)
    return api_response(json.loads(row["raw_json"]))


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Aggregate statistics endpoint — used by the Chart.js donut chart and KPI cards."""
    with get_db() as conn:
        sev_rows = conn.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM events
            GROUP BY severity
        """).fetchall()
        type_rows = conn.execute("""
            SELECT event_type, COUNT(*) as cnt
            FROM events
            GROUP BY event_type
        """).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        high_risk = conn.execute(
            "SELECT COUNT(*) FROM events WHERE risk_score >= 70"
        ).fetchone()[0]

    return api_response({
        "total":       total,
        "high_risk":   high_risk,
        "by_severity": {row["severity"]: row["cnt"] for row in sev_rows},
        "by_type":     {row["event_type"]: row["cnt"] for row in type_rows if row["event_type"]},
    })


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    Return SIEM detection alerts generated by the ZenGuard Detection Engine.

    Query params:
        limit     (int, default 50)  — max rows to return
        since     (ISO8601 string)   — only alerts newer than this timestamp
        severity  (str)              — filter by severity level
        type      (str)              — filter by alert_type
        correlated (bool str)        — '1'/'true' to return only correlated alerts
    """
    limit      = min(int(request.args.get("limit", 50)), 200)
    since      = request.args.get("since")
    severity   = request.args.get("severity")
    alert_type = request.args.get("type")
    correlated = request.args.get("correlated")

    query   = "SELECT * FROM alerts"
    params  = []
    clauses = []

    if since:
        clauses.append("received_at > ?")
        params.append(since)
    if severity:
        clauses.append("severity = ?")
        params.append(severity.lower())
    if alert_type:
        clauses.append("alert_type = ?")
        params.append(alert_type.lower())
    if correlated in ("1", "true"):
        clauses.append("is_correlated = 1")

    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY received_at DESC LIMIT ?"
    params.append(limit)

    import json as _json
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        total_alerts     = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        critical_alerts  = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='critical'"
        ).fetchone()[0]
        correlated_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE is_correlated=1"
        ).fetchone()[0]

    alerts = []
    for row in rows:
        d = dict(row)
        # Deserialize reason_json back to a list
        try:
            d["reason"] = _json.loads(d.get("reason_json") or "[]")
        except Exception:
            d["reason"] = []
        alerts.append(d)

    by_type = {}
    for a in alerts:
        t = a.get("alert_type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1

    return api_response({
        "total":           total_alerts,
        "critical":        critical_alerts,
        "correlated":      correlated_count,
        "by_type":         by_type,
        "alerts":          alerts,
    })


# ==============================================================================
# ROUTES — SOAR ACTION ENDPOINTS
# Each endpoint simulates a SOAR response action. They are stub implementations.
# In production, replace the stub bodies with:
#   - block_ip:  iptables/firewall API call or cloud security group update
#   - isolate:   EDR (Wazuh/CrowdStrike) host isolation API call
#   - mfa:       LDAP/AD attribute change or push MFA challenge via Duo/Okta
# ==============================================================================

def _log_soar_action(event_id: str, action_name: str) -> None:
    """Update the event's soar_action field so the table reflects it."""
    with get_db() as conn:
        conn.execute(
            "UPDATE events SET soar_action = ? WHERE id = ?",
            (action_name, event_id)
        )

def _soar_response(event_id: str, action: str, detail: str):
    """Standard SOAR action response builder."""
    _log_soar_action(event_id, action)
    log.warning("SOAR ACTION [%s] executed for event %s — %s", action, event_id, detail)
    return api_response({
        "action":   action,
        "event_id": event_id,
        "result":   "success",
        "detail":   detail,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/soar/block_ip", methods=["POST"])
@require_json
def soar_block_ip():
    """
    SOAR Action: Block a source IP address.
    Stub: logs the action. Production: call iptables/cloud firewall API.
    Expected body: { "event_id": "...", "src_ip": "..." }
    """
    body     = request.get_json()
    event_id = body.get("event_id", "unknown")
    src_ip   = body.get("src_ip", "unknown")

    # --- STUB: replace with real firewall API call ---
    # Example (iptables via subprocess):
    #   subprocess.run(["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"])
    # Example (AWS Security Group via boto3):
    #   ec2.revoke_security_group_ingress(...)

    detail = f"IP {src_ip} flagged for blocking. Awaiting firewall enforcement."
    return _soar_response(event_id, "block_ip", detail)


@app.route("/api/soar/isolate", methods=["POST"])
@require_json
def soar_isolate():
    """
    SOAR Action: Isolate an endpoint from the network.
    Stub: logs. Production: Wazuh active-response / EDR isolation API.
    Expected body: { "event_id": "...", "endpoint_id": "..." }
    """
    body        = request.get_json()
    event_id    = body.get("event_id", "unknown")
    endpoint_id = body.get("endpoint_id", "unknown")

    # --- STUB: replace with Wazuh active-response API call ---
    # Example:
    #   requests.put(f"{WAZUH_API}/active-response/{agent_id}",
    #                json={"command": "isolate", "alert": {...}})

    detail = f"Endpoint '{endpoint_id}' queued for network isolation. Wazuh active-response pending."
    return _soar_response(event_id, "isolate", detail)


@app.route("/api/soar/mfa", methods=["POST"])
@require_json
def soar_enforce_mfa():
    """
    SOAR Action: Force MFA re-authentication for a user.
    Stub: logs. Production: Okta/Duo/Azure AD conditional access policy update.
    Expected body: { "event_id": "...", "user_id": "..." }
    """
    body     = request.get_json()
    event_id = body.get("event_id", "unknown")
    user_id  = body.get("user_id", "unknown")

    # --- STUB: replace with identity provider API call ---
    # Example (Okta):
    #   okta_client.user_factor_enroll(user_id, factor_type="token:software:totp")

    detail = f"MFA step-up challenge issued for user '{user_id}'. Session invalidated."
    return _soar_response(event_id, "mfa_enforce", detail)


@app.route("/api/soar/whitelist", methods=["POST"])
@require_json
def soar_whitelist():
    """
    SOAR Action: Mark an event as a false positive and whitelist the source.
    Expected body: { "event_id": "...", "src_ip": "...", "reason": "..." }
    """
    body     = request.get_json()
    event_id = body.get("event_id", "unknown")
    src_ip   = body.get("src_ip", "unknown")
    reason   = body.get("reason", "Manual analyst review")

    detail = f"IP {src_ip} whitelisted. Reason: '{reason}'. Event marked as false positive."
    return _soar_response(event_id, "whitelisted", detail)


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    init_db()
    # NOTE: Port 5001 is used here because Docker maps Logstash's TCP input to
    # host port 5000, which blocks Flask from receiving connections on localhost.
    log.info("ZenGuard Dashboard starting on http://0.0.0.0:5001")
    # debug=False in production; use gunicorn instead:
    #   gunicorn -w 4 -b 0.0.0.0:5001 app:app
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=False)
