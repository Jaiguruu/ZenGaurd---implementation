#!/usr/bin/env python3
"""
================================================================================
File: siem_listener.py
Project: ZenGuard Zero Trust SIEM - Layer 2 (Correlation & UEBA Hand-off)

Description:
    The ZenGuard SIEM Listener is the bridge between Layer 2 (ELK) and the
    upstream UEBA/ML and SOAR layers. It runs as a persistent daemon,
    continuously polling Elasticsearch every 5 seconds for anomalous security
    events that have been normalized by the Logstash pipeline.

    When a qualifying event is detected, the listener:
      1. Extracts the canonical ZenGuard metadata fields (src_ip, dst_ip,
         user_id, event_type, timestamp, severity).
      2. Formats the extracted data into a structured JSON payload.
      3. Prints the payload to stdout — simulating the API hand-off to the
         UEBA/SOAR orchestration layer (Layer 3+).

Architectural Role:
    ┌──────────────┐   Beats/5044  ┌──────────────┐   Index    ┌────────────┐
    │ Layer 1      │──────────────▶│ Logstash     │──────────▶│ Elastic-   │
    │ Endpoints    │               │ (normalize)   │            │ search     │
    │ Filebeat     │               └──────────────┘            └─────┬──────┘
    │ Snort/Wazuh  │                                                  │ Poll
    └──────────────┘                                                  ▼
                                                             ┌────────────────┐
                                                             │ siem_listener  │ ◀ THIS SCRIPT
                                                             │ (correlation)  │
                                                             └───────┬────────┘
                                                                     │ JSON payload
                                                                     ▼
                                                             ┌────────────────┐
                                                             │ UEBA / SOAR    │
                                                             │ (Layer 3+)     │
                                                             └────────────────┘

Query Design:
    The Elasticsearch query uses a compound bool query:
      - `filter.range` : restricts results to events from the last N seconds.
        This sliding time window prevents re-processing old events without
        needing external state (like a Redis cursor). It is simpler and more
        resilient to restarts than tracking a `search_after` cursor, though
        a cursor approach is provided as a commented alternative.
      - `filter.terms` : scopes results to the specific event_type values that
        indicate anomalous behaviour and are relevant to UEBA/SOAR.
        The full list:
          • failed_logins          — brute-force credential attacks
          • snort_alerts           — network-layer IDS hits
          • privilege_escalation   — sudo/su lateral movement
          • wazuh_alert            — EDR behavioural detections
          • port_scan              — reconnaissance activity

Usage:
    # Run directly:
    python3 siem_listener.py

    # With environment overrides:
    ES_HOST=https://es.internal:9200 ES_PASSWORD=secret python3 siem_listener.py

    # As a systemd service (see siem_listener.service):
    sudo systemctl start zenguard-listener

Dependencies:
    pip install elasticsearch>=8.0.0 python-dotenv
================================================================================
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Generator

# Third-party — install via: pip install elasticsearch>=8.0.0 requests
from elasticsearch import Elasticsearch, AuthenticationException, ConnectionError as ESConnectionError
from elasticsearch.exceptions import NotFoundError, RequestError, TransportError

# CHANGE 1 OF 3 — import requests for HTTP hand-off to the Flask dashboard.
# Previously the payload was only printed to stdout. Now it is POSTed to
# the Flask /api/ingest endpoint so the dashboard can persist and display it.
import requests as http_requests


# ==============================================================================
# LOGGING CONFIGURATION
# Purpose: Structured logging to both stdout (for systemd journal capture) and
#          a rotating file (for persistent audit trail). We use a custom
#          formatter that emits JSON lines so that if the listener's own logs
#          are ever shipped to Elasticsearch, they can be parsed without grok.
# ==============================================================================

class JsonLineFormatter(logging.Formatter):
    """
    Emits each log record as a single-line JSON object. This is deliberately
    machine-parseable so the listener's own operational logs can be ingested
    into the SIEM for self-monitoring ("who watches the watchmen").
    """
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "ts":       datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level":    record.levelname,
            "logger":   record.name,
            "msg":      record.getMessage(),
            "module":   record.module,
            "line":     record.lineno,
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def setup_logging(log_level: str = "INFO", log_file: str | None = None) -> logging.Logger:
    """Configure root logger with JSON stdout handler and optional file handler."""
    logger = logging.getLogger("zenguard.listener")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # --- Stdout handler (captured by systemd journal / Docker logs) ---
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(JsonLineFormatter())
    logger.addHandler(stdout_handler)

    # --- File handler (rotating, 10 MB max, 5 backups) ---
    if log_file:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5
        )
        file_handler.setFormatter(JsonLineFormatter())
        logger.addHandler(file_handler)

    return logger


# ==============================================================================
# CONFIGURATION
# All tunables are read from environment variables with sensible defaults.
# This makes the listener 12-factor compliant and Docker/k8s friendly.
# ==============================================================================

CONFIG = {
    # --- Elasticsearch connection ---
    "ES_HOST":         os.getenv("ES_HOST",         "http://localhost:9200"),
    "ES_USER":         os.getenv("ES_USER",          "elastic"),
    "ES_PASSWORD":     os.getenv("ES_PASSWORD",      "ZenGuard@2024!"),
    "ES_INDEX":        os.getenv("ES_INDEX",          "zenguard-*"),    # wildcard covers all daily indices

    # --- Polling & window ---
    "POLL_INTERVAL_S": int(os.getenv("POLL_INTERVAL_S",  "5")),    # seconds between ES queries
    "LOOK_BACK_S":     int(os.getenv("LOOK_BACK_S",      "5")),    # sliding time window for query

    # --- Query scope: which event_type values trigger a UEBA hand-off ---
    "ALERT_EVENT_TYPES": os.getenv(
        "ALERT_EVENT_TYPES",
        "failed_logins,snort_alerts,privilege_escalation,wazuh_alert,port_scan"
    ).split(","),

    # --- Resilience ---
    "MAX_EVENTS_PER_POLL": int(os.getenv("MAX_EVENTS_PER_POLL", "200")),   # ES size limit per query
    "RETRY_MAX":           int(os.getenv("RETRY_MAX",           "10")),    # max reconnect attempts
    "RETRY_BASE_DELAY_S":  float(os.getenv("RETRY_BASE_DELAY_S", "2.0")), # exponential backoff base

    # CHANGE 2 OF 3 — Dashboard ingest URL.
    # Set DASHBOARD_URL env var to override (e.g. for staging/prod deployments).
    # The listener will POST every UEBA payload batch to this endpoint.
    # If the dashboard is unreachable, the listener logs a warning and continues
    # — the ES polling loop is NOT interrupted by a dashboard outage.
    "DASHBOARD_URL": os.getenv("DASHBOARD_URL", "http://localhost:5000/api/ingest"),

    # --- Logging ---
    "LOG_LEVEL":    os.getenv("LOG_LEVEL",    "INFO"),
    "LOG_FILE":     os.getenv("LOG_FILE",     "siem_listener.log"),
}


# ==============================================================================
# ELASTICSEARCH CLIENT FACTORY
# ==============================================================================

def build_es_client(cfg: dict, logger: logging.Logger) -> Elasticsearch:
    """
    Construct and return an authenticated Elasticsearch 8.x client.

    Design notes:
      - `retry_on_timeout=True` and `retry_on_status` instruct the client to
        automatically retry transient HTTP errors (503, 429) without the
        caller needing to handle them. This is essential for the long-running
        daemon pattern.
      - `max_retries=3` means the client-level retry (per-request) is 3 hops.
        The outer daemon-level retry (build_es_client called again) handles
        sustained outages.
      - `sniff_on_node_failure=False` is explicitly set because sniffing
        injects DNS resolution overhead on every failure, which is undesirable
        for a tight 5-second polling loop.
    """
    logger.info("Building Elasticsearch client", extra={"host": cfg["ES_HOST"]})
    return Elasticsearch(
        hosts=[cfg["ES_HOST"]],
        basic_auth=(cfg["ES_USER"], cfg["ES_PASSWORD"]),
        retry_on_timeout=True,
        max_retries=3,
        # Retry on these HTTP status codes (rate limit, service unavailable)
        retry_on_status=(429, 502, 503, 504),
        # keep_alive: reuse TCP connections across polls — avoids the 3-way
        # handshake overhead on every 5-second poll cycle.
        connections_per_node=2,
        # request_timeout: abort a query that takes longer than 30 seconds
        # rather than blocking the polling loop indefinitely.
        request_timeout=30,
    )


# ==============================================================================
# ELASTICSEARCH QUERY BUILDER
# ==============================================================================

def build_alert_query(cfg: dict, look_back_seconds: int) -> dict:
    """
    Build the Elasticsearch DSL query that fetches anomalous events from the
    last `look_back_seconds` seconds.

    Query anatomy:
      bool.filter (cached, no scoring):
        range(@timestamp)  → sliding window; only events after (now - look_back_s)
        terms(event_type)  → whitelist of event types that feed UEBA/SOAR

    Why `filter` instead of `must`?
      Filter clauses DO NOT contribute to the relevance score and ARE cached
      by Elasticsearch's query cache. For a pure boolean yes/no match like
      this (we want all matching docs, not ranked ones), filter is significantly
      faster than must, especially under high-frequency polling.

    Why `range` with `gte: now-{N}s` instead of tracking a cursor?
      The sliding-window approach is stateless — if the listener crashes and
      restarts, it picks up from `now - look_back_s` automatically. The
      trade-off is ~5 seconds of potential duplicate processing on restart,
      which the UEBA layer is expected to handle via idempotency keys
      (event _id from Elasticsearch).
    """
    return {
        # `size`: cap results per query; prevents memory spike on alert burst.
        "size": cfg["MAX_EVENTS_PER_POLL"],

        # `sort`: fetch the most recent events first so that if we hit the
        # size cap, we process the newest (highest-impact) events.
        "sort": [{"@timestamp": {"order": "desc"}}],

        # `_source`: project only the fields we need into the response.
        # This dramatically reduces network payload for high-volume SIEM indices.
        "_source": [
            "@timestamp",
            "timestamp",
            "src_ip",
            "dst_ip",
            "user_id",
            "event_type",
            "action",
            "severity",
            "log_source",
            "endpoint_id",
            "snort_msg",          # Snort-specific: alert description
            "wazuh_rule_level",   # Wazuh-specific: rule severity level
            "src_geo",            # GeoIP enrichment from Logstash
            "tags",               # e.g., possible_brute_force
        ],

        "query": {
            "bool": {
                "filter": [
                    # --- TIME WINDOW ---
                    # `now` is resolved server-side by Elasticsearch, which
                    # means clock skew between the listener host and ES nodes
                    # does not affect correctness.
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{look_back_seconds}s",
                                "lte": "now"
                            }
                        }
                    },
                    # --- EVENT TYPE WHITELIST ---
                    # Only fetch the event types we care about. This is a
                    # `terms` query (not `term`) to match any of the list.
                    {
                        "terms": {
                            "event_type": cfg["ALERT_EVENT_TYPES"]
                        }
                    }
                ]
            }
        }
    }


# ==============================================================================
# METADATA EXTRACTION
# ==============================================================================

def extract_metadata(hit: dict) -> dict[str, Any]:
    """
    Extract and normalize the canonical ZenGuard metadata from a single
    Elasticsearch hit (_source document).

    Returns a flat dict guaranteed to have all required UEBA fields.
    Missing optional fields are filled with None rather than being omitted,
    so that the downstream UEBA layer always receives a predictable schema.
    """
    src = hit.get("_source", {})

    # --- Canonical required fields ---
    src_ip      = src.get("src_ip")     or "0.0.0.0"
    dst_ip      = src.get("dst_ip")     or "0.0.0.0"
    user_id     = src.get("user_id")    or "unknown"
    event_type  = src.get("event_type") or "unknown"
    timestamp   = src.get("timestamp")  or src.get("@timestamp") or datetime.now(timezone.utc).isoformat()
    severity    = src.get("severity")   or "low"

    # --- Optional enrichment fields ---
    action        = src.get("action")
    log_source    = src.get("log_source")
    endpoint_id   = src.get("endpoint_id")
    snort_msg     = src.get("snort_msg")
    wazuh_level   = src.get("wazuh_rule_level")
    tags          = src.get("tags", [])
    src_country   = None
    src_city      = None

    # GeoIP — the src_geo nested object from Logstash geoip filter
    geo = src.get("src_geo", {})
    if isinstance(geo, dict):
        src_country = geo.get("country_name")
        src_city    = geo.get("city_name")

    # --- 7 ZenGuard ML Features (safe .get() with typed defaults) ---
    # Each feature uses a typed default so downstream UEBA/ML code never
    # receives None and never throws a TypeError during model inference.
    failed_logins             = int(src.get("failed_logins",             0)   or 0)
    privilege_change_attempted = int(src.get("privilege_change_attempted", 0)  or 0)
    external_connection       = int(src.get("external_connection",        0)   or 0)
    MFA_bypassed              = int(src.get("MFA_bypassed",               0)   or 0)
    session_duration          = float(src.get("session_duration",         0.0) or 0.0)
    access_time               = src.get("access_time") or timestamp
    device_trust_score        = float(src.get("device_trust_score",       0.5) or 0.5)

    return {
        # --- UEBA Required Fields ---
        "event_id":    hit.get("_id"),
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "user_id":     user_id,
        "event_type":  event_type,
        "timestamp":   timestamp,
        "severity":    severity,

        # --- UEBA Enrichment Fields ---
        "action":      action,
        "log_source":  log_source,
        "endpoint_id": endpoint_id,
        "snort_msg":   snort_msg,
        "wazuh_level": wazuh_level,
        "src_country": src_country,
        "src_city":    src_city,
        "tags":        tags,

        # --- 7 ZenGuard ML Features ---
        "failed_logins":              failed_logins,
        "privilege_change_attempted": privilege_change_attempted,
        "external_connection":        external_connection,
        "MFA_bypassed":               MFA_bypassed,
        "session_duration":           session_duration,
        "access_time":                access_time,
        "device_trust_score":         device_trust_score,

        # Listener metadata
        "detected_at":       datetime.now(timezone.utc).isoformat(),
        "listener_version":  "2.0.0",
        "zenguard_layer":    2,
    }


def format_ueba_payload(events: list[dict]) -> dict:
    """
    Wrap a batch of extracted event metadata into the ZenGuard UEBA hand-off
    envelope. The envelope carries batch-level statistics that allow the SOAR
    layer to triage without inspecting individual events.
    """
    # Compute batch-level severity tally for rapid SOAR triage
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    event_type_counts: dict[str, int] = {}
    unique_src_ips: set[str] = set()

    for evt in events:
        sev = evt.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        et = evt.get("event_type", "unknown")
        event_type_counts[et] = event_type_counts.get(et, 0) + 1
        if evt.get("src_ip") and evt["src_ip"] != "0.0.0.0":
            unique_src_ips.add(evt["src_ip"])

    return {
        "schema_version": "zenguard/ueba-payload/v1",
        "batch": {
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "event_count":     len(events),
            "severity_summary": severity_counts,
            "event_types":     event_type_counts,
            "unique_src_ips":  list(unique_src_ips),
        },
        "events": events,
    }


# ==============================================================================
# CORE POLLING LOOP
# ==============================================================================

def poll_once(es: Elasticsearch, cfg: dict, logger: logging.Logger) -> list[dict]:
    """
    Execute a single Elasticsearch query and return extracted event metadata.
    Raises exceptions upward to the retry loop in `run_listener`.
    """
    query = build_alert_query(cfg, cfg["LOOK_BACK_S"])

    response = es.search(
        index=cfg["ES_INDEX"],
        body=query,
        # ignore_unavailable: don't fail if a daily index doesn't exist yet
        # (e.g., at midnight when a new date-based index hasn't been created).
        ignore_unavailable=True,
        # allow_no_indices: same reasoning — wildcard `zenguard-*` might
        # match zero indices on a freshly bootstrapped system.
        allow_no_indices=True,
    )

    hits = response.get("hits", {}).get("hits", [])
    total = response.get("hits", {}).get("total", {}).get("value", 0)

    if total > cfg["MAX_EVENTS_PER_POLL"]:
        logger.warning(
            "Query result truncated: %d total hits, returning first %d",
            total, cfg["MAX_EVENTS_PER_POLL"]
        )

    extracted = [extract_metadata(hit) for hit in hits]
    logger.debug("poll_once: fetched %d of %d total qualifying events", len(extracted), total)
    return extracted


def run_listener(cfg: dict, logger: logging.Logger) -> None:
    """
    Main daemon loop. Implements:
      - Exponential backoff with jitter for Elasticsearch connection failures.
      - Graceful degradation: a single failed poll doesn't terminate the daemon.
      - Structured per-cycle console output (the UEBA hand-off simulation).
    """
    import random

    retry_count = 0
    es: Elasticsearch | None = None

    logger.info("ZenGuard SIEM Listener starting", extra={
        "config": {k: v for k, v in cfg.items() if "PASSWORD" not in k}
    })

    while True:
        # ------------------------------------------------------------------
        # CONNECTION PHASE — with exponential backoff + jitter
        # We attempt to (re)connect on the first iteration and after any
        # sustained connection failure. Jitter ±20% prevents a thundering
        # herd if multiple listener instances restart simultaneously.
        # ------------------------------------------------------------------
        if es is None:
            if retry_count >= cfg["RETRY_MAX"]:
                logger.critical(
                    "Exceeded maximum reconnection attempts (%d). Exiting.",
                    cfg["RETRY_MAX"]
                )
                sys.exit(1)

            delay = cfg["RETRY_BASE_DELAY_S"] * (2 ** retry_count)
            delay *= (1 + random.uniform(-0.2, 0.2))   # jitter
            delay = min(delay, 120)                      # cap at 2 minutes

            if retry_count > 0:
                logger.info("Retrying ES connection in %.1fs (attempt %d/%d)...",
                            delay, retry_count + 1, cfg["RETRY_MAX"])
                time.sleep(delay)

            try:
                es = build_es_client(cfg, logger)
                # Ping to verify credentials and connectivity before entering loop
                if not es.ping():
                    raise ESConnectionError("Ping returned False")
                info_resp = es.info()
                logger.info("Connected to Elasticsearch", extra={
                    "cluster_name": info_resp.get("cluster_name"),
                    "version": info_resp.get("version", {}).get("number"),
                })
                retry_count = 0  # reset on successful connection
            except AuthenticationException as exc:
                # Auth failure: wrong credentials — no point retrying forever
                logger.critical("Elasticsearch authentication failed: %s", exc)
                sys.exit(2)
            except (ESConnectionError, TransportError) as exc:
                logger.error("Cannot connect to Elasticsearch: %s", exc)
                es = None
                retry_count += 1
                continue

        # ------------------------------------------------------------------
        # POLL PHASE
        # ------------------------------------------------------------------
        cycle_start = time.monotonic()

        try:
            events = poll_once(es, cfg, logger)

            if events:
                payload = format_ueba_payload(events)

                # ---------------------------------------------------------
                # CHANGE 3 OF 3 — HTTP POST to Flask dashboard.
                #
                # Previously: print(json.dumps(payload, ...)) + sys.stdout.flush()
                # Now:        POST payload to /api/ingest on the Flask dashboard.
                #
                # Design decisions:
                #   - timeout=5: don't let a slow dashboard stall the ES poll loop.
                #   - The except block catches ALL network errors and logs a warning
                #     rather than raising, so a dashboard outage never kills the
                #     listener's ES polling — the primary data pipeline stays alive.
                #   - We still call logger.info on success so the systemd journal
                #     (and any log-shipping Filebeat) records every dispatch.
                # ---------------------------------------------------------
                try:
                    response = http_requests.post(
                        cfg["DASHBOARD_URL"],
                        json=payload,          # sets Content-Type: application/json
                        timeout=5,             # 5-second hard deadline
                    )
                    response.raise_for_status()  # surface 4xx/5xx as exceptions

                    logger.info(
                        "UEBA payload POSTed to dashboard: %d events | HTTP %s | severities: %s",
                        payload["batch"]["event_count"],
                        response.status_code,
                        payload["batch"]["severity_summary"]
                    )

                except http_requests.exceptions.RequestException as dash_err:
                    # Dashboard unreachable or returned an error — log and continue.
                    # The ES poll loop must NEVER be blocked by a dashboard outage.
                    logger.warning(
                        "Dashboard POST failed (non-fatal): %s — payload NOT delivered to GUI.",
                        dash_err
                    )
            else:
                logger.debug("No qualifying events in the last %ds window.", cfg["LOOK_BACK_S"])

        except NotFoundError as exc:
            # Index doesn't exist yet — this is expected on a freshly
            # bootstrapped system. Log at DEBUG to avoid alarm fatigue.
            logger.debug("Index not found (likely new deployment): %s", exc)

        except RequestError as exc:
            # Malformed query or mapping conflict — these are bugs in our
            # query builder and should be surfaced loudly.
            logger.error("Elasticsearch query error (check query DSL): %s", exc)

        except (ESConnectionError, TransportError) as exc:
            # Transient network failure — invalidate the client so the
            # connection phase runs again on the next iteration.
            logger.error("Elasticsearch connection lost: %s", exc)
            es = None
            retry_count += 1
            # Don't sleep here; the backoff in the connection phase handles it.
            continue

        except Exception as exc:
            # Catch-all: log the full traceback but do NOT exit.
            # A production daemon must be resilient to unexpected exceptions
            # in individual poll cycles.
            logger.exception("Unexpected error in poll cycle: %s", exc)

        # ------------------------------------------------------------------
        # SLEEP — Align to the configured poll interval.
        # Use elapsed time to account for query duration, so the effective
        # poll rate stays constant under varying ES response times.
        # ------------------------------------------------------------------
        elapsed = time.monotonic() - cycle_start
        sleep_duration = max(0.0, cfg["POLL_INTERVAL_S"] - elapsed)

        logger.debug("Cycle took %.3fs, sleeping %.3fs.", elapsed, sleep_duration)
        time.sleep(sleep_duration)


# ==============================================================================
# ENTRY POINT
# ==============================================================================

def main() -> None:
    logger = setup_logging(
        log_level=CONFIG["LOG_LEVEL"],
        log_file=CONFIG.get("LOG_FILE"),
    )

    try:
        run_listener(CONFIG, logger)
    except KeyboardInterrupt:
        logger.info("Received SIGINT — ZenGuard SIEM Listener shutting down gracefully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
