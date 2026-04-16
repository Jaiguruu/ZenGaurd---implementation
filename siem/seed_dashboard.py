#!/usr/bin/env python3
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
"""
seed_dashboard.py — ZenGuard Dashboard Direct Seeder
=====================================================
Generates realistic synthetic SIEM events and POSTs them directly to
the Flask dashboard's /api/ingest endpoint. This bypasses the
Logstash → Elasticsearch → siem_listener pipeline, letting you see
live data in the dashboard immediately without the full ELK stack
needing to have indexed anything.

Usage:
    python seed_dashboard.py              # continuous mode (Ctrl+C to stop)
    python seed_dashboard.py --once       # seed once (50 events) and exit
    python seed_dashboard.py --count 200  # seed N events and exit
"""

import argparse
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta

try:
    import requests
except ImportError:
    raise SystemExit("pip install requests")

# ─── Config ───────────────────────────────────────────────────────────────────
DASHBOARD_URL  = "http://127.0.0.1:5001/api/ingest"
BATCH_SIZE     = 10      # events per POST
INTERVAL_S     = 2.0    # seconds between batches in continuous mode

# ─── Realistic data pools ─────────────────────────────────────────────────────
USERS      = ["jsmith", "agarwal", "m.chen", "root", "svc_backup",
              "admin", "harish", "deploy_user", "intern01", "ftpuser"]
HOSTS      = ["corp-laptop-07", "ws-finance-02", "srv-db-01",
              "dev-machine-14", "jumpbox-01", "kiosk-lobby"]
INT_IPS    = ["192.168.1.{0}".format(i) for i in range(10, 60)]
EXT_IPS    = ["45.33.32.156", "104.21.14.201", "66.249.66.1",
              "198.51.100.42", "203.0.113.77", "8.8.4.4",
              "91.108.4.1", "185.220.101.5"]

EVENT_TYPES = [
    "failed_logins", "snort_alerts", "privilege_escalation",
    "wazuh_alert", "port_scan", "auth_generic",
]
SEVERITIES  = ["critical", "high", "medium", "low"]
ACTIONS     = ["ssh_login_failed", "ssh_login_success", "sudo_exec",
               "port_probe", "file_access", "service_start", "mfa_bypass"]
LOG_SOURCES = ["auth.log", "snort", "wazuh", "syslog", "filebeat"]

SEV_WEIGHTS   = [0.05, 0.15, 0.35, 0.45]   # critical, high, medium, low
ET_WEIGHTS    = [0.20, 0.20, 0.15, 0.15, 0.20, 0.10]

# ─── Event generator ──────────────────────────────────────────────────────────

def rand_ip(external: bool = False) -> str:
    pool = EXT_IPS if external else INT_IPS
    return random.choice(pool)

def make_event() -> dict:
    event_type = random.choices(EVENT_TYPES, weights=ET_WEIGHTS, k=1)[0]
    severity   = random.choices(SEVERITIES,  weights=SEV_WEIGHTS, k=1)[0]
    is_attack  = event_type != "auth_generic"

    # Time: attacks skew to off-hours, benign to business hours
    now = datetime.now(timezone.utc)
    if is_attack:
        hours = list(range(0, 6)) + list(range(22, 24))
    else:
        hours = list(range(8, 18))
    ts = now.replace(hour=random.choice(hours),
                     minute=random.randint(0, 59),
                     second=random.randint(0, 59))

    src_ip = rand_ip(external=is_attack and random.random() > 0.3)
    dst_ip = rand_ip(external=False)

    # Map event_type to attack_category for dataset_label consistency
    et_to_cat = {
        "failed_logins":       "brute_force",
        "snort_alerts":        "port_scan",
        "privilege_escalation":"infiltration",
        "wazuh_alert":         "malware",
        "port_scan":           "port_scan",
        "auth_generic":        "benign",
    }
    attack_cat = et_to_cat.get(event_type, "unknown")

    return {
        "event_id":    str(uuid.uuid4()),
        "timestamp":   ts.isoformat(),
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "user_id":     random.choice(USERS),
        "event_type":  event_type,
        "action":      random.choice(ACTIONS),
        "severity":    severity,
        "log_source":  random.choice(LOG_SOURCES),
        "endpoint_id": random.choice(HOSTS) if random.random() > 0.3 else None,
        "tags":        (["possible_brute_force"] if event_type == "failed_logins"
                        and random.random() > 0.5 else []),
        "failed_logins":              random.randint(0, 25) if is_attack else random.randint(0, 1),
        "privilege_change_attempted": int(random.random() > 0.7 and is_attack),
        "MFA_bypassed":               int(random.random() > 0.85 and is_attack),
        "device_trust_score":         round(random.uniform(0.05, 0.40) if is_attack
                                           else random.uniform(0.65, 1.0), 2),
        # Dataset provenance — required for dashboard Dataset column
        "dataset":       "synthetic",
        "dataset_label": "Synthetic",
        "attack_category": attack_cat,
        "raw_label":     attack_cat,
    }


def build_payload(n: int = BATCH_SIZE) -> dict:
    events = [make_event() for _ in range(n)]
    return {
        "schema_version": "zenguard/ueba-payload/v1",
        "batch": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "event_count":  len(events),
            "source":       "seed_dashboard.py",
        },
        "events": events,
    }


def post_batch(payload: dict, url: str = DASHBOARD_URL, verbose: bool = True) -> bool:
    try:
        r = requests.post(url, json=payload, timeout=5)
        r.raise_for_status()
        data = r.json().get("data", {})
        if verbose:
            print(f"  [OK] Ingested {data.get('ingested',0)} events "
                  f"(skipped {data.get('skipped',0)} duplicates)")
        return True
    except requests.exceptions.ConnectionError:
        print(f"  [ERR] Cannot reach {url} - is the dashboard running?")
        return False
    except requests.exceptions.HTTPError as e:
        print(f"  [ERR] HTTP error: {e}")
        return False


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Seed ZenGuard dashboard with synthetic events")
    parser.add_argument("--once",   action="store_true", help="Post one batch and exit")
    parser.add_argument("--count",  type=int, default=None, help="Total events to send then exit")
    parser.add_argument("--batch",  type=int, default=BATCH_SIZE, help="Events per batch (default 10)")
    parser.add_argument("--url",    default=DASHBOARD_URL, help="Dashboard ingest URL")
    args = parser.parse_args()

    url = args.url
    batch_size = args.batch

    print(f"\n" + "-"*60)
    print(f"  ZenGuard Dashboard Seeder")
    print(f"  Target : {url}")
    print(f"  Batch  : {batch_size} events / POST")
    print("-"*60 + "\n")

    if args.count is not None:
        # Fixed total mode
        sent = 0
        while sent < args.count:
            n = min(batch_size, args.count - sent)
            payload = build_payload(n)
            if not post_batch(payload, url=url, verbose=True):
                break
            sent += n
        print(f"\n  Done - {sent} events sent.\n")

    elif args.once:
        payload = build_payload(batch_size)
        post_batch(payload, url=url, verbose=True)
        print()

    else:
        # Continuous streaming mode
        print("  Streaming events every 2s - press Ctrl+C to stop\n")
        total = 0
        try:
            while True:
                payload = build_payload(batch_size)
                ok = post_batch(payload, url=url, verbose=True)
                if ok:
                    total += batch_size
                    print(f"  Total sent this session: {total}")
                time.sleep(INTERVAL_S)
        except KeyboardInterrupt:
            print(f"\n\n  Stopped. Total events sent: {total}\n", flush=True)


if __name__ == "__main__":
    main()
