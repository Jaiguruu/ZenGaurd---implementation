#!/usr/bin/env python3
"""
================================================================================
File: dataset_feeder.py
Project: ZenGuard Zero Trust SIEM — Direct Dataset Feeder

Description:
    Reads rows from CIC-IDS-2017 and UNSW-NB15 CSV files, maps them to the
    ZenGuard canonical event schema (with all 7 UEBA features synthesized),
    and POSTs them DIRECTLY to the Flask dashboard's /api/ingest endpoint.
    
    This bypasses Logstash / Elasticsearch entirely — the dashboard receives
    real, labelled dataset events immediately.

    The feeder alternates between CIC and UNSW rows so the dashboard shows
    both dataset sources simultaneously. It streams indefinitely, cycling
    through files, until stopped with Ctrl+C.

Usage:
    # From the siemfinal directory:
    python dataset_feeder.py

    # Custom rate (events per second):
    python dataset_feeder.py --rate 3

    # Send a fixed count then stop:
    python dataset_feeder.py --count 500

    # Use specific files:
    python dataset_feeder.py --cic "Datasets/CIC-IDS-2017/Tuesday-WorkingHours.csv"
    python dataset_feeder.py --unsw "Datasets/UNSW-NB15/UNSW-NB15_1.csv"

Prerequisites:
    pip install requests faker
================================================================================
"""

import argparse
import csv
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from itertools import cycle
from typing import Iterator

try:
    import requests
except ImportError:
    sys.exit("ERROR: pip install requests")

try:
    from faker import Faker
    _faker = Faker()
except ImportError:
    _faker = None


# =============================================================================
# CONFIGURATION
# =============================================================================

DASHBOARD_URL   = "http://127.0.0.1:5001/api/ingest"
DEFAULT_RATE    = 2       # events per second (float)
BATCH_SIZE      = 5       # events per POST request
SKIP_ROWS       = 500     # skip N rows between reads for sampling diversity

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CIC_DEFAULT_FILES = [
    os.path.join(BASE_DIR, "Datasets", "CIC-IDS-2017", "Tuesday-WorkingHours.csv"),
    os.path.join(BASE_DIR, "Datasets", "CIC-IDS-2017", "Friday-WorkingHours-Afternoon-DDos.csv"),
    os.path.join(BASE_DIR, "Datasets", "CIC-IDS-2017", "Friday-WorkingHours-Afternoon-PortScan.csv"),
    os.path.join(BASE_DIR, "Datasets", "CIC-IDS-2017", "Wednesday-workingHours.csv"),
]

UNSW_DEFAULT_FILES = [
    os.path.join(BASE_DIR, "Datasets", "UNSW-NB15", "UNSW-NB15_1.csv"),
    os.path.join(BASE_DIR, "Datasets", "UNSW-NB15", "UNSW-NB15_2.csv"),
]

SYNTHETIC_USERS = [
    "jsmith", "agarwal", "m.chen", "root", "svc_backup",
    "admin", "harish", "deploy_user", "intern01", "ftpuser",
]
SYNTHETIC_HOSTS = [
    "corp-laptop-07", "ws-finance-02", "srv-db-01",
    "dev-machine-14", "jumpbox-01", "kiosk-lobby",
]


# =============================================================================
# COLUMN MAPS (mirrors zenguard_replayer.py logic)
# =============================================================================

CIC_COLUMN_MAP = {
    "src_ip":        [" Source IP",        "Source IP",        "Src IP"],
    "dst_ip":        [" Destination IP",   "Destination IP",   "Dst IP"],
    "src_port":      [" Source Port",      "Source Port",      "Src Port"],
    "dst_port":      [" Destination Port", "Destination Port", "Dst Port"],
    "protocol":      [" Protocol",         "Protocol"],
    "flow_duration": [" Flow Duration",    "Flow Duration"],
    "timestamp":     [" Timestamp",        "Timestamp"],
    "label":         [" Label",            "Label"],
}

UNSW_COLUMN_MAP = {
    "src_ip":        ["srcip"],
    "dst_ip":        ["dstip"],
    "src_port":      ["sport"],
    "dst_port":      ["dsport"],
    "protocol":      ["proto"],
    "flow_duration": ["dur"],
    "timestamp":     ["Stime"],
    "label":         ["attack_cat", "Label"],
}

ATTACK_CATEGORY_MAP = {
    "benign":                        "benign",
    "ddos":                          "dos_ddos",
    "portscan":                      "port_scan",
    "bot":                           "malware",
    "infiltration":                  "infiltration",
    "web attack \u2013 brute force": "brute_force",
    "web attack - brute force":      "brute_force",
    "ftp-patator":                   "brute_force",
    "ssh-patator":                   "brute_force",
    "dos hulk":                      "dos_ddos",
    "dos goldeneye":                 "dos_ddos",
    "dos slowloris":                 "dos_ddos",
    "dos slowhttptest":              "dos_ddos",
    "heartbleed":                    "exploit",
    "web attack \u2013 xss":         "exploit",
    "web attack \u2013 sql injection": "exploit",
    "normal":                        "benign",
    "fuzzers":                       "exploit",
    "analysis":                      "port_scan",
    "backdoors":                     "malware",
    "dos":                           "dos_ddos",
    "exploits":                      "exploit",
    "generic":                       "exploit",
    "reconnaissance":                "port_scan",
    "shellcode":                     "malware",
    "worms":                         "malware",
    "0":                             "benign",
    "1":                             "dos_ddos",
}


def normalize_label(raw: str) -> str:
    return ATTACK_CATEGORY_MAP.get(raw.strip().lower(), "unknown")


def resolve_col(row: dict, candidates: list) -> str:
    stripped = {k.strip(): v for k, v in row.items()}
    for col in candidates:
        if col in row:
            return row[col].strip()
        if col.strip() in stripped:
            return stripped[col.strip()].strip()
    return ""


# =============================================================================
# CSV SAMPLER — yields rows skipping N at a time for diversity
# =============================================================================

def sample_csv(filepath: str, col_map: dict, dataset_key: str,
               skip: int = SKIP_ROWS) -> Iterator[dict]:
    """
    Generator that reads a CSV file, skipping `skip` rows between each yield.
    Yields normalised ZenGuard flow dicts one at a time.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            idx = 0
            for row in reader:
                idx += 1
                if idx % (skip + 1) != 0:
                    continue
                try:
                    src_ip   = resolve_col(row, col_map["src_ip"])   or "10.0.0.1"
                    dst_ip   = resolve_col(row, col_map["dst_ip"])   or "10.0.0.2"
                    src_port = resolve_col(row, col_map["src_port"]) or "0"
                    dst_port = resolve_col(row, col_map["dst_port"]) or "0"
                    protocol = resolve_col(row, col_map["protocol"]) or "TCP"
                    dur_raw  = resolve_col(row, col_map["flow_duration"]) or "0"
                    raw_label = resolve_col(row, col_map["label"])   or "unknown"

                    if src_ip in ("0.0.0.0", "") and dst_ip in ("0.0.0.0", ""):
                        continue

                    try:
                        dur_f = float(dur_raw)
                        session_duration = round(dur_f / 1_000_000 if dataset_key == "cic" else dur_f, 3)
                    except ValueError:
                        session_duration = 0.0

                    yield {
                        "src_ip":           src_ip,
                        "dst_ip":           dst_ip,
                        "src_port":         src_port,
                        "dst_port":         dst_port,
                        "protocol":         str(protocol).upper(),
                        "session_duration": session_duration,
                        "attack_category":  normalize_label(raw_label),
                        "raw_label":        raw_label,
                        "dataset":          dataset_key,
                    }
                except Exception:
                    continue
    except FileNotFoundError:
        print(f"  [WARN] File not found: {filepath}")
    except PermissionError:
        print(f"  [WARN] Permission denied: {filepath}")


# =============================================================================
# UEBA FEATURE SYNTHESIZER
# =============================================================================

def _rand_user() -> str:
    if _faker:
        return _faker.user_name().replace(" ", ".").lower()[:12]
    return random.choice(SYNTHETIC_USERS)

def _rand_host() -> str:
    if _faker:
        return f"host-{_faker.hostname().split('.')[0]}"
    return random.choice(SYNTHETIC_HOSTS)

def _rand_ext_ip() -> str:
    prefixes = ["45.33.", "104.21.", "66.249.", "198.51.", "203.0.", "8.8."]
    return random.choice(prefixes) + f"{random.randint(1,254)}.{random.randint(1,254)}"

def synthesize_features(flow: dict) -> dict:
    """Add the 7 UEBA behavioral features to a dataset flow record."""
    cat = flow.get("attack_category", "unknown")

    # Access time: off-hours for attacks, business hours for benign
    now = datetime.now(timezone.utc).replace(microsecond=0, second=random.randint(0, 59))
    if cat == "benign":
        access_hour = random.randint(8, 17)
    else:
        access_hour = random.choice(list(range(0, 6)) + list(range(22, 24)))
    access_time = now.replace(hour=access_hour, minute=random.randint(0, 59)).isoformat()

    # failed_logins
    failed_map = {
        "benign": (0, 1), "brute_force": (8, 30), "dos_ddos": (0, 2),
        "port_scan": (0, 3), "exploit": (1, 5), "malware": (2, 10),
        "infiltration": (3, 15), "unknown": (0, 5),
    }
    lo, hi = failed_map.get(cat, (0, 5))
    failed_logins = random.randint(lo, hi)

    # privilege_change_attempted
    priv_prob = {
        "benign": 0.02, "brute_force": 0.30, "dos_ddos": 0.00,
        "port_scan": 0.05, "exploit": 0.70, "malware": 0.80,
        "infiltration": 0.90, "unknown": 0.10,
    }
    priv_chg = int(random.random() < priv_prob.get(cat, 0.05))

    # MFA_bypassed
    mfa_prob = {
        "benign": 0.00, "brute_force": 0.00, "dos_ddos": 0.00,
        "port_scan": 0.00, "exploit": 0.50, "malware": 0.60,
        "infiltration": 0.80, "unknown": 0.05,
    }
    mfa_bypassed = int(random.random() < mfa_prob.get(cat, 0.00))

    # device_trust_score
    src = flow.get("src_ip", "0.0.0.0")
    is_internal = (src.startswith("10.") or src.startswith("192.168.")
                   or src.startswith("172.") or src == "127.0.0.1")
    if cat == "benign" and is_internal:
        device_trust_score = round(random.uniform(0.70, 1.00), 2)
    else:
        device_trust_score = round(random.uniform(0.05, 0.40), 2)

    # User / host
    user_id  = _rand_user() if cat != "benign" or random.random() > 0.3 else "svc_backup"
    hostname = _rand_host() if is_internal else _rand_ext_ip()

    flow.update({
        "failed_logins":              failed_logins,
        "access_time":                access_time,
        "device_trust_score":         device_trust_score,
        "privilege_change_attempted": priv_chg,
        "external_connection":        int(not is_internal),
        "MFA_bypassed":               mfa_bypassed,
        "user_id":                    user_id,
        "hostname":                   hostname,
    })
    return flow


# =============================================================================
# EVENT BUILDER — maps a synthesized flow to the ZenGuard ingest schema
# =============================================================================

ATTACK_CAT_TO_EVENT_TYPE = {
    "benign":       "auth_success",
    "brute_force":  "failed_logins",
    "dos_ddos":     "snort_alerts",
    "port_scan":    "port_scan",
    "exploit":      "snort_alerts",
    "malware":      "wazuh_alert",
    "infiltration": "privilege_escalation",
    "unknown":      "wazuh_alert",
}

ATTACK_CAT_TO_SEVERITY = {
    "benign":       "low",
    "brute_force":  "medium",
    "dos_ddos":     "high",
    "port_scan":    "medium",
    "exploit":      "high",
    "malware":      "critical",
    "infiltration": "critical",
    "unknown":      "medium",
}

ATTACK_CAT_TO_ACTION = {
    "benign":       "successful_login",
    "brute_force":  "failed_login",
    "dos_ddos":     "ids_alert",
    "port_scan":    "port_probe",
    "exploit":      "ids_alert",
    "malware":      "c2_beacon",
    "infiltration": "privilege_escalation",
    "unknown":      "suspicious_traffic",
}

LOG_SOURCE_MAP = {
    "cic":  "snort",
    "unsw": "wazuh",
}

DATASET_LABEL_MAP = {
    "cic":  "CIC-IDS-2017",
    "unsw": "UNSW-NB15",
}

def build_event(flow: dict) -> dict:
    """Convert a synthesized flow into a ZenGuard ingest-ready event."""
    cat     = flow.get("attack_category", "unknown")
    dataset = flow.get("dataset", "unknown")

    ev_type  = ATTACK_CAT_TO_EVENT_TYPE.get(cat, "wazuh_alert")
    severity = ATTACK_CAT_TO_SEVERITY.get(cat, "medium")
    action   = ATTACK_CAT_TO_ACTION.get(cat, "suspicious_traffic")

    # Boost severity if privilege escalated or MFA bypassed
    if flow.get("privilege_change_attempted") and severity == "medium":
        severity = "high"
    if flow.get("MFA_bypassed") and severity in ("low", "medium"):
        severity = "high"

    return {
        "event_id":                  str(uuid.uuid4()),
        "timestamp":                 flow.get("access_time", datetime.now(timezone.utc).isoformat()),
        "src_ip":                    flow.get("src_ip", "0.0.0.0"),
        "dst_ip":                    flow.get("dst_ip", "0.0.0.0"),
        "src_port":                  flow.get("src_port", "0"),
        "dst_port":                  flow.get("dst_port", "0"),
        "protocol":                  flow.get("protocol", "TCP"),
        "user_id":                   flow.get("user_id", "unknown"),
        "hostname":                  flow.get("hostname", "unknown"),
        "event_type":                ev_type,
        "action":                    action,
        "severity":                  severity,
        "log_source":                LOG_SOURCE_MAP.get(dataset, "syslog"),
        # UEBA features
        "failed_logins":             flow.get("failed_logins", 0),
        "access_time":               flow.get("access_time"),
        "session_duration":          flow.get("session_duration", 0.0),
        "device_trust_score":        flow.get("device_trust_score", 0.5),
        "privilege_change_attempted":flow.get("privilege_change_attempted", 0),
        "external_connection":       flow.get("external_connection", 0),
        "MFA_bypassed":              flow.get("MFA_bypassed", 0),
        # Dataset provenance — shown in dashboard Detail modal
        "dataset":                   dataset,
        "dataset_label":             DATASET_LABEL_MAP.get(dataset, dataset.upper()),
        "attack_category":           cat,
        "raw_label":                 flow.get("raw_label", "unknown"),
        # Tags for risk scoring boost
        "tags": (["possible_brute_force"]
                 if cat == "brute_force" and flow.get("failed_logins", 0) > 8
                 else []),
    }


# =============================================================================
# HTTP POSTER
# =============================================================================

_session = requests.Session()
_session.headers.update({"Content-Type": "application/json"})

def post_batch(events: list, url: str = DASHBOARD_URL) -> tuple[int, int]:
    """POST a batch of events to the dashboard. Returns (ingested, skipped)."""
    payload = {
        "schema_version": "zenguard/ueba-payload/v1",
        "batch": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "event_count":  len(events),
            "source":       "dataset_feeder.py",
        },
        "events": events,
    }
    try:
        r = _session.post(url, data=json.dumps(payload), timeout=5)
        r.raise_for_status()
        data = r.json().get("data", {})
        return data.get("ingested", 0), data.get("skipped", 0)
    except requests.exceptions.ConnectionError:
        print("  [ERR] Cannot reach dashboard — is 'python app.py' running in dashboard/?")
        return 0, 0
    except Exception as e:
        print(f"  [ERR] {e}")
        return 0, 0


# =============================================================================
# INTERLEAVED GENERATOR — alternates CIC and UNSW rows
# =============================================================================

def build_interleaved_generator(cic_files: list, unsw_files: list,
                                skip: int = SKIP_ROWS) -> Iterator[dict]:
    """
    Yields fully-synthesized, ingest-ready event dicts, alternating between
    CIC-IDS-2017 and UNSW-NB15 rows. Cycles through files indefinitely.
    """
    cic_iters  = []
    unsw_iters = []

    for path in cic_files:
        if os.path.exists(path):
            cic_iters.append(cycle(sample_csv(path, CIC_COLUMN_MAP, "cic", skip)))
        else:
            print(f"  [SKIP] CIC file not found: {path}")

    for path in unsw_files:
        if os.path.exists(path):
            unsw_iters.append(cycle(sample_csv(path, UNSW_COLUMN_MAP, "unsw", skip)))
        else:
            print(f"  [SKIP] UNSW file not found: {path}")

    if not cic_iters and not unsw_iters:
        print("\n[ERROR] No dataset files found. Check paths and try again.\n")
        return

    # Create a weighted pool: 50% CIC, 50% UNSW (or 100% whichever exists)
    sources = []
    if cic_iters:
        sources.append(("cic", cycle(cic_iters)))
    if unsw_iters:
        sources.append(("unsw", cycle(unsw_iters)))

    source_cycle = cycle(sources)

    while True:
        label, iter_cycle = next(source_cycle)
        file_iter = next(iter_cycle)
        try:
            flow = next(file_iter)
            flow = synthesize_features(flow)
            yield build_event(flow)
        except StopIteration:
            continue


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ZenGuard Dataset Feeder — streams real CSV data to the SIEM dashboard"
    )
    parser.add_argument("--rate",  type=float, default=DEFAULT_RATE,
                        help=f"Events per second (default: {DEFAULT_RATE})")
    parser.add_argument("--count", type=int,   default=None,
                        help="Stop after sending this many events")
    parser.add_argument("--cic",   type=str,   default=None,
                        help="Path to a specific CIC-IDS-2017 CSV file")
    parser.add_argument("--unsw",  type=str,   default=None,
                        help="Path to a specific UNSW-NB15 CSV file")
    parser.add_argument("--skip",  type=int,   default=SKIP_ROWS,
                        help=f"Rows to skip between samples (default: {SKIP_ROWS})")
    parser.add_argument("--url",   type=str,   default=DASHBOARD_URL,
                        help="Dashboard ingest URL")
    parser.add_argument("--batch", type=int,   default=BATCH_SIZE,
                        help=f"Events per POST batch (default: {BATCH_SIZE})")
    args = parser.parse_args()

    cic_files  = [args.cic]  if args.cic  else CIC_DEFAULT_FILES
    unsw_files = [args.unsw] if args.unsw else UNSW_DEFAULT_FILES

    # Filter to files that exist
    cic_files  = [f for f in cic_files  if os.path.exists(f)]
    unsw_files = [f for f in unsw_files if os.path.exists(f)]

    delay = 1.0 / args.rate   # seconds between events
    batch_delay = delay * args.batch  # seconds between POST batches

    print("\n" + "=" * 70)
    print("  ZenGuard Dataset Feeder")
    print("=" * 70)
    print(f"  CIC-IDS-2017 files : {len(cic_files)} file(s)")
    for f in cic_files:
        print(f"    >> {os.path.basename(f)}")
    print(f"  UNSW-NB15 files    : {len(unsw_files)} file(s)")
    for f in unsw_files:
        print(f"    >> {os.path.basename(f)}")
    print(f"  Target             : {args.url}")
    print(f"  Rate               : {args.rate} events/sec (batch of {args.batch} every {batch_delay:.1f}s)")
    print(f"  Row skip interval  : every {args.skip + 1} rows")
    if args.count:
        print(f"  Stop after        : {args.count} events")
    print("=" * 70)
    print("  Press Ctrl+C to stop\n")

    if not cic_files and not unsw_files:
        print("[ERROR] No dataset CSV files found. Check paths:")
        print(f"  CIC  : {CIC_DEFAULT_FILES[0]}")
        print(f"  UNSW : {UNSW_DEFAULT_FILES[0]}")
        sys.exit(1)

    gen     = build_interleaved_generator(cic_files, unsw_files, skip=args.skip)
    total   = 0
    batch   = []
    ingested_total = 0
    skipped_total  = 0
    start   = time.time()

    try:
        for event in gen:
            batch.append(event)
            total += 1

            if len(batch) >= args.batch:
                ing, skp = post_batch(batch, url=args.url)
                ingested_total += ing
                skipped_total  += skp
                elapsed = time.time() - start
                rate    = total / max(elapsed, 0.001)

                # Color output
                cic_count  = sum(1 for e in batch if e.get("dataset") == "cic")
                unsw_count = sum(1 for e in batch if e.get("dataset") == "unsw")

                print(
                    f"  Batch posted | "
                    f"Total: {total:>5} | "
                    f"Ingested: {ingested_total:>5} | "
                    f"Skipped: {skipped_total:>4} | "
                    f"CIC: {cic_count} UNSW: {unsw_count} | "
                    f"Rate: {rate:.1f}/s"
                )
                batch = []
                time.sleep(batch_delay)

            if args.count and total >= args.count:
                # Flush remaining
                if batch:
                    ing, skp = post_batch(batch, url=args.url)
                    ingested_total += ing
                break

    except KeyboardInterrupt:
        # Flush remaining batch
        if batch:
            post_batch(batch, url=args.url)
        elapsed = time.time() - start
        print(f"\n\n  Stopped. Sent {total} events in {elapsed:.1f}s "
              f"({total/max(elapsed,1):.1f}/s). "
              f"Ingested: {ingested_total}, Skipped: {skipped_total}\n")
        sys.exit(0)

    elapsed = time.time() - start
    print(f"\n  Done. Sent {total} events in {elapsed:.1f}s. "
          f"Ingested: {ingested_total}, Skipped: {skipped_total}\n")


if __name__ == "__main__":
    main()
