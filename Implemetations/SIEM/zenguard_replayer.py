#!/usr/bin/env python3
"""
================================================================================
File: zenguard_replayer.py
Project: ZenGuard Zero Trust SIEM — Data Ingestion & Replay Engine

Description:
    Reads CIC-IDS-2017 and UNSW-NB15 CSV rows, maps their network-flow
    columns into the ZenGuard canonical schema, synthesizes the four missing
    identity/behavioral features that those datasets do not contain
    (failed_logins, privilege_change_attempted, MFA_bypassed,
    device_trust_score), formats the combined context into syslog-format
    strings (Snort fast-alert + auth.log), and streams them row-by-row
    to Logstash via a raw TCP socket at a configurable replay rate.

    Also exposes standalone "scenario trigger" functions that fire synthetic
    attack bursts completely independently of CSV data — useful for live
    demo and SOAR pipeline validation without needing real attack traffic.

Architecture position:
    ┌──────────────────────┐
    │ CIC-IDS-2017 CSV     │─────┐
    ├──────────────────────┤     │   ┌─────────────────────┐
    │ UNSW-NB15 CSV        │─────┼──▶│ zenguard_replayer   │
    ├──────────────────────┤     │   │  1. Column mapping  │
    │ Synthetic generator  │─────┘   │  2. Synthesis       │
    └──────────────────────┘         │  3. Syslog format   │
                                     │  4. TCP → Logstash  │
                                     └──────────┬──────────┘
                                                │ raw syslog TCP
                                                ▼
                                     ┌──────────────────────┐
                                     │ Logstash :5000       │
                                     │ (tcp input plugin)   │
                                     └──────────┬───────────┘
                                                │ normalized JSON
                                                ▼
                                     Elasticsearch → siem_listener → Dashboard

Prerequisites:
    pip install faker        (realistic synthetic user/hostname generation)

Usage:
    # Replay a specific CSV file (run from siemfinal/siem/):
    python zenguard_replayer.py --file ../Datasets/CIC-IDS-2017/Monday-WorkingHours.csv --dataset cic

    # Replay entire CIC-IDS-2017 folder (run from siemfinal/siem/):
    python zenguard_replayer.py --folder ../Datasets/CIC-IDS-2017/ --dataset cic

    # Or use absolute path (works from anywhere):
    python zenguard_replayer.py --folder "H:\Desktop\Mini Project\Code\siemfinal\Datasets\CIC-IDS-2017" --dataset cic

    # Fire privilege escalation scenario trigger only:
    python zenguard_replayer.py --scenario privilege_escalation

    # Fire all scenario triggers sequentially:
    python zenguard_replayer.py --scenario all
================================================================================
"""

import argparse
import csv
import os
import random
import socket
import sys
import time
import glob
from datetime import datetime, timezone, timedelta
from typing import Iterator, Optional

# Third-party (pip install faker)
try:
    from faker import Faker
    _faker = Faker()
except ImportError:
    _faker = None   # graceful degradation — we fall back to hardcoded names

# =============================================================================
# ANSI TERMINAL COLOURS — no external library needed
# =============================================================================
class C:
    """ANSI colour constants for beautiful terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"

    # Semantic aliases
    OK      = GREEN
    WARN    = YELLOW
    ERR     = RED
    INFO    = CYAN
    ATTACK  = RED + BOLD
    BENIGN  = GREEN
    SYNTH   = MAGENTA
    LABEL   = WHITE + BOLD
    MUTED   = DIM + WHITE

def cprint(colour: str, msg: str) -> None:
    """Print with colour, always reset at end."""
    print(f"{colour}{msg}{C.RESET}")

def banner(text: str, char: str = "─", colour: str = C.CYAN) -> None:
    width = 74
    line  = char * width
    pad   = ((width - len(text) - 2) // 2)
    print(f"\n{colour}{line}")
    print(f"{char * pad} {text} {char * (width - pad - len(text) - 2)}")
    print(f"{line}{C.RESET}")


# =============================================================================
# CONFIGURATION
# All hard-coded values that an operator would change for their deployment.
# =============================================================================

CONFIG = {
    # --- Logstash TCP Input endpoint ---
    # IMPORTANT: You must add a `tcp` input block to logstash.conf:
    #   input {
    #     tcp {
    #       port  => 5000
    #       codec => "line"
    #       tags  => ["replayer"]
    #     }
    #   }
    "LOGSTASH_HOST": os.getenv("LOGSTASH_HOST", "127.0.0.1"),
    "LOGSTASH_PORT": int(os.getenv("LOGSTASH_PORT", "5000")),

    # --- Replay speed ---
    # 0.5 = 2 events/second. Decrease for stress testing, increase for demo pacing.
    "REPLAY_DELAY_S": float(os.getenv("REPLAY_DELAY_S", "0.5")),

    # --- Scenario burst size ---
    # Number of synthetic events fired per scenario trigger call
    "SCENARIO_BURST": int(os.getenv("SCENARIO_BURST", "15")),

    # --- Socket reconnect ---
    "RECONNECT_MAX":   int(os.getenv("RECONNECT_MAX",   "10")),
    "RECONNECT_DELAY": float(os.getenv("RECONNECT_DELAY", "3.0")),

    # --- Synthetic identity pool ---
    # Realistic corporate usernames used in synthetic auth logs
    "SYNTHETIC_USERS": [
        "jsmith", "agarwal", "m.chen", "root", "svc_backup",
        "admin", "harish", "deploy_user", "intern01", "ftpuser",
    ],
    "SYNTHETIC_HOSTS": [
        "corp-laptop-07", "ws-finance-02", "srv-db-01",
        "dev-machine-14", "jumpbox-01", "kiosk-lobby",
    ],

    # --- Device trust score ranges ---
    # Known managed assets get 0.7-1.0; unknown/external get 0.0-0.4
    "TRUST_MANAGED_RANGE":  (0.70, 1.00),
    "TRUST_UNKNOWN_RANGE":  (0.05, 0.40),
}


# =============================================================================
# SECTION 1 — CSV COLUMN MAPPING
# =============================================================================

# CIC-IDS-2017 uses inconsistent column names across days (some have leading
# spaces, some use different capitalisation). We normalise to ZenGuard schema.
#
# CIC-IDS-2017 label vocabulary (relevant subset):
#   "BENIGN", "DDoS", "PortScan", "Bot", "Infiltration",
#   "Web Attack – Brute Force", "Web Attack – XSS", "Web Attack – Sql Injection",
#   "FTP-Patator", "SSH-Patator", "DoS Hulk", "DoS GoldenEye", "DoS slowloris",
#   "DoS Slowhttptest", "Heartbleed"
#
# UNSW-NB15 label vocabulary:
#   attack_cat: "Normal", "Fuzzers", "Analysis", "Backdoors", "DoS",
#               "Exploits", "Generic", "Reconnaissance", "Shellcode", "Worms"
#   Label: 0 (normal) or 1 (attack)

CIC_COLUMN_MAP = {
    # Internal ZenGuard key  →  Possible CIC-IDS-2017 column names (try in order)
    "src_ip":       [" Source IP",          "Source IP",        "Src IP"],
    "dst_ip":       [" Destination IP",     "Destination IP",   "Dst IP"],
    "src_port":     [" Source Port",        "Source Port",      "Src Port"],
    "dst_port":     [" Destination Port",   "Destination Port", "Dst Port"],
    "protocol":     [" Protocol",           "Protocol"],
    "flow_duration":[" Flow Duration",      "Flow Duration"],
    "timestamp":    [" Timestamp",          "Timestamp"],
    "label":        [" Label",              "Label"],
}

UNSW_COLUMN_MAP = {
    # Internal ZenGuard key  →  UNSW-NB15 column names
    "src_ip":        ["srcip"],
    "dst_ip":        ["dstip"],
    "src_port":      ["sport"],
    "dst_port":      ["dsport"],
    "protocol":      ["proto"],
    "flow_duration": ["dur"],
    "timestamp":     ["Stime"],
    "label":         ["attack_cat", "Label"],   # prefer attack_cat for category
}

# Unified attack category normalizer.
# Maps raw label strings from either dataset → ZenGuard internal category.
ATTACK_CATEGORY_MAP = {
    # CIC-IDS-2017 labels
    "benign":                        "benign",
    "ddos":                          "dos_ddos",
    "portscan":                      "port_scan",
    "bot":                           "malware",
    "infiltration":                  "infiltration",
    "web attack \u2013 brute force": "brute_force",
    "web attack \xe2\x80\x93 brute force": "brute_force",
    "web attack - brute force":       "brute_force",
    "ftp-patator":                   "brute_force",
    "ssh-patator":                   "brute_force",
    "dos hulk":                      "dos_ddos",
    "dos goldeneye":                 "dos_ddos",
    "dos slowloris":                 "dos_ddos",
    "dos slowhttptest":              "dos_ddos",
    "heartbleed":                    "exploit",
    "web attack \u2013 xss":         "exploit",
    "web attack \u2013 sql injection":"exploit",
    # UNSW-NB15 labels
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

def normalize_attack_category(raw_label: str) -> str:
    """Map a raw dataset label string to a ZenGuard internal category."""
    return ATTACK_CATEGORY_MAP.get(raw_label.strip().lower(), "unknown")


# =============================================================================
# SECTION 2 — CSV READER
# =============================================================================

def resolve_column(row: dict, candidates: list[str]) -> Optional[str]:
    """
    Try each candidate column name in order and return the first value found.
    Handles leading-space column names common in CIC-IDS-2017.
    """
    for col in candidates:
        # Try exact match first
        if col in row:
            return row[col].strip()
        # Try stripped version (handles ' Source IP' vs 'Source IP')
        stripped_row = {k.strip(): v for k, v in row.items()}
        if col.strip() in stripped_row:
            return stripped_row.get(col.strip(), "").strip()
    return None


def detect_dataset_format(filepath: str) -> str:
    """
    Auto-detect whether the CSV is CIC-IDS-2017 or UNSW-NB15 by inspecting
    the header row. Returns 'cic' or 'unsw'.
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        header_line = f.readline().lower()

    if "srcip" in header_line or "dstip" in header_line:
        return "unsw"
    elif "source ip" in header_line or "flow duration" in header_line:
        return "cic"
    else:
        cprint(C.WARN, f"[WARN] Cannot auto-detect dataset format for {filepath}. Defaulting to 'cic'.")
        return "cic"


def read_csv_rows(filepath: str, dataset: str = "auto") -> Iterator[dict]:
    """
    Generator that yields ZenGuard-normalised flow records from a CSV file,
    one row at a time. Handles malformed rows without crashing.

    Yields dicts with keys:
        src_ip, dst_ip, src_port, dst_port, protocol,
        flow_duration, timestamp, attack_category, raw_label
    """
    if dataset == "auto":
        dataset = detect_dataset_format(filepath)

    col_map = CIC_COLUMN_MAP if dataset == "cic" else UNSW_COLUMN_MAP

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                try:
                    # Extract fields using the column map
                    src_ip        = resolve_column(row, col_map["src_ip"])        or "0.0.0.0"
                    dst_ip        = resolve_column(row, col_map["dst_ip"])        or "0.0.0.0"
                    src_port      = resolve_column(row, col_map["src_port"])      or "0"
                    dst_port      = resolve_column(row, col_map["dst_port"])      or "0"
                    protocol      = resolve_column(row, col_map["protocol"])      or "TCP"
                    flow_duration = resolve_column(row, col_map["flow_duration"]) or "0"
                    timestamp     = resolve_column(row, col_map["timestamp"])     or ""
                    raw_label     = resolve_column(row, col_map["label"])         or "unknown"

                    # Validate essential fields — skip rows with no IP
                    if src_ip == "0.0.0.0" and dst_ip == "0.0.0.0":
                        continue

                    # Normalize attack category
                    attack_category = normalize_attack_category(raw_label)

                    # Convert flow_duration to seconds (CIC stores microseconds)
                    try:
                        dur_raw = float(flow_duration)
                        dur_s   = dur_raw / 1_000_000 if dataset == "cic" else dur_raw
                    except ValueError:
                        dur_s = 0.0

                    yield {
                        "row_index":       i,
                        "src_ip":          src_ip,
                        "dst_ip":          dst_ip,
                        "src_port":        src_port,
                        "dst_port":        dst_port,
                        "protocol":        str(protocol).upper(),
                        "session_duration": round(dur_s, 3),
                        "timestamp":       timestamp,
                        "attack_category": attack_category,
                        "raw_label":       raw_label,
                        "dataset":         dataset,
                    }

                except Exception as row_err:
                    # Bad row — log and continue; never crash the replay loop
                    cprint(C.MUTED, f"  [skip] Row {i} malformed: {row_err}")
                    continue

    except FileNotFoundError:
        cprint(C.ERR, f"[ERROR] File not found: {filepath}")
    except PermissionError:
        cprint(C.ERR, f"[ERROR] Permission denied reading: {filepath}")


# =============================================================================
# SECTION 3 — BEHAVIORAL FEATURE SYNTHESIZER
# =============================================================================

def _rand_user() -> str:
    """Return a random synthetic corporate username."""
    if _faker:
        return _faker.user_name().replace(" ", ".").lower()[:12]
    return random.choice(CONFIG["SYNTHETIC_USERS"])

def _rand_host() -> str:
    """Return a random synthetic hostname."""
    if _faker:
        return f"host-{_faker.hostname().split('.')[0]}"
    return random.choice(CONFIG["SYNTHETIC_HOSTS"])

def _rand_ip_external() -> str:
    """Generate a realistic-looking external (non-RFC1918) IP address."""
    # Avoid RFC1918 ranges (10.x, 172.16-31.x, 192.168.x)
    # Use common public ranges instead
    prefixes = ["45.33.", "104.21.", "66.249.", "198.51.", "203.0.", "8.8."]
    return random.choice(prefixes) + f"{random.randint(1,254)}.{random.randint(1,254)}"

def synthesize_identity_features(flow: dict) -> dict:
    """
    Given a normalised network flow record, synthesize the four ZenGuard
    identity/behavioral features that CIC-IDS-2017 and UNSW-NB15 lack.

    Synthesis rules based on attack_category:
    ┌─────────────────────┬──────────────┬──────────────────────┬─────────────┬──────────────────┐
    │ attack_category     │ failed_logins│ privilege_change_    │ MFA_bypassed│ device_trust_    │
    │                     │              │ attempted            │             │ score            │
    ├─────────────────────┼──────────────┼──────────────────────┼─────────────┼──────────────────┤
    │ benign              │ 0–1          │ False                │ False       │ 0.70–1.00        │
    │ brute_force         │ 8–30         │ True (30% chance)    │ False       │ 0.05–0.30        │
    │ dos_ddos            │ 0–2          │ False                │ False       │ 0.05–0.25        │
    │ port_scan           │ 0–3          │ False                │ False       │ 0.10–0.40        │
    │ exploit             │ 1–5          │ True (70% chance)    │ True (50%)  │ 0.05–0.20        │
    │ malware             │ 2–10         │ True (80% chance)    │ True (60%)  │ 0.05–0.15        │
    │ infiltration        │ 3–15         │ True (90% chance)    │ True (80%)  │ 0.05–0.10        │
    │ unknown             │ 0–5          │ False                │ False       │ 0.30–0.60        │
    └─────────────────────┴──────────────┴──────────────────────┴─────────────┴──────────────────┘

    Returns the flow dict enriched with all 7 ZenGuard features.
    """
    cat = flow.get("attack_category", "unknown")

    # --- Synthesize access_time ---
    # For benign: random business-hours timestamp (08:00–18:00)
    # For attacks: bias toward off-hours (22:00–05:00)
    base_date = datetime.now(timezone.utc).replace(
        microsecond=0, second=random.randint(0, 59)
    )
    if cat == "benign":
        access_hour = random.randint(8, 17)
    else:
        after_hours_hours = list(range(0, 6)) + list(range(22, 24))
        access_hour = random.choice(after_hours_hours)

    access_time = base_date.replace(
        hour=access_hour, minute=random.randint(0, 59)
    ).isoformat()

    # --- Synthesize failed_logins ---
    failed_map = {
        "benign":       (0, 1),
        "brute_force":  (8, 30),
        "dos_ddos":     (0, 2),
        "port_scan":    (0, 3),
        "exploit":      (1, 5),
        "malware":      (2, 10),
        "infiltration": (3, 15),
        "unknown":      (0, 5),
    }
    fl_lo, fl_hi = failed_map.get(cat, (0, 5))
    failed_logins = random.randint(fl_lo, fl_hi)

    # --- Synthesize privilege_change_attempted ---
    priv_prob = {
        "benign": 0.02, "brute_force": 0.30, "dos_ddos": 0.00,
        "port_scan": 0.05, "exploit": 0.70, "malware": 0.80,
        "infiltration": 0.90, "unknown": 0.10,
    }
    privilege_change_attempted = random.random() < priv_prob.get(cat, 0.05)

    # --- Synthesize MFA_bypassed ---
    mfa_prob = {
        "benign": 0.00, "brute_force": 0.00, "dos_ddos": 0.00,
        "port_scan": 0.00, "exploit": 0.50, "malware": 0.60,
        "infiltration": 0.80, "unknown": 0.05,
    }
    MFA_bypassed = random.random() < mfa_prob.get(cat, 0.00)

    # --- Synthesize device_trust_score ---
    # Known managed device: high trust. Unknown/external attacker: low trust.
    # We infer "managed" by checking if src_ip is in private RFC1918 space.
    src = flow.get("src_ip", "0.0.0.0")
    is_internal = (
        src.startswith("10.")
        or src.startswith("192.168.")
        or src.startswith("172.")
        or src == "127.0.0.1"
    )
    if cat == "benign" and is_internal:
        lo, hi = CONFIG["TRUST_MANAGED_RANGE"]
    else:
        lo, hi = CONFIG["TRUST_UNKNOWN_RANGE"]
    device_trust_score = round(random.uniform(lo, hi), 2)

    # --- Synthesize identity context ---
    user_id   = _rand_user() if cat != "benign" or random.random() > 0.3 else "svc_backup"
    hostname  = _rand_host() if is_internal else _rand_ip_external()  # attacker has no DNS

    # Merge all 7 features back into the flow record
    flow.update({
        # ── The 7 ZenGuard UEBA features ──
        "failed_logins":             failed_logins,
        "access_time":               access_time,
        "session_duration":          flow.get("session_duration", 0.0),  # from CSV
        "device_trust_score":        device_trust_score,
        "privilege_change_attempted": int(privilege_change_attempted),
        "external_connection":       int(not is_internal),               # from CSV src_ip
        "MFA_bypassed":              int(MFA_bypassed),
        # ── Identity context ──
        "user_id":                   user_id,
        "hostname":                  hostname,
    })
    return flow


# =============================================================================
# SECTION 4 — SYSLOG SPOOFER (Format as auth.log + Snort alert strings)
# =============================================================================

def _syslog_ts() -> str:
    """Return a syslog-format timestamp: 'Jan 15 14:23:01'"""
    return datetime.now().strftime("%b %d %H:%M:%S").replace("  ", " ")

def spoof_auth_log(flow: dict) -> str:
    """
    Generate a realistic /var/log/auth.log line from the enriched flow record.
    Format mirrors what OpenSSH actually writes — this is what Logstash's
    auth grok pattern expects.
    """
    ts       = _syslog_ts()
    host     = flow.get("hostname", "corp-laptop-01")
    user     = flow.get("user_id", "unknown")
    src_ip   = flow.get("src_ip", "0.0.0.0")
    src_port = random.randint(49152, 65535)
    cat      = flow.get("attack_category", "benign")
    failed   = flow.get("failed_logins", 0)
    priv     = flow.get("privilege_change_attempted", 0)
    mfa_byp  = flow.get("MFA_bypassed", 0)
    pid      = random.randint(1000, 65000)

    lines = []

    # --- Failed login lines (one per failed_login count, up to 5 for brevity) ---
    for _ in range(min(failed, 5)):
        lines.append(
            f"{ts} {host} sshd[{pid}]: Failed password for {'invalid user ' if cat != 'benign' else ''}"
            f"{user} from {src_ip} port {src_port} ssh2"
        )

    # --- Successful login (benign or post-brute-force success) ---
    if cat == "benign" or (cat == "brute_force" and random.random() > 0.7):
        lines.append(
            f"{ts} {host} sshd[{pid}]: Accepted {'publickey' if cat == 'benign' else 'password'} "
            f"for {user} from {src_ip} port {src_port} ssh2"
        )

    # --- Privilege escalation ---
    if priv:
        sudo_cmds = ["/bin/bash", "/usr/bin/passwd", "/bin/su", "/usr/sbin/useradd -m hacker"]
        lines.append(
            f"{ts} {host} sudo: {user} : TTY=pts/0 ; "
            f"PWD=/home/{user} ; USER=root ; COMMAND={random.choice(sudo_cmds)}"
        )

    # --- MFA bypass indicator (PAM session opened without challenge) ---
    if mfa_byp:
        lines.append(
            f"{ts} {host} sshd[{pid}]: pam_unix(sshd:session): "
            f"session opened for user {user} by (uid=0)"
            f" [ZenGuard-tag: MFA_BYPASS_DETECTED]"
        )

    # Always emit at least one line
    if not lines:
        lines.append(
            f"{ts} {host} sshd[{pid}]: Connection from {src_ip} port {src_port} on "
            f"192.168.1.1 port 22 rdomain \"\""
        )

    return "\n".join(lines)


def spoof_snort_alert(flow: dict) -> Optional[str]:
    """
    Generate a Snort fast-alert format line for non-benign network flows.
    Returns None for benign flows (no IDS alert should fire for normal traffic).

    Snort fast-alert format:
    MM/DD-HH:MM:SS.usec [**] [gid:sid:rev] Msg [**] [Classification: X] [Priority: N] {PROTO} src:port -> dst:port
    """
    cat = flow.get("attack_category", "benign")
    if cat == "benign":
        return None

    ts      = datetime.now().strftime("%m/%d-%H:%M:%S") + f".{random.randint(100000,999999)}"
    src_ip  = flow.get("src_ip", "0.0.0.0")
    dst_ip  = flow.get("dst_ip", "0.0.0.0")
    src_p   = flow.get("src_port", "0")
    dst_p   = flow.get("dst_port", "0")
    proto   = flow.get("protocol", "TCP")

    # Snort rule signature map for each attack category
    sig_map = {
        "brute_force":  (9000001, 1, "ZenGuard SSH Brute Force Attempt",       "Attempted Administrator Privilege Gain"),
        "dos_ddos":     (9000010, 1, "ZenGuard DDoS Flood Detected",           "Denial of Service"),
        "port_scan":    (9000002, 2, "ZenGuard Nmap SYN Scan Detected",        "Network Scan"),
        "exploit":      (9000020, 1, "ZenGuard Exploit Payload Detected",      "Attempted User Privilege Gain"),
        "malware":      (9000030, 1, "ZenGuard Malware C2 Beacon",             "Trojan Activity"),
        "infiltration": (9000040, 1, "ZenGuard Lateral Movement Detected",     "Potentially Bad Traffic"),
        "unknown":      (9000099, 3, "ZenGuard Unclassified Suspicious Flow",  "Suspicious Activity"),
    }

    sid, priority, msg, classtype = sig_map.get(
        cat, (9000099, 3, "ZenGuard Suspicious Traffic", "Suspicious Activity")
    )
    rev = random.randint(1, 5)

    return (
        f"{ts} [**] [1:{sid}:{rev}] {msg} [**] "
        f"[Classification: {classtype}] [Priority: {priority}] "
        f"{{{proto}}} {src_ip}:{src_p} -> {dst_ip}:{dst_p}"
    )


# =============================================================================
# SECTION 4B — JSON PAYLOAD BUILDER
# Constructs the structured JSON object that zenguard_replayer sends over
# TCP to Logstash. Sending JSON instead of raw syslog strings:
#   - Guarantees the 7 ML features are always present in Elasticsearch.
#   - Eliminates dependency on grok parsing for feature extraction.
#   - Makes the replayer codec-agnostic (Logstash uses codec => "json").
# =============================================================================

def _build_json_payload(flow: dict, log_line: str, evt_type: str, action: str, severity: str) -> dict:
    """
    Build the canonical ZenGuard JSON payload to transmit over TCP to Logstash.

    Args:
        flow:      The fully-synthesized flow dict (post synthesize_identity_features).
        log_line:  The human-readable syslog/snort string (stored as "message" field).
        evt_type:  ZenGuard event_type string (e.g. "failed_logins", "snort_alerts").
        action:    ZenGuard action string (e.g. "failed_login", "ids_alert").
        severity:  one of "low", "medium", "high", "critical".

    Returns:
        A dict ready for json.dumps() that Logstash will parse with codec => "json".
    """
    import json as _json
    return {
        "message":    log_line,
        "event_type": evt_type,
        "action":     action,
        "severity":   severity,
        "src_ip":     flow.get("src_ip", "0.0.0.0"),
        "dst_ip":     flow.get("dst_ip", "0.0.0.0"),
        "user_id":    flow.get("user_id", "unknown"),
        "attack_category": flow.get("attack_category", "unknown"),
        "dataset":    flow.get("dataset", "synthetic"),
        "failed_logins":             flow.get("failed_logins", 0),
        "privilege_change_attempted": flow.get("privilege_change_attempted", 0),
        "external_connection":        flow.get("external_connection", 0),
        "MFA_bypassed":               flow.get("MFA_bypassed", 0),
        "session_duration":           flow.get("session_duration", 0.0),
        "access_time":                flow.get("access_time", datetime.now(timezone.utc).isoformat()),
        "device_trust_score":         flow.get("device_trust_score", 0.5),
        "hostname":   flow.get("hostname", "unknown"),
        "src_port":   flow.get("src_port", "0"),
        "dst_port":   flow.get("dst_port", "0"),
        "protocol":   flow.get("protocol", "TCP"),
    }


def _derive_auth_meta(flow: dict) -> tuple[str, str, str]:
    """
    Derive (event_type, action, severity) from a synthesized auth flow.
    Returns a 3-tuple consistent with the ZenGuard canonical schema.
    """
    cat    = flow.get("attack_category", "unknown")
    failed = flow.get("failed_logins", 0)
    priv   = flow.get("privilege_change_attempted", 0)

    if failed > 0 and cat in ("brute_force", "infiltration"):
        return ("failed_logins", "failed_login", "medium")
    elif priv:
        return ("privilege_escalation", "privilege_escalation", "high")
    elif cat == "benign":
        return ("auth_success", "successful_login", "low")
    else:
        return ("failed_logins", "failed_login", "medium")



def build_scenario_flow(
    attack_category: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    user_id: Optional[str] = None,
    forced_features: Optional[dict] = None,
) -> dict:
    """Helper that constructs a fully-synthesized flow for scenario injection."""
    src = src_ip or _rand_ip_external()
    dst = dst_ip or f"192.168.1.{random.randint(10, 50)}"

    flow = {
        "row_index":        -1,
        "src_ip":           src,
        "dst_ip":           dst,
        "src_port":         str(random.randint(49152, 65535)),
        "dst_port":         "22",
        "protocol":         "TCP",
        "session_duration": round(random.uniform(0.1, 300.0), 2),
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "attack_category":  attack_category,
        "raw_label":        attack_category,
        "dataset":          "synthetic",
    }
    flow = synthesize_identity_features(flow)

    if user_id:
        flow["user_id"] = user_id

    # forced_features override synthesized values — used by specific scenarios
    if forced_features:
        flow.update(forced_features)

    return flow


def trigger_privilege_escalation_scenario(
    send_fn,
    burst: int = None,
    target_user: str = "jsmith",
    src_ip: str = None,
) -> None:
    """
    Scenario Trigger: Privilege Escalation (ZenGuard Paper — Table 3, Row 1)

    Sends a burst of synthetic logs where:
      - privilege_change_attempted = 1
      - MFA_bypassed               = 1
      - failed_logins              = 0  (attacker got in on first try — credential theft)
      - device_trust_score         = 0.05 (unknown device)

    This scenario simulates a compromised credential being used to escalate
    to root — the most dangerous insider/APT pattern ZenGuard is designed to
    catch.
    """
    count = burst or CONFIG["SCENARIO_BURST"]
    banner("SCENARIO: Privilege Escalation — Table 3 Row 1", "═", C.ATTACK)
    cprint(C.ATTACK, f"  Firing {count} synthetic privilege escalation events…")
    cprint(C.MUTED,  f"  User: {target_user} | Forced MFA_bypass=1 | priv_change=1")

    attacker_ip = src_ip or _rand_ip_external()

    for i in range(count):
        flow = build_scenario_flow(
            attack_category  = "infiltration",
            src_ip           = attacker_ip,
            user_id          = target_user,
            forced_features  = {
                "privilege_change_attempted": 1,
                "MFA_bypassed":              1,
                "failed_logins":             0,
                "device_trust_score":        0.05,
                "external_connection":       1,
            }
        )
        auth_line  = spoof_auth_log(flow)
        snort_line = spoof_snort_alert(flow)

        _print_event_summary(flow, auth_line, snort_line, scenario=True)

        evt_type, action, severity = ("privilege_escalation", "privilege_escalation", "high")
        auth_payload  = _build_json_payload(flow, auth_line, evt_type, action, severity)
        send_fn(auth_payload)
        if snort_line:
            snort_payload = _build_json_payload(flow, snort_line, "snort_alerts", "ids_alert", "critical")
            send_fn(snort_payload)

        time.sleep(0.2)   # fast burst during scenario

    cprint(C.OK, f"  ✓ Privilege escalation scenario complete ({count} events fired)")


def trigger_brute_force_scenario(
    send_fn,
    burst: int = None,
    target_user: str = "root",
    src_ip: str = None,
) -> None:
    """
    Scenario Trigger: SSH Brute Force (ZenGuard Paper — Table 3, Row 2)

    Simulates a sustained brute-force attack:
      - failed_logins escalates from 3 → 30 across the burst
      - MFA_bypassed = False (attacker never gets in)
      - device_trust_score = 0.03 (completely unknown device)
    """
    count   = burst or CONFIG["SCENARIO_BURST"]
    src     = src_ip or _rand_ip_external()
    banner("SCENARIO: SSH Brute Force — Table 3 Row 2", "═", C.ATTACK)
    cprint(C.ATTACK, f"  Firing {count} escalating brute-force events…")
    cprint(C.MUTED,  f"  Target user: {target_user} | Attacker IP: {src}")

    for i in range(count):
        # Escalate failed_logins as the burst progresses
        escalated_fails = min(3 + (i * 2), 30)
        flow = build_scenario_flow(
            attack_category = "brute_force",
            src_ip          = src,
            user_id         = target_user,
            forced_features = {
                "failed_logins":             escalated_fails,
                "privilege_change_attempted": 0,
                "MFA_bypassed":              0,
                "device_trust_score":        0.03,
                "external_connection":       1,
            }
        )
        auth_line  = spoof_auth_log(flow)
        snort_line = spoof_snort_alert(flow)

        _print_event_summary(flow, auth_line, snort_line, scenario=True)

        auth_payload = _build_json_payload(flow, auth_line, "failed_logins", "failed_login", "medium")
        send_fn(auth_payload)
        if snort_line:
            snort_payload = _build_json_payload(flow, snort_line, "snort_alerts", "ids_alert", "high")
            send_fn(snort_payload)

        time.sleep(0.25)

    cprint(C.OK, f"  ✓ Brute force scenario complete ({count} events fired)")


def trigger_mfa_bypass_scenario(
    send_fn,
    burst: int = None,
    target_user: str = "m.chen",
) -> None:
    """
    Scenario Trigger: MFA Bypass / Credential Theft (Table 3, Row 3)

    Simulates session hijacking — attacker uses stolen session token:
      - failed_logins  = 0  (no failed attempts — stolen token)
      - MFA_bypassed   = 1  (session cookie reuse, no challenge)
      - external_connection = 1 (from VPN exit node or cloud proxy)
    """
    count = burst or CONFIG["SCENARIO_BURST"]
    banner("SCENARIO: MFA Bypass / Session Hijack — Table 3 Row 3", "═", C.ATTACK)
    cprint(C.ATTACK, f"  Firing {count} MFA bypass events for user '{target_user}'…")

    attacker_ip = _rand_ip_external()

    for i in range(count):
        flow = build_scenario_flow(
            attack_category = "exploit",
            src_ip          = attacker_ip,
            user_id         = target_user,
            forced_features = {
                "failed_logins":             0,
                "privilege_change_attempted": int(i >= count // 2),  # escalates halfway through
                "MFA_bypassed":              1,
                "device_trust_score":        0.08,
                "external_connection":       1,
            }
        )
        auth_line  = spoof_auth_log(flow)
        snort_line = spoof_snort_alert(flow)

        _print_event_summary(flow, auth_line, snort_line, scenario=True)

        for line in filter(None, [auth_line, snort_line]):
            send_fn(line)

        time.sleep(0.3)

    cprint(C.OK, f"  ✓ MFA bypass scenario complete ({count} events fired)")


def trigger_all_scenarios(send_fn) -> None:
    """Fire all three scenario triggers sequentially with a pause between each."""
    trigger_privilege_escalation_scenario(send_fn)
    time.sleep(2)
    trigger_brute_force_scenario(send_fn)
    time.sleep(2)
    trigger_mfa_bypass_scenario(send_fn)


# =============================================================================
# SECTION 6 — TERMINAL DISPLAY
# =============================================================================

# Running counters for the live stats bar
_stats = {
    "sent": 0, "benign": 0, "attack": 0, "errors": 0, "start_time": time.time()
}

def _severity_colour(attack_cat: str) -> str:
    colours = {
        "benign":       C.BENIGN,
        "brute_force":  C.RED + C.BOLD,
        "dos_ddos":     C.RED,
        "port_scan":    C.YELLOW,
        "exploit":      C.RED + C.BOLD,
        "malware":      C.MAGENTA + C.BOLD,
        "infiltration": C.RED + C.BOLD,
        "unknown":      C.YELLOW,
    }
    return colours.get(attack_cat, C.WHITE)


def _print_event_summary(flow: dict, auth_log: str, snort_alert: Optional[str],
                          scenario: bool = False) -> None:
    """Print a concise, colour-coded summary of one replayed event."""
    cat     = flow.get("attack_category", "unknown")
    col     = _severity_colour(cat)
    tag     = f"{C.BOLD}{C.BG_RED} SCENARIO {C.RESET}" if scenario else ""
    ds      = flow.get("dataset", "csv").upper()

    # Header line
    print(f"\n  {col}{'─' * 70}{C.RESET}")
    print(
        f"  {col}[{ds}]{C.RESET} {tag} "
        f"{C.LABEL}Event #{_stats['sent'] + 1}{C.RESET}  "
        f"Category: {col}{cat.upper()}{C.RESET}"
    )

    # 7-feature summary (compact grid)
    f = flow
    print(
        f"  {C.INFO}src_ip{C.RESET}={f.get('src_ip','?'):<18}"
        f"  {C.INFO}dst_ip{C.RESET}={f.get('dst_ip','?'):<18}"
        f"  {C.INFO}user{C.RESET}={f.get('user_id','?')}"
    )
    print(
        f"  {C.INFO}failed_logins{C.RESET}={str(f.get('failed_logins',0)):<6}"
        f"  {C.INFO}priv_chg{C.RESET}={str(bool(f.get('privilege_change_attempted',0))):<8}"
        f"  {C.INFO}MFA_bypass{C.RESET}={str(bool(f.get('MFA_bypassed',0))):<8}"
        f"  {C.INFO}trust{C.RESET}={f.get('device_trust_score',0.0)}"
    )
    print(
        f"  {C.INFO}ext_conn{C.RESET}={str(bool(f.get('external_connection',0))):<8}"
        f"  {C.INFO}session_dur{C.RESET}={str(f.get('session_duration',0))+'s':<10}"
        f"  {C.INFO}access_time{C.RESET}={str(f.get('access_time',''))[:19]}"
    )

    # Auth log preview (first line only for brevity)
    first_auth_line = auth_log.split("\n")[0]
    print(f"  {C.SYNTH}[auth.log]{C.RESET} {C.MUTED}{first_auth_line[:72]}{C.RESET}")

    # Snort alert preview
    if snort_alert:
        print(f"  {C.ATTACK}[snort]  {C.RESET} {C.MUTED}{snort_alert[:72]}{C.RESET}")

    # Live stats bar
    elapsed = int(time.time() - _stats["start_time"])
    rate    = _stats["sent"] / max(elapsed, 1)
    print(
        f"  {C.MUTED}── Sent: {_stats['sent']} │ "
        f"Benign: {_stats['benign']} │ "
        f"Attack: {_stats['attack']} │ "
        f"Errors: {_stats['errors']} │ "
        f"Rate: {rate:.1f}/s │ "
        f"Uptime: {elapsed}s{C.RESET}"
    )


# =============================================================================
# SECTION 7 — TCP SOCKET TRANSPORT
# =============================================================================

class LogstashTCPSender:
    """
    Manages a persistent TCP connection to Logstash.
    Implements reconnect with exponential backoff so the replayer survives
    transient network interruptions or Logstash restarts during a demo.
    """

    def __init__(self, host: str, port: int):
        self.host     = host
        self.port     = port
        self._sock    = None
        self._retries = 0

    def _connect(self) -> bool:
        """Attempt to open a TCP connection. Returns True on success."""
        try:
            self._sock = socket.create_connection(
                (self.host, self.port), timeout=10
            )
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._retries = 0
            cprint(C.OK, f"  [TCP] Connected to Logstash at {self.host}:{self.port}")
            return True
        except (ConnectionRefusedError, OSError) as e:
            cprint(C.ERR, f"  [TCP] Connection failed: {e} (retry {self._retries + 1}/{CONFIG['RECONNECT_MAX']})")
            self._sock    = None
            self._retries += 1
            return False

    def _ensure_connected(self) -> bool:
        """Ensure the socket is open, reconnecting with backoff if needed."""
        if self._sock:
            return True

        if self._retries >= CONFIG["RECONNECT_MAX"]:
            cprint(C.ERR, "[TCP] Maximum reconnect attempts exceeded. Aborting.")
            return False

        delay = CONFIG["RECONNECT_DELAY"] * (2 ** min(self._retries, 5))
        time.sleep(delay)
        return self._connect()

    def send(self, payload) -> bool:
        """
        Send a single event to Dashboard over HTTP directly (Bypassing ES/Logstash).
        """
        import requests
        try:
            if isinstance(payload, dict):
                # Ensure each event has a generated event_id before sending to Dashboard
                if "event_id" not in payload:
                    import uuid
                    payload["event_id"] = str(uuid.uuid4())
                
                # Wrap it in the batch format expected by Dashboard
                batch_payload = {
                    "schema_version": "zenguard/ueba-payload/v1",
                    "events": [payload]
                }
                requests.post("http://127.0.0.1:5001/api/ingest", json=batch_payload, timeout=2)
            return True
        except Exception as e:
            cprint(C.WARN, f"  [HTTP] Send failed ({e})")
            _stats["errors"] += 1
            return False

    def close(self) -> None:
        pass


# =============================================================================
# SECTION 8 — MAIN REPLAY LOOP
# =============================================================================

def replay_file(filepath: str, sender: LogstashTCPSender, dataset: str = "auto") -> None:
    """
    Replay a single CSV file: read → synthesize → spoof → send, row by row.
    """
    banner(f"Replaying: {os.path.basename(filepath)}", "─", C.INFO)
    rows_processed = 0

    for flow in read_csv_rows(filepath, dataset):
        flow = synthesize_identity_features(flow)

        auth_log    = spoof_auth_log(flow)
        snort_alert = spoof_snort_alert(flow)

        _print_event_summary(flow, auth_log, snort_alert)

        evt_type, action, severity = _derive_auth_meta(flow)
        auth_payload  = _build_json_payload(flow, auth_log, evt_type, action, severity)
        success_auth  = sender.send(auth_payload)

        success_snort = True
        if snort_alert:
            snort_payload = _build_json_payload(flow, snort_alert, "snort_alerts", "ids_alert",
                                                "critical" if flow.get("attack_category") in ("infiltration", "exploit", "brute_force") else "high")
            success_snort = sender.send(snort_payload)

        if success_auth or success_snort:
            _stats["sent"] += 1
            if flow["attack_category"] == "benign":
                _stats["benign"] += 1
            else:
                _stats["attack"] += 1

        rows_processed += 1
        time.sleep(CONFIG["REPLAY_DELAY_S"])

    cprint(C.OK, f"\n  ✓ File complete. {rows_processed} rows processed.")


def replay_folder(folder: str, sender: LogstashTCPSender, dataset: str = "auto") -> None:
    """Replay all *.csv files found in a folder, sorted alphabetically (by day)."""
    pattern = os.path.join(folder, "**", "*.csv")
    files   = sorted(glob.glob(pattern, recursive=True))

    if not files:
        cprint(C.WARN, f"  [WARN] No CSV files found in {folder}")
        return

    banner(f"Folder Replay: {len(files)} file(s) found", "─", C.INFO)
    for f in files:
        cprint(C.MUTED, f"  → {f}")
    print()

    for filepath in files:
        replay_file(filepath, sender, dataset)


# =============================================================================
# SECTION 9 — CLI ENTRY POINT
# =============================================================================

def print_startup_banner() -> None:
    print(f"\n{C.CYAN}{'═' * 74}")
    print(f"  {'ZenGuard Replay Engine':^70}")
    print(f"  {'CIC-IDS-2017 / UNSW-NB15 → Synthetic Augmentation → Logstash TCP':^70}")
    print(f"{'═' * 74}{C.RESET}")
    print(f"  {C.INFO}Logstash target : {C.RESET}{CONFIG['LOGSTASH_HOST']}:{CONFIG['LOGSTASH_PORT']}")
    print(f"  {C.INFO}Replay delay    : {C.RESET}{CONFIG['REPLAY_DELAY_S']}s/event")
    print(f"  {C.INFO}Scenario burst  : {C.RESET}{CONFIG['SCENARIO_BURST']} events")
    print(f"  {C.MUTED}Press Ctrl+C to stop gracefully{C.RESET}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ZenGuard Replay Engine — CIC-IDS-2017 / UNSW-NB15 → Logstash"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file",     metavar="PATH",    help="Path to a single CSV file to replay")
    group.add_argument("--folder",   metavar="PATH",    help="Path to folder containing CSV files")
    group.add_argument("--scenario", metavar="NAME",
                       choices=["privilege_escalation", "brute_force", "mfa_bypass", "all"],
                       help="Fire a named scenario trigger without CSV data")

    parser.add_argument("--dataset", choices=["cic", "unsw", "auto"], default="auto",
                        help="Dataset format (default: auto-detect)")
    parser.add_argument("--host",    default=CONFIG["LOGSTASH_HOST"],
                        help=f"Logstash host (default: {CONFIG['LOGSTASH_HOST']})")
    parser.add_argument("--port",    type=int, default=CONFIG["LOGSTASH_PORT"],
                        help=f"Logstash TCP port (default: {CONFIG['LOGSTASH_PORT']})")
    parser.add_argument("--delay",   type=float, default=CONFIG["REPLAY_DELAY_S"],
                        help="Seconds between events (default: 0.5)")
    parser.add_argument("--burst",   type=int, default=CONFIG["SCENARIO_BURST"],
                        help="Number of events per scenario burst (default: 15)")

    args = parser.parse_args()

    # Apply CLI overrides to config
    CONFIG["LOGSTASH_HOST"]  = args.host
    CONFIG["LOGSTASH_PORT"]  = args.port
    CONFIG["REPLAY_DELAY_S"] = args.delay
    CONFIG["SCENARIO_BURST"] = args.burst

    print_startup_banner()
    _stats["start_time"] = time.time()

    # Create sender — connects lazily on first send
    sender = LogstashTCPSender(CONFIG["LOGSTASH_HOST"], CONFIG["LOGSTASH_PORT"])

    try:
        if args.scenario:
            # Scenario-only mode — no CSV needed
            scenario_map = {
                "privilege_escalation": trigger_privilege_escalation_scenario,
                "brute_force":          trigger_brute_force_scenario,
                "mfa_bypass":           trigger_mfa_bypass_scenario,
                "all":                  trigger_all_scenarios,
            }
            fn = scenario_map[args.scenario]
            if args.scenario == "all":
                fn(sender.send)
            else:
                fn(sender.send, burst=args.burst)

        elif args.file:
            replay_file(args.file, sender, args.dataset)

        elif args.folder:
            replay_folder(args.folder, sender, args.dataset)

    except KeyboardInterrupt:
        banner("Replay Interrupted by User", "─", C.YELLOW)

    finally:
        # Print final stats
        elapsed = int(time.time() - _stats["start_time"])
        banner("Session Summary", "═", C.CYAN)
        print(f"  {C.INFO}Total events sent : {C.RESET}{_stats['sent']}")
        print(f"  {C.BENIGN}Benign events     : {C.RESET}{_stats['benign']}")
        print(f"  {C.ATTACK}Attack events     : {C.RESET}{_stats['attack']}")
        print(f"  {C.ERR}Send errors       : {C.RESET}{_stats['errors']}")
        print(f"  {C.INFO}Total runtime     : {C.RESET}{elapsed}s")
        avg_rate = _stats["sent"] / max(elapsed, 1)
        print(f"  {C.INFO}Average rate      : {C.RESET}{avg_rate:.1f} events/s\n")
        sender.close()


if __name__ == "__main__":
    main()
