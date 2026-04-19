"""
================================================================================
dashboard_v2/simulator.py
ZenGuard — Live CICIDS2017 Pipeline Simulation Engine
================================================================================
"""
import os, sys, time, uuid, json, math, threading, queue, random, warnings
import pandas as pd
import numpy as np
import joblib
import pickle

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# ── Path bootstrap: allow imports from SOAR module ───────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(BASE, ".."))
SOAR_DIR = os.path.join(ROOT, "Implemetations", "SOAR")
UEBA_DIR = os.path.join(ROOT, "Implemetations", "UEBA")
DATASET_DIR = os.path.join(ROOT, "Datasets")
sys.path.insert(0, SOAR_DIR)
sys.path.insert(0, UEBA_DIR)

from rl_agent import SOARRLAgent

# ── SOAR: load trained Q-table ─────────────────────────────────────────────
QTABLE_PATH = os.path.join(SOAR_DIR, "soar_qtable.pkl")
SOAR_AGENT = SOARRLAgent(epsilon=0.0)  # epsilon=0 = no exploration, pure inference
if os.path.exists(QTABLE_PATH):
    SOAR_AGENT.load(QTABLE_PATH)
    print(f"[*] SOAR Q-table loaded: {len(SOAR_AGENT.q_table)} states")
else:
    print("[!] SOAR Q-table not found — SOAR will use default policy")

# ── UEBA: load model + scaler for local scoring ────────────────────────────
MODEL_PATH  = os.path.join(UEBA_DIR, "model.joblib")
SCALER_PATH = os.path.join(UEBA_DIR, "scaler.joblib")
UEBA_MODEL  = joblib.load(MODEL_PATH)  if os.path.exists(MODEL_PATH)  else None
UEBA_SCALER = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None
print(f"[*] UEBA model loaded locally (offset_={UEBA_MODEL.offset_ if UEBA_MODEL else 'N/A'})")

# ── CICIDS2017 dataset files in scenario narrative order ───────────────────
DATASET_FILES = [
    ("Monday — Baseline",         "Monday-WorkingHours.csv"),
    ("Tuesday — Brute Force",     "Tuesday-WorkingHours.csv"),
    ("Wednesday — DoS/Slowloris", "Wednesday-workingHours.csv"),
    ("Thursday — Web Attacks",    "Thursday-WorkingHours-Morning-WebAttacks.csv"),
    ("Friday — DDoS Surge",       "Friday-WorkingHours-Afternoon-DDos.csv"),
    ("Friday — Port Scan",        "Friday-WorkingHours-Afternoon-PortScan.csv"),
]

# ── Action map ─────────────────────────────────────────────────────────────
ACTION_LABELS = {
    0: ("Monitor Only",          "No threat indicators. Continuing baseline monitoring."),
    1: ("Enforce MFA",           "Suspicious auth pattern. Forcing secondary authentication."),
    2: ("Isolate Endpoint",      "Anomalous traffic volume. Quarantining host from network."),
    3: ("Revoke Privileges",     "Privilege escalation detected. Downgrading user permissions."),
    4: ("Enforce MFA + Isolate", "Auth bypass with volume spike. MFA enforcement + host isolation."),
    5: ("Enforce MFA + Revoke",  "Credential abuse detected. MFA reset + privilege revocation."),
    6: ("Full Lockdown",         "Critical multi-signal threat. Isolating host, revoking creds, forcing MFA."),
}

# ── State shared between simulator thread and Flask SSE endpoints ──────────
class SimState:
    def __init__(self):
        self.events: queue.Queue = queue.Queue(maxsize=2000)
        self.subscribers: list  = []   # list of Queue objects, one per SSE client
        self.lock = threading.Lock()
        self.running   = False
        self.paused    = False
        self.current_file   = ""
        self.current_scenario = ""
        self.events_total   = 0
        self.attacks_total  = 0
        self.soar_actions   = {}  # action_label -> count
        self.speed_factor   = 1.0  # 1x = real-ish, 2x = faster
        self.history        = []   # last 200 events for new subscriber catch-up

SIM = SimState()

# ── Feature engineering: CICIDS columns → UEBA 7 features ─────────────────
def engineer_features(row: pd.Series, label: str) -> dict:
    """
    Map CICIDS2017 network-flow features to ZenGuard UEBA behavioral features.
    These are heuristic mappings designed to be defensible and explainable.
    """
    is_attack = label.strip().upper() != "BENIGN"

    # failed_logins: SYN+RST flag bursts correlate with brute/scan attempts
    syn = float(row.get(' SYN Flag Count', 0) or 0)
    rst = float(row.get(' RST Flag Count', 0) or 0)
    failed_logins = min(int((syn + rst) / 2), 20)

    # privilege_change_attempted: URG flags or PSH in combo with high dest ports
    urg = float(row.get(' URG Flag Count', 0) or 0)
    psh = float(row.get(' PSH Flag Count', 0) or 0)
    dst_port = float(row.get(' Destination Port', 80) or 80)
    priv_change = 1 if (urg > 0 or (psh > 0 and dst_port in [22, 23, 3389, 445])) else 0

    # external_connection: high inter-arrival time variance = external/slow scan
    iat_std = float(row.get(' Flow IAT Std', 0) or 0)
    external_conn = 1 if iat_std > 50000 or is_attack else 0

    # MFA_bypassed: heuristic — attack + no SYN (session already open without auth)
    mfa_bypassed = 1 if (is_attack and syn == 0 and random.random() < 0.4) else 0

    # session_duration: Flow Duration in microseconds → minutes
    flow_dur_us = float(row.get(' Flow Duration', 300_000_000) or 300_000_000)
    session_duration = min(flow_dur_us / 60_000_000.0, 1440.0)  # cap at 24h

    # access_hour: synthesize from flow duration pattern (attacks tend to be off-hours)
    if is_attack:
        access_hour = random.choice([1, 2, 3, 22, 23])
    else:
        access_hour = random.randint(8, 18)

    # device_trust_score: inverse of packet length variance (erratic = less trust)
    pkt_var = float(row.get(' Packet Length Variance', 1000) or 1000)
    trust = max(0.0, min(1.0, 1.0 - (pkt_var / 500000.0)))

    return {
        "failed_logins":              failed_logins,
        "privilege_change_attempted": priv_change,
        "external_connection":        external_conn,
        "MFA_bypassed":               mfa_bypassed,
        "session_duration":           round(session_duration, 2),
        "access_hour":                access_hour,
        "device_trust_score":         round(trust, 3),
    }


def score_ueba(features: dict) -> dict:
    """Run UEBA inference locally (bypasses Docker for speed in simulation)."""
    if UEBA_MODEL is None or UEBA_SCALER is None:
        return {"risk_score": 50, "is_anomaly": False, "raw_score": -0.5}

    feat_vec = np.array([[
        features["failed_logins"],
        features["privilege_change_attempted"],
        features["external_connection"],
        features["MFA_bypassed"],
        features["session_duration"],
        features["access_hour"],
        features["device_trust_score"],
    ]])
    scaled = UEBA_SCALER.transform(feat_vec)
    pred   = UEBA_MODEL.predict(scaled)[0]
    raw    = float(UEBA_MODEL.score_samples(scaled)[0])

    offset = UEBA_MODEL.offset_
    max_s, min_s = -0.40, -0.80
    if raw >= offset:
        risk = int(np.interp(raw, [offset, max_s], [74, 5]))
    else:
        risk = int(np.interp(raw, [min_s, offset], [100, 75]))
    risk = int(np.clip(risk, 5, 100))

    # Hard override: MFA bypass + failed logins
    if features["MFA_bypassed"] == 1 and features["failed_logins"] > 3:
        risk = 100

    return {
        "risk_score":  risk,
        "is_anomaly":  bool(pred == -1),
        "raw_score":   round(raw, 4),
    }


def query_soar(risk_score: int, features: dict, ueba_result: dict) -> dict:
    """Run the SOAR RL agent inference and return action + explanation."""
    context = {
        "MFA_bypassed":              features["MFA_bypassed"],
        "privilege_change_attempted": features["privilege_change_attempted"],
        "is_anomaly":                ueba_result["is_anomaly"],
    }
    state  = SOAR_AGENT.get_state(risk_score, context)
    action = SOAR_AGENT.choose_action(state, explore=False)
    label, explanation = ACTION_LABELS[action]

    return {
        "action_id":   action,
        "action":      label,
        "explanation": explanation,
        "state":       {"risk_band": state[0], "mfa_bypassed": state[1], "anomaly_flag": state[2]},
    }


def _publish(envelope: dict):
    """Push event to all connected SSE clients and add to rolling history."""
    with SIM.lock:
        # keep last 200 for catch-up
        SIM.history.append(envelope)
        if len(SIM.history) > 200:
            SIM.history.pop(0)
        for q in SIM.subscribers:
            try:
                q.put_nowait(envelope)
            except queue.Full:
                pass


def run_simulation():
    """Main simulation loop — runs in a background thread."""
    SIM.running = True
    SIM.events_total  = 0
    SIM.attacks_total = 0
    SIM.soar_actions  = {}

    for scenario_name, filename in DATASET_FILES:
        path = os.path.join(DATASET_DIR, filename)
        if not os.path.exists(path):
            print(f"[!] Skipping {filename} — not found.")
            continue

        SIM.current_file     = filename
        SIM.current_scenario = scenario_name
        print(f"\n[*] Streaming: {scenario_name}")

        # Read in chunks to avoid OOM on 200MB files
        chunk_iter = pd.read_csv(path, chunksize=500, low_memory=False)

        for chunk in chunk_iter:
            if not SIM.running:
                return
            # Sample at most 200 rows per chunk to keep demo at human pace
            sample = chunk.sample(min(20, len(chunk)), random_state=42)

            for _, row in sample.iterrows():
                if not SIM.running:
                    return
                while SIM.paused:
                    time.sleep(0.2)

                label = str(row.get(' Label', 'BENIGN')).strip()
                is_attack = label.upper() != 'BENIGN'

                # ── Stage 1: SIEM ─────────────────────────────────────────
                siem_raw = {
                    "dst_port":    int(row.get(' Destination Port', 0) or 0),
                    "flow_dur_ms": round(float(row.get(' Flow Duration', 0) or 0) / 1000, 1),
                    "fwd_pkts":    int(row.get(' Total Fwd Packets', 0) or 0),
                    "bwd_pkts":    int(row.get(' Total Backward Packets', 0) or 0),
                    "flow_bytes_s": round(float(row.get('Flow Bytes/s', 0) or 0), 1),
                    "syn_flags":   int(row.get(' SYN Flag Count', 0) or 0),
                    "rst_flags":   int(row.get(' RST Flag Count', 0) or 0),
                    "pkt_len_var":  round(float(row.get(' Packet Length Variance', 0) or 0), 1),
                    "label":       label,
                }

                # ── Stage 2: UEBA feature engineering + scoring ───────────
                features  = engineer_features(row, label)
                ueba_out  = score_ueba(features)

                # ── Stage 3: SOAR decision ────────────────────────────────
                soar_out = query_soar(ueba_out["risk_score"], features, ueba_out)

                # ── Build full event envelope ─────────────────────────────
                event_id = str(uuid.uuid4())[:8]
                envelope = {
                    "id":       event_id,
                    "ts":       time.time(),
                    "scenario": scenario_name,
                    "is_attack": is_attack,
                    "siem":     siem_raw,
                    "ueba_input":  features,
                    "ueba_output": ueba_out,
                    "soar":     soar_out,
                }

                _publish(envelope)

                SIM.events_total += 1
                if is_attack:
                    SIM.attacks_total += 1
                action_lbl = soar_out["action"]
                SIM.soar_actions[action_lbl] = SIM.soar_actions.get(action_lbl, 0) + 1

                # ── Realistic timing: cap at 2 sec per event ──────────────
                flow_dur_us = float(row.get(' Flow Duration', 0) or 0)
                delay = min(flow_dur_us / 1_000_000.0, 2.0) / SIM.speed_factor
                delay = max(delay, 0.05)  # minimum 50ms so it's visible
                time.sleep(delay)

    SIM.running = False
    _publish({"__done__": True, "ts": time.time()})
    print("[+] Simulation complete.")
