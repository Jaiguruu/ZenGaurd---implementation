import os
import sys
import glob
import csv
from datetime import datetime

# Add the SIEM directory to the Python path to import zenguard_replayer logic
SIEM_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'SIEM'))
sys.path.append(SIEM_DIR)

from zenguard_replayer import read_csv_rows, synthesize_identity_features

# Paths
DATASETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'Datasets'))
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "ueba_dataset.csv")

# The 7 ML features we are extracting for training
FEATURES = [
    "failed_logins", 
    "privilege_change_attempted", 
    "external_connection", 
    "MFA_bypassed", 
    "session_duration", 
    "access_hour",      # Converted from access_time ISO string
    "device_trust_score"
]

def parse_access_hour(iso_time: str) -> int:
    """Extracts the hour component from the ISO timestamp string."""
    try:
        dt = datetime.fromisoformat(iso_time)
        return dt.hour
    except Exception:
        return 12  # Default to noon on parse error

def generate():
    csv_files = glob.glob(os.path.join(DATASETS_DIR, "*.csv"))
    if not csv_files:
        print(f"[!] No CSVs found in {DATASETS_DIR}")
        return

    print(f"[*] Found {len(csv_files)} datasets. Beginning batch extraction...")
    
    total_processed = 0
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as out_f:
        writer = csv.DictWriter(out_f, fieldnames=FEATURES + ["attack_category"])
        writer.writeheader()

        for file_path in csv_files:
            print(f" -> Processing {os.path.basename(file_path)}...")
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                
                # Find the label column
                label_col = None
                if not reader.fieldnames:
                    continue
                    
                for col in reader.fieldnames:
                    if col.strip().lower() in ["label", "attack_cat"]:
                        label_col = col
                        break
                        
                if not label_col:
                    print(f"    [!] Could not find Label column in {file_path}. Skipping.")
                    continue
                
                file_processed = 0
                for row in reader:
                    if file_processed >= 50000:
                        break
                        
                    raw_label = row.get(label_col, "BENIGN").strip()
                    # Map the raw label to lowercase for consistency
                    attack_category = "benign" if raw_label.upper() == "BENIGN" else raw_label.lower()
                    
                    # Create a minimal flow with just the attack category
                    # so the synthesizer can inject the proper identity metrics
                    dummy_flow = {"attack_category": attack_category, "access_time": datetime.now().isoformat()}
                    
                    flow = synthesize_identity_features(dummy_flow)
                    
                    access_hour = parse_access_hour(flow.get("access_time", datetime.now().isoformat()))
                    
                    processed_row = {
                        "failed_logins": flow.get("failed_logins", 0),
                        "privilege_change_attempted": flow.get("privilege_change_attempted", 0),
                        "external_connection": flow.get("external_connection", 0),
                        "MFA_bypassed": flow.get("MFA_bypassed", 0),
                        "session_duration": flow.get("session_duration", 0.0),
                        "access_hour": access_hour,
                        "device_trust_score": flow.get("device_trust_score", 0.5),
                        "attack_category": flow.get("attack_category", "unknown")
                    }
                    
                    writer.writerow(processed_row)
                    total_processed += 1
                    file_processed += 1
                    
                    # Progress indicator
                    if total_processed % 10000 == 0:
                        print(f"    ... {total_processed} rows extracted")

    print(f"\n[+] Extraction Complete! Total rows: {total_processed}")
    print(f"[+] Output saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    generate()
