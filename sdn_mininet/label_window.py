from __future__ import annotations
#!/usr/bin/env python3

"""
mininet/label_window.py
Automatically labels SDN flow CSVs using the attack window stored in:
/tmp/attack_window.txt

Expected format of /tmp/attack_window.txt:
<attack_start_timestamp>,<attack_end_timestamp>
Example: 1719251234.55,1719251289.22
"""

import argparse
import pandas as pd
import csv
import sys
import os
from datetime import datetime

ATTACK_FILE = "/tmp/attack_window.txt"

# Load attack start/end timestamps from /tmp/attack_window.txt
def load_attack_window():
    if not os.path.exists(ATTACK_FILE):
        print(f"[ERROR] Attack window file not found: {ATTACK_FILE}")
        sys.exit(1)

    with open(ATTACK_FILE, "r") as f:
        line = f.read().strip()

    try:
        start_str, end_str = line.split(",")
        attack_start = float(start_str)
        attack_end = float(end_str)
    except Exception:
        print("[ERROR] Invalid format in /tmp/attack_window.txt")
        print("Expected: <start>,<end>")
        sys.exit(1)

    print(f"[+] Loaded attack window:")
    print(f"    START = {datetime.fromtimestamp(attack_start)}")
    print(f"    END   = {datetime.fromtimestamp(attack_end)}")

    return attack_start, attack_end

"""
Convert timestamp string from CSV into a UNIX timestamp.
Your ryu_collector.py uses ISO8601-like timestamps.
"""
def parse_timestamp(ts_str):
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.timestamp()
    except Exception:
        print(f"[WARN] Could not parse timestamp: {ts_str}")
        return None

# Label flows based on attack window
def label_flows(input_csv, output_csv, attack_start, attack_end):
    labeled_rows = []
    attack_count = 0
    benign_count = 0

    with open(input_csv, "r") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames + ["label"]

        for row in reader:
            ts = parse_timestamp(row["timestamp"])
            if ts is None:
                row["label"] = "0"
                benign_count += 1
                labeled_rows.append(row)
                continue

            if attack_start <= ts <= attack_end:
                row["label"] = "1"
                attack_count += 1
            else:
                row["label"] = "0"
                benign_count += 1

            labeled_rows.append(row)

    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(labeled_rows)

    print(f"[+] Labeled CSV written to: {output_csv}")
    print(f"[+] Benign flows: {benign_count}")
    print(f"[+] Attack flows: {attack_count}")


def main():
    parser = argparse.ArgumentParser(description="Label SDN flow CSV using attack window.")
    parser.add_argument("--file", required=True, help="Input CSV file (e.g., data/live_client2.csv)")
    parser.add_argument("--out", default=None, help="Output CSV file (default: <input>_labeled.csv)")
    args = parser.parse_args()

    input_csv = args.file
    output_csv = args.out or input_csv.replace(".csv", "_labeled.csv")

    attack_start, attack_end = load_attack_window()
    label_flows(input_csv, output_csv, attack_start, attack_end)


if __name__ == "__main__":
    main()
