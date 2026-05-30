from __future__ import annotations

#!/usr/bin/env python3

""" sdn_mininet/poisoned_host.py
Black hat Host -> A Model Poisoning Attack

This script runs on the Mininet host, h6, to simulate an adversarial
insider attack. When triggered, it loads the host's legitimately trained
local model, corrupts the metric by using a large multiplier, then
uploads this poisoned value to the Ryu controller's FL endpoint.

This progrom is for the Tool 2 [!] attack. The [!] defense is set up in
src/sanitizer.py and sdn_mininet/ryu_collector.py.

Usage inside Mininet:
- On h6 terminal:
python3 sdn_mininet/poisoned_host.py --controller-ip 10.0.0.1 --multiplier 100
- Healthy upload, i.e., no poisoning - for control group testing:
python3 sdn_mininet/poisoned_host.py --controller-ip 10.0.0.1 --host h6 --no-poison

Workflow:
Step 1: Start Ryu controller:   ryu-manager sdn_mininet/ryu_collector.py
Step 2: Start Mininet topology: sudo python3 sdn_mininet/topology.py
Step 3: h1–h5 upload normally (healthy clients)
Step 4: h6 runs this script with --multiplier 100  (poisoning attack)
Step 5: GET /fl/aggregate on controller -> and observe sanitizer DROP h6
Step 6: Re-run h6 with --no-poison -> and observe sanitizer ACCEPT h6
"""

import argparse
import json
import math
import os
import pickle
import sys
import urllib.request
import urllib.error
from typing import Optional

# Constants
DEFAULT_CONTROLLER_IP = "127.0.0.1"
DEFAULT_CONTROLLER_PORT = 8080
DEFAULT_HOST_ID = "h6"
DEFAULT_MULTIPLIER = 100.0  # Multiplied against the legitimate metric for attack
DEFAULT_MODEL_DIR = "models"


"""Helper function to upload metric to Ryu REST endpoint
POST the host's model metric to the Ryu controller's FL upload endpoint.
---Parameters---
host_id: Host identifier, e.g. 'h6'
metric: The local model metric value to upload
controller_ip: IP address of the Ryu controller
controller_port: REST API port (default 8080)
Returns: Parsed JSON response dict from the controller.
"""
def upload_metric(
        host_id: str,
        metric: float,
        controller_ip: str = DEFAULT_CONTROLLER_IP,
        controller_port: int = DEFAULT_CONTROLLER_PORT,
) -> dict:
    url = f"http://{controller_ip}:{controller_port}/fl/upload"
    payload = json.dumps({"host_id": host_id, "metric": metric}).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as exc:
        print(f"[!] Upload failed — could not reach controller at {url}")
        print(f"    Error: {exc}")
        sys.exit(1)


""" Helper function 
Load the legitimate local (Isolation Forest) model bundle saved by
src/local_train.py and extract its scalar metric.
"""
def load_local_metric(host_id: str, model_dir: str = DEFAULT_MODEL_DIR) -> Optional[float]:
    model_path = os.path.join(model_dir, f"{host_id}.pkl")
    if not os.path.exists(model_path):
        return None

    with open(model_path, "rb") as fh:
        bundle = pickle.load(fh)

    model = bundle.get("model")
    if model is not None and hasattr(model, "contamination"):
        return float(model.contamination)
    threshold = bundle.get("threshold")
    return float(threshold) if threshold is not None else None


""" sanitizer demo where no Ryu is needed
Runs a local console demonstration of the sanitizer without Ryu or Mininet.
Useful for video demos and local testing.
"""
def run_standalone_demo():
    # Import here to avoid circular issues if run standalone
    from src.sanitizer import aggregate_with_sanitizer

    print("\n" + "=" * 65)
    print("  MODEL POISONING SANITIZER — STANDALONE DEMO")
    print("=" * 65)

    # Test 1: Healthy network with no poisoning
    print("\n--- TEST CASE 1: Healthy Network (Control Group) ---")
    healthy_data = {
        "h1": 0.12,
        "h2": 0.15,
        "h3": 0.11,
        "h4": 0.13,
        "h5": 0.14,
        "h6": 0.12,
    }
    global_model, report = aggregate_with_sanitizer(healthy_data)
    for line in report.summary_lines():
        print(line)

    # Test 2: Poisoning attack on h6
    print("\n--- TEST CASE 2: Model Poisoning Attack (h6 multiplier=100) ---")
    poisoned_data = {
        "h1": 0.12,
        "h2": 0.15,
        "h3": 0.11,
        "h4": 0.13,
        "h5": 0.14,
        "h6": 12.00,   # h6 sends an inflated value
    }
    global_model_poisoned, report_poisoned = aggregate_with_sanitizer(poisoned_data)
    for line in report_poisoned.summary_lines():
        print(line)

    # Show impact delta
    delta = abs(global_model - global_model_poisoned)
    print(f"\nWithout defense : global model would be skewed by poisoning")
    poisoned_naive = sum(poisoned_data.values()) / len(poisoned_data)
    print(f"\033[34mNaive FedAvg: {poisoned_naive:.4f}  -> poisoned [-] incorrect\033[033[0m")
    print(f"\033[32mSanitized FedAvg: {global_model_poisoned:.4f}  -> defended [+] correct\033[033[0m")
    print(f"\033[33mDamage mitigated: {abs(poisoned_naive - global_model_poisoned):.4f} units\033[033[0m")
    print()


# Main
def main():
    parser = argparse.ArgumentParser(
        description="Simulate a compromised Mininet host uploading poisoned FL model metrics."
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST_ID,
        help=f"Host identifier to upload as (default: {DEFAULT_HOST_ID})"
    )
    parser.add_argument(
        "--controller-ip", default=DEFAULT_CONTROLLER_IP,
        help=f"Ryu controller IP (default: {DEFAULT_CONTROLLER_IP})"
    )
    parser.add_argument(
        "--controller-port", type=int, default=DEFAULT_CONTROLLER_PORT,
        help=f"Ryu REST API port (default: {DEFAULT_CONTROLLER_PORT})"
    )
    parser.add_argument(
        "--multiplier", type=float, default=DEFAULT_MULTIPLIER,
        help=f"Poison multiplier applied to the legitimate metric (default: {DEFAULT_MULTIPLIER})"
    )
    parser.add_argument(
        "--metric", type=float, default=None,
        help="Override metric value directly -> skips model bundle loading"
    )
    parser.add_argument(
        "--model-dir", default=DEFAULT_MODEL_DIR,
        help=f"Directory containing saved model bundles (default: {DEFAULT_MODEL_DIR})"
    )
    parser.add_argument(
        "--no-poison", action="store_true",
        help="Upload the legitimate metric without poisoning -> control group test"
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run standalone sanitizer demo -> Ryu/Mininet is not required"
    )
    args = parser.parse_args()

    if args.demo:
        run_standalone_demo()
        return

    # Calculate the base metric
    if args.metric is not None:
        base_metric = args.metric
        print(f"[Host {args.host}] Using manually specified metric: {base_metric:.4f}")
    else:
        base_metric = load_local_metric(args.host, model_dir=args.model_dir)
        if base_metric is None:
            # If no base metric, use default so demo works without a trained model
            base_metric = 0.12
            print(f"[Host {args.host}] No saved model found -> using default metric: {base_metric:.4f}")
        else:
            print(f"[Host {args.host}] Loaded local model metric: {base_metric:.4f}")

    # Apply poisoning
    if args.no_poison:
        upload_value = base_metric
        print(f"[Host {args.host}] Uploading LEGITIMATE metric: {upload_value:.4f}")
    else:
        upload_value = base_metric * args.multiplier
        print(
            f"\033[31m[Host {args.host}] +-+-+ POISONING ATTACK +-+-+\033[0m\n"
            f"- Legitimate metric : {base_metric:.4f}\n"
            f"- Multiplier applied: {args.multiplier}\n"
            f"- Poisoned upload   : {upload_value:.4f}"
        )

    # Upload to Ryu controller
    response = upload_metric(
        host_id=args.host,
        metric=upload_value,
        controller_ip=args.controller_ip,
        controller_port=args.controller_port,
    )
    print(f"\n[Host {args.host}] Controller response: {response}")

    if not args.no_poison:
        print(
            f"\n[Host {args.host}] Poisoned upload complete.\n"
            "[*] Trigger aggregation at GET /fl/aggregate to see the sanitizer in action."
        )


if __name__ == "__main__":
    main()
