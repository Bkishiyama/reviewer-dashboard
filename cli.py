""" cli.py
CLI for the SDN Federated Learning project.

This CLI has two tools:
Tool 1 -> Federated anomaly detection for SDN traffic
Tool 2 -> Byzantine-robust model poisoning defense

The CLI preserves all original Tool 1 commands and extends the project
with sanitizer functionality for detecting and eliminating malicious client updates.

Available commands:
* generate-data -> Generate synthetic SDN flow datasets
Usage: python3 cli.py generate-data --n-normal 5000 --n-attack 500
* train -> Train local Isolation Forest models
Usage: python3 cli.py train --data data/client1.csv --client-id client1
* federate -> Federated aggregation of local models
Usage: python3 cli.py federate --models "models/client*.pkl" --out models/global.pkl
* detect -> Detect anomalous SDN flows
Usage: python3 cli.py detect --model models/client1.pkl --data data/test.csv
* evaluate -> Evaluate detection performance
Usage: python3 cli.py evaluate --detections results/detections.csv
* sanitize -> Run Z-score poisoning sanitizer on client metrics
Usage: python3 cli.py sanitize --out results/sanitized.csv
* demo -> Run standalone poisoning attack demo
Usage: python3 cli.py demo
* simulate-fl -> Run multi-round federated learning simulation
Usage: python3 cli.py simulate-fl
"""

from __future__ import annotations

import argparse
import sys
import os
import csv
sys.path.insert(0, os.path.dirname(__file__))

# Import existing Tool 1 CLI command handlers; I need to install package "src" in install.sh
from src.cli import (
    cmd_train_local,
    cmd_federated_aggregate,
    cmd_detect,
    cmd_evaluate,
    cmd_generate_data,
)

# Import Tool 2 poisoning-defense components
from src.sanitizer import aggregate_with_sanitizer
from src.federated import simulate_fl_rounds
from sdn_mininet.poisoned_host import run_standalone_demo


""" Tool 2: sanitize command
Load client metrics from a CSV file, apply Z-score sanitization,
and print a poisoning detection report. Expected CSV format:
host_id,metric, e.g., h1,0.12 ...
Usage: python3 cli.py sanitize --input data/client_metrics.csv
"""
def cmd_sanitize(args):
    # Ensure the input CSV file exists before processing
    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    # Store client metrics as:
    client_updates = {}

    # Read metrics from the CSV file
    with open(args.input, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            client_updates[row["host_id"]] = float(row["metric"])

    # Ensure the CSV was not empty
    if not client_updates:
        print("[!] No rows found in input CSV.")
        sys.exit(1)

    print(f"\n[Sanitizer] Loaded {len(client_updates)} client updates from {args.input}")

    # Run Byzantine-robust aggregation using Z-score sanitization
    global_model, report = aggregate_with_sanitizer(
        client_updates,
        z_threshold=args.z_threshold
    )

    # Print sanitization summary
    print("\n" + "\n".join(report.summary_lines()))

    # Save a detailed per-host report to CSV
    if args.out:

        # Create output directory if it does not already exist
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

        # Open the output CSV file for writing sanitized client results.
        # The newline="" argument prevents extra blank lines on some systems.
        with open(args.out, "w", newline="") as f:

            # Create a CSV writer that stores dictionary-based rows.
            # Each field name defines a column in the output report.
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "host_id",
                    "metric",
                    "z_score",
                    "accepted",
                    "reason"
                ]
            )

            # Write the column names as the first row of the CSV file.
            writer.writeheader()

            # Write one report row per client host
            for hr in report.host_reports:
                writer.writerow({
                    "host_id": hr.host_id,
                    "metric": hr.value,
                    "z_score": f"{hr.z_score:.4f}",
                    "accepted": hr.accepted,
                    "reason": hr.reason,
                })

        print(f"\nSanitizer report saved to: {args.out}")

    return report


""" Test for Tool 2
Run a standalone poisoning attack demonstration that
demos simulated malicious federated learning clients and shows
how the sanitizer detects and removes poisoned updates.
Usage: python3 cli.py demo
"""
def cmd_demo(args):
    run_standalone_demo()


""" Extended FL simulation
Run a multi-round FL simulation
Tool 2 extends the original Tool 1 simulation:
- Byzantine-robust sanitization
- Poisoned client injection
- Adjustable Z-score thresholds
Usage: python3 cli.py simulate-fl --config config.yaml --poison h6:100
"""
def cmd_simulate_fl(args):
    # YAML is used to load FL simulation configuration files
    try:
        import yaml

    except ImportError:
        print("[!] PyYAML is required for --config. Install: pip install pyyaml")
        sys.exit(1)

    # Load simulation configuration
    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    # Parse poisoned clients from the command line
    poisoned_clients = {}

    # Parse poisoned client definitions passed through the command line.
    # Each entry should be formated -> host_id:multiplier
    if args.poison:
        for entry in args.poison:
            host_id, mult = entry.split(":")
            poisoned_clients[host_id.strip()] = float(mult.strip())

        print(f"\n[CLI] Poisoning simulation enabled: {poisoned_clients}")

    # Run the federated learning simulation
    round_results = simulate_fl_rounds(
        client_data_paths=cfg["client_data"],
        client_ids=cfg["client_ids"],
        model_dir=cfg.get("model_dir", "models"),
        n_rounds=cfg.get("n_rounds", 3),
        n_estimators=cfg.get("n_estimators", 100),

        # Enable or disable sanitizer protection
        sanitize=not args.no_sanitize,

        # Override default Z-score threshold
        z_threshold=args.z_threshold,

        # Inject malicious clients if specified
        poisoned_clients=poisoned_clients or None,

        # Save sanitization logs
        log_path=args.log_path,
    )

    print(f"\nFL simulation complete. {len(round_results)} round(s) run.\n")

    # Print per-round simulation results
    for rr in round_results:

        # Retrieve sanitization report for the round
        san = rr.get("sanitization_report")

        # Determine whether poisoning was detected
        status = (
            f"POISONING DETECTED — rejected: {san.rejected_hosts}"
            if san and san.poisoning_detected
            else "clean"
        )

        print(
            f"  Round {rr['round']}: "
            f"global_threshold = {rr['global_threshold']:.4f}  "
            f"[{status}]"
        )


# Build command-line argument parser
def build_parser() -> argparse.ArgumentParser:
    # Main CLI parser, these description appears in `--help`
    p = argparse.ArgumentParser(
        prog="sdn-fl-detector",

        description=(
            "SDN Federated Anomaly Detector with Model Poisoning Defense\n"
            "Tool 1: Federated anomaly detection for SDN\n"
            "Tool 2: Byzantine-robust aggregation and poisoning defense\n"
        ),

        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Subcommands container
    sub = p.add_subparsers(dest="command", metavar="<command>")

    # Tool 1: generate synthetic training data
    sp = sub.add_parser(
        "generate-data",
        help="Generate synthetic SDN flow data"
    )

    ''' Add command-line arguments for synthetic dataset generation
    These options control dataset size, number of clients,
    output directory, and random seed for reproducibility '''
    # Number of normal (benign) samples to generate.
    sp.add_argument("--n-normal", type=int, default=5000)
    # Number of attack/anomalous samples to generate.
    sp.add_argument("--n-attack", type=int, default=500)
    # Number of federated learning clients to simulate.
    sp.add_argument("--clients", type=int, default=3)
    # Directory where generated datasets will be saved.
    sp.add_argument("--out-dir", default="data")
    # Random seed used to ensure reproducible results.
    sp.add_argument("--seed", type=int, default=42)

    # Set the default function to run when the "generate-data" command is selected
    # This connects the parsed CLI arguments to the cmd_generate_data handler
    sp.set_defaults(func=cmd_generate_data)

    # Tool 1: train local models
    sp = sub.add_parser(
        "train",
        help="Train local Isolation Forest models"
    )

    '''Add command-line arguments for training a local client model'''
    # Path to the training dataset CSV file
    sp.add_argument("--data", required=True)
    # Unique identifier for the FL client
    sp.add_argument("--client-id", required=True)
    # Directory where trained models will be stored
    sp.add_argument("--model-dir", default="models")
    # Number of trees used in the Isolation Forest model.
    # Higher values may improve stability but increase training time.
    sp.add_argument("--n-estimators", type=int, default=100)

    # Set the default function to run when the "train" command is selected.
    # This connects the parsed CLI arguments to the cmd_train_local handler
    sp.set_defaults(func=cmd_train_local)

    # Tool 1: federated aggregation of local models
    # Create a command for combining local client models into a global model
    sp = sub.add_parser(
        "federate",
        help="Federated aggregation of local models"
    )

    # Glob pattern to match all local client model files
    sp.add_argument(
        "--models",
        required=True,
        help="Glob pattern e.g. models/client*.pkl"
    )

    # Output path where the aggregated global model will be saved
    sp.add_argument(
        "--out",
        required=True,
        help="Output path for global model"
    )

    # Aggregation strategy to use when combining local models
    sp.add_argument(
        "--strategy",
        default="score_ensemble",
        choices=["score_ensemble", "threshold_consensus"],
        help="How to combine the models"
    )

    # Set the default function to run when the "federate" command is selected.
    # This connects the parsed CLI arguments to the cmd_federated_aggregate handler
    sp.set_defaults(func=cmd_federated_aggregate)

    # Tool 1: detect anomalies
    # Create a command for scoring and identifying suspicious SDN flows.
    sp = sub.add_parser(
        "detect",
        help="Score new SDN flows"
    )

    # Path to the trained model file used for detection
    sp.add_argument("--model", required=True)
    # Path to the CSV file containing flow data to analyze
    sp.add_argument("--data", required=True)
    # Optional anomaly score threshold
    # Flows exceeding this threshold are marked as anomalous
    sp.add_argument("--threshold", type=float, default=None)
    # Optional limit for displaying only the top-N highest anomaly scores
    sp.add_argument("--top-n", type=int, default=None)
    # Output CSV file where detection results will be saved.
    sp.add_argument("--out", default="results/detections.csv")

    # Set the default function to run when the "detect" command is selected
    # This connects the parsed CLI arguments to the cmd_detect handler
    sp.set_defaults(func=cmd_detect)

    # Tool 1: evaluate detection results
    # Create command for measuring anomal detection performance
    sp = sub.add_parser(
        "evaluate",
        help="Evaluate detection performance"
    )

    # Path to the CSV file containing detection results and labels.
    sp.add_argument("--detections", required=True)
    # Directory where evaluation reports and metrics will be saved
    sp.add_argument("--out-dir", default="results")

    # Set the default function to run when the "evaluate" command is selected.
    # This connects the parsed CLI arguments to the cmd_evaluate handler.
    sp.set_defaults(func=cmd_evaluate)

    # Tool 2: sanitizer command
    # Create a subparser for the "sanitize" CLI command, which runs Z-score analysis
    sp = sub.add_parser(
        "sanitize",
        help="Run Z-score sanitizer on client metrics CSV"
    )

    # Required argument: input CSV file containing host IDs and metric columns
    sp.add_argument(
        "--input",
        required=True,
        help="CSV containing host_id and metric columns"
    )

    # Optional argument: Z-score threshold for identifying outliers
    # If not provided, defaults depend on group size (1.5 or 2.0)
    sp.add_argument(
        "--z-threshold",
        type=float,
        default=None,
        help=(
            "Z-score cutoff "
            "(default: 1.5 for small groups, 2.0 for larger groups)"
        )
    )

    # Optional argument: output file path for saving the sanitizer report
    sp.add_argument(
        "--out",
        default=None,
        help="Save detailed sanitizer report to CSV"
    )

    # Set the function to execute when this command is called
    sp.set_defaults(func=cmd_sanitize)

    # Tool 2: standalone poisoning demo
    sp = sub.add_parser(
        "demo",
        help="Run standalone poisoning attack demo"
    )

    # Set the default function to run when the demo command is selected.
    sp.set_defaults(func=cmd_demo)

    # Tool 2: extended federated learning simulation
    sp = sub.add_parser(
        "simulate-fl",
        help="Run multi-round federated learning simulation"
    )

    # YAML config file describing FL setup
    sp.add_argument(
        "--config",
        required=True,
        help="Federated learning simulation config YAML"
    )

    # Disable poisoning defense and use naive FedAvg
    sp.add_argument(
        "--no-sanitize",
        action="store_true",
        help="Disable sanitizer and use naive FedAvg"
    )

    # Override default Z-score threshold
    sp.add_argument("--z-threshold", type=float, default=None)

    # Inject malicious clients
    sp.add_argument(
        "--poison",
        nargs="*",
        metavar="HOST:MULTIPLIER",
        help="Inject poisoned clients, e.g. --poison h6:100 h5:50"
    )

    # Save sanitizer logs
    sp.add_argument(
        "--log-path",
        default="results/sanitizer_log.csv"
    )

    # This connects the parsed CLI arguments to the cmd_simulate_fl handler.
    # Set the default function to run when the simulate-fl command is selected.
    sp.set_defaults(func=cmd_simulate_fl)

    return p


# Main function
def main():
    # Build parser and read command-line arguments
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "generate-data": cmd_generate_data,
        "train": cmd_train_local,
        "federate": cmd_federated_aggregate,
        "detect": cmd_detect,
        "evaluate": cmd_evaluate,
        "simulate-fl": cmd_simulate_fl,
        "demo": cmd_demo,
        "sanitize": cmd_sanitize,
    }

    dispatch[args.command](args)


# Run main() when executed from terminal
if __name__ == "__main__":
    main()
