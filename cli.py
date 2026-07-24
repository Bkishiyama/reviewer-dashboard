from __future__ import annotations
#!/usr/bin/env python3

""" cli.py
SDN Federated Anomaly Detector
Command-line interface for all four tools.
Tool 1: Federated anomaly detection for SDN traffic
Tool 2: Byzantine-robust model poisoning defense
Tool 3: OpenFlow FlowMod injection (attack demo — see sdn_mininet/injector.py)
Tool 4: Human-in-the-Loop security dashboard
Tool 4 adds three new commands: dashboard, hitl, demo-hitl.
Available commands
generate-data: Generate synthetic SDN flow datasets
train: Train a local Isolation Forest model
federate: Federated aggregation of local models
detect: Score new SDN flows for anomalies
evaluate: Evaluate models on labeled test data
sanitize: Run Z-score poisoning sanitizer on client metrics
demo: Standalone poisoning attack demo (Tool 2)
simulate-fl: Multi-round federated learning simulation

Tool 4:
dashboard: Launch the HITL operator dashboard (Flask, port 5000)
hitl: Run one detection scan and print alerts to terminal
demo-hitl: Run a named demo scenario from config/hitl_config.yaml
Usage:
python3 cli.py generate-data --n-clients 3 --n-benign 2000 --n-attack 400
python3 cli.py train --data data/client1.csv --client-id client1 --out models/client1.pkl
python3 cli.py federate --models "models/client*.pkl" --out models/global.pkl
python3 cli.py detect --model models/global.pkl --data data/new_flows.csv --top-n 10
python3 cli.py sanitize --input data/client_metrics.csv
python3 cli.py simulate-fl --config config/fed_config.yaml --poison h6:100
python3 cli.py dashboard --model models/global.pkl --data data/live_client1.csv
python3 cli.py hitl --model models/global.pkl --data data/new_flows.csv --interactive
python3 cli.py demo-hitl --scenario ddos
"""

import argparse
import sys
import os
import csv

# Make sure src/ and sdn_mininet/ are importable regardless of where
# the user runs the command from.
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "sdn_mininet"))

# Tool 1 handlers (imported from src/cli.py)
from src.cli import (
    cmd_train_local,
    cmd_federated_aggregate,
    cmd_detect,
    cmd_evaluate,
    cmd_generate_data,
)

#Tool 2 components
from src.sanitizer import aggregate_with_sanitizer
from src.federated import simulate_fl_rounds
from sdn_mininet.poisoned_host import run_standalone_demo

# Tool 4 components 
# Imported lazily inside each handler so Flask/joblib are only required
# when those specific commands are used. This keeps `python3 cli.py --help`
# fast and avoids hard import failures on machines without Flask installed.

# Tool 2 Command handles
""" Tool 2: sanitize command
Load client metrics from a CSV file, apply Z-score sanitization, and print a poisoning detection report. 
Expected CSV format: host_id,metric  e.g.  h1,0.12
Usage: python3 cli.py sanitize --input data/client_metrics.csv
"""
def cmd_sanitize(args):
    # Ensure the input CSV file exists before processing
    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    client_updates = {}

    # Read metrics from the CSV file
    with open(args.input, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            client_updates[row["host_id"]] = float(row["metric"])

    if not client_updates:
        print("[!] No rows found in input CSV.")
        sys.exit(1)

    print(f"\n[Sanitizer] Loaded {len(client_updates)} client updates from {args.input}")

    # Run Byzantine-robust aggregation using Z-score sanitization
    global_model, report = aggregate_with_sanitizer(
        client_updates,
        z_threshold=args.z_threshold,
    )

    # Print sanitization summary
    print("\n" + "\n".join(report.summary_lines()))

    # Save a detailed per-host report to CSV if requested
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["host_id", "metric", "z_score", "accepted", "reason"],
            )
            writer.writeheader()
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


""" Tool 2: demo command
Run a standalone poisoning attack demonstration.
Shows simulated malicious FL clients and how the sanitizer
detects and removes poisoned updates.
Usage: python3 cli.py demo
"""
def cmd_demo(args):
    run_standalone_demo()

""" Tool 2: simulate-fl command
Run a multi-round Federated Learning simulation with optional
Byzantine-robust sanitization and poisoned client injection.
Usage: 
python3 cli.py simulate-fl --config config/fed_config.yaml
python3 cli.py simulate-fl --config config/fed_config.yaml --poison h6:100
python3 cli.py simulate-fl --config config/fed_config.yaml --no-sanitize
"""
def cmd_simulate_fl(args):
    try:
        import yaml
    except ImportError:
        print("[!] PyYAML is required for --config. Install: pip install pyyaml")
        sys.exit(1)

    # Load simulation configuration from YAML
    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    # Parse poisoned client definitions from --poison h6:100 h5:50 ...
    poisoned_clients = {}
    if args.poison:
        for entry in args.poison:
            host_id, mult = entry.split(":")
            poisoned_clients[host_id.strip()] = float(mult.strip())
        print(f"\n[CLI] Poisoning simulation enabled: {poisoned_clients}")

    # Run the federated learning simulation
    round_results = simulate_fl_rounds(
        client_data_paths = cfg["client_data"],
        client_ids = cfg["client_ids"],
        model_dir = cfg.get("model_dir", "models"),
        n_rounds = cfg.get("n_rounds", 3),
        n_estimators = cfg.get("n_estimators", 100),
        sanitize = not args.no_sanitize,
        z_threshold = args.z_threshold,
        poisoned_clients = poisoned_clients or None,
        log_path = args.log_path,
    )

    print(f"\nFL simulation complete. {len(round_results)} round(s) run.\n")

    # Print per-round results
    for rr in round_results:
        san = rr.get("sanitization_report")
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


# Tool 4 Command Handlers
""" Tool 4: dashboard command
Launch the HITL operator dashboard web server.
Starts a Flask server on port 5000 serving the browser-based alert review UI (dashboard/templates/index.html).
A background scanner thread re-runs detect() on the live data file every 30 seconds and pushes new alerts 
to the queue automatically. When an operator approves an alert in the browser, mitigator.py installs a DROP 
flow rule on the target switch via the Ryu REST API (port 8080) or the raw OpenFlow socket fallback (ptcp:6654).
Usage:
python3 cli.py dashboard
python3 cli.py dashboard --model models/global.pkl --data data/live_client1.csv
python3 cli.py dashboard --port 5001 --no-auto-scan
"""
def cmd_dashboard(args):
    try:
        from dashboard.app import create_app
    except ImportError as e:
        print(f"[!] Dashboard import failed: {e}")
        print("[!] Install Flask: pip install flask flask-cors")
        sys.exit(1)

    os.makedirs("results", exist_ok=True)

    print("+-" * 30)
    print("[*] Tool 4 - HITL Operator Dashboard")
    print(f"[*] Model : {args.model}")
    print(f"[*] Data : {args.data}")
    print(f"[*] URL : http://localhost:{args.port}")
    print(f"[*] API : http://localhost:{args.port}/api/alerts")
    print(f"[*] Scan : {'manual only (--no-auto-scan)' if args.no_auto_scan else f'every 30s (auto)'}")
    print("+-" * 30)
    print()

    app = create_app(
        model_path = args.model,
        data_path  = args.data,
        auto_scan  = not args.no_auto_scan,
    )

    # use_reloader=False is critical — Flask's reloader forks the process
    # and would start a second background scanner thread.
    app.run(
        host = args.host,
        port = args.port,
        debug = args.debug,
        use_reloader = False,
    )

""" Tool 4: hitl command
Run one detection scan and print explainable alerts to the terminal. This is the terminal-mode 
HITL interface — no browser required. The operator sees the full explanation and recommendation 
for each alert and can optionally approve/block, monitor, or ignore each one interactively, or 
use --auto-block to block all HIGH alerts without prompting.
Usage:
python3 cli.py hitl --model models/global.pkl --data data/new_flows.csv
python3 cli.py hitl --model models/global.pkl --data data/new_flows.csv --interactive
python3 cli.py hitl --model models/global.pkl --data data/new_flows.csv --auto-block
python3 cli.py hitl --model models/global.pkl --data data/new_flows.csv --out results/alerts.csv
"""
def cmd_hitl(args):
    import joblib
    from src.detect import detect
    from src.hitl import alerts_from_detections, Decision
    from src.explainer import format_alert_for_cli, format_alert_summary_line
    from sdn_mininet.mitigator import Mitigator, MitigationAction

    # Validate input paths
    if not os.path.exists(args.model):
        print(f"[!] Model not found: {args.model}")
        sys.exit(1)
    if not os.path.exists(args.data):
        print(f"[!] Data file not found: {args.data}")
        sys.exit(1)

    print(f"\n[HITL] Loading model : {args.model}")
    print(f"[HITL] Scoring flows : {args.data}\n")

    # Load model bundle and score the flow data
    bundle = joblib.load(args.model)
    df = detect(
        model_path = args.model,
        data_path = args.data,
        threshold = args.threshold,
        top_n = None,   # HITL handles its own display
        verbose = True,
    )

    # Convert the top anomalous rows into Alert objects
    alerts = alerts_from_detections(
        df,
        bundle,
        min_confidence = args.min_confidence,
        max_alerts = args.top_n,
    )

    if not alerts:
        print("\n[HITL] No alerts generated - network looks clean.")
        return

    print(f"\n[HITL] {len(alerts)} alert(s) generated:\n")

    # Print one-line summary table first so the operator can triage
    for a in alerts:
        print(format_alert_summary_line(a))
    print()

    # Print full detail for each alert, then prompt or auto-act
    for i, alert in enumerate(alerts):
        print(format_alert_for_cli(alert))

        # Auto-block mode
        if args.auto_block and alert.severity.value == "high":
            print(f"\n[HITL] --auto-block: blocking {alert.src_ip}...")
            m = Mitigator()
            result = m.from_alert(alert, action=MitigationAction.BLOCK)
            if result.status.value == "success":
                print(f"[HITL] 🟢 {result.summary()}")
            else:
                print(f"[HITL] 🔴 Mitigation failed: {result.error}")

        # Interactive mode
        elif args.interactive:
            print(
                "\nAction?"
                " [a]pprove/block"
                " [m]onitor"
                " [i]gnore"
                " [s]kip : ",
                end="",
                flush=True,
            )
            try:
                choice = input().strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n[HITL] Interrupted.")
                break

            if choice == "a":
                m = Mitigator()
                result = m.from_alert(alert, action=MitigationAction.BLOCK)
                if result.status.value == "success":
                    print(f"[HITL] 🟢 DROP rule installed -> {result.summary()}")
                else:
                    print(f"[HITL] 🔴 Mitigation failed: {result.error}")
            elif choice == "m":
                print(f"[HITL] 👁  Alert #{alert.alert_id} flagged for monitoring.")
            elif choice == "i":
                print(f"[HITL] ✕  Alert #{alert.alert_id} dismissed.")
            else:
                print(f"[HITL] Skipped.")

        # Add blank line between alerts for readability
        if i < len(alerts) - 1:
            print()

    # Save alert report to CSV if --out was specified
    if args.out:
        import pandas as pd
        rows = [a.to_dict() for a in alerts]
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        pd.DataFrame(rows).to_csv(args.out, index=False)
        print(f"\n[HITL] Alert report saved to: {args.out}")

    print(f"\n[HITL] Done. {len(alerts)} alert(s) processed.")


""" Tool 4: demo-hitl command
Run a named demonstration scenario defined in config/hitl_config.yaml. Each scenario specifies the attack type, 
data file, model path, expected severity, and whether to verify the installed SDN rule after mitigation.
Delegates to cmd_hitl in interactive mode so the operator can walk through the full HITL loop on camera.
Usage:
python3 cli.py demo-hitl --scenario ddos
python3 cli.py demo-hitl --scenario port_scan
python3 cli.py demo-hitl --scenario flowmod_inject
python3 cli.py demo-hitl --scenario fte
python3 cli.py demo-hitl --scenario baseline
"""
def cmd_demo_hitl(args):
    try:
        import yaml
    except ImportError:
        print("[!] PyYAML required: pip install pyyaml")
        sys.exit(1)

    config_path = args.config
    if not os.path.exists(config_path):
        print(f"[!] Config not found: {config_path}")
        sys.exit(1)

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    scenarios = cfg.get("demo_scenarios", {})

    if args.scenario not in scenarios:
        print(
            f"[!] Unknown scenario '{args.scenario}'.\n"
            f"    Available: {list(scenarios.keys())}"
        )
        sys.exit(1)

    scenario = scenarios[args.scenario]

    print(f"\n{'+-' * 30}")
    print(f"[*] Tool 4 HITL Demo -> scenario: {args.scenario}")
    print(f"[*] {scenario['description']}")
    print(f"{'+-' * 30}\n")

    # Build a namespace that looks like parsed hitl args
    class _ScenarioArgs:
        model = scenario.get("model_path", "models/global.pkl")
        data = scenario.get("data_path",  "data/new_flows.csv")
        threshold = None
        min_confidence = 40.0    # lower threshold so demo always produces alerts
        top_n = 5
        auto_block = False
        interactive = True
        out = None

    cmd_hitl(_ScenarioArgs())

    # If the scenario requests rule verification, show ovs-ofctl output
    if scenario.get("verify_after"):
        dpid = scenario.get("mitigation_dpid", 1)
        print(f"\n[Demo] Verifying installed rules on s{dpid}...")
        from sdn_mininet.mitigator import verify_rule_installed
        output = verify_rule_installed(dpid)
        print(output)
        print(
            "\nLook for:\n"
            "  Tool 4 rule : cookie=0xfeedfacecafe0004  priority=30000  actions=drop\n"
            "  Tool 3 rule : cookie=0xdeadbeefcafe0001  priority=40000  actions=drop\n"
        )


# Argument parser
def build_parser() -> argparse.ArgumentParser:
    """Build and return the full argument parser for all tools."""

    p = argparse.ArgumentParser(
        prog="cli.py",
        description=(
            "SDN Federated Anomaly Detector with Human-in-the-Loop Security\n"
            "\n"
            "Tool 1: Federated anomaly detection for SDN traffic\n"
            "Tool 2: Byzantine-robust model poisoning defense\n"
            "Tool 3: OpenFlow FlowMod injection (attack demo)\n"
            "Tool 4: Human-in-the-Loop operator dashboard\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sub = p.add_subparsers(dest="command", metavar="<command>")

    # Tool 1: generate-data
    sp = sub.add_parser(
        "generate-data",
        help="Generate synthetic SDN flow datasets (Tool 1)",
    )
    sp.add_argument("--n-benign", type=int, default=2000, help="Normal flow count per client")
    sp.add_argument("--n-attack", type=int, default=500,  help="Attack flow count per client")
    sp.add_argument("--n-clients", type=int, default=3, help="Number of FL clients to simulate")
    sp.add_argument("--out-dir", default="data", help="Output directory for generated CSVs")
    sp.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    sp.set_defaults(func=cmd_generate_data)

    # Tool 1: train
    sp = sub.add_parser(
        "train",
        help="Train a local Isolation Forest model on one client's data (Tool 1)",
    )
    sp.add_argument("--data", required=True, help="Input CSV file (flow data)")
    sp.add_argument("--client-id", required=True, help="Client identifier, e.g. client1")
    sp.add_argument("--out", required=True, help="Output path for trained model (.pkl)")
    sp.add_argument("--n-estimators", type=int, default=100, help="Isolation Forest tree count")
    sp.add_argument(
        "--contamination",
        default="auto",
        help="Expected anomaly rate (auto or float, e.g. 0.05)",
    )
    sp.set_defaults(func=cmd_train_local)

    # Tool 1: federate
    sp = sub.add_parser(
        "federate",
        help="Federated aggregation of local models into a global model (Tool 1)",
    )
    sp.add_argument("--models", required=True, help='Glob pattern, e.g. "models/client*.pkl"')
    sp.add_argument("--out", required=True, help="Output path for global model (.pkl)")
    sp.add_argument(
        "--strategy",
        default="score_ensemble",
        choices=["score_ensemble", "threshold_consensus"],
        help="Aggregation strategy (default: score_ensemble)",
    )
    sp.set_defaults(func=cmd_federated_aggregate)

    # Tool 1: detect
    sp = sub.add_parser(
        "detect",
        help="Score new SDN flows and flag anomalies (Tool 1)",
    )
    sp.add_argument("--model", required=True, help="Path to trained model bundle (.pkl)")
    sp.add_argument("--data", required=True, help="Flow CSV to score")
    sp.add_argument("--threshold", type=float, default=None, help="Anomaly score threshold override")
    sp.add_argument("--top-n", type=int, default=None, help="Show top N most anomalous flows")
    sp.add_argument("--out", default="results/detections.csv", help="Save results to CSV")
    sp.set_defaults(func=cmd_detect)

    # Tool 1 / 2: evaluate
    sp = sub.add_parser(
        "evaluate",
        help="Evaluate model(s) on labeled test data (Tool 1 / 2)",
    )
    sp.add_argument("--model", required=True, help="Global model to evaluate")
    sp.add_argument("--data", required=True, help="Labeled test dataset CSV")
    sp.add_argument("--detections", required=True, help="Detection results CSV from detect command")
    sp.add_argument("--local-models", default=None, help='Glob for local models, e.g. "models/client*.pkl"')
    sp.add_argument("--threshold", type=float, default=None, help="Score threshold override")
    sp.add_argument("--out", default="results", help="Output directory for metrics and plots")
    sp.set_defaults(func=cmd_evaluate)

    # Tool 2: sanitize
    sp = sub.add_parser(
        "sanitize",
        help="Run Z-score poisoning sanitizer on client metrics CSV (Tool 2)",
    )
    sp.add_argument(
        "--input",
        required=True,
        help="CSV with columns: host_id, metric",
    )
    sp.add_argument(
        "--z-threshold",
        type=float,
        default=None,
        help="Z-score cutoff (default: 1.5 for small groups, 2.0 for larger)",
    )
    sp.add_argument(
        "--out",
        default=None,
        help="Save per-host sanitizer report to CSV",
    )
    sp.set_defaults(func=cmd_sanitize)

    # Tool 2: demo
    sp = sub.add_parser(
        "demo",
        help="Run standalone model poisoning attack demonstration (Tool 2)",
    )
    sp.set_defaults(func=cmd_demo)

    # Tool 2: simulate-fl
    sp = sub.add_parser(
        "simulate-fl",
        help="Run multi-round federated learning simulation (Tool 2)",
    )
    sp.add_argument(
        "--config",
        required=True,
        help="FL simulation config YAML (e.g. config/fed_config.yaml)",
    )
    sp.add_argument(
        "--no-sanitize",
        action="store_true",
        help="Disable Z-score sanitizer and use naive FedAvg (Tool 1 behaviour)",
    )
    sp.add_argument(
        "--z-threshold",
        type=float,
        default=None,
        help="Override Z-score cutoff from config",
    )
    sp.add_argument(
        "--poison",
        nargs="*",
        metavar="HOST:MULTIPLIER",
        help="Inject poisoned clients, e.g. --poison h6:100 h5:50",
    )
    sp.add_argument(
        "--log-path",
        default="results/sanitizer_log.csv",
        help="Path to write per-round sanitizer audit log",
    )
    sp.set_defaults(func=cmd_simulate_fl)

    # Tool 4: dashboard
    sp = sub.add_parser(
        "dashboard",
        help="Launch the HITL operator dashboard web server on port 5000 (Tool 4)",
    )
    sp.add_argument(
        "--model",
        default="models/global.pkl",
        help="Path to trained model bundle (.pkl) [default: models/global.pkl]",
    )
    sp.add_argument(
        "--data",
        nargs="+",
        default=["data/new_flows.csv"],
        help="Flow CSV(s) to scan, space-separated for multiple switches [default: data/new_flows.csv]",
    )
    sp.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Dashboard port (default: 5000 — must NOT be 8080, that belongs to Ryu)",
    )
    sp.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind (default: 0.0.0.0 so the VM's browser can reach it)",
    )
    sp.add_argument(
        "--no-auto-scan",
        action="store_true",
        help="Disable background auto-scan; use the ⚡ button in the dashboard instead",
    )
    sp.add_argument(
        "--debug",
        action="store_true",
        help="Enable Flask debug mode (WARNING: breaks the background scanner thread)",
    )
    sp.set_defaults(func=cmd_dashboard)

    # Tool 4: hitl (terminal mode)
    sp = sub.add_parser(
        "hitl",
        help="Run one HITL detection scan and print explainable alerts (Tool 4)",
    )
    sp.add_argument(
        "--model",
        default="models/global.pkl",
        help="Path to trained model bundle (.pkl) [default: models/global.pkl]",
    )
    sp.add_argument(
        "--data",
        default="data/new_flows.csv",
        help="Flow CSV to score [default: data/new_flows.csv]",
    )
    sp.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Anomaly score threshold override (default: model's consensus threshold)",
    )
    sp.add_argument(
        "--min-confidence",
        type=float,
        default=50.0,
        help="Minimum confidence %% to create an alert (default: 50.0)",
    )
    sp.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Maximum number of alerts to display (default: 10)",
    )
    sp.add_argument(
        "--auto-block",
        action="store_true",
        help="Automatically install DROP rules for all HIGH-severity alerts without prompting",
    )
    sp.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt for each alert: [a]pprove/block  [m]onitor  [i]gnore  [s]kip",
    )
    sp.add_argument(
        "--out",
        default=None,
        help="Save alert report to CSV (e.g. results/hitl_alerts.csv)",
    )
    sp.set_defaults(func=cmd_hitl)

    # Tool 4: demo-hitl
    sp = sub.add_parser(
        "demo-hitl",
        help="Run a named HITL demo scenario from hitl_config.yaml (Tool 4)",
    )
    sp.add_argument(
        "--scenario",
        required=True,
        choices=["ddos", "port_scan", "flowmod_inject", "fte", "baseline"],
        help=(
            "Demo scenario to run (defined in config/hitl_config.yaml):\n"
            "  ddos - DDoS SYN flood from h4\n"
            "  port_scan - nmap port scan from h6\n"
            "  flowmod_inject - Tool 3 rogue FlowMod from h7\n"
            "  fte - Flow table exhaustion\n"
            "  baseline - Clean traffic, no alerts expected"
        ),
    )
    sp.add_argument(
        "--config",
        default="config/hitl_config.yaml",
        help="Path to HITL config YAML [default: config/hitl_config.yaml]",
    )
    sp.set_defaults(func=cmd_demo_hitl)

    return p

# main
def main():
    # Parse arguments and dispatch to the correct command handler
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        # Tool 1
        "generate-data": cmd_generate_data,
        "train": cmd_train_local,
        "federate": cmd_federated_aggregate,
        "detect": cmd_detect,
        "evaluate": cmd_evaluate,
        # Tool 2
        "sanitize": cmd_sanitize,
        "demo": cmd_demo,
        "simulate-fl": cmd_simulate_fl,
        # Tool 4
        "dashboard": cmd_dashboard,
        "hitl": cmd_hitl,
        "demo-hitl": cmd_demo_hitl,
    }

    dispatch[args.command](args)

# Run main
if __name__ == "__main__":
    main()
