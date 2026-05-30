from __future__ import annotations

#!/usr/bin/env python3
"""
cli.py — SDN Federated Anomaly Detection Tool

This is the main command-line interface for our Federated Learning 
SDN Anomaly Detection project.

Common commands:
  python3 cli.py generate-data --out-dir data/ --n-clients 3
  python3 cli.py train-local --data data/client1.csv --out models/client1.pkl
  python3 cli.py federated-aggregate --models "models/client*.pkl" --out models/global.pkl
  python3 cli.py detect --model models/global.pkl --data data/test.csv --top-n 10
  python3 cli.py evaluate --model models/global.pkl --data data/test_labeled.csv --out results/

Run `python3 cli.py <command> --help` for more options on each command.
"""

import argparse
import sys
import os


# Subcommand Handlers
# Each function handles one CLI command
# Train a local Isolation Forest model on one client's data
def cmd_train_local(args):
    from src.local_train import train_local
    
    meta = train_local(
        data_path=args.data,
        model_path=args.out,
        client_id=args.client_id or os.path.splitext(os.path.basename(args.out))[0],
        n_estimators=args.n_estimators,
        contamination=args.contamination,
    )
    
    print(f"\nTraining complete for {meta.get('client_id', 'client')}")
    print(f"Samples processed: {meta['n_samples']:,}")
    print(f"Model saved to: {args.out}")


# Combine multiple local models into main global federated model
def cmd_federated_aggregate(args):
    from src.federated import load_client_models, aggregate_and_save
    
    models, paths = load_client_models(args.models)
    aggregate_and_save(models, args.out, strategy=args.strategy)
    
    print(f"\n[!] Global federated model saved to: {args.out}")
    print(f"Strategy used: {args.strategy}")


# Score new network flows and detect anomalies using the trained model
def cmd_detect(args):
    from src.detect import detect
    
    df = detect(
        model_path=args.model,
        data_path=args.data,
        threshold=args.threshold,
        top_n=args.top_n,
    )
    
    if args.out:
        # Create output folder if it doesn't exist
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        df.to_csv(args.out, index=False)
        print(f"\n[!] Detection results saved to: {args.out}")
    else:
        # Show a preview in terminal if no output file specified
        print("\n── Top 10 Most Suspicious Flows ──")
        cols = ["anomaly_rank", "anomaly_score", "is_anomaly"] + [
            c for c in df.columns 
            if c not in {"anomaly_rank", "anomaly_score", "is_anomaly"}
        ][:6]
        print(df[cols].head(10).to_string(index=False))


# Evaluate model performance on labeled test data.
# Compare the global federated model against individual local models.
def cmd_evaluate(args):
    import glob
    import pandas as pd
    from src.features import load_flows, get_labels
    from src.detect import detect, detect_local
    from src.evaluate import compute_metrics, compare_setups, plot_confusion_matrix, plot_comparison_bar
    
    os.makedirs(args.out, exist_ok=True)
    
    # Load test data
    df_test = load_flows(args.data)
    y_true = get_labels(df_test)
    
    if y_true is None:
        print("[-] Error: Test file must contain a 'label' column for evaluation.")
        sys.exit(1)
    
    results = []
    
    # Evaluate the main federated model
    print("\nEvaluating Federated (Global) Model...")
    df_fed = detect(args.model, args.data, threshold=args.threshold, verbose=True)
    y_pred_fed = df_fed["is_anomaly"].astype(int).values
    scores_fed = df_fed["anomaly_score"].values
    
    r_fed = compute_metrics(y_true, y_pred_fed, scores_fed, label="Federated")
    results.append(r_fed)
    
    plot_confusion_matrix(r_fed["confusion_matrix"], "Federated",
                          os.path.join(args.out, "cm_federated.png"))
    
    # Evaluate local models if the user provided them
    if args.local_models:
        print("Evaluating Local Client Models...")
        local_paths = sorted(glob.glob(args.local_models))
        for lp in local_paths:
            cid = os.path.splitext(os.path.basename(lp))[0]
            print(f"  -> {cid}")
            
            df_local = detect_local(lp, args.data, threshold=args.threshold, verbose=False)
            y_pred_local = df_local["is_anomaly"].astype(int).values
            scores_local = df_local["anomaly_score"].values
            
            r_local = compute_metrics(y_true, y_pred_local, scores_local, label=f"Local:{cid}")
            results.append(r_local)
            
            plot_confusion_matrix(r_local["confusion_matrix"], cid,
                                  os.path.join(args.out, f"cm_{cid}.png"))
    
    # Save summary table
    summary = compare_setups(results)
    summary.to_csv(os.path.join(args.out, "evaluation_summary.csv"), index=False)
    
    print("\n── Evaluation Summary ──")
    print(summary[["label", "accuracy", "precision", "recall", "f1"]].to_string(index=False))
    print(f"\n[!] All evaluation results saved to folder: {args.out}")
    
    # Generate comparison charts
    plot_comparison_bar(results, metric="f1", 
                        out_path=os.path.join(args.out, "f1_comparison.png"))
    plot_comparison_bar(results, metric="recall", 
                        out_path=os.path.join(args.out, "recall_comparison.png"))


# Run a Federated Learning simulation with several rounds from a config file
def cmd_simulate_fl(args):
    try:
        import yaml
    except ImportError:
        print("[!] PyYAML is required for simulation.")
        print("    Install with: pip install pyyaml")
        sys.exit(1)
    
    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    
    from src.federated import simulate_fl_rounds
    
    round_results = simulate_fl_rounds(
        client_data_paths=cfg["client_data"],
        client_ids=cfg["client_ids"],
        model_dir=cfg.get("model_dir", "models"),
        n_rounds=cfg.get("n_rounds", 3),
        n_estimators=cfg.get("n_estimators", 100),
    )
    
    print(f"\n[!] FL Simulation finished - {len(round_results)} rounds completed.")


# Generate fake SDN flow data for testing the pipeline
def cmd_generate_data(args):
    from scripts.generate_data import generate_all_clients
    
    generate_all_clients(
        out_dir=args.out_dir,
        n_clients=args.n_clients,
        n_benign=args.n_benign,
        n_attack=args.n_attack,
        seed=args.seed,
    )
    
    print(f"\n[!] Synthetic data generated in: {args.out_dir}")
    print(f"    Created {args.n_clients} client datasets.")



# Argument Parser Setup
# Build and configure the argument parser for all subcommands
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sdnfl",
        description="SDN Federated Anomaly Detection CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See the project README for more details and examples."
    )
    
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # Train local model
    p = sub.add_parser("train-local", help="Train local anomaly model on one client")
    p.add_argument("--data", required=True, help="Input CSV file with flow data")
    p.add_argument("--out", required=True, help="Where to save the trained model (.pkl)")
    p.add_argument("--client-id", default=None, help="Client identifier (optional)")
    p.add_argument("--n-estimators", type=int, default=100, help="Number of trees in Isolation Forest")
    p.add_argument("--contamination", default="auto", help="Expected anomaly rate (auto or float)")

    # Federated aggregation
    p = sub.add_parser("federated-aggregate", help="Create global model from local models")
    p.add_argument("--models", required=True, help="Glob pattern, e.g. models/client*.pkl")
    p.add_argument("--out", required=True, help="Output path for global model")
    p.add_argument("--strategy", default="score_ensemble", 
                   choices=["score_ensemble", "threshold_consensus"],
                   help="How to combine the models")

    # Detection
    p = sub.add_parser("detect", help="Detect anomalies in new flow data")
    p.add_argument("--model", required=True, help="Path to trained model")
    p.add_argument("--data", required=True, help="CSV file to analyze")
    p.add_argument("--threshold", type=float, default=None, help="Manual threshold override")
    p.add_argument("--top-n", type=int, default=None, help="Show top N anomalies")
    p.add_argument("--out", default=None, help="Save results to CSV")

    # Evaluation
    p = sub.add_parser("evaluate", help="Evaluate model(s) on labeled test data")
    p.add_argument("--model", required=True, help="Global model to evaluate")
    p.add_argument("--data", required=True, help="Labeled test dataset")
    p.add_argument("--local-models", default=None, help="Glob for local models to compare")
    p.add_argument("--threshold", type=float, default=None)
    p.add_argument("--out", default="results/", help="Output directory")

    # Simulation
    p = sub.add_parser("simulate-fl", help="Run multi-round federated learning simulation")
    p.add_argument("--config", required=True, help="YAML configuration file")

    # Data generation
    p = sub.add_parser("generate-data", help="Generate synthetic training data")
    p.add_argument("--out-dir", default="data/", help="Output folder")
    p.add_argument("--n-clients", type=int, default=3)
    p.add_argument("--n-benign", type=int, default=2000)
    p.add_argument("--n-attack", type=int, default=400)
    p.add_argument("--seed", type=int, default=42)

    return parser


# main function 
def main():
    parser = build_parser()
    args = parser.parse_args()
    
    # Dispatch to the right function based on command
    dispatch = {
        "train-local": cmd_train_local,
        "federated-aggregate": cmd_federated_aggregate,
        "detect": cmd_detect,
        "evaluate": cmd_evaluate,
        "simulate-fl": cmd_simulate_fl,
        "generate-data": cmd_generate_data,
    }
    
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
