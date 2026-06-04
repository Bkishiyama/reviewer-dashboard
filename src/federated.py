from __future__ import annotations

#!/usr/bin/env python3
"""
federated.py

This file handles the Federated Learning setup for SDN anomaly detection.
Since we can't directly average Isolation Forest trees:
1. Score Ensemble (default) -> average scores from all clients
2. Threshold Consensus -> average the anomaly thresholds from each client

Tool 2 extends this file with:
- Byzantine-robust Z-score sanitization before aggregation
- Poisoned client injection for attack simulation
- Per-round sanitization audit logged to CSV
"""

import glob
import os
import csv
import joblib
import numpy as np
from typing import Optional

# Tool 2: import sanitizer
from src.sanitizer import aggregate_with_sanitizer, SanitizationReport


# Load multiple client model files using a glob pattern
def load_client_models(pattern: str):
    paths = sorted(glob.glob(pattern))
    if not paths:
        raise FileNotFoundError(f"No client models found matching: {pattern}")
    
    models = [joblib.load(p) for p in paths]
    
    print(f"[FedAgg] Loaded {len(models)} client model(s)")
    client_names = [m.get('meta', {}).get('client_id', 'unknown') for m in models]
    print(f"         Clients: {client_names}")
    
    return models, paths



# Scoring strategies


# Strategy A: Average anomaly scores from all client models
def federated_score_ensemble(
    client_models: list[dict],
    X_raw: np.ndarray,
) -> np.ndarray:
    # Combine predictions by averaging scores from every client model.
    all_scores = []
    
    for bundle in client_models:
        # Each client uses its own scaler (important for federated setup)
        X_scaled = bundle["scaler"].transform(X_raw)
        scores = bundle["model"].score_samples(X_scaled)
        all_scores.append(scores)
    
    # Average across all clients
    stacked = np.vstack(all_scores)
    return stacked.mean(axis=0)


# Strategy B: Average the anomaly thresholds from each client
# Create a global threshold by averaging each client's local threshold.
def federated_threshold_consensus(client_models: list[dict]) -> float:
    p5_values = [m["score_stats"]["p5"] for m in client_models]
    
    global_threshold = float(np.mean(p5_values))
    
    print(f"[FedAgg] Client p5 thresholds: {[round(v, 4) for v in p5_values]}")
    print(f"[FedAgg] Global consensus threshold: {global_threshold:.4f}")
    
    return global_threshold



# Aggregate and save global model


# Combine client models into a single global bundle and save it
def aggregate_and_save(
    client_models: list[dict],
    out_path: str,
    strategy: str = "score_ensemble",
):
    # Create and save the global federated model bundle
    global_threshold = federated_threshold_consensus(client_models)
    
    global_bundle = {
        "clients": client_models,                    # Keep all client models
        "n_clients": len(client_models),
        "strategy": strategy,
        "global_threshold": global_threshold,
        "client_ids": [m["meta"]["client_id"] for m in client_models],
        "features": client_models[0]["features"],    # Assume all have same features
    }
    
    # Make sure output directory exists
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    joblib.dump(global_bundle, out_path)
    
    print(f"\n[!] Global federated model saved to: {out_path}")
    print(f"Strategy used : {strategy}")
    print(f"Clients included: {global_bundle['client_ids']}")
    
    return global_bundle


# Tool 2: extract a scalar metric from a saved model bundle
def _model_bundle_to_scalar(bundle: dict) -> float:
    """
    Convert a saved local model bundle to a single representative scalar
    suitable for Z-score comparison. Uses the p5 threshold as the metric
    since it is the value most vulnerable to poisoning.
    """
    # Use p5 threshold as the primary metric for sanitization
    score_stats = bundle.get("score_stats", {})
    p5 = score_stats.get("p5")
    if p5 is not None:
        return abs(float(p5))   # use absolute value
    return 0.0


# Simulate multi-round Federated Learning
# Tool 2 extends this with sanitize, z_threshold, poisoned_clients, and log_path
def simulate_fl_rounds(
    client_data_paths: list[str],
    client_ids: list[str],
    model_dir: str,
    n_rounds: int = 3,
    n_estimators: int = 100,
    sanitize: bool = True,
    z_threshold: Optional[float] = None,
    poisoned_clients: Optional[dict] = None,
    log_path: str = "results/sanitizer_log.csv",
):
    # Simulate multiple rounds of federated learning for testing
    from src.local_train import train_local   # Import here to avoid circular imports

    os.makedirs(model_dir, exist_ok=True)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    round_results = []
    log_rows = []

    for r in range(1, n_rounds + 1):
        print(f"\n{'+-'*20}")
        print(f"FEDERATED LEARNING ROUND {r}/{n_rounds}")
        print(f"{'+-'*20}")

        round_model_paths = []

        # Each client trains locally (Tool 1 behaviour — unchanged)
        for path, cid in zip(client_data_paths, client_ids):
            out = os.path.join(model_dir, f"round{r}_{cid}.pkl")

            train_local(
                data_path=path,
                model_path=out,
                client_id=cid,
                n_estimators=n_estimators,
            )
            round_model_paths.append(out)

        # Load all client bundles for this round
        models, _ = load_client_models(
            os.path.join(model_dir, f"round{r}_*.pkl")
        )

        # Map client_id to bundle
        client_bundles = {}
        for bundle in models:
            cid = bundle.get("meta", {}).get("client_id", "unknown")
            client_bundles[cid] = bundle

        # Collect scalar metrics for each client
        client_metrics = {
            cid: _model_bundle_to_scalar(bundle)
            for cid, bundle in client_bundles.items()
        }

        # Tool 2: inject poisoned uploads if specified
        if poisoned_clients:
            for victim_id, multiplier in poisoned_clients.items():
                if victim_id in client_metrics:
                    original = client_metrics[victim_id]
                    client_metrics[victim_id] = original * multiplier
                    print(
                        f"\n[ATTACK SIMULATION] Host {victim_id} uploaded POISONED metric: "
                        f"{original:.4f} x {multiplier} = {client_metrics[victim_id]:.4f}"
                    )

        # Tool 2: sanitize before aggregation or use naive FedAvg
        san_report: Optional[SanitizationReport] = None

        if sanitize:
            # Byzantine-robust aggregation
            global_threshold, san_report = aggregate_with_sanitizer(
                client_metrics, z_threshold=z_threshold
            )
            for line in san_report.summary_lines():
                print(line)
        else:
            # Tool 1 naive FedAvg — simple mean, no defense
            global_threshold = sum(client_metrics.values()) / len(client_metrics)
            print(f"[FedAgg] Sanitizer DISABLED — naive FedAvg applied")
            print(f"[FedAgg] Global threshold: {global_threshold:.4f}")

        # Save global model bundle for this round
        global_out = os.path.join(model_dir, f"round{r}_global.pkl")
        global_bundle = {
            "global_threshold": global_threshold,
            "round": r,
            "client_ids": list(client_bundles.keys()),
            "strategy": "score_ensemble",
        }
        joblib.dump(global_bundle, global_out)

        # Build round result dict
        result = {
            "round": r,
            "global_threshold": global_threshold,
            "sanitization_report": san_report,
            "accepted_clients": san_report.accepted_hosts if san_report else list(client_bundles.keys()),
            "rejected_clients": san_report.rejected_hosts if san_report else [],
        }
        round_results.append(result)

        # Accumulate CSV log rows
        if san_report:
            for hr in san_report.host_reports:
                log_rows.append({
                    "round": r,
                    "host": hr.host_id,
                    "value": f"{hr.value:.6f}",
                    "z_score": f"{hr.z_score:.4f}",
                    "accepted": hr.accepted,
                    "reason": hr.reason,
                    "global_threshold": f"{global_threshold:.6f}",
                    "poisoning_detected": san_report.poisoning_detected,
                })

    # Write sanitizer audit log
    if log_rows:
        with open(log_path, "w", newline="") as csvfile:
            fieldnames = [
                "round", "host", "value", "z_score",
                "accepted", "reason", "global_threshold", "poisoning_detected",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(log_rows)
        print(f"\n[!] Sanitizer audit log saved to: {log_path}")

    print("\n[->] FL Simulation Complete")
    for rr in round_results:
        print(f" Round {rr['round']}: Global threshold = {rr['global_threshold']:.4f}")

    return round_results
