#!/usr/bin/env python3
"""
federated.py

This file handles the Federated Learning setup for SDN anomaly detection.
Since we can't directly average Isolation Forest trees:
1. Score Ensemble (default) -> average scores from all clients
2. Threshold Consensus -> average the anomaly thresholds from each client
"""

import glob
import os
import joblib
import numpy as np


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


# Simulate multi-round Federated Learning
def simulate_fl_rounds(
    client_data_paths: list[str],
    client_ids: list[str],
    model_dir: str,
    n_rounds: int = 3,
    n_estimators: int = 100,
    verbose: bool = True,
):
    # Simulate multiple rounds of federated learning for testing
    from .local_train import train_local   # Import here to avoid circular imports
    
    round_results = []
    
    for r in range(1, n_rounds + 1):
        if verbose:
            print(f"\n{'+-'*20}")
            print(f"FEDERATED LEARNING ROUND {r}/{n_rounds}")
            print(f"{'+-'*20}")
        
        round_model_paths = []
        
        # Each client trains locally
        for path, cid in zip(client_data_paths, client_ids):
            out = os.path.join(model_dir, f"round{r}_{cid}.pkl")
            
            train_local(
                data_path=path,
                model_path=out,
                client_id=cid,
                n_estimators=n_estimators,
                verbose=verbose,
            )
            round_model_paths.append(out)
        
        # Aggregate into global model
        models, _ = load_client_models(
            os.path.join(model_dir, f"round{r}_*.pkl")
        )
        
        global_out = os.path.join(model_dir, f"round{r}_global.pkl")
        bundle = aggregate_and_save(models, global_out)
        
        round_results.append({
            "round": r,
            "global_threshold": bundle["global_threshold"],
            "client_ids": bundle["client_ids"],
            "global_model": global_out,
        })
    
    if verbose:
        print("\n[->] FL Simulation Complete")
        for rr in round_results:
            print(f" Round {rr['round']}: Global threshold = {rr['global_threshold']:.4f}")
    
    return round_results