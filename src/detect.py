#!/usr/bin/env python3
"""
detect.py — Anomaly Detection Engine

This file handles scoring new SDN flow data using our trained models.
It can work with:
- The global federated model (recommended)
- Individual local client models (for comparison)

Each flow gets these extra columns:
- anomaly_score: lower = more suspicious
- is_anomaly: True/False based on threshold
- anomaly_rank: 1 is the most anomalous flow
"""

import joblib
import numpy as np
import pandas as pd

from .features import load_flows, preprocess
from .federated import federated_score_ensemble

# Main detection function for the global federated model
# Score SDN flows using the global federated model (or a local model)
def detect(
    model_path: str,
    data_path: str,
    threshold: float | None = None,
    top_n: int | None = None,
    verbose: bool = True,
) -> pd.DataFrame:
    #main function used by cli.py to detect anomalies.
    if verbose:
        print(f"[Detect] Loading model from : {model_path}")
        print(f"[Detect] Scoring flows from : {data_path}")

    # Load the saved model bundle
    bundle = joblib.load(model_path)
    df = load_flows(data_path)

    # Check if this is a global federated bundle or single local model
    if "clients" in bundle:
        # This is the global federated model
        client_models = bundle["clients"]
        X_for_global, _, _ = preprocess(df, scaler=None)
        
        # Use special ensemble scoring across all client models
        scores = federated_score_ensemble(client_models, X_for_global)
        consensus_threshold = bundle.get("global_threshold", -0.5)
        model_type = "federated"
        
        if verbose:
            print(f"[Detect] Using global federated model with {len(client_models)} clients")
    else:
        # This is a single local client model
        X, _, _ = preprocess(df, scaler=bundle["scaler"])
        scores = bundle["model"].score_samples(X)
        consensus_threshold = bundle["score_stats"]["p5"]
        model_type = "local"
        
        if verbose:
            print("[Detect] Using single local model")

    # Decide which threshold to use
    if threshold is None:
        threshold = consensus_threshold
        if verbose:
            print(f"[Detect] Using {model_type} consensus threshold: {threshold:.4f}")
    else:
        if verbose:
            print(f"[Detect] Using user override threshold: {threshold:.4f}")

    # Flag flows as anomalous
    anomalies = scores < threshold

    # Add results back to the original dataframe
    df = df.copy()
    df["anomaly_score"] = scores
    df["is_anomaly"] = anomalies
    # Rank anomalies (1 = most anomalous)
    df["anomaly_rank"] = pd.Series(scores).rank(ascending=True).astype(int).values

    n_flagged = int(anomalies.sum())
    n_total = len(df)

    if verbose:
        print(f"[Detect] ✓ Flagged {n_flagged:,} / {n_total:,} flows as anomalous "
              f"({100*n_flagged/max(n_total,1):.1f}%)")

    # Show top suspicious flows if requested
    if top_n:
        print(f"\n[Detect] Top {top_n} most anomalous flows:")
        cols = ["anomaly_rank", "anomaly_score"] + [
            c for c in ["src_ip", "dst_ip", "src_port", "dst_port",
                        "protocol", "bytes", "packets", "duration"]
            if c in df.columns
        ]
        print(df.nsmallest(top_n, "anomaly_score")[cols].to_string(index=False))

    return df



# Helper function for evaluating a single local client model
# Score flows using only one local client's model (used for comparison)
def detect_local(
    model_path: str,
    data_path: str,
    threshold: float | None = None,
    verbose: bool = True,
) -> pd.DataFrame:
    #Used during evaluation to test individual client models.
    if verbose:
        print(f"[DetectLocal] Loading local model: {model_path}")

    bundle = joblib.load(model_path)
    df = load_flows(data_path)

    # Preprocess using this client's own scaler
    X, _, _ = preprocess(df, scaler=bundle["scaler"])
    scores = bundle["model"].score_samples(X)

    # Use provided threshold or the model's default
    t = threshold if threshold is not None else bundle["score_stats"]["p5"]

    df = df.copy()
    df["anomaly_score"] = scores
    df["is_anomaly"] = scores < t
    df["anomaly_rank"] = pd.Series(scores).rank(ascending=True).astype(int).values

    n_flagged = int((scores < t).sum())

    if verbose:
        print(f"[DetectLocal] Flagged {n_flagged:,} / {len(df):,} flows "
              f"(threshold={t:.4f})")

    return df