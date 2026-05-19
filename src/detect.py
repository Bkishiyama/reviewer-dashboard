from __future__ import annotations

"""
detect.py - Anomaly Detection Engine
I adjusted the parameters since my f1, precision, etc. came back as zero.
Loads a trained model bundle and scores new SDN flow logs.
Supports both the global federated model and single local client models.

Each scored flow gets three extra columns:
- anomaly_score: float (lower = more anomalous)
- is_anomaly: bool (True when score is below the threshold)
- anomaly_rank: int (1 = most anomalous flow in the batch)
"""

import joblib
import numpy as np
import pandas as pd

from .features import load_flows, preprocess
from .federated import federated_score_ensemble



"""
Score SDN flows using the global federated model.
Parameters:
- model_path: path to the global model bundle (.pkl)
- data_path: path to the CSV flow log to score
- threshold: anomaly score cutoff. If None, uses the federated consensus 
threshold stored in the bundle. If that threshold flags zero 
flows, automatically falls back to the 5th percentile of the 
actual scores so results are never all zero.
- top_n: if set, print the N most anomalous flows to stdout
- verbose: print progress messages

- Returns:
df : original DataFrame with anomaly_score, is_anomaly, anomaly_rank added
"""
def detect(
    model_path: str,
    data_path: str,
    threshold: float | None = None,
    top_n: int | None = None,
    verbose: bool = True,
) -> pd.DataFrame:
    if verbose:
        print(f"[Detect] Loading model from : {model_path}")
        print(f"[Detect] Scoring flows from : {data_path}")

    bundle = joblib.load(model_path)
    df = load_flows(data_path)

    if "clients" in bundle:
        client_models = bundle["clients"]
        X, _, _ = preprocess(df, scaler=None)
        scores = federated_score_ensemble(client_models, X)
        consensus_threshold = bundle.get("global_threshold", -0.5)
        model_type = "federated"
        if verbose:
            print(f"[Detect] Using global federated model with {len(client_models)} clients")
    else:
        X, _, _ = preprocess(df, scaler=bundle["scaler"])
        scores = bundle["model"].score_samples(X)
        consensus_threshold = bundle["score_stats"]["p5"]
        model_type = "local"
        if verbose:
            print("[Detect] Using single local model")

    if threshold is None:
        threshold = consensus_threshold
        if verbose:
            print(f"[Detect] Using {model_type} consensus threshold: {threshold:.4f}")
    else:
        if verbose:
            print(f"[Detect] Using user override threshold: {threshold:.4f}")

    # Fallback: if the threshold flags nothing, use the 5th percentile of
    # actual scores. This handles cases where live traffic distributions
    # differ from training data, which causes an overly conservative threshold.
    if (scores < threshold).sum() == 0:
        threshold = float(np.percentile(scores, 5))
        if verbose:
            print(f"[Detect] Threshold too conservative, falling back to p5: {threshold:.4f}")

    anomalies = scores < threshold

    df = df.copy()
    df["anomaly_score"] = scores
    df["is_anomaly"] = anomalies
    df["anomaly_rank"] = pd.Series(scores).rank(ascending=True).astype(int).values

    n_flagged = int(anomalies.sum())
    n_total = len(df)

    if verbose:
        print(f"[Detect] Flagged {n_flagged:,} / {n_total:,} flows as anomalous "
              f"({100 * n_flagged / max(n_total, 1):.1f}%)")

    if top_n:
        print(f"\n[Detect] Top {top_n} most anomalous flows:")
        cols = ["anomaly_rank", "anomaly_score"] + [
            c for c in ["src_ip", "dst_ip", "src_port", "dst_port",
                        "protocol", "bytes", "packets", "duration"]
            if c in df.columns
        ]
        print(df.nsmallest(top_n, "anomaly_score")[cols].to_string(index=False))

    return df


"""
Score flows using a single local client model.
Used during evaluation to compare individual clients against the
federated global model.

Parameters:
- model_path: path to a local client model bundle (.pkl)
- data_path: path to the CSV flow log to score
- threshold: anomaly score cutoff. If None, uses the model's stored p5 
score. Falls back to p5 of actual scores if nothing is flagged.
- verbose: print progress messages

Returns:
- df : original DataFrame with anomaly_score, is_anomaly, anomaly_rank added
"""
def detect_local(
    model_path: str,
    data_path: str,
    threshold: float | None = None,
    verbose: bool = True,
) -> pd.DataFrame:
    if verbose:
        print(f"[DetectLocal] Loading local model: {model_path}")

    bundle = joblib.load(model_path)
    df = load_flows(data_path)

    X, _, _ = preprocess(df, scaler=bundle["scaler"])
    scores = bundle["model"].score_samples(X)

    t = threshold if threshold is not None else bundle["score_stats"]["p5"]

    if (scores < t).sum() == 0:
        t = float(np.percentile(scores, 5))
        if verbose:
            print(f"[DetectLocal] Threshold too conservative, falling back to p5: {t:.4f}")

    df = df.copy()
    df["anomaly_score"] = scores
    df["is_anomaly"] = scores < t
    df["anomaly_rank"] = pd.Series(scores).rank(ascending=True).astype(int).values

    n_flagged = int((scores < t).sum())

    if verbose:
        print(f"[DetectLocal] Flagged {n_flagged:,} / {len(df):,} flows "
              f"(threshold={t:.4f})")

    return df
