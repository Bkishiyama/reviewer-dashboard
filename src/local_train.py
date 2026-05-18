#!/usr/bin/env python3
"""
local_train.py Local Model Training for Each Client

This script trains an Isolation Forest model on a single client's 
SDN flow data. Each client trains independently.

The model learns what normal traffic looks like without using labels.
We save the model + scaler + stats so it can be used later in the 
federated aggregation step.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .features import load_flows, preprocess


# Train a local Isolation Forest model on one client's data
def train_local(
    data_path: str,
    model_path: str,
    client_id: str = "unknown",
    n_estimators: int = 100,
    contamination: float | str = "auto",
    random_state: int = 42,
    verbose: bool = True,
) -> dict:
    # Train and save a local anomaly detection model for one client
    if verbose:
        print(f"[{client_id}] Loading flows from: {data_path}")

    # Load and preprocess the data
    df = load_flows(data_path)
    X, scaler, feature_names = preprocess(df)
    
    n_samples, n_features = X.shape

    if verbose:
        print(f"[{client_id}] Training on {n_samples:,} samples with {n_features} features")

    # Train the Isolation Forest model
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,   # Use all available CPU cores
    )
    model.fit(X)

    # Calculate score statistics for later threshold setting
    scores = model.score_samples(X)
    score_stats = {
        "mean": float(np.mean(scores)),
        "std": float(np.std(scores)),
        "p5": float(np.percentile(scores, 5)), # 5th percentile used as default threshold
        "p1": float(np.percentile(scores, 1)),
    }

    # Bundle these and save
    bundle = {
        "model": model,
        "scaler": scaler,
        "features": feature_names,
        "score_stats": score_stats,
        "meta": {
            "client_id": client_id,
            "n_samples": n_samples,
            "n_features": n_features,
            "n_estimators": n_estimators,
            "contamination": contamination,
        },
    }

    # Save the bundle
    os.makedirs(os.path.dirname(model_path) or ".", exist_ok=True)
    joblib.dump(bundle, model_path)

    if verbose:
        print(f"[{client_id}] ✓ Model saved to: {model_path}")
        print(f"[{client_id}] Score stats → mean={score_stats['mean']:.4f}, "
              f"p5={score_stats['p5']:.4f} (used as threshold)")

    return bundle["meta"]