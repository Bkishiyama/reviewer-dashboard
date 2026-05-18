#!/usr/bin/env python3
"""
features.py — SDN Flow Log Feature Extraction

This file is responsible for loading raw SDN flow data from CSV files 
and turning it into clean numeric features for our models to use.
- Loads and cleans the data
- Encodes categorical fields (like protocol)
- Creates derived features (bytes per packet, packet rate)
- Normalizes numeric values using StandardScaler
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Column groups used throughout the preprocessing
NUMERIC_COLS = ["bytes", "packets", "duration", "src_port", "dst_port"]
CATEGORICAL_COLS = ["protocol"]
LABEL_COL = "label"   # Use during evaluation but not training

# Port binning: well known (0-1023), registered (1024-49151), dynamic (49152+)
PORT_BINS = [0, 1024, 49152, 65536]
PORT_LABELS = [0, 1, 2]

# Simple protocol encoding
PROTOCOL_MAP = {
    "tcp": 0,
    "udp": 1,
    "icmp": 2,
    "other": 3,
}


# Load raw flow data from CSV
# Load a CSV file containing SDN flow logs
def load_flows(path: str) -> pd.DataFrame:
    # Read CSV flow data and clean up column names
    df = pd.read_csv(path, low_memory=False)
    
    # Standardize column names (lowercase, no spaces)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    
    return df


# Main preprocessing function
# Convert raw dataframe into numeric features ready for the model
def preprocess(df: pd.DataFrame, scaler: StandardScaler = None):
    # Main function that transforms raw flows into model-ready features
    df = df.copy()

    # Numeric Features
    numeric_data = {}
    
    for col in ["bytes", "packets", "duration"]:
        numeric_data[col] = pd.to_numeric(
            df.get(col, pd.Series([0] * len(df))), 
            errors="coerce"
        ).fillna(0).clip(lower=0)

    # Create some useful derived features
    numeric_data["bytes_per_packet"] = np.where(
        numeric_data["packets"] > 0,
        numeric_data["bytes"] / numeric_data["packets"],
        0
    )
    
    numeric_data["packet_rate"] = np.where(
        numeric_data["duration"] > 0,
        numeric_data["packets"] / numeric_data["duration"],
        0
    )

    num_df = pd.DataFrame(numeric_data)

    # Protocol Encoding
    if "protocol" in df.columns:
        proto = df["protocol"].astype(str).str.strip().str.lower()
        num_df["protocol_enc"] = proto.map(PROTOCOL_MAP).fillna(PROTOCOL_MAP["other"])
    else:
        num_df["protocol_enc"] = PROTOCOL_MAP["other"]

    # Port Binning
    for port_col in ["src_port", "dst_port"]:
        if port_col in df.columns:
            ports = pd.to_numeric(df[port_col], errors="coerce").fillna(0).clip(0, 65535)
            num_df[f"{port_col}_bin"] = pd.cut(
                ports, bins=PORT_BINS, labels=PORT_LABELS, right=False
            ).astype(float).fillna(2)
        else:
            num_df[f"{port_col}_bin"] = 2  # default to dynamic ports

    # Scalin
    feature_names = list(num_df.columns)
    X = num_df.values.astype(np.float32)

    if scaler is None:
        # Fit a new scaler (training time)
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
    else:
        # Use existing scaler (detection / evaluation time)
        X = scaler.transform(X)

    return X, scaler, feature_names


# Extract ground truth labels (for evaluation only)
# Get true labels if they exist in the dataset (used only for evaluation)
def get_labels(df: pd.DataFrame) -> np.ndarray | None:
    # Return ground-truth labels if the 'label' column exists
    if LABEL_COL not in df.columns:
        return None

    raw = df[LABEL_COL].astype(str).str.strip().str.lower()
    
    # Support multiple ways of labeling
    label_map = {
        "0": 0, "benign": 0, "normal": 0,
        "1": 1, "attack": 1, "anomaly": 1, "malicious": 1,
    }
    
    return raw.map(label_map).fillna(1).astype(int).values