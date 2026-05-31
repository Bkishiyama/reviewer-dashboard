from __future__ import annotations
#!/usr/bin/env python3
"""
scripts/generate_data.py -> Synthetic SDN Flow Log Generator

This script creates fake but realistic SDN flow data for testing our 
FL anomaly detection system.

It generates:
- Normal (benign) traffic
- Different types of attacks (DDoS, port scans, flow table exhaustion)
  
Each client gets slightly different attack patterns to simulate 
real-world non-IID data in federated learning.
"""

from __future__ import annotations
import os
import numpy as np
import pandas as pd

# Create normal, realistic, benign traffic (HTTP, HTTPS, DNS, etc.)
def _benign_flows(n: int, rng: np.random.Generator, client_idx: int = 0) -> pd.DataFrame:
    # Mix of common protocols
    protocol_choices = rng.choice(["tcp", "udp", "tcp"], size=n, p=[0.6, 0.25, 0.15])
    dst_ports = rng.choice([80, 443, 53, 8080, 22, 3306], size=n, 
                          p=[0.3, 0.3, 0.2, 0.1, 0.05, 0.05])
    
    src_ports = rng.integers(1024, 65535, size=n)
    
    # Slight variation per client
    byte_scale = 1.0 + client_idx * 0.15
    
    rows = {
        "src_ip": [f"10.{client_idx}.{rng.integers(0,255)}.{rng.integers(1,254)}"
                   for _ in range(n)],
        "dst_ip": [f"192.168.{rng.integers(0,10)}.{rng.integers(1,254)}"
                   for _ in range(n)],
        "src_port": src_ports,
        "dst_port": dst_ports,
        "protocol": protocol_choices,
        "bytes": (rng.lognormal(mean=8.5, sigma=1.2, size=n) * byte_scale)
                  .clip(64, 65536).astype(int),
        "packets": rng.integers(1, 50, size=n),
        "duration": rng.exponential(scale=2.5, size=n).clip(0.01, 120),
        "flags": rng.choice(["ACK", "SYN", "PSH+ACK", "FIN+ACK", "SYN+ACK"], 
                           size=n, p=[0.5, 0.2, 0.15, 0.1, 0.05]),
        "label": np.zeros(n, dtype=int),   # 0 = benign
    }
    return pd.DataFrame(rows)


# Simulate DDoS attack, i.e., like traffic: high volume, short duration.
def _ddos_flows(n: int, rng: np.random.Generator) -> pd.DataFrame:
    rows = {
        "src_ip": [f"172.{rng.integers(16,32)}.{rng.integers(0,255)}.{rng.integers(1,254)}"
                   for _ in range(n)],
        "dst_ip": [f"192.168.1.{rng.integers(1,5)}" for _ in range(n)],  # few targets
        "src_port": rng.integers(1024, 65535, size=n),
        "dst_port": rng.choice([80, 443, 53], size=n),
        "protocol": rng.choice(["tcp", "udp"], size=n, p=[0.5, 0.5]),
        "bytes": rng.integers(40_000, 1_500_000, size=n),
        "packets": rng.integers(500, 5000, size=n),
        "duration": rng.uniform(0.001, 0.5, size=n),   # very short
        "flags": rng.choice(["SYN", "UDP"], size=n),
        "label": np.ones(n, dtype=int),   # 1 = attack
    }
    return pd.DataFrame(rows)


# Simulate port scan traffic -> many different destination ports
def _port_scan_flows(n: int, rng: np.random.Generator) -> pd.DataFrame:
    rows = {
        "src_ip": [f"10.99.{rng.integers(0,5)}.{rng.integers(1,10)}" for _ in range(n)],
        "dst_ip": [f"192.168.0.{rng.integers(1,50)}" for _ in range(n)],
        "src_port": rng.integers(1024, 65535, size=n),
        "dst_port": rng.integers(1, 65535, size=n),   # scanning many ports
        "protocol": ["tcp"] * n,
        "bytes": rng.integers(40, 120, size=n),
        "packets": np.ones(n, dtype=int),
        "duration": rng.uniform(0.0001, 0.05, size=n),
        "flags": ["SYN"] * n,
        "label": np.ones(n, dtype=int),
    }
    return pd.DataFrame(rows)


# Simulate flow table exhaustion attack; many short lived random flows
def _flow_table_exhaustion(n: int, rng: np.random.Generator) -> pd.DataFrame:
    rows = {
        "src_ip": [f"{rng.integers(1,223)}.{rng.integers(0,255)}."
                   f"{rng.integers(0,255)}.{rng.integers(1,254)}" for _ in range(n)],
        "dst_ip": [f"192.168.{rng.integers(0,5)}.1" for _ in range(n)],
        "src_port": rng.integers(1024, 65535, size=n),
        "dst_port": rng.integers(1, 65535, size=n),
        "protocol": rng.choice(["tcp", "udp", "icmp"], size=n),
        "bytes": rng.integers(40, 500, size=n),
        "packets": np.ones(n, dtype=int),
        "duration": rng.uniform(0.0001, 0.1, size=n),
        "flags": rng.choice(["SYN", "UDP", "ICMP"], size=n),
        "label": np.ones(n, dtype=int),
    }
    return pd.DataFrame(rows)


# Generate full dataset, both benign and attacks, for a single client
def generate_client_dataset(
    client_id: str,
    n_benign: int = 2000,
    n_attack: int = 400,
    seed: int = 42,
    client_idx: int = 0,
) -> pd.DataFrame:
    # Creates one client's dataset with varied attack types
    rng = np.random.default_rng(seed + client_idx * 1000)
    
    benign = _benign_flows(n_benign, rng, client_idx)
    
    # Different clients have different attack types
    attack_splits = {
        0: {"ddos": 0.7, "scan": 0.2, "fte": 0.1},
        1: {"ddos": 0.1, "scan": 0.8, "fte": 0.1},
        2: {"ddos": 0.4, "scan": 0.1, "fte": 0.5},
    }
    split = attack_splits.get(client_idx, {"ddos": 0.4, "scan": 0.3, "fte": 0.3})
    
    n_ddos = int(n_attack * split["ddos"])
    n_scan = int(n_attack * split["scan"])
    n_fte = n_attack - n_ddos - n_scan
    
    attack_frames = []
    if n_ddos > 0:
        attack_frames.append(_ddos_flows(n_ddos, rng))
    if n_scan > 0:
        attack_frames.append(_port_scan_flows(n_scan, rng))
    if n_fte > 0:
        attack_frames.append(_flow_table_exhaustion(n_fte, rng))
    
    attacks = pd.concat(attack_frames, ignore_index=True)
    
    # Combine and shuffle
    df = pd.concat([benign, attacks], ignore_index=True)
    df = df.sample(frac=1, random_state=seed + client_idx).reset_index(drop=True)
    
    return df


# Generate data for multiple clients and test sets
def generate_all_clients(
    out_dir: str = "data/",
    n_clients: int = 3,
    n_benign: int = 2000,
    n_attack: int = 400,
    seed: int = 42,
) -> list[str]:
    # Generate training data for all clients and supporting test files
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    all_test_frames = []
    
    print(f"[DataGen] Generating data for {n_clients} clients...\n")
    
    for i in range(n_clients):
        cid = f"client{i+1}"
        df = generate_client_dataset(
            client_id=cid,
            n_benign=n_benign,
            n_attack=n_attack,
            seed=seed,
            client_idx=i,
        )
        
        # Simple 80/20 split
        n_test = max(100, len(df) // 5)
        test_df = df.iloc[-n_test:].copy()
        train_df = df.iloc[:-n_test].copy()
        
        train_path = os.path.join(out_dir, f"{cid}.csv")
        train_df.to_csv(train_path, index=False)
        paths.append(train_path)
        
        all_test_frames.append(test_df)
        
        n_b = (train_df["label"] == 0).sum()
        n_a = (train_df["label"] == 1).sum()
        print(f"[DataGen] {cid}: {len(train_df):,} flows "
              f"({n_b} benign, {n_a} attack) -> {train_path}")
    
    # Combined labeled test set
    test_all = pd.concat(all_test_frames, ignore_index=True).sample(
        frac=1, random_state=seed
    ).reset_index(drop=True)
    
    test_path = os.path.join(out_dir, "test_labeled.csv")
    test_all.to_csv(test_path, index=False)
    paths.append(test_path)
    print(f"[DataGen] Combined test set: {len(test_all):,} flows -> {test_path}")
    
    # Unlabeled flows for detection demo
    rng = np.random.default_rng(seed + 9999)
    new_df = generate_client_dataset("new", n_benign=200, n_attack=50, seed=seed+1)
    new_df = new_df.drop(columns=["label"])   # remove labels
    
    new_path = os.path.join(out_dir, "new_flows.csv")
    new_df.to_csv(new_path, index=False)
    paths.append(new_path)
    print(f"[DataGen] New flows (unlabeled): {len(new_df):,} flows -> {new_path}")
    
    return paths


if __name__ == "__main__":
    # I set this to always generate 6 clients. 
    generate_all_clients(n_clients=6)
