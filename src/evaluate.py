#!/usr/bin/env python3
"""
evaluate.py — Model Evaluation Script

This file compares our anomaly detection predictions against 
ground-truth labels (used only for testing; never during training).

Calculate metrics like Accuracy, Precision, Recall, and F1.
Generate confusion matrices and comparison chart.
"""

import os
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    roc_auc_score,
    f1_score,
    precision_score,
    recall_score,
)

# Import plotting libraries
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    _PLOTTING = True
except ImportError:
    _PLOTTING = False
    print("[Warning] matplotlib/seaborn not installed. Plots will be skipped.")



# Compute metrics
# Calculate accuracy, precision, recall, F1.
def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    scores: np.ndarray | None = None,
    label: str = "model",
    verbose: bool = True,
) -> dict:
    # Compute all evaluation metrics for model setup.
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

    result = {
        "label": label,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "confusion_matrix": cm,
    }

    # Calculate ROC-AUC if we have anomaly scores
    if scores is not None:
        try:
            # Negate scores because lower is more anomalous in Isolation Forest
            auc = roc_auc_score(y_true, -scores)
            result["roc_auc"] = round(auc, 4)
        except ValueError:
            result["roc_auc"] = None

    if verbose:
        _print_report(result)

    return result



# Compare multiple models
# Create a summary table of different models
def compare_setups(results: list[dict]) -> pd.DataFrame:
    # Turn metric dictionaries into comparison table.
    rows = []
    for r in results:
        # Remove confusion matrix for the table
        row = {k: v for k, v in r.items() if k != "confusion_matrix"}
        rows.append(row)
    
    return pd.DataFrame(rows)



# Plot and save a confusion matrix heatmap
def plot_confusion_matrix(
    cm: np.ndarray,
    label: str = "model",
    out_path: str | None = None,
):
    # Create confusion matrix visualization.
    if not _PLOTTING:
        print("[Eval] Skipping plot - matplotlib not available.")
        return

    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Pred Benign", "Pred Anomaly"],
        yticklabels=["True Benign", "True Anomaly"],
        ax=ax,
    )
    
    ax.set_title(f"Confusion Matrix — {label}")
    ax.set_ylabel("Actual")
    ax.set_xlabel("Predicted")
    
    plt.tight_layout()
    
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        fig.savefig(out_path, dpi=150)
        print(f"[Eval] Saved confusion matrix → {out_path}")
    else:
        plt.show()
    
    plt.close(fig)


# Create bar chart to compare metrics across models
def plot_comparison_bar(
    results: list[dict],
    metric: str = "f1",
    out_path: str | None = None,
):
    # Make a bar chart comparing models
    if not _PLOTTING:
        return

    labels = [r["label"] for r in results]
    values = [r.get(metric, 0) for r in results]

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(labels, values, color=["#4C72B0", "#DD8452", "#55A868"])
    
    ax.set_ylim(0, 1.05)
    ax.set_ylabel(metric.upper())
    ax.set_title(f"{metric.upper()} Comparison: Local vs Federated")
    
    # Add value labels on top of bars
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, val + 0.01,
                f"{val:.3f}", ha="center", va="bottom", fontsize=10)

    plt.tight_layout()
    
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        fig.savefig(out_path, dpi=150)
        print(f"[Eval] Saved {metric} comparison chart → {out_path}")
    else:
        plt.show()
    
    plt.close(fig)


# Pretty print the results
def _print_report(r: dict):
    """Internal function to print formatted evaluation results."""
    cm = r["confusion_matrix"]
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    
    sep = "─" * 42
    print(f"\n{sep}")
    print(f" Results: {r['label']}")
    print(sep)
    print(f" Accuracy  : {r['accuracy']:.4f}")
    print(f" Precision : {r['precision']:.4f}")
    print(f" Recall    : {r['recall']:.4f}")
    print(f" F1 Score  : {r['f1']:.4f}")
    
    if "roc_auc" in r and r["roc_auc"] is not None:
        print(f" ROC-AUC   : {r['roc_auc']:.4f}")
    
    print(f" Confusion Matrix:")
    print(f"   TN={tn:4d}   FP={fp:4d}")
    print(f"   FN={fn:4d}   TP={tp:4d}")
    print(sep)