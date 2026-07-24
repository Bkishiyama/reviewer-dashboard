from __future__ import annotations
#!/usr/bin/env python3

"""
src/hitl.py — Human-in-the-Loop Alert Engine (Tool 4)
The program sits between the anomaly detector and SDN mitigation,
requiring the user to review and approve every security action.
Responsibilities:
1. Receive detected anomalies from detect.py as Alert objects
2. Each alert gets an explanation via src/explainer.py
3. Queue alerts for user to review 
4. User will decide to BLOCK, MONITOR, or IGNORE
5. Log every decision with a timestamp for audit
Decision states:
    PENDING  -> alert is waiting for user to review
    APPROVED -> user has approved mitigation that triggers mitigator.py
    MONITOR  -> user will watch but not block
    IGNORED  -> user dismisses the alert
Usage from cli.py or dashboard/app.py:
    from src.hitl import AlertQueue, Alert, Decision
    queue = AlertQueue()
    alert = Alert.from_detection_row(row, model_bundle, flow_df)
    queue.push(alert)
    # User reviews via dashboard, then 
    -> queue.decide(alert.alert_id, Decision.APPROVED)
"""

import uuid
import time
import threading
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Constants
# Feature names that correspond to what features.py produces.
# Used to build per-feature deviation explanations shown to the user.
FEATURE_NAMES = [
    "bytes",
    "packets",
    "duration",
    "bytes_per_packet",
    "packet_rate",
    "protocol_enc",
]

# Easy to read labels that user sees; explains each feature
FEATURE_LABELS = {
    "bytes": "Total bytes transferred",
    "packets": "Packet count",
    "duration": "Flow duration (s)",
    "bytes_per_packet": "Bytes per packet",
    "packet_rate": "Packets per second",
    "protocol_enc": "Protocol (encoded)",
}

# Severity thresholds based on anomaly score percentile rank (lower score = worse).
# Rank 1 = most anomalous flow in the batch.
SEVERITY_HIGH   = 0.05   # top 5% most anomalous
SEVERITY_MEDIUM = 0.15   # top 15%

# Enums
# User makes a decision as shown in the dashboard
class Decision(str, Enum): 
    PENDING = "pending"  # waiting for user to decide
    APPROVED = "approved"  # block it or mitigate now
    MONITOR = "monitor"  # monitor but do no block
    IGNORED = "ignored"  # false positive, dismiss

# Alert severity level, derived from anomaly score rank
class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"



"""  Alert dataclass
Describes how much a single feature deviated from the learned baseline.
Shown to the user as an explainability indicator.
"""
@dataclass
class FeatureDeviation:
    feature: str  # internal feature name (e.g. "packet_rate")
    label:  str  # human-readable label
    flow_value: float  # actual value observed in this flow
    baseline_mean: float  # mean value from training data
    baseline_std: float  # std deviation from training data
    z_score: float  # how many std devs away from the mean

    # Returns 'above' or 'below' baseline for display
    @property
    def direction(self) -> str: 
        return "above" if self.flow_value > self.baseline_mean else "below"

    # How many times the baseline mean this value is 
    @property
    def multiplier(self) -> float:
        if self.baseline_mean == 0:
            return 0.0
        return abs(self.flow_value / self.baseline_mean)

    def to_dict(self) -> dict:
        return {
            "feature": self.feature,
            "label": self.label,
            "flow_value": round(self.flow_value, 4),
            "baseline_mean": round(self.baseline_mean, 4),
            "baseline_std": round(self.baseline_std, 4),
            "z_score": round(self.z_score, 2),
            "direction": self.direction,
            "multiplier": round(self.multiplier, 2),
        }


# A suspicious flow event, with explanation data, queued for an operator's review and decision.
@dataclass
class Alert:
    # Unique identifier for this alert
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    # Timestamp when the alert was created
    created_at: float = field(default_factory=time.time)

    # Core detection results from detect.py
    anomaly_score: float = 0.0  # raw Isolation Forest score (lower = worse)
    anomaly_rank: int = 0  # rank within batch (1 = most anomalous)
    batch_size: int = 1  # total flows in the scored batch
    confidence_pct: float = 0.0  # derived confidence percentage (0–100)
    severity: Severity = Severity.LOW

    # Flow identifiers (for display and for mitigator.py to target)
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    dpid: int = 0  # OpenFlow switch datapath ID or 0 if unknown

    # Raw flow stats for context in the dashboard
    bytes: int = 0
    packets: int = 0
    duration: float = 0.0

    # Explanation: which features contributed most to the anomaly
    top_deviations: list[FeatureDeviation] = field(default_factory=list)

    # Plain-English summary generated by src/explainer.py
    explanation:   str = ""

    # Suggested action text shown to the operator
    recommendation: str = ""

    # Operator decision; updated by AlertQueue.decide()
    decision: Decision = Decision.PENDING
    decided_at: Optional[float] = None
    decided_by: str = "operator"   # future: could be a username

    # Constructors 
    @classmethod
    def from_detection_row(
        cls,
        row: pd.Series,
        model_bundle: dict,
        batch_df: pd.DataFrame,
        total_count: int = None,
    ) -> "Alert":
        """
        Build an Alert from a single row of detect.py's output DataFrame.
        batch_df may be a SLICE of a larger file (e.g. the dashboard's
        newly-arrived rows). total_count should be the full file's row
        count anomaly_rank was computed against, or confidence_pct can
        go negative.
        """

        batch_size = len(batch_df)
        if total_count is None:
            total_count = batch_size
        score = float(row.get("anomaly_score", 0.0))
        rank = int(row.get("anomaly_rank", 1))

        rank_pct = rank / max(total_count, 1)
        confidence = round((1.0 - rank_pct) * 100, 1)

        # Severity bucketing
        if rank_pct <= SEVERITY_HIGH:
            severity = Severity.HIGH
        elif rank_pct <= SEVERITY_MEDIUM:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Extract flow identity fields 
        src_ip = str(row.get("src_ip", "unknown"))
        dst_ip = str(row.get("dst_ip", "unknown"))
        src_port = int(row.get("src_port", 0))
        dst_port = int(row.get("dst_port", 0))
        protocol = str(row.get("protocol", "unknown"))
        dpid = int(row.get("dpid", 0))
        bytes_ = int(row.get("bytes", 0))
        packets = int(row.get("packets", 0))
        duration = float(row.get("duration", 0.0))

        # Compute per-feature deviations using the model bundle's training stats
        deviations = _compute_deviations(row, model_bundle)
        top_devs = sorted(deviations, key=lambda d: abs(d.z_score), reverse=True)[:3]

        # Build explanation and recommendation text (delegated to explainer.py,
        # but we do a lightweight fallback here if explainer is not yet available)
        try:
            from src.explainer import build_explanation, build_recommendation
            explanation = build_explanation(top_devs, severity, protocol)
            recommendation = build_recommendation(severity, protocol, dst_port)
        except ImportError:
            explanation = _fallback_explanation(top_devs, severity)
            recommendation = _fallback_recommendation(severity)

        alert = cls(
            anomaly_score = score,
            anomaly_rank = rank,
            batch_size = batch_size,
            confidence_pct = confidence,
            severity = severity,
            src_ip = src_ip,
            dst_ip = dst_ip,
            src_port = src_port,
            dst_port = dst_port,
            protocol = protocol,
            dpid = dpid,
            bytes = bytes_,
            packets = packets,
            duration = duration,
            top_deviations = top_devs,
            explanation = explanation,
            recommendation = recommendation,
        )

        logger.info(
            "[HITL] Alert %s created | severity=%s confidence=%.1f%% src=%s → dst=%s",
            alert.alert_id, alert.severity.value, alert.confidence_pct,
            src_ip, dst_ip,
        )

        return alert

    """ Serialization
    Serialize the alert to a plain dict for the Flask REST API and
    the operator dashboard's JavaScript frontend.
    """
    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "created_at": self.created_at,
            "created_at_str": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)
            ),
            "anomaly_score": round(self.anomaly_score, 4),
            "anomaly_rank": self.anomaly_rank,
            "batch_size": self.batch_size,
            "confidence_pct": self.confidence_pct,
            "severity": self.severity.value,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "dpid": self.dpid,
            "bytes": self.bytes,
            "packets": self.packets,
            "duration": round(self.duration, 4),
            "top_deviations": [d.to_dict() for d in self.top_deviations],
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "decision": self.decision.value,
            "decided_at": self.decided_at,
            "decided_at_str": (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.decided_at))
                if self.decided_at else None
            ),
            "decided_by": self.decided_by,
        }



"""  AlertQueue
Thread-safe queue of Alert objects.
The Flask dashboard, dashboard/app.py, and the Ryu controller, sdn_mininet/ryu_collector.py,
run in separate threads. This class uses a lock so both can safely push and read alerts concurrently.
Design choice - the dashboard needs random access by alert_id to update a decision after operator 
interaction.
"""
class AlertQueue:
    """
    Parameters
    max_size: int
    Maximum number of alerts retained in memory. When the queue is full, the oldest 
    resolved alert is evicted. If all alerts are still PENDING, the oldest pending 
    alert is evicted and a warning is logged. This prevents memory exhaustion under a
    sustained attack.
    """
    def __init__(self, max_size: int = 500):
        self._alerts: dict[str, Alert] = {}
        self._lock    = threading.Lock()
        self._max     = max_size

    # Write operations
    # Add a new alert to the queue.
    def push(self, alert: Alert) -> None:
        with self._lock:
            if len(self._alerts) >= self._max:
                self._evict_oldest()
            self._alerts[alert.alert_id] = alert
            logger.debug("[AlertQueue] Pushed alert %s (queue size: %d)",
                         alert.alert_id, len(self._alerts))
    
    """
    Record an operator's decision on a pending alert. Returns the updated Alert, 
    or None if the alert_id is not found. The caller (dashboard/app.py) should trigger 
    mitigator.py when the returned alert has decision == Decision.APPROVED.
    """
    def decide(
        self,
        alert_id: str,
        decision: Decision,
        decided_by: str = "operator",
    ) -> Optional[Alert]:
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                logger.warning("[AlertQueue] decide() called for unknown alert_id %s", alert_id)
                return None

            if alert.decision != Decision.PENDING:
                logger.warning(
                    "[AlertQueue] Alert %s already decided as '%s', ignoring new decision '%s'",
                    alert_id, alert.decision.value, decision.value,
                )
                return alert

            alert.decision   = decision
            alert.decided_at = time.time()
            alert.decided_by = decided_by

            logger.info(
                "[HITL] Alert %s decided: %s by %s at %s",
                alert_id, decision.value, decided_by,
                time.strftime("%H:%M:%S", time.localtime(alert.decided_at)),
            )

            return alert

    # Read operations
    # Retrieve a single alert by ID 
    def get(self, alert_id: str) -> Optional[Alert]:
        with self._lock:
            return self._alerts.get(alert_id)
    # Return all alerts still waiting for operator review, with newest first
    def pending(self) -> list[Alert]:
        with self._lock:
            return [
                a for a in reversed(list(self._alerts.values()))
                if a.decision == Decision.PENDING
            ]
    # Return every alert, all decisions with newest first
    def all_alerts(self) -> list[Alert]:
        with self._lock:
            return list(reversed(list(self._alerts.values())))
    # Return alerts the operator has already acted on
    def resolved(self) -> list[Alert]:
        with self._lock:
            return [
                a for a in reversed(list(self._alerts.values()))
                if a.decision != Decision.PENDING
            ]

    # Remove all alerts from the queue (pending and resolved). Used for a
    # clean demo reset — does not touch the underlying data files or
    # scanned-row bookkeeping, only the in-memory alert history.
    def clear(self) -> int:
        with self._lock:
            n = len(self._alerts)
            self._alerts.clear()
            return n

    # Summary counts for the dashboard's status bar. Returns counts by decision state and by severity.
    def stats(self) -> dict:
        with self._lock:
            alerts = list(self._alerts.values())

        counts = {d.value: 0 for d in Decision}
        sev = {s.value: 0 for s in Severity}

        for a in alerts:
            counts[a.decision.value] += 1
            sev[a.severity.value] += 1

        return {
            "total": len(alerts),
            "by_state": counts,
            "by_severity": sev,
        }

    def __len__(self) -> int:
        with self._lock:
            return len(self._alerts)

    
    """  Internal
    Remove the oldest resolved alert. If none are resolved, remove the oldest pending alert
    Called inside the lock do not acquire the lock again
    """
    def _evict_oldest(self) -> None:
        # Try to evict a resolved alert first
        for aid, alert in self._alerts.items():
            if alert.decision != Decision.PENDING:
                del self._alerts[aid]
                logger.debug("[AlertQueue] Evicted resolved alert %s", aid)
                return

        # All alerts are pending; evict the oldest one
        oldest_id = next(iter(self._alerts))
        del self._alerts[oldest_id]
        logger.warning(
            "[AlertQueue] Queue full and all alerts pending — "
            "evicted oldest pending alert %s", oldest_id,
        )



"""  Feature deviation computation
Compare each feature value in row against the training baseline stored in model_bundle["score_stats"] 
and the raw training data stats. For the global federated model, average baseline stats across clients. 
For a local model bundle, use the single client's stats directly.
Returns a list of FeatureDeviation objects, one per FEATURE_NAMES entry that is present in both 
the row and the bundle.
"""
def _compute_deviations(
    row: pd.Series,
    model_bundle: dict,
) -> list[FeatureDeviation]:
    # Extract baseline mean/std for each feature.
    # local_train.py stores score_stats (mean, std, p5, p1) but does not store
    # per-feature stats, so derive a best-effort baseline from the bundle.
    # If per-feature stats are available, use directly.
    feature_stats = _extract_feature_stats(model_bundle)

    deviations = []
    for feat in FEATURE_NAMES:
        if feat not in row.index:
            continue

        flow_val = float(row[feat]) if not pd.isna(row.get(feat)) else 0.0

        if feat in feature_stats:
            b_mean = feature_stats[feat]["mean"]
            b_std = feature_stats[feat]["std"]
        else:
            # No baseline available for this feature — skip it
            continue

        z = (flow_val - b_mean) / b_std if b_std > 0 else 0.0

        deviations.append(FeatureDeviation(
            feature = feat,
            label = FEATURE_LABELS.get(feat, feat),
            flow_value = flow_val,
            baseline_mean = b_mean,
            baseline_std = b_std,
            z_score = z,
        ))

    return deviations

"""
Pull per-feature baseline stats from the model bundle.
local_train.py currently only stores overall score stats (mean, std).
This function uses those to derive a reasonable per-feature approximation, and reads per-feature 
stats from bundle["feature_stats"] if your training pipeline stores them.
Returns a dict: { feature_name: {"mean": float, "std": float} }
"""
def _extract_feature_stats(model_bundle: dict) -> dict[str, dict]:
    stats: dict[str, dict] = {}

    # Preferred: per-feature stats stored at training time
    if "feature_stats" in model_bundle:
        return model_bundle["feature_stats"]

    # Federated model: average per-feature stats across clients
    if "clients" in model_bundle:
        clients = model_bundle["clients"]
        all_client_stats: list[dict] = [
            c.get("feature_stats", {}) for c in clients
        ]
        # Merge by averaging across clients for each feature
        for feat in FEATURE_NAMES:
            means = [cs[feat]["mean"] for cs in all_client_stats if feat in cs]
            stds = [cs[feat]["std"]  for cs in all_client_stats if feat in cs]
            if means:
                stats[feat] = {
                    "mean": float(np.mean(means)),
                    "std": float(np.mean(stds)),
                }
        if stats:
            return stats

    # Fallback: no per-feature stats available.
    # Return sensible defaults derived from known synthetic data distributions
    # (from scripts/generate_data.py). These keep the dashboard functional
    # even without extended training stats.
    DEFAULTS = {
        "bytes": {"mean": 15_000.0, "std": 50_000.0},
        "packets": {"mean": 10.0, "std": 30.0},
        "duration": {"mean": 2.5, "std": 5.0},
        "bytes_per_packet": {"mean": 1_200.0, "std": 3_000.0},
        "packet_rate": {"mean": 5.0, "std": 20.0},
        "protocol_enc": {"mean": 0.5, "std": 0.7},
    }
    return DEFAULTS


# Fallback explanation builders - used if src/explainer.py is not present
# Minimal explanation when src/explainer.py is not available
def _fallback_explanation(
    top_devs: list[FeatureDeviation],
    severity: Severity,
) -> str:
    if not top_devs:
        return "Anomalous flow detected. No feature breakdown available."

    reasons = []
    for dev in top_devs[:3]:
        reasons.append(
            f"- {dev.label}: {dev.flow_value:.2f} "
            f"({dev.direction} baseline by {abs(dev.z_score):.1f}σ)"
        )

    header = {
        Severity.HIGH: "⚠ HIGH SEVERITY -> unusual traffic pattern detected",
        Severity.MEDIUM: "⚡ MEDIUM SEVERITY -> moderately suspicious flow",
        Severity.LOW: "ℹ LOW SEVERITY -> minor anomaly flagged",
    }[severity]

    return header + "\n\nTop contributing indicators:\n" + "\n".join(reasons)

# Minimal recommendation when src/explainer.py is not available
def _fallback_recommendation(severity: Severity) -> str:
    recs = {
        Severity.HIGH: "Consider blocking this host immediately.",
        Severity.MEDIUM: "Monitor this host closely. Block if behaviour persists.",
        Severity.LOW: "Log and continue monitoring.",
    }
    return recs[severity]


# Convenience: batch-process a detect.py output DataFrame
    """
    Convert the top anomalous rows from detect.py's output into Alert objects.
    Parameters
    - detections_df: pd.DataFrame
    Full output of detect() -> contains anomaly_score, anomaly_rank, is_anomaly, plus original flow columns.
    - model_bundle: dict
    Loaded model bundle from joblib (.pkl file).
    - min_confidence : float
    Only create alerts for flows with confidence >= this value (0–100).
    Default 50.0 — filters out the least suspicious half.
    - max_alerts : int
      Cap on how many alerts to create in one batch. Prevents flooding
      the dashboard during large-scale attacks.
    Returns
    list[Alert]
    Alerts sorted by confidence descending with most suspicious first
    """
def alerts_from_detections(
    detections_df: pd.DataFrame,
    model_bundle: dict,
    min_confidence: float = 50.0,
    max_alerts: int = 50,
    total_count: int = None,
) -> list[Alert]:
    # total_count lets callers pass the FULL scored file's row count as the
    # confidence-percentile denominator, separate from len(detections_df).
    # This matters when detections_df is only a SLICE of newly-arrived rows
    # (as the Tool 4 dashboard's scanner does) -- anomaly_rank was assigned
    # relative to the whole file, so dividing by the slice's own length
    # would produce nonsensical (often >1.0) percentiles.
    if total_count is None:
        total_count = len(detections_df)

    # Keep only flagged anomalies above the confidence threshold
    flagged = detections_df[detections_df["is_anomaly"] == True].copy()

    if flagged.empty:
        logger.info("[HITL] No anomalies in this batch — no alerts created.")
        return []

    # Sort by anomaly score ascending (most anomalous = lowest score = first)
    flagged = flagged.sort_values("anomaly_score", ascending=True)

    alerts = []
    for _, row in flagged.iterrows():
        # Compute confidence inline to apply the filter before building Alert
        rank_pct = int(row["anomaly_rank"]) / max(total_count, 1)
        confidence = (1.0 - rank_pct) * 100

        if confidence < min_confidence:
            continue

        alert = Alert.from_detection_row(row, model_bundle, detections_df, total_count=total_count)
        alerts.append(alert)

        if len(alerts) >= max_alerts:
            logger.warning(
                "[HITL] Reached max_alerts=%d cap — %d additional anomalies not queued.",
                max_alerts,
                len(flagged) - max_alerts,
            )
            break

    logger.info("[HITL] Created %d alert(s) from batch of %d flows.",
                len(alerts), len(detections_df))

    return alerts
