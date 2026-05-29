# src/__init__.py
# Makes src/ a proper Python package so relative imports work.
#
# Tool 1: core ML pipeline
# Tool 2: Byzantine-robust poisoning defense
# Tool 4: Human-in-the-Loop alert and explanation engine
#
# Public surface — what's safe to import directly from src:
#   from src.hitl     import AlertQueue, Alert, Decision, alerts_from_detections
#   from src.explainer import build_explanation, build_recommendation, format_alert_for_cli

from src.hitl import (
    AlertQueue,
    Alert,
    Decision,
    Severity,
    FeatureDeviation,
    alerts_from_detections,
)

from src.explainer import (
    build_explanation,
    build_recommendation,
    format_alert_for_cli,
    format_alert_summary_line,
)
