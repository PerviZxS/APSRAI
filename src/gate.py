"""Stage 2 - Alert generation and the severity gate.

The gate is the core of the framework: it decides whether a classification
triggers a mandatory halt or is logged for batch review. Severity is computed as
confidence x node-criticality. Missing/malformed confidence is treated as worst
case (halt); low-calibration confidence routes to halt regardless of magnitude.
"""

from uuid import uuid4
from datetime import datetime, timezone

from config import NODE_CRITICALITY, SEVERITY_THRESHOLD, LOW_CALIBRATION_FLOOR


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def consequence_class(node, confidence):
    """Return (severity_value, consequence_label, gate_decision).

    gate_decision is 'halt' or 'log_only'.
    """
    criticality = NODE_CRITICALITY.get(node, 0.5)

    if confidence is None:
        # Cannot assess -> fail safe on absent input.
        return (None, "indeterminate", "halt")

    severity = round(confidence * criticality, 3)

    if confidence < LOW_CALIBRATION_FLOOR:
        return (severity, "low_calibration", "halt")
    if severity >= SEVERITY_THRESHOLD:
        return (severity, "consequential", "halt")
    return (severity, "sub_threshold", "log_only")


def generate_alert(anomaly):
    """Build the full alert package, including the gate decision."""
    severity, label, gate = consequence_class(anomaly["node"], anomaly["confidence"])
    return {
        "alert_id": str(uuid4()),
        "alert_timestamp": now_iso(),
        "anomaly_id": anomaly["entry_id"],     # used by the dedup guard
        "anomaly_type": anomaly["anomaly_type"],
        "confidence": anomaly["confidence"],
        "observed_value": anomaly["observed_value"],
        "policy_limit": anomaly["policy_limit"],
        "node": anomaly["node"],
        "node_criticality": NODE_CRITICALITY.get(anomaly["node"], 0.5),
        "severity": severity,
        "consequence_class": label,
        "gate_decision": gate,
    }
