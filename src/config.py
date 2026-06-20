"""Configuration constants for the APSRAI proof-of-concept.

All tunable parameters live here so the gate's behaviour is inspectable in one
place. NOTE: thresholds below are illustrative parameters chosen to make the
demonstration legible; they are not empirically calibrated. Threshold
calibration is identified as future work in the paper.
"""

# Synthetic infrastructure nodes and event types
NODES = ["node-01", "node-03", "node-07", "node-11", "node-14"]
EVENT_TYPES = [
    "cpu_spike",
    "network_flood",
    "auth_failure",
    "latency_breach",
    "disk_overflow",
]

# Node criticality in [0, 1]: how consequential an action on this node is.
# Drives the consequence dimension of the severity gate.
NODE_CRITICALITY = {
    "node-01": 0.9,   # core control node
    "node-03": 0.7,
    "node-07": 0.4,
    "node-11": 0.8,
    "node-14": 0.3,   # peripheral / telemetry node
}

# severity = confidence * node_criticality; at/above this -> mandatory halt
SEVERITY_THRESHOLD = 0.45

# A confidence score below this floor is treated as low-calibration and routed
# to halt regardless of severity magnitude.
LOW_CALIBRATION_FLOOR = 0.20

# Hash chain genesis value (predecessor of the first entry)
GENESIS_HASH = "0" * 64

# Default output paths (relative to repo root)
AUDIT_LOG = "outputs/apsrai_audit_log.jsonl"
SUMMARY_CSV = "outputs/apsrai_summary.csv"

# Operator response codes
DECISION_MAP = {"1": "threat_confirmed", "2": "false_positive", "3": "escalated"}
