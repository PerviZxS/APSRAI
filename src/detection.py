"""Stage 1 - Detection.

Generates synthetic infrastructure events and flags anomalies where an observed
value exceeds its policy limit. Confidence may be absent when the upstream model
fails to emit a usable score (a boundary condition handled downstream).
"""

import random
from uuid import uuid4

from config import NODES, EVENT_TYPES


def generate_synthetic_log(n=15, missing_conf_rate=0.12, dup_rate=0.12):
    """Generate `n` synthetic events.

    Deliberately injects two boundary-condition triggers so a random run can
    exercise them: missing/malformed confidence and duplicate anomaly IDs.
    """
    entries = []
    for _ in range(n):
        policy_limit = round(random.uniform(0.5, 0.8), 2)
        observed = round(random.uniform(0.3, 1.2), 2)
        entries.append({
            "entry_id": str(uuid4()),
            "node": random.choice(NODES),
            "event_type": random.choice(EVENT_TYPES),
            "observed_value": observed,
            "policy_limit": policy_limit,
            "force_missing_conf": random.random() < missing_conf_rate,
        })

    candidates = [e for e in entries if e["observed_value"] > e["policy_limit"]]
    if candidates:
        for e in random.sample(candidates, k=min(2, len(candidates))):
            if random.random() < dup_rate + 0.5:
                dup = dict(e)
                dup["_is_injected_duplicate"] = True
                entries.append(dup)

    return entries


def detect_anomaly(entry):
    """Return an anomaly record if observed exceeds policy limit, else None."""
    if entry["observed_value"] <= entry["policy_limit"]:
        return None

    if entry.get("force_missing_conf"):
        confidence = None  # malformed / absent upstream score
    else:
        confidence = round(
            min((entry["observed_value"] / entry["policy_limit"]) - 1.0, 1.0), 2
        )

    return {
        "entry_id": entry["entry_id"],
        "node": entry["node"],
        "anomaly_type": entry["event_type"],
        "observed_value": entry["observed_value"],
        "policy_limit": entry["policy_limit"],
        "confidence": confidence,
    }
