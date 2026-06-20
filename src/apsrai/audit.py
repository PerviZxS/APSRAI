"""Stage 4 - Append-only, hash-chained audit log (EU AI Act Art. 12).

Each entry binds to its predecessor via entry_hash = SHA-256(canonical(payload)
+ prev_hash). Any retroactive edit, deletion, or reorder breaks the chain and is
detected by verify_chain(). This provides the tamper-evidence the Article 12
record-keeping obligation implies.
"""

import json
import hashlib
from uuid import uuid4
from datetime import datetime, timezone

from .config import GENESIS_HASH, AUDIT_LOG


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _canonical(payload: dict) -> str:
    """Deterministic serialization for hashing (sorted keys, no whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _entry_hash(payload: dict, prev_hash: str) -> str:
    return hashlib.sha256((_canonical(payload) + prev_hash).encode("utf-8")).hexdigest()


def last_hash(filepath=AUDIT_LOG) -> str:
    """Return the entry_hash of the last record, or GENESIS if empty/absent."""
    last = GENESIS_HASH
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = json.loads(line)["entry_hash"]
    except FileNotFoundError:
        pass
    return last


def append_audit_entry(alert, decision, outcome_note="", filepath=AUDIT_LOG):
    """Append a hash-chained record and return it."""
    prev_hash = last_hash(filepath)
    payload = {
        "log_id": str(uuid4()),
        "alert_id": alert["alert_id"],
        "anomaly_id": alert["anomaly_id"],
        "alert_timestamp": alert["alert_timestamp"],
        "node": alert["node"],
        "anomaly_type": alert["anomaly_type"],
        "confidence": alert["confidence"],
        "observed_value": alert["observed_value"],
        "policy_limit": alert["policy_limit"],
        "severity": alert["severity"],
        "consequence_class": alert["consequence_class"],
        "gate_decision": alert["gate_decision"],
        "operator_decision": decision,
        "outcome_note": outcome_note,
        "log_timestamp": _now_iso(),
        "prev_hash": prev_hash,
    }
    payload["entry_hash"] = _entry_hash(payload, prev_hash)
    with open(filepath, "a") as f:
        f.write(json.dumps(payload) + "\n")
    return payload


def verify_chain(filepath=AUDIT_LOG):
    """Re-walk the log and confirm every link. Return (ok: bool, message: str)."""
    prev_hash = GENESIS_HASH
    count = 0
    try:
        with open(filepath, "r") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                stored = rec.get("entry_hash")
                recorded_prev = rec.get("prev_hash")
                if recorded_prev != prev_hash:
                    return (False, f"Line {i}: prev_hash mismatch "
                                   f"(broken chain: deletion or reorder).")
                check = dict(rec)
                check.pop("entry_hash", None)
                if _entry_hash(check, recorded_prev) != stored:
                    return (False, f"Line {i}: entry_hash mismatch "
                                   f"(record altered after writing).")
                prev_hash = stored
                count += 1
    except FileNotFoundError:
        return (False, "No audit log found.")
    return (True, f"Chain verified: {count} entries, no tampering detected.")


def tamper_test(filepath=AUDIT_LOG):
    """Flip one field in a copy and show the chain detects it."""
    with open(filepath, "r") as f:
        lines = [l for l in f if l.strip()]
    if not lines:
        print("No entries to tamper-test.")
        return False
    target = len(lines) // 2
    rec = json.loads(lines[target])
    original = rec["operator_decision"]
    rec["operator_decision"] = (
        "threat_confirmed" if original != "threat_confirmed" else "false_positive"
    )
    lines[target] = json.dumps(rec) + "\n"
    tampered = filepath.replace(".jsonl", "_TAMPERED.jsonl")
    with open(tampered, "w") as f:
        f.writelines(lines)
    ok, msg = verify_chain(tampered)
    print("\n" + "=" * 56)
    print("TAMPER TEST")
    print("=" * 56)
    print(f"  Altered line {target + 1}: operator_decision "
          f"'{original}' -> '{rec['operator_decision']}'")
    print(f"  Result: {'PASS (BAD - not detected)' if ok else 'DETECTED (correct)'}")
    print(f"  Detail: {msg}")
    print("=" * 56)
    return (not ok)
