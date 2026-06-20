"""Behavioural tests for APSRAI.

Each test asserts one claim made in the paper's Artifact Description, so the
test suite doubles as a checklist mapping claims to verifiable behaviour.
Run: pytest -q
"""

import os
import json
import tempfile

from apsrai.gate import consequence_class, generate_alert
from apsrai.detection import detect_anomaly
from apsrai.audit import append_audit_entry, verify_chain, last_hash
from apsrai.config import GENESIS_HASH
from apsrai.orchestrator import run


def test_missing_confidence_fails_safe_to_halt():
    sev, label, gate = consequence_class("node-07", None)
    assert gate == "halt"
    assert label == "indeterminate"


def test_sub_threshold_logs_without_halt():
    # low criticality node, modest confidence -> below threshold
    sev, label, gate = consequence_class("node-14", 0.3)
    assert gate == "log_only"
    assert label == "sub_threshold"


def test_consequential_action_halts():
    sev, label, gate = consequence_class("node-01", 0.9)
    assert gate == "halt"
    assert label == "consequential"


def test_low_calibration_halts_regardless():
    sev, label, gate = consequence_class("node-01", 0.05)
    assert gate == "halt"
    assert label == "low_calibration"


def test_detection_skips_within_limit():
    entry = {"entry_id": "x", "node": "node-01", "event_type": "cpu_spike",
             "observed_value": 0.4, "policy_limit": 0.6}
    assert detect_anomaly(entry) is None


def test_chain_is_append_only_and_verifies():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "log.jsonl")
        alert = generate_alert(detect_anomaly({
            "entry_id": "a", "node": "node-01", "event_type": "auth_failure",
            "observed_value": 1.1, "policy_limit": 0.55}))
        r1 = append_audit_entry(alert, "threat_confirmed", filepath=path)
        r2 = append_audit_entry(alert, "escalated", filepath=path)
        assert r1["prev_hash"] == GENESIS_HASH
        assert r2["prev_hash"] == r1["entry_hash"]
        ok, _ = verify_chain(path)
        assert ok


def test_tamper_is_detected():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "log.jsonl")
        alert = generate_alert(detect_anomaly({
            "entry_id": "a", "node": "node-01", "event_type": "auth_failure",
            "observed_value": 1.1, "policy_limit": 0.55}))
        append_audit_entry(alert, "threat_confirmed", filepath=path)
        append_audit_entry(alert, "escalated", filepath=path)
        # tamper: rewrite first line with an altered decision
        lines = [l for l in open(path) if l.strip()]
        rec = json.loads(lines[0]); rec["operator_decision"] = "false_positive"
        lines[0] = json.dumps(rec) + "\n"
        open(path, "w").writelines(lines)
        ok, msg = verify_chain(path)
        assert not ok


def test_demo_exercises_all_behaviours():
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "log.jsonl"); summ = os.path.join(d, "s.csv")
        stats, ok = run(demo=True, audit_path=log, summary_path=summ)
        assert ok
        assert stats["timeouts"] >= 1
        assert stats["late"] >= 1
        assert stats["deduped"] >= 1
        assert stats["log_only"] >= 1
        assert stats["missing_conf"] >= 1
        assert stats["halted"] >= 1
