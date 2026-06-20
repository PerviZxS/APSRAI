"""Orchestration - wires the four stages and the boundary conditions.

Routing per anomaly:
  dedup guard -> late-after-timeout -> severity gate -> halt/decision -> audit.
"""

import csv
from uuid import uuid4

from config import NODE_CRITICALITY, SUMMARY_CSV, AUDIT_LOG
from detection import generate_synthetic_log, detect_anomaly
from gate import generate_alert
from decision import human_decision
from audit import append_audit_entry, verify_chain


def write_summary_csv(records, filepath=SUMMARY_CSV):
    fields = ["log_id", "node", "anomaly_type", "confidence", "severity",
              "consequence_class", "gate_decision", "operator_decision",
              "outcome_note", "log_timestamp"]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def build_demo_entries():
    """Deterministic scenario set guaranteeing one of each behaviour, so the
    committed audit log is complete evidence rather than seed-dependent.

    Returns (entries, scripted) where scripted maps entry index -> forced
    operator action ('timeout' | '1' | '2' | '3').
    """
    entries = []
    scripted = {}

    def add(node, ev, observed, limit, missing=False, dup_id=None):
        e = {"entry_id": dup_id or str(uuid4()), "node": node, "event_type": ev,
             "observed_value": observed, "policy_limit": limit,
             "force_missing_conf": missing}
        entries.append(e)
        return e["entry_id"]

    add("node-01", "auth_failure", 1.10, 0.55); scripted[0] = "1"          # consequential halt
    add("node-14", "cpu_spike", 0.66, 0.60)                                # sub-threshold
    add("node-07", "latency_breach", 0.90, 0.50, missing=True); scripted[2] = "2"  # missing conf
    tid = add("node-11", "network_flood", 1.15, 0.50); scripted[3] = "timeout"     # timeout
    add("node-11", "network_flood", 1.15, 0.50, dup_id=tid); scripted[4] = "3"     # late
    add("node-01", "auth_failure", 1.10, 0.55, dup_id=entries[0]["entry_id"])      # dedup
    add("node-03", "disk_overflow", 0.95, 0.60); scripted[6] = "1"         # filler halt
    add("node-07", "cpu_spike", 0.58, 0.55)                                # filler
    return entries, scripted


def run(simulate=False, demo=False, audit_path=AUDIT_LOG, summary_path=SUMMARY_CSV):
    if demo:
        log_entries, scripted = build_demo_entries()
        simulate = True
    else:
        log_entries, scripted = generate_synthetic_log(15), {}

    index_of = {id(e): i for i, e in enumerate(log_entries)}
    audit_records = []
    open_windows = {}   # anomaly_id -> alert_id
    timed_out = {}      # anomaly_id -> log record

    stats = {"entries": len(log_entries), "anomalies": 0, "halted": 0,
             "log_only": 0, "deduped": 0, "timeouts": 0, "late": 0,
             "missing_conf": 0}

    for entry in log_entries:
        forced = scripted.get(index_of.get(id(entry))) if scripted else None
        anomaly = detect_anomaly(entry)
        if anomaly is None:
            continue
        stats["anomalies"] += 1

        alert = generate_alert(anomaly)
        aid = alert["anomaly_id"]
        if alert["confidence"] is None:
            stats["missing_conf"] += 1

        # Boundary: dedup within an open window
        if aid in open_windows and aid not in timed_out:
            stats["deduped"] += 1
            print(f"\n[DEDUP] Duplicate anomaly {aid[:8]} suppressed; "
                  f"annotating open alert {open_windows[aid][:8]}.")
            append_audit_entry(alert, "duplicate_suppressed",
                               outcome_note=f"dedup_of:{open_windows[aid]}",
                               filepath=audit_path)
            continue

        # Boundary: late decision after a recorded timeout
        if aid in timed_out:
            stats["late"] += 1
            print(f"\n[LATE] Decision for {aid[:8]} arrived after timeout; "
                  f"timeout stands, appending annotated entry.")
            late = human_decision(alert, simulate=simulate, forced=forced)
            rec = append_audit_entry(
                alert, f"late_{late}",
                outcome_note=f"timeout_final:{timed_out[aid]['log_id']};late_not_binding",
                filepath=audit_path)
            audit_records.append(rec)
            continue

        # Severity gate
        if alert["gate_decision"] == "log_only":
            stats["log_only"] += 1
            print(f"\n[SUB-THRESHOLD] {alert['anomaly_type']} on {alert['node']} "
                  f"(severity {alert['severity']}) logged for batch review, no halt.")
            rec = append_audit_entry(alert, "none_sub_threshold",
                                     outcome_note="logged_no_halt", filepath=audit_path)
            audit_records.append(rec)
            continue

        # Mandatory halt + human decision
        stats["halted"] += 1
        open_windows[aid] = alert["alert_id"]
        decision = human_decision(alert, simulate=simulate, forced=forced)

        if decision == "timeout":
            stats["timeouts"] += 1
            rec = append_audit_entry(
                alert, "timeout",
                outcome_note="fail_closed:action_blocked;auto_escalated",
                filepath=audit_path)
            timed_out[aid] = rec
        else:
            rec = append_audit_entry(alert, decision, filepath=audit_path)
        audit_records.append(rec)

    write_summary_csv(audit_records, summary_path)
    ok, msg = verify_chain(audit_path)

    print("\n" + "=" * 56)
    print("  RUN SUMMARY")
    print("=" * 56)
    print(f"  Entries processed     : {stats['entries']}")
    print(f"  Anomalies detected    : {stats['anomalies']}")
    print(f"  Mandatory halts       : {stats['halted']}")
    print(f"    - of which timeouts : {stats['timeouts']} (fail-closed)")
    print(f"    - late responses    : {stats['late']}")
    print(f"  Sub-threshold logged  : {stats['log_only']}")
    print(f"  Duplicates suppressed : {stats['deduped']}")
    print(f"  Missing-confidence    : {stats['missing_conf']} (failed safe to halt)")
    print(f"  Chain status          : {msg}")
    print(f"  Audit log             : {audit_path}")
    print(f"  Summary CSV           : {summary_path}")
    print("=" * 56)
    return stats, ok
