"""Stage 3 - Time-bound human decision.

Presents the alert to the operator and captures one of four outcomes:
confirm / dismiss / escalate / timeout. On timeout the system FAILS CLOSED: the
pending action is blocked and the alert is auto-escalated to the next tier.
"""

import random

from .config import DECISION_MAP


def human_decision(alert, simulate=False, timeout_rate=0.15, forced=None):
    """Return one of: threat_confirmed | false_positive | escalated | timeout.

    `forced` overrides the outcome for deterministic runs ('timeout','1','2','3').
    `simulate` randomises the outcome for unattended runs.
    Otherwise the function blocks for interactive operator input.
    """
    print("\n" + "=" * 56)
    print("MANDATORY SYSTEM HALT - Human Decision Required")
    print("=" * 56)
    print(f"  Node            : {alert['node']} (criticality {alert['node_criticality']})")
    print(f"  Anomaly Type    : {alert['anomaly_type']}")
    print(f"  Confidence      : {alert['confidence']}")
    print(f"  Severity        : {alert['severity']} ({alert['consequence_class']})")
    print(f"  Policy Limit    : {alert['policy_limit']}")
    print(f"  Alert ID        : {alert['alert_id']}")
    print("-" * 56)

    if forced is not None:
        if forced == "timeout":
            print("  [DEMO] No response in window -> TIMEOUT (fail-closed)")
            return "timeout"
        print(f"  [DEMO] Operator response: {forced} -> {DECISION_MAP[forced]}")
        return DECISION_MAP[forced]

    if simulate:
        if random.random() < timeout_rate:
            print("  [SIMULATED] No response in window -> TIMEOUT (fail-closed)")
            return "timeout"
        choice = random.choices(["1", "2", "3"], weights=[30, 50, 20])[0]
        print(f"  [SIMULATED] Operator response: {choice} -> {DECISION_MAP[choice]}")
        return DECISION_MAP[choice]

    while True:
        response = input(
            "  Decision - 1: Confirm | 2: False Positive | 3: Escalate : "
        ).strip()
        if response in DECISION_MAP:
            return DECISION_MAP[response]
        print("  Invalid input. Enter 1, 2, or 3 only.")
