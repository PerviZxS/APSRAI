# APSRAI Prototype
**A Python Simulation of Human-in-the-Loop Governance for Agentic AI Threat Detection**

---

## What this is

This repository contains a working prototype of the APSRAI framework Agentic Public Sector Resilience AI developed as part of a Design Science Research study on embedding human oversight into agentic AI systems for critical infrastructure threat detection.

The prototype is not a production system. It is a simulation that demonstrates one specific thing: that a human operator can be made structurally mandatory in an AI-driven decision pipeline, not optional, not advisory, but a hard stop before any action is taken. This directly operationalizes Article 14 of the EU AI Act, which mandates human oversight for high-risk AI systems but does not specify how to implement it.

The underlying paper proposes APSRAI as a governance framework. This prototype instantiates that framework as executable code, serving as the demonstration and artifact components of the DSRM methodology used in the study.

---

## What it demonstrates

The script runs 15 synthetic infrastructure monitoring events through a four-stage pipeline:

1. **Detection**: Each event is checked against a policy threshold. If the observed value exceeds the limit, an anomaly is detected and a confidence score is calculated.
2. **Alert generation**: The anomaly is packaged into a structured alert containing the anomaly type, confidence score, policy limit breached, and affected node.
3. **Mandatory human decision**: The system halts. The operator must choose one of three authorized responses: threat confirmation, dismissal as false positive, or escalation. The pipeline cannot continue without this input.
4. **Audit logging**: Regardless of the decision made, a complete and timestamped record is appended to an immutable log file.
![APSRAI.drawio.svg](../vault/academia/Papers/Agentic%20AI%20for%20Public%20Sector%20Resilience/APSRAI.drawio.svg)
The output is a `.jsonl` audit log and a `.csv` summary file showing every anomaly detected and every decision made.

---

## Repository contents

```
apsrai_simulation.py       # The simulation script
apsrai_sample_output.jsonl # Sample audit log from a simulated run
apsrai_sample_output.csv   # Summary table of the same run
README.md                  # This file
```

---

## How to run it

Python 3.10 or higher is needed. No external libraries are required, the script uses only the Python standard library.

**Interactive mode**: the script pauses at each anomaly and asks you to enter a decision:

```bash
python apsrai_simulation.py
```

**Automated mode**: decisions are randomized, the full run completes without input. Use this for demos or to generate sample output:

```bash
python apsrai_simulation.py --simulate
```

When the run completes, two files are written to the same directory:
- `apsrai_audit_log.jsonl`: append-only audit log, one JSON record per line
- `apsrai_summary.csv`: flat summary table, one row per logged decision

---

## Output format

Each audit log entry contains the following fields:

| Field | Description |
|---|---|
| `log_id` | Unique identifier for this log entry |
| `alert_id` | Identifier linking back to the original alert |
| `alert_timestamp` | When the alert was generated |
| `node` | Affected infrastructure node |
| `anomaly_type` | Type of anomaly detected |
| `confidence` | AI confidence score (0.0 – 1.0) |
| `policy_limit` | The threshold that was exceeded |
| `operator_decision` | One of: `threat_confirmed`, `false_positive`, `escalated` |
| `log_timestamp` | When the log entry was written |

---

## Limitations

This prototype demonstrates workflow logic and regulatory alignment. It does not validate detection accuracy, system performance under load, or integration with real infrastructure. The synthetic data is randomly generated. The confidence score is a simplified ratio, not the output of a trained model. Real-world effectiveness would require empirical testing in an active deployment context, which is explicitly outside the scope of this study.

---

## Regulatory alignment

The four-stage architecture maps directly to the following regulatory instruments evaluated in the accompanying paper:

- **EU AI Act, Article 14**: the mandatory halt in Stage 3 implements the human oversight requirement as an operational stop-gate
- **ALTAI (transparency criterion)**: the alert package in Stage 2 provides the operator with full decision context before any action is taken
- **ALTAI (accountability criterion)**: the immutable audit log in Stage 4 creates a complete and reviewable record of every AI-influenced classification
- **CER Directive (oversight capacity)**: the three-response decision structure ensures all high-stakes classifications are reviewed by an authorized human operator

---

## How to cite

If you use or reference this prototype in academic work, please cite it as (Please check the up to dated doi to cite):

> PerviZxS (2026) “PerviZxS/APSRAIv1: APSRAI Prototype v1.0.0”. Zenodo. doi:10.5281/zenodo.XXXXXXX.

---

## Author

**Parviz Salmanov, MSc**
Research Assistant @ Tallinn University of Technology (TalTech)

---

## License

MIT License. You are free to use, modify, and distribute this code for academic and non-commercial purposes with attribution.
