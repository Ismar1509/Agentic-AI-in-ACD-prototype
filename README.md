# Thesis Experiment – Governed Agentic AI for Autonomous Cyber Defence
## Chapter 5 – Phase 2 Empirical Validation

AutoGen + Ollama multi-agent pipeline implementing the governed architecture
described in Chapter 5. Runs entirely locally on Linux Mint / Ubuntu 22.04.
No cloud API keys required.

---

## Quick Start (copy-paste these commands in order)

```bash
# 1. Clone / copy this folder somewhere on your machine, then cd into it
cd thesis_experiment

# 2. One-time setup (installs Ollama, pulls model, creates Python venv)
bash 00_setup.sh

# 3. Activate the Python virtual environment
source .venv/bin/activate

# 4. Start Ollama in a SEPARATE terminal tab (leave it running)
ollama serve

# 5. Back in your first terminal – verify everything works
python 00_verify.py

# 6. Run the full experiment (all 3 scenarios, 3 runs each = 9 total)
python 01_run_experiment.py

# 7. Analyse the Decision Traces and generate the report
python 02_analyse_traces.py
```

---

## What Each File Does

| File | Purpose |
|------|---------|
| `00_setup.sh` | Installs Ollama, pulls the LLM model, creates the Python venv |
| `00_verify.py` | Pre-flight check: Ollama reachable, model loaded, AutoGen works |
| `agents.py` | Core architecture: Analyst, Planner, Executor agents + guardrail engine |
| `scenarios.py` | Alert prompt definitions for S1, S2, S3 (MITRE ATT&CK-aligned) |
| `01_run_experiment.py` | Main runner – executes all scenarios, saves traces and CSV |
| `02_analyse_traces.py` | Reads trace JSON files, detects anomalies, writes analysis report |

---

## Output Files

After running the experiment you will have:

```
logs/
  S1_run1.json          ← Decision Trace: T1 (Analyst) T2 (Planner) T3 (Executor)
  S1_run2.json
  S1_run3.json
  S2_run1.json
  S2_run2.json
  S2_run3.json
  S3_run1.json          ← Multi-turn: 4 chain stages × 3 agents each
  S3_run2.json
  S3_run3.json

results/
  experiment_summary.csv   ← One row per run; suitable for pasting into thesis tables
  trace_analysis.txt       ← Full anomaly report (boundary failures, reliability issues)
```

---

## Guardrail Rules (Code-Layer – Not Prompt-Only)

| Rule | Condition | Action |
|------|-----------|--------|
| **G1** | Analyst confidence < 0.60 | Override to Escalate-HITL |
| **G2** | Isolate-Host or Block-Account AND confidence < 0.75 | Override to Escalate-HITL |
| **G3** | High-impact action without PLANNER_APPROVED token | Executor hard stop (Governance-Blocked) |

G1 and G2 are enforced in `agents.py::enforce_guardrails()` – pure Python,
not delegated to the LLM. This is the key architectural contribution over
vanilla AutoGen.

---

## Running Individual Scenarios

```bash
# Only S1 (Insider Anomaly)
python 01_run_experiment.py --scenario S1

# Only S2, 1 run (faster for testing)
python 01_run_experiment.py --scenario S2 --runs 1

# Show full agent conversation output
python 01_run_experiment.py --verbose

# Analyse only S2 traces
python 02_analyse_traces.py --scenario S2
```

---

## Hardware Requirements

| Component | Minimum |
|-----------|---------|
| RAM | 8 GB (16 GB recommended) |
| Disk | 6 GB free (model ~4 GB) |
| GPU | Not required (CPU inference) |
| OS | Linux Mint 21 / Ubuntu 22.04 |

**Note on model tag:** these scripts use `mistral:7b-instruct-q4_0`. Check
what you have locally with: `ollama list`. If the tag differs, either pull
the exact tag above or update the `model` field in `agents.py` and
`00_verify.py` to match.

CPU-only inference for mistral:7b-q4_0 takes approximately 15–30 seconds
per agent turn depending on hardware. Each full 3-turn scenario takes
roughly 1–2 minutes.

---

## Expected Results (Reference)

| Scenario | Expected Guardrail | Expected Outcome |
|----------|--------------------|-----------------|
| S1 – Insider Anomaly | G1 (confidence ~0.43–0.50) | Escalate-HITL all 3 runs |
| S2 – Ransomware (runs 1-2) | None (confidence ~0.80) | Isolate-Host executed |
| S2 – Ransomware (run 3) | G2 boundary (confidence ~0.70) | Escalate-HITL or boundary failure |
| S3 – APT Chain | Escalating across 4 turns | Progressive HITL at T1055 / T1041 stages |

---

## Citing in Thesis

The guardrail enforcement is in `agents.py`, function `enforce_guardrails()`.
This is the code-layer implementation referenced in Chapter 5, Section 5.3.2.
The Decision Trace structure in `TraceLogger` implements the logging schema
specified in Chapter 3, Section 3.5.2.
