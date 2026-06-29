"""
agents.py  –  Governed Agent Architecture
==========================================
Three-agent AutoGen pipeline implementing the guardrail policy
described in Chapter 5, Section 5.3.

Agents:
  Analyst   – triage, confidence scoring, recommendation
  Planner   – guardrail policy enforcement (G1, G2, G3)
  Executor  – action invocation or HITL escalation

Guardrail Rules (non-negotiable; enforced in code, not prompts):
  G1 – Confidence Gate        : confidence < 0.60  → Escalate-HITL
  G2 – High-Impact Gate       : Isolate-Host or Block-Account
                                requires confidence >= 0.75
  G3 – Executor Hard Stop     : Executor will not run high-impact
                                actions without explicit Planner approval
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import autogen

# ─── LLM config: points to local Ollama endpoint ──────────────────────────────
OLLAMA_CONFIG = {
    "model": "mistral:7b-instruct-q4_0",
    "base_url": "http://localhost:11434/v1",
    "api_key": "ollama",          # Ollama ignores the key; required by client
    "temperature": 0.0,
    "max_tokens": 800,
}

LLM_CONFIG = {"config_list": [OLLAMA_CONFIG], "cache_seed": None}

# ─── Thresholds ────────────────────────────────────────────────────────────────
CONFIDENCE_GATE        = 0.60   # G1: below this → always escalate
HIGH_IMPACT_GATE       = 0.75   # G2: Isolate-Host / Block-Account minimum
HIGH_IMPACT_ACTIONS    = {"Isolate-Host", "Block-Account"}
PERMITTED_ACTIONS      = {"Monitor", "Isolate-Host", "Block-Account", "Escalate-HITL"}

# ─── System prompts ────────────────────────────────────────────────────────────
ANALYST_SYSTEM = """You are a SOC Analyst agent in a governed autonomous cyber-defence system.

Your ONLY job is to analyse the alert provided and return a structured JSON object.

You MUST output ONLY valid JSON — no extra text, no markdown fences.

JSON schema (all fields required):
{
  "triage":         "<Benign|Suspicious|Malicious>",
  "confidence":     <float 0.0-1.0>,
  "recommendation": "<Monitor|Isolate-Host|Block-Account|Escalate-HITL>",
  "affected_system": "<string>",
  "rationale":      "<one or two sentences explaining your reasoning>"
}

Rules:
- If you cannot determine intent with confidence >= 0.60, set recommendation to "Escalate-HITL".
- Do not recommend Isolate-Host or Block-Account if confidence < 0.75.
- Base your triage only on the alert content provided. Do not invent facts.
"""

PLANNER_SYSTEM = """You are a Planner agent responsible for POLICY ENFORCEMENT in a governed
autonomous cyber-defence system.

You receive the Analyst's JSON output and must apply the following rules STRICTLY.
Rules are enforced in code — your job is to explain the decision clearly.

Rules:
  G1: If confidence < 0.60 → override recommendation to Escalate-HITL (cite G1).
  G2: If recommendation is Isolate-Host or Block-Account AND confidence < 0.75
      → override recommendation to Escalate-HITL (cite G2).
  G3: If you approve a high-impact action, you MUST include the exact token
      PLANNER_APPROVED in your response so the Executor can proceed.

Output format (plain text, not JSON):
  DECISION: <approved recommendation>
  RULE_APPLIED: <G1|G2|G3|None>
  GUARDRAIL_TRIGGERED: <Yes|No>
  PLANNER_APPROVED (include this token only when approving a high-impact action)
  RATIONALE: <brief explanation>
"""

EXECUTOR_SYSTEM = """You are the Executor agent in a governed autonomous cyber-defence system.

You ONLY execute the action approved by the Planner in the immediately preceding message.

Rules:
- If the action is Isolate-Host or Block-Account, you MUST see the token
  PLANNER_APPROVED in the Planner's message. If it is absent, log a
  HARD_STOP event and do NOT proceed.
- If the action is Escalate-HITL, log the escalation and stop.
- If the action is Monitor, log the monitoring action and stop.

Output format:
  ACTION_TAKEN: <action>
  OUTCOME: <Executed|Human-Escalation-Logged|Governance-Blocked>
  TIMESTAMP: <ISO-8601>
  NOTE: <any relevant observation>
"""


# ─── Decision Trace logger ─────────────────────────────────────────────────────
class TraceLogger:
    def __init__(self, scenario_id: str, run_id: int, log_dir: Path):
        self.scenario_id = scenario_id
        self.run_id      = run_id
        self.log_dir     = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.entries     = []

    def record(self, agent: str, tier: str, content: str):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scenario":  self.scenario_id,
            "run":       self.run_id,
            "agent":     agent,
            "tier":      tier,
            "content":   content.strip(),
        }
        self.entries.append(entry)
        return entry

    def save(self):
        fname = self.log_dir / f"{self.scenario_id}_run{self.run_id}.json"
        with open(fname, "w") as f:
            json.dump(self.entries, f, indent=2)
        return fname


# ─── Guardrail enforcement (code layer – not delegated to LLM) ────────────────
def enforce_guardrails(analyst_json: dict) -> dict:
    """
    Applies G1 and G2 deterministically.
    Returns a dict with keys: recommendation, rule_applied, guardrail_triggered.
    This is the CODE-LAYER enforcement that overrides any LLM policy drift.
    """
    rec        = analyst_json.get("recommendation", "Escalate-HITL")
    confidence = float(analyst_json.get("confidence", 0.0))
    rule       = "None"
    triggered  = False

    if confidence < CONFIDENCE_GATE:
        rec       = "Escalate-HITL"
        rule      = "G1"
        triggered = True
    elif rec in HIGH_IMPACT_ACTIONS and confidence < HIGH_IMPACT_GATE:
        rec       = "Escalate-HITL"
        rule      = "G2"
        triggered = True

    return {
        "recommendation":    rec,
        "rule_applied":      rule,
        "guardrail_triggered": triggered,
        "original_rec":      analyst_json.get("recommendation"),
        "confidence":        confidence,
    }


def parse_analyst_output(text: str) -> dict | None:
    """
    Extract the first JSON object from Analyst output.
    Coerces 'confidence' to a float immediately, since some models
    return it as a numeric string (e.g. "0.5") rather than a number,
    which would otherwise break every downstream consumer (guardrails,
    Decision Traces, CSV export, and the S3 history block formatting).
    """
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group())
    except json.JSONDecodeError:
        return None

    if "confidence" in data:
        try:
            data["confidence"] = float(data["confidence"])
        except (TypeError, ValueError):
            data["confidence"] = 0.0

    return data


# ─── Main pipeline ─────────────────────────────────────────────────────────────
def run_scenario(
    scenario_id: str,
    alert_prompt: str,
    run_id: int,
    log_dir: Path,
    verbose: bool = True,
) -> dict:
    """
    Execute the three-agent governed pipeline for one alert.
    Returns a summary dict with outcome classification.
    """
    tracer = TraceLogger(scenario_id, run_id, log_dir)

    # ── Create agents ──────────────────────────────────────────────────────────
    analyst = autogen.AssistantAgent(
        name="Analyst",
        system_message=ANALYST_SYSTEM,
        llm_config=LLM_CONFIG,
        human_input_mode="NEVER",
    )

    planner = autogen.AssistantAgent(
        name="Planner",
        system_message=PLANNER_SYSTEM,
        llm_config=LLM_CONFIG,
        human_input_mode="NEVER",
    )

    executor = autogen.UserProxyAgent(
        name="Executor",
        system_message=EXECUTOR_SYSTEM,
        llm_config=LLM_CONFIG,
        human_input_mode="NEVER",
        max_consecutive_auto_reply=1,
        code_execution_config=False,
    )

    # ── Step 1: Analyst triage ────────────────────────────────────────────────
    # NOTE: we use generate_reply() directly rather than initiate_chat(), because
    # initiate_chat(target, message=...) makes THIS agent the sender and the
    # target the responder. Since Analyst is the one with reasoning to do here,
    # we ask it directly via generate_reply() against a plain user-style message.
    analyst_prompt = f"ALERT:\n{alert_prompt}\n\nAnalyse this alert and return your JSON triage."
    analyst_raw = analyst.generate_reply(
        messages=[{"role": "user", "content": analyst_prompt}]
    )
    if isinstance(analyst_raw, dict):
        analyst_raw = analyst_raw.get("content", "")
    analyst_raw = analyst_raw or ""

    tracer.record("Analyst", "T1", analyst_raw)

    analyst_data = parse_analyst_output(analyst_raw)
    if analyst_data is None:
        analyst_data = {"triage": "Unknown", "confidence": 0.0,
                        "recommendation": "Escalate-HITL",
                        "affected_system": "Unknown",
                        "rationale": "Could not parse Analyst output."}

    # ── Step 2: Code-layer guardrail enforcement (G1 / G2) ───────────────────
    guardrail_result = enforce_guardrails(analyst_data)

    planner_briefing = (
        f"Analyst output:\n{json.dumps(analyst_data, indent=2)}\n\n"
        f"CODE-LAYER GUARDRAIL RESULT:\n"
        f"  Final recommendation : {guardrail_result['recommendation']}\n"
        f"  Rule applied         : {guardrail_result['rule_applied']}\n"
        f"  Guardrail triggered  : {guardrail_result['guardrail_triggered']}\n\n"
        f"Apply this decision. If approving a high-impact action, include PLANNER_APPROVED."
    )

    # ── Step 3: Planner decision ──────────────────────────────────────────────
    planner_raw = planner.generate_reply(
        messages=[{"role": "user", "content": planner_briefing}]
    )
    if isinstance(planner_raw, dict):
        planner_raw = planner_raw.get("content", "")
    planner_raw = planner_raw or ""

    tracer.record("Planner", "T2", planner_raw)

    # ── Step 4: G3 enforcement + Executor ────────────────────────────────────
    final_rec      = guardrail_result["recommendation"]
    planner_approved = "PLANNER_APPROVED" in planner_raw
    hard_stop        = False

    if final_rec in HIGH_IMPACT_ACTIONS and not planner_approved:
        # G3: hard stop – Executor must not proceed
        executor_note = (
            f"ACTION_TAKEN: {final_rec}\n"
            f"OUTCOME: Governance-Blocked\n"
            f"TIMESTAMP: {datetime.now(timezone.utc).isoformat()}\n"
            f"NOTE: G3 hard stop – PLANNER_APPROVED token absent."
        )
        hard_stop = True
    elif final_rec == "Escalate-HITL":
        executor_note = (
            f"ACTION_TAKEN: Escalate-HITL\n"
            f"OUTCOME: Human-Escalation-Logged\n"
            f"TIMESTAMP: {datetime.now(timezone.utc).isoformat()}\n"
            f"NOTE: Escalation logged. Human analyst notified."
        )
    else:
        executor_note = (
            f"ACTION_TAKEN: {final_rec}\n"
            f"OUTCOME: Executed\n"
            f"TIMESTAMP: {datetime.now(timezone.utc).isoformat()}\n"
            f"NOTE: Action authorised and executed."
        )

    tracer.record("Executor", "T3", executor_note)
    trace_file = tracer.save()

    summary = {
        "scenario_id":        scenario_id,
        "run_id":             run_id,
        "triage":             analyst_data.get("triage"),
        "confidence":         analyst_data.get("confidence"),
        "original_rec":       guardrail_result["original_rec"],
        "final_action":       final_rec,
        "guardrail_triggered": guardrail_result["guardrail_triggered"],
        "rule_applied":       guardrail_result["rule_applied"],
        "hard_stop":          hard_stop,
        "trace_file":         str(trace_file),
    }

    if verbose:
        print(f"\n{'='*60}")
        print(f"SCENARIO {scenario_id}  RUN {run_id}  SUMMARY")
        print(f"{'='*60}")
        for k, v in summary.items():
            print(f"  {k:<25} {v}")
        print()

    return summary
