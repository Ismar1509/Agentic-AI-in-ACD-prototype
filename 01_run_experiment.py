"""
01_run_experiment.py  –  Main Experiment Runner
================================================
Runs all three scenarios (S1, S2, S3) with 3 runs each,
saves Decision Traces to logs/, and writes a summary CSV.

Usage:
  python 01_run_experiment.py                  # all scenarios
  python 01_run_experiment.py --scenario S1    # single scenario
  python 01_run_experiment.py --scenario S2 --runs 1

Decision Traces are saved to:
  logs/<SCENARIO_ID>_run<N>.json

Summary CSV is saved to:
  results/experiment_summary.csv
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

# ── graceful import check ──────────────────────────────────────────────────────
try:
    import autogen
    from rich.console import Console
    from rich.table import Table
except ImportError:
    sys.exit(
        "Missing dependencies. Run:  source .venv/bin/activate  then retry.\n"
        "If you haven't set up yet, run:  bash 00_setup.sh"
    )

from agents import run_scenario
from scenarios import SCENARIOS

console = Console()

LOG_DIR     = Path("logs")
RESULTS_DIR = Path("results")
LOG_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

NUM_RUNS = 3


# ─── S3 multi-turn handler ─────────────────────────────────────────────────────
def run_s3_multiturn(run_id: int, verbose: bool) -> dict:
    """
    S3 feeds four alerts sequentially, prepending conversation history
    to each subsequent turn so the Analyst can reference the full chain.
    Returns a summary dict representing the final (most severe) outcome.
    """
    from agents import (
        OLLAMA_CONFIG, LLM_CONFIG, ANALYST_SYSTEM, PLANNER_SYSTEM, EXECUTOR_SYSTEM,
        enforce_guardrails, parse_analyst_output, TraceLogger
    )
    import autogen
    import json
    from datetime import datetime, timezone
    from scenarios import S3_TURN_1, S3_TURN_2, S3_TURN_3, S3_TURN_4

    turns    = [S3_TURN_1, S3_TURN_2, S3_TURN_3, S3_TURN_4]
    history  = []
    tracer   = TraceLogger("S3", run_id, LOG_DIR)
    summaries = []

    for turn_idx, alert in enumerate(turns, start=1):
        console.print(f"  [dim]S3 Turn {turn_idx}/4...[/dim]")

        # Build prompt including prior chain context
        if history:
            history_block = "\n\nPREVIOUS ANALYST OUTPUTS THIS CHAIN:\n"
            for h in history:
                history_block += f"  Turn {h['turn']}: triage={h['triage']}, " \
                                 f"confidence={h['confidence']:.2f}, " \
                                 f"recommendation={h['recommendation']}\n"
            full_prompt = alert + history_block
        else:
            full_prompt = alert

        analyst = autogen.AssistantAgent(
            name="Analyst", system_message=ANALYST_SYSTEM,
            llm_config=LLM_CONFIG, human_input_mode="NEVER",
        )
        planner = autogen.AssistantAgent(
            name="Planner", system_message=PLANNER_SYSTEM,
            llm_config=LLM_CONFIG, human_input_mode="NEVER",
        )
        executor = autogen.UserProxyAgent(
            name="Executor", system_message=EXECUTOR_SYSTEM,
            llm_config=LLM_CONFIG, human_input_mode="NEVER",
            max_consecutive_auto_reply=1, code_execution_config=False,
        )

        analyst_prompt = f"ALERT:\n{full_prompt}\n\nAnalyse and return your JSON triage."
        analyst_raw = analyst.generate_reply(
            messages=[{"role": "user", "content": analyst_prompt}]
        )
        if isinstance(analyst_raw, dict):
            analyst_raw = analyst_raw.get("content", "")
        analyst_raw = analyst_raw or ""

        analyst_data = parse_analyst_output(analyst_raw) or {
            "triage": "Unknown", "confidence": 0.0,
            "recommendation": "Escalate-HITL",
            "affected_system": "Unknown",
            "rationale": "Parse failure."
        }

        tracer.record("Analyst", f"T{turn_idx}-T1", analyst_raw)

        guardrail_result = enforce_guardrails(analyst_data)

        planner_briefing = (
            f"Analyst output:\n{json.dumps(analyst_data, indent=2)}\n\n"
            f"CODE-LAYER GUARDRAIL:\n"
            f"  Final recommendation : {guardrail_result['recommendation']}\n"
            f"  Rule applied         : {guardrail_result['rule_applied']}\n"
            f"  Guardrail triggered  : {guardrail_result['guardrail_triggered']}\n\n"
            f"Apply this decision."
        )

        planner_raw = planner.generate_reply(
            messages=[{"role": "user", "content": planner_briefing}]
        )
        if isinstance(planner_raw, dict):
            planner_raw = planner_raw.get("content", "")
        planner_raw = planner_raw or ""

        planner_approved  = "PLANNER_APPROVED" in planner_raw
        final_rec         = guardrail_result["recommendation"]

        tracer.record("Planner", f"T{turn_idx}-T2", planner_raw)

        if final_rec in {"Isolate-Host", "Block-Account"} and not planner_approved:
            outcome = "Governance-Blocked"
        elif final_rec == "Escalate-HITL":
            outcome = "Human-Escalation-Logged"
        else:
            outcome = "Executed"

        executor_note = (
            f"ACTION_TAKEN: {final_rec}\n"
            f"OUTCOME: {outcome}\n"
            f"TIMESTAMP: {datetime.now(timezone.utc).isoformat()}\n"
            f"CHAIN_STAGE: {turn_idx}"
        )
        tracer.record("Executor", f"T{turn_idx}-T3", executor_note)

        history.append({
            "turn":           turn_idx,
            "triage":         analyst_data.get("triage"),
            "confidence":     analyst_data.get("confidence", 0.0),
            "recommendation": final_rec,
            "outcome":        outcome,
        })
        summaries.append(history[-1])

    trace_file = tracer.save()

    # Final outcome = most severe across the chain
    severity_order = ["Executed", "Human-Escalation-Logged", "Governance-Blocked"]
    final_outcome  = max(summaries, key=lambda x: severity_order.index(x["outcome"])
                         if x["outcome"] in severity_order else 0)

    return {
        "scenario_id":         "S3",
        "run_id":              run_id,
        "triage":              history[-1]["triage"],
        "confidence":          history[-1]["confidence"],
        "original_rec":        history[-1]["recommendation"],
        "final_action":        history[-1]["recommendation"],
        "guardrail_triggered": any(
            enforce_guardrails({"confidence": h["confidence"],
                                "recommendation": h["recommendation"]})
            ["guardrail_triggered"] for h in history
        ),
        "rule_applied":        "Multi-turn",
        "hard_stop":           False,
        "trace_file":          str(trace_file),
    }


# ─── Helpers ───────────────────────────────────────────────────────────────────
def check_ollama():
    import urllib.request, urllib.error
    try:
        urllib.request.urlopen("http://localhost:11434", timeout=3)
    except Exception:
        console.print("[bold red]ERROR:[/bold red] Ollama is not running.")
        console.print("Start it with:  [bold]ollama serve[/bold]")
        sys.exit(1)


def save_summary(all_results: list):
    csv_path = RESULTS_DIR / "experiment_summary.csv"
    fieldnames = [
        "scenario_id", "run_id", "triage", "confidence",
        "original_rec", "final_action", "guardrail_triggered",
        "rule_applied", "hard_stop", "trace_file"
    ]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)
    return csv_path


def print_summary_table(all_results: list):
    tbl = Table(title="Experiment Summary", show_lines=True)
    tbl.add_column("Scenario", style="cyan")
    tbl.add_column("Run", justify="right")
    tbl.add_column("Triage")
    tbl.add_column("Conf.", justify="right")
    tbl.add_column("Final Action")
    tbl.add_column("Guardrail", justify="center")
    tbl.add_column("Rule")

    for r in all_results:
        guardrail_str = "[green]Yes[/green]" if r["guardrail_triggered"] else "[grey50]No[/grey50]"
        conf_str      = f"{float(r['confidence']):.2f}" if r["confidence"] else "—"
        tbl.add_row(
            r["scenario_id"], str(r["run_id"]), str(r["triage"]),
            conf_str, str(r["final_action"]),
            guardrail_str, str(r["rule_applied"])
        )
    console.print(tbl)


# ─── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Run thesis experiment pipeline")
    parser.add_argument("--scenario", choices=["S1","S2","S3"], default=None,
                        help="Run only this scenario (default: all)")
    parser.add_argument("--runs", type=int, default=NUM_RUNS,
                        help="Number of runs per scenario (default: 3)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show full agent conversation output")
    args = parser.parse_args()

    check_ollama()

    targets = [args.scenario] if args.scenario else ["S1", "S2", "S3"]
    all_results = []

    for scenario_id in targets:
        scenario = SCENARIOS[scenario_id]
        console.rule(f"[bold blue]Scenario {scenario_id}: {scenario['name']}[/bold blue]")

        for run_id in range(1, args.runs + 1):
            console.print(f"  Run [bold]{run_id}/{args.runs}[/bold] …")
            start = time.time()

            try:
                if scenario_id == "S3":
                    result = run_s3_multiturn(run_id, args.verbose)
                else:
                    alerts = scenario["alerts"]
                    alert  = alerts[min(run_id - 1, len(alerts) - 1)]
                    result = run_scenario(
                        scenario_id, alert, run_id, LOG_DIR, verbose=args.verbose
                    )
            except Exception as exc:
                console.print(f"  [red]Run {run_id} failed:[/red] {exc}")
                result = {
                    "scenario_id": scenario_id, "run_id": run_id,
                    "triage": "ERROR", "confidence": 0.0,
                    "original_rec": "ERROR", "final_action": "ERROR",
                    "guardrail_triggered": False, "rule_applied": "N/A",
                    "hard_stop": False, "trace_file": "N/A",
                }

            elapsed = time.time() - start
            console.print(
                f"  [green]✓[/green] Done in {elapsed:.1f}s  │  "
                f"Action: [bold]{result.get('final_action')}[/bold]  │  "
                f"Guardrail: {result.get('rule_applied')}"
            )
            all_results.append(result)

    print_summary_table(all_results)
    csv_path = save_summary(all_results)
    console.print(f"\n[bold green]All results saved to {csv_path}[/bold green]")
    console.print(f"Decision traces in: [bold]{LOG_DIR}/[/bold]")


if __name__ == "__main__":
    main()
