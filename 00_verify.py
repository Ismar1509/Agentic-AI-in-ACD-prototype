"""
00_verify.py  –  Pre-flight Check
==================================
Run this BEFORE the main experiment to confirm:
  1. Ollama is running and the model is loaded
  2. AutoGen can communicate with Ollama
  3. The Analyst produces parseable JSON

Usage:
  python 00_verify.py
"""

import json, re, sys, urllib.request

try:
    import autogen
    from rich.console import Console
except ImportError:
    sys.exit("Activate your venv first:  source .venv/bin/activate")

console = Console()

OLLAMA_URL = "http://localhost:11434"

# ─── Step 1: Ollama reachable? ────────────────────────────────────────────────
console.rule("[bold blue]Step 1: Ollama connectivity[/bold blue]")
try:
    urllib.request.urlopen(OLLAMA_URL, timeout=5)
    console.print("[green]✓ Ollama is running[/green]")
except Exception as e:
    console.print(f"[red]✗ Cannot reach Ollama at {OLLAMA_URL}[/red]")
    console.print("  Start with:  [bold]ollama serve[/bold]")
    sys.exit(1)

# ─── Step 2: Model available? ─────────────────────────────────────────────────
console.rule("[bold blue]Step 2: Model availability[/bold blue]")
try:
    with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=5) as resp:
        data = json.loads(resp.read())
    models = [m["name"] for m in data.get("models", [])]
    target = "mistral:7b-instruct-q4_0"
    if any(target in m for m in models):
        console.print(f"[green]✓ Model '{target}' is available[/green]")
    else:
        console.print(f"[yellow]⚠ Model '{target}' not found. Available: {models}[/yellow]")
        console.print(f"  Pull it with:  [bold]ollama pull {target}[/bold]")
        sys.exit(1)
except Exception as e:
    console.print(f"[red]✗ Could not query model list: {e}[/red]")
    sys.exit(1)

# ─── Step 3: AutoGen → Ollama round-trip ─────────────────────────────────────
console.rule("[bold blue]Step 3: AutoGen round-trip test[/bold blue]")

LLM_CONFIG = {
    "config_list": [{
        "model":    "mistral:7b-instruct-q4_0",
        "base_url": "http://localhost:11434/v1",
        "api_key":  "ollama",
        "temperature": 0.0,
        "max_tokens":  200,
    }],
    "cache_seed": None,
}

tester = autogen.AssistantAgent(
    name="Tester",
    system_message=(
        "You are a JSON test agent. "
        "Return ONLY this exact JSON: "
        '{"status": "ok", "model": "mistral"}'
    ),
    llm_config=LLM_CONFIG,
    human_input_mode="NEVER",
)

proxy = autogen.UserProxyAgent(
    name="Proxy",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=1,
    code_execution_config=False,
)

try:
    proxy.initiate_chat(tester, message="Ping.", max_turns=1, silent=True)
    reply = tester.last_message(proxy)["content"]
    match = re.search(r'\{.*\}', reply, re.DOTALL)
    if match:
        parsed = json.loads(match.group())
        console.print(f"[green]✓ AutoGen round-trip OK. Response: {parsed}[/green]")
    else:
        console.print(f"[yellow]⚠ Response not JSON – model may need warming up.[/yellow]")
        console.print(f"  Raw: {reply[:200]}")
except Exception as e:
    console.print(f"[red]✗ AutoGen→Ollama communication failed: {e}[/red]")
    sys.exit(1)

# ─── Step 4: Analyst JSON format test ────────────────────────────────────────
console.rule("[bold blue]Step 4: Analyst JSON format test[/bold blue]")

from agents import ANALYST_SYSTEM, LLM_CONFIG as AGENT_LLM_CONFIG, parse_analyst_output

analyst = autogen.AssistantAgent(
    name="Analyst",
    system_message=ANALYST_SYSTEM,
    llm_config=AGENT_LLM_CONFIG,
    human_input_mode="NEVER",
)
probe = autogen.UserProxyAgent(
    name="Probe",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=1,
    code_execution_config=False,
)

TEST_ALERT = """
ALERT TYPE    : Test Alert
AFFECTED SYSTEM: TEST-HOST-01
TIMESTAMP     : 2024-01-01T00:00:00Z
OBSERVABLE INDICATORS:
  - Suspicious login from unusual IP.
  - Confidence hint: 0.50 (ambiguous)
"""

try:
    analyst_prompt = f"ALERT:\n{TEST_ALERT}\n\nReturn your JSON triage."
    raw = analyst.generate_reply(
        messages=[{"role": "user", "content": analyst_prompt}]
    )
    if isinstance(raw, dict):
        raw = raw.get("content", "")
    raw = raw or ""

    parsed = parse_analyst_output(raw)

    if parsed and all(k in parsed for k in ["triage", "confidence", "recommendation"]):
        try:
            conf_val = float(parsed["confidence"])
        except (TypeError, ValueError):
            conf_val = 0.0
        console.print(f"[green]✓ Analyst produces valid JSON[/green]")
        console.print(f"  triage={parsed['triage']}, confidence={conf_val:.2f}, "
                      f"rec={parsed['recommendation']}")
    else:
        console.print(f"[yellow]⚠ Analyst output not fully parseable.[/yellow]")
        console.print(f"  Raw (first 300 chars): {raw[:300]}")
except Exception as e:
    console.print(f"[red]✗ Analyst test failed: {e}[/red]")
    sys.exit(1)

console.rule()
console.print("\n[bold green]✅  All checks passed. Ready to run the experiment.[/bold green]")
console.print("  Next step:  [bold]python 01_run_experiment.py[/bold]\n")
