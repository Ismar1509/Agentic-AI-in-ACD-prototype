#!/usr/bin/env bash
# ============================================================
#  00_setup.sh  –  One-time environment setup
#  Tested on Linux Mint 21+ (Ubuntu 22.04 base)
#  Run once before any experiment scripts.
# ============================================================

set -e

echo "=== [1/5] Updating package lists ==="
sudo apt-get update -qq

echo "=== [2/5] Installing Python 3, pip, curl ==="
sudo apt-get install -y python3 python3-pip python3-venv curl

# ── Ollama ────────────────────────────────────────────────
echo "=== [3/5] Installing Ollama ==="
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "    Ollama already installed – skipping."
fi

# Pull the model (quantised 4-bit, ~4 GB download)
echo "=== [4/5] Pulling mistral:7b-instruct model (this may take a while) ==="
ollama pull mistral   # already pulled if you followed the chat instructions

# ── Python virtual environment ────────────────────────────
echo "=== [5/5] Creating Python venv and installing dependencies ==="
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip -q
pip install -q \
    "pyautogen==0.2.35" \
    "openai>=1.0.0" \
    "rich"       # pretty console output

echo ""
echo "✅  Setup complete."
echo "    Activate the environment before running experiments:"
echo "    source .venv/bin/activate"
