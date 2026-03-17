#!/usr/bin/env bash
# push-agent.sh — pull latest agent.py and push to all jump-server hosts
#
# SETUP:
#   cp scripts/push-agent.example.sh deploy/push-agent.sh
#   chmod +x deploy/push-agent.sh
#   # Edit AGENT_HOSTS in deploy/push-agent.sh with your real hosts
#   ./deploy/push-agent.sh
#
# NOTE: deploy/push-agent.sh is in .gitignore (contains real hostnames/users)

set -euo pipefail

# ── Agent hosts ──────────────────────────────────────────────────────────────
# Format: "user@host"
AGENT_HOSTS=(
    "user@jump-server-1"
    "user@jump-server-2"
    "user@jump-server-3"
)
SSH_PORT=22
REMOTE_DIR="~/.pypnm-agent"
# ─────────────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_PY="$REPO_ROOT/agent.py"

echo "[1/2] git pull"
git -C "$REPO_ROOT" pull origin main

echo
echo "[2/2] deploying agent.py to ${#AGENT_HOSTS[@]} host(s)"

ok=0
fail=0
for target in "${AGENT_HOSTS[@]}"; do
    echo -n "  scp → ${target}:${REMOTE_DIR}/agent.py ... "
    if scp -P "$SSH_PORT" -q "$AGENT_PY" "${target}:${REMOTE_DIR}/agent.py"; then
        echo "OK"
        echo -n "  restart → ${target} ... "
        if ssh -p "$SSH_PORT" "$target" "cd ${REMOTE_DIR} && bash run_background.sh restart"; then
            echo "OK"
        else
            echo "FAILED (agent.py deployed but restart failed — restart manually)"
        fi
        ((ok++)) || true
    else
        echo "FAILED"
        ((fail++)) || true
    fi
    echo
done

echo "Done: $ok succeeded, $fail failed."
