#!/usr/bin/env bash
# push-agent.sh — pull latest agent.py and push to all jump-server hosts
# Usage: ./deploy/push-agent.sh
#
# Edit AGENT_HOSTS and optionally SSH_USER / REMOTE_DIR below.

set -euo pipefail

# ── Configure hosts here ─────────────────────────────────────────────────────
AGENT_HOSTS=(
    "jump-server-1"   # replace with real hostname or IP
    "jump-server-2"
    "jump-server-3"
)
SSH_USER="svdleer"
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
for host in "${AGENT_HOSTS[@]}"; do
    echo -n "  scp → ${SSH_USER}@${host}:${REMOTE_DIR}/agent.py ... "
    if scp -P "$SSH_PORT" -q "$AGENT_PY" "${SSH_USER}@${host}:${REMOTE_DIR}/agent.py"; then
        echo "OK"
        ((ok++)) || true
    else
        echo "FAILED"
        ((fail++)) || true
    fi
done

echo
echo "Done: $ok succeeded, $fail failed."
echo "Restart the agent process on each host to pick up the new code."
