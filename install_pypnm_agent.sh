#!/bin/bash
# pyPNMAgent standalone install script
# Usage: ./install_pypnm_agent.sh
set -e

# 1. Prompt for config
read -r -p "Agent ID: " PYPNM_AGENT_ID
read -r -p "PyPNM API WebSocket URL (e.g. ws://<api_host>:8000/api/agents/ws): " PYPNM_SERVER_URL
read -r -p "Agent token: " PYPNM_AGENT_TOKEN
read -r -s -p "CMTS SNMP community (leave empty to require an explicit task community): " CMTS_COMMUNITY
printf '\n'
read -r -s -p "CMTS SNMP write community (leave empty to require an explicit task community): " CMTS_WRITE_COMMUNITY
printf '\n'
read -r -s -p "Cable modem SNMP community (leave empty to require an explicit task community): " CM_COMMUNITY
printf '\n'
read -r -s -p "Cable modem SNMP write community (leave empty to require an explicit task community): " CM_WRITE_COMMUNITY
printf '\n'

# 2. Write agent_config.json using Python (env vars avoid JSON-escaping issues)
PYPNM_AGENT_ID="$PYPNM_AGENT_ID" \
PYPNM_SERVER_URL="$PYPNM_SERVER_URL" \
PYPNM_AGENT_TOKEN="$PYPNM_AGENT_TOKEN" \
CMTS_COMMUNITY="$CMTS_COMMUNITY" \
CMTS_WRITE_COMMUNITY="$CMTS_WRITE_COMMUNITY" \
CM_COMMUNITY="$CM_COMMUNITY" \
CM_WRITE_COMMUNITY="$CM_WRITE_COMMUNITY" \
python3 - <<'PYEOF'
import json
import os

def optional_community(name):
    value = os.environ[name]
    return value if value.strip() else None


cmts_access = {"enabled": True}
cmts_community = optional_community("CMTS_COMMUNITY")
if cmts_community is not None:
    cmts_access["community"] = cmts_community
cmts_write_community = optional_community("CMTS_WRITE_COMMUNITY")
if cmts_write_community is not None:
    cmts_access["write_community"] = cmts_write_community

cm_access = {"enabled": True}
cm_community = optional_community("CM_COMMUNITY")
if cm_community is not None:
    cm_access["community"] = cm_community
cm_write_community = optional_community("CM_WRITE_COMMUNITY")
if cm_write_community is not None:
    cm_access["write_community"] = cm_write_community

config = {
    "agent_id": os.environ["PYPNM_AGENT_ID"],
    "server_url": os.environ["PYPNM_SERVER_URL"],
    "token": os.environ["PYPNM_AGENT_TOKEN"],
    "cmts_access": cmts_access,
    "cm_access": cm_access,
}

with open("agent_config.json", "w") as f:
    json.dump(config, f, indent=2)
    f.write("\n")

# Validate round-trip
with open("agent_config.json") as f:
    json.load(f)
print("[INFO] agent_config.json written and validated OK")
PYEOF

# 3. Set up Python venv and install requirements
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[INFO] pyPNMAgent installed. To start:"
echo "source venv/bin/activate && python agent.py -c agent_config.json"
