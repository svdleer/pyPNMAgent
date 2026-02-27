#!/bin/bash
# pyPNMAgent standalone install script
# Usage: ./install_pypnm_agent.sh
set -e

# 1. Prompt for config
read -p "Agent ID: " AGENT_ID
read -p "PyPNM API WebSocket URL (e.g. ws://<api_host>:8000/api/ws/agent): " PYPNM_SERVER_URL
read -p "Agent token: " PYPNM_AGENT_TOKEN
read -p "SNMP community (ARRIS): " SNMP_COMMUNITY_ARRIS
read -p "SNMP community (CASA): " SNMP_COMMUNITY_CASA
read -p "SNMP community (CISCO): " SNMP_COMMUNITY_CISCO
read -p "SNMP community (COMMSCOPE): " SNMP_COMMUNITY_COMMSCOPE
read -p "Modem SNMP community: " CM_DIRECT_COMMUNITY
read -p "TFTP IPv4 (default 172.16.6.101): " TFTP_IPV4
TFTP_IPV4=${TFTP_IPV4:-172.16.6.101}
read -p "TFTP IPv4 ALT (default 172.22.147.18): " TFTP_IPV4_ALT
TFTP_IPV4_ALT=${TFTP_IPV4_ALT:-172.22.147.18}

# 2. Write agent_config.json using Python (env vars avoid JSON-escaping issues)
AGENT_ID="$AGENT_ID" \
PYPNM_SERVER_URL="$PYPNM_SERVER_URL" \
PYPNM_AGENT_TOKEN="$PYPNM_AGENT_TOKEN" \
SNMP_COMMUNITY_ARRIS="$SNMP_COMMUNITY_ARRIS" \
SNMP_COMMUNITY_CASA="$SNMP_COMMUNITY_CASA" \
SNMP_COMMUNITY_CISCO="$SNMP_COMMUNITY_CISCO" \
SNMP_COMMUNITY_COMMSCOPE="$SNMP_COMMUNITY_COMMSCOPE" \
CM_DIRECT_COMMUNITY="$CM_DIRECT_COMMUNITY" \
TFTP_IPV4="$TFTP_IPV4" \
TFTP_IPV4_ALT="$TFTP_IPV4_ALT" \
python3 - <<'PYEOF'
import json, os

config = {
  "agent_id":   os.environ["AGENT_ID"],
  "server_url": os.environ["PYPNM_SERVER_URL"],
  "token":      os.environ["PYPNM_AGENT_TOKEN"],
  "snmp_communities": {
    "arris":     os.environ["SNMP_COMMUNITY_ARRIS"],
    "casa":      os.environ["SNMP_COMMUNITY_CASA"],
    "cisco":     os.environ["SNMP_COMMUNITY_CISCO"],
    "commscope": os.environ["SNMP_COMMUNITY_COMMSCOPE"],
  },
  "modem_community": os.environ["CM_DIRECT_COMMUNITY"],
  "tftp_ipv4":       os.environ["TFTP_IPV4"],
  "tftp_ipv4_alt":   os.environ["TFTP_IPV4_ALT"],
}

with open("agent_config.json", "w") as f:
    json.dump(config, f, indent=2)
    f.write("\n")

# Validate round-trip
json.load(open("agent_config.json"))
print("[INFO] agent_config.json written and validated OK")
PYEOF

# 3. Set up Python venv and install requirements
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[INFO] pyPNMAgent installed. To start:"
echo "source venv/bin/activate && python agent.py -c agent_config.json"
