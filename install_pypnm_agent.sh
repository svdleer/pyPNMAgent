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

# 2. Write agent_config.json
cat > agent_config.json <<EOF
{
  "agent_id": "$AGENT_ID",
  "server_url": "$PYPNM_SERVER_URL",
  "token": "$PYPNM_AGENT_TOKEN",
  "snmp_communities": {
    "arris": "$SNMP_COMMUNITY_ARRIS",
    "casa": "$SNMP_COMMUNITY_CASA",
    "cisco": "$SNMP_COMMUNITY_CISCO",
    "commscope": "$SNMP_COMMUNITY_COMMSCOPE"
  },
  "modem_community": "$CM_DIRECT_COMMUNITY",
  "tftp_ipv4": "$TFTP_IPV4",
  "tftp_ipv4_alt": "$TFTP_IPV4_ALT"
}
EOF

# 3. Set up Python venv and install requirements
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[INFO] pyPNMAgent installed. To start:"
echo "source venv/bin/activate && python agent.py -c agent_config.json"
