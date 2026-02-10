# PyPNM Agent Installation Guide

## Prerequisites

- Python 3.10+ (or Docker)
- Network access to:
  - PyPNM GUI Server (WebSocket port 5050)
  - CMTS devices (SNMP UDP/161)
  - Cable modems (if cm_access enabled)
  - TFTP server (if using PNM file retrieval)

## Installation Methods

### 1. Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/svdleer/pyPNMAgent.git
cd pyPNMAgent

# Create config directory
mkdir -p config

# Copy and edit configuration
cp agent_config.example.json config/agent_config.json
nano config/agent_config.json

# Build and start
docker compose up -d

# Check logs
docker logs -f pypnm-agent
```

### 2. Manual Installation

```bash
# Clone
git clone https://github.com/svdleer/pyPNMAgent.git
cd pyPNMAgent

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp agent_config.example.json agent_config.json
nano agent_config.json

# Run
python agent.py -c agent_config.json
```

### 3. Systemd Service

```bash
# Install as above, then:
sudo cp systemd/pypnm-agent.service /etc/systemd/system/

# Edit the service file to set correct paths
sudo nano /etc/systemd/system/pypnm-agent.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable pypnm-agent
sudo systemctl start pypnm-agent

# Check status
sudo systemctl status pypnm-agent
journalctl -u pypnm-agent -f
```

## Configuration

Edit `agent_config.json`:

```json
{
    "agent_id": "your-agent-name",
    "pypnm_server": {
        "url": "ws://your-pypnm-gui-server:5050/ws/agent",
        "auth_token": "optional-auth-token"
    },
    "cmts_access": {
        "enabled": true,
        "community": "your-cmts-read-community",
        "write_community": "your-cmts-write-community",
        "ssh_enabled": false,
        "ssh_user": "admin",
        "ssh_key_file": "~/.ssh/id_rsa"
    },
    "cm_access": {
        "enabled": false,
        "community": "your-cm-community",
        "proxy": {
            "host": "proxy-host-if-needed",
            "user": "ssh-user",
            "key_file": "~/.ssh/id_rsa"
        }
    },
    "tftp_server": {
        "tftp_path": "/tftpboot"
    }
}
```

### Configuration Options

| Section | Option | Description |
|---------|--------|-------------|
| `agent_id` | - | Unique identifier for this agent |
| `pypnm_server.url` | - | WebSocket URL of PyPNM GUI server |
| `cmts_access.enabled` | - | Enable CMTS SNMP access |
| `cmts_access.community` | - | SNMP read community for CMTS |
| `cmts_access.write_community` | - | SNMP write community (for PNM triggers) |
| `cm_access.enabled` | - | Enable cable modem SNMP access |
| `cm_access.community` | - | SNMP community for cable modems |
| `cm_access.proxy` | - | SSH proxy settings if CMs not directly reachable |

## Verification

Check the agent is connected:

```bash
# Docker
docker logs pypnm-agent | grep -i "connected\|authenticated"

# Or check from GUI server
curl http://your-gui-server:5050/api/pypnm/health
```

Expected output:
```json
{
    "status": "ok",
    "connected_agents": 1,
    "cmts_capable_agents": 1,
    "cm_capable_agents": 0
}
```

## Troubleshooting

### Agent won't connect

1. Check WebSocket URL is correct
2. Verify network connectivity: `curl -v ws://gui-server:5050/ws/agent`
3. Check firewall allows WebSocket connections

### SNMP queries fail

1. Verify SNMP community strings
2. Test SNMP manually: `snmpwalk -v2c -c community cmts-ip 1.3.6.1.2.1.1.1`
3. Check agent has network route to CMTS/modems

### Agent keeps disconnecting

1. Check for network instability
2. Increase `reconnect_interval` in config
3. Check GUI server logs for errors
