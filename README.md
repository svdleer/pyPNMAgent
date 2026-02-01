# PyPNM Agent

Remote agent for PyPNM that runs on a jump server with access to DOCSIS network equipment (CMTS, cable modems, TFTP servers).

## Features

- **CMTS Access**: SNMP queries and CLI commands to CMTS devices
- **Cable Modem Access**: Direct or proxy-based SNMP to cable modems
- **PNM Measurements**: Trigger and retrieve Proactive Network Maintenance data
- **WebSocket Connection**: Secure connection to PyPNM GUI server
- **pysnmp v7**: Pure Python SNMP - no net-snmp dependency

## Quick Start

### Docker (Recommended)

```bash
# Build
docker build -t pypnm-agent -f docker/Dockerfile .

# Run
docker run -d \
  --name pypnm-agent \
  -v ./config:/app/config:ro \
  -v ~/.ssh:/home/pypnm/.ssh:ro \
  pypnm-agent
```

### Manual Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and edit config
cp agent_config.example.json agent_config.json
# Edit agent_config.json with your settings

# Run
python agent.py -c agent_config.json
```

### Systemd Service

```bash
# Copy service file
sudo cp systemd/pypnm-agent.service /etc/systemd/system/

# Enable and start
sudo systemctl enable pypnm-agent
sudo systemctl start pypnm-agent
```

## Configuration

See `agent_config.example.json` for all options:

```json
{
    "agent_id": "jump-server-01",
    "pypnm_server": {
        "url": "ws://pypnm-gui:5050/ws/agent",
        "auth_token": "your-token"
    },
    "cmts_access": {
        "enabled": true,
        "community": "public",
        "write_community": "private"
    },
    "cm_access": {
        "enabled": true,
        "community": "m0d3m1nf0"
    }
}
```

## Capabilities

The agent reports its capabilities to the server:

| Capability | Description |
|------------|-------------|
| `cmts_reachable` | Can reach CMTS devices |
| `cm_reachable` | Can reach cable modems |
| `snmp_get/walk/set` | SNMP operations |
| `pnm_*` | PNM measurement commands |

## License

Apache-2.0
