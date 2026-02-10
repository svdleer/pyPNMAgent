# PyPNM Agent

Remote agent for [PyPNM](https://github.com/svdleer/PyPNM) that runs on a jump server with network access to DOCSIS equipment (CMTS, cable modems, TFTP servers).

## Features

- **Pure Python SNMP** - Uses pysnmp v7, no net-snmp dependency
- **CMTS Access** - SNMP queries and optional SSH CLI to CMTS devices
- **Cable Modem Access** - Direct or proxy-based SNMP to cable modems
- **PNM Measurements** - Trigger and retrieve Proactive Network Maintenance data
  - Downstream RxMER, Spectrum, Channel Estimation
  - Upstream OFDMA RxMER and UTSC
- **Secure Connection** - WebSocket with authentication to PyPNM GUI server
- **Capability-based Routing** - Advertises capabilities for smart task routing

## Quick Start

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

### Docker (Recommended)

```bash
git clone https://github.com/svdleer/pyPNMAgent.git
cd pyPNMAgent
mkdir -p config
cp agent_config.example.json config/agent_config.json
# Edit config/agent_config.json
docker compose up -d
```

### Manual

```bash
pip install -r requirements.txt
cp agent_config.example.json agent_config.json
python agent.py -c agent_config.json
```

## Configuration

```json
{
    "agent_id": "jump-server-01",
    "pypnm_server": {
        "url": "ws://pypnm-gui:5050/ws/agent",
        "auth_token": "your-token"
    },
    "cmts_access": {
        "enabled": true,
        "community": "public"
    },
    "cm_access": {
        "enabled": false,
        "community": "your-cm-community"
    }
}
```

## Capabilities

| Capability | Description |
|------------|-------------|
| `cmts_reachable` | Can reach CMTS devices for SNMP |
| `cm_reachable` | Can reach cable modems for SNMP |
| `snmp_get/walk/set` | SNMP operations |
| `pnm_ofdm_rxmer` | Downstream RxMER measurements |
| `pnm_us_rxmer_*` | Upstream OFDMA RxMER |
| `pnm_utsc_*` | Upstream Triggered Spectrum Capture |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENT_ID` | Unique agent identifier | `pypnm-agent-01` |
| `SERVER_URL` | PyPNM GUI WebSocket URL | `ws://localhost:5050/ws/agent` |
| `PYPNM_CMTS_ENABLED` | Enable CMTS access | `true` |
| `PYPNM_CM_ENABLED` | Enable CM access | `false` |

## License

Apache-2.0
