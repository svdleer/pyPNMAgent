# PyPNM Agent

Remote agent for [PyPNM](https://github.com/svdleer/PyPNM) that runs on a jump server with network access to DOCSIS equipment (CMTS, cable modems, TFTP servers).

## Features

- **Pure Python SNMP** - Uses pysnmp v7, no net-snmp dependency
- **CMTS Access** - SNMP queries and optional SSH CLI to CMTS devices
- **Cable Modem Access** - Direct or proxy-based SNMP to cable modems
- **PNM Measurements** - Trigger and retrieve Proactive Network Maintenance data
  - Downstream RxMER, Spectrum, Channel Estimation
  - Upstream OFDMA RxMER and UTSC
- **Secure Connection** - Authenticated WebSocket connection to the PyPNM API server
- **Capability-based Routing** - Advertises capabilities for smart task routing
- **Safe Capture Retention** - Optional exact deletion and bounded age-housekeeping under one explicit writable root

## Related Repositories

- PyPNM core: https://github.com/svdleer/PyPNM
- PyPNM GUI: https://github.com/svdleer/PyPNMGui

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
        "url": "ws://pypnm-server:8000/api/agents/ws",
        "auth_token": "your-token"
    },
    "cmts_access": {
        "enabled": true,
        "community": "public"
    },
    "cm_access": {
        "enabled": false,
        "community": "your-cm-community"
    },
    "tftp_server": {
        "tftp_path": "/srv/tftp",
        "pnm_file_get_enabled": true,
        "pnm_file_write_root": "/srv/tftp",
        "pnm_file_delete_enabled": false,
        "pnm_file_housekeeping_enabled": false
    }
}
```

PNM write operations are default-disabled. Enable each operation independently only on the designated file agent, and set `pnm_file_write_root` to the exact writable capture root. Read discovery paths and fallback directories are never authorized for deletion.

## Capabilities

| Capability | Description |
|------------|-------------|
| `cmts_reachable` | Can reach CMTS devices for SNMP |
| `cm_reachable` | Can reach cable modems for SNMP |
| `snmp_get/walk/set` | SNMP operations |
| `pnm_file_get` | Exact, bounded PNM capture retrieval (explicit read opt-in) |
| `pnm_file_catalog` | Bounded PNM capture metadata catalog |
| `pnm_file_delete` | Exact approved UTSC basename deletion (explicit write opt-in) |
| `pnm_file_housekeeping` | Bounded age-based UTSC cleanup with dry-run support (explicit write opt-in) |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PYPNM_AGENT_ID` | Unique agent identifier | `agent-01` |
| `PYPNM_SERVER_URL` | PyPNM API WebSocket URL | `ws://127.0.0.1:8000/api/agents/ws` |
| `PYPNM_CMTS_ENABLED` | Enable CMTS access | `true` |
| `PYPNM_CM_ENABLED` | Enable CM access | `false` |
| `PYPNM_PNM_FILE_GET_ENABLED` | Advertise exact PNM file retrieval when the read root is available | `false` |
| `PYPNM_PNM_WRITE_ROOT` | Explicit writable root for destructive PNM operations; no fallback | unset |
| `PYPNM_PNM_FILE_DELETE_ENABLED` | Enable exact approved UTSC deletion | `false` |
| `PYPNM_PNM_FILE_HOUSEKEEPING_ENABLED` | Enable bounded aged-UTSC housekeeping | `false` |

## License

Apache-2.0
