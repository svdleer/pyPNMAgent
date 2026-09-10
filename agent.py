# PyPNM Jump Server Agent
# SPDX-License-Identifier: Apache-2.0
# 
# This agent runs on the Jump Server and connects OUT to the GUI Server
# via WebSocket. It executes SNMP/SSH commands and returns results.

from __future__ import annotations  # enables PEP 604/585 syntax on Python 3.8/3.9

import json
import logging
import os
import stat
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import websocket
except ImportError:
    print("ERROR: websocket-client not installed. Run: pip install websocket-client")
    exit(1)

try:
    import paramiko
except ImportError:
    paramiko = None
    print("WARNING: paramiko not installed. SSH proxy features disabled.")

# pysnmp imports -- requires v7+ (lextudio fork, Python 3.9+)
import asyncio
try:
    # pysnmp >= 7 (lextudio fork, Python 3.9+) — v3arch.asyncio path
    # Naming changed across releases: camelCase (7.1.x) → snake_case (7.1.22+)
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity,
        Integer32, OctetString, Unsigned32, Counter32, Counter64, Gauge32, TimeTicks, IpAddress
    )
    import pysnmp.hlapi.v3arch.asyncio as _snmp_mod

    def _pick(*names):
        for n in names:
            v = getattr(_snmp_mod, n, None)
            if v is not None:
                return v
        raise ImportError(f"None of {names} found in pysnmp.hlapi.v3arch.asyncio")

    get_cmd       = _pick('get_cmd',       'getCmd')
    set_cmd       = _pick('set_cmd',       'setCmd')
    bulk_walk_cmd = _pick('bulk_walk_cmd', 'bulkWalkCmd', 'walkCmd')

    PYSNMP_AVAILABLE = True
    import pysnmp as _pysnmp_pkg
    print(f"INFO: pysnmp {_pysnmp_pkg.__version__} loaded (v3arch.asyncio)", flush=True)
except (ImportError, Exception) as _pysnmp_err:
    # Check if pysnmp is installed at all (could be v6 or missing)
    try:
        import pysnmp as _pysnmp_pkg
        _ver = getattr(_pysnmp_pkg, '__version__', 'unknown')
        print(
            f"ERROR: pysnmp {_ver} is installed but failed to import required symbols: {_pysnmp_err}\n"
            f"       This agent requires pysnmp v7+ (lextudio fork) on Python 3.9+.\n"
            f"       To reinstall:\n"
            f"         pyenv local 3.11.9\n"
            f"         rm -rf venv && python -m venv venv\n"
            f"         venv/bin/pip install -r requirements.txt",
            flush=True
        )
    except ImportError:
        print(
            "ERROR: pysnmp is not installed.\n"
            "       Run: pip install pysnmp",
            flush=True
        )
    PYSNMP_AVAILABLE = False
    raise SystemExit(1)

async def make_transport(ip: str, port: int = 161, timeout: float = 5, retries: int = 1):
    """Create UdpTransportTarget via create() classmethod (required by pysnmp v7)."""
    return await UdpTransportTarget.create((ip, port), timeout=timeout, retries=retries)

try:
    import redis
except ImportError:
    redis = None
    print("INFO: redis not installed. Caching disabled. Run: pip install redis")


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
# Ensure the console handler only shows INFO+, even though the logger allows DEBUG
for _h in logging.root.handlers:
    _h.setLevel(logging.INFO)
logger = logging.getLogger('PyPNM-Agent')
# Allow DEBUG records to reach WebSocketLogHandler (streams to API for remote debugging).
# Console stays at INFO because the root handler is explicitly set above.
logger.setLevel(logging.DEBUG)


class WebSocketLogHandler(logging.Handler):
    """Streams log records to PyPNM API over the agent's existing WebSocket.

    Keeps a local ring buffer (default 500) so recent logs survive even
    if the WS is temporarily disconnected.  The handler is installed once
    and the ``ws`` reference is swapped on reconnect.
    """

    MAX_BUFFER: int = 500

    def __init__(self, agent_id: str, level: int = logging.DEBUG) -> None:
        super().__init__(level)
        self.agent_id = agent_id
        self._ws: Any = None
        self._send_lock: threading.Lock | None = None
        self._buffer: deque[dict[str, Any]] = deque(maxlen=self.MAX_BUFFER)

    def attach(self, ws: Any, send_lock: threading.Lock) -> None:
        """Point the handler at the current WebSocket + send lock."""
        self._ws = ws
        self._send_lock = send_lock

    def detach(self) -> None:
        self._ws = None

    def emit(self, record: logging.LogRecord) -> None:
        entry = {
            "ts": record.created,
            "level": record.levelname,
            "name": record.name,
            "msg": self.format(record),
        }
        self._buffer.append(entry)
        # Don't send over WS synchronously — it competes with task response
        # sends via the shared _send_lock and can starve response delivery.
        # Logs are batched and flushed periodically by _flush_logs() instead.

    def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return up to *limit* recent log entries from the ring buffer."""
        items = list(self._buffer)
        return items[-limit:]

    def start_flush_thread(self) -> None:
        """Start a daemon thread that periodically flushes buffered logs over WS."""
        self._flush_cursor = len(self._buffer)
        t = threading.Thread(target=self._flush_loop, daemon=True, name="ws-log-flush")
        t.start()

    def _flush_loop(self) -> None:
        """Send batched log entries every 5 seconds, outside the hot path."""
        while True:
            time.sleep(5)
            ws = self._ws
            lock = self._send_lock
            if not ws or not lock:
                continue
            items = list(self._buffer)
            to_send = items[self._flush_cursor:]
            if not to_send:
                continue
            self._flush_cursor = len(self._buffer)
            # Send as a single batch message
            try:
                batch = to_send[-200:]  # cap to last 200 per flush
                msg = json.dumps({
                    "type": "log_batch",
                    "agent_id": self.agent_id,
                    "entries": batch,
                })
                with lock:
                    ws.send(msg)
            except Exception:
                pass


def _first_nonblank(*values):
    """Return the first non-blank value without modifying it."""
    for value in values:
        if value is not None and str(value).strip():
            return value
    return None


@dataclass
class AgentConfig:
    """Agent configuration for Jump Server deployment."""
    agent_id: str
    pypnm_server_url: str
    auth_token: str
    reconnect_interval: int = 5

    # Dedicated command worker pools. ``gui`` in agent_config.json maps to
    # the interactive priority used by PyPNM's wire protocol.
    interactive_workers: int = 50
    bulk_workers: int = 2
    identity_workers: int = 8
    long_workers: int = 10
    
    # SSH Tunnel to PyPNM Server (WebSocket connection)
    pypnm_ssh_tunnel_enabled: bool = False
    pypnm_ssh_host: Optional[str] = None
    pypnm_ssh_port: int = 22
    pypnm_ssh_user: Optional[str] = None
    pypnm_ssh_key: Optional[str] = None
    pypnm_tunnel_local_port: int = 8080
    pypnm_tunnel_remote_port: int = 8080
    
    # Reverse SSH tunnels -- each entry opens a port on a remote peer server
    # so that peer agent can reach PyPNM via localhost there.
    # Supports both a single peer_tunnel object (legacy) and a peer_tunnels array.
    # Each entry: {enabled, ssh_host, ssh_port, ssh_user, ssh_key, local_port, remote_port}
    peer_tunnels: list = field(default_factory=list)

    # CMTS Access - for SNMP to CMTS devices
    cmts_enabled: bool = True
    cmts_community: str = ''
    cmts_write_community: Optional[str] = None
    # Per-target CMTS credentials. Explicit task values still take precedence.
    cmts_list: list = field(default_factory=list)
    # Optional: SSH to CMTS for CLI commands
    cmts_ssh_enabled: bool = False
    cmts_ssh_user: Optional[str] = None
    cmts_ssh_key: Optional[str] = None
    
    # CM Access - for SNMP to Cable Modems
    cm_enabled: bool = False
    cm_community: str = ''
    cm_write_community: Optional[str] = None
    # Optional: SSH proxy to reach CMs (if not directly reachable)
    cm_proxy_host: Optional[str] = None
    cm_proxy_port: int = 22
    cm_proxy_user: Optional[str] = None
    cm_proxy_key: Optional[str] = None
    
    # Equalizer Server - for SNMP queries via SSH (has best CMTS connectivity)
    equalizer_host: Optional[str] = None
    equalizer_port: int = 22
    equalizer_user: Optional[str] = None
    equalizer_key: Optional[str] = None
    
    # Redis caching for modem data
    redis_host: Optional[str] = None
    redis_port: int = 6379
    redis_ttl: int = 86400  # Cache TTL in seconds (24 hours)
    
    # TFTP/FTP Server - accessed via SSH for PNM file retrieval
    tftp_ssh_host: Optional[str] = None
    tftp_ssh_port: int = 22
    tftp_ssh_user: Optional[str] = None
    tftp_ssh_key: Optional[str] = None
    tftp_path: str = "/tftpboot"
    # Explicitly opt-in to announcing pnm_file_get capability.
    # Only set True on agents that have direct read access to the TFTP capture root.
    pnm_file_get_enabled: bool = False
    # Destructive PNM operations require a separate explicit writable root and
    # independent opt-ins. Read-only roots and discovery fallbacks are never used.
    pnm_file_write_root: Optional[str] = None
    pnm_file_delete_enabled: bool = False
    pnm_file_housekeeping_enabled: bool = False

    @staticmethod
    def _parse_worker_count(
        value: Any,
        default: int,
        name: str,
        *,
        allow_string: bool = False,
    ) -> int:
        """Validate one worker count without silently truncating JSON values."""
        if value is None:
            return default
        if isinstance(value, bool):
            raise ValueError(f"workers.{name} must be an integer")
        if isinstance(value, int):
            count = value
        elif allow_string and isinstance(value, str):
            try:
                count = int(value.strip())
            except ValueError as exc:
                raise ValueError(f"workers.{name} must be an integer") from exc
        else:
            raise ValueError(f"workers.{name} must be an integer")
        if not 1 <= count <= 512:
            raise ValueError(f"workers.{name} must be between 1 and 512")
        return count
    
    @classmethod
    def _parse_peer_tunnels(cls, data: dict, expand_path) -> dict:
        """Parse peer_tunnels (array) or legacy peer_tunnel (object) from config."""
        def _normalise(pt: dict) -> dict:
            return {
                'enabled': pt.get('enabled', True),
                'ssh_host': pt.get('ssh_host'),
                'ssh_port': pt.get('ssh_port', 22),
                'ssh_user': pt.get('ssh_user'),
                'ssh_key': expand_path(pt.get('ssh_key_file') or pt.get('key_file')),
                'local_port': pt.get('local_port', 8000),
                'remote_port': pt.get('remote_port', 8000),
                'label': pt.get('label', pt.get('ssh_host', 'peer')),
                'ssh_options': pt.get('ssh_options', []),
                'keepalive_interval': pt.get('keepalive_interval', 0),  # 0 = use SSHTunnelConfig default
            }

        # New: array form
        raw_list = data.get('peer_tunnels')
        if isinstance(raw_list, list):
            return {'peer_tunnels': [_normalise(pt) for pt in raw_list if pt]}

        # Legacy: single object form
        pt = data.get('peer_tunnel', {})
        if pt:
            return {'peer_tunnels': [_normalise(pt)]}

        return {'peer_tunnels': []}

    @classmethod
    def from_file(cls, path: str) -> 'AgentConfig':
        """Load configuration from JSON file."""
        import re
        with open(path) as f:
            raw = f.read()
        # Strip trailing garbage (e.g. from broken heredoc installs)
        idx = raw.rfind('}')
        if idx == -1:
            raise ValueError(f"No closing '}}' found in {path} -- file appears empty or corrupt")
        raw = raw[:idx + 1]

        # Remove stray control characters that are illegal in JSON
        # (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F — keep tab 0x09, LF 0x0A, CR 0x0D)
        sanitized, n_removed = re.subn(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', raw)
        if n_removed:
            # Find first occurrence for a useful diagnostic
            m = re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', raw)
            line_no = raw[:m.start()].count('\n') + 1
            col_no  = m.start() - raw[:m.start()].rfind('\n')
            logger.warning(
                f"Stripped {n_removed} illegal control character(s) from {path} "
                f"(first at line {line_no}, col {col_no}, char 0x{ord(m.group()):02x}). "
                f"Re-save the file to remove this warning."
            )
            raw = sanitized

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {path}: {e}") from e
        
        # Expand ~ in paths
        def expand_path(p):
            return os.path.expanduser(p) if p else None
        
        server_config = data.get('pypnm_server') or data.get('gui_server') or {}
        # Also support flat format: server_url / token at top level
        if not server_config.get('url') and data.get('server_url'):
            server_config = {
                'url': data['server_url'],
                'auth_token': data.get('token', data.get('auth_token', 'dev-token')),
                'reconnect_interval': data.get('reconnect_interval', 5),
            }

        workers = data.get('workers')
        if workers is None:
            workers = {}
        elif not isinstance(workers, dict):
            raise ValueError("workers must be a JSON object")
        interactive_workers = cls._parse_worker_count(
            workers.get('gui', workers.get('interactive')),
            50,
            'gui',
        )
        bulk_workers = cls._parse_worker_count(workers.get('bulk'), 2, 'bulk')
        identity_workers = cls._parse_worker_count(
            workers.get('identity'),
            8,
            'identity',
        )
        long_workers = cls._parse_worker_count(workers.get('long'), 10, 'long')

        tunnel_config = data.get('pypnm_ssh_tunnel') or data.get('gui_ssh_tunnel', {})
        cmts = data.get('cmts_access', {})
        cm_access = data.get('cm_access', {})
        cm_proxy = cm_access.get('proxy', {}) or data.get('cm_proxy', {})
        cm_direct = data.get('cm_direct', {})
        cm_enabled = cm_access.get('enabled', cm_direct.get('enabled', False))
        cm_community = _first_nonblank(
            cm_access.get('community'),
            cm_direct.get('community'),
            data.get('modem_community'),
        ) or ''
        cm_write_community = _first_nonblank(
            cm_access.get('write_community'),
            cm_direct.get('write_community'),
            data.get('modem_write_community'),
            os.environ.get('PYPNM_CM_WRITE_COMMUNITY'),
            os.environ.get('MODEM_WRITE_COMMUNITY'),
            os.environ.get('CM_RW_COMMUNITY'),
        )
        cmts_community = _first_nonblank(
            cmts.get('community'),
            data.get('cmts_community'),
            os.environ.get('PYPNM_CMTS_COMMUNITY'),
            os.environ.get('CMTS_SNMP_COMMUNITY'),
            os.environ.get('CMTS_COMMUNITY'),
        ) or ''
        cmts_write_community = _first_nonblank(
            cmts.get('write_community'),
            data.get('cmts_write_community'),
            os.environ.get('PYPNM_CMTS_WRITE_COMMUNITY'),
            os.environ.get('CMTS_WRITE_COMMUNITY'),
        )

        cmts_list = []
        raw_cmts_list = data.get('cmts_list', [])
        if isinstance(raw_cmts_list, list):
            allowed_cmts_keys = {
                'name', 'ip', 'community', 'write_community', 'vendor', 'type'
            }
            for raw_cmts in raw_cmts_list:
                if not isinstance(raw_cmts, dict):
                    continue
                entry = {
                    key: value
                    for key, value in raw_cmts.items()
                    if key in allowed_cmts_keys
                    and value is not None
                    and (not isinstance(value, str) or value.strip())
                }
                if entry.get('ip') is not None:
                    cmts_list.append(entry)
        
        equalizer = data.get('equalizer', {})
        redis_config = data.get('redis', {})
        tftp = data.get('tftp_server', {})
        
        return cls(
            agent_id=data['agent_id'],
            pypnm_server_url=server_config['url'],
            auth_token=server_config.get('auth_token', 'dev-token'),
            reconnect_interval=server_config.get('reconnect_interval', 5),
            interactive_workers=interactive_workers,
            bulk_workers=bulk_workers,
            identity_workers=identity_workers,
            long_workers=long_workers,
            # SSH Tunnel to PyPNM Server
            pypnm_ssh_tunnel_enabled=tunnel_config.get('enabled', False),
            pypnm_ssh_host=tunnel_config.get('ssh_host'),
            pypnm_ssh_port=tunnel_config.get('ssh_port', 22),
            pypnm_ssh_user=tunnel_config.get('ssh_user'),
            pypnm_ssh_key=expand_path(tunnel_config.get('ssh_key_file') or tunnel_config.get('key_file')),
            pypnm_tunnel_local_port=tunnel_config.get('local_port', 8080),
            pypnm_tunnel_remote_port=tunnel_config.get('remote_port', 8080),
            # Reverse tunnel to peer agent server
            **cls._parse_peer_tunnels(data, expand_path),
            # CMTS Access
            cmts_enabled=cmts.get('enabled', cmts.get('snmp_direct', True)),
            cmts_community=cmts_community,
            cmts_write_community=cmts_write_community,
            cmts_list=cmts_list,
            cmts_ssh_enabled=cmts.get('ssh_enabled', False),
            cmts_ssh_user=cmts.get('ssh_user'),
            cmts_ssh_key=expand_path(cmts.get('ssh_key_file')),
            # CM Access
            cm_enabled=cm_enabled,
            cm_community=cm_community,
            cm_write_community=cm_write_community,
            cm_proxy_host=cm_proxy.get('host'),
            cm_proxy_port=cm_proxy.get('port', 22),
            cm_proxy_user=cm_proxy.get('username') or cm_proxy.get('user'),
            cm_proxy_key=expand_path(cm_proxy.get('key_file')),
            # Equalizer (for CMTS SNMP via SSH)
            equalizer_host=equalizer.get('host'),
            equalizer_port=equalizer.get('port', 22),
            equalizer_user=equalizer.get('username') or equalizer.get('user'),
            equalizer_key=expand_path(equalizer.get('key_file')),
            # Redis caching
            redis_host=redis_config.get('host'),
            redis_port=redis_config.get('port', 6379),
            redis_ttl=redis_config.get('ttl', 300),
            # TFTP Server (via SSH)
            tftp_ssh_host=tftp.get('host'),
            tftp_ssh_port=tftp.get('port', 22),
            tftp_ssh_user=tftp.get('username'),
            tftp_ssh_key=expand_path(tftp.get('key_file')),
            tftp_path=tftp.get('tftp_path', '/tftpboot'),
            pnm_file_get_enabled=tftp.get('pnm_file_get_enabled', False),
            pnm_file_write_root=expand_path(tftp.get('pnm_file_write_root')),
            pnm_file_delete_enabled=tftp.get('pnm_file_delete_enabled', False),
            pnm_file_housekeeping_enabled=tftp.get('pnm_file_housekeeping_enabled', False),
        )
    
    @classmethod
    def from_env(cls) -> 'AgentConfig':
        """Load configuration from environment variables."""
        def expand_path(p):
            return os.path.expanduser(p) if p else None

        cmts_community = _first_nonblank(
            os.environ.get('PYPNM_CMTS_COMMUNITY'),
            os.environ.get('CMTS_SNMP_COMMUNITY'),
            os.environ.get('CMTS_COMMUNITY'),
        ) or ''
        cmts_write_community = _first_nonblank(
            os.environ.get('PYPNM_CMTS_WRITE_COMMUNITY'),
            os.environ.get('CMTS_WRITE_COMMUNITY'),
        )
        cm_community = _first_nonblank(
            os.environ.get('PYPNM_CM_COMMUNITY'),
            os.environ.get('MODEM_COMMUNITY'),
            os.environ.get('CM_SNMP_COMMUNITY'),
        ) or ''
        cm_write_community = _first_nonblank(
            os.environ.get('PYPNM_CM_WRITE_COMMUNITY'),
            os.environ.get('MODEM_WRITE_COMMUNITY'),
            os.environ.get('CM_RW_COMMUNITY'),
        )

        return cls(
            agent_id=os.environ.get('PYPNM_AGENT_ID', 'agent-01'),
            pypnm_server_url=os.environ.get('PYPNM_SERVER_URL', 'ws://127.0.0.1:8000/api/agents/ws'),
            auth_token=os.environ.get('PYPNM_AUTH_TOKEN', 'dev-token'),
            reconnect_interval=int(os.environ.get('PYPNM_RECONNECT_INTERVAL', '5')),
            interactive_workers=cls._parse_worker_count(
                os.environ.get('AGENT_INTERACTIVE_THREADS'),
                50,
                'gui',
                allow_string=True,
            ),
            bulk_workers=cls._parse_worker_count(
                os.environ.get('AGENT_BULK_THREADS'),
                2,
                'bulk',
                allow_string=True,
            ),
            identity_workers=cls._parse_worker_count(
                os.environ.get('AGENT_IDENTITY_THREADS'),
                8,
                'identity',
                allow_string=True,
            ),
            long_workers=cls._parse_worker_count(
                os.environ.get('AGENT_LONG_THREADS'),
                10,
                'long',
                allow_string=True,
            ),
            # SSH Tunnel to PyPNM
            pypnm_ssh_tunnel_enabled=os.environ.get('PYPNM_SSH_TUNNEL', 'false').lower() == 'true',
            pypnm_ssh_host=os.environ.get('PYPNM_SSH_HOST'),
            cmts_community=cmts_community,
            cmts_write_community=cmts_write_community,
            pypnm_ssh_port=int(os.environ.get('PYPNM_SSH_PORT', '22')),
            pypnm_ssh_user=os.environ.get('PYPNM_SSH_USER'),
            pypnm_ssh_key=expand_path(os.environ.get('PYPNM_SSH_KEY')),
            pypnm_tunnel_local_port=int(os.environ.get('PYPNM_LOCAL_PORT', '8080')),
            pypnm_tunnel_remote_port=int(os.environ.get('PYPNM_REMOTE_PORT', '8080')),
            # CMTS Access
            cmts_enabled=os.environ.get('PYPNM_CMTS_ENABLED', 'true').lower() == 'true',
            # CM Access
            cm_enabled=os.environ.get('PYPNM_CM_ENABLED', 'false').lower() == 'true',
            cm_community=cm_community,
            cm_write_community=cm_write_community,
            cm_proxy_host=os.environ.get('PYPNM_CM_PROXY_HOST'),
            cm_proxy_port=int(os.environ.get('PYPNM_CM_PROXY_PORT', '22')),
            cm_proxy_user=os.environ.get('PYPNM_CM_PROXY_USER'),
            cm_proxy_key=expand_path(os.environ.get('PYPNM_CM_PROXY_KEY')),
            # TFTP
            tftp_ssh_host=os.environ.get('PYPNM_TFTP_SSH_HOST'),
            tftp_ssh_port=int(os.environ.get('PYPNM_TFTP_SSH_PORT', '22')),
            tftp_ssh_user=os.environ.get('PYPNM_TFTP_SSH_USER'),
            tftp_ssh_key=expand_path(os.environ.get('PYPNM_TFTP_SSH_KEY')),
            tftp_path=os.environ.get('PYPNM_TFTP_PATH', '/tftpboot'),
            pnm_file_get_enabled=os.environ.get('PYPNM_PNM_FILE_GET_ENABLED', 'false').lower() == 'true',
            pnm_file_write_root=expand_path(os.environ.get('PYPNM_PNM_WRITE_ROOT')),
            pnm_file_delete_enabled=os.environ.get('PYPNM_PNM_FILE_DELETE_ENABLED', 'false').lower() == 'true',
            pnm_file_housekeeping_enabled=os.environ.get('PYPNM_PNM_FILE_HOUSEKEEPING_ENABLED', 'false').lower() == 'true',
        )


class SSHProxyExecutor:
    """Executes commands on remote server via SSH."""
    
    def __init__(self, host: str, port: int, username: str, key_file: Optional[str] = None):
        self.host = host
        self.port = port
        self.username = username
        self.key_file = key_file
        self._client: Optional[paramiko.SSHClient] = None
        self.logger = logging.getLogger(f'{__name__}.SSHProxy')
    
    def connect(self) -> bool:
        """Establish SSH connection."""
        if paramiko is None:
            self.logger.error("paramiko not installed")
            return False
        
        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.host,
                'port': self.port,
                'username': self.username,
            }
            
            if self.key_file:
                connect_kwargs['key_filename'] = self.key_file
            
            self._client.connect(**connect_kwargs)
            self.logger.info(f"Connected to SSH proxy: {self.host}")
            return True
            
        except Exception as e:
            self.logger.error(f"SSH connection failed: {e}")
            return False
    
    def execute(self, command: str, timeout: int = 30) -> tuple[int, str, str]:
        """Execute command on remote server."""
        if not self._client:
            if not self.connect():
                return -1, "", "SSH connection failed"
        
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            return exit_code, stdout.read().decode(), stderr.read().decode()
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return -1, "", str(e)
    
    def close(self):
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None


class TFTPExecutor:
    """Handles TFTP file transfers."""
    
    def __init__(self, tftp_host: str, tftp_port: int = 69):
        self.tftp_host = tftp_host
        self.tftp_port = tftp_port
        self.logger = logging.getLogger(f'{__name__}.TFTP')
    
    def get_file(self, remote_path: str, local_path: Optional[str] = None) -> dict:
        """Download file from TFTP server."""
        if local_path is None:
            local_path = f"/tmp/{os.path.basename(remote_path)}"
        
        cmd = f"tftp {self.tftp_host} {self.tftp_port} -c get {remote_path} {local_path}"
        
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and os.path.exists(local_path):
                with open(local_path, 'rb') as f:
                    content = f.read()
                
                return {
                    'success': True,
                    'path': local_path,
                    'size': len(content),
                    'content_base64': content.hex()
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr or 'File not found'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


class PyPNMAgent:
    """Main agent class that connects to GUI Server and handles requests."""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = logging.getLogger('PyPNM-Agent')
        self.ws: Optional[websocket.WebSocketApp] = None
        self.running = False
        
        # Three separate thread pools:
        # · interactive_pool — GUI clicks, CMTS walks, RF/ifindex discovery
        # · bulk_pool        — bounded CMTS inventory/background work
        # · identity_pool    — fail-fast per-modem identity GETs
        # · long_pool        — PNM file captures (file_get/pnm_file_get), may run 30-90 s
        # Configured by the agent_config.json ``workers`` object.
        self._int_threads = config.interactive_workers
        self._bulk_threads = config.bulk_workers
        self._identity_threads = config.identity_workers
        self._long_threads = config.long_workers
        self._interactive_executor = ThreadPoolExecutor(max_workers=self._int_threads, thread_name_prefix='snmp-int')
        self._bulk_executor = ThreadPoolExecutor(max_workers=self._bulk_threads, thread_name_prefix='snmp-bulk')
        self._identity_executor = ThreadPoolExecutor(max_workers=self._identity_threads, thread_name_prefix='snmp-identity')
        self._long_executor = ThreadPoolExecutor(max_workers=self._long_threads, thread_name_prefix='snmp-long')
        # Legacy alias kept so any direct references still work
        self._executor = self._interactive_executor
        # websocket-client ws.send() is NOT thread-safe — serialise all sends
        self._send_lock = threading.Lock()
        # Monotone counter incremented on every reconnect so stale tasks can
        # detect they belong to a previous session and drop their response.
        self._session_id = 0
        
        # WebSocket log streaming — sends log records to API for remote debugging
        self._ws_log_handler = WebSocketLogHandler(agent_id=config.agent_id, level=logging.DEBUG)
        self._ws_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logging.getLogger('PyPNM-Agent').addHandler(self._ws_log_handler)
        self._ws_log_handler.start_flush_thread()
        
        # SSH Tunnel to PyPNM
        self.pypnm_tunnel = None
        self.pypnm_tunnel_monitor = None
        # Reverse tunnels to peer agent servers (one SSHTunnelManager per entry)
        self.peer_tunnels: list = []
        self.peer_tunnel_monitors: list = []
        
        # CM Proxy (SSH to reach modems)
        self.cm_proxy: Optional[SSHProxyExecutor] = None
        if config.cm_proxy_host:
            self.cm_proxy = SSHProxyExecutor(
                host=config.cm_proxy_host,
                port=config.cm_proxy_port,
                username=config.cm_proxy_user,
                key_file=config.cm_proxy_key
            )
            self.logger.info(f"CM Proxy configured: {config.cm_proxy_host}")
        
        # Equalizer (CMTS SNMP via SSH)
        self.equalizer: Optional[SSHProxyExecutor] = None
        if config.equalizer_host:
            self.equalizer = SSHProxyExecutor(
                host=config.equalizer_host,
                port=config.equalizer_port,
                username=config.equalizer_user,
                key_file=config.equalizer_key
            )
            self.logger.info(f"Equalizer configured: {config.equalizer_host}")
        
        # TFTP (file retrieval via SSH)
        self.tftp_ssh: Optional[SSHProxyExecutor] = None
        if config.tftp_ssh_host:
            self.tftp_ssh = SSHProxyExecutor(
                host=config.tftp_ssh_host,
                port=config.tftp_ssh_port,
                username=config.tftp_ssh_user,
                key_file=config.tftp_ssh_key
            )
            self.logger.info(f"TFTP SSH configured: {config.tftp_ssh_host}")
        
        # Command handlers
        self.handlers: dict[str, Callable] = {
            'ping': self._handle_ping,
            'snmp_get': self._handle_snmp_get,
            'snmp_walk': self._handle_snmp_walk,
            'snmp_set': self._handle_snmp_set,
            'snmp_set_sequence': self._handle_snmp_set_sequence,
            'snmp_bulk_get': self._handle_snmp_bulk_get,
            'snmp_bulk_walk': self._handle_snmp_bulk_walk,
            'snmp_parallel_walk': self._handle_snmp_parallel_walk,
            'ping_sweep': self._handle_ping_sweep,
            'tftp_get': self._handle_tftp_get,
            'file_get': self._handle_file_get,
            'file_list': self._handle_file_list,
            'pnm_file_get': self._handle_pnm_file_get,
            'pnm_file_catalog': self._handle_pnm_file_catalog,
            'pnm_file_delete': self._handle_pnm_file_delete,
            'pnm_file_housekeeping': self._handle_pnm_file_housekeeping,
            'cmts_command': self._handle_cmts_command,
        }
    
    def _setup_peer_tunnel(self) -> bool:
        """Set up reverse SSH tunnels to peer agent servers.

        Iterates over all entries in config.peer_tunnels and starts a
        reverse SSH tunnel + monitor for each enabled entry.  Failures
        are non-fatal per entry; returns False only if ALL entries fail.
        """
        entries = [pt for pt in self.config.peer_tunnels if pt.get('enabled', True)]
        if not entries:
            self.logger.info("Peer tunnels: none enabled, skipping")
            return True

        self.logger.info(f"Peer tunnels: starting {len(entries)} reverse SSH tunnel(s)...")

        try:
            from ssh_tunnel import SSHTunnelConfig, SSHTunnelManager, TunnelMonitor
        except ImportError:
            self.logger.error("ssh_tunnel module not available")
            return False

        any_ok = False
        for pt in entries:
            label = pt.get('label', pt.get('ssh_host', 'peer'))
            if not pt.get('ssh_host'):
                self.logger.error(f"  [{label}] no ssh_host configured, skipping")
                continue
            self.logger.info(
                f"  [{label}] ssh -R {pt.get('remote_port', 8000)}:localhost:{pt.get('local_port', 8000)}"
                f" {pt.get('ssh_user', '')}@{pt['ssh_host']}:{pt.get('ssh_port', 22)}"
                f" (key: {pt.get('ssh_key') or 'default'})"
            )
            try:
                tunnel_config = SSHTunnelConfig(
                    ssh_host=pt['ssh_host'],
                    ssh_port=pt.get('ssh_port', 22),
                    ssh_user=pt.get('ssh_user'),
                    ssh_key_file=pt.get('ssh_key'),
                    local_port=pt.get('local_port', 8000),
                    remote_host='127.0.0.1',
                    remote_port=pt.get('remote_port', 8000),
                    reverse=True,
                    ssh_extra_options=pt.get('ssh_options', []),
                    keepalive_interval=pt.get('keepalive_interval') or 30,
                )
                tunnel = SSHTunnelManager(tunnel_config, use_paramiko=False)
                if not tunnel.start_tunnel():
                    self.logger.error(f"  [{label}] FAILED to start — check SSH connectivity/auth/GatewayPorts on remote")
                    continue
                monitor = TunnelMonitor(tunnel)
                monitor.start()
                self.peer_tunnels.append(tunnel)
                self.peer_tunnel_monitors.append(monitor)
                self.logger.info(
                    f"  [{label}] OK — port {pt.get('remote_port', 8000)} open on {pt['ssh_host']}"
                    f" → PyPNM localhost:{pt.get('local_port', 8000)}"
                )
                any_ok = True
            except Exception as e:
                self.logger.error(f"  [{label}] setup error: {e}")

        return any_ok

    def _setup_pypnm_tunnel(self) -> bool:
        """Set up SSH tunnel to PyPNM Server if configured."""
        if not self.config.pypnm_ssh_tunnel_enabled:
            return True  # No tunnel needed
        
        if not self.config.pypnm_ssh_host:
            self.logger.error("PyPNM SSH tunnel enabled but no ssh_host configured")
            return False
        
        try:
            from ssh_tunnel import SSHTunnelConfig, SSHTunnelManager, TunnelMonitor
            
            tunnel_config = SSHTunnelConfig(
                ssh_host=self.config.pypnm_ssh_host,
                ssh_port=self.config.pypnm_ssh_port,
                ssh_user=self.config.pypnm_ssh_user,
                ssh_key_file=self.config.pypnm_ssh_key,
                local_port=self.config.pypnm_tunnel_local_port,
                remote_port=self.config.pypnm_tunnel_remote_port,
            )
            
            self.pypnm_tunnel = SSHTunnelManager(tunnel_config, use_paramiko=False)
            
            if not self.pypnm_tunnel.start_tunnel():
                self.logger.error("Failed to start PyPNM SSH tunnel")
                return False
            
            # Auto-reconnect monitor
            self.pypnm_tunnel_monitor = TunnelMonitor(self.pypnm_tunnel)
            self.pypnm_tunnel_monitor.start()
            
            self.logger.info(f"PyPNM SSH tunnel established: localhost:{self.config.pypnm_tunnel_local_port} -> {self.config.pypnm_ssh_host}:{self.config.pypnm_tunnel_remote_port}")
            return True
            
        except ImportError:
            self.logger.error("ssh_tunnel module not available")
            return False
        except Exception as e:
            self.logger.error(f"Failed to set up PyPNM tunnel: {e}")
            return False
    
    def _get_websocket_url(self) -> str:
        """Get the WebSocket URL (through tunnel if enabled)."""
        if self.config.pypnm_ssh_tunnel_enabled:
            # Connect to local tunnel endpoint
            return f"ws://127.0.0.1:{self.config.pypnm_tunnel_local_port}/api/agents/ws"
        else:
            return self.config.pypnm_server_url
    
    def _on_open(self, ws):
        """Called when WebSocket connection is established."""
        ws_url = self._get_websocket_url()
        if self._session_id > 0:
            self.logger.info(f"Reconnected to PyPNM Server (session #{self._session_id + 1}): {ws_url}")
        else:
            self.logger.info(f"Connected to PyPNM Server: {ws_url}")
        self._session_id += 1
        self.logger.info(f"Session #{self._session_id} — executor pools reset, ready for commands")

        auth_msg = {
            'type': 'auth',
            'agent_id': self.config.agent_id,
            'token': self.config.auth_token,
            'capabilities': self._get_capabilities(),
            'limits': {
                'interactive': self._int_threads,
                'bulk': self._bulk_threads,
                'identity': self._identity_threads,
                'long': self._long_threads,
            },
        }
        ws.send(json.dumps(auth_msg))
        self._ws_log_handler.attach(ws, self._send_lock)
    
    def _on_message(self, ws, message):
        """Called when a message is received."""
        try:
            data = json.loads(message)
            msg_type = data.get('type')
            
            if msg_type == 'auth_success':
                self.logger.info(f"Authentication successful as {data.get('agent_id')}")
                
            elif msg_type == 'auth_response':
                if data.get('success'):
                    self.logger.info("Authentication successful")
                else:
                    self.logger.error(f"Authentication failed: {data.get('error')}")
                    ws.close()
                    
            elif msg_type == 'command':
                self._handle_command(ws, data)
                
            elif msg_type == 'heartbeat_ack':
                pass  # Server acknowledged heartbeat
                
            elif msg_type == 'ping':
                ws.send(json.dumps({'type': 'pong', 'timestamp': time.time()}))
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON message: {e}")
    
    def _on_error(self, ws, error):
        """Called when an error occurs."""
        self.logger.error(f"WebSocket error: {error}")
    
    def _on_close(self, ws, close_status_code, close_msg):
        """Called when connection is closed — reset executor pools so queued tasks
        from this session are cancelled and threads are reclaimed before reconnect."""
        self._ws_log_handler.detach()
        self.logger.warning(f"Connection closed (session #{self._session_id}): {close_status_code} - {close_msg}")
        self._reset_executors()

    def _reset_executors(self):
        """Shut down both executor pools (cancels queued tasks) and create fresh ones.
        Called on every disconnect so the next session starts with empty queues."""
        self.logger.info("Resetting executor pools (cancelling queued tasks)...")
        # shutdown(wait=False, cancel_futures=True) is Python 3.9+;
        # fall back to shutdown(wait=False) for older interpreters.
        for pool, name in ((self._interactive_executor, 'interactive'),
                           (self._bulk_executor, 'bulk'),
                           (self._identity_executor, 'identity'),
                           (self._long_executor, 'long')):
            try:
                pool.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                pool.shutdown(wait=False)
            self.logger.debug(f"  {name} pool shut down")

        self._interactive_executor = ThreadPoolExecutor(
            max_workers=self._int_threads, thread_name_prefix='snmp-int')
        self._bulk_executor = ThreadPoolExecutor(
            max_workers=self._bulk_threads, thread_name_prefix='snmp-bulk')
        self._identity_executor = ThreadPoolExecutor(
            max_workers=self._identity_threads, thread_name_prefix='snmp-identity')
        self._long_executor = ThreadPoolExecutor(
            max_workers=self._long_threads, thread_name_prefix='snmp-long')
        self._executor = self._interactive_executor
        self.logger.info("Executor pools reset — ready for next connection")
    
    def _get_capabilities(self) -> list[str]:
        """Return list of agent capabilities."""
        caps = ['snmp_get', 'snmp_walk', 'snmp_set', 'snmp_set_sequence', 'snmp_bulk_get', 'snmp_parallel_walk']
        
        # CM (Cable Modem) reachability
        if self.cm_proxy:
            caps.append('cm_proxy')
            caps.append('cm_reachable')  # Can reach modems via proxy
        
        if self.config.cm_enabled:
            caps.append('cm_reachable')  # Can reach modems directly
        
        # CMTS reachability  
        if self.config.cmts_enabled:
            caps.append('cmts_reachable')  # Can reach CMTS
            caps.append('cmts_snmp_direct')
        
        if self.config.cmts_ssh_enabled:
            caps.append('cmts_command')  # Can execute CMTS CLI commands via SSH
        
        if self.tftp_ssh:
            caps.append('tftp_get')

        # Local file retrieval from TFTP root — always available
        caps.append('file_get')
        caps.append('file_list')

        # pnm_file_get: only announced when explicitly enabled in config/env
        # AND the TFTP root is actually readable.  cm-agents that only do SNMP
        # must NOT announce this capability.
        tftp_root = os.environ.get('TFTP_ROOT', self.config.tftp_path)
        pnm_file_get_enabled = (
            self.config.pnm_file_get_enabled
            or os.environ.get('PYPNM_PNM_FILE_GET_ENABLED', 'false').lower() == 'true'
        )
        if pnm_file_get_enabled and os.path.isdir(tftp_root) and os.access(tftp_root, os.R_OK):
            caps.append('pnm_file_get')
            caps.append('pnm_file_catalog')

        # Destructive file capabilities are independent, default-disabled, and
        # require an explicitly configured writable root. Retrieval fallbacks
        # such as /tmp are deliberately never eligible.
        write_root = self._pnm_write_root()
        if write_root is not None:
            delete_enabled = (
                self.config.pnm_file_delete_enabled is True
                or os.environ.get('PYPNM_PNM_FILE_DELETE_ENABLED', 'false').lower() == 'true'
            )
            housekeeping_enabled = (
                self.config.pnm_file_housekeeping_enabled is True
                or os.environ.get('PYPNM_PNM_FILE_HOUSEKEEPING_ENABLED', 'false').lower() == 'true'
            )
            if delete_enabled:
                caps.append('pnm_file_delete')
            if housekeeping_enabled:
                caps.append('pnm_file_housekeeping')

        return caps
    
    def _handle_command(self, ws, data: dict):
        """Dispatch command to its isolated priority executor."""
        request_id = data.get('request_id')
        command = data.get('command')
        priority = str(data.get('priority') or 'interactive').strip().lower()
        if priority not in {'interactive', 'bulk', 'identity', 'long'}:
            self.logger.warning(
                "Unknown priority %r for task %s; routing as interactive",
                priority,
                request_id,
            )
            priority = 'interactive'

        raw_params = data.get('params') or {}
        if not isinstance(raw_params, dict):
            raw_params = {}
        params = dict(raw_params)
        # Internal-only context lets handlers enforce resource bounds by pool.
        params['_agent_priority'] = priority
        received_at = time.monotonic()

        self.logger.info(
            "Received command: %s - %s (priority=%s)",
            request_id,
            command,
            priority,
        )

        handler = self.handlers.get(command)
        if not handler:
            self.logger.warning(f"Unknown command '{command}' for task {request_id}")
            response = {
                'type': 'error',
                'request_id': request_id,
                'error': f'Unknown command: {command}'
            }
            with self._send_lock:
                ws.send(json.dumps(response))
            return

        def _run_handler():
            # Capture session id and ws at dispatch time — if either has changed
            # by the time we finish (i.e. we've disconnected and reconnected),
            # drop the response instead of trying to send on a dead socket.
            dispatched_session = self._session_id
            dispatched_ws = ws
            worker_name = threading.current_thread().name
            queue_wait = time.monotonic() - received_at
            started_at = time.monotonic()
            try:
                self.logger.debug(
                    "Executing %s for %s (priority=%s worker=%s queue_wait=%.3fs)",
                    command,
                    request_id,
                    priority,
                    worker_name,
                    queue_wait,
                )
                result = handler(params)
                elapsed = time.monotonic() - started_at
                success = result.get('success', True) if isinstance(result, dict) else True
                if not success:
                    self.logger.warning(
                        "Handler returned failure for %s (%s priority=%s worker=%s "
                        "elapsed=%.3fs): %s",
                        request_id,
                        command,
                        priority,
                        worker_name,
                        elapsed,
                        result.get('error', 'no error detail'),
                    )
                else:
                    self.logger.info(
                        "Handler returned for %s (success=True priority=%s worker=%s "
                        "queue_wait=%.3fs elapsed=%.3fs)",
                        request_id,
                        priority,
                        worker_name,
                        queue_wait,
                        elapsed,
                    )
                response = {
                    'type': 'response',
                    'request_id': request_id,
                    'result': result
                }
            except Exception as e:
                self.logger.exception(f"Command execution error for {request_id}: {e}")
                response = {
                    'type': 'error',
                    'request_id': request_id,
                    'error': str(e)
                }
            # Guard: don't send on a stale websocket from a previous session
            if self._session_id != dispatched_session or self.ws is not dispatched_ws:
                self.logger.warning(
                    f"Dropping response for {request_id} — session changed "
                    f"(was #{dispatched_session}, now #{self._session_id})"
                )
                return
            try:
                with self._send_lock:
                    dispatched_ws.send(json.dumps(response))
                self.logger.info(f"Response sent for {request_id}")
            except Exception as e:
                self.logger.error(f"Failed to send response for {request_id}: {e}")

        # Route tasks to the appropriate pool:
        #   long  — file transfer / bounded PNM file scans (30–90 s)
        #   identity — fail-fast inventory identity GETs only
        #   bulk  — bounded CMTS inventory and other background work
        #   interactive — GUI clicks and ordinary SNMP operations
        if priority == 'identity':
            self._identity_executor.submit(_run_handler)
        elif priority == 'bulk':
            self._bulk_executor.submit(_run_handler)
        elif priority == 'long' or command in (
            'file_get', 'pnm_file_get', 'pnm_file_delete', 'pnm_file_housekeeping'
        ):
            self._long_executor.submit(_run_handler)
        else:
            self._interactive_executor.submit(_run_handler)
    
    def _handle_ping(self, params: dict) -> dict:
        """Handle ping/connectivity check."""
        target = params.get('target')
        
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '2', target],
            capture_output=True,
            text=True
        )
        
        return {
            'success': result.returncode == 0,
            'reachable': result.returncode == 0,
            'target': target,
            'output': result.stdout
        }

    def _handle_ping_sweep(self, params: dict) -> dict:
        """Bulk ICMP ping sweep — returns list of reachable IPs.

        Params:
            targets: list[str]  — IP addresses to probe
            count: int          — pings per host (default 1)
            timeout: float      — seconds per host (default 1)
            concurrent_tasks: int — parallel probes (default 100)
        """
        targets = params.get('targets', [])
        if not targets:
            return {'success': True, 'reachable': [], 'unreachable': [], 'total': 0}

        count = int(params.get('count', 1))
        timeout = float(params.get('timeout', 1))
        concurrent = int(params.get('concurrent_tasks', 100))

        self.logger.info(f"ping_sweep: {len(targets)} targets, timeout={timeout}s, concurrent={concurrent}")
        try:
            from icmplib import multiping
            # Try privileged=False first (needs net.ipv4.ping_group_range),
            # fall back to privileged=True (needs CAP_NET_RAW or root).
            for privileged in (False, True):
                try:
                    results = multiping(
                        targets,
                        count=count,
                        timeout=timeout,
                        concurrent_tasks=concurrent,
                        privileged=privileged,
                    )
                    reachable = [h.address for h in results if h.is_alive]
                    unreachable = [h.address for h in results if not h.is_alive]
                    self.logger.info(f"ping_sweep done (privileged={privileged}): {len(reachable)}/{len(targets)} reachable")
                    return {
                        'success': True,
                        'reachable': reachable,
                        'unreachable': unreachable,
                        'total': len(targets),
                    }
                except PermissionError:
                    continue
                except OSError as e:
                    if 'not permitted' in str(e).lower() or 'operation not permitted' in str(e).lower():
                        continue
                    raise
            # Both modes failed — fall through to subprocess fallback
            raise PermissionError("icmplib needs root or net.ipv4.ping_group_range")
        except Exception as e:
            self.logger.warning(f"icmplib failed ({e}), falling back to subprocess ping")

        # Fallback: concurrent subprocess ping (no special permissions needed)
        import asyncio
        reachable: list[str] = []

        async def _ping_one(ip: str, sem: asyncio.Semaphore):
            async with sem:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        'ping', '-c', str(count), '-W', str(max(1, int(timeout))), ip,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await asyncio.wait_for(proc.wait(), timeout=timeout + 2)
                    if proc.returncode == 0:
                        reachable.append(ip)
                except Exception:
                    pass

        async def _run_all():
            sem = asyncio.Semaphore(concurrent)
            await asyncio.gather(*[_ping_one(ip, sem) for ip in targets])

        asyncio.run(_run_all())
        unreachable = [ip for ip in targets if ip not in set(reachable)]
        self.logger.info(f"ping_sweep done (subprocess): {len(reachable)}/{len(targets)} reachable")
        return {
            'success': True,
            'reachable': reachable,
            'unreachable': unreachable,
            'total': len(targets),
        }
    
    def _resolve_community(self, params: dict, *, write: bool = False) -> str:
        """Resolve role-specific credentials without letting CM tasks override the agent."""
        explicit = _first_nonblank(params.get('community'))
        target_role = str(
            params.get('target_role') or params.get('target_type') or ''
        ).strip().lower()

        # Preserve legacy explicit-only tasks that predate target_role.
        if target_role not in {'cm', 'cmts'}:
            if explicit is not None:
                self.logger.debug("_resolve_community: using explicit legacy task community")
                return str(explicit)
            raise ValueError(
                "target_role must be 'cm' or 'cmts' when community is omitted"
            )

        if target_role == 'cm':
            # Cable-modem credentials belong to the CM agent. A separate write
            # value is optional because deployed modems commonly use one
            # community for both reads and writes.
            configured = _first_nonblank(
                self.config.cm_write_community if write else None,
                self.config.cm_community,
            )
            if configured is not None:
                if explicit is not None:
                    self.logger.debug(
                        "_resolve_community: ignoring explicit CM task community; "
                        "using agent-configured community"
                    )
                else:
                    self.logger.debug(
                        "_resolve_community: using agent-configured CM community"
                    )
                return str(configured)
            raise ValueError("No SNMP community configured for target_role 'cm'")

        # CMTS explicit overrides and per-target credentials retain their
        # existing precedence; the modem fallback policy must not affect them.
        if explicit is not None:
            self.logger.debug("_resolve_community: using explicit CMTS task community")
            return str(explicit)

        configured = None
        target_ip = _first_nonblank(
            params.get('target_ip'),
            params.get('modem_ip'),
            params.get('ip'),
            params.get('cmts_ip'),
        )
        if target_ip is not None:
            normalized_target = str(target_ip).strip()
            for cmts_entry in self.config.cmts_list:
                if str(cmts_entry.get('ip', '')).strip() != normalized_target:
                    continue
                configured = (
                    cmts_entry.get('write_community')
                    if write
                    else cmts_entry.get('community')
                )
                if configured is not None and str(configured).strip():
                    self.logger.debug(
                        "_resolve_community: using per-target cmts %s community",
                        "write" if write else "read",
                    )
                else:
                    configured = None
                break
        if configured is None:
            configured = (
                self.config.cmts_write_community
                if write
                else self.config.cmts_community
            )
        if configured is None or not str(configured).strip():
            raise ValueError("No SNMP community configured for target_role 'cmts'")

        self.logger.debug("_resolve_community: using configured cmts community")
        return str(configured)

    def _handle_snmp_get(self, params: dict) -> dict:
        """Handle SNMP GET request via pysnmp."""
        target_ip = params.get('target_ip') or params.get('modem_ip')
        if not target_ip:
            return {'success': False, 'error': 'target_ip or modem_ip required'}
        oid = params['oid']
        community = self._resolve_community(params)

        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}

        timeout = params.get('timeout', 5)
        retries = params.get('retries', 2)
        raw_octets = bool(params.get('raw_octets', False))
        return asyncio.run(self._async_snmp_get(
            target_ip,
            oid,
            community,
            timeout,
            retries,
            raw_octets=raw_octets,
        ))

    def _handle_snmp_walk(self, params: dict) -> dict:
        """Handle SNMP WALK request via pysnmp."""
        target_ip = params.get('target_ip') or params.get('modem_ip')
        if not target_ip:
            return {'success': False, 'error': 'target_ip or modem_ip required'}
        oid = params['oid']
        community = self._resolve_community(params)

        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}

        timeout = params.get('timeout', 10)
        retries = params.get('retries', 2)
        return asyncio.run(self._async_snmp_walk(
            target_ip, oid, community, timeout, retries,
        ))

    def _handle_snmp_set(self, params: dict) -> dict:
        """Handle SNMP SET request via pysnmp."""
        target_ip = params.get('target_ip') or params.get('modem_ip')
        if not target_ip:
            return {'success': False, 'error': 'target_ip or modem_ip required'}
        oid = params['oid']
        value = params['value']
        value_type = params.get('type', 'i')
        community = self._resolve_community(params, write=True)

        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}

        timeout = params.get('timeout', 5)
        retries = params.get('retries', 2)
        return asyncio.run(self._async_snmp_set(
            target_ip,
            oid,
            value,
            value_type,
            community,
            timeout,
            retries,
        ))

    def _handle_snmp_set_sequence(self, params: dict) -> dict:
        """Execute a sequence of SNMP SETs using the configured CM credential."""
        target_ip = params.get('target_ip') or params.get('modem_ip')
        if not target_ip:
            return {'success': False, 'error': 'target_ip required'}
        sets = params.get('sets', [])
        if not sets:
            return {'success': False, 'error': 'sets list required'}
        community = self._resolve_community(params, write=True)
        timeout = params.get('timeout', 5)
        retries = params.get('retries', 2)

        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}

        async def run_sequence():
            results = []
            for item in sets:
                oid = item['oid']
                value = item['value']
                value_type = item.get('type', 'i')
                result = await self._async_snmp_set(
                    target_ip,
                    oid,
                    value,
                    value_type,
                    community,
                    timeout,
                    retries,
                )
                results.append({'oid': oid, 'value': value, **result})
                if not result.get('success'):
                    return {
                        'success': False,
                        'failed_oid': oid,
                        'results': results,
                        'error': result.get('error', 'SET failed'),
                    }
                sleep_after = item.get('sleep_after', 0)
                if sleep_after:
                    await asyncio.sleep(sleep_after)
            return {'success': True, 'results': results}

        return asyncio.run(run_sequence())

    def _handle_snmp_bulk_get(self, params: dict) -> dict:
        """Handle multiple SNMP GET requests with controlled concurrency."""
        oids = params.get('oids', [])
        target_ip = params.get('target_ip') or params.get('modem_ip')
        if not target_ip:
            return {'success': False, 'error': 'target_ip or modem_ip required'}
        community = self._resolve_community(params)
        timeout = params.get('timeout', 5)
        retries = params.get('retries', 2)  # 0 = fail-fast (e.g. enrichment), 2 = default
        priority = str(params.get('_agent_priority') or 'interactive')
        try:
            max_concurrent = max(1, int(params.get('max_concurrent', 10)))
        except (TypeError, ValueError):
            max_concurrent = 10
        if priority == 'identity':
            # Identity already has task-level concurrency through its dedicated
            # executor. Serializing each task's OIDs prevents the bounded worker
            # pool from multiplying into many simultaneous pysnmp engines and
            # preserves process capacity for the interactive GUI executor.
            max_concurrent = 1
        self.logger.debug(
            f"snmp_bulk_get: target={target_ip} oids={len(oids)} "
            f"timeout={timeout} retries={retries} priority={priority} "
            f"max_concurrent={max_concurrent}"
        )

        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}

        async def fetch_all():
            semaphore = asyncio.Semaphore(max_concurrent)

            async def fetch_with_semaphore(oid):
                async with semaphore:
                    return await self._async_snmp_get(
                        target_ip, oid, community, timeout, retries,
                    )

            tasks = [fetch_with_semaphore(oid) for oid in oids]
            return await asyncio.gather(*tasks, return_exceptions=True)

        fetch_results = asyncio.run(fetch_all())

        results = {}
        for oid, result in zip(oids, fetch_results):
            if isinstance(result, Exception):
                results[oid] = {'success': False, 'error': str(result)}
            else:
                results[oid] = result

        return {'success': True, 'results': results}
    
    def _handle_snmp_bulk_walk(self, params: dict) -> dict:
        """Handle SNMP BULK WALK for efficient table retrieval (e.g., CMTS modem table)."""
        target_ip = params['target_ip']
        oid = params['oid']
        community = self._resolve_community(params)
        max_repetitions = params.get('max_repetitions', 25)
        limit = params.get('limit', 10000)
        timeout = params.get('timeout', 10)
        
        self.logger.info(f"SNMP bulk walk: {target_ip} OID {oid} (max_rep={max_repetitions}, limit={limit})")
        
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available', 'modems': []}
        
        # Use pysnmp async bulk_walk_cmd
        try:
            modems = asyncio.run(self._async_snmp_bulk_walk(
                target_ip, oid, community, max_repetitions, limit, timeout
            ))
            
            self.logger.info(f"Retrieved {len(modems)} entries from {target_ip}")
            
            return {
                'success': True,
                'modems': modems,
                'count': len(modems)
            }
        except Exception as e:
            self.logger.error(f"SNMP bulk walk failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'modems': []
            }
    
    def _handle_snmp_parallel_walk(self, params: dict) -> dict:
        """Walk multiple OID trees serially within a bounded total deadline."""
        ip = params.get('ip')
        oids = params.get('oids', [])
        community = self._resolve_community(params)
        timeout = max(0.1, float(params.get('timeout', 5)))
        max_reps = max(1, int(params.get('max_repetitions', 500)))
        limit = max(1, int(params.get('limit', 10000)))
        overall_timeout = max(30.0, float(params.get('overall_timeout', 270)))
        try:
            min_remaining_tree_reserve = float(
                params.get('min_remaining_tree_reserve', 0)
            )
        except (TypeError, ValueError):
            min_remaining_tree_reserve = 0.0
        if min_remaining_tree_reserve != min_remaining_tree_reserve:
            min_remaining_tree_reserve = 0.0
        min_remaining_tree_reserve = min(
            max(0.0, min_remaining_tree_reserve),
            overall_timeout / max(len(oids), 1),
        )
        raw_octet_oids = {
            str(raw_oid).strip().lstrip('.')
            for raw_oid in (params.get('raw_octet_oids') or [])
            if str(raw_oid).strip()
        }
        
        if not ip or not oids:
            return {'success': False, 'error': 'ip and oids required'}
        
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        self.logger.info(f"SNMP parallel walk: {ip} - {len(oids)} OIDs")
        
        # Estimate the number of BULK PDUs from the row limit. max_repetitions
        # is rows requested per PDU, not a count of PDUs.
        expected_pdus = max(1, (limit + int(max_reps) - 1) // int(max_reps))
        calculated_tree_limit = float(timeout) * (expected_pdus + 4) * 1.5
        fair_tree_budget = max(10.0, overall_timeout / max(len(oids), 1) * 1.5)
        per_tree_hard_limit = min(calculated_tree_limit, fair_tree_budget)

        async def do_parallel_walk():
            errors = {}   # oid -> error string
            completed_oids = set()
            truncated_oids = set()

            async def walk_one(oid):
                transport = await make_transport(ip, 161, timeout=timeout, retries=0)
                results = []
                async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
                    SnmpEngine(), CommunityData(community), transport, ContextData(),
                    0, max_reps, ObjectType(ObjectIdentity(oid))
                ):
                    if errorIndication:
                        err = str(errorIndication)
                        errors[oid] = err
                        self.logger.warning(f"SNMP walk error OID {oid} on {ip}: {err}")
                        break
                    if errorStatus:
                        err = f"{errorStatus.prettyPrint()} at {errorIndex}"
                        errors[oid] = err
                        self.logger.warning(f"SNMP walk error OID {oid} on {ip}: {err}")
                        break
                    for varBind in varBinds:
                        oid_str = str(varBind[0]).lstrip('.')
                        if not oid_str.startswith(oid.lstrip('.')):
                            completed_oids.add(oid)
                            return results
                        results.append({
                            'oid': oid_str,
                            'value': self._parse_snmp_value(
                                varBind[1],
                                preserve_octets=oid.lstrip('.') in raw_octet_oids,
                            ),
                            'type': type(varBind[1]).__name__
                        })
                        if len(results) >= limit:
                            truncated_oids.add(oid)
                            return results
                if oid not in errors:
                    completed_oids.add(oid)
                return results

            async def walk_one_safe(oid, hard_limit):
                try:
                    return await asyncio.wait_for(walk_one(oid), timeout=hard_limit)
                except asyncio.TimeoutError:
                    err = f"timed out after {hard_limit:.0f}s"
                    errors[oid] = err
                    self.logger.warning(f"walk_one {err} for OID {oid} on {ip}")
                    return []
                except Exception as e:
                    errors[oid] = str(e)
                    self.logger.warning(f"walk_one error OID {oid} on {ip}: {e}")
                    return []

            # Serialize walks against the same modem — cable modems have
            # limited SNMP capacity and drop packets when hit with multiple
            # concurrent bulk walks, causing timeouts.
            all_results = {}
            walk_durations = {}
            loop = asyncio.get_event_loop()
            deadline = loop.time() + overall_timeout
            for index, oid in enumerate(oids):
                remaining = deadline - loop.time()
                if remaining <= 0:
                    for pending_oid in oids[index:]:
                        errors[pending_oid] = f"overall timeout budget exhausted after {overall_timeout:.0f}s"
                        all_results[pending_oid] = []
                        walk_durations[pending_oid] = 0.0
                    break
                later_tree_count = len(oids) - index - 1
                available_for_current = (
                    remaining
                    - min_remaining_tree_reserve * later_tree_count
                )
                if available_for_current <= 0:
                    errors[oid] = (
                        "timeout budget reserved for "
                        f"{later_tree_count} remaining OID tree(s)"
                    )
                    all_results[oid] = []
                    walk_durations[oid] = 0.0
                    continue
                t0 = loop.time()
                all_results[oid] = await walk_one_safe(
                    oid,
                    min(per_tree_hard_limit, available_for_current),
                )
                elapsed = loop.time() - t0
                walk_durations[oid] = round(elapsed, 2)
            non_empty = sum(1 for v in all_results.values() if v)
            success = non_empty > 0

            # Log per-OID timing so we can identify slow MIBs
            dur_summary = ', '.join(
                f"{oid.split('.')[-2]}.{oid.split('.')[-1]}={walk_durations[oid]:.1f}s({len(all_results[oid])}rows)"
                for oid in oids
            )
            self.logger.info(f"Walk durations for {ip}: total={sum(walk_durations.values()):.1f}s | {dur_summary}")

            # Build a human-readable summary for callers
            warnings = []
            if errors:
                for oid, err in errors.items():
                    warnings.append(f"{oid}: {err}")
            if not success:
                warnings.append(
                    f"All {len(oids)} OID trees empty on {ip} — possible wrong community "
                    "or device offline"
                )
                self.logger.error(
                    f"Parallel walk: ALL trees empty for {ip} — "
                    f"{len(errors)} OID errors: {list(errors.values())[:3]}"
                )
            else:
                if errors:
                    self.logger.warning(
                        f"Parallel walk: {non_empty}/{len(oids)} trees returned data for {ip}, "
                        f"{len(errors)} OIDs had errors"
                    )

            return {
                'success': success,
                'results': all_results,
                'warnings': warnings,
                'errors': errors,
                'completed_oids': sorted(completed_oids),
                'truncated_oids': sorted(truncated_oids),
                'walk_durations': walk_durations,
            }
        
        try:
            result = asyncio.run(do_parallel_walk())
            self.logger.info(
                f"Parallel walk completed: {len(result.get('results', {}))} OID trees, "
                f"{sum(1 for v in result.get('results', {}).values() if v)} non-empty"
            )
            return result
        except Exception as e:
            self.logger.error(f"SNMP parallel walk error: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _async_snmp_get(
        self,
        target_ip: str,
        oid: str,
        community: str,
        timeout: int = 5,
        retries: int = 2,
        *,
        raw_octets: bool = False,
    ) -> dict:
        """Async SNMP GET using pysnmp."""
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                SnmpEngine(),
                CommunityData(community),
                await make_transport(target_ip, 161, timeout=timeout, retries=retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            if errorIndication:
                return {
                    'success': False,
                    'error': str(errorIndication),
                    'failure_kind': (
                        'transport_timeout'
                        if type(errorIndication).__name__ == 'RequestTimedOut'
                        else 'transport_error'
                    ),
                }
            elif errorStatus:
                return {'success': False, 'error': f'{errorStatus.prettyPrint()} at {errorIndex}'}
            
            output_lines = []
            for varBind in varBinds:
                value = varBind[1]
                if raw_octets and type(value).__name__ == 'OctetString':
                    rendered_value = bytes(value).hex()
                else:
                    rendered_value = value.prettyPrint()
                output_lines.append(f"{varBind[0].prettyPrint()} = {rendered_value}")
            
            return {'success': True, 'output': '\n'.join(output_lines)}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _async_snmp_walk(
        self, target_ip: str, oid: str, community: str,
        timeout: int = 10, retries: int = 2,
    ) -> dict:
        """Async SNMP WALK using pysnmp."""
        try:
            results = []
            async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
                SnmpEngine(),
                CommunityData(community),
                await make_transport(target_ip, 161, timeout=timeout, retries=retries),
                ContextData(),
                0, 25,  # non-repeaters, max-repetitions
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if errorIndication:
                    return {
                        'success': False,
                        'error': str(errorIndication),
                        'failure_kind': (
                            'transport_timeout'
                            if type(errorIndication).__name__ == 'RequestTimedOut'
                            else 'transport_error'
                        ),
                    }
                elif errorStatus:
                    return {'success': False, 'error': f'{errorStatus.prettyPrint()} at {errorIndex}'}
                
                for varBind in varBinds:
                    oid_str = str(varBind[0]).lstrip('.')
                    # Stop if we've walked past the requested OID tree
                    if not oid_str.startswith(oid.lstrip('.')):
                        break
                    results.append({
                        'oid': oid_str,
                        'value': self._parse_snmp_value(varBind[1]),
                        'type': type(varBind[1]).__name__
                    })
            
            return {'success': True, 'results': results}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _async_snmp_set(
        self, target_ip: str, oid: str, value: any, value_type: str,
        community: str, timeout: int = 5, retries: int = 2,
    ) -> dict:
        """Async SNMP SET using pysnmp."""
        try:
            snmp_value = self._to_snmp_value(value, value_type)
            
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                SnmpEngine(),
                CommunityData(community),
                await make_transport(target_ip, 161, timeout=timeout, retries=retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid), snmp_value)
            )
            
            if errorIndication:
                return {
                    'success': False,
                    'error': str(errorIndication),
                    'failure_kind': (
                        'transport_timeout'
                        if type(errorIndication).__name__ == 'RequestTimedOut'
                        else 'transport_error'
                    ),
                }
            elif errorStatus:
                return {'success': False, 'error': f'{errorStatus.prettyPrint()} at {errorIndex}'}
            
            output_lines = []
            for varBind in varBinds:
                output_lines.append(f"{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}")
            
            return {'success': True, 'output': '\n'.join(output_lines)}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def _async_snmp_bulk_walk(self, target_ip: str, oid: str, community: str, 
                                     max_repetitions: int, limit: int, timeout: int):
        """Async SNMP bulk walk using pysnmp."""
        modems = []
        
        async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
            SnmpEngine(),
            CommunityData(community),
            await make_transport(target_ip, 161, timeout=timeout, retries=2),
            ContextData(),
            0, max_repetitions,  # non-repeaters, max-repetitions
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if errorIndication:
                self.logger.error(f"SNMP error: {errorIndication}")
                break
            elif errorStatus:
                self.logger.error(f"SNMP error: {errorStatus.prettyPrint()}")
                break
            
            for varBind in varBinds:
                oid_val, value = varBind
                mac_hex = value.prettyPrint()
                if mac_hex.startswith('0x'):
                    mac_hex = mac_hex[2:]
                
                if len(mac_hex) == 12:
                    mac_address = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
                    modems.append({
                        'mac_address': mac_address.upper()
                    })
            
            if len(modems) >= limit:
                break
        
        return modems
    
    def _handle_tftp_get(self, params: dict) -> dict:
        """Handle TFTP/PNM file retrieval via SSH to TFTP server."""
        if not self.tftp_ssh:
            return {'success': False, 'error': 'TFTP SSH not configured'}
        
        remote_path = params.get('path', '')
        filename = os.path.basename(remote_path)
        
        tftp_full_path = os.path.join(self.config.tftp_path, remote_path)
        
        try:
            exit_code, stdout, stderr = self.tftp_ssh.execute(
                f"cat '{tftp_full_path}'",
                timeout=60
            )
            
            if exit_code == 0:
                content = stdout.encode() if isinstance(stdout, str) else stdout
                return {
                    'success': True,
                    'filename': filename,
                    'path': remote_path,
                    'size': len(content),
                    'content_base64': content.hex()
                }
            else:
                return {
                    'success': False,
                    'error': stderr or f'Failed to read file: exit code {exit_code}'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def _safe_file_component(value: str, allow_empty: bool = False) -> str:
        """Validate an agent file basename/prefix without accepting paths or globs."""
        text = str(value or '')
        if not text and allow_empty:
            return ''
        if (
            not text
            or text in {'.', '..'}
            or os.path.isabs(text)
            or Path(text).name != text
            or '\x00' in text
            or any(ch in text for ch in ('*', '?', '[', ']'))
        ):
            raise ValueError('Invalid filename or prefix')
        return text

    @staticmethod
    def _path_contains_symlink(path: Path) -> bool:
        """Return True when any existing component of an absolute path is a symlink."""
        current = Path(path.anchor)
        try:
            for component in path.parts[1:]:
                current /= component
                if stat.S_ISLNK(os.lstat(current).st_mode):
                    return True
        except OSError:
            return True
        return False

    def _pnm_file_roots(self) -> list[Path]:
        """Return unique, readable, non-symlink PNM roots in retrieval priority order."""
        roots: list[Path] = []

        def _add_root(value: str | None) -> None:
            if not value:
                return
            root = Path(os.path.abspath(os.path.expanduser(value)))
            try:
                root_stat = os.lstat(root)
            except OSError:
                return
            if (
                root in roots
                or not stat.S_ISDIR(root_stat.st_mode)
                or stat.S_ISLNK(root_stat.st_mode)
                or self._path_contains_symlink(root)
                or not os.access(str(root), os.R_OK)
            ):
                return
            roots.append(root)

        _add_root(os.environ.get('TFTP_ROOT'))
        _add_root(os.environ.get('PYPNM_TFTP_PATH'))
        _add_root(self.config.tftp_path)
        for fallback in ('/var/lib/tftpboot', '/tftpboot', '/tmp', '/access/pnmupload', '/pnmupload'):
            _add_root(fallback)
        return roots

    @staticmethod
    def _bounded_scan_setting(name: str, default: int, hard_maximum: int, minimum: int = 1) -> int:
        """Read a scan setting while retaining a non-bypassable hard bound."""
        try:
            value = int(os.environ.get(name, str(default)))
        except (TypeError, ValueError):
            value = default
        return max(minimum, min(value, hard_maximum))

    def _bounded_pnm_files(self) -> tuple[list[tuple[int, Path]], bool]:
        """Recursively enumerate regular files under approved roots without following symlinks."""
        max_depth = self._bounded_scan_setting('PYPNM_AGENT_SCAN_MAX_DEPTH', 8, 32, 0)
        max_directories = self._bounded_scan_setting('PYPNM_AGENT_SCAN_MAX_DIRECTORIES', 2048, 16384)
        max_files = self._bounded_scan_setting('PYPNM_AGENT_SCAN_MAX_FILES', 20000, 100000)
        directories_scanned = 0
        files_seen = 0
        discovered: list[tuple[int, Path]] = []
        truncated = False

        for root_index, root in enumerate(self._pnm_file_roots()):
            pending: list[tuple[Path, int]] = [(root, 0)]
            while pending:
                if directories_scanned >= max_directories:
                    truncated = True
                    return discovered, truncated
                directory, depth = pending.pop()
                directories_scanned += 1
                try:
                    with os.scandir(directory) as scan:
                        entries = sorted(scan, key=lambda entry: entry.name)
                except OSError as exc:
                    self.logger.debug('PNM scan directory %s unavailable: %s', directory, exc)
                    continue

                child_directories: list[Path] = []
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_file(follow_symlinks=False):
                            if files_seen >= max_files:
                                truncated = True
                                return discovered, truncated
                            files_seen += 1
                            discovered.append((root_index, Path(entry.path)))
                        elif depth < max_depth and entry.is_dir(follow_symlinks=False):
                            child_directories.append(Path(entry.path))
                    except OSError:
                        continue
                for child in reversed(child_directories):
                    pending.append((child, depth + 1))

        return discovered, truncated

    def _pnm_write_root(self) -> Path | None:
        """Return the one explicit writable PNM root, never a discovery fallback."""
        configured = (
            os.environ.get('PYPNM_PNM_WRITE_ROOT')
            or self.config.pnm_file_write_root
        )
        if not configured:
            return None
        root = Path(os.path.abspath(os.path.expanduser(configured)))
        try:
            root_stat = os.lstat(root)
        except OSError:
            return None
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or stat.S_ISLNK(root_stat.st_mode)
            or self._path_contains_symlink(root)
            or not os.access(str(root), os.R_OK | os.W_OK | os.X_OK)
        ):
            return None
        return root

    def _pnm_write_enabled(self, operation: str) -> bool:
        """Check the independent default-deny opt-in for a destructive operation."""
        if operation == 'delete':
            return (
                self.config.pnm_file_delete_enabled is True
                or os.environ.get('PYPNM_PNM_FILE_DELETE_ENABLED', 'false').lower() == 'true'
            )
        if operation == 'housekeeping':
            return (
                self.config.pnm_file_housekeeping_enabled is True
                or os.environ.get('PYPNM_PNM_FILE_HOUSEKEEPING_ENABLED', 'false').lower() == 'true'
            )
        return False

    @classmethod
    def _safe_utsc_capture_name(cls, value: str) -> str:
        """Accept only exact UTSC capture basenames owned by this API."""
        filename = cls._safe_file_component(value)
        if not filename.startswith(('utsc_', 'PNMCcapUsSpecAn_')):
            raise ValueError('Filename is not an approved UTSC capture basename')
        return filename

    def _bounded_pnm_write_files(self, root: Path) -> tuple[list[Path], bool]:
        """Recursively enumerate regular files under the explicit writable root."""
        max_depth = self._bounded_scan_setting('PYPNM_AGENT_SCAN_MAX_DEPTH', 8, 32, 0)
        max_directories = self._bounded_scan_setting(
            'PYPNM_AGENT_SCAN_MAX_DIRECTORIES', 2048, 16384
        )
        max_files = self._bounded_scan_setting('PYPNM_AGENT_SCAN_MAX_FILES', 20000, 100000)
        pending: list[tuple[Path, int]] = [(root, 0)]
        discovered: list[Path] = []
        directories_scanned = 0

        while pending:
            if directories_scanned >= max_directories:
                return discovered, True
            directory, depth = pending.pop()
            directories_scanned += 1
            try:
                with os.scandir(directory) as scan:
                    entries = sorted(scan, key=lambda entry: entry.name)
            except OSError as exc:
                self.logger.debug('PNM write scan directory unavailable: %s', exc)
                continue

            child_directories: list[Path] = []
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_file(follow_symlinks=False):
                        if len(discovered) >= max_files:
                            return discovered, True
                        discovered.append(Path(entry.path))
                    elif depth < max_depth and entry.is_dir(follow_symlinks=False):
                        child_directories.append(Path(entry.path))
                except OSError:
                    continue
            for child in reversed(child_directories):
                pending.append((child, depth + 1))

        return discovered, False

    @staticmethod
    def _unlink_regular_file_nofollow(
        root: Path,
        path: Path,
        expected: os.stat_result,
    ) -> None:
        """Unlink a verified regular file relative to a no-follow parent descriptor."""
        if os.path.commonpath((str(root), str(path.parent))) != str(root):
            raise OSError('File is outside the approved PNM root')
        parent_flags = (
            os.O_RDONLY
            | getattr(os, 'O_CLOEXEC', 0)
            | getattr(os, 'O_DIRECTORY', 0)
            | getattr(os, 'O_NOFOLLOW', 0)
        )
        parent_fd = os.open(str(path.parent), parent_flags)
        file_fd: int | None = None
        try:
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_dev != expected.st_dev
                or current.st_ino != expected.st_ino
                or current.st_size != expected.st_size
                or current.st_mtime_ns != expected.st_mtime_ns
            ):
                raise OSError('File changed before deletion')
            file_flags = (
                os.O_RDONLY
                | getattr(os, 'O_CLOEXEC', 0)
                | getattr(os, 'O_NOFOLLOW', 0)
            )
            file_fd = os.open(path.name, file_flags, dir_fd=parent_fd)
            opened = os.fstat(file_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != current.st_dev
                or opened.st_ino != current.st_ino
            ):
                raise OSError('File changed during secure deletion')
            os.unlink(path.name, dir_fd=parent_fd)
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(parent_fd)

    def _handle_pnm_file_delete(self, params: dict) -> dict:
        """Delete exact approved UTSC basenames from one explicit writable root."""
        if not self._pnm_write_enabled('delete'):
            return {'success': False, 'error': 'PNM file deletion is not enabled'}
        root = self._pnm_write_root()
        if root is None:
            return {'success': False, 'error': 'No approved writable PNM root is configured'}

        raw_names = params.get('filenames')
        if not isinstance(raw_names, list) or not 1 <= len(raw_names) <= 100:
            return {'success': False, 'error': 'filenames must contain 1 to 100 basenames'}
        try:
            filenames = list(dict.fromkeys(
                self._safe_utsc_capture_name(value) for value in raw_names
            ))
        except (TypeError, ValueError) as exc:
            return {'success': False, 'error': str(exc)}

        discovered, truncated = self._bounded_pnm_write_files(root)
        by_name: dict[str, list[Path]] = {}
        for path in discovered:
            if path.name in filenames:
                by_name.setdefault(path.name, []).append(path)

        deleted: list[str] = []
        errors: list[dict] = []
        for filename in filenames:
            matches = by_name.get(filename, [])
            if not matches:
                if truncated:
                    errors.append({'filename': filename, 'error': 'Scan bound reached; absence is uncertain'})
                continue  # Exact deletion is idempotent when the file is already absent.
            if len(matches) != 1:
                errors.append({'filename': filename, 'error': 'Duplicate basename is ambiguous'})
                continue
            path = matches[0]
            try:
                expected = os.lstat(path)
                if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
                    raise OSError('Refusing to delete a symlink or non-regular file')
                self._unlink_regular_file_nofollow(root, path, expected)
                deleted.append(filename)
            except OSError as exc:
                errors.append({'filename': filename, 'error': str(exc)})

        result = {
            'success': not errors,
            'deleted_count': len(deleted),
            'files': deleted,
            'errors': errors,
        }
        if truncated:
            result['truncated'] = True
        if errors:
            result['error'] = 'One or more exact PNM file deletions were refused'
        return result

    def _handle_pnm_file_housekeeping(self, params: dict) -> dict:
        """Delete aged approved UTSC files from one explicit writable root."""
        if not self._pnm_write_enabled('housekeeping'):
            return {'success': False, 'error': 'PNM file housekeeping is not enabled'}
        root = self._pnm_write_root()
        if root is None:
            return {'success': False, 'error': 'No approved writable PNM root is configured'}
        try:
            max_age_seconds = int(params.get('max_age_seconds', 60))
        except (TypeError, ValueError):
            return {'success': False, 'error': 'max_age_seconds must be an integer'}
        if max_age_seconds < 1:
            return {'success': False, 'error': 'max_age_seconds must be positive'}
        dry_run = bool(params.get('dry_run', True))
        cutoff = time.time() - max_age_seconds
        max_actions = self._bounded_scan_setting(
            'PYPNM_AGENT_HOUSEKEEPING_MAX_FILES', 1000, 5000
        )

        discovered, scan_truncated = self._bounded_pnm_write_files(root)
        candidates: list[tuple[Path, os.stat_result]] = []
        for path in discovered:
            if not path.name.startswith(('utsc_', 'PNMCcapUsSpecAn_')):
                continue
            try:
                file_stat = os.lstat(path)
            except OSError:
                continue
            if (
                stat.S_ISREG(file_stat.st_mode)
                and not stat.S_ISLNK(file_stat.st_mode)
                and file_stat.st_mtime < cutoff
            ):
                candidates.append((path, file_stat))
        candidates.sort(key=lambda item: (item[1].st_mtime, item[0].name))
        selected = candidates[:max_actions]
        truncated = scan_truncated or len(candidates) > len(selected)

        records: list[dict] = []
        errors: list[dict] = []
        if dry_run:
            records = [
                {'filename': path.name, 'size_bytes': int(file_stat.st_size), 'source': 'agent'}
                for path, file_stat in selected
            ]
        else:
            for path, file_stat in selected:
                try:
                    self._unlink_regular_file_nofollow(root, path, file_stat)
                    records.append({
                        'filename': path.name,
                        'size_bytes': int(file_stat.st_size),
                        'source': 'agent',
                    })
                except OSError as exc:
                    errors.append({'filename': path.name, 'error': str(exc)})

        result = {
            'success': not errors,
            'dry_run': dry_run,
            'candidate_count': len(candidates),
            'deleted_count': 0 if dry_run else len(records),
            'total_size_bytes': sum(item['size_bytes'] for item in records),
            'files': records[:50],
            'truncated': truncated or len(records) > 50,
            'errors': errors,
        }
        if errors:
            result['error'] = 'One or more aged PNM file deletions were refused'
        return result

    @staticmethod
    def _open_regular_file_nofollow(path: Path) -> tuple[int, os.stat_result]:
        """Open a regular file and verify that the descriptor matches the no-symlink path."""
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise OSError('Refusing to read a symlink or non-regular file')
        flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(str(path), flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise OSError('File changed during secure open')
            return descriptor, opened
        except Exception:
            os.close(descriptor)
            raise

    @classmethod
    def _pnm_header_metadata(cls, path: Path) -> dict | None:
        """Read only enough bytes to classify PNN2/PNN6/PNN7 and identify the modem."""
        descriptor: int | None = None
        try:
            descriptor, opened = cls._open_regular_file_nofollow(path)
            header = os.read(descriptor, 32)
            if len(header) < 17 or header[:3] != b'PNN':
                return None
            pnn_number = int(header[3])
            if pnn_number not in {2, 6, 7}:
                return None
            # PNN2/6/7 use the standard 10-byte PNM header. Their payloads
            # start with channel ID followed by the six-byte cable-modem MAC.
            payload_offset = 10
            channel_id = int(header[payload_offset])
            mac_bytes = header[payload_offset + 1:payload_offset + 7]
            if len(mac_bytes) != 6:
                return None
            mac_address = ':'.join(f'{octet:02x}' for octet in mac_bytes)
            return {
                'pnm_file_type': f'PNN{pnn_number}',
                'direction': 'downstream' if pnn_number == 2 else 'upstream',
                'mac_address': mac_address,
                'channel_id': channel_id,
                'capture_time': int.from_bytes(header[6:10], byteorder='big', signed=False),
                'size': int(opened.st_size),
                'modified_time': float(opened.st_mtime),
            }
        except (OSError, ValueError, IndexError):
            return None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @classmethod
    def _read_regular_file_nofollow(cls, path: Path, max_bytes: int) -> bytes:
        """Read one bounded regular file through a verified no-follow descriptor."""
        descriptor: int | None = None
        try:
            descriptor, opened = cls._open_regular_file_nofollow(path)
            size = int(opened.st_size)
            if size <= 0 or size > max_bytes:
                raise ValueError('File is empty or exceeds the configured size limit')
            chunks: list[bytes] = []
            remaining = size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise OSError('File changed while being read')
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise OSError('File changed while being read')
            return b''.join(chunks)
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _handle_pnm_file_catalog(self, params: dict) -> dict:
        """Return metadata for recursively discovered PNN2/PNN6/PNN7 files."""
        raw_mac = str(params.get('mac_address') or '').strip().lower()
        requested_mac = raw_mac.replace(':', '').replace('-', '').replace('.', '')
        if requested_mac and (
            len(requested_mac) != 12
            or any(ch not in '0123456789abcdef' for ch in requested_mac)
        ):
            return {'success': False, 'error': 'mac_address must contain 12 hexadecimal digits'}
        direction = str(params.get('direction') or 'both').lower()
        if direction not in {'downstream', 'upstream', 'both'}:
            return {'success': False, 'error': 'direction must be downstream, upstream, or both'}
        requested_types = {
            str(value).upper() for value in (params.get('pnm_types') or ['PNN2', 'PNN6', 'PNN7'])
        }
        requested_types &= {'PNN2', 'PNN6', 'PNN7'}
        if not requested_types:
            return {'success': False, 'error': 'No supported PNM types requested'}
        try:
            limit = max(1, min(int(params.get('limit') or 1000), 5000))
        except (TypeError, ValueError):
            return {'success': False, 'error': 'limit must be an integer'}

        # Basenames are the public identity. Prefer the first approved root;
        # within that root, retain the newest matching duplicate basename.
        files_by_name: dict[str, tuple[int, dict]] = {}
        discovered, truncated = self._bounded_pnm_files()
        for root_index, path in discovered:
            metadata = self._pnm_header_metadata(path)
            if metadata is None or metadata['pnm_file_type'] not in requested_types:
                continue
            if direction != 'both' and metadata['direction'] != direction:
                continue
            normalized_mac = metadata['mac_address'].replace(':', '')
            if requested_mac and normalized_mac != requested_mac:
                continue

            candidate = {'filename': path.name, **metadata}
            existing = files_by_name.get(path.name)
            if existing is None or root_index < existing[0]:
                files_by_name[path.name] = (root_index, candidate)
            elif root_index == existing[0]:
                existing_item = existing[1]
                if (
                    int(candidate.get('capture_time', 0)),
                    float(candidate.get('modified_time', 0.0)),
                ) > (
                    int(existing_item.get('capture_time', 0)),
                    float(existing_item.get('modified_time', 0.0)),
                ):
                    files_by_name[path.name] = (root_index, candidate)

        files = sorted(
            (item for _, item in files_by_name.values()),
            key=lambda item: (
                int(item.get('capture_time', 0)),
                float(item.get('modified_time', 0.0)),
                str(item.get('filename', '')),
            ),
            reverse=True,
        )[:limit]
        response = {'success': True, 'files': files, 'count': len(files)}
        if truncated:
            response['warning'] = 'PNM catalog scan reached a configured safety bound; results may be incomplete'
        return response

    def _handle_pnm_file_get(self, params: dict) -> dict:
        """Recursively retrieve an exact basename from approved roots without following symlinks."""
        import base64

        try:
            filename = self._safe_file_component(params.get('filename', ''))
        except ValueError as exc:
            return {'success': False, 'error': str(exc)}
        try:
            max_bytes = int(os.environ.get('PYPNM_AGENT_FILE_MAX_BYTES', str(32 * 1024 * 1024)))
        except (TypeError, ValueError):
            return {'success': False, 'error': 'PYPNM_AGENT_FILE_MAX_BYTES must be an integer'}
        if max_bytes <= 0:
            return {'success': False, 'error': 'PYPNM_AGENT_FILE_MAX_BYTES must be positive'}

        discovered, truncated = self._bounded_pnm_files()
        candidates: list[Path] = []
        selected_root: int | None = None
        for root_index, path in discovered:
            if path.name != filename:
                continue
            if selected_root is None:
                selected_root = root_index
            if root_index == selected_root:
                candidates.append(path)

        if not candidates:
            suffix = ' before a scan safety bound was reached' if truncated else ''
            return {'success': False, 'error': f'Exact PNM file basename not found{suffix}'}
        try:
            selected = max(candidates, key=lambda path: os.lstat(path).st_mtime)
            data = self._read_regular_file_nofollow(selected, max_bytes)
            return {
                'success': True,
                'filename': selected.name,
                'size': len(data),
                'content_base64': base64.b64encode(data).decode(),
            }
        except FileNotFoundError:
            return {'success': False, 'error': 'PNM file disappeared during retrieval'}
        except (OSError, ValueError) as exc:
            return {'success': False, 'error': f'PNM file retrieval refused: {exc}'}

    def _handle_file_list(self, params: dict) -> dict:
        """List regular files matching one or more safe basename prefixes."""
        raw_prefixes = params.get('prefixes')
        if raw_prefixes is None:
            single = params.get('prefix')
            raw_prefixes = [single] if single is not None else []
        if not isinstance(raw_prefixes, list) or not raw_prefixes:
            return {'success': False, 'error': 'prefix or prefixes param required'}
        try:
            prefixes = [self._safe_file_component(value, allow_empty=True) for value in raw_prefixes]
        except ValueError as exc:
            return {'success': False, 'error': str(exc)}

        matches: list[str] = []
        for root in self._pnm_file_roots():
            try:
                with os.scandir(root) as entries:
                    matches = sorted({
                        entry.name
                        for entry in entries
                        if entry.is_file(follow_symlinks=False)
                        and any(entry.name.startswith(prefix) for prefix in prefixes)
                    })
            except OSError:
                continue
            if matches:
                break
        return {'success': True, 'files': matches, 'count': len(matches)}

    def _handle_file_get(self, params: dict) -> dict:
        """Read a bounded regular file selected by safe basename or prefix."""
        import base64

        try:
            filename = self._safe_file_component(params.get('filename', ''))
        except ValueError as exc:
            return {'success': False, 'error': str(exc)}
        use_prefix = bool(params.get('glob', True))
        selected: Path | None = None

        for root in self._pnm_file_roots():
            candidates: list[Path] = []
            try:
                with os.scandir(root) as entries:
                    for entry in entries:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        if (use_prefix and entry.name.startswith(filename)) or (not use_prefix and entry.name == filename):
                            candidates.append(Path(entry.path))
            except OSError:
                continue
            if candidates:
                selected = max(candidates, key=lambda path: path.stat().st_mtime)
                break

        if selected is None:
            return {'success': False, 'error': 'File not found'}

        try:
            max_bytes = int(os.environ.get('PYPNM_AGENT_FILE_MAX_BYTES', str(32 * 1024 * 1024)))
            size = selected.stat().st_size
            if size <= 0 or size > max_bytes:
                return {'success': False, 'error': 'File is empty or exceeds the configured size limit'}
            data = selected.read_bytes()
            return {
                'success': True,
                'filename': selected.name,
                'size': len(data),
                'content_base64': base64.b64encode(data).decode(),
            }
        except FileNotFoundError:
            return {'success': False, 'error': 'File not found'}
        except Exception as exc:
            return {'success': False, 'error': str(exc)}

    def _handle_cmts_command(self, params: dict) -> dict:
        """Execute command on CMTS via SSH."""
        cmts_host = params.get('cmts_host') or params.get('cmts_ip')
        command = params.get('command')
        username = params.get('username') or self.config.cmts_ssh_user
        key_file = params.get('key_file') or self.config.cmts_ssh_key
        
        if not cmts_host or not command:
            return {'success': False, 'error': 'cmts_host and command required'}
        
        if not self.config.cmts_ssh_enabled:
            return {'success': False, 'error': 'CMTS SSH not enabled in agent config'}
        
        if not username:
            return {'success': False, 'error': 'CMTS SSH user not configured'}
        
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': cmts_host,
                'username': username,
                'timeout': 30
            }
            
            if key_file:
                key_file = os.path.expanduser(key_file)
                connect_kwargs['key_filename'] = key_file
            
            self.logger.info(f"Connecting to CMTS {cmts_host} via SSH")
            ssh.connect(**connect_kwargs)
            
            stdin, stdout, stderr = ssh.exec_command(command, timeout=60)
            output = stdout.read().decode('utf-8', errors='replace')
            error = stderr.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()
            
            ssh.close()
            
            return {
                'success': exit_code == 0,
                'output': output,
                'error': error if error else None,
                'exit_code': exit_code,
                'cmts_host': cmts_host
            }
            
        except Exception as e:
            self.logger.error(f"CMTS SSH command failed: {e}")
            return {'success': False, 'error': str(e)}
    
    
    def _parse_snmp_value(self, value, *, preserve_octets: bool = False) -> Any:
        """Parse a pysnmp value, optionally preserving OCTET STRING bytes as hex."""
        try:
            if value is None:
                return None
            
            type_name = type(value).__name__
            
            if type_name == 'OctetString':
                raw = bytes(value)
                if preserve_octets:
                    return raw.hex()
                non_printable = any(b < 0x20 or b > 0x7e for b in raw)
                # Preserve the established binary MAC representation, but
                # serialize every other non-text OCTET STRING losslessly before
                # decoding or stripping. This includes valid UTF-8 control bytes
                # such as profile/IUC values 0x09 through 0x0d.
                if len(raw) == 6 and non_printable:
                    return ':'.join(f'{b:02x}' for b in raw).upper()
                if non_printable:
                    return raw.hex()
                try:
                    return raw.decode('utf-8').strip()
                except UnicodeDecodeError:
                    return raw.hex()
            
            if type_name == 'IpAddress':
                if hasattr(value, 'prettyPrint'):
                    return value.prettyPrint()
                raw = bytes(value)
                if len(raw) == 4:
                    return '.'.join(str(b) for b in raw)
                return str(value)
            
            # Integer types -- pysnmp v7 has quirks with int() conversion
            if type_name in ('Integer', 'Integer32', 'Unsigned32', 'Counter32', 
                            'Counter64', 'Gauge32', 'TimeTicks'):
                
                # Best: use internal _value attr
                if hasattr(value, '_value') and value._value is not None:
                    try:
                        return int(value._value)
                    except (ValueError, TypeError):
                        try:
                            return int(str(value._value))
                        except:
                            pass
                
                # Fallback: prettyPrint
                if hasattr(value, 'prettyPrint'):
                    pretty = value.prettyPrint()
                    if pretty:
                        if type_name == 'TimeTicks' and ':' in pretty:
                            return pretty  # e.g. "1:23:45.67"
                        try:
                            return int(pretty)
                        except (ValueError, TypeError):
                            pass
                
                # Fallback: direct int(), guard against pysnmp returning 0 incorrectly
                try:
                    n = int(value)
                    if n == 0 and hasattr(value, 'prettyPrint'):
                        pretty = value.prettyPrint()
                        if pretty and pretty != '0':
                            import re
                            m = re.findall(r'\d+', pretty)
                            if m:
                                return int(m[0])
                    return n
                except (ValueError, TypeError):
                    pass
                
                try:
                    s = str(value)
                    return int(s) if s.isdigit() else s
                except:
                    return 0
            
            if type_name == 'ObjectIdentifier':
                return str(value)
            
            return str(value) if value else ''
                
        except Exception:
            return None
    
    def _to_snmp_value(self, value: Any, value_type: str):
        """Convert Python value to pysnmp type."""
        type_map = {
            'i': Integer32, 'u': Unsigned32, 's': OctetString,
            'x': OctetString, 'a': IpAddress, 'c': Counter32,
            'g': Gauge32, 't': TimeTicks,
        }
        
        if value_type == 'x':
            if isinstance(value, str):
                hex_clean = value.replace(' ', '').replace(':', '')
                value = bytes.fromhex(hex_clean)
            return OctetString(value)
        
        snmp_type = type_map.get(value_type, OctetString)
        return snmp_type(value)
    
    def connect(self):
        """Connect to PyPNM Server."""
        self.running = True

        # PyPNM WebSocket is always direct (LAN or our own SSH tunnel)
        # -- never route it through a corporate HTTP proxy
        for _var in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'):
            os.environ.pop(_var, None)

        if self.config.pypnm_ssh_tunnel_enabled:
            if not self._setup_pypnm_tunnel():
                self.logger.error("Failed to establish SSH tunnel, cannot continue")
                return

        if self.config.peer_tunnels:
            self._setup_peer_tunnel()  # non-fatal -- log and continue
        
        ws_url = self._get_websocket_url()
        
        while self.running:
            try:
                self.logger.info(f"Connecting to {ws_url}...")
                
                self.ws = websocket.WebSocketApp(
                    ws_url,
                    on_open=self._on_open,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                )

                # Always bypass HTTP proxy -- PyPNM connection is direct (LAN or SSH tunnel)
                self.ws.run_forever(
                    ping_interval=120,
                    ping_timeout=60,
                )
                
            except Exception as e:
                self.logger.error(f"Connection failed: {e}")
            
            if self.running:
                self.logger.info(f"Reconnecting in {self.config.reconnect_interval} seconds...")
                time.sleep(self.config.reconnect_interval)
    
    def stop(self):
        """Stop the agent and cleanup connections."""
        self.logger.info("Stopping agent...")
        self.running = False
        if self.ws:
            self.ws.close()
        if self.cm_proxy:
            self.cm_proxy.close()
        if self.tftp_ssh:
            self.tftp_ssh.close()
        if self.pypnm_tunnel_monitor:
            self.pypnm_tunnel_monitor.stop()
        for monitor in self.peer_tunnel_monitors:
            monitor.stop()
        for tunnel in self.peer_tunnels:
            tunnel.stop_tunnel()
        self.peer_tunnel_monitors.clear()
        self.peer_tunnels.clear()
        if self.pypnm_tunnel:
            self.pypnm_tunnel.stop_tunnel()
        self._reset_executors()

        self.logger.info("Agent stopped")


def main():
    """Main entry point for the PyPNM Agent."""
    import argparse
    
    parser = argparse.ArgumentParser(description='PyPNM Remote Agent')
    parser.add_argument('--config', '-c', type=str, help='Path to agent_config.json')
    parser.add_argument('--agent-id', type=str, help='Override agent ID from config')
    parser.add_argument('--url', help='PyPNM Server WebSocket URL (overrides config)')
    parser.add_argument('--token', help='Authentication token (overrides config)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    if args.config:
        config = AgentConfig.from_file(args.config)
        logger.info(f"Loaded config from {args.config}")
    else:
        # Try default locations
        possible_configs = [
            'agent_config.json',
            os.path.expanduser('~/.pypnm-agent/agent_config.json'),
            os.path.expanduser('~/agent_config.json'),
            '/etc/pypnm-agent/agent_config.json',
        ]
        config = None
        for config_path in possible_configs:
            if os.path.exists(config_path):
                config = AgentConfig.from_file(config_path)
                logger.info(f"Loaded config from {config_path}")
                break
        
        if not config:
            config = AgentConfig.from_env()
            logger.info("Loaded config from environment variables")
    
    # Override with command line args
    if args.agent_id:
        config.agent_id = args.agent_id
    if args.url:
        config.pypnm_server_url = args.url
    if args.token:
        config.auth_token = args.token
    
    # Log configuration summary
    logger.info(f"Agent ID: {config.agent_id}")
    logger.info(
        "Worker pools: gui=%s bulk=%s identity=%s long=%s",
        config.interactive_workers,
        config.bulk_workers,
        config.identity_workers,
        config.long_workers,
    )
    logger.info(f"PyPNM Server: {config.pypnm_server_url}")
    logger.info(f"PyPNM SSH Tunnel: {'enabled -> ' + config.pypnm_ssh_host if config.pypnm_ssh_tunnel_enabled else 'disabled'}")
    logger.info(f"CMTS SNMP: {'enabled' if config.cmts_enabled else 'disabled'}")
    logger.info(f"CM access: {'enabled' if config.cm_enabled else 'disabled'}")
    logger.info(f"CM Proxy: {config.cm_proxy_host or 'not configured'}")
    logger.info(f"TFTP SSH: {config.tftp_ssh_host or 'not configured'}")
    enabled_peer_tunnels = [pt for pt in config.peer_tunnels if pt.get('enabled', True)]
    if enabled_peer_tunnels:
        logger.info(f"Peer reverse tunnels: {len(enabled_peer_tunnels)} configured")
        for pt in enabled_peer_tunnels:
            logger.info(
                f"  [{pt.get('label', 'peer')}]"
                f" -R {pt.get('remote_port', 8000)}:localhost:{pt.get('local_port', 8000)}"
                f" via {pt.get('ssh_user', '')}@{pt.get('ssh_host')}:{pt.get('ssh_port', 22)}"
            )
    else:
        logger.info("Peer reverse tunnels: none configured")
    
    agent = PyPNMAgent(config)
    
    try:
        agent.connect()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        agent.stop()


if __name__ == '__main__':
    main()
