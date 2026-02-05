# PyPNM Jump Server Agent
# SPDX-License-Identifier: Apache-2.0
# 
# This agent runs on the Jump Server and connects OUT to the GUI Server
# via WebSocket. It executes SNMP/SSH commands and returns results.

import json
import logging
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
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

# pysnmp imports (pysnmp v7 uses v3arch.asyncio)
try:
    import asyncio
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity,
        get_cmd, set_cmd, bulk_walk_cmd,
        Integer32, OctetString, Unsigned32, Counter32, Counter64, Gauge32, TimeTicks, IpAddress
    )
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    print("WARNING: pysnmp not installed. Using net-snmp fallback.")

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
logger = logging.getLogger('PyPNM-Agent')


@dataclass
class AgentConfig:
    """Agent configuration for Jump Server deployment."""
    agent_id: str
    pypnm_server_url: str
    auth_token: str
    reconnect_interval: int = 5
    
    # SSH Tunnel to PyPNM Server (WebSocket connection)
    pypnm_ssh_tunnel_enabled: bool = False
    pypnm_ssh_host: Optional[str] = None
    pypnm_ssh_port: int = 22
    pypnm_ssh_user: Optional[str] = None
    pypnm_ssh_key: Optional[str] = None
    pypnm_tunnel_local_port: int = 8080
    pypnm_tunnel_remote_port: int = 8080
    
    # CMTS Access - for SNMP to CMTS devices
    cmts_enabled: bool = True
    cmts_community: str = 'public'
    cmts_write_community: Optional[str] = None
    # Optional: SSH to CMTS for CLI commands
    cmts_ssh_enabled: bool = False
    cmts_ssh_user: Optional[str] = None
    cmts_ssh_key: Optional[str] = None
    
    # CM Access - for SNMP to Cable Modems
    cm_enabled: bool = False
    cm_community: str = 'm0d3m1nf0'
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
    redis_ttl: int = 300  # Cache TTL in seconds
    
    # TFTP/FTP Server - accessed via SSH for PNM file retrieval
    tftp_ssh_host: Optional[str] = None
    tftp_ssh_port: int = 22
    tftp_ssh_user: Optional[str] = None
    tftp_ssh_key: Optional[str] = None
    tftp_path: str = "/tftpboot"
    
    @classmethod
    def from_file(cls, path: str) -> 'AgentConfig':
        """Load configuration from JSON file."""
        with open(path) as f:
            data = json.load(f)
        
        # Expand ~ in paths
        def expand_path(p):
            return os.path.expanduser(p) if p else None
        
        # Support both old 'gui_server' and new 'pypnm_server' keys
        server_config = data.get('pypnm_server') or data.get('gui_server', {})
        tunnel_config = data.get('pypnm_ssh_tunnel') or data.get('gui_ssh_tunnel', {})
        
        # CMTS access config
        cmts = data.get('cmts_access', {})
        
        # CM access config - support both old and new format
        cm_access = data.get('cm_access', {})
        cm_proxy = cm_access.get('proxy', {}) or data.get('cm_proxy', {})  # New or old format
        
        # Backward compat: cm_direct -> cm_access
        cm_direct = data.get('cm_direct', {})
        cm_enabled = cm_access.get('enabled', cm_direct.get('enabled', False))
        cm_community = cm_access.get('community', cm_direct.get('community', 'm0d3m1nf0'))
        
        equalizer = data.get('equalizer', {})
        redis_config = data.get('redis', {})
        tftp = data.get('tftp_server', {})
        
        return cls(
            agent_id=data['agent_id'],
            pypnm_server_url=server_config['url'],
            auth_token=server_config.get('auth_token', 'dev-token'),
            reconnect_interval=server_config.get('reconnect_interval', 5),
            # SSH Tunnel to PyPNM Server
            pypnm_ssh_tunnel_enabled=tunnel_config.get('enabled', False),
            pypnm_ssh_host=tunnel_config.get('ssh_host'),
            pypnm_ssh_port=tunnel_config.get('ssh_port', 22),
            pypnm_ssh_user=tunnel_config.get('ssh_user'),
            pypnm_ssh_key=expand_path(tunnel_config.get('ssh_key_file')),
            pypnm_tunnel_local_port=tunnel_config.get('local_port', 8080),
            pypnm_tunnel_remote_port=tunnel_config.get('remote_port', 8080),
            # CMTS Access
            cmts_enabled=cmts.get('enabled', cmts.get('snmp_direct', True)),  # Backward compat
            cmts_community=cmts.get('community', 'public'),
            cmts_write_community=cmts.get('write_community'),
            cmts_ssh_enabled=cmts.get('ssh_enabled', False),
            cmts_ssh_user=cmts.get('ssh_user'),
            cmts_ssh_key=expand_path(cmts.get('ssh_key_file')),
            # CM Access
            cm_enabled=cm_enabled,
            cm_community=cm_community,
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
        )
    
    @classmethod
    def from_env(cls) -> 'AgentConfig':
        """Load configuration from environment variables."""
        def expand_path(p):
            return os.path.expanduser(p) if p else None
        
        return cls(
            agent_id=os.environ.get('PYPNM_AGENT_ID', 'agent-01'),
            pypnm_server_url=os.environ.get('PYPNM_SERVER_URL', 'ws://127.0.0.1:5050/ws/agent'),
            auth_token=os.environ.get('PYPNM_AUTH_TOKEN', 'dev-token'),
            reconnect_interval=int(os.environ.get('PYPNM_RECONNECT_INTERVAL', '5')),
            # SSH Tunnel to PyPNM
            pypnm_ssh_tunnel_enabled=os.environ.get('PYPNM_SSH_TUNNEL', 'false').lower() == 'true',
            pypnm_ssh_host=os.environ.get('PYPNM_SSH_HOST'),
            pypnm_ssh_port=int(os.environ.get('PYPNM_SSH_PORT', '22')),
            pypnm_ssh_user=os.environ.get('PYPNM_SSH_USER'),
            pypnm_ssh_key=expand_path(os.environ.get('PYPNM_SSH_KEY')),
            pypnm_tunnel_local_port=int(os.environ.get('PYPNM_LOCAL_PORT', '8080')),
            pypnm_tunnel_remote_port=int(os.environ.get('PYPNM_REMOTE_PORT', '8080')),
            # CMTS Access
            cmts_enabled=os.environ.get('PYPNM_CMTS_ENABLED', 'true').lower() == 'true',
            # CM Access
            cm_enabled=os.environ.get('PYPNM_CM_ENABLED', 'false').lower() == 'true',
            cm_community=os.environ.get('PYPNM_CM_COMMUNITY', 'm0d3m1nf0'),
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
                    'content_base64': content.hex()  # Send as hex for binary safety
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
        
        # SSH Tunnel to PyPNM Server (if enabled)
        self.pypnm_tunnel = None
        self.pypnm_tunnel_monitor = None
        
        # Initialize SSH executor for CM Proxy (to reach modems)
        self.cm_proxy: Optional[SSHProxyExecutor] = None
        if config.cm_proxy_host:
            self.cm_proxy = SSHProxyExecutor(
                host=config.cm_proxy_host,
                port=config.cm_proxy_port,
                username=config.cm_proxy_user,
                key_file=config.cm_proxy_key
            )
            self.logger.info(f"CM Proxy configured: {config.cm_proxy_host}")
        
        # Equalizer executor for CMTS SNMP
        self.equalizer: Optional[SSHProxyExecutor] = None
        if config.equalizer_host:
            self.equalizer = SSHProxyExecutor(
                host=config.equalizer_host,
                port=config.equalizer_port,
                username=config.equalizer_user,
                key_file=config.equalizer_key
            )
            self.logger.info(f"Equalizer configured: {config.equalizer_host}")
        
        # SSH executor for TFTP server
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
            'snmp_bulk_get': self._handle_snmp_bulk_get,
            'snmp_bulk_walk': self._handle_snmp_bulk_walk,
            'tftp_get': self._handle_tftp_get,
            'cmts_command': self._handle_cmts_command,
            'execute_pnm': self._handle_pnm_command,
            'cmts_get_modems': self._handle_cmts_get_modems,
            'cmts_get_modem_info': self._handle_cmts_get_modem_info,
            'enrich_modems': self._handle_enrich_modems,
            # PNM measurement commands (downstream - on CM)
            'pnm_rxmer': self._handle_pnm_rxmer,
            'pnm_spectrum': self._handle_pnm_spectrum,
            'pnm_fec': self._handle_pnm_fec,
            'pnm_pre_eq': self._handle_pnm_pre_eq,
            'pnm_channel_info': self._handle_pnm_channel_info,
            'pnm_event_log': self._handle_pnm_event_log,
            # OFDM capture commands (downstream - on CM)
            'pnm_ofdm_channels': self._handle_pnm_ofdm_channels,
            'pnm_ofdm_capture': self._handle_pnm_ofdm_capture,
            'pnm_ofdm_rxmer': self._handle_pnm_ofdm_rxmer,
            'pnm_set_tftp': self._handle_pnm_set_tftp,
            # Upstream PNM commands (on CMTS)
            'pnm_utsc_configure': self._handle_pnm_utsc_configure,
            'pnm_utsc_start': self._handle_pnm_utsc_start,
            'pnm_utsc_stop': self._handle_pnm_utsc_stop,
            'pnm_utsc_status': self._handle_pnm_utsc_status,
            'pnm_utsc_data': self._handle_pnm_utsc_data,
            'pnm_us_rxmer_start': self._handle_pnm_us_rxmer_start,
            'pnm_us_rxmer_status': self._handle_pnm_us_rxmer_status,
            'pnm_us_rxmer_data': self._handle_pnm_us_rxmer_data,
            'pnm_us_get_interfaces': self._handle_pnm_us_get_interfaces,
        }
    
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
            
            # Start tunnel monitor for auto-reconnect
            self.pypnm_tunnel_monitor = TunnelMonitor(self.pypnm_tunnel)
            self.pypnm_tunnel_monitor.start()
            
            self.logger.info(f"PyPNM SSH tunnel established: localhost:{self.config.pypnm_tunnel_local_port} → {self.config.pypnm_ssh_host}:{self.config.pypnm_tunnel_remote_port}")
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
            return f"ws://127.0.0.1:{self.config.pypnm_tunnel_local_port}/ws/agent"
        else:
            return self.config.pypnm_server_url
    
    def _on_open(self, ws):
        """Called when WebSocket connection is established."""
        ws_url = self._get_websocket_url()
        self.logger.info(f"Connected to PyPNM Server: {ws_url}")
        
        # Send authentication message
        auth_msg = {
            'type': 'auth',
            'agent_id': self.config.agent_id,
            'token': self.config.auth_token,
            'capabilities': self._get_capabilities()
        }
        ws.send(json.dumps(auth_msg))
    
    def _on_message(self, ws, message):
        """Called when a message is received."""
        try:
            data = json.loads(message)
            msg_type = data.get('type')
            
            if msg_type == 'auth_success':
                self.logger.info(f"Authentication successful as {data.get('agent_id')}")
                
            elif msg_type == 'auth_response':
                # Legacy support
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
        """Called when connection is closed."""
        self.logger.warning(f"Connection closed: {close_status_code} - {close_msg}")
    
    def _get_capabilities(self) -> list[str]:
        """Return list of agent capabilities.
        
        Special tags:
        - cm_reachable: Agent can reach cable modems directly (for modem SNMP)
        - cmts_reachable: Agent can reach CMTS devices (for CMTS SNMP)
        """
        caps = ['snmp_get', 'snmp_walk', 'snmp_set', 'snmp_bulk_get']
        
        # CM (Cable Modem) reachability
        if self.cm_proxy:
            caps.append('cm_proxy')
            caps.append('cm_reachable')  # Can reach modems via proxy
        
        if self.config.cm_enabled:
            caps.append('cm_reachable')  # Can reach modems directly
        
        # CMTS reachability  
        if self.config.cmts_enabled:
            caps.append('cmts_reachable')  # Can reach CMTS
            caps.append('cmts_snmp_direct')  # Backward compat
            caps.append('cmts_get_modems')
            caps.append('cmts_get_modem_info')
            caps.append('enrich_modems')
        
        if self.config.cmts_ssh_enabled:
            caps.append('cmts_command')  # Can execute CMTS CLI commands via SSH
        
        if self.tftp_ssh:
            caps.append('tftp_get')
        
        caps.append('execute_pnm')
        
        # OFDM capture capabilities (requires CM access)
        caps.extend(['pnm_ofdm_channels', 'pnm_ofdm_capture', 'pnm_ofdm_rxmer', 'pnm_set_tftp', 'pnm_spectrum'])
        
        # Modem SNMP capabilities (requires cm_reachable)
        caps.extend(['pnm_channel_info', 'pnm_event_log'])
        
        # Upstream PNM capabilities (requires cmts_reachable)
        if self.config.cmts_enabled:
            caps.extend([
                'pnm_utsc_configure', 'pnm_utsc_start', 'pnm_utsc_stop', 'pnm_utsc_status', 'pnm_utsc_data',
                'pnm_us_rxmer_start', 'pnm_us_rxmer_status', 'pnm_us_rxmer_data', 'pnm_us_get_interfaces'
            ])
        
        return caps
    
    def _handle_command(self, ws, data: dict):
        """Handle incoming command from PyPNM Server."""
        request_id = data.get('request_id')
        command = data.get('command')
        params = data.get('params', {})
        
        self.logger.info(f"Received command: {request_id} - {command}")
        
        # Find handler
        handler = self.handlers.get(command)
        
        if handler:
            try:
                result = handler(params)
                response = {
                    'type': 'response',
                    'request_id': request_id,
                    'result': result
                }
                self.logger.info(f"Handler returned for {request_id}")
            except Exception as e:
                self.logger.exception(f"Command execution error: {e}")
                response = {
                    'type': 'error',
                    'request_id': request_id,
                    'error': str(e)
                }
        else:
            response = {
                'type': 'error',
                'request_id': request_id,
                'error': f'Unknown command: {command}'
            }
        
        self.logger.info(f"Sending response for {request_id}")
        ws.send(json.dumps(response))
        self.logger.info(f"Response sent for {request_id}")
    
    # ============== Command Handlers ==============
    
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
    
    def _handle_snmp_get(self, params: dict) -> dict:
        """Handle SNMP GET request via pysnmp."""
        target_ip = params['target_ip']
        oid = params['oid']
        community = params.get('community', 'private')
        
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        return asyncio.run(self._async_snmp_get(target_ip, oid, community, params.get('timeout', 5)))
    
    def _handle_snmp_walk(self, params: dict) -> dict:
        """Handle SNMP WALK request via pysnmp."""
        target_ip = params['target_ip']
        oid = params['oid']
        community = params.get('community', 'private')
        
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        return asyncio.run(self._async_snmp_walk(target_ip, oid, community, params.get('timeout', 10)))
    
    def _handle_snmp_set(self, params: dict) -> dict:
        """Handle SNMP SET request via pysnmp."""
        target_ip = params['target_ip']
        oid = params['oid']
        value = params['value']
        value_type = params.get('type', 'i')
        community = params.get('community', 'private')
        
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        return asyncio.run(self._async_snmp_set(target_ip, oid, value, value_type, community, params.get('timeout', 5)))
    
    def _handle_snmp_bulk_get(self, params: dict) -> dict:
        """Handle multiple SNMP GET requests."""
        oids = params.get('oids', [])
        target_ip = params['target_ip']
        community = params.get('community', 'private')
        timeout = params.get('timeout', 5)
        
        # Use pysnmp
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        results = {}
        for oid in oids:
            try:
                result = asyncio.run(self._async_snmp_get(target_ip, oid, community, timeout))
                results[oid] = result
            except Exception as e:
                results[oid] = {'success': False, 'error': str(e)}
        return {'success': True, 'results': results}
    
    def _handle_snmp_bulk_walk(self, params: dict) -> dict:
        """Handle SNMP BULK WALK for efficient table retrieval (e.g., CMTS modem table)."""
        target_ip = params['target_ip']
        oid = params['oid']
        community = params.get('community', 'public')
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
    
    async def _async_snmp_get(self, target_ip: str, oid: str, community: str, timeout: int = 5) -> dict:
        """Async SNMP GET using pysnmp."""
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                SnmpEngine(),
                CommunityData(community),
                await UdpTransportTarget.create((target_ip, 161), timeout=timeout, retries=2),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            if errorIndication:
                return {'success': False, 'error': str(errorIndication)}
            elif errorStatus:
                return {'success': False, 'error': f'{errorStatus.prettyPrint()} at {errorIndex}'}
            
            # Format output
            output_lines = []
            for varBind in varBinds:
                output_lines.append(f"{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}")
            
            return {'success': True, 'output': '\n'.join(output_lines)}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _async_snmp_walk(self, target_ip: str, oid: str, community: str, timeout: int = 10) -> dict:
        """Async SNMP WALK using pysnmp."""
        try:
            output_lines = []
            async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
                SnmpEngine(),
                CommunityData(community),
                await UdpTransportTarget.create((target_ip, 161), timeout=timeout, retries=2),
                ContextData(),
                0, 25,  # non-repeaters, max-repetitions
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if errorIndication:
                    return {'success': False, 'error': str(errorIndication)}
                elif errorStatus:
                    return {'success': False, 'error': f'{errorStatus.prettyPrint()} at {errorIndex}'}
                
                for varBind in varBinds:
                    output_lines.append(f"{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}")
            
            return {'success': True, 'output': '\n'.join(output_lines)}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _async_snmp_set(self, target_ip: str, oid: str, value: any, value_type: str, 
                               community: str, timeout: int = 5) -> dict:
        """Async SNMP SET using pysnmp."""
        try:
            # Map value type to pysnmp type
            type_map = {
                'i': Integer32,
                's': OctetString,
                'u': Unsigned32,
                'c': Counter32,
                'C': Counter64,
                'g': Gauge32,
                't': TimeTicks,
                'a': IpAddress,
            }
            
            pysnmp_type = type_map.get(value_type, OctetString)
            
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                SnmpEngine(),
                CommunityData(community),
                await UdpTransportTarget.create((target_ip, 161), timeout=timeout, retries=2),
                ContextData(),
                ObjectType(ObjectIdentity(oid), pysnmp_type(value))
            )
            
            if errorIndication:
                return {'success': False, 'error': str(errorIndication)}
            elif errorStatus:
                return {'success': False, 'error': f'{errorStatus.prettyPrint()} at {errorIndex}'}
            
            # Format output
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
            await UdpTransportTarget.create((target_ip, 161), timeout=timeout, retries=2),
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
                # Extract MAC address from hex string
                mac_hex = value.prettyPrint()
                if mac_hex.startswith('0x'):
                    mac_hex = mac_hex[2:]
                
                # Convert to standard MAC format
                if len(mac_hex) == 12:
                    mac_address = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
                    modems.append({
                        'mac_address': mac_address.upper()
                    })
            
            if len(modems) >= limit:
                break
        
        return modems
    
    async def _async_cmts_get_modems(self, cmts_ip: str, community: str, limit: int,
                                      oid_d3_mac: str, oid_old_mac: str, oid_old_ip: str,
                                      oid_old_status: str, oid_d31_freq: str) -> dict:
        """Async CMTS modem discovery using pysnmp with parallel walks."""
        import asyncio
        
        async def bulk_walk_oid(oid: str, timeout: int = 30) -> list:
            """Walk a single OID and return list of (index, value) tuples."""
            results = []
            try:
                async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    await UdpTransportTarget.create((cmts_ip, 161), timeout=timeout, retries=2),
                    ContextData(),
                    0, 50,  # non-repeaters, max-repetitions
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False
                ):
                    if errorIndication or errorStatus:
                        break
                    for varBind in varBinds:
                        oid_str = str(varBind[0])
                        # Extract full suffix after base OID (not just last component)
                        base_oid_parts = oid.split('.')
                        full_oid_parts = oid_str.split('.')
                        suffix_parts = full_oid_parts[len(base_oid_parts):]
                        index = '.'.join(suffix_parts) if suffix_parts else oid_str.split('.')[-1]
                        value = varBind[1]
                        results.append((index, value))
                        if len(results) >= limit:
                            return results
            except Exception as e:
                self.logger.debug(f"Bulk walk {oid} failed: {e}")
            return results
        
        # OIDs for upstream channel mapping
        OID_US_CH_ID = '1.3.6.1.4.1.4491.2.1.20.1.4.1.3'     # docsIf3CmtsCmUsStatusChIfIndex (US channel)
        OID_SW_REV = '1.3.6.1.2.1.10.127.1.2.2.1.3'  # docsIfCmtsCmStatusValue (firmware/software revision)
        
        # Run essential walks in parallel (skip slow MD-IF-INDEX and fiber node queries)
        mac_task = asyncio.create_task(bulk_walk_oid(oid_d3_mac))
        old_mac_task = asyncio.create_task(bulk_walk_oid(oid_old_mac))
        old_ip_task = asyncio.create_task(bulk_walk_oid(oid_old_ip))
        old_status_task = asyncio.create_task(bulk_walk_oid(oid_old_status))
        d31_freq_task = asyncio.create_task(bulk_walk_oid(oid_d31_freq))
        us_ch_task = asyncio.create_task(bulk_walk_oid(OID_US_CH_ID))
        sw_rev_task = asyncio.create_task(bulk_walk_oid(OID_SW_REV))
        
        mac_results, old_mac_results, old_ip_results, old_status_results, d31_freq_results, us_ch_results, sw_rev_results = await asyncio.gather(
            mac_task, old_mac_task, old_ip_task, old_status_task, d31_freq_task, us_ch_task, sw_rev_task
        )
        
        # Parse MAC addresses from docsIf3 table
        mac_map = {}  # index -> mac
        for index, value in mac_results:
            mac_hex = value.prettyPrint()
            if mac_hex.startswith('0x'):
                mac_hex = mac_hex[2:]
            mac_hex = mac_hex.replace(' ', '').replace(':', '')
            if len(mac_hex) >= 12:
                mac = ':'.join([mac_hex[i:i+2] for i in range(0, 12, 2)]).lower()
                mac_map[index] = mac
        
        self.logger.info(f"Parsed {len(mac_map)} MAC addresses from docsIf3 table (pysnmp)")
        
        # Query MD-IF-INDEX individually for each modem (bulk walk unreliable on E6000)
        OID_MD_IF_INDEX = '1.3.6.1.4.1.4491.2.1.20.1.3.1.5'  # docsIf3CmtsCmRegStatusMdIfIndex
        md_if_map = {}  # modem_index -> md_if_index
        if_name_map = {}  # md_if_index -> interface_name (cable-mac 108, etc)
        
        async def get_md_if_and_name(modem_idx):
            """Query MD-IF-INDEX and IF-MIB::ifName for modem"""
            try:
                # Get MD-IF-INDEX
                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    await UdpTransportTarget.create((cmts_ip, 161), timeout=3, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(f'{OID_MD_IF_INDEX}.{modem_idx}'))
                )
                if errorIndication or errorStatus:
                    return (modem_idx, None, None)
                
                md_if_index = None
                for varBind in varBinds:
                    value = varBind[1]
                    if hasattr(value, 'prettyPrint'):
                        pp = value.prettyPrint()
                        if pp and 'No Such' not in pp:
                            try:
                                md_if_index = int(pp)
                            except:
                                pass
                
                if not md_if_index:
                    return (modem_idx, None, None)
                
                # Get IF-MIB::ifName for this MD-IF-INDEX
                OID_IF_NAME = '1.3.6.1.2.1.31.1.1.1.1'
                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    await UdpTransportTarget.create((cmts_ip, 161), timeout=3, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(f'{OID_IF_NAME}.{md_if_index}'))
                )
                if not errorIndication and not errorStatus:
                    for varBind in varBinds:
                        if_name = str(varBind[1])
                        if if_name and 'No Such' not in if_name:
                            return (modem_idx, md_if_index, if_name)
                
                return (modem_idx, md_if_index, None)
            except Exception as e:
                return (modem_idx, None, None)
        
        # Query in batches for speed
        modem_indexes = list(mac_map.keys())
        batch_size = 20  # Parallel queries
        for i in range(0, len(modem_indexes), batch_size):
            batch = modem_indexes[i:i+batch_size]
            tasks = [get_md_if_and_name(idx) for idx in batch]
            results = await asyncio.gather(*tasks)
            
            for modem_idx, md_if_idx, if_name in results:
                if md_if_idx:
                    md_if_map[modem_idx] = md_if_idx
                    if if_name:
                        if_name_map[md_if_idx] = if_name
        
        self.logger.info(f"Resolved {len(md_if_map)} MD-IF-INDEX values and {len(if_name_map)} interface names")
        
        # Discover OFDMA upstream interfaces using PyPNM method
        # Query docsIf31CmtsCmUsOfdmaChannelTimingOffset which has index: {cm_index}.{ofdma_ifindex}
        OID_CM_OFDMA_TIMING = '1.3.6.1.4.1.4491.2.1.28.1.4.1.2'  # docsIf31CmtsCmUsOfdmaChannelTimingOffset
        ofdma_if_results = await bulk_walk_oid(OID_CM_OFDMA_TIMING)
        
        # Build map of cm_index -> ofdma_ifindex
        ofdma_if_map = {}  # cm_index -> ofdma_ifindex
        ofdma_ifindexes = set()
        for index, value in ofdma_if_results:
            try:
                # Index format: {cm_index}.{ofdma_ifindex}
                parts = index.split('.')
                if len(parts) >= 2:
                    cm_idx = parts[0]
                    ofdma_ifidx = int(parts[1])
                    # OFDMA ifindexes are typically in the 843087xxx range (large numbers)
                    if ofdma_ifidx >= 840000000:
                        ofdma_if_map[cm_idx] = ofdma_ifidx
                        ofdma_ifindexes.add(ofdma_ifidx)
            except:
                pass
        
        self.logger.info(f"Discovered {len(ofdma_if_map)} OFDMA upstream interfaces")
        
        # Query IF-MIB::ifDescr for OFDMA interfaces to get upstream interface names
        # This gives us the actual upstream port like "Cable8/0/1 upstream 0"
        ofdma_descr_map = {}  # ofdma_ifindex -> description
        if ofdma_ifindexes:
            OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2'  # IF-MIB::ifDescr
            
            async def get_if_descr(ofdma_ifidx):
                """Query ifDescr for OFDMA ifIndex"""
                try:
                    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                        SnmpEngine(),
                        CommunityData(community),
                        await UdpTransportTarget.create((cmts_ip, 161), timeout=5, retries=1),
                        ContextData(),
                        ObjectType(ObjectIdentity(f'{OID_IF_DESCR}.{ofdma_ifidx}'))
                    )
                    if not errorIndication and not errorStatus:
                        for varBind in varBinds:
                            value = str(varBind[1])
                            if value and 'No Such' not in value:
                                return (ofdma_ifidx, value)
                except:
                    pass
                return (ofdma_ifidx, None)
            
            ofdma_descr_tasks = [get_if_descr(idx) for idx in ofdma_ifindexes]
            ofdma_descr_results = await asyncio.gather(*ofdma_descr_tasks)
            
            for ofdma_ifidx, descr in ofdma_descr_results:
                if descr:
                    ofdma_descr_map[ofdma_ifidx] = descr
                    self.logger.info(f"OFDMA IF-MIB: {ofdma_ifidx} -> {descr}")
            
            self.logger.info(f"Resolved {len(ofdma_descr_map)} OFDMA interface descriptions")
        
        # Build old table MAC lookup
        old_mac_map = {}  # old_index -> mac
        for index, value in old_mac_results:
            mac_hex = value.prettyPrint()
            if mac_hex.startswith('0x'):
                mac_hex = mac_hex[2:]
            mac_hex = mac_hex.replace(' ', '').replace(':', '')
            if len(mac_hex) >= 12:
                mac = ':'.join([mac_hex[i:i+2] for i in range(0, 12, 2)]).lower()
                old_mac_map[index] = mac
        
        # Build old table IP lookup
        old_ip_map = {}  # old_index -> ip
        for index, value in old_ip_results:
            ip = value.prettyPrint()
            old_ip_map[index] = ip
        
        # Build old table status lookup
        old_status_map = {}  # old_index -> status
        for index, value in old_status_results:
            try:
                old_status_map[index] = int(value)
            except:
                pass
        
        # Build firmware/software revision map (old table index)
        sw_rev_map = {}  # old_index -> firmware_version
        for index, value in sw_rev_results:
            try:
                firmware = str(value)
                if firmware and firmware != 'No Such Instance currently exists at this OID' and firmware != '0':
                    sw_rev_map[index] = firmware
            except:
                pass
        
        # Build DOCSIS 3.1 detection
        d31_map = {}  # index -> is_docsis31
        for index, value in d31_freq_results:
            try:
                freq = int(value)
                d31_map[index] = freq > 0
            except:
                pass
        
        # Build US channel mapping
        us_ch_map = {}  # index -> us_channel_id
        for index, value in us_ch_results:
            try:
                # US channel OID has compound index: {modem_index}.{channel_ifindex}
                # Extract modem_index (first part) as the key
                modem_index = index.split('.')[0] if '.' in index else index
                us_ch_map[modem_index] = int(value)
            except:
                pass
                pass
        
        self.logger.info(f"Correlated {len(us_ch_map)} US channel mappings")
        if us_ch_map:
            self.logger.info(f"US channel sample keys: {list(us_ch_map.keys())[:5]}")
        self.logger.info(f"MAC map sample keys: {list(mac_map.keys())[:5]}")
        
        # Create MAC -> IP and MAC -> status lookups
        mac_to_ip = {}
        mac_to_status = {}
        mac_to_firmware = {}
        for old_index, mac in old_mac_map.items():
            if old_index in old_ip_map:
                mac_to_ip[mac] = old_ip_map[old_index]
            if old_index in old_status_map:
                mac_to_status[mac] = old_status_map[old_index]
            if old_index in sw_rev_map:
                mac_to_firmware[mac] = sw_rev_map[old_index]
        
        self.logger.info(f"Correlated {len(mac_to_ip)} IP addresses from old table (pysnmp)")
        self.logger.info(f"Correlated {len(mac_to_status)} status values from old table (pysnmp)")
        self.logger.info(f"Correlated {len(mac_to_firmware)} firmware versions from old table (pysnmp)")
        
        # Status code mapping
        STATUS_MAP = {
            1: 'other', 2: 'ranging', 3: 'rangingAborted', 4: 'rangingComplete',
            5: 'ipComplete', 6: 'registrationComplete', 7: 'accessDenied',
            8: 'operational', 9: 'registeredBPIInitializing'
        }
        
        # Build modem list
        modems = []
        d31_count = 0
        d30_count = 0
        
        for index, mac in mac_map.items():
            modem = {
                'mac_address': mac,
                'cmts_index': index
            }
            
            # Add IP if available
            if mac in mac_to_ip:
                modem['ip_address'] = mac_to_ip[mac]
            
            # Add status if available
            if mac in mac_to_status:
                status_code = mac_to_status[mac]
                modem['status_code'] = status_code
                modem['status'] = STATUS_MAP.get(status_code, 'unknown')
            
            # Add vendor from MAC OUI
            modem['vendor'] = self._get_vendor_from_mac(mac)
            
            # Add firmware if available
            if mac in mac_to_firmware:
                modem['firmware'] = mac_to_firmware[mac]
            
            # Add DOCSIS version
            is_d31 = d31_map.get(index, False)
            modem['docsis_version'] = 'DOCSIS 3.1' if is_d31 else 'DOCSIS 3.0'
            if is_d31:
                d31_count += 1
            else:
                d30_count += 1
            
            # Add cable-mac interface (from MD-IF-INDEX -> IF-MIB::ifName)
            if index in md_if_map:
                md_if_index = md_if_map[index]
                if md_if_index in if_name_map:
                    modem['cable_mac'] = if_name_map[md_if_index]
            
            # Add OFDMA upstream interface if available (DOCSIS 3.1)
            if index in ofdma_if_map:
                ofdma_ifindex = ofdma_if_map[index]
                modem['ofdma_ifindex'] = ofdma_ifindex
                if ofdma_ifindex in ofdma_descr_map:
                    modem['upstream_interface'] = ofdma_descr_map[ofdma_ifindex]
                else:
                    modem['upstream_interface'] = f"ofdmaIfIndex.{ofdma_ifindex}"
            elif 'cable_mac' in modem:
                # Non-OFDMA modems: use cable_mac as upstream_interface
                modem['upstream_interface'] = modem['cable_mac']
            
            if index in us_ch_map:
                modem['upstream_channel_id'] = us_ch_map[index]
            
            modems.append(modem)
        
        self.logger.info(f"DOCSIS version detection: {d31_count} x 3.1, {d30_count} x 3.0 (pysnmp)")
        
        return {
            'success': True,
            'modems': modems,
            'count': len(modems),
            'cmts_ip': cmts_ip
        }

    def _handle_tftp_get(self, params: dict) -> dict:
        """Handle TFTP/PNM file retrieval via SSH to TFTP server."""
        if not self.tftp_ssh:
            return {'success': False, 'error': 'TFTP SSH not configured'}
        
        remote_path = params.get('path', '')
        filename = os.path.basename(remote_path)
        
        # Full path on TFTP server
        tftp_full_path = os.path.join(self.config.tftp_path, remote_path)
        
        try:
            # Read file via SSH
            exit_code, stdout, stderr = self.tftp_ssh.execute(
                f"cat '{tftp_full_path}'",
                timeout=60
            )
            
            if exit_code == 0:
                # File content retrieved
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
    
    def _handle_pnm_command(self, params: dict) -> dict:
        """Handle PyPNM-specific commands (trigger PNM tests via SNMP)."""
        pnm_type = params.get('pnm_type')
        target_ip = params.get('target_ip')
        community = params.get('community', 'private')
        
        # PNM OIDs for different tests
        pnm_oids = {
            'rxmer': '1.3.6.1.4.1.4491.2.1.27.1.3.1',
            'spectrum': '1.3.6.1.4.1.4491.2.1.27.1.3.2',
            'fec': '1.3.6.1.4.1.4491.2.1.27.1.3.3',
        }
        
        if pnm_type not in pnm_oids:
            return {'success': False, 'error': f'Unknown PNM type: {pnm_type}'}
        
        # This would trigger the actual PNM measurement via SNMP
        # For now, return a placeholder
        return {
            'success': True,
            'pnm_type': pnm_type,
            'message': f'PNM {pnm_type} triggered for {target_ip}'
        }
    
    # ========== PYSNMP-BASED SNMP METHODS (pysnmp v7) ==========
    
    def _snmp_get(self, host: str, oid: str, community: str, timeout: int = 10) -> dict:
        """SNMP GET using pysnmp v7 (async)."""
        if not PYSNMP_AVAILABLE:
            return self._snmp_get_fallback(host, oid, community)
        
        async def do_get():
            try:
                transport = await UdpTransportTarget.create((host, 161), timeout=timeout, retries=1)
                result = await get_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    transport,
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                
                errorIndication, errorStatus, errorIndex, varBinds = result
                
                if errorIndication:
                    return {'success': False, 'error': str(errorIndication)}
                elif errorStatus:
                    return {'success': False, 'error': f'{errorStatus.prettyPrint()} at {errorIndex}'}
                else:
                    results = []
                    for varBind in varBinds:
                        oid_str = str(varBind[0])
                        value = varBind[1]
                        results.append({
                            'oid': oid_str,
                            'value': self._parse_snmp_value(value),
                            'type': type(value).__name__
                        })
                    return {'success': True, 'results': results}
            except Exception as e:
                self.logger.error(f"SNMP GET error: {e}")
                return {'success': False, 'error': str(e)}
        
        return asyncio.run(do_get())
    
    def _snmp_walk(self, host: str, oid: str, community: str, timeout: int = 10) -> dict:
        """SNMP WALK using pysnmp v7 (async)."""
        if not PYSNMP_AVAILABLE:
            return self._snmp_walk_fallback(host, oid, community)
        
        async def do_walk():
            try:
                transport = await UdpTransportTarget.create((host, 161), timeout=timeout, retries=1)
                results = []
                
                async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    transport,
                    ContextData(),
                    0, 25,  # nonRepeaters, maxRepetitions
                    ObjectType(ObjectIdentity(oid))
                ):
                    if errorIndication:
                        if not results:  # Only error if no results yet
                            return {'success': False, 'error': str(errorIndication)}
                        break
                    elif errorStatus:
                        break
                    else:
                        for varBind in varBinds:
                            oid_str = str(varBind[0])
                            # Stop if we've walked past the requested OID tree
                            if not oid_str.startswith(oid):
                                return {'success': len(results) > 0, 'results': results}
                            value = varBind[1]
                            results.append({
                                'oid': oid_str,
                                'value': self._parse_snmp_value(value),
                                'type': type(value).__name__
                            })
                
                return {'success': len(results) > 0, 'results': results}
            except Exception as e:
                self.logger.error(f"SNMP WALK error: {e}")
                return {'success': False, 'error': str(e)}
        
        return asyncio.run(do_walk())
    
    def _snmp_set(self, host: str, oid: str, value: Any, value_type: str, community: str, timeout: int = 10) -> dict:
        """SNMP SET using pysnmp v7 (async)."""
        if not PYSNMP_AVAILABLE:
            return self._snmp_set_fallback(host, oid, value, value_type, community)
        
        async def do_set():
            try:
                transport = await UdpTransportTarget.create((host, 161), timeout=timeout, retries=1)
                # Convert value to appropriate pysnmp type
                snmp_value = self._to_snmp_value(value, value_type)
                
                result = await set_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    transport,
                    ContextData(),
                    ObjectType(ObjectIdentity(oid), snmp_value)
                )
                
                errorIndication, errorStatus, errorIndex, varBinds = result
                
                if errorIndication:
                    return {'success': False, 'error': str(errorIndication)}
                elif errorStatus:
                    return {'success': False, 'error': f'{errorStatus.prettyPrint()} at {errorIndex}'}
                else:
                    return {'success': True}
            except Exception as e:
                self.logger.error(f"SNMP SET error: {e}")
                return {'success': False, 'error': str(e)}
        
        return asyncio.run(do_set())
    
    def _snmp_bulk_get(self, host: str, oids: list, community: str, timeout: int = 10) -> dict:
        """SNMP BULK GET - fetch multiple OIDs in one request using pysnmp v7."""
        if not PYSNMP_AVAILABLE:
            # Fallback: do individual gets
            results = []
            for oid in oids:
                r = self._snmp_get_fallback(host, oid, community)
                if r.get('success') and r.get('results'):
                    results.extend(r['results'])
            return {'success': len(results) > 0, 'results': results}
        
        async def do_bulk_get():
            try:
                from pysnmp.hlapi.v3arch.asyncio import bulk_cmd
                transport = await UdpTransportTarget.create((host, 161), timeout=timeout, retries=1)
                
                # Create ObjectType for each OID
                obj_types = [ObjectType(ObjectIdentity(oid)) for oid in oids]
                
                result = await bulk_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    transport,
                    ContextData(),
                    0, len(oids),  # nonRepeaters=0, maxRepetitions=len(oids)
                    *obj_types
                )
                
                errorIndication, errorStatus, errorIndex, varBinds = result
                
                if errorIndication:
                    return {'success': False, 'error': str(errorIndication)}
                elif errorStatus:
                    return {'success': False, 'error': f'{errorStatus.prettyPrint()} at {errorIndex}'}
                else:
                    results = []
                    for varBind in varBinds:
                        oid_str = str(varBind[0])
                        value = varBind[1]
                        results.append({
                            'oid': oid_str,
                            'value': self._parse_snmp_value(value),
                            'type': type(value).__name__
                        })
                    return {'success': True, 'results': results}
            except Exception as e:
                self.logger.error(f"SNMP BULK GET error: {e}")
                return {'success': False, 'error': str(e)}
        
        return asyncio.run(do_bulk_get())
    
    def _snmp_parallel_walk(self, host: str, oids: list, community: str, timeout: int = 10) -> dict:
        """SNMP parallel walk - walk multiple OID trees concurrently using asyncio."""
        if not PYSNMP_AVAILABLE:
            # Fallback: do sequential walks
            all_results = {}
            for oid in oids:
                r = self._snmp_walk_fallback(host, oid, community)
                all_results[oid] = r.get('results', []) if r.get('success') else []
            return {'success': any(len(v) > 0 for v in all_results.values()), 'results': all_results}
        
        async def do_parallel_walk():
            try:
                async def walk_one(oid):
                    transport = await UdpTransportTarget.create((host, 161), timeout=timeout, retries=1)
                    results = []
                    async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
                        SnmpEngine(),
                        CommunityData(community),
                        transport,
                        ContextData(),
                        0, 25,
                        ObjectType(ObjectIdentity(oid))
                    ):
                        if errorIndication or errorStatus:
                            break
                        for varBind in varBinds:
                            oid_str = str(varBind[0])
                            if not oid_str.startswith(oid):
                                return results
                            results.append({
                                'oid': oid_str,
                                'value': self._parse_snmp_value(varBind[1]),
                                'type': type(varBind[1]).__name__
                            })
                    return results
                
                # Run all walks concurrently
                tasks = [walk_one(oid) for oid in oids]
                results_list = await asyncio.gather(*tasks)
                
                all_results = dict(zip(oids, results_list))
                return {'success': any(len(v) > 0 for v in all_results.values()), 'results': all_results}
            except Exception as e:
                self.logger.error(f"SNMP parallel walk error: {e}")
                return {'success': False, 'error': str(e)}
        
        return asyncio.run(do_parallel_walk())
    
    def _parse_snmp_value(self, value) -> Any:
        """Parse pysnmp value to Python native type."""
        try:
            # Check the actual pysnmp type name
            type_name = type(value).__name__
            
            # For OctetString (may contain binary data like MAC addresses)
            if type_name == 'OctetString':
                raw = bytes(value)
                # Try to decode as UTF-8 string first
                try:
                    return raw.decode('utf-8')
                except:
                    # Return as hex string for binary data (like MAC addresses)
                    return ':'.join(f'{b:02x}' for b in raw)
            
            # For integer types
            if type_name in ('Integer', 'Integer32', 'Unsigned32', 'Counter32', 'Counter64', 'Gauge32', 'TimeTicks'):
                return int(value)
            
            # For IpAddress
            if type_name == 'IpAddress':
                return value.prettyPrint()
            
            # Fallback to prettyPrint
            if hasattr(value, 'prettyPrint'):
                return value.prettyPrint()
            
            return str(value)
        except Exception as e:
            # Ultimate fallback
            if hasattr(value, 'prettyPrint'):
                return value.prettyPrint()
            return str(value)
    
    def _to_snmp_value(self, value: Any, value_type: str):
        """Convert Python value to pysnmp type."""
        type_map = {
            'i': Integer32,      # INTEGER
            'u': Unsigned32,     # Unsigned32
            's': OctetString,    # STRING
            'x': OctetString,    # Hex-STRING (we'll convert)
            'a': IpAddress,      # IpAddress
            'c': Counter32,      # Counter32
            'g': Gauge32,        # Gauge32
            't': TimeTicks,      # TimeTicks
        }
        
        if value_type == 'x':
            # Hex string - convert to bytes
            if isinstance(value, str):
                # Remove spaces and convert hex to bytes
                hex_clean = value.replace(' ', '').replace(':', '')
                value = bytes.fromhex(hex_clean)
            return OctetString(value)
        
        snmp_type = type_map.get(value_type, OctetString)
        return snmp_type(value)
    
    # ========== CONVENIENCE METHODS ==========
    
    def _query_modem(self, modem_ip: str, oid: str, community: str, walk: bool = False) -> dict:
        """Query a modem via pysnmp."""
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        if walk:
            return asyncio.run(self._async_snmp_walk(modem_ip, oid, community, timeout=10))
        else:
            return asyncio.run(self._async_snmp_get(modem_ip, oid, community, timeout=5))
    
    def _handle_pnm_rxmer(self, params: dict) -> dict:
        """Get RxMER (Receive Modulation Error Ratio) data from modem."""
        modem_ip = params.get('modem_ip')
        community = params.get('community') or self.config.cm_community
        mac_address = params.get('mac_address')
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        self.logger.info(f"Getting RxMER for modem {modem_ip}")
        
        # DOCSIS 3.1 RxMER OIDs (docsIf31CmDsOfdmChannelPowerTable)
        OID_OFDM_POWER = '1.3.6.1.4.1.4491.2.1.28.1.5'  # docsIf31CmDsOfdmChannelPowerTable
        OID_DS_MER = '1.3.6.1.4.1.4491.2.1.20.1.24.1.1'  # docsIf3CmStatusUsTxPower (for reference)
        
        result = self._query_modem(modem_ip, OID_OFDM_POWER, community, walk=True)
        
        if not result.get('success'):
            return {'success': False, 'error': result.get('error', 'SNMP query failed')}
        
        # Parse RxMER values
        measurements = []
        for line in result.get('output', '').split('\n'):
            if '=' in line and ('INTEGER' in line or 'Gauge' in line):
                try:
                    parts = line.split('=')
                    oid_part = parts[0].strip()
                    value_part = parts[1].strip()
                    
                    # Extract channel index from OID
                    idx = oid_part.split('.')[-1]
                    
                    # Extract value
                    val = ''.join(c for c in value_part.split(':')[-1] if c.isdigit() or c == '-')
                    if val:
                        measurements.append({
                            'channel_id': int(idx),
                            'mer_db': float(val) / 10 if abs(int(val)) > 100 else float(val)
                        })
                except:
                    pass
        
        return {
            'success': True,
            'mac_address': mac_address,
            'modem_ip': modem_ip,
            'timestamp': datetime.now().isoformat(),
            'measurements': measurements,
            'average_mer_db': sum(m['mer_db'] for m in measurements) / len(measurements) if measurements else 0
        }
    
    def _handle_pnm_spectrum(self, params: dict) -> dict:
        """Trigger DS OFDM Spectrum Analyzer (Full Band Capture) via SNMP.
        
        This triggers the modem to perform a spectrum capture and upload to TFTP.
        PyPNM then reads the file from TFTP and generates matplotlib plots.
        """
        import os
        import time
        from datetime import datetime
        
        modem_ip = params.get('modem_ip')
        mac_address = params.get('mac_address', '')
        community = params.get('community', os.environ.get('CM_SNMP_COMMUNITY', ''))
        tftp_server = params.get('tftp_server', os.environ.get('TFTP_IPV4', '172.22.147.18'))
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        self.logger.info(f"Triggering Spectrum Analyzer capture for {modem_ip} (community: {community[:4]}...)")
        
        try:
            # Step 1: Set TFTP/Bulk destination (from PyPNM setDocsPnmBulk)
            # docsPnmBulkDestIpAddrType.0 = 1 (IPv4)
            OID_BULK_IP_TYPE = '1.3.6.1.4.1.4491.2.1.27.1.1.1.1.0'
            # docsPnmBulkDestIpAddr.0 = IP as bytes  
            OID_BULK_IP_ADDR = '1.3.6.1.4.1.4491.2.1.27.1.1.1.2.0'
            # docsPnmBulkUploadControl.0 = 3 (AUTO_UPLOAD)
            OID_BULK_UPLOAD_CTRL = '1.3.6.1.4.1.4491.2.1.27.1.1.1.4.0'
            
            self.logger.info(f"Setting TFTP server: {tftp_server}")
            self._snmp_set(modem_ip, OID_BULK_IP_TYPE, 1, 'i', community)
            ip_parts = tftp_server.split('.')
            ip_hex = ''.join([f'{int(p):02x}' for p in ip_parts])
            self._snmp_set(modem_ip, OID_BULK_IP_ADDR, ip_hex, 'x', community)
            self._snmp_set(modem_ip, OID_BULK_UPLOAD_CTRL, 3, 'i', community)  # 3 = AUTO_UPLOAD
            
            # Step 2: Configure Spectrum Analyzer (from PyPNM setDocsIf3CmSpectrumAnalysisCtrlCmd)
            # These OIDs are from docsIf3CmSpectrumAnalysisCtrlCmd (1.3.6.1.4.1.4491.2.1.20.1.34)
            mac_clean = mac_address.replace(':', '').lower()
            timestamp = int(datetime.now().timestamp())
            filename = f"spectrum_{mac_clean}_{timestamp}"
            
            # Detect vendor and adjust segment span for Ubee modems
            vendor = self._get_vendor_from_mac(mac_address)
            segment_span = 1_000_000  # Default 1 MHz
            if vendor == 'Ubee':
                segment_span = 2_000_000  # Ubee needs 2 MHz minimum
                self.logger.info(f"Ubee modem detected ({mac_address}), using 2 MHz segment span")
            else:
                self.logger.info(f"Vendor: {vendor}, using 1 MHz segment span")
            
            # Spectrum analyzer parameters (from PyPNM SpectrumAnalysisDefaults)
            first_seg_freq = 108_000_000  # 108 MHz
            last_seg_freq = 993_000_000   # 993 MHz
            num_bins = 256
            noise_bw = 110  # Hz
            window_func = 1  # HANN
            num_averages = 1
            inactivity_timeout = 100  # seconds
            
            # OID definitions (docsIf3CmSpectrumAnalysisCtrlCmd base: 1.3.6.1.4.1.4491.2.1.20.1.34)
            OID_INACTIVITY_TIMEOUT = '1.3.6.1.4.1.4491.2.1.20.1.34.2.0'
            OID_FIRST_SEG_FREQ = '1.3.6.1.4.1.4491.2.1.20.1.34.3.0'
            OID_LAST_SEG_FREQ = '1.3.6.1.4.1.4491.2.1.20.1.34.4.0'
            OID_SEGMENT_SPAN = '1.3.6.1.4.1.4491.2.1.20.1.34.5.0'
            OID_NUM_BINS = '1.3.6.1.4.1.4491.2.1.20.1.34.6.0'
            OID_NOISE_BW = '1.3.6.1.4.1.4491.2.1.20.1.34.7.0'
            OID_WINDOW_FUNC = '1.3.6.1.4.1.4491.2.1.20.1.34.8.0'
            OID_NUM_AVERAGES = '1.3.6.1.4.1.4491.2.1.20.1.34.9.0'
            OID_SPEC_FILE_ENABLE = '1.3.6.1.4.1.4491.2.1.20.1.34.10.0'
            OID_SPEC_FILENAME = '1.3.6.1.4.1.4491.2.1.20.1.34.12.0'
            OID_SPEC_ENABLE = '1.3.6.1.4.1.4491.2.1.20.1.34.1.0'
            
            # Set all spectrum parameters (order matters - configure before enable)
            self.logger.info(f"Configuring spectrum analyzer parameters...")
            self._snmp_set(modem_ip, OID_INACTIVITY_TIMEOUT, inactivity_timeout, 'i', community)
            self._snmp_set(modem_ip, OID_FIRST_SEG_FREQ, first_seg_freq, 'i', community)
            self._snmp_set(modem_ip, OID_LAST_SEG_FREQ, last_seg_freq, 'i', community)
            self._snmp_set(modem_ip, OID_SEGMENT_SPAN, segment_span, 'i', community)
            self._snmp_set(modem_ip, OID_NUM_BINS, num_bins, 'i', community)
            self._snmp_set(modem_ip, OID_NOISE_BW, noise_bw, 'i', community)
            self._snmp_set(modem_ip, OID_WINDOW_FUNC, window_func, 'i', community)
            self._snmp_set(modem_ip, OID_NUM_AVERAGES, num_averages, 'i', community)
            
            # Set filename
            self.logger.info(f"Setting spectrum filename: {filename}")
            result = self._snmp_set(modem_ip, OID_SPEC_FILENAME, filename, 's', community)
            if not result.get('success'):
                self.logger.warning(f"Failed to set spectrum filename: {result.get('error')}")
            
            # Disable first (toggle FALSE -> TRUE as per PyPNM)
            self._snmp_set(modem_ip, OID_SPEC_ENABLE, 2, 'i', community)  # 2 = FALSE
            
            # Enable spectrum capture (triggers measurement)
            self.logger.info(f"Enabling spectrum analyzer")
            result = self._snmp_set(modem_ip, OID_SPEC_ENABLE, 1, 'i', community)  # 1 = TRUE
            if not result.get('success'):
                self.logger.warning(f"Failed to enable spectrum: {result.get('error')}")
            
            # Enable file output (triggers file upload to TFTP)
            self.logger.info(f"Enabling spectrum file output")
            result = self._snmp_set(modem_ip, OID_SPEC_FILE_ENABLE, 1, 'i', community)  # 1 = TRUE
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to trigger spectrum capture: {result.get('error')}"}
            
            # Poll status to check if measurement completed
            # docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus.0 = 1.3.6.1.4.1.4491.2.1.20.1.34.11.0
            # Values: 1=notReady, 2=sampleReady, 3=complete
            OID_SPEC_STATUS = '1.3.6.1.4.1.4491.2.1.20.1.34.11.0'
            import time
            max_wait = 30
            poll_interval = 2
            elapsed = 0
            
            self.logger.info(f"Polling spectrum status (max {max_wait}s)...")
            while elapsed < max_wait:
                time.sleep(poll_interval)
                elapsed += poll_interval
                
                status_result = self._snmp_get(modem_ip, OID_SPEC_STATUS, community)
                if status_result.get('success') and status_result.get('results'):
                    # Extract value from results array
                    status_value = status_result['results'][0].get('value') if status_result['results'] else None
                    self.logger.info(f"Spectrum status: {status_value} (after {elapsed}s)")
                    
                    # 3 = complete (file ready)
                    if status_value == 3:
                        self.logger.info(f"Spectrum capture complete, polling for file on TFTP...")
                        # Poll for file on TFTP (max 60s) - agent mounts at /tftpboot
                        tftp_file = f"/tftpboot/{filename}"
                        file_wait = 0
                        max_file_wait = 60
                        while file_wait < max_file_wait:
                            if os.path.exists(tftp_file):
                                self.logger.info(f"File found on TFTP after {file_wait}s")
                                break
                            time.sleep(2)
                            file_wait += 2
                        
                        if not os.path.exists(tftp_file):
                            self.logger.warning(f"File never appeared on TFTP after {max_file_wait}s")
                        break
                    # 1 = notReady, 2 = sampleReady (still processing)
                else:
                    error_msg = status_result.get('error', 'No results')
                    self.logger.warning(f"Failed to poll status: {error_msg}")
                    # Continue polling even if one poll fails
            
            if elapsed >= max_wait:
                self.logger.warning(f"Spectrum capture timed out after {max_wait}s")
            
            return {
                'success': True,
                'mac_address': mac_address,
                'modem_ip': modem_ip,
                'message': 'Spectrum capture triggered',
                'filename': filename,
                'status_polled': elapsed < max_wait
            }
            
        except Exception as e:
            self.logger.error(f"Spectrum capture error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _handle_pnm_channel_power(self, params: dict) -> dict:
        """Get basic channel power data from modem (not full spectrum)."""
        modem_ip = params.get('modem_ip')
        community = params.get('community') or self.config.cm_community
        mac_address = params.get('mac_address')
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        self.logger.info(f"Getting spectrum for modem {modem_ip}")
        
        # DOCSIS CM spectrum OIDs
        OID_DS_FREQ = '1.3.6.1.2.1.10.127.1.1.1.1.2'  # docsIfDownChannelFrequency
        OID_DS_POWER = '1.3.6.1.2.1.10.127.1.1.1.1.6'  # docsIfDownChannelPower
        OID_US_FREQ = '1.3.6.1.2.1.10.127.1.1.2.1.2'  # docsIfUpChannelFrequency
        OID_US_POWER = '1.3.6.1.4.1.4491.2.1.20.1.2.1.1'  # docsIf3CmStatusUsTxPower
        
        ds_freq_result = self._query_modem(modem_ip, OID_DS_FREQ, community, walk=True)
        ds_power_result = self._query_modem(modem_ip, OID_DS_POWER, community, walk=True)
        us_power_result = self._query_modem(modem_ip, OID_US_POWER, community, walk=True)
        
        ds_channels = []
        us_channels = []
        
        # Parse downstream
        freq_map = {}
        for line in ds_freq_result.get('output', '').split('\n'):
            if '=' in line:
                try:
                    idx = line.split('=')[0].strip().split('.')[-1]
                    val = ''.join(c for c in line.split('=')[1] if c.isdigit())
                    if val:
                        freq_map[idx] = int(val)
                except:
                    pass
        
        for line in ds_power_result.get('output', '').split('\n'):
            if '=' in line:
                try:
                    idx = line.split('=')[0].strip().split('.')[-1]
                    val = ''.join(c for c in line.split('=')[1] if c.isdigit() or c == '-')
                    if val and idx in freq_map:
                        ds_channels.append({
                            'channel_id': int(idx),
                            'frequency_hz': freq_map[idx],
                            'power_dbmv': float(val) / 10
                        })
                except:
                    pass
        
        # Parse upstream power
        for line in us_power_result.get('output', '').split('\n'):
            if '=' in line:
                try:
                    idx = line.split('=')[0].strip().split('.')[-1]
                    val = ''.join(c for c in line.split('=')[1] if c.isdigit() or c == '-')
                    if val:
                        us_channels.append({
                            'channel_id': int(idx),
                            'power_dbmv': float(val) / 10
                        })
                except:
                    pass
        
        return {
            'success': True,
            'mac_address': mac_address,
            'modem_ip': modem_ip,
            'timestamp': datetime.now().isoformat(),
            'downstream_channels': ds_channels,
            'upstream_channels': us_channels
        }
    
    def _handle_pnm_fec(self, params: dict) -> dict:
        """Get FEC (Forward Error Correction) statistics from modem."""
        modem_ip = params.get('modem_ip')
        community = params.get('community') or self.config.cm_community
        mac_address = params.get('mac_address')
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        self.logger.info(f"Getting FEC stats for modem {modem_ip}")
        
        # DOCSIS FEC OIDs
        OID_UNERRORED = '1.3.6.1.2.1.10.127.1.1.4.1.2'  # docsIfSigQUnerroreds
        OID_CORRECTED = '1.3.6.1.2.1.10.127.1.1.4.1.3'  # docsIfSigQCorrecteds
        OID_UNCORRECTABLE = '1.3.6.1.2.1.10.127.1.1.4.1.4'  # docsIfSigQUncorrectables
        OID_SNR = '1.3.6.1.2.1.10.127.1.1.4.1.5'  # docsIfSigQSignalNoise
        
        unerrored = self._query_modem(modem_ip, OID_UNERRORED, community, walk=True)
        corrected = self._query_modem(modem_ip, OID_CORRECTED, community, walk=True)
        uncorrectable = self._query_modem(modem_ip, OID_UNCORRECTABLE, community, walk=True)
        snr = self._query_modem(modem_ip, OID_SNR, community, walk=True)
        
        def parse_values(result):
            values = {}
            for line in result.get('output', '').split('\n'):
                if '=' in line:
                    try:
                        idx = line.split('=')[0].strip().split('.')[-1]
                        val = ''.join(c for c in line.split('=')[1] if c.isdigit())
                        if val:
                            values[idx] = int(val)
                    except:
                        pass
            return values
        
        unerrored_map = parse_values(unerrored)
        corrected_map = parse_values(corrected)
        uncorrectable_map = parse_values(uncorrectable)
        snr_map = parse_values(snr)
        
        channels = []
        for idx in unerrored_map:
            total = unerrored_map.get(idx, 0) + corrected_map.get(idx, 0) + uncorrectable_map.get(idx, 0)
            channels.append({
                'channel_id': int(idx),
                'unerrored': unerrored_map.get(idx, 0),
                'corrected': corrected_map.get(idx, 0),
                'uncorrectable': uncorrectable_map.get(idx, 0),
                'total_codewords': total,
                'snr_db': snr_map.get(idx, 0) / 10 if idx in snr_map else 0
            })
        
        return {
            'success': True,
            'mac_address': mac_address,
            'modem_ip': modem_ip,
            'timestamp': datetime.now().isoformat(),
            'channels': channels,
            'total_uncorrectable': sum(c['uncorrectable'] for c in channels),
            'total_corrected': sum(c['corrected'] for c in channels)
        }
    
    def _handle_pnm_pre_eq(self, params: dict) -> dict:
        """Get pre-equalization coefficients from modem."""
        modem_ip = params.get('modem_ip')
        community = params.get('community') or self.config.cm_community
        mac_address = params.get('mac_address')
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        self.logger.info(f"Getting pre-eq coefficients for modem {modem_ip}")
        
        # DOCSIS Pre-equalization OID
        OID_PRE_EQ = '1.3.6.1.4.1.4491.2.1.20.1.2.1.5'  # docsIf3CmStatusUsEqData
        
        result = self._query_modem(modem_ip, OID_PRE_EQ, community, walk=True)
        
        if not result.get('success'):
            return {'success': False, 'error': result.get('error', 'SNMP query failed')}
        
        coefficients = []
        for line in result.get('output', '').split('\n'):
            if '=' in line and 'Hex-STRING' in line:
                try:
                    idx = line.split('=')[0].strip().split('.')[-1]
                    hex_data = line.split('Hex-STRING:')[-1].strip()
                    coefficients.append({
                        'channel_id': int(idx),
                        'hex_data': hex_data,
                        'length': len(hex_data.replace(' ', '')) // 2
                    })
                except:
                    pass
        
        return {
            'success': True,
            'mac_address': mac_address,
            'modem_ip': modem_ip,
            'timestamp': datetime.now().isoformat(),
            'coefficients': coefficients
        }
    
    def _handle_pnm_channel_info(self, params: dict) -> dict:
        """Get comprehensive channel info (DS/US power, frequency, modulation) via pysnmp.
        
        Works with cm_direct (direct SNMP to modems) or cm_proxy SSH tunnel.
        """
        modem_ip = params.get('modem_ip')
        # Use cm_community from config as fallback
        community = params.get('community', self.config.cm_community)
        mac_address = params.get('mac_address')
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        self.logger.info(f"Getting channel info for modem {modem_ip} via pysnmp (community={community[:4]}...)")

        
        # Define OIDs for channel stats
        oids = {
            'ds_freq': '1.3.6.1.2.1.10.127.1.1.1.1.2',    # docsIfDownChannelFrequency
            'ds_power': '1.3.6.1.2.1.10.127.1.1.1.1.6',   # docsIfDownChannelPower
            'ds_snr': '1.3.6.1.2.1.10.127.1.1.4.1.5',     # docsIfSigQSignalNoise
            'us_power': '1.3.6.1.4.1.4491.2.1.20.1.2.1.1', # docsIf3CmStatusUsTxPower
            'ds_ofdm_power': '1.3.6.1.4.1.4491.2.1.28.1.2.1.6',  # docsIf31CmDsOfdmChannelPowerRxPower
            'us_ofdma_power': '1.3.6.1.4.1.4491.2.1.28.1.3.1.4', # docsIf31CmUsOfdmaChannelStatusTxPower
        }
        
        # Use parallel walk for all OIDs at once
        result = self._snmp_parallel_walk(modem_ip, list(oids.values()), community, timeout=15)
        
        self.logger.info(f"parallel_walk result success={result.get('success')}, keys={list(result.get('results', {}).keys())}")
        
        if not result.get('success'):
            # Try fallback via cm_proxy SSH if available
            if self.config.cm_proxy_host:
                self.logger.info("pysnmp failed, trying cm_proxy SSH fallback")
                return self._handle_pnm_channel_info_ssh(params)
            return {'success': False, 'error': result.get('error', 'SNMP query failed')}
        
        walk_results = result.get('results', {})
        self.logger.info(f"walk_results counts: ds_freq={len(walk_results.get(oids['ds_freq'], []))}, ds_power={len(walk_results.get(oids['ds_power'], []))}")
        
        def parse_oid_values(results_list, divisor=1):
            """Parse OID results to dict of index -> value."""
            values = {}
            for r in results_list:
                try:
                    idx = r['oid'].split('.')[-1]
                    val = r['value']
                    if isinstance(val, (int, float)):
                        values[idx] = val / divisor
                    elif isinstance(val, str) and val.lstrip('-').isdigit():
                        values[idx] = int(val) / divisor
                except:
                    pass
            return values
        
        ds_freq_map = parse_oid_values(walk_results.get(oids['ds_freq'], []))
        ds_power_map = parse_oid_values(walk_results.get(oids['ds_power'], []), 10)
        ds_snr_map = parse_oid_values(walk_results.get(oids['ds_snr'], []), 10)
        us_power_map = parse_oid_values(walk_results.get(oids['us_power'], []), 10)
        ds_ofdm_power_map = parse_oid_values(walk_results.get(oids['ds_ofdm_power'], []), 10)
        us_ofdma_power_map = parse_oid_values(walk_results.get(oids['us_ofdma_power'], []), 10)
        
        downstream = []
        for idx in ds_freq_map:
            downstream.append({
                'channel_id': int(idx),
                'type': 'SC-QAM',
                'frequency_mhz': ds_freq_map[idx] / 1000000,
                'power_dbmv': ds_power_map.get(idx, 0),
                'snr_db': ds_snr_map.get(idx, 0)
            })
        
        for idx in ds_ofdm_power_map:
            downstream.append({
                'channel_id': int(idx),
                'type': 'OFDM',
                'power_dbmv': ds_ofdm_power_map[idx]
            })
        
        upstream = []
        for idx in us_power_map:
            upstream.append({
                'channel_id': int(idx),
                'type': 'ATDMA',
                'power_dbmv': us_power_map[idx]
            })
        
        for idx in us_ofdma_power_map:
            upstream.append({
                'channel_id': int(idx),
                'type': 'OFDMA',
                'power_dbmv': us_ofdma_power_map[idx]
            })
        
        return {
            'success': True,
            'mac_address': mac_address,
            'modem_ip': modem_ip,
            'timestamp': datetime.now().isoformat(),
            'downstream': sorted(downstream, key=lambda x: x['channel_id']),
            'upstream': sorted(upstream, key=lambda x: x['channel_id'])
        }
    
    def _handle_pnm_channel_info_ssh(self, params: dict) -> dict:
        """Fallback: Get channel info via cm_proxy SSH (old method)."""
        modem_ip = params.get('modem_ip')
        community = params.get('community') or self.config.cm_community
        mac_address = params.get('mac_address')
        
        oids = {
            'ds_freq': '1.3.6.1.2.1.10.127.1.1.1.1.2',
            'ds_power': '1.3.6.1.2.1.10.127.1.1.1.1.6',
            'ds_snr': '1.3.6.1.2.1.10.127.1.1.4.1.5',
            'us_power': '1.3.6.1.4.1.4491.2.1.20.1.2.1.1',
        }
        
        batch_result = self._batch_query_modem(modem_ip, oids, community)
        
        if not batch_result.get('success'):
            return {'success': False, 'error': batch_result.get('error', 'Batch query failed')}
        
        results = batch_result.get('results', {})
        
        def parse_int_values(output_str, divisor=1):
            values = {}
            for line in output_str.split('\n'):
                if '=' in line:
                    try:
                        idx = line.split('=')[0].strip().split('.')[-1]
                        val = ''.join(c for c in line.split('=')[1] if c.isdigit() or c == '-')
                        if val:
                            values[idx] = int(val) / divisor
                    except:
                        pass
            return values
        
        ds_freq_map = parse_int_values(results.get('ds_freq', ''))
        ds_power_map = parse_int_values(results.get('ds_power', ''), 10)
        ds_snr_map = parse_int_values(results.get('ds_snr', ''), 10)
        us_power_map = parse_int_values(results.get('us_power', ''), 10)
        
        downstream = []
        for idx in ds_freq_map:
            downstream.append({
                'channel_id': int(idx),
                'frequency_mhz': ds_freq_map[idx] / 1000000,
                'power_dbmv': ds_power_map.get(idx, 0),
                'snr_db': ds_snr_map.get(idx, 0)
            })
        
        upstream = []
        for idx in us_power_map:
            upstream.append({
                'channel_id': int(idx),
                'power_dbmv': us_power_map[idx]
            })
        
        return {
            'success': True,
            'mac_address': mac_address,
            'modem_ip': modem_ip,
            'timestamp': datetime.now().isoformat(),
            'downstream': sorted(downstream, key=lambda x: x['channel_id']),
            'upstream': sorted(upstream, key=lambda x: x['channel_id'])
        }
    
    def _handle_pnm_event_log(self, params: dict) -> dict:
        """Get event log from modem via pysnmp."""
        modem_ip = params.get('modem_ip')
        community = params.get('community') or self.config.cm_community
        mac_address = params.get('mac_address')
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        self.logger.info(f"Getting event log for modem {modem_ip} via pysnmp")
        
        # DOCSIS Event Log OIDs
        OID_EVENT_TEXT = '1.3.6.1.2.1.69.1.5.8.1.7'   # docsDevEvText
        OID_EVENT_TIME = '1.3.6.1.2.1.69.1.5.8.1.6'   # docsDevEvLastTime
        OID_EVENT_LEVEL = '1.3.6.1.2.1.69.1.5.8.1.4'  # docsDevEvLevel
        
        result = self._snmp_parallel_walk(modem_ip, [OID_EVENT_TEXT, OID_EVENT_TIME, OID_EVENT_LEVEL], community, timeout=15)
        
        if not result.get('success'):
            return {'success': False, 'error': result.get('error', 'SNMP query failed')}
        
        walk_results = result.get('results', {})
        
        # Parse text entries
        text_map = {}
        for r in walk_results.get(OID_EVENT_TEXT, []):
            try:
                idx = r['oid'].split('.')[-1]
                text_map[idx] = r['value']
            except:
                pass
        
        # Parse time entries
        time_map = {}
        for r in walk_results.get(OID_EVENT_TIME, []):
            try:
                idx = r['oid'].split('.')[-1]
                time_map[idx] = r['value']
            except:
                pass
        
        # Parse level entries
        level_map = {}
        level_names = {1: 'emergency', 2: 'alert', 3: 'critical', 4: 'error', 5: 'warning', 6: 'notice', 7: 'info', 8: 'debug'}
        for r in walk_results.get(OID_EVENT_LEVEL, []):
            try:
                idx = r['oid'].split('.')[-1]
                level_val = int(r['value']) if isinstance(r['value'], (int, str)) else 7
                level_map[idx] = level_names.get(level_val, 'unknown')
            except:
                pass
        
        events = []
        for idx in text_map:
            events.append({
                'id': int(idx),
                'text': text_map[idx],
                'time': time_map.get(idx, ''),
                'level': level_map.get(idx, 'info')
            })
        
        # Sort by ID descending (newest first)
        events.sort(key=lambda x: x['id'], reverse=True)
        
        return {
            'success': True,
            'mac_address': mac_address,
            'modem_ip': modem_ip,
            'timestamp': datetime.now().isoformat(),
            'events': events[:50],  # Last 50 events
            'total_events': len(events)
        }

    def _handle_pnm_ofdm_channels(self, params: dict) -> dict:
        """Get list of OFDM channels via cm_proxy SNMP."""
        modem_ip = params.get('modem_ip')
        community = params.get('community') or self.config.cm_community
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        if not self.config.cm_proxy_host and not self.config.cm_enabled:
            return {'success': False, 'error': 'cm_proxy not configured'}
        
        try:
            # DOCSIS 3.1 OFDM channel OIDs
            OID_OFDM_CHAN_ID = '1.3.6.1.4.1.4491.2.1.28.1.9.1.1'  # docsIf31CmDsOfdmChanChannelId
            
            self.logger.info(f"Querying OFDM channels for {modem_ip}")
            result = self._query_modem(modem_ip, OID_OFDM_CHAN_ID, community, walk=True)
            self.logger.info(f"OFDM query result: success={result.get('success')}")
            
            if not result.get('success'):
                # Not an error - modem might be DOCSIS 3.0 only
                return {'success': True, 'channels': []}
            
            channels = []
            for line in result.get('output', '').split('\n'):
                if '=' in line and 'INTEGER' in line:
                    try:
                        parts = line.split('=')[0].strip().split('.')
                        idx = int(parts[-1])
                        chan_id = int(line.split('INTEGER:')[-1].strip())
                        channels.append({
                            "index": idx,
                            "channel_id": chan_id
                        })
                    except:
                        pass
            
            return {"success": True, "channels": channels}
        except Exception as e:
            self.logger.error(f"OFDM channels error: {e}")
            return {'success': False, 'error': str(e)}

    def _handle_pnm_ofdm_capture(self, params: dict) -> dict:
        """Trigger OFDM RxMER capture via cm_proxy SNMP SET."""
        modem_ip = params.get('modem_ip')
        ofdm_channel = params.get('ofdm_channel', 0)
        filename = params.get('filename', 'rxmer_capture')
        community = params.get('community') or self.config.cm_community
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        if not self.config.cm_proxy_host and not self.config.cm_enabled:
            return {'success': False, 'error': 'cm_proxy not configured'}
        
        try:
            # Correct OIDs from PyPNM compiled_oids.py
            OID_RXMER_FILENAME = f'1.3.6.1.4.1.4491.2.1.27.1.2.5.1.8.{ofdm_channel}'
            OID_RXMER_ENABLE = f'1.3.6.1.4.1.4491.2.1.27.1.2.5.1.1.{ofdm_channel}'
            
            # Set filename
            self.logger.info(f"Setting OFDM capture filename for {modem_ip} channel {ofdm_channel}")
            result = self._set_modem_via_cm_proxy(modem_ip, OID_RXMER_FILENAME, filename, 's', community)
            self.logger.info(f"Filename set result: success={result.get('success')}")
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to set filename: {result.get('error')}"}
            
            # Trigger capture (enable = 1)
            self.logger.info(f"Triggering OFDM capture for {modem_ip} channel {ofdm_channel}")
            result = self._set_modem_via_cm_proxy(modem_ip, OID_RXMER_ENABLE, '1', 'i', community)
            self.logger.info(f"Trigger result: success={result.get('success')}")
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to trigger capture: {result.get('error')}"}
            
            return {'success': True, 'message': 'OFDM capture triggered', 'filename': filename}
        except Exception as e:
            self.logger.error(f"OFDM capture error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _handle_pnm_ofdm_rxmer(self, params: dict) -> dict:
        """Trigger OFDM RxMER capture via SNMP.
        
        This only triggers the capture - PyPNM handles file retrieval and parsing.
        The modem uploads the PNM file to TFTP, PyPNM fetches and parses it.
        """
        modem_ip = params.get('modem_ip')
        mac_address = params.get('mac_address', '')
        community = params.get('community') or self.config.cm_community
        tftp_server = params.get('tftp_server', os.environ.get('TFTP_IPV4', '172.22.147.18'))
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        self.logger.info(f"Triggering OFDM RxMER capture for {modem_ip}")
        
        try:
            # Step 1: Get OFDM channel indexes
            OID_OFDM_CHAN_ID = '1.3.6.1.4.1.4491.2.1.28.1.1.1.1'  # docsIf31CmDsOfdmChanChannelId
            chan_result = self._snmp_walk(modem_ip, OID_OFDM_CHAN_ID, community)
            
            if not chan_result.get('success') or not chan_result.get('results'):
                return {'success': False, 'error': 'No OFDM channels found - modem may be DOCSIS 3.0'}
            
            # Extract channel indexes
            ofdm_indexes = []
            for r in chan_result['results']:
                try:
                    oid_parts = r['oid'].split('.')
                    idx = int(oid_parts[-1])
                    ofdm_indexes.append(idx)
                except (ValueError, IndexError):
                    pass
            
            if not ofdm_indexes:
                return {'success': False, 'error': 'No OFDM channel indexes found'}
            
            self.logger.info(f"Found OFDM channel indexes: {ofdm_indexes}")
            
            # Step 2: Set TFTP destination on modem (docsPnmBulk)
            OID_BULK_IP_TYPE = '1.3.6.1.4.1.4491.2.1.27.1.1.1.1.0'
            OID_BULK_IP_ADDR = '1.3.6.1.4.1.4491.2.1.27.1.1.1.2.0'
            
            # Set IP type to IPv4 (1)
            self._snmp_set(modem_ip, OID_BULK_IP_TYPE, 1, 'i', community)
            
            # Set TFTP server IP (as hex)
            ip_parts = tftp_server.split('.')
            ip_hex = ''.join([f'{int(p):02x}' for p in ip_parts])
            self._snmp_set(modem_ip, OID_BULK_IP_ADDR, ip_hex, 'x', community)
            
            # Step 3: Trigger RxMER capture for each OFDM channel
            triggered_channels = []
            
            for ofdm_idx in ofdm_indexes:
                # Generate unique filename
                mac_clean = mac_address.replace(':', '').lower()
                timestamp = int(time.time())
                filename = f"{mac_clean}_{timestamp}_{ofdm_idx}_rxmer"
                
                # Set filename (docsPnmCmDsOfdmRxMerFileName)
                OID_RXMER_FILENAME = f'1.3.6.1.4.1.4491.2.1.27.1.2.5.1.8.{ofdm_idx}'
                set_result = self._snmp_set(modem_ip, OID_RXMER_FILENAME, filename, 's', community)
                
                if not set_result.get('success'):
                    self.logger.warning(f"Failed to set RxMER filename for channel {ofdm_idx}")
                    continue
                
                # Trigger capture (docsPnmCmDsOfdmRxMerFileEnable = 1)
                OID_RXMER_ENABLE = f'1.3.6.1.4.1.4491.2.1.27.1.2.5.1.1.{ofdm_idx}'
                set_result = self._snmp_set(modem_ip, OID_RXMER_ENABLE, 1, 'i', community)
                
                if set_result.get('success'):
                    self.logger.info(f"Triggered RxMER capture for channel {ofdm_idx}: {filename}")
                    triggered_channels.append({
                        'channel_index': ofdm_idx,
                        'filename': filename
                    })
                else:
                    self.logger.warning(f"Failed to trigger RxMER for channel {ofdm_idx}")
            
            if not triggered_channels:
                return {'success': False, 'error': 'Failed to trigger capture on any channel'}
            
            # Return success - PyPNM will handle file retrieval and parsing
            return {
                'success': True,
                'message': 'RxMER capture triggered',
                'mac_address': mac_address,
                'modem_ip': modem_ip,
                'tftp_server': tftp_server,
                'channels': triggered_channels,
                'note': 'Call PyPNM API to retrieve parsed data'
            }
            
        except Exception as e:
            self.logger.error(f"OFDM RxMER trigger error: {e}")
            return {'success': False, 'error': str(e)}

    def _handle_pnm_set_tftp(self, params: dict) -> dict:
        """Configure modem TFTP destination for PNM captures."""
        modem_ip = params.get('modem_ip')
        mac_address = params.get('mac_address')
        tftp_server = params.get('tftp_server', '149.210.167.40')
        tftp_path = params.get('tftp_path', '')
        community = params.get('community') or self.config.cm_community
        
        if not modem_ip:
            return {'success': False, 'error': 'modem_ip required'}
        
        try:
            # OIDs from PyPNM
            OID_IP_TYPE = '1.3.6.1.4.1.4491.2.1.27.1.1.1.1.0'  # docsPnmBulkDestIpAddrType
            OID_IP_ADDR = '1.3.6.1.4.1.4491.2.1.27.1.1.1.2.0'  # docsPnmBulkDestIpAddr
            OID_PATH = '1.3.6.1.4.1.4491.2.1.27.1.1.1.3.0'      # docsPnmBulkDestPath
            OID_UPLOAD = '1.3.6.1.4.1.4491.2.1.27.1.1.1.4.0'    # docsPnmBulkUploadControl
            
            # Set IP address type (1 = IPv4)
            result = self._set_modem_via_cm_proxy(modem_ip, OID_IP_TYPE, '1', 'i', community)
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to set IP type: {result.get('error')}"}
            
            # Set IP address (as hex string: 149.210.167.40 = 95d2a728)
            ip_parts = tftp_server.split('.')
            ip_hex = ''.join([f'{int(p):02x}' for p in ip_parts])
            result = self._set_modem_via_cm_proxy(modem_ip, OID_IP_ADDR, ip_hex, 'x', community)
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to set IP address: {result.get('error')}"}
            
            # Set TFTP path
            if tftp_path:
                result = self._set_modem_via_cm_proxy(modem_ip, OID_PATH, tftp_path, 's', community)
                if not result.get('success'):
                    return {'success': False, 'error': f"Failed to set path: {result.get('error')}"}
            
            # Enable auto upload (2 = autoUpload)
            result = self._set_modem_via_cm_proxy(modem_ip, OID_UPLOAD, '2', 'i', community)
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to enable auto upload: {result.get('error')}"}
            
            return {
                'success': True,
                'message': f'TFTP destination set to {tftp_server}{tftp_path} with AUTO_UPLOAD enabled',
                'tftp_server': tftp_server,
                'tftp_path': tftp_path,
                'auto_upload': True
            }
                
        except Exception as e:
            self.logger.error(f"Set TFTP error: {e}")
            return {'success': False, 'error': str(e)}

    # ============== Upstream PNM Handlers (CMTS-side) ==============
    
    def _query_cmts_direct(self, cmts_ip: str, oid: str, community: str, walk: bool = False) -> dict:
        """Query CMTS directly via pysnmp SNMP."""
        self.logger.info(f"CMTS SNMP {'WALK' if walk else 'GET'}: {cmts_ip} {oid}")
        if walk:
            result = self._snmp_walk(cmts_ip, oid, community, timeout=15)
            # Convert to old format for compatibility
            if result.get('success') and result.get('results'):
                output_lines = []
                for r in result['results']:
                    output_lines.append(f"{r['oid']} = {r['type']}: {r['value']}")
                return {'success': True, 'output': '\n'.join(output_lines), 'results': result['results']}
            return result
        else:
            result = self._snmp_get(cmts_ip, oid, community, timeout=15)
            if result.get('success') and result.get('results'):
                r = result['results'][0]
                return {'success': True, 'output': f"{r['oid']} = {r['type']}: {r['value']}", 'results': result['results']}
            return result
    
    def _set_cmts_direct(self, cmts_ip: str, oid: str, value: str, value_type: str, community: str) -> dict:
        """Set SNMP value on CMTS directly via pysnmp."""
        self.logger.info(f"CMTS SNMP SET: {cmts_ip} {oid} = {value} (type={value_type})")
        return self._snmp_set(cmts_ip, oid, value, value_type, community, timeout=15)
    
    def _handle_pnm_us_get_interfaces(self, params: dict) -> dict:
        """Get upstream RF port interfaces from CMTS for UTSC.
        
        Uses same OIDs as PyPNM UtscRfPortDiscoveryService:
        - docsIf3CmtsCmRegStatusMacAddr to find CM index
        - docsIf3CmtsCmUsStatusRxPower to find modem's US channels  
        - docsPnmCmtsUtscCfgLogicalChIfIndex to get RF ports
        """
        cmts_ip = params.get('cmts_ip')
        cm_mac = params.get('cm_mac_address')
        community = params.get('community') or self.config.cmts_write_community or self.config.cmts_community
        
        if not cmts_ip:
            return {'success': False, 'error': 'cmts_ip required'}
        
        try:
            # OIDs from PyPNM UtscRfPortDiscoveryService
            OID_CM_REG_MAC = '1.3.6.1.4.1.4491.2.1.20.1.3.1.2'  # docsIf3CmtsCmRegStatusMacAddr
            OID_CM_US_RXPOWER = '1.3.6.1.4.1.4491.2.1.20.1.4.1.2'  # docsIf3CmtsCmUsStatusRxPower
            OID_UTSC_LOGICAL_CH = '1.3.6.1.4.1.4491.2.1.27.1.3.10.2.1.2'  # docsPnmCmtsUtscCfgLogicalChIfIndex
            OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2'  # ifDescr
            
            cm_index = None
            us_channels = []
            rf_ports = []
            modem_rf_port = None
            
            # Step 1: Find CM index from MAC
            if cm_mac:
                mac_normalized = cm_mac.replace(':', '').replace('-', '').lower()
                result = self._query_cmts_direct(cmts_ip, OID_CM_REG_MAC, community, walk=True)
                
                if result.get('success') and result.get('results'):
                    for r in result['results']:
                        try:
                            mac_value = str(r.get('value', '')).replace(':', '').replace(' ', '').lower()
                            if mac_normalized == mac_value:
                                cm_index = int(r['oid'].split('.')[-1])
                                self.logger.info(f"Found CM index {cm_index} for MAC {cm_mac}")
                                break
                        except:
                            pass
            
            # Step 2: Get modem's US channels from docsIf3CmtsCmUsStatusRxPower
            if cm_index:
                result = self._query_cmts_direct(cmts_ip, OID_CM_US_RXPOWER, community, walk=True)
                
                if result.get('success') and result.get('results'):
                    for r in result['results']:
                        try:
                            # OID format: base.cmIndex.usChIfIndex
                            oid_suffix = r['oid'].replace(OID_CM_US_RXPOWER + '.', '')
                            parts = oid_suffix.split('.')
                            if len(parts) >= 2:
                                found_cm_idx = int(parts[0])
                                us_ch_ifindex = int(parts[1])
                                if found_cm_idx == cm_index and us_ch_ifindex not in us_channels:
                                    us_channels.append(us_ch_ifindex)
                                    self.logger.info(f"Found US channel ifIndex {us_ch_ifindex} for CM {cm_mac}")
                        except:
                            pass
            
            # Step 3: Get RF ports from docsPnmCmtsUtscCfgLogicalChIfIndex
            result = self._query_cmts_direct(cmts_ip, OID_UTSC_LOGICAL_CH, community, walk=True)
            
            if result.get('success') and result.get('results'):
                seen_rf_ports = set()
                for r in result['results']:
                    try:
                        # OID format: base.rfPortIfIndex.cfgIndex
                        oid_suffix = r['oid'].replace(OID_UTSC_LOGICAL_CH + '.', '')
                        parts = oid_suffix.split('.')
                        if len(parts) >= 1:
                            rf_port_ifindex = int(parts[0])
                            if rf_port_ifindex > 1000000000 and rf_port_ifindex not in seen_rf_ports:
                                seen_rf_ports.add(rf_port_ifindex)
                                # Get description
                                desc_result = self._snmp_get(cmts_ip, f"{OID_IF_DESCR}.{rf_port_ifindex}", community)
                                description = ""
                                if desc_result.get('success') and desc_result.get('results'):
                                    description = str(desc_result['results'][0].get('value', ''))
                                rf_ports.append({'ifindex': rf_port_ifindex, 'description': description})
                    except:
                        pass
            
            # Step 4: If modem has US channels, find matching RF port
            if us_channels and rf_ports:
                first_us_ch = us_channels[0]
                for rf_port in rf_ports:
                    # Test if this RF port accepts the modem's logical channel
                    test_oid = f"{OID_UTSC_LOGICAL_CH}.{rf_port['ifindex']}.1"
                    set_result = self._snmp_set(cmts_ip, test_oid, first_us_ch, 'i', community)
                    if set_result.get('success'):
                        modem_rf_port = rf_port
                        self.logger.info(f"Found modem's RF port: {rf_port['description']} ({rf_port['ifindex']})")
                        # Reset to 0
                        self._snmp_set(cmts_ip, test_oid, 0, 'i', community)
                        break
            
            # Return modem-specific RF port - for UTSC the RF port goes in ofdma_channels
            # Frontend expects ofdma_channels for UTSC measurement
            return {
                'success': True,
                'cmts_ip': cmts_ip,
                'rf_ports': [modem_rf_port] if modem_rf_port else rf_ports,
                'all_rf_ports': rf_ports,
                'ofdma_channels': [modem_rf_port] if modem_rf_port else rf_ports,  # RF port for UTSC
                'scqam_channels': [],  # No SC-QAM selection needed
                'cm_index': cm_index,
                'modem_rf_port': modem_rf_port,
                'us_channels': us_channels
            }
            
        except Exception as e:
            self.logger.error(f"US get interfaces error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _handle_pnm_utsc_configure(self, params: dict) -> dict:
        """Configure UTSC test parameters on CMTS."""
        cmts_ip = params.get('cmts_ip')
        rf_port_ifindex = params.get('rf_port_ifindex')
        community = params.get('community') or self.config.cmts_write_community or self.config.cmts_community
        
        if not cmts_ip or not rf_port_ifindex:
            return {'success': False, 'error': 'cmts_ip and rf_port_ifindex required'}
        
        try:
            # UTSC OIDs (with ifIndex suffix)
            base = '1.3.6.1.4.1.4491.2.1.27.1.3.1.1'  # docsPnmCmtsUtscCfgTable
            idx = f".{rf_port_ifindex}.1"  # ifIndex.cfgIndex
            
            # Set trigger mode
            trigger_mode = params.get('trigger_mode', 2)  # Default: FreeRunning
            result = self._set_cmts_direct(cmts_ip, f"{base}.3{idx}", str(trigger_mode), 'i', community)
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to set trigger mode: {result.get('error')}"}
            
            # Set center frequency (in Hz)
            center_freq = params.get('center_freq_hz', 30000000)
            result = self._set_cmts_direct(cmts_ip, f"{base}.8{idx}", str(center_freq), 'u', community)
            if not result.get('success'):
                self.logger.warning(f"Failed to set center freq: {result.get('error')}")
            
            # Set span (in Hz)
            span = params.get('span_hz', 80000000)
            result = self._set_cmts_direct(cmts_ip, f"{base}.9{idx}", str(span), 'u', community)
            if not result.get('success'):
                self.logger.warning(f"Failed to set span: {result.get('error')}")
            
            # Set number of bins
            num_bins = params.get('num_bins', 800)
            result = self._set_cmts_direct(cmts_ip, f"{base}.10{idx}", str(num_bins), 'u', community)
            if not result.get('success'):
                self.logger.warning(f"Failed to set num_bins: {result.get('error')}")
            
            # Set output format (2 = fftPower)
            output_format = params.get('output_format', 2)
            result = self._set_cmts_direct(cmts_ip, f"{base}.17{idx}", str(output_format), 'i', community)
            if not result.get('success'):
                self.logger.warning(f"Failed to set output format: {result.get('error')}")
            
            # Set filename
            filename = params.get('filename', 'utsc_capture')
            result = self._set_cmts_direct(cmts_ip, f"{base}.13{idx}", filename, 's', community)
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to set filename: {result.get('error')}"}
            
            # For CM MAC trigger mode
            if trigger_mode == 6 and params.get('cm_mac_address'):
                mac = params['cm_mac_address'].replace(':', '').replace('-', '').upper()
                mac_hex = ' '.join([mac[i:i+2] for i in range(0, 12, 2)])
                result = self._set_cmts_direct(cmts_ip, f"{base}.6{idx}", mac_hex, 'x', community)
                if not result.get('success'):
                    self.logger.warning(f"Failed to set CM MAC: {result.get('error')}")
                
                # Set logical channel ifindex if provided
                if params.get('logical_ch_ifindex'):
                    result = self._set_cmts_direct(cmts_ip, f"{base}.2{idx}", 
                                                   str(params['logical_ch_ifindex']), 'i', community)
            
            # For FreeRunning mode, set repeat period and duration
            if trigger_mode == 2:
                repeat_period = params.get('repeat_period_ms', 0)
                result = self._set_cmts_direct(cmts_ip, f"{base}.18{idx}", str(repeat_period), 'u', community)
                
                freerun_duration = params.get('freerun_duration_ms', 1000)
                result = self._set_cmts_direct(cmts_ip, f"{base}.19{idx}", str(freerun_duration), 'u', community)
            
            return {
                'success': True,
                'message': 'UTSC configured',
                'rf_port_ifindex': rf_port_ifindex,
                'trigger_mode': trigger_mode,
                'filename': filename
            }
            
        except Exception as e:
            self.logger.error(f"UTSC configure error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _handle_pnm_utsc_start(self, params: dict) -> dict:
        """Start UTSC test (set InitiateTest to true)."""
        cmts_ip = params.get('cmts_ip')
        rf_port_ifindex = params.get('rf_port_ifindex')
        community = params.get('community') or self.config.cmts_write_community or self.config.cmts_community
        
        if not cmts_ip or not rf_port_ifindex:
            return {'success': False, 'error': 'cmts_ip and rf_port_ifindex required'}
        
        try:
            # docsPnmCmtsUtscCtrlInitiateTest
            oid = f"1.3.6.1.4.1.4491.2.1.27.1.3.2.1.1.{rf_port_ifindex}.1"
            
            result = self._set_cmts_direct(cmts_ip, oid, '1', 'i', community)  # 1 = true
            
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to start UTSC: {result.get('error')}"}
            
            return {
                'success': True,
                'message': 'UTSC test started',
                'rf_port_ifindex': rf_port_ifindex
            }
            
        except Exception as e:
            self.logger.error(f"UTSC start error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _handle_pnm_utsc_stop(self, params: dict) -> dict:
        """Stop UTSC test (set InitiateTest to false)."""
        cmts_ip = params.get('cmts_ip')
        rf_port_ifindex = params.get('rf_port_ifindex')
        community = params.get('community') or self.config.cmts_write_community or self.config.cmts_community
        
        if not cmts_ip or not rf_port_ifindex:
            return {'success': False, 'error': 'cmts_ip and rf_port_ifindex required'}
        
        try:
            # docsPnmCmtsUtscCtrlInitiateTest
            oid = f"1.3.6.1.4.1.4491.2.1.27.1.3.2.1.1.{rf_port_ifindex}.1"
            
            result = self._set_cmts_direct(cmts_ip, oid, '2', 'i', community)  # 2 = false
            
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to stop UTSC: {result.get('error')}"}
            
            return {
                'success': True,
                'message': 'UTSC test stopped',
                'rf_port_ifindex': rf_port_ifindex
            }
            
        except Exception as e:
            self.logger.error(f"UTSC stop error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _handle_pnm_utsc_status(self, params: dict) -> dict:
        """Get UTSC test status."""
        cmts_ip = params.get('cmts_ip')
        rf_port_ifindex = params.get('rf_port_ifindex')
        community = params.get('community') or self.config.cmts_write_community or self.config.cmts_community
        
        if not cmts_ip or not rf_port_ifindex:
            return {'success': False, 'error': 'cmts_ip and rf_port_ifindex required'}
        
        try:
            # docsPnmCmtsUtscStatusMeasStatus
            oid = f"1.3.6.1.4.1.4491.2.1.27.1.3.3.1.1.{rf_port_ifindex}.1"
            
            result = self._query_cmts_direct(cmts_ip, oid, community, walk=False)
            
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to get UTSC status: {result.get('error')}"}
            
            # Parse status value
            status_value = 1  # other
            status_name = 'unknown'
            output = result.get('output', '')
            if 'INTEGER' in output:
                try:
                    status_value = int(output.split(':')[-1].strip().split('(')[0])
                    status_names = {1: 'other', 2: 'inactive', 3: 'busy', 4: 'sampleReady', 
                                    5: 'error', 6: 'resourceUnavailable', 7: 'sampleTruncated'}
                    status_name = status_names.get(status_value, 'unknown')
                except:
                    pass
            
            return {
                'success': True,
                'rf_port_ifindex': rf_port_ifindex,
                'meas_status': status_value,
                'meas_status_name': status_name,
                'is_ready': status_value == 4,
                'is_busy': status_value == 3,
                'is_error': status_value == 5
            }
            
        except Exception as e:
            self.logger.error(f"UTSC status error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _handle_pnm_utsc_data(self, params: dict) -> dict:
        """Fetch and parse UTSC spectrum data from TFTP server."""
        cmts_ip = params.get('cmts_ip')
        rf_port_ifindex = params.get('rf_port_ifindex')
        filename = params.get('filename', 'utsc_capture')
        community = params.get('community') or self.config.cmts_community
        
        if not cmts_ip:
            return {'success': False, 'error': 'cmts_ip required'}
        
        try:
            # First try to get the filename from CMTS if not provided
            if not filename or filename == 'utsc_capture':
                base = '1.3.6.1.4.1.4491.2.1.27.1.3.2.1'
                idx = f".{rf_port_ifindex}.1" if rf_port_ifindex else ".1.1"
                result = self._query_cmts_direct(cmts_ip, f"{base}.13{idx}", community)
                if result.get('success') and 'STRING' in result.get('output', ''):
                    filename = result['output'].split('STRING:')[-1].strip().strip('"')
            
            # Construct full path on TFTP server
            # Format: /tftpboot/pnm/utsc/<cmts_name>/<filename>
            tftp_path = self.config.tftp_path or '/tftpboot'
            cmts_name = cmts_ip.replace('.', '_')
            full_path = f"{tftp_path}/pnm/utsc/{cmts_name}/{filename}"
            
            self.logger.info(f"Fetching UTSC data from: {full_path}")
            
            # Fetch file via SSH/SFTP
            if not self.config.tftp_ssh_host:
                return {'success': False, 'error': 'TFTP SSH not configured'}
            
            binary_data = self._fetch_file_via_ssh(
                self.config.tftp_ssh_host,
                self.config.tftp_ssh_user,
                self.config.tftp_ssh_key,
                full_path,
                self.config.tftp_ssh_port
            )
            
            if not binary_data:
                return {'success': False, 'error': f'Could not fetch file: {full_path}'}
            
            # Parse with PyPNM CmSpectrumAnalysis
            try:
                from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis
                parser = CmSpectrumAnalysis(binary_data)
                model = parser.to_model()
                
                # Convert to JSON-serializable format
                spectrum_data = {
                    'channel_id': model.channel_id,
                    'mac_address': model.mac_address,
                    'first_freq_hz': model.first_segment_center_frequency,
                    'last_freq_hz': model.last_segment_center_frequency,
                    'span_hz': model.segment_frequency_span,
                    'num_bins': model.num_bins_per_segment,
                    'bin_spacing_hz': model.bin_frequency_spacing,
                    'segments': []
                }
                
                # Build frequency and amplitude arrays for graphing
                frequencies = []
                amplitudes = []
                
                for seg_idx, segment in enumerate(model.amplitude_bin_segments_float):
                    seg_center = model.first_segment_center_frequency + (seg_idx * model.segment_frequency_span)
                    for bin_idx, amplitude in enumerate(segment):
                        freq = seg_center - (model.segment_frequency_span / 2) + (bin_idx * model.bin_frequency_spacing)
                        frequencies.append(freq / 1e6)  # Convert to MHz
                        amplitudes.append(amplitude)
                
                spectrum_data['frequencies_mhz'] = frequencies
                spectrum_data['amplitudes_dbmv'] = amplitudes
                
                return {
                    'success': True,
                    'data': spectrum_data
                }
                
            except ImportError:
                self.logger.warning("CmSpectrumAnalysis not available, returning raw data")
                import base64
                return {
                    'success': True,
                    'data': {
                        'raw_data': base64.b64encode(binary_data).decode('ascii'),
                        'file_size': len(binary_data)
                    }
                }
            
        except Exception as e:
            self.logger.error(f"UTSC data fetch error: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return {'success': False, 'error': str(e)}
    
    def _fetch_file_via_ssh(self, host: str, user: str, key_file: str, remote_path: str, port: int = 22) -> bytes:
        """Fetch a file from remote server via SSH/SFTP."""
        if not paramiko:
            self.logger.error("paramiko not installed")
            return None
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': host,
                'port': port,
                'username': user,
                'timeout': 30
            }
            
            if key_file and os.path.exists(os.path.expanduser(key_file)):
                connect_kwargs['key_filename'] = os.path.expanduser(key_file)
            
            ssh.connect(**connect_kwargs)
            sftp = ssh.open_sftp()
            
            with sftp.file(remote_path, 'rb') as f:
                data = f.read()
            
            sftp.close()
            ssh.close()
            
            return data
            
        except Exception as e:
            self.logger.error(f"SSH file fetch error: {e}")
            return None
    
    def _handle_pnm_us_rxmer_data(self, params: dict) -> dict:
        """Fetch and parse Upstream OFDMA RxMER data from TFTP folder (mounted or via SSH)."""
        cmts_ip = params.get('cmts_ip')
        ofdma_ifindex = params.get('ofdma_ifindex')
        filename = params.get('filename', 'us_rxmer')
        community = params.get('community') or self.config.cmts_community
        
        if not cmts_ip:
            return {'success': False, 'error': 'cmts_ip required'}
        
        try:
            import os
            import glob
            
            tftp_path = self.config.tftp_path or '/tftpboot'
            
            # Search for the file - CMTS may write to different locations
            # Try multiple patterns:
            # 1. Direct in tftp root: /tftpboot/usrxmer_<mac>*
            # 2. Organized: /tftpboot/pnm/rxmer/<cmts>/filename
            # 3. Access folder: /tftpboot/access/config/ccap/pnm/*
            
            search_patterns = [
                f"{tftp_path}/{filename}*",
                f"{tftp_path}/pnm/rxmer/*/{filename}*",
                f"{tftp_path}/access/config/ccap/pnm/{filename}*",
            ]
            
            found_file = None
            for pattern in search_patterns:
                matches = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
                if matches:
                    found_file = matches[0]  # Most recent match
                    break
            
            self.logger.info(f"Searching for US RxMER file: {filename}")
            
            binary_data = None
            
            # Try local file first (if TFTP is mounted)
            if found_file and os.path.exists(found_file):
                self.logger.info(f"Reading from local mount: {found_file}")
                with open(found_file, 'rb') as f:
                    binary_data = f.read()
            elif self.config.tftp_ssh_host:
                # Fall back to SSH if configured
                cmts_name = cmts_ip.replace('.', '_')
                full_path = f"{tftp_path}/pnm/rxmer/{cmts_name}/{filename}"
                binary_data = self._fetch_file_via_ssh(
                    self.config.tftp_ssh_host,
                    self.config.tftp_ssh_user,
                    self.config.tftp_ssh_key,
                    full_path,
                    self.config.tftp_ssh_port
                )
            else:
                # List what files match the pattern
                all_matches = glob.glob(f"{tftp_path}/*{filename}*") + glob.glob(f"{tftp_path}/**/*{filename}*", recursive=True)
                if all_matches:
                    return {'success': False, 'error': f'File not found for: {filename}. Similar: {[os.path.basename(f) for f in all_matches[:5]]}'}
                return {'success': False, 'error': f'No files matching: {filename}'}
            
            if not binary_data:
                return {'success': False, 'error': f'Could not fetch file: {filename}'}
            
            # Parse the RxMER data - E6000 ARRIS/CommScope format
            # Header: "PNNi" magic bytes, then metadata, MER data starts around offset 0x128
            # Each MER value is a single byte, representing dB * 4 (so 0xa6 = 166 → 41.5 dB)
            # 0xff is used for excluded subcarriers
            
            rxmer_values = []
            subcarriers = []
            
            # Find the MER data section
            # Look for the pattern after MAC address (6 bytes) + some metadata
            offset = 0
            
            if len(binary_data) > 4 and binary_data[0:4] == b'PNNi':
                # E6000 US RxMER format - data starts after header (~0x128)
                offset = 0x128
                
                idx = 0
                while offset < len(binary_data):
                    val = binary_data[offset]
                    if val != 0xff:  # 0xff = excluded subcarrier
                        mer_db = val / 4.0  # Convert to dB (value is in 0.25 dB units)
                        rxmer_values.append(mer_db)
                        subcarriers.append(idx)
                    idx += 1
                    offset += 1
            else:
                # Generic 2-byte format fallback
                import struct
                idx = 0
                while offset + 2 <= len(binary_data):
                    val = struct.unpack('>h', binary_data[offset:offset+2])[0]
                    rxmer_values.append(val / 10.0)
                    subcarriers.append(idx)
                    idx += 1
                    offset += 2
            
            return {
                'success': True,
                'data': {
                    'subcarriers': subcarriers,
                    'rxmer_values': rxmer_values,
                    'ofdma_ifindex': ofdma_ifindex,
                    'found_file': found_file
                }
            }
            
        except Exception as e:
            self.logger.error(f"US RxMER data fetch error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _handle_pnm_us_rxmer_start(self, params: dict) -> dict:
        """Start Upstream OFDMA RxMER measurement on CMTS."""
        cmts_ip = params.get('cmts_ip')
        ofdma_ifindex = params.get('ofdma_ifindex')
        cm_mac = params.get('cm_mac_address')
        community = params.get('community') or self.config.cmts_write_community or self.config.cmts_community
        
        if not cmts_ip or not ofdma_ifindex or not cm_mac:
            return {'success': False, 'error': 'cmts_ip, ofdma_ifindex, and cm_mac_address required'}
        
        try:
            # docsPnmCmtsUsOfdmaRxMerTable OIDs (1.3.6.1.4.1.4491.2.1.27.1.3.7.1)
            # Column order: .1=Enable, .2=CmMac, .3=PreEq, .4=NumAvgs, .5=MeasStatus, .6=FileName, .7=DestIdx
            base = '1.3.6.1.4.1.4491.2.1.27.1.3.7.1'
            idx = f".{ofdma_ifindex}"
            
            # Set CM MAC address first
            mac = cm_mac.replace(':', '').replace('-', '').upper()
            mac_hex = ' '.join([mac[i:i+2] for i in range(0, 12, 2)])
            result = self._set_cmts_direct(cmts_ip, f"{base}.2{idx}", mac_hex, 'x', community)
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to set CM MAC: {result.get('error')}"}
            
            # Set filename
            filename = params.get('filename', 'us_rxmer')
            result = self._set_cmts_direct(cmts_ip, f"{base}.6{idx}", filename, 's', community)
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to set filename: {result.get('error')}"}
            
            # Set pre-equalization option (.3)
            pre_eq = 1 if params.get('pre_eq', True) else 2  # 1=true, 2=false
            result = self._set_cmts_direct(cmts_ip, f"{base}.3{idx}", str(pre_eq), 'i', community)
            
            # Enable measurement (.1 = 1 = true)
            result = self._set_cmts_direct(cmts_ip, f"{base}.1{idx}", '1', 'i', community)
            if not result.get('success'):
                return {'success': False, 'error': f"Failed to start US RxMER: {result.get('error')}"}
            
            return {
                'success': True,
                'message': 'US OFDMA RxMER measurement started',
                'ofdma_ifindex': ofdma_ifindex,
                'cm_mac': cm_mac,
                'filename': filename
            }
            
        except Exception as e:
            self.logger.error(f"US RxMER start error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _handle_pnm_us_rxmer_status(self, params: dict) -> dict:
        """Get Upstream RxMER measurement status."""
        cmts_ip = params.get('cmts_ip')
        ofdma_ifindex = params.get('ofdma_ifindex')
        community = params.get('community') or self.config.cmts_write_community or self.config.cmts_community
        
        if not cmts_ip or not ofdma_ifindex:
            return {'success': False, 'error': 'cmts_ip and ofdma_ifindex required'}
        
        try:
            # docsPnmCmtsUsOfdmaRxMerMeasStatus (.5)
            oid = f"1.3.6.1.4.1.4491.2.1.27.1.3.7.1.5.{ofdma_ifindex}"
            
            result = self._snmp_get(cmts_ip, oid, community)
            
            if not result.get('success') or not result.get('results'):
                return {'success': False, 'error': f"Failed to get status: {result.get('error')}"}
            
            # Parse status value from pysnmp result
            status_value = int(result['results'][0].get('value', 1))
            status_names = {1: 'other', 2: 'inactive', 3: 'busy', 4: 'sampleReady', 5: 'error'}
            status_name = status_names.get(status_value, 'unknown')
            
            return {
                'success': True,
                'ofdma_ifindex': ofdma_ifindex,
                'meas_status': status_value,
                'meas_status_name': status_name,
                'is_ready': status_value == 4,
                'is_busy': status_value == 3,
                'is_error': status_value == 5
            }
            
        except Exception as e:
            self.logger.error(f"US RxMER status error: {e}")
            return {'success': False, 'error': str(e)}

    def _handle_cmts_get_modems(self, params: dict) -> dict:
        """
        Get list of cable modems from a CMTS via SNMP.
        Uses parallel queries for MAC, IP, Status. Supports Redis caching.
        
        DOCSIS CMTS MIBs used:
        - docsIfCmtsCmStatusMacAddress: 1.3.6.1.2.1.10.127.1.3.3.1.2
        - docsIfCmtsCmStatusIpAddress: 1.3.6.1.2.1.10.127.1.3.3.1.3
        - docsIfCmtsCmStatusValue (status): 1.3.6.1.2.1.10.127.1.3.3.1.9
        - docsIf3CmtsCmRegStatusMdIfIndex (interface): 1.3.6.1.4.1.4491.2.1.20.1.3.1.5
        """
        cmts_ip = params.get('cmts_ip')
        community = params.get('community') or self.config.cmts_write_community or self.config.cmts_community
        limit = params.get('limit', 10000)  # Increased limit
        use_bulk = params.get('use_bulk', True)
        use_cache = params.get('use_cache', True)
        # CMTS queries go DIRECT - don't auto-enable equalizer just because it's configured
        # Equalizer/cm_proxy is for modem enrichment, not CMTS queries
        use_equalizer = params.get('use_equalizer', False)
        
        if not cmts_ip:
            return {'success': False, 'error': 'cmts_ip required'}
        
        # Check Redis cache first
        cache_key = f"cmts_modems:{cmts_ip}"
        if use_cache and redis and self.config.redis_host:
            try:
                r = redis.Redis(host=self.config.redis_host, port=self.config.redis_port, decode_responses=True)
                cached = r.get(cache_key)
                if cached:
                    self.logger.info(f"Returning cached modems for {cmts_ip}")
                    return json.loads(cached)
            except Exception as e:
                self.logger.warning(f"Redis cache error: {e}")
        
        self.logger.info(f"Getting cable modems from CMTS {cmts_ip}")
        
        # DOCSIS 3.0 MIB OIDs - use docsIf3 table for MAC and DOCSIS version
        OID_D3_MAC = '1.3.6.1.4.1.4491.2.1.20.1.3.1.2'  # docsIf3CmtsCmRegStatusMacAddr
        
        # Old DOCSIS table for IP and Status (has different index, correlate by MAC)
        OID_OLD_MAC = '1.3.6.1.2.1.10.127.1.3.3.1.2'   # docsIfCmtsCmStatusMacAddress
        OID_OLD_IP = '1.3.6.1.2.1.10.127.1.3.3.1.3'    # docsIfCmtsCmStatusIpAddress
        OID_OLD_STATUS = '1.3.6.1.2.1.10.127.1.3.3.1.9'  # docsIfCmtsCmStatusValue
        
        # DOCSIS 3.1 MIB - MaxUsableDsFreq: if > 0, modem is DOCSIS 3.1
        OID_D31_MAX_DS_FREQ = '1.3.6.1.4.1.4491.2.1.28.1.3.1.7'  # docsIf31CmtsCmRegStatusMaxUsableDsFreq
        
        # Use pysnmp (required)
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available', 'cmts_ip': cmts_ip}
        
        self.logger.info(f"Using pysnmp for CMTS modem discovery")
        return asyncio.run(self._async_cmts_get_modems(
            cmts_ip, community, limit,
            OID_D3_MAC, OID_OLD_MAC, OID_OLD_IP, OID_OLD_STATUS, OID_D31_MAX_DS_FREQ
        ))
    
    def _handle_enrich_modems(self, params: dict) -> dict:
        """
        Enrich modems with vendor/model/firmware info via cm_proxy (hop-access) or cm_direct.
        This runs in background after initial modem list is returned.
        """
        modems = params.get('modems', [])
        modem_community = params.get('modem_community', 'm0d3m1nf0')
        
        # Check if we can reach modems - either via cm_proxy or cm_direct
        if not self.config.cm_proxy_host and not self.config.cm_enabled:
            self.logger.error("Neither cm_proxy_host nor cm_direct configured!")
            return {
                'success': False,
                'error': 'No modem access method configured for enrichment'
            }
        
        # Log some stats about incoming modems
        status_counts = {}
        for m in modems:
            s = m.get('status', 'unknown')
            status_counts[s] = status_counts.get(s, 0) + 1
        self.logger.info(f"Enrichment request: {len(modems)} modems, status breakdown: {status_counts}")
        
        try:
            # Use cm_direct if enabled (direct SNMP to modems), otherwise use cm_proxy
            if self.config.cm_enabled:
                enriched = self._enrich_modems_direct(modems, modem_community, max_workers=50)
            else:
                enriched = self._enrich_modems_parallel(modems, modem_community, max_workers=50)
            
            # Count how many were enriched
            enriched_count = sum(1 for m in enriched if m.get('model') and m.get('model') not in ['N/A', 'Unknown'])
            self.logger.info(f"Enrichment complete: {enriched_count}/{len(enriched)} modems have model info")
            
            return {
                'success': True,
                'modems': enriched,
                'enriched_count': enriched_count,
                'total_count': len(enriched)
            }
        except Exception as e:
            self.logger.exception(f"Failed to enrich modems: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _enrich_modems_direct(self, modems: list, modem_community: str = 'm0d3m1nf0', max_workers: int = 20) -> list:
        """
        Query each modem directly via pysnmp to get sysDescr for model info.
        Uses asyncio with concurrent execution.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0'  # sysDescr
        
        # Query modems with valid IPs (any status that indicates online)
        online_statuses = {'operational', 'registrationComplete', 'ipComplete', 'online'}
        online_modems = [m for m in modems 
                         if m.get('ip_address') and m.get('ip_address') != 'N/A' 
                         and m.get('status') in online_statuses][:200]
        
        self.logger.info(f"Direct enrichment: {len(online_modems)} modems with valid IP (from {len(modems)} total)")
        
        if not online_modems:
            self.logger.warning("No online modems to enrich")
            return modems
        
        if not PYSNMP_AVAILABLE:
            self.logger.error("pysnmp not available for enrichment")
            return modems
        
        results = {}
        
        def query_modem(modem):
            ip = modem.get('ip_address')
            try:
                result = asyncio.run(self._async_snmp_get(ip, OID_SYS_DESCR, modem_community, timeout=2))
                if result.get('success') and result.get('output'):
                    output = result.get('output', '')
                    if '=' in output:
                        sys_descr = output.split('=', 1)[-1].strip()
                        return ip, sys_descr
            except Exception as e:
                pass
            return ip, None
        
        self.logger.info(f"Running direct SNMP queries for {len(online_modems)} modems with {max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(query_modem, m): m for m in online_modems}
            for future in as_completed(futures):
                ip, sys_descr = future.result()
                if sys_descr:
                    results[ip] = sys_descr
        
        self.logger.info(f"Direct query returned {len(results)} results")
        
        # Apply results to modems
        enriched_count = 0
        for modem in online_modems:
            ip = modem.get('ip_address')
            if ip in results:
                model_info = self._parse_sys_descr(results[ip])
                modem['model'] = model_info.get('model', 'Unknown')
                modem['software_version'] = model_info.get('software', '')
                if model_info.get('vendor'):
                    modem['vendor'] = model_info.get('vendor')
                enriched_count += 1
        
        self.logger.info(f"Direct enrichment done: {enriched_count}/{len(online_modems)} modems enriched")
        
        # Merge enriched modems back
        enriched_map = {m['mac_address']: m for m in online_modems}
        for modem in modems:
            if modem['mac_address'] in enriched_map:
                modem.update(enriched_map[modem['mac_address']])
        
        return modems
    
    def _enrich_modems_parallel(self, modems: list, modem_community: str = 'm0d3m1nf0', max_workers: int = 20) -> list:
        """
        Query each modem via pysnmp to get sysDescr for model info.
        This is an alias for _enrich_modems_direct (cm_proxy SSH no longer used).
        """
        return self._enrich_modems_direct(modems, modem_community, max_workers)
    
    def _parse_sys_descr(self, sys_descr: str) -> dict:
        """Parse sysDescr to extract vendor, model, and software version."""
        result = {}
        import re
        
        # Check for structured format: <<KEY: value; KEY: value>>
        # Example: "FAST3896 Wireless Voice Gateway <<HW_REV: 1.2; VENDOR: SAGEMCOM; SW_REV: LG-RDK_11.10.26; MODEL: F3896LG>>"
        structured_match = re.search(r'<<(.+?)>>', sys_descr)
        if structured_match:
            fields = structured_match.group(1)
            for pair in fields.split(';'):
                if ':' in pair:
                    key, value = pair.split(':', 1)
                    key = key.strip().upper()
                    value = value.strip()
                    if key == 'MODEL':
                        result['model'] = value
                    elif key == 'VENDOR':
                        result['vendor'] = value
                    elif key == 'SW_REV':
                        result['software'] = value
            if result.get('model'):
                return result
        
        # Fallback: pattern matching for non-structured sysDescr
        descr = sys_descr.lower()
        
        if 'arris' in descr or 'touchstone' in descr:
            result['vendor'] = 'ARRIS'
        elif 'technicolor' in descr:
            result['vendor'] = 'Technicolor'
        elif 'sagemcom' in descr:
            result['vendor'] = 'Sagemcom'
        elif 'hitron' in descr:
            result['vendor'] = 'Hitron'
        elif 'motorola' in descr:
            result['vendor'] = 'Motorola'
        elif 'cisco' in descr:
            result['vendor'] = 'Cisco'
        elif 'ubee' in descr:
            result['vendor'] = 'Ubee'
        
        # Model patterns
        model_match = re.search(r'(FAST\d+|F\d{4}[A-Z]*|TG\d+|TC\d+|SB\d+|DPC\d+|EPC\d+|CM\d+|SBG\d+|CGM\d+)', sys_descr, re.I)
        if model_match:
            result['model'] = model_match.group(1).upper()
        
        # Software version
        version_match = re.search(r'(\d+\.\d+\.\d+[\.\d\-a-zA-Z]*)', sys_descr)
        if version_match:
            result['software'] = version_match.group(1)
        
        return result
    
    def _decode_cm_status(self, status_code: int) -> str:
        """Decode DOCSIS CM status code to human-readable string."""
        # docsIfCmtsCmStatusValue values
        status_map = {
            1: 'other',
            2: 'ranging',
            3: 'rangingAborted',
            4: 'rangingComplete',
            5: 'ipComplete',
            6: 'registrationComplete',
            7: 'accessDenied',
            8: 'operational',  # This is the "online" state
            9: 'registeredBPIInitializing',
        }
        return status_map.get(status_code, f'unknown({status_code})')
    
    def _decode_d3_status(self, status_code: int) -> str:
        """Decode docsIf3CmtsCmRegStatusValue to human-readable string."""
        # docsIf3CmtsCmRegStatusValue values from DOCS-IF3-MIB
        status_map = {
            1: 'other',
            2: 'initialRanging',
            3: 'rangingAutoAdjComplete',
            4: 'startEae',
            5: 'startDhcpv4',
            6: 'startDhcpv6',
            7: 'dhcpv4Complete',
            8: 'dhcpv6Complete',
            9: 'startCfgFileDownload',
            10: 'cfgFileDownloadComplete',
            11: 'startRegistration',
            12: 'registrationComplete',
            13: 'operational',  # This is the "online" state
            14: 'bpiInit',
            15: 'forwardingDisabled',
            16: 'rfMuteAll',
        }
        return status_map.get(status_code, f'unknown({status_code})')
    
    def _decode_docsis_version(self, docsis_code: int) -> str:
        """Decode DOCSIS version from docsIf3CmtsCmRegStatusDocsisVersion."""
        # docsIf3CmtsCmRegStatusDocsisVersion values from DOCSIS-IF3-MIB
        version_map = {
            1: 'ATDMA',
            2: 'SCDMA', 
            3: 'DOCSIS 1.0',
            4: 'DOCSIS 1.1',
            5: 'DOCSIS 2.0',
            6: 'DOCSIS 3.0',
            7: 'DOCSIS 3.1',
            8: 'DOCSIS 4.0',
        }
        return version_map.get(docsis_code, f'Unknown({docsis_code})')
    
    def _get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor name from MAC address OUI (first 3 bytes)."""
        # Common cable modem OUIs
        oui_vendors = {
            '00:00:ca': 'ARRIS',
            '00:01:5c': 'ARRIS',
            '00:15:96': 'ARRIS',
            '00:15:a2': 'ARRIS',
            '00:15:a3': 'ARRIS',
            '00:15:a4': 'ARRIS',
            '00:15:a5': 'ARRIS',
            '00:1d:ce': 'ARRIS',
            '00:1d:cf': 'ARRIS',
            '00:1d:d0': 'ARRIS',
            '00:1d:d1': 'ARRIS',
            '00:1d:d2': 'ARRIS',
            '00:1d:d3': 'ARRIS',
            '00:1d:d4': 'ARRIS',
            '00:1d:d5': 'ARRIS',
            '00:23:74': 'ARRIS',
            '18:35:d1': 'Arris',
            '20:3d:66': 'ARRIS',
            '40:0d:10': 'Arris',
            '44:6a:b7': 'Arris',
            '48:d3:43': 'Arris',
            '4c:38:d8': 'Arris',
            '54:e2:e0': 'Arris',
            '70:76:30': 'Arris',
            '70:85:c6': 'Arris',
            '7c:26:34': 'Arris',
            '84:a0:6e': 'ARRIS',
            '84:e0:58': 'Arris',
            'a0:c5:62': 'Arris',
            'a4:05:d6': 'Arris',
            'ac:f8:cc': 'Arris',
            'c0:05:c2': 'Arris',
            'd4:2c:0f': 'Arris',
            'd8:25:22': 'Arris',
            'e4:57:40': 'Arris',
            'e8:ed:05': 'ARRIS',
            'f0:af:85': 'ARRIS',
            'f8:0b:be': 'ARRIS',
            'fc:51:a4': 'ARRIS',
            'fc:6f:b7': 'Arris',
            '00:1e:5a': 'CISCO',
            '00:1e:bd': 'CISCO',
            '00:22:6b': 'CISCO',
            '00:26:0a': 'CISCO',
            '00:30:f1': 'CISCO',
            '5c:50:15': 'CISCO',
            'c0:c5:20': 'CISCO',
            '00:11:1a': 'Motorola',
            '00:12:25': 'Motorola',
            '00:14:f8': 'Motorola',
            '00:15:9a': 'Motorola',
            '00:15:d1': 'Motorola',
            '00:17:e2': 'Motorola',
            '00:18:a4': 'Motorola',
            '00:19:47': 'Motorola',
            '00:1a:66': 'Motorola',
            '00:1a:77': 'Motorola',
            '00:1c:c1': 'Motorola',
            '00:1c:fb': 'Motorola',
            '00:1d:6b': 'Motorola',
            '00:1e:46': 'Motorola',
            '00:1e:5d': 'Motorola',
            '00:1f:6b': 'Motorola',
            '00:23:be': 'Motorola',
            '00:24:95': 'Motorola',
            '00:26:41': 'Motorola',
            '00:26:42': 'Motorola',
            '08:95:2a': 'Technicolor',
            '10:86:8c': 'Technicolor',
            '18:35:d1': 'Technicolor',
            '2c:39:96': 'Technicolor',
            '30:d3:2d': 'Technicolor',
            '44:32:c8': 'Technicolor',
            '50:09:59': 'Technicolor',
            '58:23:8c': 'Technicolor',
            '70:5a:9e': 'Technicolor',
            '70:b1:4e': 'Technicolor',
            '7c:03:4c': 'Technicolor',
            '80:29:94': 'Technicolor',
            '88:f7:c7': 'Technicolor',
            '8c:04:ff': 'Technicolor',
            '90:01:3b': 'Technicolor',
            'a0:ce:c8': 'Technicolor',
            'b0:c2:87': 'Technicolor',
            'c4:27:95': 'Technicolor',
            'c8:d1:5e': 'Technicolor',
            'cc:03:fa': 'Technicolor',
            'cc:35:40': 'Technicolor',
            'd0:b2:c4': 'Technicolor',
            'd4:35:1d': 'Technicolor',
            'e0:88:5d': 'Technicolor',
            'f4:ca:e5': 'Technicolor',
            'fc:52:8d': 'Technicolor',
            'fc:91:14': 'Technicolor',
            'fc:94:e3': 'Technicolor',
            '00:1d:b5': 'Juniper',
            '00:1f:12': 'Juniper',
            '00:21:59': 'Juniper',
            '00:23:9c': 'Juniper',
            '00:26:88': 'Juniper',
            # Sci Atl
            '00:0a:73': 'Sci Atl',
            '00:14:f8': 'Sci Atl',
            '00:16:92': 'Sci Atl',
            '00:18:68': 'Sci Atl',
            '00:19:47': 'Sci Atl',
            '00:1a:c3': 'Sci Atl',
            '00:1b:d7': 'Sci Atl',
            '00:1c:ea': 'Sci Atl',
            # Thomson
            '00:18:9b': 'Thomson',
            '00:1e:69': 'Thomson',
            '00:24:d1': 'Thomson',
            '00:26:24': 'Thomson',
            '80:c6:ab': 'Thomson',
            # Samsung
            '00:21:4c': 'Samsung',
            '1c:3a:de': 'Samsung',
            '20:d5:bf': 'Samsung',
            '54:fa:3e': 'Samsung',
            'd4:7a:e2': 'Samsung',
            # Cisco
            '00:22:3a': 'Cisco',
            '08:80:39': 'Cisco',
            '0c:02:27': 'Cisco',
            '10:5f:49': 'Cisco',
            '14:98:7d': 'Cisco',
            '18:55:0f': 'Cisco',
            '24:37:4c': 'Cisco',
            '2c:ab:a4': 'Cisco',
            '38:5f:66': 'Cisco',
            '48:1d:70': 'Cisco',
            '48:f7:c0': 'Cisco',
            '50:39:55': 'Cisco',
            '74:54:7d': 'Cisco',
            '84:8d:c7': 'Cisco',
            'c0:c6:87': 'Cisco',
            'c8:fb:26': 'Cisco',
            'e4:48:c7': 'Cisco',
            # Pace
            '00:4c:00': 'Pace',
            '00:4e:00': 'Pace',
            '00:d0:37': 'Pace',
            '34:7a:60': 'Pace',
            '80:f5:03': 'Pace',
            '84:96:d8': 'Pace',
            'fc:8e:7e': 'Pace',
            # Intel
            '00:50:f1': 'Intel',
            # Teleste
            '00:90:50': 'Teleste',
            # Netgear
            '04:a1:51': 'Netgear',
            '6c:b0:ce': 'Netgear',
            # FritzBox
            '04:b4:fe': 'FritzBox',
            '1c:ed:6f': 'FritzBox',
            '2c:91:ab': 'FritzBox',
            '3c:37:12': 'FritzBox',
            '3c:a6:2f': 'FritzBox',
            '48:5d:35': 'FritzBox',
            '74:42:7f': 'FritzBox',
            'b0:f2:08': 'FritzBox',
            'dc:15:c8': 'FritzBox',
            # Sagemcom
            '04:e3:1a': 'Sagemcom',
            '08:95:2a': 'Sagemcom',
            '10:b3:6f': 'Sagemcom',
            '18:6a:81': 'Sagemcom',
            '28:52:e8': 'Sagemcom',
            '30:7c:b2': 'Sagemcom',
            '34:5d:9e': 'Sagemcom',
            '44:05:3f': 'Sagemcom',
            '44:d4:54': 'Sagemcom',
            '44:e1:37': 'Sagemcom',
            '4c:19:5d': 'Sagemcom',
            '54:47:cc': 'Sagemcom',
            '5c:fa:25': 'Sagemcom',
            '64:fd:96': 'Sagemcom',
            '6c:ff:ce': 'Sagemcom',
            '70:fc:8f': 'Sagemcom',
            '7c:16:89': 'Sagemcom',
            '7c:8b:ca': 'Sagemcom',
            '94:3c:96': 'Sagemcom',
            '94:98:8f': 'Sagemcom',
            'a0:1b:29': 'Sagemcom',
            'a8:4e:3f': 'Sagemcom',
            'a8:70:5d': 'Sagemcom',
            'b0:5b:99': 'Sagemcom',
            'c4:eb:39': 'Sagemcom',
            'cc:00:f1': 'Sagemcom',
            'cc:33:bb': 'Sagemcom',
            'cc:58:30': 'Sagemcom',
            'd0:6d:c9': 'Sagemcom',
            'd0:cf:0e': 'Sagemcom',
            'e4:c0:e2': 'Sagemcom',
            'f8:08:4f': 'Sagemcom',
            # Ubee
            '00:14:d1': 'Ubee',
            '00:15:2c': 'Ubee',
            '00:26:5e': 'Ubee',
            '08:3e:8e': 'Ubee',
            '0c:84:dc': 'Ubee',
            '0c:b9:37': 'Ubee',
            '0c:ee:e6': 'Ubee',
            '10:08:b1': 'Ubee',
            '1c:3e:84': 'Ubee',
            '28:c6:8e': 'Ubee',
            '2c:33:7a': 'Ubee',
            '34:23:87': 'Ubee',
            '38:b1:db': 'Ubee',
            '3c:77:e6': 'Ubee',
            '48:5a:b6': 'Ubee',
            '4c:eb:bd': 'Ubee',
            '54:35:30': 'Ubee',
            '58:6d:8f': 'Ubee',
            '5c:3a:45': 'Ubee',
            '5c:b0:66': 'Ubee',
            '64:0d:ce': 'Ubee',
            '64:7c:34': 'Ubee',
            '68:94:23': 'Ubee',
            '68:b6:fc': 'Ubee',
            '70:18:8b': 'Ubee',
            '70:77:81': 'Ubee',
            '74:29:af': 'Ubee',
            '78:96:84': 'Ubee',
            '78:dd:08': 'Ubee',
            '7c:e9:d3': 'Ubee',
            '80:56:f2': 'Ubee',
            '88:9f:fa': 'Ubee',
            '90:32:4b': 'Ubee',
            '94:53:30': 'Ubee',
            '9c:2a:70': 'Ubee',
            '9c:30:5b': 'Ubee',
            'a4:17:31': 'Ubee',
            'a4:cf:d2': 'Ubee',
            'ac:d1:b8': 'Ubee',
            'bc:85:56': 'Ubee',
            'c0:38:96': 'Ubee',
            'd4:6a:6a': 'Ubee',
            'd8:0f:99': 'Ubee',
            'fc:01:7c': 'Ubee',
            '08:95:2a': 'Sagemcom',
            '10:b3:6f': 'Sagemcom',
            '28:52:e8': 'Sagemcom',
            '30:7c:b2': 'Sagemcom',
            '44:e1:37': 'Sagemcom',
            '70:fc:8f': 'Sagemcom',
            '7c:8b:ca': 'Sagemcom',
            'a0:1b:29': 'Sagemcom',
            'a8:4e:3f': 'Sagemcom',
            'a8:70:5d': 'Sagemcom',
            'cc:33:bb': 'Sagemcom',
            'f8:08:4f': 'Sagemcom',
            # Compal
            '34:2c:c4': 'Compal',
            '38:43:7d': 'Compal',
            '54:67:51': 'Compal',
            '68:02:b8': 'Compal',
            '90:5c:44': 'Compal',
            'ac:22:05': 'Compal',
            'b4:f2:67': 'Compal',
            # Hitron
            '00:04:bd': 'Hitron',
            '00:26:5b': 'Hitron',
            '00:26:d8': 'Hitron',
            '1c:ab:c0': 'Hitron',
            '84:94:8c': 'Hitron',
            '90:50:ca': 'Hitron',
            'a8:4e:3f': 'Hitron',
            'ac:20:2e': 'Hitron',
            'bc:14:85': 'Hitron',
            'bc:4d:fb': 'Hitron',
            'f0:f2:49': 'Hitron',
            'f8:1d:0f': 'Hitron',
        }
        
        if not mac or len(mac) < 8:
            return 'Unknown'
        
        # Normalize MAC format
        mac_normalized = mac.lower().replace('-', ':')
        oui = mac_normalized[:8]
        
        return oui_vendors.get(oui, 'Unknown')
    
    def _handle_cmts_get_modem_info(self, params: dict) -> dict:
        """
        Get detailed info for a specific modem from CMTS.
        
        Can search by MAC or IP address.
        """
        cmts_ip = params.get('cmts_ip')
        mac_address = params.get('mac_address')
        modem_ip = params.get('modem_ip')
        community = params.get('community', 'private')
        
        if not cmts_ip:
            return {'success': False, 'error': 'cmts_ip required'}
        
        if not mac_address and not modem_ip:
            return {'success': False, 'error': 'mac_address or modem_ip required'}
        
        # First get all modems and find the matching one
        modems_result = self._handle_cmts_get_modems({
            'cmts_ip': cmts_ip,
            'community': community,
            'limit': 5000,  # Get more for search
            'use_bulk': True
        })
        
        if not modems_result.get('success'):
            return modems_result
        
        # Find matching modem
        for modem in modems_result.get('modems', []):
            if mac_address and modem['mac_address'].lower() == mac_address.lower():
                return {'success': True, 'modem': modem, 'cmts_ip': cmts_ip}
            if modem_ip and modem['ip_address'] == modem_ip:
                return {'success': True, 'modem': modem, 'cmts_ip': cmts_ip}
        
        return {
            'success': False,
            'error': f"Modem not found on CMTS {cmts_ip}",
            'search_mac': mac_address,
            'search_ip': modem_ip
        }
    
    def connect(self):
        """Connect to PyPNM Server."""
        self.running = True
        
        # Set up SSH tunnel if enabled
        if self.config.pypnm_ssh_tunnel_enabled:
            if not self._setup_pypnm_tunnel():
                self.logger.error("Failed to establish SSH tunnel, cannot continue")
                return
        
        ws_url = self._get_websocket_url()
        
        while self.running:
            try:
                self.logger.info(f"Connecting to {ws_url}...")
                
                self.ws = websocket.WebSocketApp(
                    ws_url,
                    on_open=self._on_open,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close
                )
                
                self.ws.run_forever(ping_interval=120, ping_timeout=60)
                
            except Exception as e:
                self.logger.error(f"Connection failed: {e}")
            
            if self.running:
                self.logger.info(f"Reconnecting in {self.config.reconnect_interval} seconds...")
                time.sleep(self.config.reconnect_interval)
    
    def stop(self):
        """Stop the agent and cleanup connections."""
        self.logger.info("Stopping agent...")
        self.running = False
        
        # Close WebSocket
        if self.ws:
            self.ws.close()
        
        # Close CM Proxy SSH connection
        if self.cm_proxy:
            self.cm_proxy.close()
        
        # Close TFTP SSH connection
        if self.tftp_ssh:
            self.tftp_ssh.close()
        
        # Stop PyPNM tunnel monitor and tunnel
        if self.pypnm_tunnel_monitor:
            self.pypnm_tunnel_monitor.stop()
        if self.pypnm_tunnel:
            self.pypnm_tunnel.stop_tunnel()
        
        self.logger.info("Agent stopped")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='PyPNM Remote Agent')
    parser.add_argument('-c', '--config', help='Path to config file')
    parser.add_argument('--url', help='PyPNM Server WebSocket URL (overrides config)')
    parser.add_argument('--token', help='Authentication token (overrides config)')
    parser.add_argument('--agent-id', help='Agent ID (overrides config)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    if args.config:
        config = AgentConfig.from_file(args.config)
        logger.info(f"Loaded config from {args.config}")
    else:
        config = AgentConfig.from_env()
        logger.info("Loaded config from environment variables")
    
    # Override with command line args
    if args.url:
        config.pypnm_server_url = args.url
    if args.token:
        config.auth_token = args.token
    if args.agent_id:
        config.agent_id = args.agent_id
    
    # Log configuration summary
    logger.info(f"Agent ID: {config.agent_id}")
    logger.info(f"PyPNM Server: {config.pypnm_server_url}")
    logger.info(f"SSH Tunnel: {'enabled' if config.pypnm_ssh_tunnel_enabled else 'disabled'}")
    if config.pypnm_ssh_tunnel_enabled:
        logger.info(f"  SSH Host: {config.pypnm_ssh_host}")
    logger.info(f"CM Proxy: {config.cm_proxy_host or 'not configured'}")
    logger.info(f"CMTS SNMP Direct: {config.cmts_enabled}")
    if config.cmts_enabled:
        logger.info(f"  CMTS Read Community: {config.cmts_community}")
        logger.info(f"  CMTS Write Community: {'configured' if config.cmts_write_community else 'not configured (upstream PNM disabled)'}")
    logger.info(f"TFTP SSH: {config.tftp_ssh_host or 'not configured'}")
    
    # Start agent
    agent = PyPNMAgent(config)
    
    try:
        agent.connect()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        agent.stop()


# OFDM Capture Handler Methods (add to PyPNMAgent class)
def _handle_pnm_ofdm_channels(self, params: dict) -> dict:
    """Get list of OFDM channels using PyPNM."""
    import sys
    sys.path.insert(0, '/home/svdleer/PyPNM')
    
    try:
        import asyncio
        from pypnm.lib.mac_address import MacAddress
        from pypnm.lib.inet import Inet
        from agent_cable_modem import AgentCableModem
        
        mac = params.get('mac_address')
        ip = params.get('modem_ip')
        community = params.get('community') or self.config.cm_community
        
        async def get_channels():
            cm = AgentCableModem(
                mac_address=MacAddress(mac),
                inet=Inet(ip),
                backend_url='http://localhost:5050',
                write_community=community
            )
            channels_data = await cm.getDocsIf31CmDsOfdmChanEntry()
            
            channels = []
            for ch in channels_data:
                channels.append({
                    "index": ch.index,
                    "channel_id": getattr(ch.entry, 'docsIf31CmDsOfdmChanChannelId', None),
                    "subcarrier_zero_freq": getattr(ch.entry, 'docsIf31CmDsOfdmChannelSubcarrierZeroFreq', None),
                    "num_subcarriers": getattr(ch.entry, 'docsIf31CmDsOfdmChanNumActiveSubcarriers', None),
                })
            return channels
        
        channels = asyncio.run(get_channels())
        return {"success": True, "channels": channels}
        
    except Exception as e:
        logger.error(f"OFDM channels error: {e}")
        return {"success": False, "error": str(e)}


def main():
    """Main entry point for the PyPNM Agent."""
    import argparse
    
    parser = argparse.ArgumentParser(description='PyPNM Web GUI Agent')
    parser.add_argument('--config', '-c', type=str, help='Path to agent_config.json')
    parser.add_argument('--agent-id', type=str, help='Override agent ID from config')
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
            logger.error("No configuration file found. Use --config or set environment variables.")
            return
    
    # Override agent ID if provided
    if args.agent_id:
        config.agent_id = args.agent_id
    
    # Log configuration summary
    logger.info(f"Agent ID: {config.agent_id}")
    logger.info(f"PyPNM Server: {config.pypnm_server_url}")
    logger.info(f"SSH Tunnel: {'enabled' if config.pypnm_ssh_tunnel_enabled else 'disabled'}")
    if config.pypnm_ssh_tunnel_enabled:
        logger.info(f"  SSH Host: {config.pypnm_ssh_host}")
    logger.info(f"CM Proxy: {config.cm_proxy_host or 'not configured'}")
    logger.info(f"CMTS SNMP Direct: {config.cmts_enabled}")
    logger.info(f"TFTP SSH: {config.tftp_ssh_host or 'not configured'}")
    
    # Start agent
    agent = PyPNMAgent(config)
    
    try:
        agent.connect()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        agent.stop()


if __name__ == '__main__':
    main()



