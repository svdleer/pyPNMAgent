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
    redis_ttl: int = 86400  # Cache TTL in seconds (24 hours)
    
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
            'snmp_parallel_walk': self._handle_snmp_parallel_walk,
            'tftp_get': self._handle_tftp_get,
            'cmts_command': self._handle_cmts_command,
            'execute_pnm': self._handle_pnm_command,
            # REMOVED: cmts_get_modems, cmts_get_modem_info, enrich_modems - handlers deleted
            # 'cmts_get_modems': self._handle_cmts_get_modems,
            # 'cmts_get_modem_info': self._handle_cmts_get_modem_info,
            # 'enrich_modems': self._handle_enrich_modems,
            # PNM measurement commands (downstream - on CM)
            'pnm_rxmer': self._handle_pnm_rxmer,
            'pnm_spectrum': self._handle_pnm_spectrum,
            'pnm_fec': self._handle_pnm_fec,
            'pnm_pre_eq': self._handle_pnm_pre_eq,

            # REMOVED: pnm_channel_stats - parsing now done in API, agent only does SNMP walks
            # Temporarily disabled until these handlers are restored:
            # 'pnm_event_log': self._handle_pnm_event_log,
            # 'pnm_ofdm_capture': self._handle_pnm_ofdm_capture,
            # 'pnm_ofdm_rxmer': self._handle_pnm_ofdm_rxmer,
            # 'pnm_set_tftp': self._handle_pnm_set_tftp,
            # 'pnm_utsc_configure': self._handle_pnm_utsc_configure,
            # 'pnm_utsc_start': self._handle_pnm_utsc_start,
            # 'pnm_utsc_stop': self._handle_pnm_utsc_stop,
            # 'pnm_utsc_status': self._handle_pnm_utsc_status,
            # 'pnm_utsc_data': self._handle_pnm_utsc_data,
            # 'pnm_us_rxmer_start': self._handle_pnm_us_rxmer_start,
            # 'pnm_us_rxmer_status': self._handle_pnm_us_rxmer_status,
            # 'pnm_us_rxmer_data': self._handle_pnm_us_rxmer_data,
            # 'pnm_us_get_interfaces': self._handle_pnm_us_get_interfaces,
            # OFDM capture commands (downstream - on CM)
            # 'pnm_ofdm_channels': self._handle_pnm_ofdm_channels,  # REMOVED - handler deleted
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
        caps.extend(['pnm_event_log'])
        
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
        target_ip = params.get('target_ip') or params.get('modem_ip')
        if not target_ip:
            return {'success': False, 'error': 'target_ip or modem_ip required'}
        oid = params['oid']
        community = params.get('community', 'private')
        
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        return asyncio.run(self._async_snmp_get(target_ip, oid, community, params.get('timeout', 5)))
    
    def _handle_snmp_walk(self, params: dict) -> dict:
        """Handle SNMP WALK request via pysnmp."""
        target_ip = params.get('target_ip') or params.get('modem_ip')
        if not target_ip:
            return {'success': False, 'error': 'target_ip or modem_ip required'}
        oid = params['oid']
        community = params.get('community', 'private')
        
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        return asyncio.run(self._async_snmp_walk(target_ip, oid, community, params.get('timeout', 10)))
    
    def _handle_snmp_set(self, params: dict) -> dict:
        """Handle SNMP SET request via pysnmp."""
        target_ip = params.get('target_ip') or params.get('modem_ip')
        if not target_ip:
            return {'success': False, 'error': 'target_ip or modem_ip required'}
        oid = params['oid']
        value = params['value']
        value_type = params.get('type', 'i')
        community = params.get('community', 'private')
        
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        return asyncio.run(self._async_snmp_set(target_ip, oid, value, value_type, community, params.get('timeout', 5)))
    
    def _handle_snmp_bulk_get(self, params: dict) -> dict:
        """Handle multiple SNMP GET requests with controlled concurrency."""
        oids = params.get('oids', [])
        target_ip = params.get('target_ip') or params.get('modem_ip')
        if not target_ip:
            return {'success': False, 'error': 'target_ip or modem_ip required'}
        community = params.get('community', 'private')
        timeout = params.get('timeout', 5)
        # Limit concurrent SNMP requests to avoid overwhelming the modem
        max_concurrent = params.get('max_concurrent', 10)
        
        # Use pysnmp
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        # Run SNMP GETs with concurrency limit using semaphore
        async def fetch_all():
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def fetch_with_semaphore(oid):
                async with semaphore:
                    return await self._async_snmp_get(target_ip, oid, community, timeout)
            
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
    
    def _handle_snmp_parallel_walk(self, params: dict) -> dict:
        """Handle parallel SNMP BULK WALK for multiple OID trees concurrently."""
        ip = params.get('ip')
        oids = params.get('oids', [])
        community = params.get('community', 'public')
        timeout = params.get('timeout', 10)
        
        if not ip or not oids:
            return {'success': False, 'error': 'ip and oids required'}
        
        self.logger.info(f"SNMP parallel walk: {ip} - {len(oids)} OIDs")
        
        result = self._snmp_parallel_walk(ip, oids, community, timeout)
        
        self.logger.info(f"Parallel walk completed: {len(result.get('results', {}))} OID trees")
        
        return result
    
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
                                      oid_old_status: str, oid_d31_freq: str, oid_old_us_ch_if: str = None) -> dict:
        """Async CMTS modem discovery using pysnmp with parallel walks."""
        import asyncio
        
        async def bulk_walk_oid(oid: str, timeout: int = 30, max_results: int = 10000) -> list:
            """Walk a single OID and return list of (index, value) tuples."""
            results = []
            if not oid:
                return results
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
                        if len(results) >= max_results:
                            return results
            except Exception as e:
                self.logger.debug(f"Bulk walk {oid} failed: {e}")
            return results
        
        # OIDs for upstream channel mapping
        OID_US_CH_ID = '1.3.6.1.4.1.4491.2.1.20.1.4.1.3'     # docsIf3CmtsCmUsStatusChIfIndex (US channel)
        OID_SW_REV = '1.3.6.1.2.1.10.127.1.2.2.1.3'  # docsIfCmtsCmStatusValue (firmware/software revision)
        OID_IF_NAME = '1.3.6.1.2.1.31.1.1.1.1'  # IF-MIB::ifName
        
        # Run essential walks in parallel (skip slow MD-IF-INDEX and fiber node queries)
        mac_task = asyncio.create_task(bulk_walk_oid(oid_d3_mac))
        old_mac_task = asyncio.create_task(bulk_walk_oid(oid_old_mac))
        old_ip_task = asyncio.create_task(bulk_walk_oid(oid_old_ip))
        old_status_task = asyncio.create_task(bulk_walk_oid(oid_old_status))
        d31_freq_task = asyncio.create_task(bulk_walk_oid(oid_d31_freq))
        us_ch_task = asyncio.create_task(bulk_walk_oid(OID_US_CH_ID))
        sw_rev_task = asyncio.create_task(bulk_walk_oid(OID_SW_REV))
        old_us_ch_if_task = asyncio.create_task(bulk_walk_oid(oid_old_us_ch_if))  # D3.0 upstream channel ifIndex
        if_name_task = asyncio.create_task(bulk_walk_oid(OID_IF_NAME, timeout=15))  # Interface names
        
        mac_results, old_mac_results, old_ip_results, old_status_results, d31_freq_results, us_ch_results, sw_rev_results, old_us_ch_if_results, if_name_results = await asyncio.gather(
            mac_task, old_mac_task, old_ip_task, old_status_task, d31_freq_task, us_ch_task, sw_rev_task, old_us_ch_if_task, if_name_task
        )
        
        self.logger.info(f"Raw SNMP results: mac={len(mac_results)}, old_mac={len(old_mac_results)}, old_us_ch_if={len(old_us_ch_if_results)}, if_name={len(if_name_results)}")
        self.logger.info(f"Queried OID_OLD_US_CH_IF: {oid_old_us_ch_if}")
        if old_us_ch_if_results:
            self.logger.info(f"old_us_ch_if sample: {old_us_ch_if_results[:3]}")
        else:
            self.logger.warning(f"old_us_ch_if_results is EMPTY - CMTS may not support this OID")
        
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
        
        # Skip slow MD-IF-INDEX and OFDMA queries for fast response
        # These can be fetched later via enrichment if needed
        md_if_map = {}
        ofdma_if_map = {}
        ofdma_descr_map = {}
        
        # Build ifName map from IF-MIB::ifName walk
        if_name_map = {}  # ifindex -> interface name
        for index, value in if_name_results:
            name = str(value)
            if name and 'No Such' not in name:
                try:
                    if_name_map[int(index)] = name
                except:
                    pass
        self.logger.info(f"Resolved {len(if_name_map)} interface names")
        
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
        
        # Build US channel mapping from docsIf3CmtsCmUsStatusChIfIndex
        # OID structure: .3.{cmRegStatusId}.{usChIfIndex} -> value is the ifIndex
        # But the INDEX already contains the usChIfIndex, so extract from index, not value!
        us_ch_map = {}  # modem_index -> us_channel_ifindex
        for index, value in us_ch_results:
            try:
                # US channel OID has compound index: {modem_index}.{channel_ifindex}
                # The channel_ifindex in the INDEX is what we want!
                parts = index.split('.')
                if len(parts) >= 2:
                    modem_index = parts[0]
                    channel_ifindex = int(parts[1])  # This is the upstream ifIndex
                    # Store the first (or lowest) channel ifindex per modem
                    if modem_index not in us_ch_map or channel_ifindex < us_ch_map[modem_index]:
                        us_ch_map[modem_index] = channel_ifindex
            except:
                pass
        
        if us_ch_results:
            self.logger.info(f"us_ch_results sample raw: {us_ch_results[:3]}")
        
        # Build D3.0 upstream channel ifIndex mapping (from old table)
        old_us_ch_if_map = {}  # old_index -> upstream_ifindex
        self.logger.info(f"Processing {len(old_us_ch_if_results)} old_us_ch_if_results")
        for index, value in old_us_ch_if_results:
            try:
                ifindex = int(value)
                if ifindex > 0:
                    old_us_ch_if_map[index] = ifindex
            except Exception as e:
                self.logger.debug(f"Failed to parse US ch ifIndex {index}={value}: {e}")
        
        self.logger.info(f"Correlated {len(old_us_ch_if_map)} D3.0 upstream channel ifIndexes")
        if old_us_ch_if_map:
            self.logger.info(f"US ch ifIndex sample: {list(old_us_ch_if_map.items())[:5]}")
        else:
            self.logger.warning(f"No D3.0 upstream channel ifIndexes found - sample raw: {old_us_ch_if_results[:3] if old_us_ch_if_results else 'empty'}")
        if old_mac_map:
            self.logger.info(f"Old MAC map sample: {list(old_mac_map.items())[:5]}")
        self.logger.info(f"Correlated {len(us_ch_map)} US channel mappings")
        if us_ch_map:
            self.logger.info(f"US channel sample keys: {list(us_ch_map.keys())[:5]}")
        self.logger.info(f"MAC map sample keys: {list(mac_map.keys())[:5]}")
        
        # Create MAC -> IP and MAC -> status lookups
        mac_to_ip = {}
        mac_to_status = {}
        mac_to_firmware = {}
        mac_to_us_ch_if = {}  # D3.0 upstream channel ifIndex
        for old_index, mac in old_mac_map.items():
            if old_index in old_ip_map:
                mac_to_ip[mac] = old_ip_map[old_index]
            if old_index in old_status_map:
                mac_to_status[mac] = old_status_map[old_index]
            if old_index in sw_rev_map:
                mac_to_firmware[mac] = sw_rev_map[old_index]
            if old_index in old_us_ch_if_map:
                mac_to_us_ch_if[mac] = old_us_ch_if_map[old_index]
        
        self.logger.info(f"Correlated {len(mac_to_ip)} IP addresses from old table (pysnmp)")
        self.logger.info(f"Correlated {len(mac_to_status)} status values from old table (pysnmp)")
        self.logger.info(f"Correlated {len(mac_to_firmware)} firmware versions from old table (pysnmp)")
        self.logger.info(f"Correlated {len(mac_to_us_ch_if)} D3.0 upstream ifIndexes from old table")
        
        # Status code mapping (docsIfCmtsCmStatusValue - old MIB)
        # Note: registrationComplete(6) is the final state for modems without BPI encryption
        # We map it to 'operational' for display since it means the modem is fully online
        STATUS_MAP = {
            1: 'other', 2: 'ranging', 3: 'rangingAborted', 4: 'rangingComplete',
            5: 'ipComplete', 6: 'operational', 7: 'accessDenied',  # 6=registrationComplete -> operational
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
            
            # Add OFDMA upstream interface if available
            if index in ofdma_if_map:
                ofdma_ifindex = ofdma_if_map[index]
                modem['ofdma_ifindex'] = ofdma_ifindex
                if ofdma_ifindex in ofdma_descr_map:
                    modem['upstream_interface'] = ofdma_descr_map[ofdma_ifindex]
                else:
                    modem['upstream_interface'] = f"ofdmaIfIndex.{ofdma_ifindex}"
            else:
                # No OFDMA: show SC-QAM upstream channel (D3.0 or D3.1 on SC-QAM)
                us_ifindex = None
                # Try old table first (docsIfCmtsCmStatusUpChannelIfIndex)
                if mac in mac_to_us_ch_if:
                    us_ifindex = mac_to_us_ch_if[mac]
                # Fallback to docsIf3 table (docsIf3CmtsCmUsStatusChIfIndex) - works for Cisco
                elif index in us_ch_map:
                    us_ifindex = us_ch_map[index]
                
                if us_ifindex:
                    modem['upstream_ifindex'] = us_ifindex
                    # Resolve ifIndex to interface name
                    if us_ifindex in if_name_map:
                        modem['upstream_interface'] = if_name_map[us_ifindex]
                    else:
                        modem['upstream_interface'] = f"US-CH {us_ifindex}"
                else:
                    modem['upstream_interface'] = "SC-QAM"
            
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

    async def _async_enrich_cmts_interfaces(self, cmts_ip: str, community: str, modems: list):
        """Background enrichment: Add cable-mac and upstream interface to modems. FAST version using bulk walks."""
        from pysnmp.hlapi.v3arch.asyncio import bulk_cmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
        
        self.logger.info(f"Enriching cable-mac/upstream for {len(modems)} modems from CMTS {cmts_ip}")
        
        # Build index -> modem map
        index_to_modem = {str(m.get('cmts_index')): m for m in modems if m.get('cmts_index')}
        modem_indexes = set(index_to_modem.keys())
        
        if not modem_indexes:
            self.logger.warning("No modem indexes to enrich")
            return
        
        # Helper: Bulk walk an OID tree
        async def bulk_walk_oid(oid, max_results=5000):
            results = []
            try:
                engine = SnmpEngine()
                target = await UdpTransportTarget.create((cmts_ip, 161), timeout=5, retries=1)
                next_oid = oid
                while len(results) < max_results:
                    errorIndication, errorStatus, errorIndex, varBinds = await bulk_cmd(
                        engine, CommunityData(community), target, ContextData(),
                        0, 100, ObjectType(ObjectIdentity(next_oid))  # 100 vars per request
                    )
                    if errorIndication or errorStatus:
                        break
                    if not varBinds:
                        break
                    for varBind in varBinds:
                        oid_str = str(varBind[0])
                        if not oid_str.startswith(oid):
                            return results
                        index = oid_str[len(oid)+1:]
                        results.append((index, varBind[1]))
                        next_oid = oid_str
            except Exception as e:
                self.logger.debug(f"Bulk walk {oid} error: {e}")
            return results
        
        # Helper: Single SNMP GET
        async def snmp_get(oid):
            from pysnmp.hlapi.v3arch.asyncio import get_cmd
            try:
                engine = SnmpEngine()
                target = await UdpTransportTarget.create((cmts_ip, 161), timeout=3, retries=1)
                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                    engine, CommunityData(community), target, ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                if errorIndication or errorStatus:
                    return None
                if varBinds:
                    value = str(varBinds[0][1])
                    if value and 'No Such' not in value:
                        return value
            except Exception as e:
                self.logger.debug(f"SNMP GET {oid} error: {e}")
            return None
        
        # OIDs
        OID_MD_IF_INDEX = '1.3.6.1.4.1.4491.2.1.20.1.3.1.7'  # docsIf3CmtsCmRegStatusMdIfIndex
        OID_IF_NAME = '1.3.6.1.2.1.31.1.1.1.1'  # IF-MIB::ifName
        OID_CM_OFDMA_TIMING = '1.3.6.1.4.1.4491.2.1.28.1.4.1.2'  # OFDMA timing offset
        OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2'  # IF-MIB::ifDescr
        
        # Run all bulk walks in parallel
        md_if_task = bulk_walk_oid(OID_MD_IF_INDEX)
        if_name_task = bulk_walk_oid(OID_IF_NAME, max_results=500)  # Only ~200 interfaces
        ofdma_task = bulk_walk_oid(OID_CM_OFDMA_TIMING)
        
        md_if_results, if_name_results, ofdma_results = await asyncio.gather(
            md_if_task, if_name_task, ofdma_task
        )
        
        # Parse MD-IF-INDEX: modem_index -> md_if_index
        md_if_map = {}
        for index, value in md_if_results:
            if index in modem_indexes:
                try:
                    md_if_map[index] = int(value)
                except:
                    pass
        
        # Parse IF-MIB::ifName: ifindex -> name
        if_name_map = {}
        for index, value in if_name_results:
            name = str(value)
            if name and 'No Such' not in name:
                try:
                    if_name_map[int(index)] = name
                except:
                    pass
        
        self.logger.info(f"Resolved {len(md_if_map)} MD-IF-INDEX, {len(if_name_map)} interface names")
        
        # Parse OFDMA: modem_index -> ofdma_ifindex
        ofdma_if_map = {}
        ofdma_ifindexes = set()
        for index, value in ofdma_results:
            try:
                parts = index.split('.')
                if len(parts) >= 2:
                    cm_idx = parts[0]
                    ofdma_ifidx = int(parts[1])
                    if cm_idx in modem_indexes and ofdma_ifidx >= 840000000:
                        ofdma_if_map[cm_idx] = ofdma_ifidx
                        ofdma_ifindexes.add(ofdma_ifidx)
            except:
                pass
        
        self.logger.info(f"Discovered {len(ofdma_if_map)} OFDMA upstream interfaces")
        
        # Get OFDMA interface descriptions (these are high ifIndexes not in bulk walk)
        ofdma_descr_map = {}
        if ofdma_ifindexes:
            # Bulk walk ifDescr for OFDMA interfaces (high ifIndexes)
            if_descr_results = await bulk_walk_oid(OID_IF_DESCR, max_results=2000)
            for index, value in if_descr_results:
                try:
                    ifidx = int(index)
                    if ifidx in ofdma_ifindexes:
                        descr = str(value)
                        if descr and 'No Such' not in descr:
                            ofdma_descr_map[ifidx] = descr
                except:
                    pass
            self.logger.info(f"Resolved {len(ofdma_descr_map)} OFDMA interface descriptions")
        
        # Apply to modems
        enriched_count = 0
        us_ch_resolved = 0
        for modem in modems:
            idx = str(modem.get('cmts_index'))
            if not idx:
                continue
            
            # Add cable_mac from MD-IF-INDEX -> ifName
            if idx in md_if_map:
                md_if_idx = md_if_map[idx]
                if md_if_idx in if_name_map:
                    modem['cable_mac'] = if_name_map[md_if_idx]
                    enriched_count += 1
            
            # Add OFDMA upstream interface if discovered
            if idx in ofdma_if_map:
                ofdma_ifidx = ofdma_if_map[idx]
                modem['ofdma_ifindex'] = ofdma_ifidx
                if ofdma_ifidx in ofdma_descr_map:
                    modem['upstream_interface'] = ofdma_descr_map[ofdma_ifidx]
            else:
                # Collect SC-QAM US-CH ifIndexes for later resolution
                us_ifidx = modem.get('upstream_ifindex')
                if us_ifidx and us_ifidx in if_name_map:
                    modem['upstream_interface'] = if_name_map[us_ifidx]
                    us_ch_resolved += 1
        
        # Resolve remaining US-CH ifIndexes with targeted SNMP GETs
        # Collect unique ifIndexes that weren't resolved
        unresolved_ifindexes = set()
        for modem in modems:
            us_ifidx = modem.get('upstream_ifindex')
            if us_ifidx and modem.get('upstream_interface', '').startswith('US-CH'):
                unresolved_ifindexes.add(us_ifidx)
        
        if unresolved_ifindexes:
            self.logger.info(f"Resolving {len(unresolved_ifindexes)} unresolved upstream ifIndexes with SNMP GET")
            OID_IF_NAME_BASE = '1.3.6.1.2.1.31.1.1.1.1'
            for ifidx in unresolved_ifindexes:
                try:
                    result = await snmp_get(f"{OID_IF_NAME_BASE}.{ifidx}")
                    if result:
                        if_name_map[ifidx] = result
                except Exception as e:
                    self.logger.debug(f"Failed to resolve ifName for {ifidx}: {e}")
            
            # Apply resolved names
            for modem in modems:
                us_ifidx = modem.get('upstream_ifindex')
                if us_ifidx and us_ifidx in if_name_map:
                    if modem.get('upstream_interface', '').startswith('US-CH'):
                        modem['upstream_interface'] = if_name_map[us_ifidx]
                        us_ch_resolved += 1
        
        self.logger.info(f"Enriched {enriched_count} modems with cable-mac, {us_ch_resolved} SC-QAM upstreams resolved")

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



