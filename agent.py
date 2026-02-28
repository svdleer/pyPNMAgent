# PyPNM Jump Server Agent
# SPDX-License-Identifier: Apache-2.0
# 
# This agent runs on the Jump Server and connects OUT to the GUI Server
# via WebSocket. It executes SNMP/SSH commands and returns results.

from __future__ import annotations  # enables PEP 604/585 syntax on Python 3.8/3.9

import json
import logging
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
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
        
        server_config = data.get('pypnm_server') or data.get('gui_server', {})
        tunnel_config = data.get('pypnm_ssh_tunnel') or data.get('gui_ssh_tunnel', {})
        cmts = data.get('cmts_access', {})
        cm_access = data.get('cm_access', {})
        cm_proxy = cm_access.get('proxy', {}) or data.get('cm_proxy', {})
        cm_direct = data.get('cm_direct', {})
        cm_enabled = cm_access.get('enabled', cm_direct.get('enabled', False))
        cm_community = cm_access.get('community', cm_direct.get('community', ''))
        
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
            cmts_enabled=cmts.get('enabled', cmts.get('snmp_direct', True)),
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
            pypnm_server_url=os.environ.get('PYPNM_SERVER_URL', 'ws://127.0.0.1:8000/api/agents/ws'),
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
        
        self._executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix='snmp')
        
        # SSH Tunnel
        self.pypnm_tunnel = None
        self.pypnm_tunnel_monitor = None
        
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
            'snmp_bulk_get': self._handle_snmp_bulk_get,
            'snmp_bulk_walk': self._handle_snmp_bulk_walk,
            'snmp_parallel_walk': self._handle_snmp_parallel_walk,
            'tftp_get': self._handle_tftp_get,
            'cmts_command': self._handle_cmts_command,
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
            
            # Auto-reconnect monitor
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
            return f"ws://127.0.0.1:{self.config.pypnm_tunnel_local_port}/api/agents/ws"
        else:
            return self.config.pypnm_server_url
    
    def _on_open(self, ws):
        """Called when WebSocket connection is established."""
        ws_url = self._get_websocket_url()
        self.logger.info(f"Connected to PyPNM Server: {ws_url}")
        
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
        """Return list of agent capabilities."""
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
            caps.append('cmts_snmp_direct')
            caps.append('snmp_parallel_walk')
        
        if self.config.cmts_ssh_enabled:
            caps.append('cmts_command')  # Can execute CMTS CLI commands via SSH
        
        if self.tftp_ssh:
            caps.append('tftp_get')
        
        # CMTS capabilities - agent provides SNMP walks, PyPNM API handles logic
        if self.config.cmts_enabled:
            caps.extend(['cmts_snmp_walk', 'cmts_snmp_get'])
        
        return caps
    
    def _handle_command(self, ws, data: dict):
        """Dispatch command to thread pool for concurrent execution."""
        request_id = data.get('request_id')
        command = data.get('command')
        params = data.get('params', {})
        
        self.logger.info(f"Received command: {request_id} - {command}")
        
        handler = self.handlers.get(command)
        if not handler:
            response = {
                'type': 'error',
                'request_id': request_id,
                'error': f'Unknown command: {command}'
            }
            ws.send(json.dumps(response))
            return
        
        def _run_handler():
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
            try:
                ws.send(json.dumps(response))
                self.logger.info(f"Response sent for {request_id}")
            except Exception as e:
                self.logger.error(f"Failed to send response for {request_id}: {e}")
        
        self._executor.submit(_run_handler)
    
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
        """Walk multiple OID trees concurrently via asyncio."""
        ip = params.get('ip')
        oids = params.get('oids', [])
        community = params.get('community', 'public')
        timeout = params.get('timeout', 5)          # 5 s per packet
        max_reps = params.get('max_repetitions', 500)  # 12k modems / 500 = 24 PDUs per tree
        
        if not ip or not oids:
            return {'success': False, 'error': 'ip and oids required'}
        
        if not PYSNMP_AVAILABLE:
            return {'success': False, 'error': 'pysnmp not available'}
        
        self.logger.info(f"SNMP parallel walk: {ip} - {len(oids)} OIDs")
        
        async def do_parallel_walk():
            async def walk_one(oid):
                transport = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=1)
                results = []
                async for (errorIndication, errorStatus, errorIndex, varBinds) in bulk_walk_cmd(
                    SnmpEngine(), CommunityData(community), transport, ContextData(),
                    0, max_reps, ObjectType(ObjectIdentity(oid))
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
            
            results_list = await asyncio.gather(*[walk_one(oid) for oid in oids])
            all_results = dict(zip(oids, results_list))
            return {'success': any(len(v) > 0 for v in all_results.values()), 'results': all_results}
        
        try:
            result = asyncio.run(do_parallel_walk())
            self.logger.info(f"Parallel walk completed: {len(result.get('results', {}))} OID trees")
            return result
        except Exception as e:
            self.logger.error(f"SNMP parallel walk error: {e}")
            return {'success': False, 'error': str(e)}
    
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
            
            output_lines = []
            for varBind in varBinds:
                output_lines.append(f"{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}")
            
            return {'success': True, 'output': '\n'.join(output_lines)}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _async_snmp_walk(self, target_ip: str, oid: str, community: str, timeout: int = 10) -> dict:
        """Async SNMP WALK using pysnmp."""
        try:
            results = []
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
                    oid_str = str(varBind[0])
                    # Stop if we've walked past the requested OID tree
                    if not oid_str.startswith(oid):
                        break
                    results.append({
                        'oid': oid_str,
                        'value': self._parse_snmp_value(varBind[1]),
                        'type': type(varBind[1]).__name__
                    })
            
            return {'success': True, 'results': results}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _async_snmp_set(self, target_ip: str, oid: str, value: any, value_type: str, 
                               community: str, timeout: int = 5) -> dict:
        """Async SNMP SET using pysnmp."""
        try:
            snmp_value = self._to_snmp_value(value, value_type)
            
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                SnmpEngine(),
                CommunityData(community),
                await UdpTransportTarget.create((target_ip, 161), timeout=timeout, retries=2),
                ContextData(),
                ObjectType(ObjectIdentity(oid), snmp_value)
            )
            
            if errorIndication:
                return {'success': False, 'error': str(errorIndication)}
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
    
    
    def _parse_snmp_value(self, value) -> Any:
        """Parse pysnmp value to Python native type."""
        try:
            if value is None:
                return None
            
            type_name = type(value).__name__
            
            if type_name == 'OctetString':
                raw = bytes(value)
                try:
                    return raw.decode('utf-8').strip()
                except UnicodeDecodeError:
                    if len(raw) == 6:  # MAC address
                        return ':'.join(f'{b:02x}' for b in raw).upper()
                    return raw.hex()
            
            if type_name == 'IpAddress':
                if hasattr(value, 'prettyPrint'):
                    return value.prettyPrint()
                raw = bytes(value)
                if len(raw) == 4:
                    return '.'.join(str(b) for b in raw)
                return str(value)
            
            # Integer types — pysnmp v7 has quirks with int() conversion
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
                    on_close=self._on_close,
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
        if self.ws:
            self.ws.close()
        if self.cm_proxy:
            self.cm_proxy.close()
        if self.tftp_ssh:
            self.tftp_ssh.close()
        if self.pypnm_tunnel_monitor:
            self.pypnm_tunnel_monitor.stop()
        if self.pypnm_tunnel:
            self.pypnm_tunnel.stop_tunnel()
        self._executor.shutdown(wait=False)
        
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
    logger.info(f"PyPNM Server: {config.pypnm_server_url}")
    logger.info(f"SSH Tunnel: {'enabled' if config.pypnm_ssh_tunnel_enabled else 'disabled'}")
    if config.pypnm_ssh_tunnel_enabled:
        logger.info(f"  SSH Host: {config.pypnm_ssh_host}")
    logger.info(f"CM Proxy: {config.cm_proxy_host or 'not configured'}")
    logger.info(f"CMTS SNMP Direct: {config.cmts_enabled}")
    logger.info(f"TFTP SSH: {config.tftp_ssh_host or 'not configured'}")
    
    agent = PyPNMAgent(config)
    
    try:
        agent.connect()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        agent.stop()


if __name__ == '__main__':
    main()
