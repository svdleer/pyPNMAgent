#!/usr/bin/env python3
# PyPNM Agent - SSH Tunnel Manager
# SPDX-License-Identifier: Apache-2.0
#
# Manages SSH tunnels for the PyPNM Agent:
# - Tunnel to GUI Server for WebSocket connection
# - SSH connection to SNMP Proxy for command execution

import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Optional

try:
    import paramiko
except ImportError:
    paramiko = None
    print("WARNING: paramiko not installed. Install with: pip install paramiko")

logger = logging.getLogger(__name__)


@dataclass
class SSHTunnelConfig:
    """SSH tunnel configuration."""
    # SSH target (the server we SSH into)
    ssh_host: str
    ssh_port: int = 22
    ssh_user: str = ""
    ssh_key_file: Optional[str] = None
    ssh_password: Optional[str] = None  # Not recommended, use keys
    
    # Local tunnel endpoint (what we bind locally)
    local_host: str = "127.0.0.1"
    local_port: int = 5050
    
    # Remote endpoint (where tunnel connects to on remote side)
    remote_host: str = "127.0.0.1"
    remote_port: int = 5050
    
    # Tunnel options
    keepalive_interval: int = 30
    keepalive_count_max: int = 3
    auto_reconnect: bool = True
    reconnect_delay: int = 5


class SSHTunnelManager:
    """
    Manages SSH tunnels using either subprocess (ssh command) or paramiko.
    
    Supports two modes:
    1. Local port forwarding (-L): Access remote service via local port
    2. Command execution: Run commands on remote server
    """
    
    def __init__(self, config: SSHTunnelConfig, use_paramiko: bool = True):
        self.config = config
        self.use_paramiko = use_paramiko and paramiko is not None
        self.logger = logging.getLogger(f'{__name__}.SSHTunnel')
        
        self._tunnel_process: Optional[subprocess.Popen] = None
        self._paramiko_client: Optional[paramiko.SSHClient] = None
        self._paramiko_transport: Optional[paramiko.Transport] = None
        self._running = False
        self._tunnel_thread: Optional[threading.Thread] = None
    
    def start_tunnel(self) -> bool:
        """Start the SSH tunnel."""
        if self.use_paramiko:
            return self._start_paramiko_tunnel()
        else:
            return self._start_subprocess_tunnel()
    
    def _start_subprocess_tunnel(self) -> bool:
        """Start tunnel using ssh subprocess."""
        ssh_cmd = [
            'ssh', '-N',  # No command, just tunnel
            '-L', f'{self.config.local_port}:{self.config.remote_host}:{self.config.remote_port}',
            '-o', f'ServerAliveInterval={self.config.keepalive_interval}',
            '-o', f'ServerAliveCountMax={self.config.keepalive_count_max}',
            '-o', 'ExitOnForwardFailure=yes',
            '-o', 'StrictHostKeyChecking=accept-new',
        ]
        
        if self.config.ssh_key_file:
            ssh_cmd.extend(['-i', self.config.ssh_key_file])
        
        if self.config.ssh_port != 22:
            ssh_cmd.extend(['-p', str(self.config.ssh_port)])
        
        ssh_target = f'{self.config.ssh_user}@{self.config.ssh_host}' if self.config.ssh_user else self.config.ssh_host
        ssh_cmd.append(ssh_target)
        
        self.logger.info(f"Starting SSH tunnel: {' '.join(ssh_cmd)}")
        
        try:
            self._tunnel_process = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Give it a moment to establish
            time.sleep(2)
            
            if self._tunnel_process.poll() is not None:
                # Process exited
                stderr = self._tunnel_process.stderr.read().decode()
                self.logger.error(f"SSH tunnel failed to start: {stderr}")
                return False
            
            self.logger.info(f"SSH tunnel established: localhost:{self.config.local_port} → {self.config.ssh_host}:{self.config.remote_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start SSH tunnel: {e}")
            return False
    
    def _start_paramiko_tunnel(self) -> bool:
        """Start tunnel using paramiko."""
        if not paramiko:
            self.logger.error("paramiko not available")
            return False
        
        try:
            self._paramiko_client = paramiko.SSHClient()
            self._paramiko_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.config.ssh_host,
                'port': self.config.ssh_port,
                'username': self.config.ssh_user,
            }
            
            if self.config.ssh_key_file:
                connect_kwargs['key_filename'] = self.config.ssh_key_file
            elif self.config.ssh_password:
                connect_kwargs['password'] = self.config.ssh_password
            
            self._paramiko_client.connect(**connect_kwargs)
            
            # Get transport for port forwarding
            self._paramiko_transport = self._paramiko_client.get_transport()
            self._paramiko_transport.set_keepalive(self.config.keepalive_interval)
            
            # Start local port forwarding in background thread
            self._running = True
            self._tunnel_thread = threading.Thread(
                target=self._paramiko_forward_tunnel,
                daemon=True
            )
            self._tunnel_thread.start()
            
            self.logger.info(f"SSH tunnel established via paramiko: localhost:{self.config.local_port} → {self.config.remote_host}:{self.config.remote_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start paramiko tunnel: {e}")
            return False
    
    def _paramiko_forward_tunnel(self):
        """Handle paramiko port forwarding (runs in thread)."""
        import socket
        import select
        
        # Create local listening socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.config.local_host, self.config.local_port))
        server_socket.listen(5)
        server_socket.settimeout(1.0)
        
        self.logger.info(f"Listening on {self.config.local_host}:{self.config.local_port}")
        
        while self._running:
            try:
                client_socket, addr = server_socket.accept()
                self.logger.debug(f"Connection from {addr}")
                
                # Open channel to remote
                channel = self._paramiko_transport.open_channel(
                    'direct-tcpip',
                    (self.config.remote_host, self.config.remote_port),
                    addr
                )
                
                if channel is None:
                    self.logger.error("Failed to open channel")
                    client_socket.close()
                    continue
                
                # Start forwarding thread
                threading.Thread(
                    target=self._forward_data,
                    args=(client_socket, channel),
                    daemon=True
                ).start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    self.logger.error(f"Tunnel error: {e}")
                break
        
        server_socket.close()
    
    def _forward_data(self, local_socket, remote_channel):
        """Forward data between local socket and remote channel."""
        import select
        
        try:
            while True:
                r, w, x = select.select([local_socket, remote_channel], [], [], 1.0)
                
                if local_socket in r:
                    data = local_socket.recv(4096)
                    if not data:
                        break
                    remote_channel.sendall(data)
                
                if remote_channel in r:
                    data = remote_channel.recv(4096)
                    if not data:
                        break
                    local_socket.sendall(data)
        except Exception as e:
            self.logger.debug(f"Forward ended: {e}")
        finally:
            local_socket.close()
            remote_channel.close()
    
    def stop_tunnel(self):
        """Stop the SSH tunnel."""
        self._running = False
        
        if self._tunnel_process:
            self._tunnel_process.terminate()
            self._tunnel_process.wait()
            self._tunnel_process = None
        
        if self._paramiko_client:
            self._paramiko_client.close()
            self._paramiko_client = None
            self._paramiko_transport = None
        
        self.logger.info("SSH tunnel stopped")
    
    def is_alive(self) -> bool:
        """Check if tunnel is still running."""
        if self._tunnel_process:
            return self._tunnel_process.poll() is None
        if self._paramiko_transport:
            return self._paramiko_transport.is_active()
        return False
    
    def execute_command(self, command: str, timeout: int = 30) -> tuple[int, str, str]:
        """Execute command on remote server (not through tunnel, direct SSH)."""
        if self.use_paramiko and self._paramiko_client:
            try:
                stdin, stdout, stderr = self._paramiko_client.exec_command(command, timeout=timeout)
                exit_code = stdout.channel.recv_exit_status()
                return exit_code, stdout.read().decode(), stderr.read().decode()
            except Exception as e:
                return -1, "", str(e)
        else:
            # Use subprocess
            ssh_cmd = ['ssh']
            
            if self.config.ssh_key_file:
                ssh_cmd.extend(['-i', self.config.ssh_key_file])
            if self.config.ssh_port != 22:
                ssh_cmd.extend(['-p', str(self.config.ssh_port)])
            
            ssh_target = f'{self.config.ssh_user}@{self.config.ssh_host}' if self.config.ssh_user else self.config.ssh_host
            ssh_cmd.extend([ssh_target, command])
            
            try:
                result = subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired:
                return -1, "", "Command timed out"
            except Exception as e:
                return -1, "", str(e)


class TunnelMonitor:
    """Monitors and auto-restarts SSH tunnels."""
    
    def __init__(self, tunnel: SSHTunnelManager):
        self.tunnel = tunnel
        self.logger = logging.getLogger(f'{__name__}.TunnelMonitor')
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start monitoring tunnel."""
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Monitor tunnel and restart if needed."""
        while self._running:
            if not self.tunnel.is_alive():
                self.logger.warning("Tunnel down, attempting restart...")
                self.tunnel.stop_tunnel()
                time.sleep(self.tunnel.config.reconnect_delay)
                
                if self.tunnel.start_tunnel():
                    self.logger.info("Tunnel restarted successfully")
                else:
                    self.logger.error("Tunnel restart failed")
            
            time.sleep(5)


# Convenience function for creating GUI server tunnel
def create_gui_tunnel(
    gui_ssh_host: str,
    gui_ssh_user: str,
    gui_ssh_key: str = None,
    gui_port: int = 5050,
    local_port: int = 5050
) -> SSHTunnelManager:
    """Create tunnel to GUI Server for WebSocket connection."""
    config = SSHTunnelConfig(
        ssh_host=gui_ssh_host,
        ssh_user=gui_ssh_user,
        ssh_key_file=gui_ssh_key,
        local_port=local_port,
        remote_port=gui_port,
    )
    return SSHTunnelManager(config)


# Convenience function for SNMP proxy connection
def create_snmp_proxy_connection(
    proxy_host: str,
    proxy_user: str,
    proxy_key: str = None
) -> SSHTunnelManager:
    """Create SSH connection to SNMP proxy for command execution."""
    config = SSHTunnelConfig(
        ssh_host=proxy_host,
        ssh_user=proxy_user,
        ssh_key_file=proxy_key,
        local_port=0,  # Not used for command execution
        remote_port=0,
    )
    return SSHTunnelManager(config, use_paramiko=True)


if __name__ == '__main__':
    # Test tunnel creation
    import argparse
    
    parser = argparse.ArgumentParser(description='SSH Tunnel Manager')
    parser.add_argument('--host', required=True, help='SSH host')
    parser.add_argument('--user', required=True, help='SSH user')
    parser.add_argument('--key', help='SSH key file')
    parser.add_argument('--local-port', type=int, default=5050, help='Local port')
    parser.add_argument('--remote-port', type=int, default=5050, help='Remote port')
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.DEBUG)
    
    config = SSHTunnelConfig(
        ssh_host=args.host,
        ssh_user=args.user,
        ssh_key_file=args.key,
        local_port=args.local_port,
        remote_port=args.remote_port,
    )
    
    tunnel = SSHTunnelManager(config, use_paramiko=False)  # Use subprocess for testing
    
    if tunnel.start_tunnel():
        print(f"Tunnel active: localhost:{args.local_port} → {args.host}:{args.remote_port}")
        print("Press Ctrl+C to stop...")
        try:
            while tunnel.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            tunnel.stop_tunnel()
    else:
        print("Failed to start tunnel")
