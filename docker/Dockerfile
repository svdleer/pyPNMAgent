# PyPNM Remote Agent Dockerfile
# SPDX-License-Identifier: Apache-2.0
#
# This runs the agent that connects TO the PyPNM server.
# Deploy this container on a host with network access to:
# - PyPNM Server (via SSH tunnel or direct)
# - CM Proxy / SNMP target servers
# - CMTS systems
# - TFTP server

FROM python:3.11-slim

LABEL maintainer="PyPNM Team"
LABEL description="PyPNM Remote Agent for Jump Server deployment"

# Install system dependencies (SSH client, SNMP tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    snmp \
    iputils-ping \
    curl \
    netcat-openbsd \
    tzdata \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Set timezone
ENV TZ=Europe/Amsterdam
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Enable MIBs (snmp-mibs-downloader not available in Debian Trixie)
RUN sed -i 's/^mibs :$/# mibs :/' /etc/snmp/snmp.conf 2>/dev/null || true

# Create app user (non-root)
RUN useradd -m -s /bin/bash -u 1000 pypnm

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent code
COPY agent.py ./
COPY ssh_tunnel.py ./

# Create directories
RUN mkdir -p /app/logs /home/pypnm/.ssh && \
    chown -R pypnm:pypnm /app /home/pypnm/.ssh && \
    chmod 700 /home/pypnm/.ssh

# Switch to non-root user
USER pypnm

# Environment variables (can be overridden)
ENV PYTHONUNBUFFERED=1
ENV PYPNM_AGENT_ID=docker-agent-01
ENV PYPNM_SERVER_URL=ws://pypnm:8080/api/agents/ws
ENV PYPNM_AUTH_TOKEN=change-me-in-production

# Volume for SSH keys and config
VOLUME ["/home/pypnm/.ssh", "/app/config"]

# Health check - verify process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f "python agent.py" || exit 1

# Default command
CMD ["python", "agent.py", "-c", "/app/config/agent_config.json"]
