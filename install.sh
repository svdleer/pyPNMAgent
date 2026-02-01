#!/bin/bash
# PyPNM Agent - Installation Script for Jump Server
# SPDX-License-Identifier: Apache-2.0
#
# This script installs the agent for a normal user (no root required)

set -e

INSTALL_DIR="${HOME}/.pypnm-agent"
VENV_DIR="${INSTALL_DIR}/venv"

echo "=========================================="
echo "  PyPNM Agent Installer (User Mode)"
echo "=========================================="
echo ""
echo "Installing to: $INSTALL_DIR"
echo ""

# Create installation directory
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"

# Copy agent files (assuming we're in the agent directory)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Copying agent files from $SCRIPT_DIR..."
cp "$SCRIPT_DIR/agent.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/ssh_tunnel.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/run_background.sh" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/run_in_tmux.sh" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/run_background.sh" "$INSTALL_DIR/run_in_tmux.sh"

# Copy example config if no config exists
if [ ! -f "$INSTALL_DIR/agent_config.json" ]; then
    cp "$SCRIPT_DIR/agent_config.example.json" "$INSTALL_DIR/agent_config.json"
    echo "Created default config at $INSTALL_DIR/agent_config.json"
fi

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Set permissions
chmod 600 "$INSTALL_DIR/agent_config.json"

# Create start script
cat > "$INSTALL_DIR/start.sh" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/venv/bin/activate"
cd "$SCRIPT_DIR"
exec python agent.py -c agent_config.json "$@"
EOF
chmod +x "$INSTALL_DIR/start.sh"

# Create user systemd service directory
mkdir -p "${HOME}/.config/systemd/user"

# Create systemd user service
cat > "${HOME}/.config/systemd/user/pypnm-agent.service" << EOF
[Unit]
Description=PyPNM Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/start.sh
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
EOF

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Set up SSH keys for each connection:"
echo ""
echo "   # For GUI Server tunnel:"
echo "   ssh-keygen -t ed25519 -f ~/.ssh/id_gui_server -N ''"
echo "   ssh-copy-id -i ~/.ssh/id_gui_server.pub user@gui-server"
echo ""
echo "   # For CM Proxy (modem connectivity):"
echo "   ssh-keygen -t ed25519 -f ~/.ssh/id_cm_proxy -N ''"
echo "   ssh-copy-id -i ~/.ssh/id_cm_proxy.pub user@cm-proxy-server"
echo ""
echo "   # (Repeat for CMTS and TFTP as needed)"
echo ""
echo "2. Edit the configuration:"
echo "   nano $INSTALL_DIR/agent_config.json"
echo ""
echo "3. Test the agent manually:"
echo "   $INSTALL_DIR/start.sh -v"
echo ""
echo "4. Run persistently (choose ONE method):"
echo ""
echo "   METHOD A - Simple background (recommended):"
echo "     $INSTALL_DIR/run_background.sh start"
echo "     $INSTALL_DIR/run_background.sh status"
echo "     $INSTALL_DIR/run_background.sh logs"
echo ""
echo "   METHOD B - tmux/screen session:"
echo "     $INSTALL_DIR/run_in_tmux.sh"
echo ""
echo "   METHOD C - Auto-start on reboot (crontab):"
echo "     crontab -e"
echo "     # Add: @reboot $INSTALL_DIR/run_background.sh start"
echo ""
echo "   METHOD D - systemd user service (if available):"
echo "     systemctl --user daemon-reload"
echo "     systemctl --user enable pypnm-agent"
echo "     systemctl --user start pypnm-agent"
echo "     # Note: May need 'loginctl enable-linger \$USER' for it to run when logged out"
echo ""
