#!/bin/bash
# PyPNM Agent - Run in tmux/screen session
# Use this if you want to attach/detach from the agent
#
# Usage:
#   ./run_in_tmux.sh        - Start in tmux (or attach if already running)
#   ./run_in_screen.sh      - Start in screen (alternative)

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SESSION_NAME="pypnm-agent"

# Check for tmux
if command -v tmux &>/dev/null; then
    # Check if session exists
    if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        echo "Attaching to existing session..."
        tmux attach-session -t "$SESSION_NAME"
    else
        echo "Creating new tmux session: $SESSION_NAME"
        tmux new-session -d -s "$SESSION_NAME" -c "$SCRIPT_DIR"
        tmux send-keys -t "$SESSION_NAME" "source venv/bin/activate && python agent.py -c agent_config.json -v" Enter
        echo ""
        echo "Agent started in tmux session '$SESSION_NAME'"
        echo ""
        echo "Commands:"
        echo "  tmux attach -t $SESSION_NAME    - Attach to session"
        echo "  Ctrl+B, D                       - Detach from session"
        echo "  tmux kill-session -t $SESSION_NAME - Stop agent"
    fi
elif command -v screen &>/dev/null; then
    # Use screen as fallback
    if screen -list | grep -q "$SESSION_NAME"; then
        echo "Attaching to existing screen session..."
        screen -r "$SESSION_NAME"
    else
        echo "Creating new screen session: $SESSION_NAME"
        screen -dmS "$SESSION_NAME" bash -c "cd $SCRIPT_DIR && source venv/bin/activate && python agent.py -c agent_config.json -v; exec bash"
        echo ""
        echo "Agent started in screen session '$SESSION_NAME'"
        echo ""
        echo "Commands:"
        echo "  screen -r $SESSION_NAME   - Attach to session"  
        echo "  Ctrl+A, D                 - Detach from session"
        echo "  screen -X -S $SESSION_NAME quit - Stop agent"
    fi
else
    echo "Neither tmux nor screen found."
    echo ""
    echo "Install one of them:"
    echo "  sudo apt install tmux    # Debian/Ubuntu"
    echo "  sudo yum install tmux    # RHEL/CentOS"
    echo ""
    echo "Or use run_background.sh instead."
    exit 1
fi
