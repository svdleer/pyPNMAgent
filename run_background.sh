#!/bin/bash
# PyPNM Agent - Run in Background
# Simple script to run agent persistently without systemd
#
# Usage:
#   ./run_background.sh start   - Start agent in background
#   ./run_background.sh stop    - Stop agent
#   ./run_background.sh status  - Check if running
#   ./run_background.sh logs    - View logs

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
AGENT_DIR="${SCRIPT_DIR}"
PID_FILE="${AGENT_DIR}/agent.pid"
LOG_FILE="${AGENT_DIR}/logs/agent.log"
VENV_DIR="${AGENT_DIR}/venv"

# Create logs directory if needed
mkdir -p "${AGENT_DIR}/logs"

start_agent() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Agent already running (PID: $PID)"
            return 1
        fi
    fi
    
    echo "Starting PyPNM Agent..."

    # Use venv python explicitly — don't rely on PATH after source activate
    PYTHON="${VENV_DIR}/bin/python"
    if [ ! -x "$PYTHON" ]; then
        echo "ERROR: venv not found at $VENV_DIR — run install.sh first"
        return 1
    fi

    cd "$AGENT_DIR"

    # Write a loop script so we don't need fragile nested quoting,
    # and setsid can exec it cleanly in its own process group.
    LOOP_SCRIPT="${AGENT_DIR}/logs/.agent_loop.sh"
    cat > "$LOOP_SCRIPT" << LOOPEOF
#!/bin/bash
cd "${AGENT_DIR}"
while true; do
    PYTHONUNBUFFERED=1 "${PYTHON}" -u agent.py -c agent_config.json
    EXIT_CODE=\$?
    echo "\$(date '+%Y-%m-%d %H:%M:%S') Agent exited (code \$EXIT_CODE), restarting in 10s..."
    sleep 10
done
LOOPEOF
    chmod +x "$LOOP_SCRIPT"

    # setsid gives the wrapper its own process group so stop() can kill
    # the whole group (wrapper + python + ssh children) in one shot.
    # Falls back to plain nohup if setsid is unavailable (older macOS).
    if command -v setsid &>/dev/null; then
        setsid nohup bash "$LOOP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    else
        nohup bash "$LOOP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    fi
    
    PID=$!
    echo $PID > "$PID_FILE"
    
    sleep 2
    if kill -0 "$PID" 2>/dev/null; then
        echo "Agent started (PID: $PID)"
        echo "Logs: $LOG_FILE"
    else
        echo "Agent failed to start. Check logs:"
        tail -20 "$LOG_FILE"
        rm -f "$PID_FILE"
        return 1
    fi
}

stop_agent() {
    local did_something=0

    # --- 1. Kill the wrapper bash loop and its entire process group ----------
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            # Derive the process-group ID (same as PID for the nohup leader)
            PGID=$(ps -o pgid= -p "$PID" 2>/dev/null | tr -d ' ')
            echo "Stopping agent wrapper (PID: $PID, PGID: ${PGID:-?})..."

            # Graceful SIGTERM to the whole group
            if [ -n "$PGID" ] && [ "$PGID" -gt 1 ]; then
                kill -- "-${PGID}" 2>/dev/null
            else
                kill "$PID" 2>/dev/null
            fi

            # Wait up to 8 s for the group to exit
            for i in {1..8}; do
                kill -0 "$PID" 2>/dev/null || break
                sleep 1
            done

            # Force-kill anything still alive in the group
            if [ -n "$PGID" ] && [ "$PGID" -gt 1 ]; then
                kill -9 -- "-${PGID}" 2>/dev/null
            elif kill -0 "$PID" 2>/dev/null; then
                kill -9 "$PID" 2>/dev/null
            fi
            did_something=1
        else
            echo "Wrapper not running (stale PID file)"
        fi
        rm -f "$PID_FILE"
    else
        echo "No PID file found"
    fi

    # --- 2. Kill any surviving agent.py python processes --------------------
    AGENT_PIDS=$(pgrep -f "${AGENT_DIR}/agent.py" 2>/dev/null)
    if [ -z "$AGENT_PIDS" ]; then
        # Fallback: match any agent.py in python carrying our config
        AGENT_PIDS=$(pgrep -f "python.*agent\.py" 2>/dev/null)
    fi
    if [ -n "$AGENT_PIDS" ]; then
        echo "Killing leftover agent.py process(es): $AGENT_PIDS"
        kill -9 $AGENT_PIDS 2>/dev/null
        did_something=1
    fi

    # --- 3. Kill any ssh tunnel processes that are children of agent PIDs ----
    # Only target ssh processes whose parent is one of our agent.py PIDs,
    # NOT a broad sweep (which would catch unrelated autossh tunnels).
    AGENT_PIDS_NOW=$(pgrep -f "${AGENT_DIR}/agent.py" 2>/dev/null)
    if [ -z "$AGENT_PIDS_NOW" ]; then
        AGENT_PIDS_NOW=$(pgrep -f "python.*agent\.py" 2>/dev/null)
    fi
    if [ -n "$AGENT_PIDS_NOW" ]; then
        for APID in $AGENT_PIDS_NOW; do
            CHILD_SSH=$(pgrep -P "$APID" -x ssh 2>/dev/null)
            if [ -n "$CHILD_SSH" ]; then
                echo "Killing ssh child process(es) of agent PID $APID: $CHILD_SSH"
                kill -9 $CHILD_SSH 2>/dev/null
                did_something=1
            fi
        done
    fi

    if [ "$did_something" -eq 1 ]; then
        echo "Agent stopped."
    else
        echo "Nothing to stop."
    fi
}

status_agent() {
    if [ ! -f "$PID_FILE" ]; then
        echo "Agent: NOT RUNNING (no PID file)"
        return 1
    fi
    
    PID=$(cat "$PID_FILE")
    
    if kill -0 "$PID" 2>/dev/null; then
        UPTIME=$(ps -o etime= -p "$PID" 2>/dev/null | tr -d ' ')
        echo "Agent: RUNNING"
        echo "  PID: $PID"
        echo "  Uptime: $UPTIME"
        echo "  Log: $LOG_FILE"
        return 0
    else
        echo "Agent: NOT RUNNING (stale PID file)"
        rm -f "$PID_FILE"
        return 1
    fi
}

show_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo "No log file found: $LOG_FILE"
    fi
}

case "${1:-}" in
    start)
        start_agent
        ;;
    stop)
        stop_agent
        ;;
    restart)
        stop_agent
        sleep 2
        start_agent
        ;;
    status)
        status_agent
        ;;
    logs)
        show_logs
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "Commands:"
        echo "  start   - Start agent in background"
        echo "  stop    - Stop agent"
        echo "  restart - Restart agent"
        echo "  status  - Check if agent is running"
        echo "  logs    - Tail the log file"
        exit 1
        ;;
esac
