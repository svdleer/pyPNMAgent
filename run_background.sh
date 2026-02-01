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
    
    # Activate venv and run agent
    cd "$AGENT_DIR"
    source "${VENV_DIR}/bin/activate"
    
    # Run with nohup, redirect output to log file
    nohup python agent.py -c agent_config.json >> "$LOG_FILE" 2>&1 &
    
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
    if [ ! -f "$PID_FILE" ]; then
        echo "Agent not running (no PID file)"
        return 0
    fi
    
    PID=$(cat "$PID_FILE")
    
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping agent (PID: $PID)..."
        kill "$PID"
        
        # Wait for graceful shutdown
        for i in {1..10}; do
            if ! kill -0 "$PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        
        # Force kill if still running
        if kill -0 "$PID" 2>/dev/null; then
            echo "Force killing..."
            kill -9 "$PID"
        fi
        
        echo "Agent stopped"
    else
        echo "Agent not running"
    fi
    
    rm -f "$PID_FILE"
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
