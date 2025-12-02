#!/bin/bash
#
# LLM Guard API Service Management Script
# ========================================
# This script manages the LLM Guard API service using uvicorn/gunicorn
# with nohup for background execution (no SSH terminal required).
#
# Usage: ./llm-guard.sh {start|stop|status|restart}
#
# Documentation: https://protectai.github.io/llm-guard/api/deployment/

# =============================================================================
# CONFIGURATION - Modify these variables according to your setup
# =============================================================================

# Service name for identification
SERVICE_NAME="llm-guard-api"

# Working directory where llm_guard_api is installed
APP_DIR="${LLM_GUARD_APP_DIR:-/opt/llm-guard-api}"

# Config file path
CONFIG_FILE="${LLM_GUARD_CONFIG:-${APP_DIR}/config/scanners.yml}"

# Host and port
HOST="${LLM_GUARD_HOST:-0.0.0.0}"
PORT="${LLM_GUARD_PORT:-8000}"

# Number of workers (for gunicorn)
WORKERS="${LLM_GUARD_WORKERS:-1}"

# Log level: DEBUG, INFO, WARNING, ERROR
LOG_LEVEL="${LLM_GUARD_LOG_LEVEL:-INFO}"

# Authentication token (optional)
AUTH_TOKEN="${LLM_GUARD_AUTH_TOKEN:-}"

# Python executable (use virtual environment if available)
PYTHON="${LLM_GUARD_PYTHON:-python3}"

# Use uvicorn with workers instead of gunicorn (recommended for production)
USE_UVICORN_WORKERS="${LLM_GUARD_USE_UVICORN_WORKERS:-false}"

# PID file location
PID_FILE="${LLM_GUARD_PID_FILE:-/var/run/${SERVICE_NAME}.pid}"

# Log directory (logs will be stored with daily rotation)
LOG_DIR="${LLM_GUARD_LOG_DIR:-/var/log/${SERVICE_NAME}}"

# Log retention days (logs older than this will be deleted)
LOG_RETENTION_DAYS="${LLM_GUARD_LOG_RETENTION_DAYS:-30}"

# Current date for log file naming (format: yyyymmdd)
CURRENT_DATE=$(date +"%Y%m%d")

# Log file with daily rotation format: logs_yyyymmdd.log
LOG_FILE="${LOG_DIR}/logs_${CURRENT_DATE}.log"

# Symlink to current log file for easy access
LOG_FILE_CURRENT="${LOG_DIR}/current.log"

# =============================================================================
# COLORS FOR OUTPUT
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Get the PID of the running service
get_pid() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        # Verify PID is valid and process exists
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return 0
        fi
    fi
    # Fallback: Try to find by process name (for Linux with pgrep)
    if command -v pgrep &> /dev/null; then
        pgrep -f "llm_guard_api|uvicorn.*app.app|gunicorn.*app.app" | head -1
    fi
}

# Check if the service is running
is_running() {
    local pid=$(get_pid)
    if [ -n "$pid" ]; then
        return 0
    else
        return 1
    fi
}

# Write to log file with timestamp
write_log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local log_entry="[${timestamp}] [${level}] ${message}"
    
    # Ensure log directory exists
    if [ -d "$LOG_DIR" ]; then
        echo "$log_entry" >> "$LOG_FILE"
    fi
}

# Rotate log file if date has changed
rotate_log_if_needed() {
    local new_date=$(date +"%Y%m%d")
    if [ "$new_date" != "$CURRENT_DATE" ]; then
        CURRENT_DATE="$new_date"
        LOG_FILE="${LOG_DIR}/logs_${CURRENT_DATE}.log"
        
        # Update symlink to current log
        ln -sf "$LOG_FILE" "$LOG_FILE_CURRENT" 2>/dev/null
        
        write_log "INFO" "Log rotated to new file: $LOG_FILE"
    fi
}

# Clean up old log files based on retention policy
cleanup_old_logs() {
    if [ -d "$LOG_DIR" ] && [ "$LOG_RETENTION_DAYS" -gt 0 ]; then
        local deleted_count=0
        
        # Find and delete log files older than retention days
        while IFS= read -r old_log; do
            if [ -f "$old_log" ]; then
                rm -f "$old_log"
                deleted_count=$((deleted_count + 1))
                write_log "INFO" "Deleted old log file: $old_log"
            fi
        done < <(find "$LOG_DIR" -name "logs_*.log" -type f -mtime +"$LOG_RETENTION_DAYS" 2>/dev/null)
        
        if [ $deleted_count -gt 0 ]; then
            log_info "Cleaned up $deleted_count old log file(s)"
        fi
    fi
}

# Create necessary directories
setup_directories() {
    # Create log directory if it doesn't exist
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR" 2>/dev/null || {
            log_warn "Cannot create log directory $LOG_DIR, using /tmp"
            LOG_DIR="/tmp/${SERVICE_NAME}"
            mkdir -p "$LOG_DIR" 2>/dev/null
            LOG_FILE="${LOG_DIR}/logs_${CURRENT_DATE}.log"
            LOG_FILE_CURRENT="${LOG_DIR}/current.log"
        }
    fi
    
    # Create PID directory if it doesn't exist
    local pid_dir=$(dirname "$PID_FILE")
    if [ ! -d "$pid_dir" ]; then
        mkdir -p "$pid_dir" 2>/dev/null || {
            log_warn "Cannot create PID directory $pid_dir, using /tmp"
            PID_FILE="/tmp/${SERVICE_NAME}.pid"
        }
    fi
    
    # Create symlink to current log file
    ln -sf "$LOG_FILE" "$LOG_FILE_CURRENT" 2>/dev/null
    
    # Clean up old logs
    cleanup_old_logs
}

# =============================================================================
# SERVICE COMMANDS
# =============================================================================

start_service() {
    log_info "Starting ${SERVICE_NAME}..."
    
    # Check if already running
    if is_running; then
        local pid=$(get_pid)
        log_warn "${SERVICE_NAME} is already running (PID: $pid)"
        return 1
    fi
    
    # Setup directories
    setup_directories
    
    # Check if config file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Config file not found: $CONFIG_FILE"
        return 1
    fi
    
    # Check if app directory exists
    if [ ! -d "$APP_DIR" ]; then
        log_error "Application directory not found: $APP_DIR"
        return 1
    fi
    
    # Change to app directory
    cd "$APP_DIR" || {
        log_error "Cannot change to directory: $APP_DIR"
        return 1
    }
    
    # Build environment variables
    local env_vars=""
    env_vars="LOG_LEVEL=${LOG_LEVEL}"
    if [ -n "$AUTH_TOKEN" ]; then
        env_vars="${env_vars} AUTH_TOKEN=${AUTH_TOKEN}"
    fi
    
    # Build the command
    local cmd=""
    if [ "$USE_UVICORN_WORKERS" = "true" ]; then
        # Use uvicorn with workers (production mode)
        cmd="uvicorn app.app:create_app --host=${HOST} --port=${PORT} --workers=${WORKERS} --forwarded-allow-ips='*' --proxy-headers --timeout-keep-alive=2"
        log_info "Using uvicorn with ${WORKERS} worker(s) (production mode)"
    else
        # Use llm_guard_api CLI (simple mode)
        cmd="llm_guard_api ${CONFIG_FILE} --host ${HOST} --port ${PORT}"
        log_info "Using llm_guard_api CLI (simple mode)"
    fi
    
    # Start the service with nohup
    log_info "Command: $cmd"
    log_info "Log directory: $LOG_DIR"
    log_info "Log file: $LOG_FILE"
    log_info "PID file: $PID_FILE"
    log_info "Log retention: $LOG_RETENTION_DAYS days"
    
    # Write startup info to log file
    write_log "INFO" "========================================"
    write_log "INFO" "Starting ${SERVICE_NAME}"
    write_log "INFO" "Command: $cmd"
    write_log "INFO" "Host: ${HOST}:${PORT}"
    write_log "INFO" "Config: $CONFIG_FILE"
    write_log "INFO" "Workers: $WORKERS"
    write_log "INFO" "Log Level: $LOG_LEVEL"
    write_log "INFO" "========================================"
    
    # Export environment variables and run
    export LOG_LEVEL="${LOG_LEVEL}"
    [ -n "$AUTH_TOKEN" ] && export AUTH_TOKEN="${AUTH_TOKEN}"
    
    # Start the service with nohup and log rotation
    # We use a simpler approach: redirect output to a log file directly
    nohup bash -c "
        exec $cmd 2>&1 | while IFS= read -r line; do
            NEW_DATE=\$(date +\"%Y%m%d\")
            CURRENT_LOG=\"${LOG_DIR}/logs_\${NEW_DATE}.log\"
            TIMESTAMP=\$(date +\"%Y-%m-%d %H:%M:%S\")
            echo \"[\${TIMESTAMP}] \${line}\" >> \"\${CURRENT_LOG}\"
            # Update symlink
            ln -sf \"\${CURRENT_LOG}\" \"${LOG_FILE_CURRENT}\" 2>/dev/null
        done
    " &
    local wrapper_pid=$!
    
    # Save wrapper PID
    echo $wrapper_pid > "$PID_FILE"
    
    # Wait for the service to start
    sleep 3
    
    # Check if the wrapper process is still running
    if kill -0 "$wrapper_pid" 2>/dev/null; then
        write_log "INFO" "Service started successfully (PID: $wrapper_pid)"
        log_info "${SERVICE_NAME} started successfully (PID: $wrapper_pid)"
        log_info "API available at: http://${HOST}:${PORT}"
        log_info "Health check: http://${HOST}:${PORT}/healthz"
        log_info "Current log: $LOG_FILE_CURRENT"
        return 0
    else
        write_log "ERROR" "Service failed to start"
        log_error "${SERVICE_NAME} failed to start. Check log file: $LOG_FILE"
        rm -f "$PID_FILE"
        tail -20 "$LOG_FILE" 2>/dev/null
        return 1
    fi
}

stop_service() {
    log_info "Stopping ${SERVICE_NAME}..."
    
    # Log shutdown attempt
    write_log "INFO" "========================================"
    write_log "INFO" "Stopping ${SERVICE_NAME}"
    write_log "INFO" "========================================"
    
    if ! is_running; then
        log_warn "${SERVICE_NAME} is not running"
        write_log "WARN" "Service was not running"
        rm -f "$PID_FILE"
        return 0
    fi
    
    local pid=$(get_pid)
    
    # Try graceful shutdown first
    log_info "Sending SIGTERM to PID $pid..."
    kill -TERM "$pid" 2>/dev/null
    
    # Wait for process to stop (max 10 seconds)
    local count=0
    while [ $count -lt 10 ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 1
        count=$((count + 1))
        echo -n "."
    done
    echo ""
    
    # Force kill if still running
    if kill -0 "$pid" 2>/dev/null; then
        log_warn "Process still running, sending SIGKILL..."
        kill -9 "$pid" 2>/dev/null
        sleep 1
    fi
    
    # Also kill any child processes
    pkill -9 -f "llm_guard_api\|uvicorn.*app.app\|gunicorn.*app.app" 2>/dev/null
    
    # Clean up PID file
    rm -f "$PID_FILE"
    
    if ! is_running; then
        write_log "INFO" "Service stopped successfully (PID: $pid)"
        log_info "${SERVICE_NAME} stopped successfully"
        return 0
    else
        write_log "ERROR" "Failed to stop service (PID: $pid)"
        log_error "Failed to stop ${SERVICE_NAME}"
        return 1
    fi
}

status_service() {
    echo "=============================================="
    echo "  ${SERVICE_NAME} Status"
    echo "=============================================="
    
    if is_running; then
        local pid=$(get_pid)
        echo -e "Status:      ${GREEN}RUNNING${NC}"
        echo "PID:         $pid"
        echo "API URL:     http://${HOST}:${PORT}"
        echo "Health URL:  http://${HOST}:${PORT}/healthz"
        echo "Config:      $CONFIG_FILE"
        echo "Log dir:     $LOG_DIR"
        echo "Log file:    $LOG_FILE"
        echo "Current log: $LOG_FILE_CURRENT"
        echo "Retention:   $LOG_RETENTION_DAYS days"
        echo "PID file:    $PID_FILE"
        echo ""
        
        # Show log files
        echo "Log Files:"
        ls -lh "${LOG_DIR}/logs_"*.log 2>/dev/null | tail -5 || echo "  No log files found"
        echo ""
        
        # Show process info
        echo "Process Info:"
        ps -p "$pid" -o pid,ppid,user,%cpu,%mem,etime,command 2>/dev/null || echo "  Unable to get process info"
        echo ""
        
        # Try health check
        echo "Health Check:"
        if command -v curl &> /dev/null; then
            local health_response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${PORT}/healthz" 2>/dev/null)
            if [ "$health_response" = "200" ]; then
                echo -e "  HTTP Status: ${GREEN}200 OK${NC}"
            else
                echo -e "  HTTP Status: ${YELLOW}${health_response}${NC} (may still be starting)"
            fi
        else
            echo "  (curl not available for health check)"
        fi
        echo ""
        
        # Show last few log lines
        echo "Recent Logs (last 5 lines):"
        tail -5 "$LOG_FILE" 2>/dev/null || echo "  Log file not available"
        
        return 0
    else
        echo -e "Status:      ${RED}STOPPED${NC}"
        echo "Config:      $CONFIG_FILE"
        echo "Log dir:     $LOG_DIR"
        echo "Log file:    $LOG_FILE"
        echo "Current log: $LOG_FILE_CURRENT"
        echo "Retention:   $LOG_RETENTION_DAYS days"
        echo "PID file:    $PID_FILE"
        
        # Show log files
        if [ -d "$LOG_DIR" ]; then
            echo ""
            echo "Log Files:"
            ls -lh "${LOG_DIR}/logs_"*.log 2>/dev/null | tail -5 || echo "  No log files found"
        fi
        
        # Show last few log lines if available
        if [ -f "$LOG_FILE" ]; then
            echo ""
            echo "Last Logs from $LOG_FILE (last 10 lines):"
            tail -10 "$LOG_FILE"
        elif [ -f "$LOG_FILE_CURRENT" ]; then
            echo ""
            echo "Last Logs from current.log (last 10 lines):"
            tail -10 "$LOG_FILE_CURRENT"
        fi
        
        return 1
    fi
}

restart_service() {
    log_info "Restarting ${SERVICE_NAME}..."
    stop_service
    sleep 2
    start_service
}

show_logs() {
    local target_log="$2"
    
    # If specific date provided, use that log file
    if [ -n "$target_log" ]; then
        local specific_log="${LOG_DIR}/logs_${target_log}.log"
        if [ -f "$specific_log" ]; then
            log_info "Showing logs from: $specific_log"
            tail -f "$specific_log"
        else
            log_error "Log file not found: $specific_log"
            echo "Available log files:"
            ls -la "${LOG_DIR}/logs_"*.log 2>/dev/null || echo "  No log files found"
            return 1
        fi
    # Use current log symlink if exists
    elif [ -f "$LOG_FILE_CURRENT" ]; then
        log_info "Following current log: $LOG_FILE_CURRENT -> $(readlink -f "$LOG_FILE_CURRENT" 2>/dev/null || echo "$LOG_FILE")"
        tail -f "$LOG_FILE_CURRENT"
    # Fallback to today's log file
    elif [ -f "$LOG_FILE" ]; then
        log_info "Following log file: $LOG_FILE"
        tail -f "$LOG_FILE"
    else
        log_error "No log files found"
        echo "Log directory: $LOG_DIR"
        ls -la "$LOG_DIR" 2>/dev/null || echo "Log directory does not exist"
        return 1
    fi
}

# List all log files
list_logs() {
    echo "=============================================="
    echo "  ${SERVICE_NAME} Log Files"
    echo "=============================================="
    echo "Log directory: $LOG_DIR"
    echo "Retention: $LOG_RETENTION_DAYS days"
    echo ""
    
    if [ -d "$LOG_DIR" ]; then
        echo "Available log files:"
        ls -lh "${LOG_DIR}/logs_"*.log 2>/dev/null | while read line; do
            echo "  $line"
        done
        
        if [ ! "$(ls -A ${LOG_DIR}/logs_*.log 2>/dev/null)" ]; then
            echo "  No log files found"
        fi
        
        echo ""
        echo "Current log symlink:"
        if [ -L "$LOG_FILE_CURRENT" ]; then
            echo "  $LOG_FILE_CURRENT -> $(readlink -f "$LOG_FILE_CURRENT")"
        else
            echo "  Not set"
        fi
    else
        echo "Log directory does not exist: $LOG_DIR"
    fi
}

# Manually trigger log cleanup
cleanup_logs() {
    log_info "Running log cleanup..."
    log_info "Retention policy: $LOG_RETENTION_DAYS days"
    
    if [ ! -d "$LOG_DIR" ]; then
        log_error "Log directory does not exist: $LOG_DIR"
        return 1
    fi
    
    # Show files that will be deleted
    echo "Files older than $LOG_RETENTION_DAYS days:"
    find "$LOG_DIR" -name "logs_*.log" -type f -mtime +"$LOG_RETENTION_DAYS" 2>/dev/null | while read f; do
        echo "  $f"
    done
    
    echo ""
    read -p "Delete these files? (y/N) " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        cleanup_old_logs
        log_info "Cleanup completed"
    else
        log_info "Cleanup cancelled"
    fi
}

show_usage() {
    echo "=============================================="
    echo "  LLM Guard API Service Manager"
    echo "=============================================="
    echo ""
    echo "Usage: $0 {start|stop|status|restart|logs|list-logs|cleanup-logs}"
    echo ""
    echo "Commands:"
    echo "  start        - Start the LLM Guard API service"
    echo "  stop         - Stop the LLM Guard API service"
    echo "  status       - Show service status"
    echo "  restart      - Restart the service"
    echo "  logs         - Follow the current log file (tail -f)"
    echo "  logs DATE    - Follow specific date's log (e.g., logs 20251202)"
    echo "  list-logs    - List all log files"
    echo "  cleanup-logs - Manually cleanup old log files"
    echo ""
    echo "Log Rotation:"
    echo "  - Logs are stored with daily rotation: logs_yyyymmdd.log"
    echo "  - A symlink 'current.log' always points to today's log"
    echo "  - Old logs are automatically cleaned up based on retention policy"
    echo ""
    echo "Environment Variables:"
    echo "  LLM_GUARD_APP_DIR          - Application directory (default: /opt/llm-guard-api)"
    echo "  LLM_GUARD_CONFIG           - Config file path (default: \$APP_DIR/config/scanners.yml)"
    echo "  LLM_GUARD_HOST             - Host to bind (default: 0.0.0.0)"
    echo "  LLM_GUARD_PORT             - Port to listen (default: 8000)"
    echo "  LLM_GUARD_WORKERS          - Number of workers (default: 1)"
    echo "  LLM_GUARD_LOG_LEVEL        - Log level (default: INFO)"
    echo "  LLM_GUARD_AUTH_TOKEN       - Authentication token (optional)"
    echo "  LLM_GUARD_USE_UVICORN_WORKERS - Use uvicorn with multiple workers (default: false)"
    echo "  LLM_GUARD_PYTHON           - Python executable (default: python3)"
    echo "  LLM_GUARD_PID_FILE         - PID file location"
    echo "  LLM_GUARD_LOG_DIR          - Log directory (default: /var/log/llm-guard-api)"
    echo "  LLM_GUARD_LOG_RETENTION_DAYS - Days to keep logs (default: 30)"
    echo ""
    echo "Examples:"
    echo "  $0 start"
    echo "  $0 stop"
    echo "  $0 status"
    echo "  $0 restart"
    echo "  $0 logs                    # Follow current log"
    echo "  $0 logs 20251201           # Follow specific date's log"
    echo "  $0 list-logs               # List all log files"
    echo "  $0 cleanup-logs            # Cleanup old logs"
    echo ""
    echo "  # With custom settings"
    echo "  LLM_GUARD_PORT=9000 LLM_GUARD_USE_UVICORN_WORKERS=true $0 start"
    echo "  LLM_GUARD_LOG_RETENTION_DAYS=7 $0 start  # Keep only 7 days of logs"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

case "$1" in
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    status)
        status_service
        ;;
    restart)
        restart_service
        ;;
    logs)
        show_logs "$1" "$2"
        ;;
    list-logs)
        list_logs
        ;;
    cleanup-logs)
        cleanup_logs
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

exit $?
