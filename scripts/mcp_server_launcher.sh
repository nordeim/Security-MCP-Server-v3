#!/usr/bin/env bash

#==============================================================================
# MCP Network Tools Server Launcher
#==============================================================================
# Purpose: Robust launcher script with process management, validation,
#          and comprehensive error handling.
#
# Usage:
#   ./mcp_server_launcher.sh [start|stop|restart|status|validate|logs]
#
# Environment Variables:
#   MCP_HOME        - Installation directory (default: script parent dir)
#   MCP_VENV        - Virtual environment path (default: $MCP_HOME/venv)
#   MCP_CONFIG      - Configuration file path (optional)
#   MCP_PID_FILE    - PID file location (default: /tmp/mcp_server.pid)
#   MCP_LOG_FILE    - Log file location (default: /tmp/mcp_server.log)
#   MCP_TRANSPORT   - Transport mode: stdio or http (default: stdio)
#   MCP_PORT        - HTTP port if transport=http (default: 8080)
#
# Requirements:
#   - Python 3.11+
#   - pip
#   - Virtual environment (created automatically if missing)
#
# Author: MCP Network Tools Team
# Version: 2.0.0
#==============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------

# Script directory and MCP home
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_HOME="${MCP_HOME:-$(dirname "$SCRIPT_DIR")}"
MCP_VENV="${MCP_VENV:-$MCP_HOME/venv}"
MCP_CONFIG="${MCP_CONFIG:-}"
MCP_PID_FILE="${MCP_PID_FILE:-/tmp/mcp_server.pid}"
MCP_LOG_FILE="${MCP_LOG_FILE:-/tmp/mcp_server.log}"
MCP_TRANSPORT="${MCP_TRANSPORT:-stdio}"
MCP_PORT="${MCP_PORT:-8080}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

#------------------------------------------------------------------------------
# Pre-flight Checks
#------------------------------------------------------------------------------

check_python() {
    log_info "Checking Python installation..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 not found. Please install Python 3.11 or higher."
        return 1
    fi
    
    local python_version
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    local major minor
    major=$(echo "$python_version" | cut -d. -f1)
    minor=$(echo "$python_version" | cut -d. -f2)
    
    if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 11 ]); then
        log_error "Python 3.11+ required, found: $python_version"
        return 1
    fi
    
    log_success "Python $python_version found"
    return 0
}

check_dependencies() {
    log_info "Checking system dependencies..."
    
    local missing_deps=()
    
    # Check for nmap
    if ! command -v nmap &> /dev/null; then
        missing_deps+=("nmap")
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_warning "Missing optional dependencies: ${missing_deps[*]}"
        log_info "Install with: sudo apt-get install ${missing_deps[*]}"
    else
        log_success "All dependencies available"
    fi
    
    return 0
}

#------------------------------------------------------------------------------
# Virtual Environment Management
#------------------------------------------------------------------------------

setup_venv() {
    log_info "Setting up virtual environment at $MCP_VENV..."
    
    if [ -d "$MCP_VENV" ]; then
        log_info "Virtual environment already exists"
        return 0
    fi
    
    # Create virtual environment
    python3 -m venv "$MCP_VENV"
    
    if [ $? -ne 0 ]; then
        log_error "Failed to create virtual environment"
        return 1
    fi
    
    log_success "Virtual environment created"
    
    # Activate and upgrade pip
    # shellcheck disable=SC1091
    source "$MCP_VENV/bin/activate"
    
    log_info "Upgrading pip..."
    pip install --upgrade pip setuptools wheel > /dev/null 2>&1
    
    # Install dependencies
    if [ -f "$MCP_HOME/requirements.txt" ]; then
        log_info "Installing dependencies from requirements.txt..."
        pip install -r "$MCP_HOME/requirements.txt"
    else
        log_warning "requirements.txt not found, skipping dependency installation"
    fi
    
    log_success "Virtual environment setup complete"
    return 0
}

activate_venv() {
    if [ ! -d "$MCP_VENV" ]; then
        log_error "Virtual environment not found at $MCP_VENV"
        log_info "Run with 'validate' command to create it"
        return 1
    fi
    
    # shellcheck disable=SC1091
    source "$MCP_VENV/bin/activate"
    
    if [ $? -ne 0 ]; then
        log_error "Failed to activate virtual environment"
        return 1
    fi
    
    log_info "Virtual environment activated"
    return 0
}

#------------------------------------------------------------------------------
# Process Management
#------------------------------------------------------------------------------

is_running() {
    if [ ! -f "$MCP_PID_FILE" ]; then
        return 1
    fi
    
    local pid
    pid=$(cat "$MCP_PID_FILE")
    
    if ! kill -0 "$pid" 2> /dev/null; then
        # PID file exists but process not running
        rm -f "$MCP_PID_FILE"
        return 1
    fi
    
    return 0
}

get_pid() {
    if [ -f "$MCP_PID_FILE" ]; then
        cat "$MCP_PID_FILE"
    fi
}

start_server() {
    log_info "Starting MCP server..."
    
    # Check if already running
    if is_running; then
        log_warning "Server already running with PID $(get_pid)"
        return 0
    fi
    
    # Activate virtual environment
    activate_venv || return 1
    
    # Set environment variables
    export MCP_SERVER_TRANSPORT="$MCP_TRANSPORT"
    export LOG_LEVEL="${LOG_LEVEL:-INFO}"
    
    if [ "$MCP_TRANSPORT" = "http" ]; then
        export MCP_SERVER_PORT="$MCP_PORT"
        export MCP_SERVER_HOST="${MCP_SERVER_HOST:-0.0.0.0}"
    fi
    
    if [ -n "$MCP_CONFIG" ]; then
        export MCP_CONFIG_FILE="$MCP_CONFIG"
    fi
    
    # Start server in background
    log_info "Starting server in $MCP_TRANSPORT mode..."
    
    cd "$MCP_HOME" || return 1
    
    if [ "$MCP_TRANSPORT" = "stdio" ]; then
        # Stdio mode - direct execution
        nohup python -m mcp_server.server > "$MCP_LOG_FILE" 2>&1 &
    else
        # HTTP mode
        nohup python -m mcp_server.server > "$MCP_LOG_FILE" 2>&1 &
    fi
    
    local pid=$!
    echo "$pid" > "$MCP_PID_FILE"
    
    # Wait a moment and verify it's still running
    sleep 2
    
    if ! is_running; then
        log_error "Server failed to start. Check logs at $MCP_LOG_FILE"
        return 1
    fi
    
    log_success "Server started with PID $pid"
    log_info "Logs: $MCP_LOG_FILE"
    
    if [ "$MCP_TRANSPORT" = "http" ]; then
        log_info "HTTP server listening on port $MCP_PORT"
        log_info "Health check: http://localhost:$MCP_PORT/health"
    fi
    
    return 0
}

stop_server() {
    log_info "Stopping MCP server..."
    
    if ! is_running; then
        log_warning "Server not running"
        return 0
    fi
    
    local pid
    pid=$(get_pid)
    
    log_info "Sending SIGTERM to PID $pid..."
    kill -TERM "$pid"
    
    # Wait for graceful shutdown (up to 30 seconds)
    local timeout=30
    local elapsed=0
    
    while is_running && [ $elapsed -lt $timeout ]; do
        sleep 1
        elapsed=$((elapsed + 1))
    done
    
    if is_running; then
        log_warning "Graceful shutdown timed out, forcing termination..."
        kill -KILL "$pid"
        sleep 1
    fi
    
    rm -f "$MCP_PID_FILE"
    log_success "Server stopped"
    return 0
}

restart_server() {
    log_info "Restarting MCP server..."
    stop_server
    sleep 2
    start_server
}

show_status() {
    echo "========================================="
    echo "  MCP Server Status"
    echo "========================================="
    echo "Transport:    $MCP_TRANSPORT"
    echo "PID File:     $MCP_PID_FILE"
    echo "Log File:     $MCP_LOG_FILE"
    echo "Config:       ${MCP_CONFIG:-<default>}"
    echo "Virtual Env:  $MCP_VENV"
    echo ""
    
    if is_running; then
        local pid
        pid=$(get_pid)
        echo -e "Status:       ${GREEN}RUNNING${NC}"
        echo "PID:          $pid"
        
        # Show resource usage if available
        if command -v ps &> /dev/null; then
            local cpu mem
            cpu=$(ps -p "$pid" -o %cpu --no-headers 2>/dev/null || echo "N/A")
            mem=$(ps -p "$pid" -o %mem --no-headers 2>/dev/null || echo "N/A")
            echo "CPU:          ${cpu}%"
            echo "Memory:       ${mem}%"
        fi
        
        # Show HTTP endpoint if applicable
        if [ "$MCP_TRANSPORT" = "http" ]; then
            echo ""
            echo "Endpoints:"
            echo "  Health:  http://localhost:$MCP_PORT/health"
            echo "  Tools:   http://localhost:$MCP_PORT/tools"
            echo "  Metrics: http://localhost:$MCP_PORT/metrics"
        fi
    else
        echo -e "Status:       ${RED}STOPPED${NC}"
    fi
    
    echo "========================================="
}

show_logs() {
    if [ ! -f "$MCP_LOG_FILE" ]; then
        log_warning "Log file not found: $MCP_LOG_FILE"
        return 1
    fi
    
    log_info "Showing last 50 lines of $MCP_LOG_FILE"
    echo "========================================="
    tail -n 50 "$MCP_LOG_FILE"
    echo "========================================="
    log_info "Use 'tail -f $MCP_LOG_FILE' to follow logs"
}

validate_installation() {
    log_info "Validating MCP server installation..."
    
    local errors=0
    
    # Check Python
    if ! check_python; then
        errors=$((errors + 1))
    fi
    
    # Check dependencies
    check_dependencies
    
    # Setup virtual environment if needed
    if [ ! -d "$MCP_VENV" ]; then
        setup_venv || errors=$((errors + 1))
    else
        log_success "Virtual environment exists"
    fi
    
    # Activate venv and check package
    if activate_venv; then
        log_info "Checking mcp_server package..."
        
        if python -c "import mcp_server" 2>/dev/null; then
            log_success "mcp_server package found"
        else
            log_error "mcp_server package not found"
            log_info "Install with: pip install -e ."
            errors=$((errors + 1))
        fi
    else
        errors=$((errors + 1))
    fi
    
    # Check configuration
    if [ -n "$MCP_CONFIG" ] && [ ! -f "$MCP_CONFIG" ]; then
        log_warning "Configuration file not found: $MCP_CONFIG"
    fi
    
    # Summary
    echo ""
    if [ $errors -eq 0 ]; then
        log_success "Validation passed! Server is ready to start."
        return 0
    else
        log_error "Validation failed with $errors error(s)"
        return 1
    fi
}

#------------------------------------------------------------------------------
# Main Command Handler
#------------------------------------------------------------------------------

show_usage() {
    cat << EOF
MCP Network Tools Server Launcher

Usage: $0 [COMMAND]

Commands:
    start       Start the MCP server
    stop        Stop the MCP server
    restart     Restart the MCP server
    status      Show server status
    logs        Show recent log entries
    validate    Validate installation and dependencies

Environment Variables:
    MCP_HOME        Installation directory (default: script parent dir)
    MCP_VENV        Virtual environment path (default: \$MCP_HOME/venv)
    MCP_CONFIG      Configuration file path (optional)
    MCP_TRANSPORT   Transport mode: stdio or http (default: stdio)
    MCP_PORT        HTTP port if transport=http (default: 8080)
    LOG_LEVEL       Logging level (default: INFO)

Examples:
    # Start server in stdio mode (default)
    $0 start

    # Start server in HTTP mode
    MCP_TRANSPORT=http MCP_PORT=8080 $0 start

    # Check server status
    $0 status

    # View logs
    $0 logs

    # Validate installation
    $0 validate

For more information, see README.md
EOF
}

main() {
    local command="${1:-}"
    
    if [ -z "$command" ]; then
        show_usage
        exit 0
    fi
    
    case "$command" in
        start)
            start_server
            ;;
        stop)
            stop_server
            ;;
        restart)
            restart_server
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs
            ;;
        validate)
            validate_installation
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
