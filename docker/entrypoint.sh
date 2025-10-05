#!/usr/bin/env bash

#==============================================================================
# MCP Network Tools Server - Docker Entrypoint Script
#==============================================================================
# Purpose: Container initialization, validation, and server startup
#
# Responsibilities:
#   - Pre-flight environment checks
#   - Configuration validation
#   - Dependency verification
#   - Signal handling setup
#   - Graceful shutdown management
#   - Server process execution
#
# Signal Handling:
#   SIGTERM - Graceful shutdown (Kubernetes, Docker stop)
#   SIGINT  - Interrupt (Ctrl+C)
#   SIGHUP  - Reload configuration
#
# Exit Codes:
#   0   - Success
#   1   - General error
#   2   - Configuration error
#   3   - Dependency error
#   4   - Permission error
#   130 - Terminated by SIGINT
#   143 - Terminated by SIGTERM
#
# Author: MCP Network Tools Team
# Version: 2.0.0
#==============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------

# Application settings
APP_HOME="${MCP_HOME:-/app}"
APP_LOG_DIR="${MCP_LOG_DIR:-/app/logs}"
APP_DATA_DIR="${MCP_DATA_DIR:-/app/data}"
APP_CONFIG_DIR="${MCP_CONFIG_DIR:-/app/config}"

# Server settings
TRANSPORT="${MCP_SERVER_TRANSPORT:-stdio}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
SHUTDOWN_TIMEOUT="${MCP_SERVER_SHUTDOWN_GRACE_PERIOD:-30}"

# Process tracking
PID_FILE="/tmp/mcp_server.pid"
SERVER_PID=""

# Colors for output (disabled in production)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

#------------------------------------------------------------------------------
# Logging Functions
#------------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date -u '+%Y-%m-%dT%H:%M:%SZ') - entrypoint - $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date -u '+%Y-%m-%dT%H:%M:%SZ') - entrypoint - $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date -u '+%Y-%m-%dT%H:%M:%SZ') - entrypoint - $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date -u '+%Y-%m-%dT%H:%M:%SZ') - entrypoint - $*" >&2
}

log_debug() {
    if [ "${LOG_LEVEL}" = "DEBUG" ]; then
        echo -e "[DEBUG] $(date -u '+%Y-%m-%dT%H:%M:%SZ') - entrypoint - $*"
    fi
}

#------------------------------------------------------------------------------
# Error Handling
#------------------------------------------------------------------------------

# Trap errors and exit
trap 'error_handler $? $LINENO' ERR

error_handler() {
    local exit_code=$1
    local line_number=$2
    log_error "Script failed at line $line_number with exit code $exit_code"
    cleanup
    exit "$exit_code"
}

#------------------------------------------------------------------------------
# Signal Handlers
#------------------------------------------------------------------------------

# Graceful shutdown handler
shutdown_handler() {
    local signal=$1
    log_info "Received signal: $signal"
    log_info "Initiating graceful shutdown..."
    
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log_info "Stopping server process (PID: $SERVER_PID)..."
        
        # Send SIGTERM to server
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        
        # Wait for graceful shutdown
        local timeout=$SHUTDOWN_TIMEOUT
        local elapsed=0
        
        while kill -0 "$SERVER_PID" 2>/dev/null && [ $elapsed -lt $timeout ]; do
            sleep 1
            elapsed=$((elapsed + 1))
            
            if [ $((elapsed % 5)) -eq 0 ]; then
                log_info "Waiting for shutdown... (${elapsed}s/${timeout}s)"
            fi
        done
        
        # Force kill if still running
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            log_warning "Graceful shutdown timeout, forcing termination..."
            kill -KILL "$SERVER_PID" 2>/dev/null || true
            sleep 1
        fi
        
        log_success "Server stopped"
    else
        log_debug "No server process to stop"
    fi
    
    cleanup
    
    # Exit with appropriate code
    case $signal in
        SIGTERM)
            exit 143
            ;;
        SIGINT)
            exit 130
            ;;
        *)
            exit 0
            ;;
    esac
}

# Setup signal traps
setup_signal_handlers() {
    log_debug "Setting up signal handlers..."
    
    trap 'shutdown_handler SIGTERM' SIGTERM
    trap 'shutdown_handler SIGINT' SIGINT
    trap 'reload_config' SIGHUP
    
    log_debug "Signal handlers configured"
}

# Configuration reload handler
reload_config() {
    log_info "Received SIGHUP - configuration reload requested"
    
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        # Forward SIGHUP to server process
        log_info "Forwarding reload signal to server (PID: $SERVER_PID)..."
        kill -HUP "$SERVER_PID" 2>/dev/null || true
    else
        log_warning "Server not running, reload ignored"
    fi
}

#------------------------------------------------------------------------------
# Pre-flight Checks
#------------------------------------------------------------------------------

check_environment() {
    log_info "Checking environment..."
    
    # Check Python version
    if ! command -v python &> /dev/null; then
        log_error "Python not found in PATH"
        return 3
    fi
    
    local python_version
    python_version=$(python --version 2>&1 | awk '{print $2}')
    log_info "Python version: $python_version"
    
    # Check virtual environment
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        log_info "Virtual environment: $VIRTUAL_ENV"
    else
        log_debug "No virtual environment detected (using system Python)"
    fi
    
    # Check required environment variables
    local required_vars=("MCP_HOME")
    for var in "${required_vars[@]}"; do
        if [ -z "${!var:-}" ]; then
            log_error "Required environment variable not set: $var"
            return 2
        fi
    done
    
    log_success "Environment check passed"
    return 0
}

check_directories() {
    log_info "Checking directories..."
    
    # Check application home
    if [ ! -d "$APP_HOME" ]; then
        log_error "Application home not found: $APP_HOME"
        return 1
    fi
    
    # Create log directory if needed
    if [ ! -d "$APP_LOG_DIR" ]; then
        log_info "Creating log directory: $APP_LOG_DIR"
        mkdir -p "$APP_LOG_DIR" || {
            log_error "Failed to create log directory"
            return 4
        }
    fi
    
    # Create data directory if needed
    if [ ! -d "$APP_DATA_DIR" ]; then
        log_info "Creating data directory: $APP_DATA_DIR"
        mkdir -p "$APP_DATA_DIR" || {
            log_error "Failed to create data directory"
            return 4
        }
    fi
    
    # Check permissions
    if [ ! -w "$APP_LOG_DIR" ]; then
        log_error "Log directory not writable: $APP_LOG_DIR"
        return 4
    fi
    
    if [ ! -w "$APP_DATA_DIR" ]; then
        log_error "Data directory not writable: $APP_DATA_DIR"
        return 4
    fi
    
    log_success "Directory check passed"
    return 0
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Python package
    if ! python -c "import mcp_server" 2>/dev/null; then
        log_error "mcp_server package not found"
        log_error "Install with: pip install -e ."
        return 3
    fi
    
    log_info "mcp_server package found"
    
    # Check optional dependencies
    local optional_deps=("psutil" "prometheus_client" "fastapi" "uvicorn")
    local missing_optional=()
    
    for dep in "${optional_deps[@]}"; do
        if ! python -c "import $dep" 2>/dev/null; then
            missing_optional+=("$dep")
        fi
    done
    
    if [ ${#missing_optional[@]} -gt 0 ]; then
        log_warning "Missing optional dependencies: ${missing_optional[*]}"
        log_info "Some features may be unavailable"
    fi
    
    # Check system tools
    local tools=("nmap")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_warning "Missing system tools: ${missing_tools[*]}"
        log_info "Some tools may not be available"
    else
        log_info "All system tools available"
    fi
    
    log_success "Dependency check passed"
    return 0
}

validate_configuration() {
    log_info "Validating configuration..."
    
    # Validate transport mode
    if [ "$TRANSPORT" != "stdio" ] && [ "$TRANSPORT" != "http" ]; then
        log_error "Invalid transport mode: $TRANSPORT (must be stdio or http)"
        return 2
    fi
    
    log_info "Transport mode: $TRANSPORT"
    
    # Validate HTTP-specific settings
    if [ "$TRANSPORT" = "http" ]; then
        local port="${MCP_SERVER_PORT:-8080}"
        
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            log_error "Invalid port number: $port"
            return 2
        fi
        
        log_info "HTTP server port: $port"
    fi
    
    # Check configuration file if specified
    if [ -n "${MCP_CONFIG_FILE:-}" ]; then
        if [ ! -f "$MCP_CONFIG_FILE" ]; then
            log_error "Configuration file not found: $MCP_CONFIG_FILE"
            return 2
        fi
        
        log_info "Configuration file: $MCP_CONFIG_FILE"
        
        # Validate configuration file format
        if [[ "$MCP_CONFIG_FILE" == *.yaml ]] || [[ "$MCP_CONFIG_FILE" == *.yml ]]; then
            if command -v python &> /dev/null; then
                if ! python -c "import yaml; yaml.safe_load(open('$MCP_CONFIG_FILE'))" 2>/dev/null; then
                    log_error "Invalid YAML configuration file"
                    return 2
                fi
            fi
        elif [[ "$MCP_CONFIG_FILE" == *.json ]]; then
            if ! python -c "import json; json.load(open('$MCP_CONFIG_FILE'))" 2>/dev/null; then
                log_error "Invalid JSON configuration file"
                return 2
            fi
        fi
        
        log_success "Configuration file validated"
    fi
    
    log_success "Configuration validation passed"
    return 0
}

#------------------------------------------------------------------------------
# Database Migration (if needed)
#------------------------------------------------------------------------------

run_migrations() {
    log_debug "Checking for database migrations..."
    
    # Example: Run Alembic migrations if database is configured
    if [ -n "${MCP_DATABASE_URL:-}" ]; then
        log_info "Database URL configured, checking migrations..."
        
        if command -v alembic &> /dev/null; then
            log_info "Running database migrations..."
            cd "$APP_HOME" || return 1
            alembic upgrade head || {
                log_error "Database migration failed"
                return 1
            }
            log_success "Database migrations completed"
        else
            log_warning "Alembic not found, skipping migrations"
        fi
    else
        log_debug "No database configured, skipping migrations"
    fi
    
    return 0
}

#------------------------------------------------------------------------------
# Dependency Waiting (for multi-container deployments)
#------------------------------------------------------------------------------

wait_for_dependencies() {
    log_debug "Checking for external dependencies..."
    
    # Example: Wait for database
    if [ -n "${MCP_DATABASE_URL:-}" ]; then
        log_info "Waiting for database to be ready..."
        
        local max_attempts=30
        local attempt=1
        
        while [ $attempt -le $max_attempts ]; do
            if python -c "import psycopg2; psycopg2.connect('$MCP_DATABASE_URL')" 2>/dev/null; then
                log_success "Database is ready"
                break
            fi
            
            if [ $attempt -eq $max_attempts ]; then
                log_error "Database not ready after $max_attempts attempts"
                return 3
            fi
            
            log_info "Attempt $attempt/$max_attempts - waiting for database..."
            sleep 2
            attempt=$((attempt + 1))
        done
    fi
    
    # Example: Wait for Redis
    if [ -n "${MCP_REDIS_URL:-}" ]; then
        log_info "Waiting for Redis to be ready..."
        
        local max_attempts=30
        local attempt=1
        
        while [ $attempt -le $max_attempts ]; do
            if timeout 1 bash -c "echo > /dev/tcp/${MCP_REDIS_HOST:-localhost}/${MCP_REDIS_PORT:-6379}" 2>/dev/null; then
                log_success "Redis is ready"
                break
            fi
            
            if [ $attempt -eq $max_attempts ]; then
                log_error "Redis not ready after $max_attempts attempts"
                return 3
            fi
            
            log_info "Attempt $attempt/$max_attempts - waiting for Redis..."
            sleep 2
            attempt=$((attempt + 1))
        done
    fi
    
    return 0
}

#------------------------------------------------------------------------------
# Server Startup
#------------------------------------------------------------------------------

start_server() {
    log_info "Starting MCP server..."
    log_info "Transport: $TRANSPORT"
    log_info "Log level: $LOG_LEVEL"
    
    # Change to application directory
    cd "$APP_HOME" || {
        log_error "Failed to change to application directory"
        return 1
    }
    
    # Execute server with proper command
    if [ $# -gt 0 ]; then
        # Custom command provided
        log_info "Executing custom command: $*"
        exec "$@"
    else
        # Default server command
        log_info "Executing default server command..."
        exec python -m mcp_server.server
    fi
}

#------------------------------------------------------------------------------
# Cleanup
#------------------------------------------------------------------------------

cleanup() {
    log_debug "Performing cleanup..."
    
    # Remove PID file
    if [ -f "$PID_FILE" ]; then
        rm -f "$PID_FILE"
        log_debug "PID file removed"
    fi
    
    # Additional cleanup tasks
    # - Close connections
    # - Flush buffers
    # - Save state
    
    log_debug "Cleanup completed"
}

#------------------------------------------------------------------------------
# Health Check (internal)
#------------------------------------------------------------------------------

internal_health_check() {
    log_debug "Running internal health check..."
    
    # Check if server process is running
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log_debug "Server process is running (PID: $SERVER_PID)"
        return 0
    else
        log_error "Server process not running"
        return 1
    fi
}

#------------------------------------------------------------------------------
# Main Execution Flow
#------------------------------------------------------------------------------

main() {
    log_info "=========================================="
    log_info "  MCP Network Tools Server - Starting"
    log_info "=========================================="
    log_info "Version: 2.0.0"
    log_info "User: $(whoami)"
    log_info "Home: $APP_HOME"
    log_info "Transport: $TRANSPORT"
    log_info ""
    
    # Setup signal handlers first
    setup_signal_handlers
    
    # Run pre-flight checks
    log_info "Running pre-flight checks..."
    
    check_environment || exit $?
    check_directories || exit $?
    check_dependencies || exit $?
    validate_configuration || exit $?
    
    log_success "All pre-flight checks passed"
    log_info ""
    
    # Wait for external dependencies (if any)
    if [ "${WAIT_FOR_DEPENDENCIES:-false}" = "true" ]; then
        wait_for_dependencies || exit $?
    fi
    
    # Run database migrations (if configured)
    if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
        run_migrations || exit $?
    fi
    
    # Display startup information
    log_info "=========================================="
    log_info "  Configuration Summary"
    log_info "=========================================="
    log_info "Transport:        $TRANSPORT"
    log_info "Log Level:        $LOG_LEVEL"
    log_info "Log Directory:    $APP_LOG_DIR"
    log_info "Data Directory:   $APP_DATA_DIR"
    log_info "Config Directory: $APP_CONFIG_DIR"
    
    if [ "$TRANSPORT" = "http" ]; then
        log_info "HTTP Host:        ${MCP_SERVER_HOST:-0.0.0.0}"
        log_info "HTTP Port:        ${MCP_SERVER_PORT:-8080}"
    fi
    
    log_info "=========================================="
    log_info ""
    
    # Start server
    log_success "Starting server..."
    start_server "$@"
}

#------------------------------------------------------------------------------
# Entry Point
#------------------------------------------------------------------------------

# Execute main function with all arguments
main "$@"

#==============================================================================
# Exit Codes Reference
#==============================================================================
# 0   - Success
# 1   - General error
# 2   - Configuration error
# 3   - Dependency error
# 4   - Permission error
# 130 - Terminated by SIGINT (Ctrl+C)
# 143 - Terminated by SIGTERM (graceful shutdown)
#==============================================================================
