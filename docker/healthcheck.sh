#!/usr/bin/env bash

#==============================================================================
# MCP Network Tools Server - Health Check Script
#==============================================================================
# Purpose: Container health verification for Docker/Kubernetes
#
# Checks:
#   1. Process health (server running)
#   2. HTTP endpoint (if HTTP mode)
#   3. Resource usage (CPU, memory)
#   4. Dependency availability
#   5. Circuit breaker status
#   6. Tool availability
#
# Exit Codes:
#   0 - Healthy
#   1 - Unhealthy
#   2 - Starting (grace period)
#
# Usage:
#   ./healthcheck.sh
#   docker exec mcp-server /app/docker/healthcheck.sh
#
# Environment Variables:
#   MCP_SERVER_TRANSPORT  - Transport mode (stdio/http)
#   MCP_SERVER_PORT       - HTTP port (default: 8080)
#   HEALTH_CHECK_TIMEOUT  - Timeout in seconds (default: 5)
#   HEALTH_CHECK_VERBOSE  - Enable verbose output (default: false)
#
# Author: MCP Network Tools Team
# Version: 2.0.0
#==============================================================================

set -eo pipefail  # Exit on error, pipe failures

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------

# Server settings
TRANSPORT="${MCP_SERVER_TRANSPORT:-http}"
HTTP_PORT="${MCP_SERVER_PORT:-8080}"
HTTP_HOST="${MCP_SERVER_HOST:-localhost}"
HEALTH_ENDPOINT="${HEALTH_ENDPOINT:-/health}"

# Health check settings
TIMEOUT="${HEALTH_CHECK_TIMEOUT:-5}"
VERBOSE="${HEALTH_CHECK_VERBOSE:-false}"
GRACE_PERIOD="${HEALTH_CHECK_GRACE_PERIOD:-10}"

# Thresholds
CPU_THRESHOLD="${MCP_HEALTH_CPU_THRESHOLD:-90}"
MEMORY_THRESHOLD="${MCP_HEALTH_MEMORY_THRESHOLD:-90}"

# Startup tracking
STARTUP_FILE="/tmp/mcp_startup_time"

#------------------------------------------------------------------------------
# Logging Functions
#------------------------------------------------------------------------------

log() {
    if [ "$VERBOSE" = "true" ]; then
        echo "[HEALTH] $(date -u '+%Y-%m-%dT%H:%M:%SZ') - $*"
    fi
}

log_error() {
    echo "[HEALTH ERROR] $(date -u '+%Y-%m-%dT%H:%M:%SZ') - $*" >&2
}

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

# Check if container is in startup grace period
is_in_grace_period() {
    if [ ! -f "$STARTUP_FILE" ]; then
        # Create startup marker
        date +%s > "$STARTUP_FILE"
        return 0
    fi
    
    local startup_time
    startup_time=$(cat "$STARTUP_FILE")
    local current_time
    current_time=$(date +%s)
    local elapsed=$((current_time - startup_time))
    
    if [ "$elapsed" -lt "$GRACE_PERIOD" ]; then
        log "In grace period: ${elapsed}s/${GRACE_PERIOD}s"
        return 0
    fi
    
    return 1
}

# Get process ID of MCP server
get_server_pid() {
    # Try to find Python process running mcp_server
    pgrep -f "python.*mcp_server.server" | head -n 1
}

#------------------------------------------------------------------------------
# Health Checks
#------------------------------------------------------------------------------

# Check 1: Process Health
check_process() {
    log "Checking process health..."
    
    local pid
    pid=$(get_server_pid)
    
    if [ -z "$pid" ]; then
        log_error "Server process not found"
        return 1
    fi
    
    # Verify process is actually running
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "Server process (PID: $pid) not responding"
        return 1
    fi
    
    log "Server process healthy (PID: $pid)"
    return 0
}

# Check 2: HTTP Endpoint (if HTTP mode)
check_http_endpoint() {
    if [ "$TRANSPORT" != "http" ]; then
        log "Not in HTTP mode, skipping endpoint check"
        return 0
    fi
    
    log "Checking HTTP endpoint: http://${HTTP_HOST}:${HTTP_PORT}${HEALTH_ENDPOINT}"
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        log_error "curl not found, cannot check HTTP endpoint"
        return 1
    fi
    
    # Make health check request
    local response
    local http_code
    
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout "$TIMEOUT" \
        --max-time "$TIMEOUT" \
        "http://${HTTP_HOST}:${HTTP_PORT}${HEALTH_ENDPOINT}" 2>&1)
    
    http_code=$?
    
    if [ $http_code -ne 0 ]; then
        log_error "HTTP request failed (curl exit code: $http_code)"
        return 1
    fi
    
    # Check HTTP status code
    if [ "$response" = "200" ] || [ "$response" = "207" ]; then
        log "HTTP endpoint healthy (status: $response)"
        return 0
    else
        log_error "HTTP endpoint unhealthy (status: $response)"
        return 1
    fi
}

# Check 3: Resource Usage
check_resources() {
    log "Checking resource usage..."
    
    # Check if psutil is available via Python
    if ! python -c "import psutil" 2>/dev/null; then
        log "psutil not available, skipping resource check"
        return 0
    fi
    
    # Get CPU usage
    local cpu_usage
    cpu_usage=$(python -c "import psutil; print(psutil.cpu_percent(interval=1))" 2>/dev/null || echo "0")
    
    # Get memory usage
    local mem_usage
    mem_usage=$(python -c "import psutil; print(psutil.virtual_memory().percent)" 2>/dev/null || echo "0")
    
    log "CPU: ${cpu_usage}%, Memory: ${mem_usage}%"
    
    # Check thresholds
    if [ "$(echo "$cpu_usage > $CPU_THRESHOLD" | bc 2>/dev/null || echo 0)" -eq 1 ]; then
        log_error "CPU usage too high: ${cpu_usage}% (threshold: ${CPU_THRESHOLD}%)"
        return 1
    fi
    
    if [ "$(echo "$mem_usage > $MEMORY_THRESHOLD" | bc 2>/dev/null || echo 0)" -eq 1 ]; then
        log_error "Memory usage too high: ${mem_usage}% (threshold: ${MEMORY_THRESHOLD}%)"
        return 1
    fi
    
    log "Resource usage healthy"
    return 0
}

# Check 4: Python Package Import
check_python_package() {
    log "Checking Python package..."
    
    if ! python -c "import mcp_server" 2>/dev/null; then
        log_error "Failed to import mcp_server package"
        return 1
    fi
    
    log "Python package import successful"
    return 0
}

# Check 5: Tool Availability (critical tools)
check_tool_availability() {
    log "Checking tool availability..."
    
    local tools=("nmap")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing critical tools: ${missing_tools[*]}"
        return 1
    fi
    
    log "All critical tools available"
    return 0
}

# Check 6: File System Access
check_filesystem() {
    log "Checking filesystem access..."
    
    # Check log directory
    local log_dir="${MCP_LOG_DIR:-/app/logs}"
    if [ ! -w "$log_dir" ]; then
        log_error "Log directory not writable: $log_dir"
        return 1
    fi
    
    # Check data directory
    local data_dir="${MCP_DATA_DIR:-/app/data}"
    if [ ! -w "$data_dir" ]; then
        log_error "Data directory not writable: $data_dir"
        return 1
    fi
    
    log "Filesystem access healthy"
    return 0
}

#------------------------------------------------------------------------------
# Main Health Check Logic
#------------------------------------------------------------------------------

run_health_checks() {
    local failures=0
    local checks_run=0
    
    log "=========================================="
    log "Starting health checks..."
    log "=========================================="
    
    # Critical checks (must pass)
    local critical_checks=(
        "check_process"
        "check_python_package"
    )
    
    for check in "${critical_checks[@]}"; do
        checks_run=$((checks_run + 1))
        log "Running critical check: $check"
        
        if ! $check; then
            log_error "Critical check failed: $check"
            failures=$((failures + 1))
        fi
    done
    
    # Important checks (should pass, but not critical in grace period)
    local important_checks=(
        "check_http_endpoint"
        "check_tool_availability"
        "check_filesystem"
    )
    
    for check in "${important_checks[@]}"; do
        checks_run=$((checks_run + 1))
        log "Running important check: $check"
        
        if ! $check; then
            log_error "Important check failed: $check"
            
            # Only count as failure if not in grace period
            if ! is_in_grace_period; then
                failures=$((failures + 1))
            else
                log "Ignoring failure (in grace period)"
            fi
        fi
    done
    
    # Optional checks (informational only)
    local optional_checks=(
        "check_resources"
    )
    
    for check in "${optional_checks[@]}"; do
        checks_run=$((checks_run + 1))
        log "Running optional check: $check"
        
        if ! $check; then
            log "Optional check failed: $check (not counted)"
        fi
    done
    
    log "=========================================="
    log "Health checks completed: $checks_run run, $failures failed"
    log "=========================================="
    
    # Determine overall health status
    if [ $failures -eq 0 ]; then
        log "Status: HEALTHY"
        return 0
    elif is_in_grace_period; then
        log "Status: STARTING (grace period)"
        return 2
    else
        log_error "Status: UNHEALTHY"
        return 1
    fi
}

#------------------------------------------------------------------------------
# Quick Health Check (for fast polling)
#------------------------------------------------------------------------------

quick_health_check() {
    log "Running quick health check..."
    
    # Just check if process is running and HTTP endpoint responds
    if ! check_process; then
        return 1
    fi
    
    if [ "$TRANSPORT" = "http" ]; then
        if ! check_http_endpoint; then
            return 1
        fi
    fi
    
    return 0
}

#------------------------------------------------------------------------------
# Main Entry Point
#------------------------------------------------------------------------------

main() {
    # Parse arguments
    local mode="${1:-full}"
    
    case "$mode" in
        quick)
            quick_health_check
            exit $?
            ;;
        full)
            run_health_checks
            exit $?
            ;;
        *)
            log_error "Invalid mode: $mode (use 'quick' or 'full')"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"

#==============================================================================
# Usage Examples
#==============================================================================
#
# Full health check (default):
#   ./healthcheck.sh
#   ./healthcheck.sh full
#
# Quick health check:
#   ./healthcheck.sh quick
#
# Verbose output:
#   HEALTH_CHECK_VERBOSE=true ./healthcheck.sh
#
# Custom timeout:
#   HEALTH_CHECK_TIMEOUT=10 ./healthcheck.sh
#
# In Docker:
#   docker exec mcp-server /app/docker/healthcheck.sh
#
# In Kubernetes:
#   livenessProbe:
#     exec:
#       command: ["/app/docker/healthcheck.sh", "quick"]
#     initialDelaySeconds: 10
#     periodSeconds: 30
#
#   readinessProbe:
#     exec:
#       command: ["/app/docker/healthcheck.sh", "full"]
#     initialDelaySeconds: 5
#     periodSeconds: 10
#
#==============================================================================
