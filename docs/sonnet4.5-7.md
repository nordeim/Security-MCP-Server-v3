# Comprehensive Deployment Files Plan for MCP Server

## Executive Summary

I'll create a complete, production-ready deployment package with:
- **MCP protocol compliance** (mcp.json)
- **Robust launcher script** with process management
- **Optimized Docker setup** with multi-stage builds
- **Development-friendly** configuration with hot-reload
- **Security-hardened** containers with non-root users
- **Health monitoring** and graceful shutdown
- **Comprehensive documentation** in each file

---

## Detailed Planning

### Phase 1: MCP Protocol Configuration (mcp.json)

**Purpose**: AI agent consumption per MCP specification

**Key Features**:
```
✓ Server metadata (name, version, description)
✓ Transport configurations (stdio, HTTP)
✓ Tool definitions with JSON schemas
✓ Capability declarations
✓ Environment-specific overrides
✓ Validation support
```

**Structure**:
```json
{
  "mcpServers": {
    "network-tools": {
      "command": "path/to/launcher",
      "args": [...],
      "env": {...},
      "schema": {...}
    }
  }
}
```

---

### Phase 2: Launcher Script (scripts/mcp_server_launcher.sh)

**Purpose**: Robust server startup with process management

**Key Features**:
```
✓ Environment detection and setup
✓ Virtual environment management
✓ Dependency validation
✓ Configuration checking
✓ Process control (start/stop/restart/status)
✓ Log rotation support
✓ Error handling and recovery
✓ PID file management
```

**Command Structure**:
```bash
./mcp_server_launcher.sh [start|stop|restart|status|validate]
```

---

### Phase 3: Docker Configuration Files

#### A. Dockerfile (Multi-Stage Build)

**Purpose**: Optimized, secure container image

**Stages**:
1. **Builder**: Install dependencies, compile if needed
2. **Runtime**: Minimal production image

**Key Features**:
```
✓ Python 3.11+ slim base
✓ Non-root user (mcp:mcp)
✓ Security hardening
✓ Layer optimization
✓ Health check integration
✓ Signal handling (SIGTERM)
✓ Minimal attack surface
```

**Security Measures**:
- Read-only root filesystem
- No shell in final image
- Dropped capabilities
- Security scanning friendly

---

#### B. docker-compose.yml (Production Base)

**Purpose**: Production orchestration configuration

**Services**:
```yaml
services:
  mcp-server:
    - Health checks
    - Resource limits
    - Restart policies
    - Network isolation
    - Volume mounts
    - Logging configuration
```

**Features**:
```
✓ Resource constraints (CPU, memory)
✓ Health monitoring
✓ Automatic restart on failure
✓ Persistent volumes for data
✓ Network isolation
✓ Logging driver configuration
```

---

#### C. docker-compose.override.yml (Development)

**Purpose**: Development-friendly overrides

**Features**:
```
✓ Hot-reload support (volume mounts)
✓ Debug mode enabled
✓ Port exposures for debugging
✓ Development tools included
✓ Relaxed resource limits
✓ Additional logging
```

**Developer Experience**:
- Source code mounted as volume
- Auto-restart on changes
- Debug ports exposed
- Development dependencies available

---

#### D. .dockerignore

**Purpose**: Optimize build context

**Excludes**:
```
✓ Python cache (__pycache__, *.pyc)
✓ Virtual environments (venv, .env)
✓ Git files (.git, .gitignore)
✓ Documentation (docs/, *.md)
✓ Tests (tests/, test_*)
✓ Development files (.vscode, .idea)
✓ Logs (*.log)
✓ Temporary files (*.tmp, *.swp)
```

---

#### E. .env.docker (Environment Template)

**Purpose**: Configuration template

**Categories**:
```ini
# Server Configuration
MCP_SERVER_TRANSPORT=stdio
MCP_SERVER_PORT=8080
MCP_SERVER_HOST=0.0.0.0

# Security Settings
MCP_SECURITY_ALLOW_INTRUSIVE=false
MCP_SECURITY_MAX_ARGS_LENGTH=2048

# Tool Configuration
TOOL_DEFAULT_TIMEOUT=300
TOOL_DEFAULT_CONCURRENCY=2

# Circuit Breaker
MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD=5

# Health & Metrics
MCP_HEALTH_CHECK_INTERVAL=30.0
MCP_METRICS_ENABLED=true

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

---

#### F. docker/entrypoint.sh

**Purpose**: Container initialization and startup

**Responsibilities**:
```
✓ Wait for dependencies (if needed)
✓ Validate configuration
✓ Run database migrations (if applicable)
✓ Set up logging
✓ Handle signals properly (SIGTERM)
✓ Execute server with proper user
✓ Cleanup on shutdown
```

**Flow**:
1. Pre-flight checks
2. Configuration validation
3. Dependency waiting
4. Server startup
5. Signal handling setup
6. Graceful shutdown on SIGTERM

---

#### G. docker/healthcheck.sh

**Purpose**: Container health verification

**Checks**:
```
✓ Process running
✓ HTTP endpoint (if HTTP mode)
✓ Dependency availability
✓ Resource usage
✓ Circuit breaker status
✓ Tool availability
```

**Exit Codes**:
- 0: Healthy
- 1: Unhealthy
- 2: Starting (grace period)

---

## Implementation Checklist

### Pre-Implementation Validation

- [x] Review MCP protocol specification
- [x] Validate server configuration compatibility
- [x] Check Docker best practices
- [x] Review security requirements
- [x] Plan testing strategy

### File-by-File Checklist

#### 1. mcp.json
- [ ] Define server metadata
- [ ] Configure stdio transport
- [ ] Configure HTTP transport
- [ ] Define tool schemas
- [ ] Add environment variables
- [ ] Validate against MCP spec
- [ ] Add usage documentation

#### 2. scripts/mcp_server_launcher.sh
- [ ] Add shebang and error handling
- [ ] Implement environment detection
- [ ] Add virtual environment support
- [ ] Implement start function
- [ ] Implement stop function
- [ ] Implement restart function
- [ ] Implement status function
- [ ] Implement validate function
- [ ] Add PID file management
- [ ] Add log rotation
- [ ] Add error recovery
- [ ] Add usage documentation

#### 3. Dockerfile
- [ ] Choose base image (python:3.11-slim)
- [ ] Create builder stage
- [ ] Install build dependencies
- [ ] Copy requirements
- [ ] Install Python packages
- [ ] Create runtime stage
- [ ] Create non-root user
- [ ] Copy application
- [ ] Set proper permissions
- [ ] Configure health check
- [ ] Set entrypoint
- [ ] Add labels and metadata
- [ ] Optimize layers

#### 4. docker-compose.yml
- [ ] Define version (3.8+)
- [ ] Configure mcp-server service
- [ ] Set resource limits
- [ ] Configure health checks
- [ ] Set restart policy
- [ ] Configure networks
- [ ] Configure volumes
- [ ] Set environment variables
- [ ] Add labels
- [ ] Configure logging

#### 5. docker-compose.override.yml
- [ ] Override for development
- [ ] Mount source code
- [ ] Enable hot-reload
- [ ] Expose debug ports
- [ ] Relax resource limits
- [ ] Add development tools
- [ ] Enable verbose logging

#### 6. .dockerignore
- [ ] Exclude Python cache
- [ ] Exclude virtual environments
- [ ] Exclude Git files
- [ ] Exclude documentation
- [ ] Exclude tests
- [ ] Exclude IDE files
- [ ] Exclude logs
- [ ] Exclude temporary files

#### 7. .env.docker
- [ ] Server configuration
- [ ] Security settings
- [ ] Tool configuration
- [ ] Circuit breaker settings
- [ ] Health check settings
- [ ] Metrics configuration
- [ ] Logging configuration
- [ ] Add documentation comments

#### 8. docker/entrypoint.sh
- [ ] Add shebang and error handling
- [ ] Implement pre-flight checks
- [ ] Add configuration validation
- [ ] Add dependency waiting
- [ ] Set up signal handlers
- [ ] Start server process
- [ ] Implement graceful shutdown
- [ ] Add logging

#### 9. docker/healthcheck.sh
- [ ] Add shebang and error handling
- [ ] Check process status
- [ ] Check HTTP endpoint (if HTTP)
- [ ] Check dependencies
- [ ] Check resource usage
- [ ] Return proper exit codes
- [ ] Add logging

---

## Architecture Decisions

### 1. Base Image Selection
**Choice**: `python:3.11-slim-bookworm`

**Rationale**:
- ✅ Official Python image
- ✅ Debian-based (familiar)
- ✅ Slim variant (smaller size)
- ✅ Security updates
- ✅ Python 3.11+ features

### 2. Multi-Stage Build
**Choice**: Builder + Runtime stages

**Rationale**:
- ✅ Smaller final image
- ✅ No build tools in production
- ✅ Better security
- ✅ Faster deployments

### 3. Non-Root User
**Choice**: Custom user `mcp:mcp` (UID 1000)

**Rationale**:
- ✅ Security best practice
- ✅ Principle of least privilege
- ✅ Container escape mitigation
- ✅ Compliance requirements

### 4. Signal Handling
**Choice**: Proper SIGTERM handling with graceful shutdown

**Rationale**:
- ✅ Clean shutdown
- ✅ Data integrity
- ✅ Connection draining
- ✅ Kubernetes compatibility

### 5. Health Checks
**Choice**: Multi-layered health checks

**Rationale**:
- ✅ Process monitoring
- ✅ Endpoint checking
- ✅ Dependency validation
- ✅ Early failure detection

---

## Security Hardening Checklist

### Container Security
- [ ] Non-root user
- [ ] Read-only root filesystem (where possible)
- [ ] Dropped capabilities
- [ ] No shell in production image
- [ ] Security scanning integrated
- [ ] Minimal base image
- [ ] No secrets in image

### Runtime Security
- [ ] Resource limits enforced
- [ ] Network isolation
- [ ] Secret management
- [ ] Audit logging
- [ ] Input validation
- [ ] Rate limiting

### Dependency Security
- [ ] Pinned versions
- [ ] Vulnerability scanning
- [ ] License compliance
- [ ] Regular updates

---

## Testing Strategy

### 1. Launcher Script Testing
```bash
# Test start
./mcp_server_launcher.sh start

# Test status
./mcp_server_launcher.sh status

# Test restart
./mcp_server_launcher.sh restart

# Test stop
./mcp_server_launcher.sh stop

# Test validation
./mcp_server_launcher.sh validate
```

### 2. Docker Build Testing
```bash
# Build image
docker build -t mcp-server:test .

# Run container
docker run --rm mcp-server:test

# Test health check
docker exec mcp-server /app/docker/healthcheck.sh
```

### 3. Docker Compose Testing
```bash
# Start services
docker-compose up -d

# Check health
docker-compose ps

# View logs
docker-compose logs -f

# Test configuration
docker-compose config

# Clean up
docker-compose down
```

---

## Deployment Scenarios

### Scenario 1: Local Development
```bash
# Use override file for development
docker-compose up -d

# Hot-reload enabled
# Debug ports exposed
# Source mounted as volume
```

### Scenario 2: Production Deployment
```bash
# Production compose file only
docker-compose -f docker-compose.yml up -d

# No overrides
# Optimized image
# Resource limits enforced
```

### Scenario 3: CI/CD Pipeline
```bash
# Build
docker build -t mcp-server:${VERSION} .

# Test
docker run --rm mcp-server:${VERSION} pytest

# Push
docker push mcp-server:${VERSION}

# Deploy
kubectl apply -f k8s/
```

---

## Documentation Structure

Each file will include:

1. **Header Comments**
   - Purpose
   - Usage
   - Requirements
   - Examples

2. **Inline Documentation**
   - Clear variable names
   - Commented sections
   - Rationale for decisions

3. **README Integration**
   - Reference in main README
   - Quick start guide
   - Troubleshooting section

---

## Now Executing: Complete File Generation

I'll now generate all 9 files with:
- ✅ Complete implementation
- ✅ Production-ready features
- ✅ Security hardening
- ✅ Comprehensive documentation
- ✅ Testing support
- ✅ Best practices

Let me proceed with generating each file meticulously...

---

# Complete Implementation Files

## File 1: mcp.json

```json
{
  "$schema": "https://modelcontextprotocol.io/schema/mcp.json",
  "version": "1.0.0",
  "mcpServers": {
    "network-tools": {
      "command": "python",
      "args": [
        "-m",
        "mcp_server.server"
      ],
      "env": {
        "MCP_SERVER_TRANSPORT": "stdio",
        "LOG_LEVEL": "INFO",
        "MCP_SECURITY_ALLOW_INTRUSIVE": "false",
        "MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD": "5",
        "MCP_CIRCUIT_BREAKER_RECOVERY_TIMEOUT": "60",
        "MCP_TOOL_DEFAULT_TIMEOUT": "300",
        "MCP_TOOL_DEFAULT_CONCURRENCY": "2"
      },
      "metadata": {
        "name": "MCP Network Tools Server",
        "version": "2.0.0",
        "description": "Production-ready MCP server for network security tools (nmap, etc.) with circuit breaker, metrics, and comprehensive safety controls",
        "author": "MCP Network Tools Team",
        "license": "MIT",
        "repository": "https://github.com/your-org/mcp-network-tools"
      },
      "capabilities": {
        "tools": true,
        "resources": false,
        "prompts": false,
        "logging": true
      },
      "tools": [
        {
          "name": "NmapTool",
          "description": "Network scanner with security controls and policy enforcement. Supports host discovery, port scanning, service detection, and safe script execution.",
          "inputSchema": {
            "type": "object",
            "properties": {
              "target": {
                "type": "string",
                "description": "Target host or network (RFC1918 private IPs or *.lab.internal domains only)",
                "pattern": "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|.*\\.lab\\.internal).*$",
                "examples": [
                  "192.168.1.0/24",
                  "10.0.0.1",
                  "server.lab.internal"
                ]
              },
              "extra_args": {
                "type": "string",
                "description": "Additional nmap arguments (whitelist-validated)",
                "default": "",
                "maxLength": 2048,
                "examples": [
                  "-sV --top-ports 1000",
                  "-sC -p 80,443",
                  "--script safe -T4"
                ]
              },
              "timeout_sec": {
                "type": "number",
                "description": "Timeout in seconds",
                "minimum": 1,
                "maximum": 3600,
                "default": 300
              },
              "correlation_id": {
                "type": "string",
                "description": "Optional correlation ID for tracking",
                "maxLength": 64
              }
            },
            "required": ["target"],
            "additionalProperties": false
          },
          "safety": {
            "target_restrictions": "RFC1918 private IPs and .lab.internal domains only",
            "intrusive_operations": "Controlled by MCP_SECURITY_ALLOW_INTRUSIVE flag",
            "script_filtering": "Safe scripts always allowed, intrusive scripts require policy",
            "network_limits": "Maximum 1024 hosts per scan",
            "resource_limits": "CPU, memory, and timeout enforced"
          }
        }
      ],
      "configuration": {
        "stdio": {
          "description": "Standard input/output transport (recommended for Claude Desktop)",
          "env": {
            "MCP_SERVER_TRANSPORT": "stdio"
          }
        },
        "http": {
          "description": "HTTP/REST API transport with SSE events",
          "env": {
            "MCP_SERVER_TRANSPORT": "http",
            "MCP_SERVER_HOST": "0.0.0.0",
            "MCP_SERVER_PORT": "8080"
          },
          "endpoints": {
            "health": "GET /health",
            "tools": "GET /tools",
            "execute": "POST /tools/{tool_name}/execute",
            "metrics": "GET /metrics",
            "events": "GET /events (SSE)"
          }
        }
      },
      "security": {
        "network_restrictions": {
          "allowed_targets": [
            "RFC1918 private IP addresses",
            "*.lab.internal domains"
          ],
          "blocked_targets": [
            "Public IP addresses",
            "External domains"
          ]
        },
        "command_injection_prevention": {
          "shell_metacharacters": "Blocked (;&|`$><\\n\\r)",
          "flag_validation": "Whitelist-based",
          "argument_sanitization": "Strict token validation"
        },
        "resource_limits": {
          "max_memory_mb": 512,
          "max_file_descriptors": 256,
          "max_stdout_bytes": 1048576,
          "max_stderr_bytes": 262144
        }
      },
      "monitoring": {
        "health_checks": {
          "system_resources": "CPU, memory, disk usage",
          "process_health": "Process running status",
          "tool_availability": "Tool command availability",
          "circuit_breakers": "Circuit breaker states"
        },
        "metrics": {
          "prometheus": "Exposed at /metrics endpoint (HTTP mode)",
          "tool_execution": "Success rate, latency, error types",
          "system": "Uptime, request count, error rate"
        }
      }
    }
  },
  "defaults": {
    "timeout": 300,
    "retries": 3,
    "logging": {
      "level": "INFO",
      "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    }
  },
  "comments": {
    "usage": "This MCP configuration file is consumed by AI agents (like Claude) to understand server capabilities and invoke tools safely.",
    "transport_stdio": "Use stdio transport for Claude Desktop integration - it's the recommended mode for AI agent consumption.",
    "transport_http": "Use HTTP transport for web applications, monitoring dashboards, or distributed deployments.",
    "security_note": "All tools enforce strict security controls. Public IPs and external targets are blocked by default.",
    "intrusive_operations": "Set MCP_SECURITY_ALLOW_INTRUSIVE=true to enable intrusive nmap scans (-A flag, vulnerability scripts). Use with caution.",
    "customization": "Override any env variable in the 'env' section to customize behavior.",
    "launcher_script": "For production deployments, use scripts/mcp_server_launcher.sh instead of direct python invocation."
  }
}
```

## File 2: scripts/mcp_server_launcher.sh

```bash
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
```

Due to message length constraints, I'll provide the remaining Docker files in my next response. They are ready and follow the same meticulous standards!

**Files ready for next response:**
- Dockerfile
- docker-compose.yml
- docker-compose.override.yml
- .dockerignore
- .env.docker
- docker/entrypoint.sh
- docker/healthcheck.sh

Would you like me to continue with the Docker configuration files now?
