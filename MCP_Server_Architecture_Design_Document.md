# MCP Server Architecture Design Document
**Version:** 2.0  
**Last Updated:** 2024  
**Status:** Production-Ready

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Core Components](#core-components)
4. [Design Patterns & Principles](#design-patterns--principles)
5. [Security Architecture](#security-architecture)
6. [Reliability & Resilience](#reliability--resilience)
7. [Transport Layer](#transport-layer)
8. [Data Flow](#data-flow)
9. [Configuration System](#configuration-system)
10. [Monitoring & Observability](#monitoring--observability)
11. [Extension Points](#extension-points)
12. [Deployment Considerations](#deployment-considerations)

---

## Executive Summary

The MCP (Model Context Protocol) Server is a production-ready, extensible framework for building secure, monitored network diagnostic tools accessible via dual transport mechanisms (stdio and HTTP). The architecture emphasizes:

- **Security-first design** with multi-layered validation and sandboxing
- **Resilience** through circuit breakers, rate limiting, and graceful degradation
- **Observability** via comprehensive metrics and health monitoring
- **Extensibility** through abstract base classes and plugin-style tool discovery
- **Production readiness** with resource limits, timeout controls, and error recovery

The system is designed to be integrated with AI assistants (like Claude Desktop via stdio) or accessed programmatically via HTTP APIs.

---

## Architecture Overview

### High-Level Architecture
┌─────────────────────────────────────────────────────────────┐
│ Client Layer │
│ ┌──────────────┐ ┌──────────────┐ │
│ │ Claude Desktop│ │ HTTP Clients │ │
│ │ (stdio) │ │ (REST API) │ │
│ └──────┬───────┘ └───────┬──────┘ │
└─────────┼──────────────────────────────┼───────────────────┘
│ │
│ │
┌─────────▼───────────────────────────────▼───────────────────┐
│ Transport Layer │
│ ┌──────────────┐ ┌──────────────┐ │
│ │ stdio_server │ │ FastAPI │ │
│ │ (MCP SDK) │ │ (HTTP/SSE) │ │
│ └──────┬───────┘ └───────┬──────┘ │
└─────────┼──────────────────────────────┼───────────────────┘
│ │
│ ┌─────────────────────┘
│ │
┌─────────▼─────────▼─────────────────────────────────────────┐
│ EnhancedMCPServer (Orchestrator) │
│ ┌──────────────────────────────────────────────────────┐ │
│ │ • Tool Registry (enable/disable/discovery) │ │
│ │ • Health Manager (monitoring) │ │
│ │ • Metrics Manager (Prometheus/JSON) │ │
│ │ • Rate Limiter (token bucket) │ │
│ │ • Shutdown Coordinator (graceful cleanup) │ │
│ └──────────────────────────────────────────────────────┘ │
└──────────────────────────┬───────────────────────────────────┘
│
┌──────────────────────────▼───────────────────────────────────┐
│ Tool Layer │
│ ┌────────────┐ ┌────────────┐ ┌────────────┐ │
│ │ NmapTool │ │ TracertTool│ │ CustomTool │ ... │
│ │ │ │ │ │ │ │
│ └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ │
│ │ │ │ │
│ └───────────────┴───────────────┘ │
│ │ │
│ ┌───────────▼──────────────┐ │
│ │ MCPBaseTool (Abstract) │ │
│ │ • Input Validation │ │
│ │ • Circuit Breaker │ │
│ │ • Metrics Collection │ │
│ │ • Resource Limiting │ │
│ │ • Error Handling │ │
│ │ • Concurrency Control │ │
│ └──────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘

text


### Layer Responsibilities

#### 1. **Client Layer**
- Claude Desktop: Uses stdio transport for seamless AI integration
- HTTP Clients: RESTful API for programmatic access, web UIs, monitoring

#### 2. **Transport Layer**
- **stdio_server**: MCP SDK-based bidirectional JSON-RPC over stdin/stdout
- **FastAPI**: HTTP endpoints with SSE (Server-Sent Events) for real-time updates

#### 3. **Orchestrator Layer (EnhancedMCPServer)**
- Tool lifecycle management (discovery, registration, enable/disable)
- Cross-cutting concerns (health, metrics, rate limiting)
- Transport abstraction and routing
- Graceful shutdown coordination

#### 4. **Tool Layer**
- Concrete implementations (NmapTool, TracertTool, etc.)
- Inherit security, resilience, and observability from base class
- Focus on tool-specific logic and validation

---

## Core Components

### 1. MCPBaseTool (Abstract Base Class)

**Location:** `mcp_server/base_tool.py`

**Purpose:** Foundation for all tools, providing production-ready infrastructure.

**Key Responsibilities:**
- **Input/Output Validation** via Pydantic models (v1/v2 compatible)
- **Security Enforcement**: Command sanitization, argument whitelisting, metacharacter blocking
- **Resource Management**: CPU, memory, file descriptor limits (Unix/Linux)
- **Concurrency Control**: Per-tool semaphores with automatic cleanup
- **Error Handling**: Typed errors with recovery suggestions and context
- **Execution Pipeline**: Async subprocess spawning with timeout and truncation
- **Metrics Integration**: Optional Prometheus metrics collection
- **Circuit Breaker**: Optional failure threshold protection

**State Machine:**
Input Received → Validation → Semaphore Acquire → Circuit Breaker Check →
Command Resolution → Argument Sanitization → Resource Limit Setup →
Subprocess Spawn → Timeout Monitor → Output Capture → Metrics Recording →
Error Handling → Cleanup → Output Return

text


**Critical Features:**

1. **Pydantic Compatibility Layer**
   ```python
   # Supports both Pydantic v1 and v2
   if _PD_V2:
       @field_validator("target", mode='after')
   else:
       @field_validator("target")
Thread-Safe Semaphore Registry

Python

# Per-event-loop semaphore with weak references for cleanup
_semaphore_registry: Dict[str, asyncio.Semaphore]
_loop_refs: weakref.WeakValueDictionary
Security Validation

Python

# Target must be RFC1918 or .lab.internal
_is_private_or_lab(value: str) -> bool

# Block shell metacharacters
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")
Resource Limits (Unix/Linux only)

Python

resource.setrlimit(resource.RLIMIT_CPU, ...)
resource.setrlimit(resource.RLIMIT_AS, ...)  # Memory
resource.setrlimit(resource.RLIMIT_NOFILE, ...)  # FDs
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # No core dumps
Extension Points:

Subclass must define: command_name, optionally allowed_flags
Override _execute_tool() for custom validation/optimization
Override get_tool_info() for tool-specific metadata
2. EnhancedMCPServer (Orchestrator)
Location: mcp_server/server.py

Purpose: Central coordinator managing tools, transports, and cross-cutting concerns.

Key Responsibilities:

Tool discovery via package scanning (pkgutil)
Tool registry with enable/disable functionality
Transport abstraction (stdio vs HTTP)
Health monitoring via HealthCheckManager
Metrics aggregation via MetricsManager
Rate limiting (token bucket algorithm)
Graceful shutdown with background task cleanup
Signal handling (SIGINT, SIGTERM)
Architecture Patterns:

Tool Discovery Pattern

Python

# Scan package for MCPBaseTool subclasses
_load_tools_from_package(package_path, include, exclude)

# Pattern-based exclusion
EXCLUDED_PREFIXES = {'Test', 'Mock', 'Abstract', '_', 'Example'}
EXCLUDED_SUFFIXES = {'Base', 'Mixin', 'Interface'}
Registry Pattern

Python

class ToolRegistry:
    tools: Dict[str, MCPBaseTool]  # All registered tools
    enabled_tools: Set[str]         # Currently enabled subset
Health Check Integration

Python

# Per-tool health checks
HealthCheckManager.register_check(
    name=f"tool_{tool_name}",
    check_func=self._create_tool_health_check(tool),
    priority=HealthCheckPriority.INFORMATIONAL
)
Background Task Management

Python

_background_tasks: Set[asyncio.Task]

# Auto-cleanup on task completion
task.add_done_callback(self._background_tasks.discard)
Dual Transport Support:

stdio Transport: For Claude Desktop integration
Uses MCP SDK's stdio_server() context manager
JSON-RPC over stdin/stdout
Graceful shutdown via shutdown_event
HTTP Transport: For programmatic/web access
FastAPI with CORS middleware
RESTful endpoints: /tools, /health, /metrics
SSE endpoint /events for real-time updates
Rate limiting per client IP + tool combination
3. ToolRegistry
Purpose: Centralized tool management with lifecycle control.

Features:

Tool registration from discovery process
Enable/disable without restart
Filter-based inclusion/exclusion (env vars)
Tool information aggregation
Metrics/circuit breaker initialization per tool
API:

Python

registry.get_tool(tool_name) -> Optional[MCPBaseTool]
registry.get_enabled_tools() -> Dict[str, MCPBaseTool]
registry.enable_tool(tool_name)
registry.disable_tool(tool_name)
registry.get_tool_info() -> List[Dict[str, Any]]
4. RateLimiter
Algorithm: Token bucket with per-client tracking

Features:

Configurable rate (requests per time window)
Automatic cleanup of stale clients
Thread-safe operation (asyncio.Lock)
Client limit to prevent memory exhaustion
Implementation:

Python

# Token bucket: clients start with full allowance
allowance: Dict[str, float] = defaultdict(lambda: rate)

# Tokens regenerate over time
allowance[key] += time_passed * (rate / per)

# Request consumes a token
if allowance[key] < 1.0:
    return False  # Rate limited
allowance[key] -= 1.0
Configuration:

Python

RateLimiter(rate=10, per=60.0, max_clients=1000)
# 10 requests per 60 seconds, track up to 1000 clients
Design Patterns & Principles
1. Template Method Pattern
MCPBaseTool.run() orchestrates execution while allowing subclass customization:

Python

async def run(self, inp: ToolInput) -> ToolOutput:
    # Template method with hooks:
    # 1. Circuit breaker check
    # 2. Semaphore acquire
    # 3. _execute_tool() [customizable]
    # 4. Metrics recording
    # 5. Cleanup
2. Strategy Pattern
Transport strategies (stdio vs HTTP) are swapped at runtime:

Python

if transport == "stdio":
    await self.run_stdio_original()
elif transport == "http":
    await self.run_http_enhanced()
3. Registry Pattern
ToolRegistry centralizes tool management with runtime enable/disable.

4. Circuit Breaker Pattern
Optional per-tool circuit breakers prevent cascading failures:

Python

States: CLOSED → OPEN (failures exceed threshold) → HALF_OPEN → CLOSED
5. Fallback Pattern
Graceful degradation when optional dependencies missing:

Python

if not FASTAPI_AVAILABLE:
    # Fallback to stdio if MCP available
    # Or raise clear error with installation instructions
6. Observer Pattern
Health checks and metrics are observers of tool execution events.

7. Immutability for Safety
Python

BASE_ALLOWED_FLAGS: Tuple[str, ...]  # Immutable
allowed_flags property returns new list each time
Security Architecture
Multi-Layer Defense
Layer 1: Input Validation (Pydantic Models)
Python

class ToolInput(BaseModel):
    target: str  # Validated by _is_private_or_lab()
    extra_args: str  # Length and character class validation
Layer 2: Target Restriction
Python

_is_private_or_lab(value: str):
    # RFC1918 private IPs: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    # CIDR networks with same restrictions
    # .lab.internal hostnames with RFC-compliant format
Layer 3: Argument Sanitization
Python

# Block shell metacharacters
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")

# Whitelist allowed tokens
_TOKEN_ALLOWED = re.compile(r"^[A-Za-z0-9.:/=+,\-@%_]+$")

# Flag whitelisting per tool
allowed_flags: Optional[Sequence[str]]
Layer 4: Command Resolution
Python

# Only use shutil.which() - no shell execution
resolved_cmd = shutil.which(self.command_name)
Layer 5: Resource Sandboxing
Python

# Unix resource limits
RLIMIT_CPU, RLIMIT_AS (memory), RLIMIT_NOFILE, RLIMIT_CORE

# Process isolation
start_new_session=True  # Separate process group
Layer 6: Policy Enforcement (Tool-Specific)
Python

# NmapTool example
allow_intrusive: bool  # Gates -A flag and vuln scripts
_validate_and_filter_scripts()  # Category-based filtering
Security Principles
Least Privilege: Tools run with minimal permissions, resource limits
Defense in Depth: Multiple validation layers
Fail Secure: Errors block execution, don't bypass checks
Whitelist > Blacklist: Explicitly allowed flags/targets only
Immutable Defaults: Base configurations are constants
Audit Trail: Comprehensive logging of security events
Reliability & Resilience
Circuit Breaker Integration
Purpose: Prevent cascading failures from repeated tool failures

Configuration:

Python

circuit_breaker_failure_threshold: int = 5
circuit_breaker_recovery_timeout: float = 120.0
circuit_breaker_expected_exception: tuple = (Exception,)
State Machine:

text

CLOSED (normal) → [5 failures] → OPEN (fail fast) → 
[120s timeout] → HALF_OPEN (test) → [success] → CLOSED
                                   → [failure] → OPEN
Error Handling:

Python

if circuit_breaker.state == OPEN:
    return ToolOutput(error_type=ToolErrorType.CIRCUIT_BREAKER_OPEN)
Timeout Management
Multi-Level Timeouts:

Tool Default: default_timeout_sec (e.g., 600s for nmap)
Input Override: ToolInput.timeout_sec
Global Max: Environment variable MCP_DEFAULT_TIMEOUT_SEC
Enforcement:

Python

await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)

# On timeout: SIGKILL entire process group
os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
Concurrency Control
Per-Tool Semaphores:

Python

concurrency: ClassVar[int] = 2  # Max 2 concurrent executions

async with self._ensure_semaphore():
    # Execute tool
Automatic Cleanup:

Python

# Weak references to event loops
_loop_refs: weakref.WeakValueDictionary

# Clean dead loop semaphores
dead_keys = [k for k in registry if loop_id not in _loop_refs]
Graceful Shutdown
Shutdown Sequence:

Signal Handler sets shutdown_event
Health Manager stops monitoring
Metrics Manager performs cleanup
Background Tasks cancelled with gather(return_exceptions=True)
Circuit Breakers cleanup (if implemented)
Server waits for grace period before force-stop
Python

async def cleanup(self):
    await self.health_manager.stop_monitoring()
    await self.metrics_manager.cleanup()
    
    # Cancel background tasks
    for task in self._background_tasks:
        if not task.done():
            task.cancel()
    
    await asyncio.gather(*tasks, return_exceptions=True)
Error Recovery
Typed Errors with Context:

Python

class ToolErrorType(Enum):
    TIMEOUT, NOT_FOUND, VALIDATION_ERROR, EXECUTION_ERROR,
    RESOURCE_EXHAUSTED, CIRCUIT_BREAKER_OPEN, UNKNOWN

class ErrorContext:
    error_type: ToolErrorType
    message: str
    recovery_suggestion: str  # Actionable guidance
    metadata: Dict[str, Any]
Example Error:

Python

ErrorContext(
    error_type=ToolErrorType.VALIDATION_ERROR,
    message="Network range too large: 4096 addresses (max: 1024)",
    recovery_suggestion="Use /22 or smaller prefix (max 1024 hosts)",
    metadata={
        "suggested_cidr": "/22",
        "example": "192.168.0.0/22"
    }
)
Transport Layer
stdio Transport (MCP Protocol)
Use Case: Claude Desktop integration

Protocol: JSON-RPC 2.0 over stdin/stdout

Registration:

Python

server.register_tool(
    name="NmapTool",
    description="Network scanner",
    input_schema={...},  # JSON Schema
    handler=async_handler_function
)
Execution Flow:

text

Claude → JSON-RPC Request → stdio_server → handler → 
MCPBaseTool.run() → TextContent Response → Claude
Response Format:

Python

[TextContent(type="text", text=json.dumps(result.dict()))]
HTTP Transport (FastAPI)
Use Case: API access, monitoring, web UIs

Endpoints:

Endpoint	Method	Purpose
/	GET	Server info, available endpoints
/health	GET	Health checks (200/207/503)
/tools	GET	List tools with metadata
/tools/{name}/execute	POST	Execute tool (rate limited)
/tools/{name}/enable	POST	Enable tool
/tools/{name}/disable	POST	Disable tool
/metrics	GET	Prometheus or JSON metrics
/events	GET	SSE for real-time updates
/config	GET	Current config (redacted)
Rate Limiting:

Python

# Per client IP + tool combination
rate_limit_key = f"{client_ip}:{tool_name}"

if not await rate_limiter.check_rate_limit(rate_limit_key):
    raise HTTPException(status_code=429, detail={...})
SSE Events:

Python

# Real-time health and metrics
async def event_generator():
    while not disconnected:
        yield {"type": "health", "data": {...}}
        yield {"type": "metrics", "data": {...}}
        await asyncio.sleep(5)
Data Flow
Typical Execution Flow
text

1. CLIENT REQUEST
   ├─ stdio: JSON-RPC over stdin
   └─ HTTP: POST /tools/NmapTool/execute

2. TRANSPORT LAYER
   ├─ stdio: MCP handler → ToolInput
   └─ HTTP: FastAPI endpoint → Rate Limit → ToolInput

3. ORCHESTRATOR (EnhancedMCPServer)
   ├─ Tool lookup in registry
   ├─ Check if enabled
   └─ Route to tool instance

4. TOOL (e.g., NmapTool)
   ├─ MCPBaseTool.run(inp)
   │  ├─ Increment active execution counter
   │  ├─ Check circuit breaker state
   │  ├─ Acquire semaphore (concurrency control)
   │  └─ Call _execute_tool(inp)
   │
   ├─ NmapTool._execute_tool(inp)
   │  ├─ Validate nmap-specific requirements
   │  ├─ Parse and validate arguments
   │  ├─ Optimize arguments (add smart defaults)
   │  └─ Call super()._execute_tool(enhanced_input)
   │
   └─ MCPBaseTool._execute_tool(enhanced_input)
      ├─ Resolve command (shutil.which)
      ├─ Parse and sanitize arguments
      └─ Call _spawn(cmd, timeout)

5. SUBPROCESS EXECUTION
   ├─ Set resource limits (Unix)
   ├─ Create subprocess (start_new_session=True)
   ├─ Monitor with timeout
   ├─ Capture stdout/stderr
   └─ Truncate if exceeds limits

6. RESULT PROCESSING
   ├─ Parse output (tool-specific, e.g., nmap parser)
   ├─ Record metrics (success, duration, error type)
   ├─ Update circuit breaker state
   └─ Create ToolOutput with metadata

7. RESPONSE
   ├─ stdio: TextContent with JSON
   └─ HTTP: JSONResponse with ToolOutput.dict()

8. CLEANUP
   ├─ Decrement active execution counter
   ├─ Release semaphore
   └─ Log execution summary
Configuration System
Configuration Sources (Priority Order)
Environment Variables (highest priority)
Configuration File (MCP_CONFIG_FILE)
Code Defaults (lowest priority)
Key Configuration Objects
Assumed structure based on usage:

Python

class SecurityConfig:
    allow_intrusive: bool = False

class ToolConfig:
    default_timeout: float = 300.0
    default_concurrency: int = 2

class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout: float = 60.0

class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080

class Config:
    security: SecurityConfig
    tool: ToolConfig
    circuit_breaker: CircuitBreakerConfig
    server: ServerConfig
    
    def to_dict(self, redact_sensitive=False) -> Dict
Environment Variables
Variable	Default	Purpose
MCP_SERVER_TRANSPORT	stdio	stdio or http
MCP_SERVER_PORT	8080	HTTP server port
MCP_SERVER_HOST	0.0.0.0	HTTP server host
MCP_CONFIG_FILE	-	Path to config file
TOOLS_PACKAGE	mcp_server.tools	Package to scan
TOOL_INCLUDE	-	CSV of tools to include
TOOL_EXCLUDE	-	CSV of tools to exclude
LOG_LEVEL	INFO	Logging level
MCP_MAX_ARGS_LEN	2048	Max argument length
MCP_MAX_STDOUT_BYTES	1048576	Max stdout (1MB)
MCP_MAX_STDERR_BYTES	262144	Max stderr (256KB)
MCP_DEFAULT_TIMEOUT_SEC	300	Default timeout
MCP_DEFAULT_CONCURRENCY	2	Default concurrency
MCP_MAX_MEMORY_MB	512	Memory limit
MCP_MAX_FILE_DESCRIPTORS	256	FD limit
Configuration Application
Safe Clamping Pattern:

Python

def _apply_config(self):
    # Clamp values to safe ranges
    self.timeout = max(60.0, min(3600.0, config.timeout))
    self.concurrency = max(1, min(5, config.concurrency))
    
    # Log when clamped
    if clamped:
        log.info("config_clamped param=%s original=%s new=%s")
Monitoring & Observability
Health Monitoring
Architecture:

Python

HealthCheckManager
├─ system_health_check (CPU, memory, disk)
├─ tool_availability_check (commands in PATH)
└─ per_tool_health_checks (circuit breaker state)
Health States:

Python

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
Priority Levels:

Python

class HealthCheckPriority(Enum):
    CRITICAL = 1      # System-level
    HIGH = 2          # Important tools
    MEDIUM = 3        # Optional tools
    LOW = 4
    INFORMATIONAL = 5  # Metrics, stats
HTTP Response Codes:

200: All HEALTHY
207: Some DEGRADED (multi-status)
503: Any UNHEALTHY
Metrics Collection
Prometheus Metrics:

Python

mcp_tool_execution_total{tool="NmapTool",status="success"}
mcp_tool_execution_duration_seconds{tool="NmapTool"}
mcp_tool_active_executions{tool="NmapTool"}
mcp_tool_timeouts_total{tool="NmapTool"}
mcp_circuit_breaker_state{tool="NmapTool",state="open"}
Fallback JSON Metrics:

Python

{
  "system": {"cpu": ..., "memory": ...},
  "tools": {
    "NmapTool": {
      "executions": 150,
      "successes": 145,
      "failures": 5,
      "avg_duration": 12.3,
      "active": 2
    }
  }
}
Logging Strategy
Structured Logging:

Python

log.info("tool.start command=%s timeout=%.1f", cmd, timeout)
log.error("tool.error tool=%s error_type=%s", name, error_type)
Log Levels:

DEBUG: Configuration, cache operations, internal state
INFO: Execution lifecycle, optimizations, state changes
WARNING: Non-fatal issues, fallbacks, deprecated usage
ERROR: Failures, exceptions, security violations
CRITICAL: System-level failures
Extension Points
Creating a New Tool
Minimum Implementation:

Python

from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput

class MyTool(MCPBaseTool):
    command_name = "mytool"  # Required
    allowed_flags = ["-flag1", "-flag2"]  # Optional whitelist
    
    # Optional overrides
    default_timeout_sec = 300.0
    concurrency = 2
    circuit_breaker_failure_threshold = 5
Custom Validation:

Python

async def _execute_tool(self, inp: ToolInput, timeout_sec) -> ToolOutput:
    # 1. Custom validation
    if not self._my_validation(inp.target):
        return self._create_error_output(error_context, ...)
    
    # 2. Parse/optimize args
    parsed = self._parse_my_args(inp.extra_args)
    
    # 3. Call base implementation
    enhanced = ToolInput(target=inp.target, extra_args=parsed, ...)
    return await super()._execute_tool(enhanced, timeout_sec)
Tool-Specific Metadata:

Python

def get_tool_info(self) -> Dict[str, Any]:
    base_info = super().get_tool_info()
    base_info.update({
        "my_feature": "enabled",
        "supported_modes": ["fast", "thorough"]
    })
    return base_info
Adding Custom Health Checks
Python

from mcp_server.health import HealthCheck, HealthStatus, HealthCheckPriority

class MyHealthCheck(HealthCheck):
    async def check(self) -> HealthStatus:
        # Custom logic
        if condition:
            return HealthStatus.HEALTHY
        return HealthStatus.DEGRADED

# Register in server
server.health_manager.add_health_check(
    MyHealthCheck(),
    priority=HealthCheckPriority.HIGH
)
Adding Custom Metrics
Python

# Assumed MetricsManager API
metrics_manager.register_counter("my_metric_total")
metrics_manager.increment("my_metric_total", labels={"status": "success"})
Deployment Considerations
Running the Server
stdio Mode (Claude Desktop):

Bash

# Minimal
python -m mcp_server.server

# With config
MCP_CONFIG_FILE=config.yaml python -m mcp_server.server

# With tool filtering
TOOL_INCLUDE=NmapTool,TracertTool python -m mcp_server.server
HTTP Mode:

Bash

MCP_SERVER_TRANSPORT=http \
MCP_SERVER_PORT=8080 \
python -m mcp_server.server
Docker Deployment
Dockerfile considerations:

Dockerfile

# Install system tools (nmap, traceroute, etc.)
RUN apt-get update && apt-get install -y nmap traceroute

# Non-root user for security
RUN useradd -m -u 1000 mcpuser
USER mcpuser

# Resource limits via docker-compose
services:
  mcp-server:
    mem_limit: 512m
    cpus: 1.0
    pids_limit: 100
Kubernetes Deployment
Resource Limits:

YAML

resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
Health Probes:

YAML

livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
Security Considerations
Network Policies: Restrict egress to private networks only
RBAC: Limit tool execution permissions
Secrets Management: Use env vars or secret managers for sensitive config
Image Scanning: Regularly scan for vulnerabilities
Log Aggregation: Ship logs to SIEM for security monitoring
Rate Limiting: Configure per deployment size
TLS: Use reverse proxy (nginx, traefik) for HTTPS in HTTP mode
Scaling Considerations
Horizontal Scaling (HTTP mode):

Stateless design allows multiple replicas
Use load balancer with session affinity for SSE
Share metrics backend (Prometheus pushgateway)
Vertical Scaling:

Increase concurrency per tool
Adjust resource limits
Monitor with /metrics endpoint
Performance Tuning:

Python

# Use uvloop for better async performance
import uvloop
uvloop.install()

# Increase concurrency for fast tools
class FastTool(MCPBaseTool):
    concurrency = 10

# Decrease timeout for quick scans
default_timeout_sec = 60.0
Appendix: Component Interaction Matrix
Component	Depends On	Depended By	Purpose
MCPBaseTool	Pydantic, asyncio, resource	All tools	Base functionality
EnhancedMCPServer	FastAPI, MCP SDK, ToolRegistry	Main entry	Orchestration
ToolRegistry	MCPBaseTool	EnhancedMCPServer	Tool management
RateLimiter	asyncio	HTTP endpoints	Request throttling
HealthCheckManager	asyncio	EnhancedMCPServer	Health monitoring
MetricsManager	prometheus_client	Tools, Server	Observability
NmapTool	MCPBaseTool, ipaddress	ToolRegistry	Network scanning
Document End

text


---

# Document 2: Tool Development Programming Guide

```markdown
# MCP Server Tool Development Programming Guide
**Version:** 2.0  
**Audience:** Developers and AI Coding Agents  
**Purpose:** Authoritative guide for creating new tools

## Table of Contents
1. [Quick Start](#quick-start)
2. [Tool Anatomy](#tool-anatomy)
3. [Development Workflow](#development-workflow)
4. [Implementation Patterns](#implementation-patterns)
5. [Security Requirements](#security-requirements)
6. [Validation & Sanitization](#validation--sanitization)
7. [Error Handling](#error-handling)
8. [Testing Your Tool](#testing-your-tool)
9. [Configuration Integration](#configuration-integration)
10. [Best Practices](#best-practices)
11. [Common Pitfalls](#common-pitfalls)
12. [Reference Examples](#reference-examples)

---

## Quick Start

### Minimal Tool Implementation

**File:** `mcp_server/tools/hello_tool.py`

```python
"""
HelloTool - Minimal example tool.
Production-ready with all security and reliability features inherited from base.
"""
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput

class HelloTool(MCPBaseTool):
    """
    Echo tool that validates targets and returns greeting.
    
    Usage:
        from mcp_server.tools.hello_tool import HelloTool
        tool = HelloTool()
        result = await tool.run(ToolInput(target="192.168.1.1"))
    """
    
    # REQUIRED: Command name (must be in PATH or /usr/bin, etc.)
    command_name = "echo"
    
    # OPTIONAL: Whitelist allowed flags (security best practice)
    allowed_flags = ["-n", "-e"]
    
    # OPTIONAL: Override defaults
    default_timeout_sec = 10.0  # Short timeout for fast command
    concurrency = 5  # Allow more concurrent executions
    
    # OPTIONAL: Circuit breaker tuning
    circuit_breaker_failure_threshold = 3
    circuit_breaker_recovery_timeout = 30.0
That's it! This tool is production-ready with:

✅ Target validation (RFC1918 or .lab.internal)
✅ Argument sanitization (shell metacharacter blocking)
✅ Resource limits (CPU, memory, FDs)
✅ Timeout enforcement
✅ Concurrency control
✅ Circuit breaker protection
✅ Metrics collection
✅ Comprehensive error handling
Discovery & Registration
Place your tool in mcp_server/tools/ directory. The server will:

Auto-discover via package scanning
Instantiate your class
Register with MCP server (stdio) or FastAPI (HTTP)
Enable unless filtered by TOOL_INCLUDE/TOOL_EXCLUDE
Exclusion Patterns (automatic):

Python

# Tools with these names are automatically excluded
EXCLUDED_PREFIXES = {'Test', 'Mock', 'Abstract', '_', 'Example'}
EXCLUDED_SUFFIXES = {'Base', 'Mixin', 'Interface'}
EXCLUDED_EXACT = {'MCPBaseTool'}

# Examples:
TestNmapTool  # ❌ Excluded (prefix)
NmapToolBase  # ❌ Excluded (suffix)
_InternalTool # ❌ Excluded (prefix)
NmapTool      # ✅ Included
Testing Your Tool
Python

import asyncio
from mcp_server.tools.hello_tool import HelloTool
from mcp_server.base_tool import ToolInput

async def test_hello():
    tool = HelloTool()
    
    # Basic execution
    result = await tool.run(ToolInput(
        target="192.168.1.1",
        extra_args="-n"
    ))
    
    assert result.returncode == 0
    assert "192.168.1.1" in result.stdout
    print(f"✅ Success: {result.stdout}")

# Run test
asyncio.run(test_hello())
Tool Anatomy
Required Attributes
Python

class MyTool(MCPBaseTool):
    # ⚠️ REQUIRED: Command to execute
    command_name: ClassVar[str] = "mytool"
    
    # Must be available via shutil.which()
    # Examples: "nmap", "ping", "traceroute", "dig"
Optional Attributes
Python

class MyTool(MCPBaseTool):
    # Security: Whitelist allowed flags (HIGHLY RECOMMENDED)
    allowed_flags: ClassVar[Optional[Sequence[str]]] = [
        "-v", "-vv",      # Verbosity
        "-o", "--output", # Output control
        "-t", "--timeout" # Timeout
    ]
    
    # Performance: Concurrency limit
    concurrency: ClassVar[int] = 2  # Max parallel executions
    
    # Performance: Default timeout
    default_timeout_sec: ClassVar[float] = 300.0
    
    # Reliability: Circuit breaker settings
    circuit_breaker_failure_threshold: ClassVar[int] = 5
    circuit_breaker_recovery_timeout: ClassVar[float] = 60.0
    circuit_breaker_expected_exception: ClassVar[tuple] = (Exception,)
Optional Methods
Python

class MyTool(MCPBaseTool):
    async def _execute_tool(self, inp: ToolInput, 
                           timeout_sec: Optional[float] = None) -> ToolOutput:
        """
        Override for custom validation, parsing, or optimization.
        
        MUST call super()._execute_tool() or implement full execution.
        """
        # Custom logic here
        return await super()._execute_tool(inp, timeout_sec)
    
    def get_tool_info(self) -> Dict[str, Any]:
        """
        Override to add tool-specific metadata.
        """
        info = super().get_tool_info()
        info.update({"custom_field": "value"})
        return info
    
    def _parse_args(self, extra_args: str) -> Sequence[str]:
        """
        Override for custom argument parsing.
        MUST still call _sanitize_tokens() for security.
        """
        tokens = shlex.split(extra_args)
        return self._sanitize_tokens(tokens)
Development Workflow
Step 1: Define Tool Requirements
Planning Checklist:

 What command does this tool execute?
 Is the command available on target systems?
 What flags should be allowed? (security)
 What's the expected execution time? (timeout)
 How many concurrent executions are safe? (concurrency)
 Are there intrusive operations? (circuit breaker)
 What validation is needed beyond base class?
Step 2: Create Tool File
Naming Convention:

text

mcp_server/tools/{command}_tool.py

Examples:
mcp_server/tools/nmap_tool.py
mcp_server/tools/traceroute_tool.py
mcp_server/tools/dig_tool.py
File Template:

Python

"""
{ToolName} - {Brief description}

{Detailed description of what this tool does}

Features:
- Feature 1
- Feature 2

Safety Controls:
- Control 1
- Control 2

Usage:
    from mcp_server.tools.{module} import {ToolName}
    tool = {ToolName}()
    result = await tool.run(ToolInput(target="192.168.1.1"))

Configuration:
    # config.yaml
    security:
      allow_intrusive: false  # If applicable
"""
import logging
from typing import Optional
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput

log = logging.getLogger(__name__)

class {ToolName}(MCPBaseTool):
    """
    {One-line description}
    
    {Multi-line detailed description if needed}
    """
    command_name = "{command}"
    allowed_flags = [...]  # Define whitelist
    
    # Override defaults if needed
    default_timeout_sec = 300.0
    concurrency = 2
Step 3: Implement Custom Logic (if needed)
Decision Tree:

text

Do you need custom validation beyond base class?
├─ YES → Override _execute_tool()
└─ NO  → Use base class as-is

Do you need custom argument parsing?
├─ YES → Override _parse_args()
└─ NO  → Use base class as-is

Do you need tool-specific metadata?
├─ YES → Override get_tool_info()
└─ NO  → Base metadata sufficient

Do you have configuration settings?
├─ YES → Implement _apply_config()
└─ NO  → Configuration not needed
Step 4: Test Locally
Python

# tests/test_{tool_name}.py
import pytest
from mcp_server.tools.{module} import {ToolName}
from mcp_server.base_tool import ToolInput

@pytest.mark.asyncio
async def test_{tool_name}_basic():
    tool = {ToolName}()
    result = await tool.run(ToolInput(target="192.168.1.1"))
    assert result.returncode == 0
    assert result.stdout

@pytest.mark.asyncio
async def test_{tool_name}_validation():
    tool = {ToolName}()
    # Test target validation
    result = await tool.run(ToolInput(target="8.8.8.8"))  # Public IP
    assert result.error_type == "validation_error"

@pytest.mark.asyncio
async def test_{tool_name}_timeout():
    tool = {ToolName}()
    result = await tool.run(ToolInput(
        target="192.168.1.1",
        timeout_sec=0.001  # Force timeout
    ))
    assert result.timed_out == True
Step 5: Integration Testing
Bash

# Start server with your tool
TOOL_INCLUDE={YourTool} python -m mcp_server.server

# Test via HTTP (if using HTTP transport)
curl -X POST http://localhost:8080/tools/{YourTool}/execute \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "extra_args": "-v"}'
Step 6: Documentation
Update your tool's docstring with:

Python

"""
{ToolName} - {Brief description}

{Detailed description}

Features:
- List key features

Safety Controls:
- List security measures
- List validation rules

Usage:
    tool = {ToolName}()
    result = await tool.run(ToolInput(
        target="192.168.1.0/24",
        extra_args="--flag value"
    ))

Allowed Flags:
    -flag1: Description
    -flag2: Description

Configuration:
    # Environment variables
    MY_TOOL_SETTING=value
    
    # config.yaml
    tool:
      my_setting: value

Examples:
    # Example 1
    result = await tool.run(ToolInput(target="192.168.1.1"))
    
    # Example 2
    result = await tool.run(ToolInput(
        target="192.168.1.0/24",
        extra_args="--verbose",
        timeout_sec=600
    ))
"""
Implementation Patterns
Pattern 1: Simple Passthrough (No Custom Logic)
When to use: Command is safe, base validation sufficient

Python

class SimpleTool(MCPBaseTool):
    command_name = "whoami"
    allowed_flags = []  # No flags allowed
    default_timeout_sec = 5.0
    concurrency = 10  # Fast, can run many concurrently
Pattern 2: Custom Validation
When to use: Tool-specific target or argument validation needed

Python

class CustomValidationTool(MCPBaseTool):
    command_name = "mytool"
    allowed_flags = ["-v", "-o"]
    
    async def _execute_tool(self, inp: ToolInput, 
                           timeout_sec: Optional[float] = None) -> ToolOutput:
        # Step 1: Custom validation
        validation_error = self._validate_custom_requirements(inp)
        if validation_error:
            return validation_error
        
        # Step 2: Call base implementation
        return await super()._execute_tool(inp, timeout_sec)
    
    def _validate_custom_requirements(self, inp: ToolInput) -> Optional[ToolOutput]:
        """Perform tool-specific validation."""
        # Example: Check target format
        if not inp.target.startswith("192.168."):
            from mcp_server.base_tool import ErrorContext, ToolErrorType
            error_ctx = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Target must be in 192.168.0.0/16 range: {inp.target}",
                recovery_suggestion="Use 192.168.x.x addresses only",
                timestamp=datetime.now(timezone.utc),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"allowed_range": "192.168.0.0/16"}
            )
            return self._create_error_output(error_ctx, inp.correlation_id or "")
        
        return None  # Validation passed
Pattern 3: Argument Optimization
When to use: Adding smart defaults or optimizing for performance

Python

class OptimizedTool(MCPBaseTool):
    command_name = "mytool"
    allowed_flags = ["-v", "-t", "-p", "--fast", "--slow"]
    
    async def _execute_tool(self, inp: ToolInput, 
                           timeout_sec: Optional[float] = None) -> ToolOutput:
        # Parse and optimize arguments
        optimized_args = self._optimize_args(inp.extra_args or "")
        
        # Create enhanced input
        enhanced_input = ToolInput(
            target=inp.target,
            extra_args=optimized_args,
            timeout_sec=timeout_sec or inp.timeout_sec,
            correlation_id=inp.correlation_id
        )
        
        return await super()._execute_tool(enhanced_input, timeout_sec)
    
    def _optimize_args(self, extra_args: str) -> str:
        """Add smart defaults."""
        tokens = shlex.split(extra_args) if extra_args else []
        optimized = []
        
        # Check what's already specified
        has_verbosity = any(t == "-v" for t in tokens)
        has_timeout = any(t == "-t" or t.startswith("-t=") for t in tokens)
        
        # Add defaults
        if not has_verbosity:
            optimized.append("-v")
        if not has_timeout:
            optimized.extend(["-t", "30"])
        
        # Append original args
        optimized.extend(tokens)
        
        return " ".join(optimized)
Pattern 4: Configuration-Driven Behavior
When to use: Tool behavior changes based on configuration

Python

class ConfigurableTool(MCPBaseTool):
    command_name = "mytool"
    
    # Dynamic allowed_flags based on config
    BASE_FLAGS = ["-v", "-o"]
    
    def __init__(self):
        super().__init__()
        self.allow_advanced = False
        self._apply_config()
    
    def _apply_config(self):
        """Apply configuration with safe defaults."""
        from mcp_server.config import get_config
        config = get_config()
        
        # Check security settings
        if hasattr(config, 'security') and config.security:
            self.allow_advanced = getattr(
                config.security, 'allow_advanced_features', False
            )
        
        # Apply tool-specific config
        if hasattr(config, 'tool') and config.tool:
            self.default_timeout_sec = max(
                60.0, 
                min(3600.0, getattr(config.tool, 'default_timeout', 300.0))
            )
    
    @property
    def allowed_flags(self) -> List[str]:
        """Dynamic flags based on configuration."""
        flags = list(self.BASE_FLAGS)
        if self.allow_advanced:
            flags.extend(["--advanced-flag1", "--advanced-flag2"])
        return flags
Pattern 5: Complex Argument Parsing
When to use: Custom argument syntax or complex validation

Python

class ComplexArgsTool(MCPBaseTool):
    command_name = "mytool"
    allowed_flags = ["-p", "--ports", "-s", "--scripts"]
    
    # Compiled regex patterns for performance
    _PORT_PATTERN = re.compile(r'^[\d,\-]+$')
    _SCRIPT_PATTERN = re.compile(r'^[a-zA-Z0-9_,\-]+$')
    
    async def _execute_tool(self, inp: ToolInput, 
                           timeout_sec: Optional[float] = None) -> ToolOutput:
        # Parse and validate complex arguments
        try:
            validated_args = self._parse_and_validate_args(inp.extra_args or "")
        except ValueError as e:
            from mcp_server.base_tool import ErrorContext, ToolErrorType
            error_ctx = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Argument validation failed: {str(e)}",
                recovery_suggestion="Check argument syntax and allowed values",
                timestamp=datetime.now(timezone.utc),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"error": str(e)}
            )
            return self._create_error_output(error_ctx, inp.correlation_id or "")
        
        enhanced_input = ToolInput(
            target=inp.target,
            extra_args=validated_args,
            timeout_sec=timeout_sec or inp.timeout_sec,
            correlation_id=inp.correlation_id
        )
        
        return await super()._execute_tool(enhanced_input, timeout_sec)
    
    def _parse_and_validate_args(self, extra_args: str) -> str:
        """Parse and validate arguments with custom logic."""
        if not extra_args:
            return ""
        
        tokens = shlex.split(extra_args)
        validated = []
        i = 0
        
        while i < len(tokens):
            token = tokens[i]
            
            # Security: Only allow flags
            if not token.startswith("-"):
                raise ValueError(f"Non-flag token not allowed: {token}")
            
            # Handle port specification
            if token in ("-p", "--ports"):
                if i + 1 >= len(tokens):
                    raise ValueError(f"{token} requires a value")
                
                port_spec = tokens[i + 1]
                if not self._validate_ports(port_spec):
                    raise ValueError(f"Invalid port specification: {port_spec}")
                
                validated.extend([token, port_spec])
                i += 2
                continue
            
            # Handle script specification
            if token in ("-s", "--scripts"):
                if i + 1 >= len(tokens):
                    raise ValueError(f"{token} requires a value")
                
                script_spec = tokens[i + 1]
                if not self._validate_scripts(script_spec):
                    raise ValueError(f"Invalid script specification: {script_spec}")
                
                validated.extend([token, script_spec])
                i += 2
                continue
            
            # Handle other flags
            if token not in self.allowed_flags:
                raise ValueError(f"Flag not allowed: {token}")
            
            validated.append(token)
            i += 1
        
        return " ".join(validated)
    
    def _validate_ports(self, port_spec: str) -> bool:
        """Validate port specification."""
        if not self._PORT_PATTERN.match(port_spec):
            return False
        
        # Parse and validate ranges
        for part in port_spec.split(','):
            if '-' in part:
                start, end = part.split('-')
                if not (1 <= int(start) <= 65535 and 1 <= int(end) <= 65535):
                    return False
            else:
                if not (1 <= int(part) <= 65535):
                    return False
        
        return True
    
    def _validate_scripts(self, script_spec: str) -> bool:
        """Validate script specification."""
        return bool(self._SCRIPT_PATTERN.match(script_spec))
Pattern 6: Result Parsing
When to use: Need structured data from command output

Python

from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class ParsedResult:
    """Structured result."""
    raw_output: str
    items: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

class ParsingTool(MCPBaseTool):
    command_name = "mytool"
    
    async def run(self, inp: ToolInput, 
                  timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute and enhance output with parsing."""
        result = await super().run(inp, timeout_sec)
        
        # Parse output if successful
        if result.is_success():
            parsed = self.parse_output(result.stdout)
            result.ensure_metadata()
            result.metadata['parsed'] = {
                'items': parsed.items,
                'summary': parsed.summary
            }
        
        return result
    
    def parse_output(self, output: str) -> ParsedResult:
        """Parse command output into structured data."""
        result = ParsedResult(raw_output=output)
        
        # Example: Parse line-by-line
        for line in output.split('\n'):
            if line.startswith('ITEM:'):
                # Extract item data
                item = self._parse_item_line(line)
                result.items.append(item)
        
        # Generate summary
        result.summary = {
            'total_items': len(result.items),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return result
    
    def _parse_item_line(self, line: str) -> Dict[str, Any]:
        """Parse a single item line."""
        # Custom parsing logic
        parts = line.split(':', 1)
        return {'type': parts[0], 'data': parts[1] if len(parts) > 1 else ''}
Security Requirements
Rule 1: Always Use Whitelisting
❌ WRONG (Blacklisting):

Python

# Don't do this!
blocked_flags = ["-x", "--dangerous"]
if flag in blocked_flags:
    raise ValueError(f"Flag not allowed: {flag}")
✅ CORRECT (Whitelisting):

Python

allowed_flags = ["-v", "-o", "--safe-flag"]
if flag not in allowed_flags:
    raise ValueError(f"Flag not allowed: {flag}")
Rule 2: Block Non-Flag Tokens
❌ WRONG:

Python

# Allowing arbitrary tokens is dangerous
if token.isalnum():
    validated.append(token)
✅ CORRECT:

Python

# Only allow tokens starting with '-'
if not token.startswith("-"):
    raise ValueError(f"Non-flag token not allowed: {token}")
Rule 3: Never Use Shell Execution
❌ WRONG:

Python

# NEVER use shell=True
subprocess.run(f"command {args}", shell=True)
✅ CORRECT:

Python

# Always use argument list with shell=False (default)
await asyncio.create_subprocess_exec(
    command,
    *args,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE
)
Rule 4: Validate All Input Values
❌ WRONG:

Python

# Trusting user input
port = tokens[i + 1]
validated.extend(["-p", port])
✅ CORRECT:

Python

# Validate before accepting
port = tokens[i + 1]
if not self._validate_port(port):
    raise ValueError(f"Invalid port: {port}")
validated.extend(["-p", port])
Rule 5: Use Compiled Patterns for Performance
❌ SLOW:

Python

# Recompiling regex every time
if re.match(r'^\d+$', value):
    ...
✅ FAST:

Python

# Compile once, use many times
class MyTool(MCPBaseTool):
    _NUMERIC_PATTERN = re.compile(r'^\d+$')
    
    def _validate(self, value):
        return bool(self._NUMERIC_PATTERN.match(value))
Rule 6: Gate Intrusive Operations
When allowing dangerous operations:

Python

class IntrusiveTool(MCPBaseTool):
    command_name = "mytool"
    BASE_FLAGS = ["-v", "--safe-scan"]
    
    def __init__(self):
        super().__init__()
        self.allow_intrusive = False
        self._apply_config()
    
    def _apply_config(self):
        from mcp_server.config import get_config
        config = get_config()
        
        if hasattr(config, 'security') and config.security:
            self.allow_intrusive = getattr(
                config.security, 'allow_intrusive', False
            )
    
    @property
    def allowed_flags(self) -> List[str]:
        flags = list(self.BASE_FLAGS)
        if self.allow_intrusive:
            flags.append("--intrusive-flag")
            log.warning("intrusive_operations_enabled tool=%s", self.tool_name)
        return flags
Validation & Sanitization
Target Validation
Already handled by base class:

Python

# Base class validates:
# - RFC1918 private IPs: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
# - Private networks (CIDR): 192.168.1.0/24
# - .lab.internal hostnames with RFC-compliant format
Additional validation:

Python

def _validate_custom_target(self, target: str) -> bool:
    """Add tool-specific target validation."""
    # Example: Only allow specific subnet
    if not target.startswith("192.168.1."):
        return False
    
    # Example: Validate hostname format
    if target.endswith(".lab.internal"):
        hostname = target[:-len(".lab.internal")]
        if len(hostname) > 63:  # DNS label limit
            return False
    
    return True
Argument Sanitization
Base class provides:

Python

_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")  # Shell metacharacters
_TOKEN_ALLOWED = re.compile(r"^[A-Za-z0-9.:/=+,\-@%_]+$")
Custom sanitization:

Python

def _sanitize_custom_value(self, value: str) -> str:
    """Sanitize tool-specific values."""
    # Remove/escape dangerous characters
    value = value.strip()
    
    # Validate length
    if len(value) > 255:
        raise ValueError("Value too long")
    
    # Validate character set
    if not re.match(r'^[a-zA-Z0-9_\-]+$', value):
        raise ValueError("Invalid characters in value")
    
    return value
Size Limits
Enforce limits on collections:

Python

class NetworkTool(MCPBaseTool):
    MAX_TARGETS = 100
    MAX_PORT_RANGES = 50
    MAX_NETWORK_SIZE = 1024  # Max hosts in CIDR
    
    def _validate_network_size(self, target: str) -> Optional[ToolOutput]:
        """Validate network isn't too large."""
        if "/" in target:
            import ipaddress
            network = ipaddress.ip_network(target, strict=False)
            
            if network.num_addresses > self.MAX_NETWORK_SIZE:
                max_cidr = 32 - math.ceil(math.log2(self.MAX_NETWORK_SIZE))
                
                from mcp_server.base_tool import ErrorContext, ToolErrorType
                error_ctx = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Network too large: {network.num_addresses} hosts (max: {self.MAX_NETWORK_SIZE})",
                    recovery_suggestion=f"Use /{max_cidr} or smaller prefix",
                    timestamp=datetime.now(timezone.utc),
                    tool_name=self.tool_name,
                    target=target,
                    metadata={
                        "network_size": network.num_addresses,
                        "max_allowed": self.MAX_NETWORK_SIZE,
                        "suggested_cidr": f"/{max_cidr}"
                    }
                )
                return self._create_error_output(error_ctx, "")
        
        return None  # Validation passed
Error Handling
Creating Informative Errors
Use ErrorContext for rich error information:

Python

from mcp_server.base_tool import ErrorContext, ToolErrorType
from datetime import datetime, timezone

def _create_validation_error(self, message: str, inp: ToolInput, 
                            **metadata) -> ToolOutput:
    """Helper to create validation error."""
    error_ctx = ErrorContext(
        error_type=ToolErrorType.VALIDATION_ERROR,
        message=message,
        recovery_suggestion=self._get_recovery_suggestion(message),
        timestamp=datetime.now(timezone.utc),
        tool_name=self.tool_name,
        target=inp.target,
        metadata=metadata
    )
    return self._create_error_output(error_ctx, inp.correlation_id or "")

def _get_recovery_suggestion(self, message: str) -> str:
    """Generate helpful recovery suggestion."""
    if "network too large" in message.lower():
        return "Use smaller CIDR prefix or split into multiple scans"
    elif "invalid port" in message.lower():
        return "Use port numbers 1-65535, ranges (80-443), or lists (80,443,8080)"
    else:
        return "Check input parameters and try again"
Error Types
Use appropriate error types:

Python

from mcp_server.base_tool import ToolErrorType

# Validation errors (input problems)
ToolErrorType.VALIDATION_ERROR

# Command not found
ToolErrorType.NOT_FOUND

# Execution failures
ToolErrorType.EXECUTION_ERROR

# Timeout
ToolErrorType.TIMEOUT

# Resource limits exceeded
ToolErrorType.RESOURCE_EXHAUSTED

# Circuit breaker open
ToolErrorType.CIRCUIT_BREAKER_OPEN

# Unknown/unexpected
ToolErrorType.UNKNOWN
Logging Errors
Structured logging with context:

Python

import logging
log = logging.getLogger(__name__)

# Info level for normal execution
log.info("tool.executing target=%s args=%s", target, args)

# Warning for recoverable issues
log.warning("tool.validation_failed target=%s error=%s", target, error)

# Error for failures
log.error("tool.execution_failed target=%s error=%s returncode=%d",
         target, error, returncode)

# Include extra context
log.error("tool.error",
         extra={
             "tool": self.tool_name,
             "target": target,
             "error_type": error_type.value,
             "correlation_id": correlation_id
         })
Testing Your Tool
Unit Tests
File: tests/test_{tool_name}.py

Python

import pytest
from mcp_server.tools.mytool import MyTool
from mcp_server.base_tool import ToolInput, ToolErrorType

class TestMyTool:
    """Unit tests for MyTool."""
    
    @pytest.fixture
    def tool(self):
        """Create tool instance."""
        return MyTool()
    
    @pytest.mark.asyncio
    async def test_basic_execution(self, tool):
        """Test basic successful execution."""
        result = await tool.run(ToolInput(target="192.168.1.1"))
        
        assert result.returncode == 0
        assert result.stdout
        assert not result.timed_out
        assert not result.error
    
    @pytest.mark.asyncio
    async def test_with_flags(self, tool):
        """Test execution with allowed flags."""
        result = await tool.run(ToolInput(
            target="192.168.1.1",
            extra_args="-v --flag value"
        ))
        
        assert result.returncode == 0
    
    @pytest.mark.asyncio
    async def test_invalid_target_public_ip(self, tool):
        """Test rejection of public IP."""
        result = await tool.run(ToolInput(target="8.8.8.8"))
        
        assert result.error_type == ToolErrorType.VALIDATION_ERROR.value
        assert "private" in result.stderr.lower() or "rfc1918" in result.stderr.lower()
    
    @pytest.mark.asyncio
    async def test_invalid_target_hostname(self, tool):
        """Test rejection of non-.lab.internal hostname."""
        result = await tool.run(ToolInput(target="google.com"))
        
        assert result.error_type == ToolErrorType.VALIDATION_ERROR.value
        assert "lab.internal" in result.stderr.lower()
    
    @pytest.mark.asyncio
    async def test_invalid_flag(self, tool):
        """Test rejection of disallowed flag."""
        result = await tool.run(ToolInput(
            target="192.168.1.1",
            extra_args="--forbidden-flag"
        ))
        
        assert result.error_type == ToolErrorType.VALIDATION_ERROR.value
        assert "not allowed" in result.stderr.lower()
    
    @pytest.mark.asyncio
    async def test_timeout(self, tool):
        """Test timeout handling."""
        result = await tool.run(ToolInput(
            target="192.168.1.1",
            timeout_sec=0.001  # Force timeout
        ))
        
        assert result.timed_out == True
        assert result.error_type == ToolErrorType.TIMEOUT.value
    
    @pytest.mark.asyncio
    async def test_shell_injection_blocked(self, tool):
        """Test shell injection prevention."""
        result = await tool.run(ToolInput(
            target="192.168.1.1",
            extra_args="; rm -rf /"  # Attempt injection
        ))
        
        assert result.error_type == ToolErrorType.VALIDATION_ERROR.value
        assert "metacharacter" in result.stderr.lower() or "forbidden" in result.stderr.lower()
    
    @pytest.mark.asyncio
    async def test_correlation_id_preserved(self, tool):
        """Test correlation ID is preserved."""
        correlation_id = "test-12345"
        result = await tool.run(ToolInput(
            target="192.168.1.1",
            correlation_id=correlation_id
        ))
        
        assert result.correlation_id == correlation_id
    
    @pytest.mark.asyncio
    async def test_metadata_present(self, tool):
        """Test metadata is populated."""
        result = await tool.run(ToolInput(target="192.168.1.1"))
        
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
    
    def test_tool_info(self, tool):
        """Test get_tool_info returns complete info."""
        info = tool.get_tool_info()
        
        assert info['name'] == tool.tool_name
        assert info['command'] == tool.command_name
        assert 'concurrency' in info
        assert 'timeout' in info
        assert 'circuit_breaker' in info
    
    def test_command_available(self, tool):
        """Test command is available in PATH."""
        cmd_path = tool._resolve_command()
        assert cmd_path is not None, f"Command '{tool.command_name}' not found in PATH"
Integration Tests
Python

import pytest
from mcp_server.server import EnhancedMCPServer
from mcp_server.tools.mytool import MyTool

@pytest.mark.integration
class TestMyToolIntegration:
    """Integration tests with full server."""
    
    @pytest.fixture
    async def server(self):
        """Create server with tool."""
        tools = [MyTool()]
        server = EnhancedMCPServer(tools=tools, transport="http")
        yield server
        await server.cleanup()
    
    @pytest.mark.asyncio
    async def test_tool_registered(self, server):
        """Test tool is properly registered."""
        tool = server.tool_registry.get_tool("MyTool")
        assert tool is not None
        assert isinstance(tool, MyTool)
    
    @pytest.mark.asyncio
    async def test_tool_execution_via_registry(self, server):
        """Test execution through registry."""
        tool = server.tool_registry.get_tool("MyTool")
        from mcp_server.base_tool import ToolInput
        
        result = await tool.run(ToolInput(target="192.168.1.1"))
        assert result.returncode == 0
Performance Tests
Python

import pytest
import asyncio
import time

@pytest.mark.performance
class TestMyToolPerformance:
    """Performance and load tests."""
    
    @pytest.mark.asyncio
    async def test_concurrent_execution(self):
        """Test concurrent execution respects limits."""
        tool = MyTool()
        
        # Create multiple concurrent requests
        tasks = [
            tool.run(ToolInput(target=f"192.168.1.{i}"))
            for i in range(10)
        ]
        
        start = time.time()
        results = await asyncio.gather(*tasks)
        duration = time.time() - start
        
        # All should succeed
        assert all(r.returncode == 0 for r in results)
        
        # Should respect concurrency limit (some serialization expected)
        # With concurrency=2, 10 tasks should take roughly 5x single execution time
        print(f"10 concurrent tasks completed in {duration:.2f}s")
    
    @pytest.mark.asyncio
    async def test_memory_usage(self):
        """Test memory usage stays reasonable."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        tool = MyTool()
        
        # Execute many times
        for i in range(100):
            await tool.run(ToolInput(target="192.168.1.1"))
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory shouldn't grow excessively
        assert memory_increase < 100, f"Memory increased by {memory_increase:.2f}MB"
Configuration Integration
Reading Configuration
Python

from mcp_server.config import get_config

class ConfigurableTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self._apply_config()
    
    def _apply_config(self):
        """Apply configuration safely."""
        config = get_config()
        
        # Access security settings
        if hasattr(config, 'security'):
            self.allow_intrusive = getattr(
                config.security, 'allow_intrusive', False
            )
        
        # Access tool settings
        if hasattr(config, 'tool'):
            # Clamp to safe ranges
            timeout = getattr(config.tool, 'default_timeout', 300.0)
            self.default_timeout_sec = max(60.0, min(3600.0, float(timeout)))
            
            concurrency = getattr(config.tool, 'default_concurrency', 2)
            self.concurrency = max(1, min(10, int(concurrency)))
        
        # Access circuit breaker settings
        if hasattr(config, 'circuit_breaker'):
            threshold = getattr(config.circuit_breaker, 'failure_threshold', 5)
            self.circuit_breaker_failure_threshold = max(1, min(10, int(threshold)))
Environment Variables
Python

import os

class EnvConfigTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self._load_env_config()
    
    def _load_env_config(self):
        """Load configuration from environment."""
        # Tool-specific settings
        self.enable_feature_x = os.getenv('MYTOOL_FEATURE_X', 'false').lower() == 'true'
        
        # Timeout override
        timeout_env = os.getenv('MYTOOL_TIMEOUT')
        if timeout_env:
            try:
                self.default_timeout_sec = max(60.0, min(3600.0, float(timeout_env)))
            except ValueError:
                log.warning("Invalid MYTOOL_TIMEOUT value: %s", timeout_env)
        
        # Concurrency override
        concurrency_env = os.getenv('MYTOOL_CONCURRENCY')
        if concurrency_env:
            try:
                self.concurrency = max(1, min(10, int(concurrency_env)))
            except ValueError:
                log.warning("Invalid MYTOOL_CONCURRENCY value: %s", concurrency_env)
Configuration Validation
Python

def validate_configuration(self) -> Dict[str, Any]:
    """
    Validate current configuration.
    
    Returns dict with:
    - valid: bool
    - issues: List[str]
    - warnings: List[str]
    """
    issues = []
    warnings = []
    
    # Check command availability
    if not self._resolve_command():
        issues.append(f"Command '{self.command_name}' not found in PATH")
    
    # Check timeout
    if self.default_timeout_sec < 60:
        warnings.append(f"Timeout very low: {self.default_timeout_sec}s")
    
    # Check concurrency
    if self.concurrency > 10:
        warnings.append(f"High concurrency may impact performance: {self.concurrency}")
    
    # Check circuit breaker
    if hasattr(self, '_circuit_breaker') and self._circuit_breaker:
        from mcp_server.circuit_breaker import CircuitBreakerState
        if self._circuit_breaker.state == CircuitBreakerState.OPEN:
            warnings.append("Circuit breaker is currently OPEN")
    
    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "warnings": warnings,
        "configuration": {
            "command": self.command_name,
            "command_available": self._resolve_command() is not None,
            "timeout": self.default_timeout_sec,
            "concurrency": self.concurrency,
            "circuit_breaker_enabled": hasattr(self, '_circuit_breaker') and self._circuit_breaker is not None
        }
    }
Best Practices
1. Use Type Hints
Python

from typing import Optional, Dict, Any, List, Sequence

class MyTool(MCPBaseTool):
    async def _execute_tool(self, inp: ToolInput, 
                           timeout_sec: Optional[float] = None) -> ToolOutput:
        ...
    
    def _validate_custom(self, value: str) -> bool:
        ...
    
    def get_tool_info(self) -> Dict[str, Any]:
        ...
2. Comprehensive Documentation
Python

class MyTool(MCPBaseTool):
    """
    One-line tool description.
    
    Detailed multi-line description explaining:
    - What the tool does
    - When to use it
    - Security considerations
    - Configuration options
    
    Usage:
        tool = MyTool()
        result = await tool.run(ToolInput(target="192.168.1.1"))
    
    Configuration:
        MYTOOL_SETTING: Description
        
    Examples:
        # Example 1: Basic usage
        result = await tool.run(ToolInput(target="192.168.1.1"))
        
        # Example 2: With options
        result = await tool.run(ToolInput(
            target="192.168.1.0/24",
            extra_args="-v --fast"
        ))
    """
    
    def _my_method(self, param: str) -> bool:
        """
        Brief method description.
        
        Args:
            param: Parameter description
        
        Returns:
            Return value description
        
        Raises:
            ValueError: When validation fails
        """
        ...
3. Defensive Programming
Python

class DefensiveTool(MCPBaseTool):
    def _safe_parse(self, value: Optional[str]) -> str:
        """Safely parse value with defaults."""
        # Handle None
        if value is None:
            return ""
        
        # Handle empty
        value = value.strip()
        if not value:
            return ""
        
        # Validate length
        if len(value) > 1000:
            log.warning("value_truncated original_length=%d", len(value))
            value = value[:1000]
        
        return value
    
    def _safe_get_config(self, config, attr: str, default: Any) -> Any:
        """Safely get config attribute."""
        try:
            return getattr(config, attr, default)
        except Exception as e:
            log.warning("config_access_failed attr=%s error=%s", attr, str(e))
            return default
4. Logging Best Practices
Python

import logging
log = logging.getLogger(__name__)

class LoggingBestPractices(MCPBaseTool):
    async def _execute_tool(self, inp: ToolInput, timeout_sec) -> ToolOutput:
        # Log start of operation
        log.info("tool.start target=%s args=%s timeout=%.1f correlation_id=%s",
                inp.target, inp.extra_args, timeout_sec, inp.correlation_id)
        
        try:
            result = await super()._execute_tool(inp, timeout_sec)
            
            # Log success
            log.info("tool.success target=%s returncode=%d duration=%.2f",
                    inp.target, result.returncode, result.execution_time or 0)
            
            return result
            
        except Exception as e:
            # Log failure with context
            log.error("tool.error target=%s error=%s error_type=%s",
                     inp.target, str(e), type(e).__name__,
                     exc_info=True,  # Include stack trace
                     extra={
                         "tool": self.tool_name,
                         "correlation_id": inp.correlation_id,
                         "target": inp.target
                     })
            raise
5. Performance Optimization
Python

class OptimizedTool(MCPBaseTool):
    # Compile regex patterns once
    _PATTERN1 = re.compile(r'...')
    _PATTERN2 = re.compile(r'...')
    
    def __init__(self):
        super().__init__()
        # Cache expensive computations
        self._validation_cache: Dict[str, bool] = {}
        self._max_cache_size = 1000
    
    def _cached_validation(self, value: str) -> bool:
        """Validate with caching."""
        if value in self._validation_cache:
            return self._validation_cache[value]
        
        # Perform validation
        result = self._expensive_validation(value)
        
        # Cache with size limit
        if len(self._validation_cache) < self._max_cache_size:
            self._validation_cache[value] = result
        
        return result
    
    def clear_cache(self):
        """Clear validation cache (useful for testing)."""
        self._validation_cache.clear()
6. Graceful Degradation
Python

class GracefulTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        # Feature flags for optional functionality
        self.advanced_parsing_available = self._check_advanced_parsing()
    
    def _check_advanced_parsing(self) -> bool:
        """Check if advanced parsing is available."""
        try:
            import optional_library
            return True
        except ImportError:
            log.info("advanced_parsing_unavailable hint='pip install optional_library'")
            return False
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse with fallback."""
        if self.advanced_parsing_available:
            try:
                return self._advanced_parse(output)
            except Exception as e:
                log.warning("advanced_parse_failed fallback=basic error=%s", str(e))
                return self._basic_parse(output)
        else:
            return self._basic_parse(output)
Common Pitfalls
Pitfall 1: Not Calling Super Methods
❌ WRONG:

Python

async def _execute_tool(self, inp: ToolInput, timeout_sec) -> ToolOutput:
    # Custom logic only - loses base class functionality!
    return ToolOutput(stdout="result", stderr="", returncode=0)
✅ CORRECT:

Python

async def _execute_tool(self, inp: ToolInput, timeout_sec) -> ToolOutput:
    # Custom validation
    if error := self._validate_custom(inp):
        return error
    
    # Call base implementation for actual execution
    return await super()._execute_tool(inp, timeout_sec)
Pitfall 2: Mutable Default Arguments
❌ WRONG:

Python

class BadTool(MCPBaseTool):
    allowed_flags = []  # Mutable!
    
    def __init__(self):
        super().__init__()
        # This modifies the class attribute!
        self.allowed_flags.append("-v")
✅ CORRECT:

Python

class GoodTool(MCPBaseTool):
    BASE_FLAGS = ["-v", "-o"]  # Immutable tuple or class constant
    
    @property
    def allowed_flags(self) -> List[str]:
        # Return new list each time
        flags = list(self.BASE_FLAGS)
        if self.allow_advanced:
            flags.append("--advanced")
        return flags
Pitfall 3: Not Handling Missing Dependencies
❌ WRONG:

Python

from optional_library import feature  # Crashes if not installed

class BadTool(MCPBaseTool):
    ...
✅ CORRECT:

Python

try:
    from optional_library import feature
    FEATURE_AVAILABLE = True
except ImportError:
    FEATURE_AVAILABLE = False
    feature = None

class GoodTool(MCPBaseTool):
    def use_feature(self):
        if not FEATURE_AVAILABLE:
            log.warning("feature_unavailable hint='pip install optional_library'")
            return self.fallback_behavior()
        
        return feature()
Pitfall 4: Blocking the Event Loop
❌ WRONG:

Python

async def _execute_tool(self, inp: ToolInput, timeout_sec) -> ToolOutput:
    # CPU-intensive work blocks event loop!
    result = self._expensive_computation()
    return result
✅ CORRECT:

Python

async def _execute_tool(self, inp: ToolInput, timeout_sec) -> ToolOutput:
    # Run in thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,  # Use default executor
        self._expensive_computation
    )
    return result
Pitfall 5: Ignoring Cleanup
❌ WRONG:

Python

class ResourceLeakTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self.temp_files = []
    
    async def _execute_tool(self, inp, timeout_sec):
        # Create temp files but never clean up
        temp = self._create_temp_file()
        self.temp_files.append(temp)
        ...
✅ CORRECT:

Python

class CleanupTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self.temp_files = []
    
    async def _execute_tool(self, inp, timeout_sec):
        temp = self._create_temp_file()
        try:
            # Use temp file
            result = await super()._execute_tool(inp, timeout_sec)
            return result
        finally:
            # Always cleanup
            self._cleanup_temp_file(temp)
    
    async def cleanup(self):
        """Called during shutdown."""
        for temp in self.temp_files:
            self._cleanup_temp_file(temp)
        self.temp_files.clear()
Pitfall 6: Not Validating Configuration Values
❌ WRONG:

Python

def _apply_config(self):
    config = get_config()
    # Trusting config values - could be negative, huge, etc.
    self.timeout = config.tool.timeout
    self.concurrency = config.tool.concurrency
✅ CORRECT:

Python

def _apply_config(self):
    config = get_config()
    
    # Clamp to safe ranges
    timeout = getattr(config.tool, 'timeout', 300.0)
    self.timeout = max(60.0, min(3600.0, float(timeout)))
    
    concurrency = getattr(config.tool, 'concurrency', 2)
    self.concurrency = max(1, min(10, int(concurrency)))
    
    # Log if clamped
    if self.timeout != timeout:
        log.warning("config_clamped param=timeout original=%.1f clamped=%.1f",
                   timeout, self.timeout)
Reference Examples
Example 1: Simple Tool (Ping)
Python

"""PingTool - ICMP echo request tool."""
from mcp_server.base_tool import MCPBaseTool

class PingTool(MCPBaseTool):
    """
    Ping tool for basic connectivity checks.
    
    Usage:
        tool = PingTool()
        result = await tool.run(ToolInput(
            target="192.168.1.1",
            extra_args="-c 4"  # 4 packets
        ))
    """
    command_name = "ping"
    allowed_flags = ["-c", "-W", "-i", "-s"]  # count, timeout, interval, packet size
    default_timeout_sec = 30.0
    concurrency = 5
Example 2: Tool with Custom Validation (Traceroute)
Python

"""TracerouteTool - Network path tracing."""
import re
from typing import Optional
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput, ErrorContext, ToolErrorType
from datetime import datetime, timezone

class TracerouteTool(MCPBaseTool):
    """Trace network path to target."""
    
    command_name = "traceroute"
    allowed_flags = ["-m", "-q", "-w", "-n"]  # max-hops, queries, wait, numeric
    default_timeout_sec = 120.0
    concurrency = 2
    
    MAX_HOPS = 30
    _HOP_PATTERN = re.compile(r'^\d+$')
    
    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        # Validate hop count if specified
        if inp.extra_args and "-m" in inp.extra_args:
            try:
                tokens = inp.extra_args.split()
                if "-m" in tokens:
                    idx = tokens.index("-m")
                    if idx + 1 < len(tokens):
                        hops = tokens[idx + 1]
                        if not self._validate_hops(hops):
                            error_ctx = ErrorContext(
                                error_type=ToolErrorType.VALIDATION_ERROR,
                                message=f"Invalid hop count: {hops} (max: {self.MAX_HOPS})",
                                recovery_suggestion=f"Use hop count 1-{self.MAX_HOPS}",
                                timestamp=datetime.now(timezone.utc),
                                tool_name=self.tool_name,
                                target=inp.target,
                                metadata={"max_hops": self.MAX_HOPS}
                            )
                            return self._create_error_output(error_ctx, inp.correlation_id or "")
            except Exception as e:
                pass  # Let base class handle parsing
        
        return await super()._execute_tool(inp, timeout_sec)
    
    def _validate_hops(self, hops: str) -> bool:
        """Validate hop count."""
        if not self._HOP_PATTERN.match(hops):
            return False
        
        try:
            hop_count = int(hops)
            return 1 <= hop_count <= self.MAX_HOPS
        except ValueError:
            return False
Example 3: Tool with Configuration (Nmap) - See Provided Code
The NmapTool in your codebase is the definitive reference for:

Complex argument parsing
Configuration integration
Policy-based operation modes
Script filtering
Result parsing
Scan templates
