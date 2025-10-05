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

The MCP (Model Context Protocol) Server is a production-ready, extensible framework for building secure, monitored network diagnostic tools accessible via dual transport mechanisms (stdio and HTTP). T[...]

- **Security-first design** with multi-layered validation and sandboxing
- **Resilience** through circuit breakers, rate limiting, and graceful degradation
- **Observability** via comprehensive metrics and health monitoring
- **Extensibility** through abstract base classes and plugin-style tool discovery
- **Production readiness** with resource limits, timeout controls, and error recovery

The system is designed to be integrated with AI assistants (like Claude Desktop via stdio) or accessed programmatically via HTTP APIs.

---

## Architecture Overview

### High-Level Architecture
```text
┌─────────────────────────────────────────────────────────────┐
│ Client Layer │
│ ┌──────────────┐ ┌──────────────┐ │
│ │ Claude Desktop│ │ HTTP Clients │ │
│ │ (stdio) │ │ (REST API) │ │
│ └──────┬───────┘ └──────┬──────┘ │
└─────────┼──────────────────────────────┼───────────────────┘
│ │
│ │
┌─────────▼───────────────────────────────▼───────────────────┐
│ Transport Layer │
│ ┌──────────────┐ ┌──────────────┐ │
│ │ stdio_server │ │ FastAPI │ │
│ │ (MCP SDK) │ │ (HTTP/SSE) │ │
│ └──────┬───────┘ └──────┬──────┘ │
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
```

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
```

Thread-Safe Semaphore Registry

```python
# Per-event-loop semaphore with weak references for cleanup
_semaphore_registry: Dict[str, asyncio.Semaphore]
_loop_refs: weakref.WeakValueDictionary
```

Security Validation

```python
# Target must be RFC1918 or .lab.internal
_is_private_or_lab(value: str) -> bool

# Block shell metacharacters
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")
```

Resource Limits (Unix/Linux only)

```python
resource.setrlimit(resource.RLIMIT_CPU, ...)
resource.setrlimit(resource.RLIMIT_AS, ...)  # Memory
resource.setrlimit(resource.RLIMIT_NOFILE, ...)  # FDs
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # No core dumps
```

Extension Points:

Subclass must define: command_name, optionally allowed_flags
Override _execute_tool() for custom validation/optimization
Override get_tool_info() for tool-specific metadata

2. EnhancedMCPServer (Orchestrator)
Location: mcp_server/server.py

Purpose: Central coordinator managing tools, transports, and cross-cutting concerns.

Key Responsibilities:

- Tool discovery via package scanning (pkgutil)
- Tool registry with enable/disable functionality
- Transport abstraction (stdio vs HTTP)
- Health monitoring via HealthCheckManager
- Metrics aggregation via MetricsManager
- Rate limiting (token bucket algorithm)
- Graceful shutdown with background task cleanup
- Signal handling (SIGINT, SIGTERM)

Architecture Patterns:

Tool Discovery Pattern

```python
# Scan package for MCPBaseTool subclasses
_load_tools_from_package(package_path, include, exclude)

# Pattern-based exclusion
EXCLUDED_PREFIXES = {'Test', 'Mock', 'Abstract', '_', 'Example'}
EXCLUDED_SUFFIXES = {'Base', 'Mixin', 'Interface'}
```

Registry Pattern

```python
class ToolRegistry:
    tools: Dict[str, MCPBaseTool]  # All registered tools
    enabled_tools: Set[str]         # Currently enabled subset
```

Health Check Integration

```python
# Per-tool health checks
HealthCheckManager.register_check(
    name=f"tool_{tool_name}",
    check_func=self._create_tool_health_check(tool),
    priority=HealthCheckPriority.INFORMATIONAL
)
```

Background Task Management

```python
_background_tasks: Set[asyncio.Task]

# Auto-cleanup on task completion
task.add_done_callback(self._background_tasks.discard)
```

Dual Transport Support:

- stdio Transport: For Claude Desktop integration
  - Uses MCP SDK's stdio_server() context manager
  - JSON-RPC over stdin/stdout
  - Graceful shutdown via shutdown_event
- HTTP Transport: For programmatic/web access
  - FastAPI with CORS middleware
  - RESTful endpoints: /tools, /health, /metrics
  - SSE endpoint /events for real-time updates
  - Rate limiting per client IP + tool combination

3. ToolRegistry
Purpose: Centralized tool management with lifecycle control.

Features:

- Tool registration from discovery process
- Enable/disable without restart
- Filter-based inclusion/exclusion (env vars)
- Tool information aggregation
- Metrics/circuit breaker initialization per tool

API:

```python
registry.get_tool(tool_name) -> Optional[MCPBaseTool]
registry.get_enabled_tools() -> Dict[str, MCPBaseTool]
registry.enable_tool(tool_name)
registry.disable_tool(tool_name)
registry.get_tool_info() -> List[Dict[str, Any]]
```

4. RateLimiter
Algorithm: Token bucket with per-client tracking

Features:

- Configurable rate (requests per time window)
- Automatic cleanup of stale clients
- Thread-safe operation (asyncio.Lock)
- Client limit to prevent memory exhaustion

Implementation:

```python
# Token bucket: clients start with full allowance
allowance: Dict[str, float] = defaultdict(lambda: rate)

# Tokens regenerate over time
allowance[key] += time_passed * (rate / per)

# Request consumes a token
if allowance[key] < 1.0:
    return False  # Rate limited
allowance[key] -= 1.0
```

Configuration:

```python
RateLimiter(rate=10, per=60.0, max_clients=1000)
# 10 requests per 60 seconds, track up to 1000 clients
```

---

## Design Patterns & Principles
1. Template Method Pattern
MCPBaseTool.run() orchestrates execution while allowing subclass customization:

```python
async def run(self, inp: ToolInput) -> ToolOutput:
    # Template method with hooks:
    # 1. Circuit breaker check
    # 2. Semaphore acquire
    # 3. _execute_tool() [customizable]
    # 4. Metrics recording
    # 5. Cleanup
```

2. Strategy Pattern
Transport strategies (stdio vs HTTP) are swapped at runtime:

```python
if transport == "stdio":
    await self.run_stdio_original()
elif transport == "http":
    await self.run_http_enhanced()
```

3. Registry Pattern
ToolRegistry centralizes tool management with runtime enable/disable.

4. Circuit Breaker Pattern
Optional per-tool circuit breakers prevent cascading failures:

```python
# States: CLOSED → OPEN (failures exceed threshold) → HALF_OPEN → CLOSED
```

5. Fallback Pattern
Graceful degradation when optional dependencies missing:

```python
if not FASTAPI_AVAILABLE:
    # Fallback to stdio if MCP available
    # Or raise clear error with installation instructions
```

6. Observer Pattern
Health checks and metrics are observers of tool execution events.

7. Immutability for Safety

```python
BASE_ALLOWED_FLAGS: Tuple[str, ...]  # Immutable
allowed_flags property returns new list each time
```

---

## Security Architecture
Multi-Layer Defense
Layer 1: Input Validation (Pydantic Models)

```python
class ToolInput(BaseModel):
    target: str  # Validated by _is_private_or_lab()
    extra_args: str  # Length and character class validation
```

Layer 2: Target Restriction

```python
_is_private_or_lab(value: str):
    # RFC1918 private IPs: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    # CIDR networks with same restrictions
    # .lab.internal hostnames with RFC-compliant format
```

Layer 3: Argument Sanitization

```python
# Block shell metacharacters
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")

# Whitelist allowed tokens
_TOKEN_ALLOWED = re.compile(r"^[A-Za-z0-9.:/=+,\-@%_]+$")

# Flag whitelisting per tool
allowed_flags: Optional[Sequence[str]]
```

Layer 4: Command Resolution

```python
# Only use shutil.which() - no shell execution
resolved_cmd = shutil.which(self.command_name)
```

Layer 5: Resource Sandboxing

```python
# Unix resource limits
RLIMIT_CPU, RLIMIT_AS (memory), RLIMIT_NOFILE, RLIMIT_CORE

# Process isolation
start_new_session=True  # Separate process group
```

Layer 6: Policy Enforcement (Tool-Specific)

```python
# NmapTool example
allow_intrusive: bool  # Gates -A flag and vuln scripts
_validate_and_filter_scripts()  # Category-based filtering
```

Security Principles
- Least Privilege: Tools run with minimal permissions, resource limits
- Defense in Depth: Multiple validation layers
- Fail Secure: Errors block execution, don't bypass checks
- Whitelist > Blacklist: Explicitly allowed flags/targets only
- Immutable Defaults: Base configurations are constants
- Audit Trail: Comprehensive logging of security events

---

## Reliability & Resilience
Circuit Breaker Integration
Purpose: Prevent cascading failures from repeated tool failures

Configuration:

```python
circuit_breaker_failure_threshold: int = 5
circuit_breaker_recovery_timeout: float = 120.0
circuit_breaker_expected_exception: tuple = (Exception,)
```

State Machine:

text

CLOSED (normal) → [5 failures] → OPEN (fail fast) → 
[120s timeout] → HALF_OPEN (test) → [success] → CLOSED
                                    → [failure] → OPEN

Error Handling:

```python
if circuit_breaker.state == OPEN:
    return ToolOutput(error_type=ToolErrorType.CIRCUIT_BREAKER_OPEN)
```

Timeout Management
Multi-Level Timeouts:

- Tool Default: default_timeout_sec (e.g., 600s for nmap)
- Input Override: ToolInput.timeout_sec
- Global Max: Environment variable MCP_DEFAULT_TIMEOUT_SEC

Enforcement:

```python
await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)

# On timeout: SIGKILL entire process group
os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
```

Concurrency Control
Per-Tool Semaphores:

```python
concurrency: ClassVar[int] = 2  # Max 2 concurrent executions

async with self._ensure_semaphore():
    # Execute tool
```

Automatic Cleanup:

```python
# Weak references to event loops
_loop_refs: weakref.WeakValueDictionary

# Clean dead loop semaphores
dead_keys = [k for k in registry if loop_id not in _loop_refs]
```

Graceful Shutdown
Shutdown Sequence:

- Signal Handler sets shutdown_event
- Health Manager stops monitoring
- Metrics Manager performs cleanup
- Background Tasks cancelled with gather(return_exceptions=True)
- Circuit Breakers cleanup (if implemented)
- Server waits for grace period before force-stop

```python
async def cleanup(self):
    await self.health_manager.stop_monitoring()
    await self.metrics_manager.cleanup()
    
    # Cancel background tasks
    for task in self._background_tasks:
        if not task.done():
            task.cancel()
    
    await asyncio.gather(*tasks, return_exceptions=True)
```

Error Recovery
Typed Errors with Context:

```python
class ToolErrorType(Enum):
    TIMEOUT, NOT_FOUND, VALIDATION_ERROR, EXECUTION_ERROR,
    RESOURCE_EXHAUSTED, CIRCUIT_BREAKER_OPEN, UNKNOWN

class ErrorContext:
    error_type: ToolErrorType
    message: str
    recovery_suggestion: str  # Actionable guidance
    metadata: Dict[str, Any]
```

Example Error:

```python
ErrorContext(
    error_type=ToolErrorType.VALIDATION_ERROR,
    message="Network range too large: 4096 addresses (max: 1024)",
    recovery_suggestion="Use /22 or smaller prefix (max 1024 hosts)",
    metadata={
        "suggested_cidr": "/22",
        "example": "192.168.0.0/22"
    }
)
```

---

## Transport Layer
stdio Transport (MCP Protocol)
Use Case: Claude Desktop integration

Protocol: JSON-RPC 2.0 over stdin/stdout

Registration:

```python
server.register_tool(
    name="NmapTool",
    description="Network scanner",
    input_schema={...},  # JSON Schema
    handler=async_handler_function
)
```

Execution Flow:

text

Claude → JSON-RPC Request → stdio_server → handler → 
MCPBaseTool.run() → TextContent Response → Claude

Response Format:

```python
[TextContent(type="text", text=json.dumps(result.dict()))]
```

HTTP Transport (FastAPI)
Use Case: API access, monitoring, web UIs

Endpoints:
```text
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
```

Rate Limiting:

```python
# Per client IP + tool combination
rate_limit_key = f"{client_ip}:{tool_name}"

if not await rate_limiter.check_rate_limit(rate_limit_key):
    raise HTTPException(status_code=429, detail={...})
```

SSE Events:

```python
# Real-time health and metrics
async def event_generator():
    while not disconnected:
        yield {"type": "health", "data": {...}}
        yield {"type": "metrics", "data": {...}}
        await asyncio.sleep(5)
```

---

## Data Flow
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

---

## Configuration System
Configuration Sources (Priority Order)
- Environment Variables (highest priority)
- Configuration File (MCP_CONFIG_FILE)
- Code Defaults (lowest priority)

Key Configuration Objects
Assumed structure based on usage:

```python
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
```

Environment Variables
```text
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
```

Configuration Application

```python
def _apply_config(self):
    # Clamp values to safe ranges
    self.timeout = max(60.0, min(3600.0, config.timeout))
    self.concurrency = max(1, min(5, config.concurrency))
    
    # Log when clamped
    if clamped:
        log.info("config_clamped param=%s original=%s new=%s")
```

---

## Monitoring & Observability
Health Monitoring
Architecture:

```text
HealthCheckManager
├─ system_health_check (CPU, memory, disk)
├─ tool_availability_check (commands in PATH)
└─ per_tool_health_checks (circuit breaker state)
```

Health States:

```python
class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
```

Priority Levels:

```python
class HealthCheckPriority(Enum):
    CRITICAL = 1      # System-level
    HIGH = 2          # Important tools
    MEDIUM = 3        # Optional tools
    LOW = 4
    INFORMATIONAL = 5  # Metrics, stats
```

HTTP Response Codes:

- 200: All HEALTHY
- 207: Some DEGRADED (multi-status)
- 503: Any UNHEALTHY

Metrics Collection
Prometheus Metrics:

```text
mcp_tool_execution_total{tool="NmapTool",status="success"}
mcp_tool_execution_duration_seconds{tool="NmapTool"}
mcp_tool_active_executions{tool="NmapTool"}
mcp_tool_timeouts_total{tool="NmapTool"}
mcp_circuit_breaker_state{tool="NmapTool",state="open"}
```

Fallback JSON Metrics:

```json
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
```

Logging Strategy
Structured Logging:

```python
log.info("tool.start command=%s timeout=%.1f", cmd, timeout)
log.error("tool.error tool=%s error_type=%s", name, error_type)
```

Log Levels:

- DEBUG: Configuration, cache operations, internal state
- INFO: Execution lifecycle, optimizations, state changes
- WARNING: Non-fatal issues, fallbacks, deprecated usage
- ERROR: Failures, exceptions, security violations
- CRITICAL: System-level failures

---

## Extension Points
Creating a New Tool
Minimum Implementation:

```python
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput

class MyTool(MCPBaseTool):
    command_name = "mytool"  # Required
    allowed_flags = ["-flag1", "-flag2"]  # Optional whitelist
    
    # Optional overrides
    default_timeout_sec = 300.0
    concurrency = 2
    circuit_breaker_failure_threshold = 5
```

Custom Validation:

```python
async def _execute_tool(self, inp: ToolInput, timeout_sec) -> ToolOutput:
    # 1. Custom validation
    if not self._my_validation(inp.target):
        return self._create_error_output(error_context, ...)
    
    # 2. Parse/optimize args
    parsed = self._parse_my_args(inp.extra_args)
    
    # 3. Call base implementation
    enhanced = ToolInput(target=inp.target, extra_args=parsed, ...)
    return await super()._execute_tool(enhanced, timeout_sec)
```

Tool-Specific Metadata:

```python
def get_tool_info(self) -> Dict[str, Any]:
    base_info = super().get_tool_info()
    base_info.update({
        "my_feature": "enabled",
        "supported_modes": ["fast", "thorough"]
    })
    return base_info
```

Adding Custom Health Checks

```python
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
```

Adding Custom Metrics

```python
# Assumed MetricsManager API
metrics_manager.register_counter("my_metric_total")
metrics_manager.increment("my_metric_total", labels={"status": "success"})
```

---

## Deployment Considerations
Running the Server
stdio Mode (Claude Desktop):

```bash
# Minimal
python -m mcp_server.server

# With config
MCP_CONFIG_FILE=config.yaml python -m mcp_server.server

# With tool filtering
TOOL_INCLUDE=NmapTool,TracertTool python -m mcp_server.server
```

HTTP Mode:

```bash
MCP_SERVER_TRANSPORT=http \
MCP_SERVER_PORT=8080 \
python -m mcp_server.server
```

Docker Deployment
Dockerfile considerations:

```dockerfile
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
```

Kubernetes Deployment
Resource Limits:

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

Health Probes:

```yaml
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
```

Security Considerations
- Network Policies: Restrict egress to private networks only
- RBAC: Limit tool execution permissions
- Secrets Management: Use env vars or secret managers for sensitive config
- Image Scanning: Regularly scan for vulnerabilities
- Log Aggregation: Ship logs to SIEM for security monitoring
- Rate Limiting: Configure per deployment size
- TLS: Use reverse proxy (nginx, traefik) for HTTPS in HTTP mode

Scaling Considerations
Horizontal Scaling (HTTP mode):

- Stateless design allows multiple replicas
- Use load balancer with session affinity for SSE
- Share metrics backend (Prometheus pushgateway)

Vertical Scaling:

- Increase concurrency per tool
- Adjust resource limits
- Monitor with /metrics endpoint

Performance Tuning:

```python
# Use uvloop for better async performance
import uvloop
uvloop.install()

# Increase concurrency for fast tools
class FastTool(MCPBaseTool):
    concurrency = 10

# Decrease timeout for quick scans
default_timeout_sec = 60.0
```

Appendix: Component Interaction Matrix
```text
Component	Depends On	Depended By	Purpose
MCPBaseTool	Pydantic, asyncio, resource	All tools	Base functionality
EnhancedMCPServer	FastAPI, MCP SDK, ToolRegistry	Main entry	Orchestration
ToolRegistry	MCPBaseTool	EnhancedMCPServer	Tool management
RateLimiter	asyncio	HTTP endpoints	Request throttling
HealthCheckManager	asyncio	EnhancedMCPServer	Health monitoring
MetricsManager	prometheus_client	Tools, Server	Observability
NmapTool	MCPBaseTool, ipaddress	ToolRegistry	Network scanning
```
